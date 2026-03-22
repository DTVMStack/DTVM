// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/compiler.h"
#include "common/thread_pool.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/pass/dead_cg_instruction_elim.h"
#include "compiler/cgir/pass/expand_post_ra_pseudos.h"
#include "compiler/cgir/pass/fast_ra.h"
#include "compiler/cgir/pass/phi_elimination.h"
#include "compiler/cgir/pass/prolog_epilog_inserter.h"
#include "compiler/cgir/pass/reg_alloc_basic.h"
#include "compiler/cgir/pass/reg_alloc_greedy.h"
#include "compiler/cgir/pass/register_coalescer.h"
#include "compiler/context.h"
#include "compiler/frontend/parser.h"
#include "compiler/mir/function.h"
#include "compiler/mir/module.h"
#include "compiler/mir/pass/dead_basicblock_elim.h"
#include "compiler/mir/pass/verifier.h"
#include "compiler/target/x86/x86_cg_peephole.h"
#include "compiler/target/x86/x86_mc_lowering.h"
#include "compiler/target/x86/x86lowering.h"
#include "compiler/wasm_frontend/wasm_mir_compiler.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/SmallVectorMemoryBuffer.h"
#include <deque>

#if defined(ZEN_ENABLE_MULTIPASS_JIT_LOGGING) || defined(ZEN_ENABLE_LINUX_PERF)
#include "utils/asm_dump.h"
#endif

#ifdef ZEN_ENABLE_LINUX_PERF
#include "utils/perf.h"
#endif

using namespace COMPILER;

// mprotect need protect by chunks(0x1000) in occulum
// so align code size space to 0x1000
const size_t MPROTECT_CHUNK_SIZE = 0x1000;

#define TO_MPROTECT_CODE_SIZE(CodeSize)                                        \
  ((((CodeSize) + MPROTECT_CHUNK_SIZE - 1) / MPROTECT_CHUNK_SIZE) *            \
   MPROTECT_CHUNK_SIZE)

#ifdef ZEN_ENABLE_DEBUG_GREEDY_RA
static inline bool isFuncNeedGreedyRA(uint32_t FuncIdx) {
  uint32_t StartIdx =
      (uint32_t)strtoul(getenv("GREEDY_FUNC_IDX_START"), NULL, 0);
  uint32_t EndIdx = (uint32_t)strtoul(getenv("GREEDY_FUNC_IDX_END"), NULL, 0);
  return FuncIdx >= StartIdx && FuncIdx <= EndIdx;
}
#endif // ZEN_ENABLE_DEBUG_GREEDY_RA

void JITCompilerBase::compileMIRToCgIR(MModule &MMod, MFunction &MFunc,
                                       CgFunction &CgFunc,
                                       bool DisableGreedyRA) {
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::DebugFlag = true;
  llvm::dbgs() << "\n########## MIR Dump ##########\n\n";
  MFunc.dump();
#endif

  MVerifier Verifier(MMod, MFunc, llvm::errs());
  if (!Verifier.verify()) {
    throw getError(ErrorCode::MIRVerifyingFailed);
  }

  DeadMBasicBlockElim MBBDCE;
  MBBDCE.runOnMFunction(MFunc);

  CgFunction &MF = CgFunc;

  // TODO: refactor to pass
  X86CgLowering CgLowering(MF);
  X86CgPeephole CgPeephole(MF);
  CgPhiElimination PhiElimination;
  PhiElimination.runOnCgFunction(MF);

  uint32_t MFuncIdx = MFunc.getFuncIdx();

  if (DisableGreedyRA) {
    ZEN_LOG_DEBUG("using fast ra for function %d", MFuncIdx);
    FastRA RA(MF);
  } else {
#ifdef ZEN_ENABLE_DEBUG_GREEDY_RA
    if (!isFuncNeedGreedyRA(MFuncIdx)) {
      ZEN_LOG_DEBUG("using fast ra for function %d", MFuncIdx);
      FastRA RA(MF);
    } else {
#endif // ZEN_ENABLE_DEBUG_GREEDY_RA
      ZEN_LOG_DEBUG("using greedy ra for function %d", MFuncIdx);
      CgDeadCgInstructionElim DCE(MF);
      CgDominatorTree DomTree(MF);
      CgLoopInfo Loops(MF);
      CgSlotIndexes Indexes(MF);
      CgLiveIntervals LIS(MF);
      CgLiveStacks LSS(MF);
      CgBlockFrequencyInfo MBFI(MF);
      // CgRegisterCoalescer must before CgVirtRegMap
      CgRegisterCoalescer Coalescer(MF);
      CgVirtRegMap VRM(MF);
      CgLiveRegMatrix Matrix(MF);
      // RABasic ra(MF);

      CgEdgeBundles EdgeBundles(MF);
      CgSpillPlacement SpillPlacer(MF);
      MF.EvictAdvisor = std::unique_ptr<CgRegAllocEvictionAdvisorAnalysis>(
          createReleaseModeAdvisor());
      std::shared_ptr<CgRAGreedy> RA = std::make_shared<CgRAGreedy>(MF);

      CgVirtRegRewriter Rewriter(MF);
#ifdef ZEN_ENABLE_DEBUG_GREEDY_RA
    }
#endif // ZEN_ENABLE_DEBUG_GREEDY_RA
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::dbgs() << "\n########## CgIR Dump After Register Allocation "
                  "##########\n\n";
  MF.dump();
#endif

  PrologEpilogInserter PEInserter;
  PEInserter.runOnCgFunction(MF);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::dbgs() << "\n########## CgIR Dump After Prologue/Epilogue Insertion "
                  "##########\n\n";
  MF.dump();
#endif

  ExpandPostRAPseudos PseudosExpander;
  PseudosExpander.runOnCgFunction(MF);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  llvm::dbgs() << "\n########## CgIR Dump After Post-RA Pseudo "
                  "Instruction Expansion "
                  "##########\n\n";
  MF.dump();
#endif
  if (MF.EvictAdvisor) {
    MF.EvictAdvisor.reset();
  }
}

void JITCompilerBase::emitObjectBuffer(CompileContext *Ctx) {
  ZEN_ASSERT(Ctx);

  // Do nothing if no function is compiled in current thread
  if (!Ctx->Inited) {
    return;
  }

  Ctx->finalize();

  auto ObjectToLoad = std::make_unique<llvm::SmallVectorMemoryBuffer>(
      std::move(Ctx->getObjBuffer()), false);
  auto LoadedObject = llvm::object::ObjectFile::createObjectFile(*ObjectToLoad);
  if (!LoadedObject) {
    throw getError(ErrorCode::ObjectFileCreationFailed);
  }

  const llvm::object::ObjectFile &Obj = *LoadedObject->get();
  if (!Obj.isELF()) {
    throw getError(ErrorCode::UnexpectedObjectFileFormat);
  }

  // Find the text section and relocation section
  llvm::object::section_iterator TextSection = Obj.section_end();
  llvm::object::section_iterator RelSection = Obj.section_end();
  for (const auto &Sec : Obj.sections()) {
    if (Sec.isText()) {
      TextSection = Sec;
    } else {
      llvm::object::relocation_iterator I = Sec.relocation_begin();
      llvm::object::relocation_iterator E = Sec.relocation_end();
      if (I != E) {
        RelSection = Sec;
      }
    }
  }

  // Must have a text section
  if (TextSection == Obj.section_end()) {
    throw getError(ErrorCode::ObjectFileResolvingFailed);
  }

  constexpr size_t FuncSymbolPrefixLen = sizeof(JIT_FUNCTION_NAME_PREFIX) - 1;

  uint32_t FuncIdx = 0;
  size_t NumSymbols = std::distance(Obj.symbol_begin(), Obj.symbol_end());
  auto &FuncOffsetMap = Ctx->FuncOffsetMap;
  FuncOffsetMap.reserve(NumSymbols);
#ifdef ZEN_ENABLE_LINUX_PERF
  auto &FuncSizeMap = Ctx->FuncSizeMap;
  FuncSizeMap.reserve(NumSymbols);
#ifdef ZEN_ENABLE_EVM
  Ctx->FuncNameMap.reserve(NumSymbols);
  uint32_t BBSymIdx = 1;
#endif
#endif
  for (const auto &Sym : Obj.symbols()) {
    // Get symbol flags
    auto FlagsOrErr = Sym.getFlags();
    if (!FlagsOrErr) {
      continue;
    }

    // Skip undefined symbols
    if (*FlagsOrErr & llvm::object::SymbolRef::SF_Undefined) {
      continue;
    }

    // Get the symbol type
    auto SymTypeOrErr = Sym.getType();
    if (!SymTypeOrErr) {
      continue;
    }

    // Skip non-function symbols
    if (*SymTypeOrErr != llvm::object::SymbolRef::ST_Function) {
      continue;
    }

    // Get symbol name.
    auto NameOrErr = Sym.getName();
    if (!NameOrErr) {
      continue;
    }

#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
    // Skip non-EVMBB symbols
    if (!NameOrErr->startswith("EVMBB")) {
      continue;
    }
#else
    // Skip non-JIT function symbols
    if (!NameOrErr->startswith(JIT_FUNCTION_NAME_PREFIX)) {
      continue;
    }

    // Get function index
    if (NameOrErr->substr(FuncSymbolPrefixLen).getAsInteger(10, FuncIdx)) {
      continue;
    }
#endif

    // Get symbol section
    llvm::object::section_iterator SI = Obj.section_end();
    if (auto SIOrErr = Sym.getSection())
      SI = *SIOrErr;
    else {
      continue;
    }
    if (SI != TextSection) {
      continue;
    }

    // Get symbol address
    auto AddressOrErr = Sym.getAddress();
    if (!AddressOrErr) {
      continue;
    }

    // Get symbol offset
    uint64_t SymOffset = *AddressOrErr - SI->getAddress();

#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
    if (NameOrErr->startswith("EVMBB")) {
      FuncSizeMap[BBSymIdx] = llvm::object::ELFSymbolRef(Sym).getSize();
      FuncOffsetMap[BBSymIdx] = SymOffset;
      Ctx->FuncNameMap[BBSymIdx] = NameOrErr->str();
      BBSymIdx++;
      continue;
    }
#endif

#ifdef ZEN_ENABLE_LINUX_PERF
    FuncSizeMap[FuncIdx] = llvm::object::ELFSymbolRef(Sym).getSize();
#endif

    FuncOffsetMap[FuncIdx] = SymOffset; // TODO: offset based on section?
  }

  // Record external relocations
  if (RelSection != Obj.section_end()) {
    auto &ExternRelocs = Ctx->ExternRelocs;
    size_t NumRelocs = std::distance(RelSection->relocation_begin(),
                                     RelSection->relocation_end());
    // TODO: reserve the exact size considering lazy compilation
    ExternRelocs.reserve(NumRelocs);
    for (const auto &Reloc : RelSection->relocations()) {
      int64_t Addend = 0;
#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF)
      if (Reloc.getType() != llvm::ELF::R_X86_64_PLT32) {
        continue;
      }
#endif
      ZEN_ASSERT(Reloc.getType() == llvm::ELF::R_X86_64_PLT32);
      if (auto AddendOrErr =
              llvm::object::ELFRelocationRef(Reloc).getAddend()) {
        Addend = *AddendOrErr;
      } else {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      llvm::object::symbol_iterator SI = Reloc.getSymbol();
      if (SI == Obj.symbol_end()) {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      // Get relocation symbol name
      auto SymNameOrErr = SI->getName();
      if (!SymNameOrErr) {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      // Must be function symbol
      if (!SymNameOrErr->startswith(JIT_FUNCTION_NAME_PREFIX)) {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      // Get function index
      if (SymNameOrErr->substr(FuncSymbolPrefixLen).getAsInteger(10, FuncIdx)) {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      // Must be external symbol
      if (FuncOffsetMap.find(FuncIdx) != FuncOffsetMap.end()) {
        throw getError(ErrorCode::ObjectFileResolvingFailed);
      }

      ExternRelocs.emplace_back(Reloc.getOffset(), Addend, FuncIdx);
    }
  }

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  dumpAsm(ObjectToLoad->getBufferStart(), ObjectToLoad->getBufferSize());
#endif

  Ctx->CodeSize = TextSection->getSize();
  size_t Align = Ctx->Lazy ? common::CodeMemPool::PageSize
                           : common::CodeMemPool::DefaultAlign;

  Ctx->CodePtr = reinterpret_cast<uint8_t *>(
      Ctx->CodeMPool->allocate(TO_MPROTECT_CODE_SIZE(Ctx->CodeSize), Align));
  Ctx->CodeOffset = Ctx->CodePtr - Ctx->CodeMPool->getMemStart();

  auto CodeOrErr = TextSection->getContents();
  if (!CodeOrErr) {
    throw getError(ErrorCode::ObjectFileResolvingFailed);
  }
  std::memcpy(Ctx->CodePtr, CodeOrErr->data(), Ctx->CodeSize);

#if defined(ZEN_ENABLE_EVM) && defined(ZEN_ENABLE_LINUX_PERF) &&               \
    !defined(ZEN_ENABLE_MULTIPASS_JIT_LOGGING)
  dumpAsm(ObjectToLoad->getBufferStart(), ObjectToLoad->getBufferSize(),
          Ctx->CodePtr);
#endif
}

void WasmJITCompiler::compileWasmToMC(WasmFrontendContext &Ctx, MModule &Mod,
                                      uint32_t FuncIdx, bool DisableGreedyRA) {
  if (Ctx.Inited) {
    // Release all memory allocated by previous function compilation
    Ctx.MemPool = CompileMemPool();
    if (Ctx.Lazy) {
      Ctx.reinitialize();
    }
  } else {
    Ctx.initialize();
  }

  uint32_t RealFuncIdx = FuncIdx + WasmMod->getNumImportFunctions();
  TypeEntry *FuncType = WasmMod->getFunctionType(RealFuncIdx);
  ZEN_ASSERT(FuncType);
  CodeEntry *FuncCode = WasmMod->getCodeEntry(RealFuncIdx);
  ZEN_ASSERT(FuncCode);
  Ctx.setCurFunc(FuncIdx, FuncType, FuncCode);
  MFunction MFunc(Ctx, FuncIdx);
  CgFunction CgFunc(Ctx, MFunc);
  MFunc.setFunctionType(Mod.getFuncType(FuncIdx));
  FunctionMirBuilder MIRBuilder(Ctx, MFunc);
  MIRBuilder.compile(&Ctx); // pass the ctx argument only for compatibility
  runtime::Runtime *RT = WasmMod->getRuntime();
  const runtime::RuntimeConfig &Config = RT->getConfig();
  compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA);
  Ctx.getMCLowering().runOnCgFunction(CgFunc);
}

void EagerJITCompiler::compile() {
  auto Timer = Stats.startRecord(zen::utils::StatisticPhase::JITCompilation);

  WasmFrontendContext MainContext(*WasmMod);
  auto &MainMemPool = MainContext.ThreadMemPool;

  MModule Mod(MainContext);
  buildAllMIRFuncTypes(MainContext, Mod, *WasmMod);
  MainContext.CodeMPool = &WasmMod->getJITCodeMemPool();

  const uint32_t NumImportFunctions = WasmMod->getNumImportFunctions();
  ZEN_ASSERT(NumInternalFunctions > 0);

#ifdef ZEN_ENABLE_LINUX_PERF
  utils::JitDumpWriter JitDumpWriter;
#define JIT_DUMP_WRITE_FUNC(FuncIdx, FuncAddr, FuncSize)                       \
  JitDumpWriter.writeFunc(WasmMod->getWasmFuncDebugName(FuncIdx),              \
                          reinterpret_cast<uint64_t>(FuncAddr), FuncSize)
#else
#define JIT_DUMP_WRITE_FUNC(...)
#endif

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  auto &SortedJITFuncPtrs = WasmMod->getSortedJITFuncPtrs();
#define INSERT_JITED_FUNC_PTR(JITCodePtr, FuncIdx)                             \
  SortedJITFuncPtrs.emplace_back(JITCodePtr, FuncIdx)
#define SORT_JITED_FUNC_PTRS                                                   \
  std::sort(                                                                   \
      SortedJITFuncPtrs.begin(), SortedJITFuncPtrs.end(),                      \
      [](const auto &A, const auto &B) -> bool { return A.first > B.first; })
#else
#define INSERT_JITED_FUNC_PTR(...)
#define SORT_JITED_FUNC_PTRS
#endif // ZEN_ENABLE_DUMP_CALL_STACK

  auto &CodeMPool = WasmMod->getJITCodeMemPool();
  uint8_t *JITCode = const_cast<uint8_t *>(CodeMPool.getMemStart());
  if (Config.DisableMultipassMultithread) {
    for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
      compileWasmToMC(MainContext, Mod, I, Config.DisableMultipassGreedyRA);
    }
    emitObjectBuffer(&MainContext);
    ZEN_ASSERT(MainContext.ExternRelocs.empty());
    for (const auto &[FuncIdx, FuncOffset] : MainContext.FuncOffsetMap) {
      uint32_t RealFuncIdx = NumImportFunctions + FuncIdx;
      CodeEntry *CE = WasmMod->getCodeEntry(RealFuncIdx);
      ZEN_ASSERT(CE);
      CE->JITCodePtr = MainContext.CodePtr + FuncOffset;
      JIT_DUMP_WRITE_FUNC(RealFuncIdx, CE->JITCodePtr,
                          MainContext.FuncSizeMap[FuncIdx]);
      INSERT_JITED_FUNC_PTR((void *)(CE->JITCodePtr), RealFuncIdx);
    }
  } else {
    common::ThreadPool<WasmFrontendContext> ThreadPool(
        std::min(Config.NumMultipassThreads, NumInternalFunctions));
    uint32_t NumThreads = ThreadPool.getThreadCount();
    ZEN_LOG_DEBUG("using %u threads for multipass JIT compilation", NumThreads);

    CompileVector<WasmFrontendContext> AuxContexts(NumThreads - 1, MainContext,
                                                   MainMemPool);
    // Some threads may not have compiled functions, so when all compilation
    // tasks are completed, in the context of these threads:
    // - Inited == false
    // - CodePtr == nullptr
    // - CodeSize == 0
    // - CodeOffset == 0
    // - FuncOffsetMap.empty() == true
    // - ExternRelocs.empty() == true
    CompileVector<WasmFrontendContext *> Contexts(MainMemPool);

    ThreadPool.setThreadContext(0, &MainContext, emitObjectBuffer);
    Contexts.push_back(&MainContext);
    for (uint32_t I = 0; I < NumThreads - 1; ++I) {
      ThreadPool.setThreadContext(I + 1, &AuxContexts[I], emitObjectBuffer);
      Contexts.push_back(&AuxContexts[I]);
    }

    // Sort functions by code size in descending order in order to compile
    // larger functions first
    CompileVector<std::pair<uint32_t, uint32_t>> FuncIdxAndSizes(MainMemPool);
    FuncIdxAndSizes.reserve(NumInternalFunctions);
    for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
      CodeEntry *CE = WasmMod->getCodeEntry(NumImportFunctions + I);
      ZEN_ASSERT(CE);
      FuncIdxAndSizes.emplace_back(I, CE->CodeSize);
    }
    std::sort(FuncIdxAndSizes.begin(), FuncIdxAndSizes.end(),
              [](const auto &LHS, const auto &RHS) {
                return LHS.second > RHS.second;
              });

    for (const auto &[FuncIdx, FuncSize] : FuncIdxAndSizes) {
      ThreadPool.pushTask([&, FuncIdx = FuncIdx](WasmFrontendContext *Ctx) {
        compileWasmToMC(*Ctx, Mod, FuncIdx, Config.DisableMultipassGreedyRA);
      });
    }

    ThreadPool.setNoNewTask();
    // Must call the `waitForTasks` method explicitly, because `Contexts` will
    // be destructed before `ThreadPool`
    ThreadPool.waitForTasks();

    CompileUnorderedMap<uint32_t, WasmFrontendContext *> FuncIdxToCtxIdMap(
        MainMemPool);
    FuncIdxToCtxIdMap.reserve(NumInternalFunctions);
    for (WasmFrontendContext *Ctx : Contexts) {
      for (const auto &[FuncIdx, FuncSymOffset] : Ctx->FuncOffsetMap) {
        FuncIdxToCtxIdMap[FuncIdx] = Ctx;
        uint32_t RealFuncIdx = NumImportFunctions + FuncIdx;
        CodeEntry *CE = WasmMod->getCodeEntry(RealFuncIdx);
        ZEN_ASSERT(CE);
        CE->JITCodePtr = Ctx->CodePtr + FuncSymOffset;
        JIT_DUMP_WRITE_FUNC(RealFuncIdx, CE->JITCodePtr,
                            Ctx->FuncSizeMap[FuncIdx]);
        INSERT_JITED_FUNC_PTR((void *)(CE->JITCodePtr), RealFuncIdx);
      }
    }
    for (WasmFrontendContext *Ctx : Contexts) {
      for (const auto &Reloc : Ctx->ExternRelocs) {
        auto It = FuncIdxToCtxIdMap.find(Reloc.CalleeFuncIdx);
        if (It == FuncIdxToCtxIdMap.end()) {
          throw getError(ErrorCode::ObjectFileResolvingFailed);
        }
        WasmFrontendContext *CalleeCtx = It->second;
        uint64_t RelOffset = Ctx->CodeOffset + Reloc.Offset;
        uint64_t FuncSymValue = CalleeCtx->CodeOffset +
                                CalleeCtx->FuncOffsetMap[Reloc.CalleeFuncIdx];
        uint64_t RelValue = FuncSymValue + Reloc.Addend - RelOffset;
        JITCode[RelOffset] = RelValue & 0xff;
        JITCode[RelOffset + 1] = (RelValue >> 8) & 0xff;
        JITCode[RelOffset + 2] = (RelValue >> 16) & 0xff;
        JITCode[RelOffset + 3] = (RelValue >> 24) & 0xff;
      }
    }
  }
  size_t CodeSize = CodeMPool.getMemEnd() - JITCode;

  platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE(CodeSize),
                     PROT_READ | PROT_EXEC);
  WasmMod->setJITCodeAndSize(JITCode, CodeSize);

  SORT_JITED_FUNC_PTRS;

  Stats.stopRecord(Timer);
}

LazyJITCompiler::LazyJITCompiler(Module *WasmMod)
    : WasmJITCompiler(WasmMod), StubBuilder(WasmMod->getJITCodeMemPool()) {
  MainContext = new WasmFrontendContext(*WasmMod);
  MainContext->Lazy = true;
  MainContext->CodeMPool = &WasmMod->getJITCodeMemPool();
  Mod = MainContext->ThreadMemPool.newObject<MModule>(*MainContext);

  const runtime::RuntimeConfig &Config = WasmMod->getRuntime()->getConfig();

  if (!Config.DisableMultipassMultithread) {
    ThreadPool = std::make_unique<common::ThreadPool<WasmFrontendContext>>(
        std::min(Config.NumMultipassThreads, NumInternalFunctions));
    uint32_t NumThreads = ThreadPool->getThreadCount();
    ZEN_LOG_DEBUG("using %u threads for multipass JIT background compilation",
                  NumThreads);
    std::vector<WasmFrontendContext> Contexts(NumThreads, *MainContext);
    for (uint32_t I = 0; I < NumThreads; ++I) {
      ThreadPool->setThreadContext(I, &Contexts[I]);
    }
    AuxContexts = std::move(Contexts);
    CompileStatuses =
        std::make_unique<std::atomic<CompileStatus>[]>(NumInternalFunctions);
    GreedyRACodePtrs =
        std::make_unique<std::atomic<uint8_t *>[]>(NumInternalFunctions);
    for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
      CompileStatuses[I] = CompileStatus::None;
      GreedyRACodePtrs[I] = nullptr;
    }
  }
}

LazyJITCompiler::~LazyJITCompiler() {
  if (ThreadPool) {
    ThreadPool->interrupt();
  }
  MainContext->ThreadMemPool.deleteObject(Mod);
  delete MainContext;
}

void LazyJITCompiler::dispatchCompileTask(uint32_t FuncIdx) {
  if (CompileStatuses[FuncIdx] != CompileStatus::None) {
    return;
  }
  CompileStatuses[FuncIdx] = CompileStatus::Pending;
  ThreadPool->pushTask([&, FuncIdx](WasmFrontendContext *Ctx) {
    compileFunctionInBackgroud(*Ctx, FuncIdx);
  });
  ZEN_LOG_DEBUG("push function %d compile task into thread pool", FuncIdx);
}

void LazyJITCompiler::dispatchCompileTasksDepthFirst(WasmFrontendContext &Ctx) {
  uint32_t NumImportFunctions = WasmMod->getNumImportFunctions();
  const auto &ExportedFuncIdxs = WasmMod->getExportedFuncIdxs();
  const auto &CallSeqMap = WasmMod->getCallSeqMap();

  /// \warning not thread-safe and not addressable
  CompileVector<bool> Visited(NumInternalFunctions, false, Ctx.MemPool);
  CompileDeque<uint32_t> Stack(Ctx.MemPool);

  // The entry function is already at the end
  for (uint32_t FuncIdx : ExportedFuncIdxs) {
    ZEN_ASSERT(FuncIdx >= NumImportFunctions);
    Stack.push_back(FuncIdx - NumImportFunctions);
  }

  // Place the start function at the end
  if (uint32_t StartFuncIdx = WasmMod->getStartFuncIdx(); StartFuncIdx != -1u) {
    ZEN_ASSERT(StartFuncIdx >= NumImportFunctions);
    StartFuncIdx -= NumImportFunctions;
    auto It = std::find(Stack.begin(), Stack.end(), StartFuncIdx);
    if (It != Stack.end()) {
      Stack.erase(It);
    }
    Stack.push_back(StartFuncIdx);
  }

  while (!Stack.empty()) {
    uint32_t FuncIdx = Stack.back();
    Stack.pop_back();
    dispatchCompileTask(FuncIdx);
    Visited[FuncIdx] = true;
    const auto &CallSeq = CallSeqMap.at(FuncIdx + NumImportFunctions);
    for (auto It = CallSeq.rbegin(); It != CallSeq.rend(); ++It) {
      uint32_t CalleeIdx = *It;
      ZEN_ASSERT(CalleeIdx >= NumImportFunctions);
      uint32_t CalleeInternalIdx = CalleeIdx - NumImportFunctions;
      if (!Visited[CalleeInternalIdx]) {
        Stack.push_back(CalleeInternalIdx);
      }
    }
  }
}

void LazyJITCompiler::dispatchCompileTasksInOrder(WasmFrontendContext &Ctx) {
  for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
    dispatchCompileTask(I);
  }
}

void LazyJITCompiler::dispatchEntryCompileTasks(WasmFrontendContext &Ctx) {
  // First strategy: dispatch compile tasks in depth-first order
  dispatchCompileTasksDepthFirst(Ctx);

  // Second strategy: dispatch compile tasks in order of function index
  // dispatchCompileTasksInOrder(Ctx);
}

void LazyJITCompiler::precompile() {
  auto Timer =
      Stats.startRecord(zen::utils::StatisticPhase::JITLazyPrecompilation);
  buildAllMIRFuncTypes(*MainContext, *Mod, *WasmMod);
  StubBuilder.allocateStubSpace(NumInternalFunctions);
  StubBuilder.compileStubResolver();
  for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
    StubBuilder.compileFunctionToStub(I);
  }
  if (ThreadPool) {
    ThreadPool->pushTask(
        [this](WasmFrontendContext *Ctx) { dispatchEntryCompileTasks(*Ctx); });
  }
  uint32_t NumImportFunctions = WasmMod->getNumImportFunctions();
  for (uint32_t I = 0; I < NumInternalFunctions; ++I) {
    uint32_t RealFuncIdx = NumImportFunctions + I;
    CodeEntry *CE = WasmMod->getCodeEntry(RealFuncIdx);
    ZEN_ASSERT(CE);
    CE->JITCodePtr = StubBuilder.getFuncStubCodePtr(I);
    // JIT_DUMP_WRITE_FUNC(RealFuncIdx, CE->JITCodePtr,
    //                     MainContext.FuncSizeMap[FuncIdx]);
    // INSERT_JITED_FUNC_PTR((void *)(CE->JITCodePtr), RealFuncIdx);
  }
  Stats.stopRecord(Timer);
}

uint8_t *LazyJITCompiler::compileFunction(WasmFrontendContext &Ctx,
                                          uint32_t FuncIdx,
                                          bool DisableGreedyRA) {
  compileWasmToMC(Ctx, *Mod, FuncIdx, DisableGreedyRA);
  emitObjectBuffer(&Ctx);
  uint8_t *JITCode = const_cast<uint8_t *>(Ctx.CodeMPool->getMemStart());
  for (const auto &Reloc : Ctx.ExternRelocs) {
    uint64_t RelOffset = Ctx.CodeOffset + Reloc.Offset;
    uint64_t FuncSymValue =
        StubBuilder.getFuncStubCodePtr(Reloc.CalleeFuncIdx) - JITCode;
    uint64_t RelValue = FuncSymValue + Reloc.Addend - RelOffset;
    JITCode[RelOffset] = RelValue & 0xff;
    JITCode[RelOffset + 1] = (RelValue >> 8) & 0xff;
    JITCode[RelOffset + 2] = (RelValue >> 16) & 0xff;
    JITCode[RelOffset + 3] = (RelValue >> 24) & 0xff;
  }
  Ctx.ExternRelocs.clear();
  Ctx.FuncOffsetMap.clear();
  uint8_t *JITFuncCodePtr = Ctx.CodePtr;
  platform::mprotect(JITFuncCodePtr, TO_MPROTECT_CODE_SIZE(Ctx.CodeSize),
                     PROT_READ | PROT_EXEC);
  return JITFuncCodePtr;
}

void LazyJITCompiler::compileFunctionInBackgroud(WasmFrontendContext &Ctx,
                                                 uint32_t FuncIdx) {
  ZEN_LOG_DEBUG("compile function %d in background", FuncIdx);
  CompileStatuses[FuncIdx] = CompileStatus::InProgress;
  auto Timer = Stats.startRecord(utils::StatisticPhase::JITLazyBgCompilation);
  uint8_t *JITFuncCodePtr =
      compileFunction(Ctx, FuncIdx, Config.DisableMultipassGreedyRA);
  uint8_t *FuncStubCodePtr = StubBuilder.getFuncStubCodePtr(FuncIdx);
  GreedyRACodePtrs[FuncIdx] = JITFuncCodePtr;
  CompileStatuses[FuncIdx] = CompileStatus::Done;
  JITStubBuilder::updateStubJmpTargetPtr(FuncStubCodePtr, JITFuncCodePtr);
  Stats.stopRecord(Timer);
}

uint8_t *LazyJITCompiler::compileFunctionOnRequest(uint8_t *FuncStubCodePtr) {
  uint32_t FuncIdx = StubBuilder.getFuncIdxByStubCodePtr(FuncStubCodePtr);
  if (!ThreadPool) { // Single thread lazy mode
    auto Timer = Stats.startRecord(utils::StatisticPhase::JITLazyFgCompilation);
    uint8_t *JITFuncCodePtr =
        compileFunction(*MainContext, FuncIdx, Config.DisableMultipassGreedyRA);
    JITStubBuilder::updateStubJmpTargetPtr(FuncStubCodePtr, JITFuncCodePtr);
    Stats.stopRecord(Timer);
    return JITFuncCodePtr;
  }
  if (CompileStatuses[FuncIdx] == CompileStatus::Done) {
    return GreedyRACodePtrs[FuncIdx];
  }
  ZEN_LOG_DEBUG("compile function %d on request", FuncIdx);
  auto Timer = Stats.startRecord(utils::StatisticPhase::JITLazyFgCompilation);
  // Compile the function with fastRA for faster compilation
  uint8_t *JITFuncCodePtr = compileFunction(*MainContext, FuncIdx, true);
  Stats.stopRecord(Timer);
  if (CompileStatuses[FuncIdx] == CompileStatus::Done) {
    return GreedyRACodePtrs[FuncIdx];
  }
  JITStubBuilder::updateStubJmpTargetPtr(FuncStubCodePtr, JITFuncCodePtr);
  return JITFuncCodePtr;
}

std::pair<std::unique_ptr<MModule>, std::vector<void *>>
MIRTextJITCompiler::compile(CompileContext &Context, const char *Ptr,
                            size_t Size) {
  if (!Context.Inited) {
    Context.initialize();
  }
  Parser Parser(Context, Ptr, Size);
  std::unique_ptr<MModule> Mod = Parser.parse();
  for (uint32_t I = 0; I < Mod->getNumFunctions(); ++I) {
    MFunction &MFunc = *Mod->getFunction(I);
    CgFunction CgFunc(Context, MFunc);
    compileMIRToCgIR(*Mod, MFunc, CgFunc, false);
    Context.getMCLowering().runOnCgFunction(CgFunc);
  }
  emitObjectBuffer(&Context);
  std::vector<void *> FuncPtrs(Mod->getNumFunctions());
  platform::mprotect(Context.CodePtr, TO_MPROTECT_CODE_SIZE(Context.CodeSize),
                     PROT_READ | PROT_EXEC);
  for (const auto &[FuncIdx, FuncOffset] : Context.FuncOffsetMap) {
    FuncPtrs[FuncIdx] = Context.CodePtr + FuncOffset;
  }
  return {std::move(Mod), FuncPtrs};
}
