// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_lazy_compiler.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/mir/module.h"
#include "compiler/target/x86/x86_mc_lowering.h"
#include "evm/evm_cache.h"
#include "evmc/instructions.h"
#include "platform/map.h"
#include "utils/statistics.h"

#ifdef ZEN_ENABLE_LINUX_PERF
#include "utils/perf.h"
#endif

#include "llvm/ADT/SmallVector.h"

// Constants for memory protection alignment
static const size_t MPROTECT_CHUNK_SIZE_LAZY = 0x1000;
#define TO_MPROTECT_CODE_SIZE_LAZY(CodeSize)                                   \
  ((((CodeSize) + MPROTECT_CHUNK_SIZE_LAZY - 1) / MPROTECT_CHUNK_SIZE_LAZY) *  \
   MPROTECT_CHUNK_SIZE_LAZY)

namespace COMPILER {

// ============================================================================
// EVMSegmentAnalyzer Implementation
// ============================================================================

void EVMSegmentAnalyzer::analyze(const zen::common::Byte *Code, size_t CodeSize,
                                 evmc_revision Rev) {
  Segments.clear();
  PCToSegmentIdx.clear();

  if (CodeSize == 0) {
    return;
  }

  // Get instruction metrics for opcode length calculation
  const auto *Metrics = evmc_get_instruction_metrics_table(Rev);
  if (!Metrics) {
    Metrics = evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
  }

  // First pass: identify all JUMPDEST positions
  std::vector<uint32_t> JumpDestPCs;
  for (size_t PC = 0; PC < CodeSize;) {
    uint8_t OpcodeU8 = static_cast<uint8_t>(Code[PC]);
    if (OpcodeU8 == static_cast<uint8_t>(OP_JUMPDEST)) {
      JumpDestPCs.push_back(static_cast<uint32_t>(PC));
    }
    // Advance past PUSH immediate bytes
    if (OpcodeU8 >= static_cast<uint8_t>(OP_PUSH1) &&
        OpcodeU8 <= static_cast<uint8_t>(OP_PUSH32)) {
      uint8_t NumBytes = OpcodeU8 - static_cast<uint8_t>(OP_PUSH1) + 1;
      PC += 1 + NumBytes;
    } else {
      PC += 1;
    }
  }

  // Build segments: each segment starts at PC=0 or a JUMPDEST
  // The entry segment always exists (from PC=0)
  uint32_t SegIdx = 0;

  // Check if PC=0 is a JUMPDEST
  bool StartsWithJumpDest =
      CodeSize > 0 &&
      static_cast<uint8_t>(Code[0]) == static_cast<uint8_t>(OP_JUMPDEST);

  if (!StartsWithJumpDest) {
    // Entry segment from PC=0 to first JUMPDEST (or end)
    uint32_t EndPC =
        JumpDestPCs.empty() ? static_cast<uint32_t>(CodeSize) : JumpDestPCs[0];
    EVMSegmentInfo Seg;
    Seg.SegmentIdx = SegIdx;
    Seg.StartPC = 0;
    Seg.EndPC = EndPC;
    Seg.IsEntry = true;
    Seg.IsJumpDest = false;
    Segments.push_back(Seg);
    PCToSegmentIdx[0] = SegIdx;
    SegIdx++;
  }

  // Create segments for JUMPDESTs, merging consecutive JUMPDESTs into one
  // segment. Each JUMPDEST PC is still mapped to the containing segment so
  // cross-segment jumps can find the right segment. Within the merged segment,
  // each JUMPDEST gets its own basic block, so jumps to any JUMPDEST in the
  // run land at the correct BB (avoiding extra gas metering).
  for (size_t I = 0; I < JumpDestPCs.size();) {
    uint32_t StartPC = JumpDestPCs[I];

    // Find the end of the consecutive JUMPDEST run
    size_t RunEnd = I + 1;
    while (RunEnd < JumpDestPCs.size() &&
           JumpDestPCs[RunEnd] == JumpDestPCs[RunEnd - 1] + 1) {
      RunEnd++;
    }

    // EndPC is the start of the next non-consecutive JUMPDEST, or CodeSize
    uint32_t EndPC = (RunEnd < JumpDestPCs.size())
                         ? JumpDestPCs[RunEnd]
                         : static_cast<uint32_t>(CodeSize);

    EVMSegmentInfo Seg;
    Seg.SegmentIdx = SegIdx;
    Seg.StartPC = StartPC;
    Seg.EndPC = EndPC;
    Seg.IsEntry = (StartPC == 0);
    Seg.IsJumpDest = true;
    Segments.push_back(Seg);

    // Map every JUMPDEST PC in this run to the same segment
    for (size_t J = I; J < RunEnd; ++J) {
      PCToSegmentIdx[JumpDestPCs[J]] = SegIdx;
    }
    SegIdx++;

    I = RunEnd;
  }
}

uint32_t EVMSegmentAnalyzer::getSegmentIdxForPC(uint32_t PC) const {
  auto It = PCToSegmentIdx.find(PC);
  if (It != PCToSegmentIdx.end()) {
    return It->second;
  }
  return UINT32_MAX;
}

uint32_t EVMSegmentAnalyzer::getSegmentIdxContainingPC(uint32_t PC) const {
  // Fast path: exact match on StartPC
  auto It = PCToSegmentIdx.find(PC);
  if (It != PCToSegmentIdx.end()) {
    return It->second;
  }
  // Range lookup: PCToSegmentIdx is ordered by StartPC.
  // upper_bound(PC) gives the first segment with StartPC > PC.
  // The previous entry (if any) is the candidate.
  auto Upper = PCToSegmentIdx.upper_bound(PC);
  if (Upper != PCToSegmentIdx.begin()) {
    --Upper;
    uint32_t SegIdx = Upper->second;
    if (SegIdx < Segments.size() && PC < Segments[SegIdx].EndPC) {
      return SegIdx;
    }
  }
  return UINT32_MAX;
}

// ============================================================================
// LazyEVMJITCompiler Implementation
// ============================================================================

LazyEVMJITCompiler::LazyEVMJITCompiler(runtime::EVMModule *EVMMod)
    : EVMJITCompiler(EVMMod) {
  MainContext = new EVMFrontendContext();
  MainContext->Lazy = true;
  MainContext->setGasMeteringEnabled(Config.EnableEvmGasMetering);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
  MainContext->setGasRegisterEnabled(true);
#endif
  MainContext->setRevision(EVMMod->getRevision());
  MainContext->setBytecode(
      reinterpret_cast<const zen::common::Byte *>(EVMMod->Code),
      EVMMod->CodeSize);
  const auto &Cache = EVMMod->getBytecodeCache();
  MainContext->setGasChunkInfo(Cache.GasChunkEnd.data(),
                               Cache.GasChunkCost.data(), EVMMod->CodeSize);
  MainContext->CodeMPool = &EVMMod->getJITCodeMemPool();

  Mod = MainContext->ThreadMemPool.newObject<MModule>(*MainContext);
  buildEVMFunction(*MainContext, *Mod, *EVMMod);
}

LazyEVMJITCompiler::~LazyEVMJITCompiler() {
  if (ThreadPool) {
    ThreadPool->interrupt();
  }
  if (Mod) {
    MainContext->ThreadMemPool.deleteObject(Mod);
  }
  delete MainContext;
}

void LazyEVMJITCompiler::precompile() {
  auto Timer =
      Stats.startRecord(zen::utils::StatisticPhase::JITLazyPrecompilation);

  // Step 1: Analyze bytecode into segments
  SegmentAnalyzer.analyze(
      reinterpret_cast<const zen::common::Byte *>(EVMMod->Code),
      EVMMod->CodeSize, EVMMod->getRevision());

  uint32_t NumSegments = SegmentAnalyzer.getNumSegments();

  // Handle empty bytecode case
  if (NumSegments == 0) {
    // For empty bytecode, still need to compile something
    compileEVMToMC(*MainContext, *Mod, 0, Config.DisableMultipassGreedyRA);
    emitObjectBuffer(MainContext);
    ZEN_ASSERT(MainContext->ExternRelocs.empty());

    auto &CodeMPool = EVMMod->getJITCodeMemPool();
    uint8_t *JITCode = const_cast<uint8_t *>(CodeMPool.getMemStart());

    EntryCodePtr = MainContext->CodePtr + MainContext->FuncOffsetMap[0];
    EVMMod->setJITCodeAndSize(EntryCodePtr, MainContext->CodeSize);

    size_t CodeSize = CodeMPool.getMemEnd() - JITCode;
    zen::platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE_LAZY(CodeSize),
                            PROT_READ | PROT_EXEC);
    EVMMod->setJITCodeAndSize(JITCode, CodeSize);

    Stats.stopRecord(Timer);
    return;
  }

  // For single-segment case, compile eagerly like EagerEVMJITCompiler
  // to avoid stub overhead when there is only one segment
  if (NumSegments == 1) {
    EVMFrontendContext FreshCtx;
    FreshCtx.setGasMeteringEnabled(Config.EnableEvmGasMetering);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
    FreshCtx.setGasRegisterEnabled(true);
#endif
    FreshCtx.setRevision(EVMMod->getRevision());
    FreshCtx.setBytecode(
        reinterpret_cast<const zen::common::Byte *>(EVMMod->Code),
        EVMMod->CodeSize);
    const auto &Cache = EVMMod->getBytecodeCache();
    FreshCtx.setGasChunkInfo(Cache.GasChunkEnd.data(),
                             Cache.GasChunkCost.data(), EVMMod->CodeSize);

    MModule FreshMod(FreshCtx);
    buildEVMFunction(FreshCtx, FreshMod, *EVMMod);
    FreshCtx.CodeMPool = &EVMMod->getJITCodeMemPool();

    auto &CodeMPool = EVMMod->getJITCodeMemPool();
    uint8_t *JITCode = const_cast<uint8_t *>(CodeMPool.getMemStart());

    compileEVMToMC(FreshCtx, FreshMod, 0, Config.DisableMultipassGreedyRA);
    emitObjectBuffer(&FreshCtx);
    ZEN_ASSERT(FreshCtx.ExternRelocs.empty());

    uint8_t *JITFuncPtr = FreshCtx.CodePtr + FreshCtx.FuncOffsetMap[0];
    EVMMod->setJITCodeAndSize(JITFuncPtr, FreshCtx.CodeSize);

    size_t CodeSize = CodeMPool.getMemEnd() - JITCode;
    zen::platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE_LAZY(CodeSize),
                            PROT_READ | PROT_EXEC);
    EVMMod->setJITCodeAndSize(JITCode, CodeSize);

    Stats.stopRecord(Timer);
    return;
  }

  ZEN_LOG_DEBUG("EVM lazy compile: %u segments identified", NumSegments);

  // Copy PC to segment index map from analyzer
  const auto &AnalyzerSegments = SegmentAnalyzer.getSegments();
  PCToSegmentIdx.clear();
  for (const auto &Seg : AnalyzerSegments) {
    PCToSegmentIdx[Seg.StartPC] = Seg.SegmentIdx;
  }

  // Initialize per-segment state
  CompileStatuses = std::make_unique<std::atomic<CompileStatus>[]>(NumSegments);
  SegmentCodePtrs = std::make_unique<std::atomic<uint8_t *>[]>(NumSegments);
  SegmentStubPtrs.resize(NumSegments, nullptr);

  for (uint32_t I = 0; I < NumSegments; ++I) {
    CompileStatuses[I] = CompileStatus::None;
    SegmentCodePtrs[I] = nullptr;
  }

  // Step 2: Create stubs for all segments (like WASM does for functions)
  StubBuilder =
      std::make_unique<EVMSegmentStubBuilder>(EVMMod->getJITCodeMemPool());
  SegmentJumpTable = std::make_unique<uint8_t *[]>(NumSegments);

  // Allocate stub space and compile resolver
  StubBuilder->allocateStubSpace(NumSegments);
  StubBuilder->compileStubResolver(this);

  // Create stubs for all segments
  for (const auto &Seg : AnalyzerSegments) {
    StubBuilder->compileSegmentToStub(Seg.SegmentIdx, Seg.StartPC);
    uint8_t *StubPtr = StubBuilder->getSegmentStubCodePtr(Seg.SegmentIdx);
    SegmentStubPtrs[Seg.SegmentIdx] = StubPtr;
    SegmentJumpTable[Seg.SegmentIdx] = StubPtr;
  }

  // Step 3: Set up context with segment jump table for lazy indirect jumps
  MainContext->setSegmentJumpTable(SegmentJumpTable.get());
  MainContext->setNumSegments(NumSegments);
  MainContext->setPCToSegmentIdxMap(&PCToSegmentIdx);

  // Step 4: LAZY COMPILATION - Set module's JIT code to entry segment's stub
  // The actual compilation happens when the stub is called
  // Find the entry segment
  uint32_t EntrySegIdx = UINT32_MAX;
  for (const auto &Seg : AnalyzerSegments) {
    if (Seg.IsEntry) {
      EntrySegIdx = Seg.SegmentIdx;
      break;
    }
  }

  if (EntrySegIdx == UINT32_MAX) {
    ZEN_LOG_ERROR("EVM lazy compile: No entry segment found");
    Stats.stopRecord(Timer);
    return;
  }

  // Set module's entry point to the entry segment's stub
  // When called, the stub will trigger compileSegmentOnRequest
  EntryCodePtr = SegmentStubPtrs[EntrySegIdx];
  EVMMod->setJITCodeAndSize(EntryCodePtr, 0);

  Stats.stopRecord(Timer);
}

uint8_t *LazyEVMJITCompiler::compileSegmentOnRequest(uint32_t SegmentIdx) {
  uint32_t NumSegments = SegmentAnalyzer.getNumSegments();

  if (!CompileStatuses || !SegmentCodePtrs || SegmentIdx >= NumSegments) {
    return nullptr;
  }

  // Fast path: already compiled
  if (CompileStatuses[SegmentIdx] == CompileStatus::Done) {
    return SegmentCodePtrs[SegmentIdx];
  }

  // Slow path: compile on demand with thread safety
  std::lock_guard<std::mutex> Lock(ForegroundMutex);

  auto Timer =
      Stats.startRecord(zen::utils::StatisticPhase::JITLazyFgCompilation);

  // Re-check after acquiring lock: validate arrays and index again
  NumSegments = SegmentAnalyzer.getNumSegments();
  if (!CompileStatuses || !SegmentCodePtrs || SegmentIdx >= NumSegments) {
    Stats.stopRecord(Timer);
    return nullptr;
  }

  // Double-check after acquiring lock
  if (CompileStatuses[SegmentIdx] == CompileStatus::Done) {
    Stats.stopRecord(Timer);
    return SegmentCodePtrs[SegmentIdx];
  }

  ZEN_LOG_DEBUG(
      "EVM lazy compile: on-demand compilation triggered by segment %u",
      SegmentIdx);

  // Compile only the requested segment
  uint8_t *CodePtr = compileSegment(*MainContext, SegmentIdx);
  if (!CodePtr) {
    Stats.stopRecord(Timer);
    return nullptr;
  }

  // Mark this segment as compiled
  CompileStatuses[SegmentIdx] = CompileStatus::Done;
  SegmentCodePtrs[SegmentIdx] = CodePtr;
  SegmentJumpTable[SegmentIdx] = CodePtr;

  // Find and patch the requested segment's stub to jump to compiled code
  uint8_t *SegmentStubPtr = SegmentStubPtrs[SegmentIdx];
  if (SegmentStubPtr && CodePtr) {
    EVMSegmentStubBuilder::updateStubJmpTargetPtr(SegmentStubPtr, CodePtr);
  }

  ZEN_LOG_DEBUG("EVM lazy compile: bytecode compiled at %p, size %lu",
                (void *)CodePtr, MainContext->CodeSize);

  Stats.stopRecord(Timer);
  return CodePtr;
}

uint8_t *LazyEVMJITCompiler::getSegmentCodePtr(uint32_t SegmentIdx) const {
  if (SegmentIdx < SegmentAnalyzer.getNumSegments()) {
    return SegmentCodePtrs[SegmentIdx];
  }
  return nullptr;
}

bool LazyEVMJITCompiler::isSegmentCompiled(uint32_t SegmentIdx) const {
  if (SegmentIdx < SegmentAnalyzer.getNumSegments()) {
    return CompileStatuses[SegmentIdx] == CompileStatus::Done;
  }
  return false;
}

uint8_t *LazyEVMJITCompiler::compileSegment(EVMFrontendContext &Ctx,
                                            uint32_t SegmentIdx) {
  const auto &Segments = SegmentAnalyzer.getSegments();
  if (SegmentIdx >= Segments.size()) {
    ZEN_LOG_ERROR("EVM lazy compile: Invalid segment index %u", SegmentIdx);
    return nullptr;
  }

  const auto &Seg = Segments[SegmentIdx];

  ZEN_LOG_DEBUG("EVM lazy compile: compiling segment %u (PC %u-%u)", SegmentIdx,
                Seg.StartPC, Seg.EndPC);

  Ctx.setSegmentBounds(Seg.StartPC, Seg.EndPC);
  Ctx.setSegmentJumpTable(SegmentJumpTable.get());
  Ctx.setNumSegments(Segments.size());
  Ctx.setPCToSegmentIdxMap(&PCToSegmentIdx);

  MModule SegmentMod(Ctx);
  buildEVMFunction(Ctx, SegmentMod, *EVMMod);

  // Compile only this segment's bytecode range
  compileEVMToMC(Ctx, SegmentMod, 0, Config.DisableMultipassGreedyRA);
  emitObjectBuffer(&Ctx);

  uint8_t *CodePtr = Ctx.CodePtr + Ctx.FuncOffsetMap[0];

  // Only mprotect the compiled code, not the entire memory pool
  // This keeps stubs writable for future patching
  zen::platform::mprotect(Ctx.CodePtr, TO_MPROTECT_CODE_SIZE_LAZY(Ctx.CodeSize),
                          PROT_READ | PROT_EXEC);

  ZEN_LOG_DEBUG("EVM lazy compile: segment %u compiled at %p, size %lu",
                SegmentIdx, (void *)CodePtr, Ctx.CodeSize);

  return CodePtr;
}

void LazyEVMJITCompiler::compileSegmentInBackground(EVMFrontendContext &Ctx,
                                                    uint32_t SegmentIdx) {
  ZEN_LOG_DEBUG("EVM lazy compile: compiling segment %u in background",
                SegmentIdx);
  CompileStatuses[SegmentIdx] = CompileStatus::InProgress;

  auto Timer =
      Stats.startRecord(zen::utils::StatisticPhase::JITLazyBgCompilation);

  uint8_t *CodePtr = compileSegment(Ctx, SegmentIdx);
  SegmentCodePtrs[SegmentIdx] = CodePtr;
  CompileStatuses[SegmentIdx] = CompileStatus::Done;

  Stats.stopRecord(Timer);
}

void LazyEVMJITCompiler::dispatchBackgroundTasks() {
  if (!ThreadPool) {
    return;
  }

  uint32_t NumSegments = SegmentAnalyzer.getNumSegments();
  for (uint32_t I = 0; I < NumSegments; ++I) {
    if (CompileStatuses[I] != CompileStatus::None) {
      continue;
    }
    CompileStatuses[I] = CompileStatus::Pending;
    ThreadPool->pushTask([this, I](EVMFrontendContext *Ctx) {
      compileSegmentInBackground(*Ctx, I);
    });
  }
}

void LazyEVMJITCompiler::buildSegmentJumpTable() {
  // This method builds a mapping from JUMPDEST PCs to segment code pointers.
  // In the current implementation where the full bytecode is compiled as one
  // function, this is not needed. It will be used when true segment-level
  // compilation is implemented.
}

} // namespace COMPILER
