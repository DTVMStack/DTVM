// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_compiler.h"
#include "common/thread_pool.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/mir/module.h"
#include "compiler/target/x86/x86_mc_lowering.h"
#include "platform/map.h"
#include "utils/statistics.h"

#ifdef ZEN_ENABLE_LINUX_PERF
#include "utils/perf.h"
#endif // ZEN_ENABLE_LINUX_PERF

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#include "llvm/Support/Debug.h"
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
#include "llvm/ADT/SmallVector.h"

// Constants for memory protection alignment
const size_t MPROTECT_CHUNK_SIZE = 0x1000;
#define TO_MPROTECT_CODE_SIZE(CodeSize)                                        \
  ((((CodeSize) + MPROTECT_CHUNK_SIZE - 1) / MPROTECT_CHUNK_SIZE) *            \
   MPROTECT_CHUNK_SIZE)

namespace COMPILER {

void EVMJITCompiler::compileEVMToMC(EVMFrontendContext &Ctx, MModule &Mod,
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

  // Create MFunction for EVM bytecode compilation
  MFunction MFunc(Ctx, FuncIdx);
  CgFunction CgFunc(Ctx, MFunc);

  // Set up EVM MIR builder
  EVMMirBuilder MIRBuilder(Ctx, MFunc);

  // Set bytecode for compilation
  MFunc.setFunctionType(Mod.getFuncType(FuncIdx));

  // Compile EVM bytecode to MIR
  MIRBuilder.compile(&Ctx);

  // Apply MIR optimizations and generate machine code
  compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA);

  // Generate machine code
  Ctx.getMCLowering().runOnCgFunction(CgFunc);
}

void EagerEVMJITCompiler::compile() {
  auto Timer = Stats.startRecord(zen::utils::StatisticPhase::JITCompilation);

  EVMFrontendContext Ctx;
  Ctx.setGasMeteringEnabled(Config.EnableEvmGasMetering);
  Ctx.setBytecode(reinterpret_cast<const Byte *>(EVMMod->Code),
                  EVMMod->CodeSize);
  auto &MainMemPool = Ctx.ThreadMemPool;

  // Create MModule for EVM
  MModule Mod(Ctx);

  // Create function type for EVM (only one func in EVM)
  MType *VoidType = &Ctx.VoidType;
  MType *I64Type = &Ctx.I64Type;
  llvm::SmallVector<MType *, 1> Params = {I64Type};
  MFunctionType *FuncType = MFunctionType::create(Ctx, *VoidType, Params);
  Mod.addFuncType(FuncType);

  Ctx.CodeMPool = &EVMMod->getJITCodeMemPool();

#ifdef ZEN_ENABLE_LINUX_PERF
  utils::JitDumpWriter JitDumpWriter;
#define JIT_DUMP_WRITE_FUNC(FuncIdx, FuncAddr, FuncSize)                       \
  JitDumpWriter.writeFunc("EVM_Main", reinterpret_cast<uint64_t>(FuncAddr),    \
                          FuncSize)
#else
#define JIT_DUMP_WRITE_FUNC(...)
#endif

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  auto &SortedJITFuncPtrs = EVMMod->getSortedJITFuncPtrs();
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

  auto &CodeMPool = EVMMod->getJITCodeMemPool();
  uint8_t *JITCode = const_cast<uint8_t *>(CodeMPool.getMemStart());

  if (Config.DisableMultipassMultithread) {
    // Single-threaded compilation
    compileEVMToMC(Ctx, Mod, 0, Config.DisableMultipassGreedyRA);
    emitObjectBuffer(&Ctx);
    ZEN_ASSERT(Ctx.ExternRelocs.empty());

    // Since EVM has only 1 function, handle it directly
    uint8_t *JITFuncPtr = Ctx.CodePtr + Ctx.FuncOffsetMap[0];
    EVMMod->setJITCodeAndSize(JITFuncPtr, Ctx.CodeSize);
    JIT_DUMP_WRITE_FUNC(0, JITFuncPtr, Ctx.FuncSizeMap[0]);
    INSERT_JITED_FUNC_PTR((void *)(JITFuncPtr), 0);
  } else {
    // Multi-threaded compilation (though EVM has only 1 function)
    common::ThreadPool<EVMFrontendContext> ThreadPool(1);
    uint32_t NumThreads = ThreadPool.getThreadCount();
    ZEN_LOG_DEBUG("using %u threads for multipass EVM JIT compilation",
                  NumThreads);

    CompileVector<EVMFrontendContext> AuxContexts(NumThreads - 1, Ctx,
                                                  MainMemPool);
    CompileVector<EVMFrontendContext *> Contexts(MainMemPool);

    ThreadPool.setThreadContext(0, &Ctx, emitObjectBuffer);
    Contexts.push_back(&Ctx);
    for (uint32_t I = 0; I < NumThreads - 1; ++I) {
      ThreadPool.setThreadContext(I + 1, &AuxContexts[I], emitObjectBuffer);
      Contexts.push_back(&AuxContexts[I]);
    }

    // 0: func index(only one func in EVM)
    ThreadPool.pushTask([&](EVMFrontendContext *Ctx) {
      compileEVMToMC(*Ctx, Mod, 0, Config.DisableMultipassGreedyRA);
    });

    ThreadPool.setNoNewTask();
    ThreadPool.waitForTasks();

    // Since EVM has only one function, process the result
    for (EVMFrontendContext *Ctx : Contexts) {
      if (!Ctx->FuncOffsetMap.empty()) {
        uint8_t *JITFuncPtr = Ctx->CodePtr + Ctx->FuncOffsetMap[0];
        EVMMod->setJITCodeAndSize(JITFuncPtr, Ctx->CodeSize);
        JIT_DUMP_WRITE_FUNC(0, JITFuncPtr, Ctx->FuncSizeMap[0]);
        INSERT_JITED_FUNC_PTR((void *)(JITFuncPtr), 0);
      }
    }
  }

  size_t CodeSize = CodeMPool.getMemEnd() - JITCode;
  platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE(CodeSize),
                     PROT_READ | PROT_EXEC);
  EVMMod->setJITCodeAndSize(JITCode, CodeSize);

  SORT_JITED_FUNC_PTRS;

  Stats.stopRecord(Timer);
}
} // namespace COMPILER
