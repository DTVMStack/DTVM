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
  MFunc.setFunctionType(Mod.getFuncType(FuncIdx));
  EVMMirBuilder MIRBuilder(Ctx, MFunc);
  MIRBuilder.compile(&Ctx);
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  MIRBuilder.dumpMemoryCompileStats();
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

  // Apply MIR optimizations and generate machine code
  compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA);

  // Generate machine code
  Ctx.getMCLowering().runOnCgFunction(CgFunc);
}

void EagerEVMJITCompiler::compile() {
  // Start the timer outside the try-block so a scope guard can always release
  // the in-flight TimerPair, even if the body throws. On the success path we
  // set Committed = true and the guard switches to stopRecord(); on any
  // exception path it falls back to revertRecord() and avoids leaking the
  // stack entry maintained by Statistics.
  auto Timer = Stats.startRecord(zen::utils::StatisticPhase::JITCompilation);
  bool Committed = false;
  // Capture by reference so the destructor sees the final Committed value.
  // StatisticTimer is a private type alias, so we keep the guard's captures
  // generic via auto/templated lambda + a small RAII shim.
  auto Finalize = [&Stats = this->Stats, Timer, &Committed]() noexcept {
    if (Committed) {
      Stats.stopRecord(Timer);
    } else {
      Stats.revertRecord(Timer);
    }
  };
  struct TimerScopeGuard {
    decltype(Finalize) F;
    ~TimerScopeGuard() { F(); }
  } TimerGuard{Finalize};

  try {
    EVMFrontendContext Ctx;
    Ctx.setGasMeteringEnabled(Config.EnableEvmGasMetering);
#ifdef ZEN_ENABLE_EVM_GAS_REGISTER
    Ctx.setGasRegisterEnabled(true);
#endif
    Ctx.setRevision(EVMMod->getRevision());
    Ctx.setBytecode(reinterpret_cast<const Byte *>(EVMMod->Code),
                    EVMMod->CodeSize);
    Ctx.setMemoryLinearStrideSkipLeadingZeroLimbStores(
        EVMMod->getMemoryLinearStrideSkipLeadingZeroLimbStores());
    const auto &Cache = EVMMod->getBytecodeCache();
    // GasChunkCostSPP is only allocated when the SPP metering pipeline runs
    // (i.e. this module will be JIT-compiled). Pass nullptr when the array is
    // empty so the JIT falls back to the unshifted GasChunkCost automatically.
    const uint64_t *CostSPPPtr =
        Cache.GasChunkCostSPP.empty() ? nullptr : Cache.GasChunkCostSPP.data();
    Ctx.setGasChunkInfo(Cache.GasChunkEnd.data(), Cache.GasChunkCost.data(),
                        CostSPPPtr, EVMMod->CodeSize);
    Ctx.setResolvedJumpTargets(&Cache.ResolvedJumpTargets);
    MModule Mod(Ctx);
    buildEVMFunction(Ctx, Mod, *EVMMod);
    Ctx.CodeMPool = &EVMMod->getJITCodeMemPool();

#ifdef ZEN_ENABLE_LINUX_PERF
    utils::JitDumpWriter JitDumpWriter;
#define JIT_DUMP_WRITE_FUNC(FuncName, FuncAddr, FuncSize)                      \
  JitDumpWriter.writeFunc(FuncName, reinterpret_cast<uint64_t>(FuncAddr),      \
                          FuncSize)
#else
#define JIT_DUMP_WRITE_FUNC(...)
#endif // ZEN_ENABLE_LINUX_PERF

    auto &CodeMPool = EVMMod->getJITCodeMemPool();
    uint8_t *JITCode = const_cast<uint8_t *>(CodeMPool.getMemStart());

    // EVM has only 1 function, use direct single-threaded compilation
    compileEVMToMC(Ctx, Mod, 0, Config.DisableMultipassGreedyRA);
    emitObjectBuffer(&Ctx);
    ZEN_ASSERT(Ctx.ExternRelocs.empty());

    uint8_t *JITFuncPtr = Ctx.CodePtr + Ctx.FuncOffsetMap[0];
#ifdef ZEN_ENABLE_LINUX_PERF
    // Write block symbols instead of EVM_Main
    // JIT_DUMP_WRITE_FUNC("EVM_Main", JITFuncPtr, Ctx.FuncSizeMap[0]);
    for (const auto &[BBIdx, BBSymOffset] : Ctx.FuncOffsetMap) {
      if (BBIdx == 0) {
        continue;
      }
      uint8_t *BBCode = Ctx.CodePtr + BBSymOffset;
      JIT_DUMP_WRITE_FUNC(Ctx.FuncNameMap[BBIdx], BBCode,
                          Ctx.FuncSizeMap[BBIdx]);
    }
#endif
    // mprotect must cover the whole code mempool starting from JITCode (the
    // page-aligned mempool start) so the entire executable buffer becomes RX.
    // The size we publish, however, must be measured from JITFuncPtr (the
    // actual function entry we hand to the runtime); otherwise consumers that
    // compute getJITCode() + getJITCodeSize() — e.g. trap handlers — would
    // walk past the end of the allocation.
    size_t MProtectSize = CodeMPool.getMemEnd() - JITCode;
    platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE(MProtectSize),
                       PROT_READ | PROT_EXEC);
    size_t PublishedCodeSize = CodeMPool.getMemEnd() - JITFuncPtr;
    // Publish JITFuncPtr only after mprotect — atomic release ensures the
    // interpreter thread sees fully executable code.
    EVMMod->setJITCodeAndSize(JITFuncPtr, PublishedCodeSize);

    Committed = true;
  } catch (const std::exception &E) {
    ZEN_LOG_ERROR("EVM JIT compilation failed: %s", E.what());
  } catch (...) {
    ZEN_LOG_ERROR("EVM JIT compilation failed");
  }
}
} // namespace COMPILER
