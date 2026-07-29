// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_compiler.h"
#include "common/thread_pool.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/evm_compiler_metrics.h"
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
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <cstring>
#include <string>

// Constants for memory protection alignment
const size_t MPROTECT_CHUNK_SIZE = 0x1000;
#define TO_MPROTECT_CODE_SIZE(CodeSize)                                        \
  ((((CodeSize) + MPROTECT_CHUNK_SIZE - 1) / MPROTECT_CHUNK_SIZE) *            \
   MPROTECT_CHUNK_SIZE)

namespace COMPILER {

namespace {

bool isCompilerObservationEnabled() {
  const char *Value = std::getenv("DTVM_EVM_COMPILER_OBSERVE");
  return Value != nullptr && Value[0] != '\0' && std::strcmp(Value, "0") != 0;
}

uint64_t fingerprintBytecode(const uint8_t *Bytecode, size_t BytecodeSize) {
  constexpr uint64_t FNVOffsetBasis = 14695981039346656037ULL;
  constexpr uint64_t FNVPrime = 1099511628211ULL;
  uint64_t Hash = FNVOffsetBasis;
  for (size_t Index = 0; Index < BytecodeSize; ++Index) {
    Hash ^= Bytecode[Index];
    Hash *= FNVPrime;
  }
  return Hash;
}

void emitMIRSnapshot(llvm::raw_ostream &OS,
                     const EVMCompilerMIRSnapshot &Snapshot) {
  OS << "{\"basic_blocks\":" << Snapshot.BasicBlocks
     << ",\"instructions\":" << Snapshot.Instructions
     << ",\"variables\":" << Snapshot.Variables
     << ",\"phi_instructions\":" << Snapshot.PhiInstructions
     << ",\"phi_incoming_edges\":" << Snapshot.PhiIncomingEdges << "}";
}

void emitCgSnapshot(llvm::raw_ostream &OS,
                    const EVMCompilerCgSnapshot &Snapshot) {
  OS << "{\"basic_blocks\":" << Snapshot.BasicBlocks
     << ",\"instructions\":" << Snapshot.Instructions
     << ",\"phi_instructions\":" << Snapshot.PhiInstructions
     << ",\"phi_incoming_edges\":" << Snapshot.PhiIncomingEdges
     << ",\"virtual_registers\":" << Snapshot.VirtualRegisters
     << ",\"stack_slot_loads\":" << Snapshot.StackSlotLoads
     << ",\"stack_slot_stores\":" << Snapshot.StackSlotStores << "}";
}

void emitCompilerObservation(const EVMCompilerObservation &Observation) {
  static constexpr const char *PhaseNames[] = {
      "context_setup",       "frontend",
      "mir_verify",          "mir_dce",
      "cg_lowering",         "phi_elimination",
      "register_allocation", "post_ra",
      "mc_lowering",         "object_emission",
      "code_publish",        "observation_overhead",
  };
  static_assert(std::size(PhaseNames) ==
                    static_cast<size_t>(EVMCompilerPhase::Count),
                "phase names must cover every EVM compiler observation phase");

  const uint64_t AccountedNs = Observation.getAccountedPhaseNs();
  const uint64_t UnaccountedNs =
      Observation.TotalNs > AccountedNs ? Observation.TotalNs - AccountedNs : 0;
  const double AccountedPercent =
      Observation.TotalNs == 0 ? 0.0
                               : static_cast<double>(AccountedNs) * 100.0 /
                                     static_cast<double>(Observation.TotalNs);

  std::string Record;
  llvm::raw_string_ostream OS(Record);
  OS << "{\"schema_version\":1"
     << ",\"compile_succeeded\":"
     << (Observation.CompileSucceeded ? "true" : "false")
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
     << ",\"stack_ssa_enabled\":true"
#else
     << ",\"stack_ssa_enabled\":false"
#endif
#ifdef ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK
     << ",\"memory_plan_framework_enabled\":true"
#else
     << ",\"memory_plan_framework_enabled\":false"
#endif
     << ",\"ra_mode\":\"" << (Observation.DisableGreedyRA ? "fast" : "greedy")
     << "\""
     << ",\"bytecode_size\":" << Observation.BytecodeSize
     << ",\"bytecode_fingerprint_fnv1a64\":\""
     << llvm::format_hex(Observation.BytecodeFingerprint, 18) << "\""
     << ",\"total_ns\":" << Observation.TotalNs
     << ",\"accounted_phase_ns\":" << AccountedNs
     << ",\"unaccounted_ns\":" << UnaccountedNs
     << ",\"accounted_percent\":" << AccountedPercent << ",\"phases_ns\":{";
  for (size_t Index = 0; Index < std::size(PhaseNames); ++Index) {
    if (Index != 0) {
      OS << ",";
    }
    OS << "\"" << PhaseNames[Index] << "\":" << Observation.PhaseNs[Index];
  }
  OS << "},\"stack_lift\":{"
     << "\"analyzed_blocks\":" << Observation.StackLift.AnalyzedBlocks
     << ",\"lifted_blocks\":" << Observation.StackLift.LiftedBlocks
     << ",\"non_lifted_blocks\":" << Observation.StackLift.NonLiftedBlocks
     << ",\"merge_blocks\":" << Observation.StackLift.MergeBlocks
     << ",\"merge_slots\":" << Observation.StackLift.MergeSlots
     << ",\"merge_predecessor_edges\":"
     << Observation.StackLift.MergePredecessorEdges
     << ",\"recorded_incoming_states\":"
     << Observation.StackLift.RecordedIncomingStates
     << ",\"folded_merge_slots\":" << Observation.StackLift.FoldedMergeSlots
     << ",\"materialization_requests\":"
     << Observation.StackLift.MaterializationRequests
     << ",\"protected_incoming_values\":"
     << Observation.StackLift.ProtectedIncomingValues
     << ",\"materialized_u256_merges\":"
     << Observation.StackLift.MaterializedU256Merges << "}"
     << ",\"mir_after_frontend\":";
  emitMIRSnapshot(OS, Observation.MIRAfterFrontend);
  OS << ",\"mir_after_dce\":";
  emitMIRSnapshot(OS, Observation.MIRAfterDCE);
  OS << ",\"cg_before_phi\":";
  emitCgSnapshot(OS, Observation.CgBeforePhi);
  OS << ",\"cg_after_phi\":";
  emitCgSnapshot(OS, Observation.CgAfterPhi);
  OS << ",\"cg_after_ra\":";
  emitCgSnapshot(OS, Observation.CgAfterRA);
  OS << ",\"cg_after_post_ra\":";
  emitCgSnapshot(OS, Observation.CgAfterPostRA);
  OS << ",\"phi_elimination\":{"
     << "\"phi_instructions\":" << Observation.PhiElimination.PhiInstructions
     << ",\"phi_incoming_edges\":"
     << Observation.PhiElimination.PhiIncomingEdges
     << ",\"candidate_edge_copies\":"
     << Observation.PhiElimination.CandidateEdgeCopies
     << ",\"identity_edge_copies\":"
     << Observation.PhiElimination.IdentityEdgeCopies
     << ",\"emitted_copy_instructions\":"
     << Observation.PhiElimination.EmittedCopyInstructions
     << ",\"split_critical_edges\":"
     << Observation.PhiElimination.SplitCriticalEdges << "}"
     << ",\"feature_coverage\":{"
     << "\"memory_expansion_plans\":"
     << Observation.FeatureCoverage.MemoryExpansionPlans
     << ",\"memory_expansion_plan_covered_ops\":"
     << Observation.FeatureCoverage.MemoryExpansionPlanCoveredOps
     << ",\"memory_expansion_plan_estimated_reduced_expansions\":"
     << Observation.FeatureCoverage
            .MemoryExpansionPlanEstimatedReducedExpansions
     << ",\"range_u64_fast_paths\":"
     << Observation.FeatureCoverage.RangeU64FastPaths
     << ",\"const_u64_fast_paths\":"
     << Observation.FeatureCoverage.ConstU64FastPaths
     << ",\"full_arithmetic_paths\":"
     << Observation.FeatureCoverage.FullArithmeticPaths << "}"
     << ",\"live_intervals_available\":"
     << (Observation.LiveIntervalsAvailable ? "true" : "false")
     << ",\"live_intervals\":" << Observation.LiveIntervals
     << ",\"emitted_code_bytes\":" << Observation.EmittedCodeBytes << "}";
  OS.flush();
  llvm::errs() << "[DTVM_EVM_COMPILER_OBSERVATION] " << Record << "\n";
}

} // namespace

void EVMJITCompiler::compileEVMToMC(EVMFrontendContext &Ctx, MModule &Mod,
                                    uint32_t FuncIdx, bool DisableGreedyRA,
                                    EVMCompilerObservation *Observation) {
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
  {
    EVMCompilerPhaseTimer PhaseTimer(Observation, EVMCompilerPhase::Frontend);
    MIRBuilder.compile(&Ctx);
  }
  if (Observation != nullptr && Observation->Enabled) {
    EVMCompilerPhaseTimer PhaseTimer(Observation,
                                     EVMCompilerPhase::ObservationOverhead);
    Observation->StackLift = MIRBuilder.getStackLiftStatistics();
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
    const auto Stats = MIRBuilder.getFeatureCoverageStatistics();
    Observation->FeatureCoverage.MemoryExpansionPlans =
        Stats.MemoryExpansionPlans;
    Observation->FeatureCoverage.MemoryExpansionPlanCoveredOps =
        Stats.MemoryExpansionPlanCoveredOps;
    Observation->FeatureCoverage.MemoryExpansionPlanEstimatedReducedExpansions =
        Stats.MemoryExpansionPlanEstimatedReducedExpansions;
    Observation->FeatureCoverage.RangeU64FastPaths = Stats.RangeU64FastPaths;
    Observation->FeatureCoverage.ConstU64FastPaths = Stats.ConstU64FastPaths;
    Observation->FeatureCoverage.FullArithmeticPaths =
        Stats.FullArithmeticPaths;
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  }
#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
  MIRBuilder.dumpMemoryCompileStats();
#endif // ZEN_ENABLE_MULTIPASS_JIT_LOGGING

  // Apply MIR optimizations and generate machine code
  compileMIRToCgIR(Mod, MFunc, CgFunc, DisableGreedyRA, Observation);

  // Generate machine code
  {
    EVMCompilerPhaseTimer PhaseTimer(Observation, EVMCompilerPhase::MCLowering);
    Ctx.getMCLowering().runOnCgFunction(CgFunc);
  }
}

void EagerEVMJITCompiler::compile() {
  EVMCompilerObservation Observation;
  Observation.Enabled = isCompilerObservationEnabled();
  Observation.BytecodeSize = EVMMod->CodeSize;
  if (Observation.Enabled) {
    Observation.BytecodeFingerprint = fingerprintBytecode(
        reinterpret_cast<const uint8_t *>(EVMMod->Code), EVMMod->CodeSize);
  }
  EVMCompilerObservation *ObservationPtr =
      Observation.Enabled ? &Observation : nullptr;
  EVMCompilerObservation::TimePoint ObservationStart;
  if (Observation.Enabled) {
    ObservationStart = EVMCompilerObservation::Clock::now();
  }

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
    {
      EVMCompilerPhaseTimer PhaseTimer(ObservationPtr,
                                       EVMCompilerPhase::ContextSetup);
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
      // empty so the JIT falls back to the unshifted GasChunkCost
      // automatically.
      const uint64_t *CostSPPPtr = Cache.GasChunkCostSPP.empty()
                                       ? nullptr
                                       : Cache.GasChunkCostSPP.data();
      Ctx.setGasChunkInfo(Cache.GasChunkEnd.data(), Cache.GasChunkCost.data(),
                          CostSPPPtr, EVMMod->CodeSize);
      Ctx.setResolvedJumpTargets(&Cache.ResolvedJumpTargets);
    }
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
    compileEVMToMC(Ctx, Mod, 0, Config.DisableMultipassGreedyRA,
                   ObservationPtr);
    {
      EVMCompilerPhaseTimer PhaseTimer(ObservationPtr,
                                       EVMCompilerPhase::ObjectEmission);
      emitObjectBuffer(&Ctx);
    }
    ZEN_ASSERT(Ctx.ExternRelocs.empty());

    {
      EVMCompilerPhaseTimer PhaseTimer(ObservationPtr,
                                       EVMCompilerPhase::CodePublish);
      uint8_t *JITFuncPtr = Ctx.CodePtr + Ctx.FuncOffsetMap[0];
      EVMMod->setEmittedJITCodeSize(Ctx.CodeSize);
      if (Observation.Enabled) {
        Observation.EmittedCodeBytes = Ctx.CodeSize;
      }
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
      // page-aligned mempool start) so the entire executable buffer becomes
      // RX. The size we publish, however, must be measured from JITFuncPtr
      // (the actual function entry we hand to the runtime); otherwise
      // consumers that compute getJITCode() + getJITCodeSize() — e.g. trap
      // handlers — would walk past the end of the allocation.
      size_t MProtectSize = CodeMPool.getMemEnd() - JITCode;
      platform::mprotect(JITCode, TO_MPROTECT_CODE_SIZE(MProtectSize),
                         PROT_READ | PROT_EXEC);
      size_t PublishedCodeSize = CodeMPool.getMemEnd() - JITFuncPtr;
      // Publish JITFuncPtr only after mprotect — atomic release ensures the
      // interpreter thread sees fully executable code.
      EVMMod->setJITCodeAndSize(JITFuncPtr, PublishedCodeSize);
    }

    Committed = true;
    Observation.CompileSucceeded = true;
  } catch (const std::exception &E) {
    ZEN_LOG_ERROR("EVM JIT compilation failed: %s", E.what());
    EVMMod->ShouldFallbackToInterp = true;
  } catch (...) {
    ZEN_LOG_ERROR("EVM JIT compilation failed");
    EVMMod->ShouldFallbackToInterp = true;
  }
  if (Observation.Enabled) {
    const auto ObservationEnd = EVMCompilerObservation::Clock::now();
    Observation.TotalNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(ObservationEnd -
                                                             ObservationStart)
            .count());
    emitCompilerObservation(Observation);
  }
}
} // namespace COMPILER
