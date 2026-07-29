// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_EVM_COMPILER_METRICS_H
#define ZEN_COMPILER_EVM_COMPILER_METRICS_H

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace COMPILER {

struct EVMLiftedStackStatistics {
  uint64_t AnalyzedBlocks = 0;
  uint64_t LiftedBlocks = 0;
  uint64_t NonLiftedBlocks = 0;
  uint64_t MergeBlocks = 0;
  uint64_t MergeSlots = 0;
  uint64_t MergePredecessorEdges = 0;
  uint64_t RecordedIncomingStates = 0;
  uint64_t FoldedMergeSlots = 0;
  uint64_t MaterializationRequests = 0;
  uint64_t ProtectedIncomingValues = 0;
  uint64_t MaterializedU256Merges = 0;
};

enum class EVMCompilerPhase : uint8_t {
  ContextSetup = 0,
  Frontend,
  MIRVerify,
  MIRDCE,
  CgLowering,
  PhiElimination,
  RegisterAllocation,
  PostRA,
  MCLowering,
  ObjectEmission,
  CodePublish,
  ObservationOverhead,
  Count,
};

struct EVMCompilerMIRSnapshot {
  uint64_t BasicBlocks = 0;
  uint64_t Instructions = 0;
  uint64_t Variables = 0;
  uint64_t PhiInstructions = 0;
  uint64_t PhiIncomingEdges = 0;
};

struct EVMCompilerCgSnapshot {
  uint64_t BasicBlocks = 0;
  uint64_t Instructions = 0;
  uint64_t PhiInstructions = 0;
  uint64_t PhiIncomingEdges = 0;
  uint64_t VirtualRegisters = 0;
  uint64_t StackSlotLoads = 0;
  uint64_t StackSlotStores = 0;
};

struct EVMCompilerPhiEliminationMetrics {
  uint64_t PhiInstructions = 0;
  uint64_t PhiIncomingEdges = 0;
  uint64_t CandidateEdgeCopies = 0;
  uint64_t IdentityEdgeCopies = 0;
  uint64_t EmittedCopyInstructions = 0;
  uint64_t SplitCriticalEdges = 0;
};

struct EVMCompilerFeatureCoverage {
  uint64_t MemoryExpansionPlans = 0;
  uint64_t MemoryExpansionPlanCoveredOps = 0;
  uint64_t MemoryExpansionPlanEstimatedReducedExpansions = 0;
  uint64_t RangeU64FastPaths = 0;
  uint64_t ConstU64FastPaths = 0;
  uint64_t FullArithmeticPaths = 0;
};

struct EVMCompilerObservation {
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  bool Enabled = false;
  bool CompileSucceeded = false;
  bool DisableGreedyRA = false;
  uint64_t BytecodeSize = 0;
  uint64_t BytecodeFingerprint = 0;
  uint64_t TotalNs = 0;
  uint64_t EmittedCodeBytes = 0;
  uint64_t LiveIntervals = 0;
  bool LiveIntervalsAvailable = false;
  std::array<uint64_t, static_cast<size_t>(EVMCompilerPhase::Count)> PhaseNs{};
  EVMLiftedStackStatistics StackLift;
  EVMCompilerMIRSnapshot MIRAfterFrontend;
  EVMCompilerMIRSnapshot MIRAfterDCE;
  EVMCompilerCgSnapshot CgBeforePhi;
  EVMCompilerCgSnapshot CgAfterPhi;
  EVMCompilerCgSnapshot CgAfterRA;
  EVMCompilerCgSnapshot CgAfterPostRA;
  EVMCompilerPhiEliminationMetrics PhiElimination;
  EVMCompilerFeatureCoverage FeatureCoverage;

  void addPhaseTime(EVMCompilerPhase Phase, uint64_t DurationNs) {
    if (!Enabled) {
      return;
    }
    PhaseNs[static_cast<size_t>(Phase)] += DurationNs;
  }

  uint64_t getAccountedPhaseNs() const {
    uint64_t Total = 0;
    for (uint64_t Duration : PhaseNs) {
      Total += Duration;
    }
    return Total;
  }
};

class EVMCompilerPhaseTimer final {
public:
  EVMCompilerPhaseTimer(EVMCompilerObservation *Observation,
                        EVMCompilerPhase Phase)
      : Observation(Observation), Phase(Phase) {
    if (Observation != nullptr && Observation->Enabled) {
      Start = EVMCompilerObservation::Clock::now();
      Active = true;
    }
  }

  ~EVMCompilerPhaseTimer() {
    if (!Active) {
      return;
    }
    const auto End = EVMCompilerObservation::Clock::now();
    const uint64_t DurationNs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(End - Start)
            .count());
    Observation->addPhaseTime(Phase, DurationNs);
  }

private:
  EVMCompilerObservation *Observation = nullptr;
  EVMCompilerPhase Phase = EVMCompilerPhase::ContextSetup;
  EVMCompilerObservation::TimePoint Start;
  bool Active = false;
};

} // namespace COMPILER

#endif // ZEN_COMPILER_EVM_COMPILER_METRICS_H
