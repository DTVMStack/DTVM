// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/statistics.h"
#include "utils/logging.h"
#include <cstdio>
#include <ratio>

namespace zen::utils {

Statistics::StatisticTimer Statistics::startRecord(StatisticPhase Phase) {
  if (!Enabled) {
    return -1u;
  }

  common::LockGuard<common::Mutex> Lock(Mtx);
  auto Timer = TimerCounter++;
  Timers[Timer] = {Phase, common::SteadyClock::now()};
  return Timer;
}

void Statistics::stopRecord(StatisticTimer Timer) {
  if (!Enabled) {
    return;
  }

  ZEN_ASSERT(Timers.find(Timer) != Timers.end());
  common::LockGuard<common::Mutex> Lock(Mtx);
  auto End = common::SteadyClock::now();
  auto Start = Timers[Timer].second;
  float TimeCost =
      common::chrono::duration<float, std::milli>(End - Start).count();
  auto Phase = Timers[Timer].first;
  Records.emplace_back(Phase, TimeCost);
  Timers.erase(Timer);
}

void Statistics::revertRecord(StatisticTimer Timer) {
  if (!Enabled) {
    return;
  }

  ZEN_ASSERT(Timers.find(Timer) != Timers.end());
  common::LockGuard<common::Mutex> Lock(Mtx);
  Timers.erase(Timer);
}

void Statistics::recordDuration(StatisticPhase Phase, float TimeCostMs) {
  if (!Enabled) {
    return;
  }

  common::LockGuard<common::Mutex> Lock(Mtx);
  Records.emplace_back(Phase, TimeCostMs);
}

void Statistics::clearAllTimers() {
  if (!Enabled) {
    return;
  }

  common::LockGuard<common::Mutex> Lock(Mtx);
  Timers.clear();
}

void Statistics::report() const {
  if (!Enabled) {
    return;
  }

  using namespace common;

  constexpr auto JITLazyFgPhaseVal =
      common::to_underlying(StatisticPhase::JITLazyFgCompilation);
  constexpr auto JITLazyBgPhaseVal =
      common::to_underlying(StatisticPhase::JITLazyBgCompilation);
  constexpr auto ExePhaseVal = common::to_underlying(StatisticPhase::Execution);
  constexpr auto NumStatPhases =
      common::to_underlying(StatisticPhase::NumStatisticPhases);

  uint32_t NumPhaseRecords[NumStatPhases] = {0};
  float TimePhaseCosts[NumStatPhases] = {0};

  for (const auto &[Phase, TimeCost] : Records) {
    auto PhaseVal = to_underlying(Phase);
    ZEN_ASSERT(PhaseVal < NumStatPhases);
    NumPhaseRecords[PhaseVal]++;
    TimePhaseCosts[PhaseVal] += TimeCost;
  }

  TimePhaseCosts[ExePhaseVal] -= TimePhaseCosts[JITLazyFgPhaseVal];

  float TotalTimeCost = 0;
  bool HasPhaseTimeCost = false;
  for (uint32_t I = 0; I < NumStatPhases; ++I) {
    if (I == JITLazyBgPhaseVal) {
      continue;
    }
    TotalTimeCost += TimePhaseCosts[I];
    if (!HasPhaseTimeCost) {
      HasPhaseTimeCost = true;
    }
  }

  // We need to know whether TotalTimeCost is exactly 0, so we should not use
  // approximate judgments like TotalTimeCost < 1e-6
  if (!HasPhaseTimeCost) {
    return;
  }

  ZEN_LOG_INFO(
      "================  [Begin] ZetaEngine Statistics  ================");

  static constexpr const char *StatLogPrefixs[] = {
      "Load:			",
      "Process To Report:	",
      "Process Bootstrap:	",
      "CLI Parse:		",
      "Logger Setup:		",
      "Runtime Create:	",
      "Host Setup:		",
      "Runtime Setup:		",
      "Bytecode Read:		",
      "Bytecode Decode:	",
      "State File Read:	",
      "State JSON Parse:	",
      "State Materialization:	",
      "State Access Warmup:	",
      "Input Decode:		",
      "Memory Profile Derive:	",
      "EVM Module Load:	",
      "CodeHolder Create:	",
      "EVM Retry Code Clone:	",
      "EVM Module Create:	",
      "EVM Module Pool Insert:	",
      "EVM Analyzer:		",
      "EVM Fallback Decision:	",
      "State Accounts Materialize:	",
      "State Storage Materialize:	",
      "State Code Materialize:	",
      "State TxContext Materialize:	",
      "Message Setup:		",
      "EVM Message Create:	",
      "Isolation Create:	",
      "Pre Execution Checks:	",
      "JIT Compilation:		",
      "JIT EVM Frontend:	",
      "JIT MIR To CgIR:	",
      "JIT Machine Code Lowering:	",
      "JIT Object Emission:	",
      "JIT Code Finalization:	",
      "JIT Lazy Precompilation:	",
      "JIT Lazy Compilation(Fg):	",
      "JIT Lazy Compilation(Bg):	",
      "JIT Lazy Release Delay:	",
      "Memory Bucket Map:	",
      "Instantiation:		",
      "Execution:		",
      "EVM Interpreter Execution:	",
      "EVM JIT Execution:	",
      "EVM Host Account Ops:	",
      "EVM Host Storage Ops:	",
      "EVM Host Call:	",
      "EVM Memory Ops:	",
      "EVM Gas Accounting:	",
      "Benchmark Hooks:	",
      "Post Execution Cleanup:	",
      "JIT MIR Verify:	",
      "JIT MIR DCE:		",
      "JIT Cg Lowering:	",
      "JIT Cg Peephole:	",
      "JIT Cg Phi Elimination:	",
      "JIT Fast RA:		",
      "JIT Cg DCE:		",
      "JIT Cg Dominator Tree:	",
      "JIT Cg Loop Info:	",
      "JIT Cg Slot Indexes:	",
      "JIT Cg Live Intervals:	",
      "JIT Cg Live Stacks:	",
      "JIT Cg Block Frequency:	",
      "JIT Cg Register Coalescer:	",
      "JIT Cg VirtReg Map:	",
      "JIT Cg LiveReg Matrix:	",
      "JIT Cg Edge Bundles:	",
      "JIT Cg Spill Placement:	",
      "JIT Cg Greedy RA:	",
      "JIT Cg VirtReg Rewrite:	",
      "JIT Prolog Epilog:	",
      "JIT Post-RA Pseudos:	",
  };

  for (uint32_t I = 0; I < NumStatPhases; ++I) {
    if (NumPhaseRecords[I] > 0) {
      float AvgPhaseTimeCost = TimePhaseCosts[I] / NumPhaseRecords[I];
      if (I == JITLazyBgPhaseVal) {
        ZEN_LOG_INFO("%s%u times, avg %.3fms, total %.3fms", StatLogPrefixs[I],
                     NumPhaseRecords[I], AvgPhaseTimeCost, TimePhaseCosts[I]);
      } else {
        float PhaseTimeCostPercent = TimePhaseCosts[I] / TotalTimeCost * 100;
        ZEN_LOG_INFO("%s%u times, avg %.3fms, total %.3fms, %.2f%%",
                     StatLogPrefixs[I], NumPhaseRecords[I], AvgPhaseTimeCost,
                     TimePhaseCosts[I], PhaseTimeCostPercent);
      }
    }
  }

  ZEN_LOG_INFO("Total:\t\t%.3fms", TotalTimeCost);

  ZEN_LOG_INFO(
      "=================  [End] ZetaEngine Statistics =================");
}

} // namespace zen::utils
