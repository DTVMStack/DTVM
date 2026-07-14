// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_UTILS_STATISTICS_H
#define ZEN_UTILS_STATISTICS_H

#include "common/defines.h"

#include <chrono>
#include <unordered_map>
#include <vector>

namespace zen::utils {

enum class StatisticPhase : uint32_t {
  Load = 0,
  ProcessToReport = 1,       // diagnostic: static init to statistics report
  ProcessBootstrap = 2,      // static init to main entry
  CLIParse = 3,              // command-line parser build + parse
  LoggerSetup = 4,           // CLI logger creation / install
  RuntimeCreate = 5,         // Runtime::newRuntime / newEVMRuntime
  HostSetup = 6,             // EVM mocked host construction/configuration
  RuntimeSetup = 7,          // mainly for EVM CLI cold-start staging
  BytecodeRead = 8,          // EVM bytecode file read + trim
  BytecodeDecode = 9,        // EVM bytecode hex decode
  StateFileRead = 10,        // mainly for EVM CLI replay state file IO
  StateJsonParse = 11,       // mainly for EVM CLI replay JSON parse
  StateMaterialization = 12, // mainly for EVM CLI account/storage import
  StateAccessListWarmup = 13,// mainly for EVM CLI access-list warmup
  InputDecode = 14,          // mainly for EVM CLI calldata/input decode
  MemoryProfileDerive = 15,  // EVM memory specialization profile derivation
  EVMModuleLoad = 16,        // diagnostic parent for EVM module load
  CodeHolderCreate = 17,     // raw bytecode holder allocation/copy
  EVMRetryCodeClone = 18,    // retry holder clone for fallback-capable JIT load
  EVMModuleCreate = 19,      // EVMModule construction parent
  EVMModulePoolInsert = 20,  // module name/pool bookkeeping
  EVMAnalyzer = 21,          // EVMAnalyzer bytecode analysis
  EVMFallbackDecision = 22,  // fallback suitability checks
  StateAccountsMaterialize = 23, // state account top-level materialization
  StateStorageMaterialize = 24,  // state storage entry materialization
  StateCodeMaterialize = 25,     // state code/codehash materialization
  StateTxContextMaterialize = 26,// state tx_context materialization
  MessageSetup = 27,         // mainly for EVM CLI message preparation
  EVMMessageCreate = 28,     // EVM evmc_message creation
  IsolationCreate = 29,      // managed isolation creation
  PreExecutionChecks = 30,   // mainly for EVM CLI pre-execution checks
  JITCompilation = 31,       // only for JIT mode
  JITEVMFrontend = 32,       // eager EVM frontend MIR build
  JITMIRToCgIR = 33,         // eager EVM mid-end lowering and RA
  JITMachineCodeLowering = 34,// eager EVM mc lowering
  JITObjectEmission = 35,    // eager EVM object emission and relocation
  JITCodeFinalization = 36,  // eager EVM code install and mprotect
  JITLazyPrecompilation = 37,// only for multipass JIT lazy mode
  JITLazyFgCompilation = 38, // only for multipass JIT lazy mode(foreground)
  JITLazyBgCompilation = 39, // only for multipass JIT lazy mode(background)
  JITLazyReleaseDelay = 40,  // only for multipass JIT lazy mode
  MemoryBucketMap = 41,
  Instantiation = 42,
  Execution = 43,
  EVMInterpreterExecution = 44, // interpreter execution body
  EVMJITExecution = 45,         // JIT native execution body
  EVMHostAccountOps = 46,       // host account/balance/code operations
  EVMHostStorageOps = 47,       // host storage operations
  EVMHostCall = 48,             // host CALL/CREATE re-entry
  EVMMemoryOps = 49,            // EVM memory expansion/copy helpers
  EVMGasAccounting = 50,        // EVM gas charge/update helpers
  BenchmarkHooks = 51,       // CLI extra benchmark loop setup/dispatch
  PostExecutionCleanup = 52, // mainly for EVM CLI output/save/unload stages
  JITMIRVerify = 53,         // MIR verifier inside MIR->CgIR pipeline
  JITMIRDCE = 54,            // MIR dead basic block elimination
  JITCgLowering = 55,        // dMIR -> CgIR lowering
  JITCgPeephole = 56,        // CgIR peephole
  JITCgPhiElimination = 57,  // CgIR phi elimination
  JITFastRA = 58,            // Fast register allocation
  JITCgDCE = 59,             // CgIR dead instruction elimination
  JITCgDominatorTree = 60,   // CgIR dominator tree
  JITCgLoopInfo = 61,        // CgIR loop info
  JITCgSlotIndexes = 62,     // CgIR slot index construction
  JITCgLiveIntervals = 63,   // CgIR live interval construction
  JITCgLiveStacks = 64,      // CgIR live stack analysis
  JITCgBlockFrequency = 65,  // CgIR block frequency analysis
  JITCgRegisterCoalescer = 66, // CgIR register coalescing
  JITCgVirtRegMap = 67,      // virtual register map construction
  JITCgLiveRegMatrix = 68,   // live register matrix construction
  JITCgEdgeBundles = 69,     // edge bundle construction
  JITCgSpillPlacement = 70,  // spill placement construction
  JITCgGreedyRA = 71,        // greedy register allocation
  JITCgVirtRegRewrite = 72,  // virtual register rewrite
  JITPrologEpilog = 73,      // prologue/epilogue insertion
  JITPostRAPseudos = 74,     // post-RA pseudo expansion
  NumStatisticPhases
};

class Statistics final {
  typedef common::SteadyClock::time_point TimePoint;
  typedef uint32_t StatisticTimer;
  typedef std::pair<StatisticPhase, float> StatisticRecord;

public:
  Statistics(bool Enabled) : Enabled(Enabled) {}

  ~Statistics() { ZEN_ASSERT(Timers.empty()); }

  NONCOPYABLE(Statistics);

  bool isEnabled() const { return Enabled; }

  StatisticTimer startRecord(StatisticPhase Phase);

  void stopRecord(StatisticTimer Timer);

  void revertRecord(StatisticTimer Timer);

  void recordDuration(StatisticPhase Phase, float TimeCostMs);

  void clearAllTimers();

  void report() const;

private:
  const bool Enabled;
  common::Mutex Mtx;
  StatisticTimer TimerCounter = 0;
  typedef std::pair<StatisticPhase, TimePoint> TimerPair;
  std::unordered_map<StatisticTimer, TimerPair> Timers;
  std::vector<StatisticRecord> Records;
};

} // namespace zen::utils

#endif // ZEN_UTILS_STATISTICS_H
