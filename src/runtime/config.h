// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_CONFIG_H
#define ZEN_RUNTIME_CONFIG_H

#include "common/defines.h"
#include "utils/logging.h"

namespace zen::runtime {

enum class LazyPrivateTierPolicy { Calls, Loops, Budgeted };

struct RuntimeConfig {
  // Run time Format
  common::InputFormat Format = common::InputFormat::WASM;
  // Run mode
  common::RunMode Mode = common::RunMode::SinglepassMode;
  // Disable mmap to allocate wasm memory
  bool DisableWasmMemoryMap = false;
  // Enable benchmark
  bool EnableBenchmark = false;
  // Enable MIR-level gas metering when compiling EVM bytecode
  // It’s disabled by default because enabling gas metering generates a lot of
  // MIR, which can interfere with normal debugging.
  bool EnableEvmGasMetering = false;
#ifdef ZEN_ENABLE_BUILTIN_WASI
  // Disable WASI
  bool DisableWASI = false;
#endif
  // Open statistics(compilation time/execution time)
  bool EnableStatistics = false;
  // Enable cpu instruction tracer hook
  bool EnableGdbTracingHook = false;
#ifdef ZEN_ENABLE_MULTIPASS_JIT
  // Disable greedy register allocation of multipass JIT
  bool DisableMultipassGreedyRA = false;
  // Opt-in scalar AVX instructions in Greedy-allocated Wasm functions.
  bool EnableGreedyScalarAVX = false;
  // Disable the automatic policy; explicit opt-in remains available.
  bool DisableAutoGreedyScalarAVX = false;
  // Disable multithread of multipass JIT
  bool DisableMultipassMultithread = false;
  // Number of threads for multipass JIT if DisableMultipassMultithread is false
  uint32_t NumMultipassThreads = 8;
  // Enable WASM multipass lazy compilation (segment-based lazy compile)
  bool EnableMultipassLazy = false;
  // Opt-in private-helper profiling/tiering. Only active for lazy MT with
  // Greedy enabled. Zero admission/time limits disable profiling entirely.
  bool EnableLazyPrivateTiering = false;
  LazyPrivateTierPolicy LazyTierPolicy = LazyPrivateTierPolicy::Budgeted;
  uint64_t LazyTierCallThreshold = 10000;
  uint64_t LazyTierLoopThreshold = 1000000;
  uint32_t LazyTierMaxFunctions = 4;
  uint64_t LazyTierMaxBytes = 16384;
  uint32_t LazyTierMaxFunctionBytes = 768;
  uint32_t LazyTierBudgetMs = 20;
  uint32_t LazyTierBenefitRatio = 2;
  // Automatic first-demand Greedy selection; zero limits mean unlimited.
  bool DisableLazyAutoGreedy = false;
  uint64_t LazyAutoGreedyMaxModuleBytes = 0;
  uint32_t LazyAutoGreedyMaxFunctionBytes = 2048;
  uint32_t LazyAutoGreedyBudgetMs = 0;

  // Enable profile-guided JIT:
  // contracts start in interpreter mode; runtime profiling (sliding window
  // of recent calls) determines which contracts are hot enough to trigger
  // background JIT compilation. Modules are NOT compiled at load time.
  bool EnableProfileGuidedJIT = false;
  // Maximum number of concurrent background JIT compilation threads.
  uint32_t NumJITCompileThreads = 10;
  // Profile-guided JIT trigger thresholds (configurable for testing).
  // Defaults match profile::JIT_TRIGGER_CALL_COUNT / JIT_TRIGGER_TOTAL_GAS.
  uint64_t JITTriggerCallCount = 32;
  uint64_t JITTriggerTotalGas = 100000;
  // Ring buffer capacity for the sliding-window call profiler.
  size_t RingBufferCapacity = 100;
#endif // ZEN_ENABLE_MULTIPASS_JIT

  bool validate() {
    // some cli options have relations
#ifdef ZEN_ENABLE_MULTIPASS_JIT
    if (EnableGdbTracingHook && !DisableMultipassMultithread) {
      ZEN_LOG_WARN(
          "multipass multithread compiling disabled in gdb tracing mode");
      DisableMultipassMultithread = true;
    }
#endif // ZEN_ENABLE_MULTIPASS_JIT

    switch (Mode) {
#ifndef ZEN_ENABLE_SINGLEPASS_JIT
    case common::RunMode::SinglepassMode: {
      ZEN_LOG_FATAL("enable singlepass JIT but not supported, please recompile "
                    "with -DZEN_ENABLE_SINGLEPASS_JIT=ON");
      return false;
    }
#endif

    case common::RunMode::MultipassMode:
#ifdef ZEN_ENABLE_MULTIPASS_JIT
      if (EnableLazyPrivateTiering &&
          (LazyTierCallThreshold == 0 || LazyTierLoopThreshold == 0 ||
           LazyTierBenefitRatio == 0)) {
        ZEN_LOG_ERROR(
            "private tiering thresholds and benefit ratio must be positive");
        return false;
      }
      if (!DisableMultipassMultithread && NumMultipassThreads == 0) {
        ZEN_LOG_FATAL(
            "multipass JIT multithread enabled but thread number is 0");
        return false;
      }
      if (EnableProfileGuidedJIT && NumJITCompileThreads == 0) {
        // A zero-sized JITCompilePool would silently accept tasks that
        // never run, and shutdown/destruction would block forever waiting
        // for unfinished futures. Require at least one worker thread when
        // profile-guided JIT is enabled.
        ZEN_LOG_FATAL(
            "profile-guided JIT enabled but NumJITCompileThreads is 0");
        return false;
      }
#else
      ZEN_LOG_FATAL("enable multipass JIT but not supported, please recompile "
                    "with -DZEN_ENABLE_MULTIPASS_JIT=ON");
      return false;
#endif
    default:
      break;
    }

    return true;
  }
};

} // namespace zen::runtime

#endif // ZEN_RUNTIME_CONFIG_H
