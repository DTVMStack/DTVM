// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_CONFIG_H
#define ZEN_RUNTIME_CONFIG_H

#include "common/defines.h"
#include "utils/logging.h"

namespace zen::runtime {

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
  // Disable multithread of multipass JIT
  bool DisableMultipassMultithread = false;
  // Number of threads for multipass JIT if DisableMultipassMultithread is false
  uint32_t NumMultipassThreads = 8;
  // Enable WASM multipass lazy compilation (segment-based lazy compile)
  bool EnableMultipassLazy = false;
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
