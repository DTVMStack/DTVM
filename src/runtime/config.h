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
  // Enable multipass lazy mode(on request compile)
  bool EnableMultipassLazy = false;
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
