// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// #ifndef ZEN_RUNTIME_INSTANCE_H
// #define ZEN_RUNTIME_INSTANCE_H

#include "common/errors.h"
#include "common/traphandler.h"
#include "evmc/evmc.hpp"
#include "intx/intx.hpp"
#include "runtime/evm_module.h"
#include "utils/backtrace.h"
#include <unordered_map>
#include <vector>

// Forward declaration for evmc_message
struct evmc_message;
#ifdef ZEN_ENABLE_VIRTUAL_STACK
#include "utils/virtual_stack.h"
#include <queue>
#endif

#ifdef ZEN_ENABLE_CPU_EXCEPTION
#include <csetjmp>
#include <csignal>
#endif // ZEN_ENABLE_CPU_EXCEPTION

#ifdef ZEN_ENABLE_BUILTIN_WASI
#include "host/wasi/wasi.h"
#endif

namespace zen {

namespace action {
class Instantiator;
} // namespace action

namespace runtime {

/// \warning: not support multi-threading
class EVMInstance final : public RuntimeObject<EVMInstance> {
  using Error = common::Error;
  using ErrorCode = common::ErrorCode;

  friend class Runtime;
  friend class Isolation;
  friend class RuntimeObjectDestroyer;
  friend class action::Instantiator;

public:
  // ==================== Module Accessing Methods ====================

  const EVMModule *getModule() const { return Mod; }

  // ==================== Platform Feature Methods ====================

  uint64_t getGas() const { return Gas; }
  void setGas(uint64_t NewGas) { Gas = NewGas; }
  static uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize,
                                               uint64_t NewSize);
  void consumeMemoryExpansionGas(uint64_t RequiredSize);
  void expandMemory(uint64_t RequiredSize);

  // ==================== Memory Methods ====================
  size_t getMemorySize() const { return Memory.size(); }
  std::vector<uint8_t> &getMemory() { return Memory; }

  // ==================== Evmc Message Stack Methods ====================
  // Note: These methods manage the call stack for JIT host interface functions
  // that need access to evmc_message context throughout the call hierarchy.

  void pushMessage(const evmc_message *Msg) { MessageStack.push_back(Msg); }
  void popMessage() {
    if (!MessageStack.empty()) {
      MessageStack.pop_back();
    }
  }
  const evmc_message *getCurrentMessage() const {
    return MessageStack.empty() ? nullptr : MessageStack.back();
  }

  struct PairHash {
    template <class T1, class T2>
    std::size_t operator()(const std::pair<T1, T2> &Pair) const {
      return std::hash<T1>{}(Pair.first) ^ (std::hash<T2>{}(Pair.second) << 1);
    }
  };

  struct ExecutionCache {
    evmc_tx_context TxContext;
    std::unordered_map<int64_t, evmc::bytes32> BlockHashes;
    std::unordered_map<uint64_t, evmc::bytes32> BlobHashes;
    std::unordered_map<std::pair<const evmc_message *, uint64_t>, evmc::bytes32,
                       PairHash>
        CalldataLoads;
    std::vector<evmc::bytes32> ExtcodeHashes;
    bool TxContextCached = false;
  };

  ExecutionCache &getMessageCache() { return InstanceExecutionCache; }
  void setReturnData(std::vector<uint8_t> Data) {
    ReturnData = std::move(Data);
  }
  void exit(int32_t exitCode) { InstanceExitCode = exitCode; }

private:
  EVMInstance(const EVMModule &M, Runtime &RT)
      : RuntimeObject<EVMInstance>(RT), Mod(&M) {}

  virtual ~EVMInstance();

  static EVMInstanceUniquePtr
  newEVMInstance(Isolation &Iso, const EVMModule &Mod, uint64_t GasLimit = 0);

  Isolation *Iso = nullptr;
  const EVMModule *Mod = nullptr;

  Error Err = ErrorCode::NoError;

  uint64_t Gas = 0;
  // memory
  std::vector<uint8_t> Memory;
  std::vector<uint8_t> ReturnData;

  // Message stack for call hierarchy tracking
  std::vector<const evmc_message *> MessageStack;

  // Instance-level cache storage (shared across all messages in execution)
  ExecutionCache InstanceExecutionCache;

  // exit code set by Instance.exit(ExitCode)
  int32_t InstanceExitCode = 0;
  static constexpr size_t ALIGNMENT = 8;
};

} // namespace runtime
} // namespace zen

// #endif // ZEN_RUNTIME_INSTANCE_H
