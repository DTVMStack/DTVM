// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// #ifndef ZEN_RUNTIME_INSTANCE_H
// #define ZEN_RUNTIME_INSTANCE_H

#include "common/errors.h"
#include "common/traphandler.h"
#include "intx/intx.hpp"
#include "runtime/evm_module.h"
#include "utils/backtrace.h"
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

  // ==================== Evmc Message Stack Methods ====================
  // Note: These methods manage the call stack for JIT host interface functions
  // that need access to evmc_message context throughout the call hierarchy.

  void pushMessage(const evmc_message *Msg) { MessageStack.push_back(Msg); }
  void popMessage() {
    if (!MessageStack.empty())
      MessageStack.pop_back();
  }
  const evmc_message *getCurrentMessage() const {
    return MessageStack.empty() ? nullptr : MessageStack.back();
  }

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

  // Message stack for call hierarchy tracking
  std::vector<const evmc_message *> MessageStack;

  // exit code set by Instance.exit(ExitCode)
  int32_t InstanceExitCode = 0;
  static constexpr size_t Alignment = 8;
};

} // namespace runtime
} // namespace zen

// #endif // ZEN_RUNTIME_INSTANCE_H
