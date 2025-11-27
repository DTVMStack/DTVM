// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_EVM_INSTANCE_H
#define ZEN_RUNTIME_EVM_INSTANCE_H

#include "common/evm_traphandler.h"
#include "evm/evm.h"
#include "evm/gas_storage_cost.h"
#include "evmc/evmc.hpp"
#include "intx/intx.hpp"
#include "runtime/evm_module.h"
#include "runtime/instance.h"
#include <array>
#include <limits>

// Forward declaration for evmc_message
struct evmc_message;

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
  static constexpr size_t HostArgScratchSlots = 8;
  static constexpr size_t HostArgScratchSize =
      HostArgScratchSlots * sizeof(intx::uint256);

  // ==================== Module Accessing Methods ====================

  const EVMModule *getModule() const { return Mod; }

  // ==================== Platform Feature Methods ====================

  uint64_t getGas() const { return Gas; }
  void setGas(uint64_t NewGas);
  static uint64_t calculateMemoryExpansionCost(uint64_t CurrentSize,
                                               uint64_t NewSize);
  void consumeMemoryExpansionGas(uint64_t RequiredSize);
  void expandMemory(uint64_t RequiredSize);
  void chargeGas(uint64_t GasCost);

  void addGasRefund(uint64_t Amount) { GasRefund += Amount; }
  void setGasRefund(uint64_t Amount) { GasRefund = Amount; }
  uint64_t getGasRefund() const { return GasRefund; }
  void setRevision(evmc_revision NewRev) { Rev = NewRev; }

  // ==================== Memory Methods ====================
  size_t getMemorySize() const { return Memory.size(); }
  std::vector<uint8_t> &getMemory() { return Memory; }

  // ==================== Evmc Message Stack Methods ====================
  // Note: These methods manage the call stack for JIT host interface functions
  // that need access to evmc_message context throughout the call hierarchy.

  void pushMessage(evmc_message *Msg);
  void popMessage();
  evmc_message *getCurrentMessage() const { return CurrentMessage; }
  bool isStaticMode() const {
    const evmc_message *Msg = getCurrentMessage();
    return Msg && (Msg->flags & EVMC_STATIC) != 0;
  }
  evmc_revision getRevision() const { return Rev; }

  const Error &getError() const { return Err; }
  void setError(const Error &E) { Err = E; }
  void clearError() { Err = ErrorCode::NoError; }

  // can only called by hostapi directly
  // setExceptionByHostapi must be inline to capture the hostapi's frame
  // pointer
  void __attribute__((always_inline))
  setExceptionByHostapi(const Error &NewErr) {
    setExecutionError(NewErr, 1, {});
  }

  // ignored_depth: the distance from the setExecutionError to the top of
  // expected call stack
  void __attribute__((noinline))
  setExecutionError(const Error &NewErr, uint32_t IgnoredDepth = 0,
                    common::evm_traphandler::EVMTrapState TS = {});

  // ==================== JIT Methods ====================

#ifdef ZEN_ENABLE_JIT
  static void __attribute__((noinline))
  setInstanceExceptionOnJIT(EVMInstance *Inst, ErrorCode ErrCode);
  static void __attribute__((noinline))
  throwInstanceExceptionOnJIT(EVMInstance *Inst);
  // trigger = set + throw
  static void __attribute__((noinline))
  triggerInstanceExceptionOnJIT(EVMInstance *Inst, ErrorCode ErrCode);
#endif // ZEN_ENABLE_JIT

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
    std::vector<evmc::bytes32> Keccak256Results;
    bool TxContextCached = false;
  };

  ExecutionCache &getMessageCache() { return InstanceExecutionCache; }
  void setReturnData(std::vector<uint8_t> Data) {
    ReturnData = std::move(Data);
  }
  const std::vector<uint8_t> &getReturnData() const { return ReturnData; }
  void setExeResult(evmc::Result Result) { ExeResult = std::move(Result); }
  const evmc::Result &getExeResult() const { return ExeResult; }
  void exit(int32_t ExitCode);
  int32_t getExitCode() const { return InstanceExitCode; }

  static constexpr int32_t getGasFieldOffset() {
    static_assert(offsetof(EVMInstance, Gas) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMInstance offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMInstance, Gas));
  }

  static constexpr int32_t getCurrentMessagePointerOffset() {
    static_assert(offsetof(EVMInstance, CurrentMessage) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMInstance offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMInstance, CurrentMessage));
  }

  static constexpr int32_t getMessageGasOffset() {
    static_assert(offsetof(evmc_message, gas) <=
                      std::numeric_limits<int32_t>::max(),
                  "evmc_message offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(evmc_message, gas));
  }

  static constexpr size_t getHostArgScratchSlotSize() {
    return sizeof(intx::uint256);
  }

  static constexpr size_t getHostArgScratchCapacity() {
    return HostArgScratchSize;
  }

  static constexpr int32_t getHostArgScratchOffset() {
    static_assert(offsetof(EVMInstance, HostArgScratch) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMInstance offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMInstance, HostArgScratch));
  }

  static constexpr int32_t getEVMStackOffset() {
    static_assert(offsetof(EVMInstance, EVMStack) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMInstance offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMInstance, EVMStack));
  }

  static constexpr int32_t getEVMStackSizeOffset() {
    static_assert(offsetof(EVMInstance, EVMStackSize) <=
                      std::numeric_limits<int32_t>::max(),
                  "EVMInstance offsets should fit in 32-bit signed range");
    return static_cast<int32_t>(offsetof(EVMInstance, EVMStackSize));
  }

  // Capacity for EVMStack: 1024 * 256 / 8 = 32768
  static const size_t EVMStackCapacity = 32768;

private:
  EVMInstance(const EVMModule &M, Runtime &RT)
      : RuntimeObject<EVMInstance>(RT), Mod(&M) {}

  virtual ~EVMInstance();
  // // ========= Instance-compatible layout (do NOT change order) =========
  Isolation *Iso = nullptr;
  const Module *ModuleInst = nullptr;

  uint32_t NumTotalGlobals = 0;
  uint32_t NumTotalMemories = 0;
  uint32_t NumTotalTables = 0;
  uint32_t NumTotalFunctions = 0;

  FunctionInstance *Functions = nullptr;
  GlobalInstance *Globals = nullptr;
  uint8_t *GlobalVarData = nullptr;
  TableInstance *Tables = nullptr;
  MemoryInstance *Memories = nullptr;

#ifdef ZEN_ENABLE_JIT
  uintptr_t *JITFuncPtrs = nullptr;
  uint32_t *FuncTypeIdxs = nullptr;
  uint64_t JITStackSize = 0;
  uint8_t *JITStackBoundary = nullptr;
#endif

  common::Error Err = common::ErrorCode::NoError;

  uint64_t Gas = 0;
  int32_t InstanceExitCode = 0;

#ifdef ZEN_ENABLE_BUILTIN_WASI
  host::WASIContext *WASICtx = nullptr;
#endif

#ifdef ZEN_ENABLE_DUMP_CALL_STACK
  int32_t *Traces;
  uint32_t NumTraces = 0;
  std::vector<std::pair<int32_t, uintptr_t>> HostFuncPtrs;
#endif

#ifdef ZEN_ENABLE_DWASM
  uint32_t StackCost = 0;
  int8_t InHostAPI = 0;
#endif

  void *CustomData = nullptr;
  WasmMemoryDataType MemDataKind =
      WasmMemoryDataType::WM_MEMORY_DATA_TYPE_MALLOC;
  bool DataSegsInited = false;

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  std::queue<utils::VirtualStackInfo *> VirtualStacks;
#endif
  // ========= EVM-specific fields start here =========

  static EVMInstanceUniquePtr
  newEVMInstance(Isolation &Iso, const EVMModule &Mod, uint64_t GasLimit = 0);

  const EVMModule *Mod = nullptr;
  uint64_t GasRefund = 0;
  // memory
  std::vector<uint8_t> Memory;
  std::vector<uint8_t> ReturnData;
  evmc::Result ExeResult{EVMC_SUCCESS, 0, 0};

  // Message stack for call hierarchy tracking
  evmc_message *CurrentMessage = nullptr;
  std::vector<evmc_message *> MessageStack;
  evmc_revision Rev = zen::evm::DEFAULT_REVISION;

  // Instance-level cache storage (shared across all messages in execution)
  ExecutionCache InstanceExecutionCache;

  // Runtime stack data for EVM.
  uint8_t EVMStack[EVMStackCapacity];
  uint64_t EVMStackSize = 0;

  static constexpr size_t ALIGNMENT = 8;
  alignas(16) std::array<uint8_t, HostArgScratchSize> HostArgScratch{};
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_EVM_INSTANCE_H
