// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/evm_instance.h"

#include "common/errors.h"
#include "common/evm_traphandler.h"
#include "entrypoint/entrypoint.h"
#include "evm/evm.h"
#include "utils/backtrace.h"
#include <algorithm>
#include <utility>

namespace zen::runtime {

using namespace common;

namespace {
bool calcRequiredMemorySize(uint64_t Offset, uint64_t Size,
                            uint64_t &RequiredSize) {
  if (Offset > std::numeric_limits<uint64_t>::max() - Size) {
    return false;
  }
  RequiredSize = Offset + Size;
  return true;
}
} // namespace

EVMInstanceUniquePtr EVMInstance::newEVMInstance(Isolation &Iso,
                                                 const EVMModule &Mod,
                                                 uint64_t GasLimit) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  [[maybe_unused]] static bool _ =
      common::evm_traphandler::initEVMPlatformTrapHandler();
#endif // ZEN_ENABLE_CPU_EXCEPTION

  Runtime *RT = Mod.getRuntime();
  void *Buf = RT->allocate(sizeof(EVMInstance), ALIGNMENT);
  ZEN_ASSERT(Buf);

  EVMInstanceUniquePtr Inst(new (Buf) EVMInstance(Mod, *RT));

  Inst->Iso = &Iso;

  Inst->setGas(GasLimit);

  return Inst;
}

EVMInstance::~EVMInstance() {}

void EVMInstance::setGas(uint64_t NewGas) { Gas = NewGas; }

void EVMInstance::pushMessage(evmc_message *Msg) {
  if (MessageStack.empty()) {
    MemoryStack.clear();
    Memory.clear();
  } else {
    MemoryStack.push_back(std::move(Memory));
    Memory.clear();
  }
  MessageStack.push_back(Msg);
  CurrentMessage = Msg;
  Gas = Msg ? Msg->gas : 0;
}

void EVMInstance::popMessage() {
  if (!MessageStack.empty()) {
    MessageStack.pop_back();
  }
  CurrentMessage = MessageStack.empty() ? nullptr : MessageStack.back();
  if (!MemoryStack.empty()) {
    Memory = std::move(MemoryStack.back());
    MemoryStack.pop_back();
  } else {
    Memory.clear();
  }
  Gas = CurrentMessage ? CurrentMessage->gas : 0;
}

uint64_t EVMInstance::calculateMemoryExpansionCost(uint64_t CurrentSize,
                                                   uint64_t NewSize) {
  if (NewSize <= CurrentSize) {
    return 0; // No expansion needed
  }
  uint64_t CurrentWords = (CurrentSize + 31) / 32;
  uint64_t NewWords = (NewSize + 31) / 32;
  auto MemoryCost = [](uint64_t Words) -> uint64_t {
    __int128 W = Words;
    return static_cast<uint64_t>(W * W / 512 + 3 * W);
  };
  uint64_t CurrentCost = MemoryCost(CurrentWords);
  uint64_t NewCost = MemoryCost(NewWords);
  return NewCost - CurrentCost;
}

void EVMInstance::setExecutionError(const Error &NewErr, uint32_t IgnoredDepth,
                                    common::evm_traphandler::EVMTrapState TS) {
  ZEN_ASSERT(NewErr.getPhase() == common::ErrorPhase::Execution);
  setError(NewErr);
  if (NewErr.getCode() == ErrorCode::GasLimitExceeded) {
    setGas(0); // gas left
  }
}

void EVMInstance::exit(int32_t ExitCode) {
  this->InstanceExitCode = ExitCode;
  setExceptionByHostapi(common::getError(ErrorCode::InstanceExit));
}

#ifdef ZEN_ENABLE_JIT

void EVMInstance::setInstanceExceptionOnJIT(EVMInstance *Inst,
                                            common::ErrorCode ErrCode) {
  Inst->setExecutionError(common::getError(ErrCode), 1,
                          common::evm_traphandler::EVMTrapState{});
}

void EVMInstance::throwInstanceExceptionOnJIT(EVMInstance *Inst) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
  SAVE_EVM_HOSTAPI_FRAME_POINTER_TO_TLS

  utils::throwCpuIllegalInstructionTrap();
#endif // ZEN_ENABLE_CPU_EXCEPTION
}

void EVMInstance::triggerInstanceExceptionOnJIT(EVMInstance *Inst,
                                                common::ErrorCode ErrCode) {
  // Not use setInstanceExceptionOnJIT instead of the following code, because we
  // need correct `ignored_depth`
  Inst->setExecutionError(common::getError(ErrCode), 1,
                          common::evm_traphandler::EVMTrapState{});

  throwInstanceExceptionOnJIT(Inst);
}
#endif // ZEN_ENABLE_JIT

void EVMInstance::expandMemory(uint64_t RequiredSize) {
  auto NewSize = (RequiredSize + 31) / 32 * 32;
  uint64_t ExpansionCost = calculateMemoryExpansionCost(Memory.size(), NewSize);
  chargeGas(ExpansionCost);
  if (NewSize > Memory.size()) {
    Memory.resize(NewSize, 0);
  }
}

bool EVMInstance::expandMemoryChecked(uint64_t Offset, uint64_t Size) {
  uint64_t RequiredSize = 0;
  if (!calcRequiredMemorySize(Offset, Size, RequiredSize)) {
    chargeGas(getGas() + 1);
    return false;
  }
  if (RequiredSize > zen::evm::MAX_REQUIRED_MEMORY_SIZE) {
    chargeGas(getGas() + 1);
    return false;
  }
  expandMemory(RequiredSize);
  return true;
}

bool EVMInstance::expandMemoryChecked(uint64_t OffsetA, uint64_t SizeA,
                                      uint64_t OffsetB, uint64_t SizeB) {
  uint64_t RequiredSizeA = 0;
  uint64_t RequiredSizeB = 0;
  if (!calcRequiredMemorySize(OffsetA, SizeA, RequiredSizeA) ||
      !calcRequiredMemorySize(OffsetB, SizeB, RequiredSizeB)) {
    chargeGas(getGas() + 1);
    return false;
  }
  const uint64_t RequiredSize = std::max(RequiredSizeA, RequiredSizeB);
  if (RequiredSize > zen::evm::MAX_REQUIRED_MEMORY_SIZE) {
    chargeGas(getGas() + 1);
    return false;
  }
  expandMemory(RequiredSize);
  return true;
}
void EVMInstance::chargeGas(uint64_t GasCost) {
  evmc_message *Msg = getCurrentMessage();
  ZEN_ASSERT(Msg && "Active message required for gas accounting");

  uint64_t GasLeft = getGas();
  if (GasLeft < GasCost) {
#if defined(ZEN_ENABLE_JIT) && defined(ZEN_ENABLE_CPU_EXCEPTION)
    triggerInstanceExceptionOnJIT(this, common::ErrorCode::GasLimitExceeded);
#else
    throw common::getError(common::ErrorCode::GasLimitExceeded);
#endif
  }
  uint64_t NewGas = GasLeft - GasCost;
  setGas(NewGas);
  Msg->gas = static_cast<int64_t>(NewGas);
}

} // namespace zen::runtime
