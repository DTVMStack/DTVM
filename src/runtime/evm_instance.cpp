// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/evm_instance.h"

#include "action/instantiator.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/traphandler.h"
#include "entrypoint/entrypoint.h"
#include "runtime/config.h"
#include <algorithm>

namespace zen::runtime {

using namespace common;

EVMInstanceUniquePtr EVMInstance::newEVMInstance(Isolation &Iso,
                                                 const EVMModule &Mod,
                                                 uint64_t GasLimit) {

  Runtime *RT = Mod.getRuntime();
  void *Buf = RT->allocate(sizeof(EVMInstance), ALIGNMENT);
  ZEN_ASSERT(Buf);

  EVMInstanceUniquePtr Inst(new (Buf) EVMInstance(Mod, *RT));

  Inst->Iso = &Iso;

  Inst->setGas(GasLimit);

  return Inst;
}

EVMInstance::~EVMInstance() {}

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

void EVMInstance::consumeMemoryExpansionGas(uint64_t RequiredSize) {
  uint64_t ExpansionCost =
      calculateMemoryExpansionCost(Memory.size(), RequiredSize);
  uint64_t GasLeft = getGas();
  if (ExpansionCost > GasLeft) {
    throw common::getError(common::ErrorCode::EVMOutOfGas);
  }
  setGas(GasLeft - ExpansionCost);
}
void EVMInstance::expandMemory(uint64_t RequiredSize) {
  if (RequiredSize > Memory.size()) {
    Memory.resize(RequiredSize, 0);
  }
}

} // namespace zen::runtime
