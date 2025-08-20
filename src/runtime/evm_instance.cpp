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
  void *Buf = RT->allocate(sizeof(EVMInstance), Alignment);
  ZEN_ASSERT(Buf);

  EVMInstanceUniquePtr Inst(new (Buf) EVMInstance(Mod, *RT));

  Inst->Iso = &Iso;

  Inst->setGas(GasLimit);

  return Inst;
}

EVMInstance::~EVMInstance() {}

} // namespace zen::runtime
