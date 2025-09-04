// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_ACTION_EVM_MODULE_LOADER_H
#define ZEN_ACTION_EVM_MODULE_LOADER_H

#include "action/module_loader.h"
#include "runtime/evm_module.h"

namespace zen::action {

class EVMModuleLoader final {
public:
  using Byte = common::Byte;
  explicit EVMModuleLoader(runtime::EVMModule &Mod, const Byte *Data,
                           size_t Size)
      : Mod(Mod), Data(Data), ModuleSize(Size) {}

  void load() {
    if (Data == nullptr || ModuleSize == 0) {
      throw common::getError(common::ErrorCode::InvalidRawData);
    }
    Mod.Code = Mod.initCode(ModuleSize);
    std::memcpy(Mod.Code, Data, ModuleSize);
    Mod.CodeSize = ModuleSize;
  }

private:
  runtime::EVMModule &Mod;
  const Byte *Data = nullptr;
  size_t ModuleSize = 0;
};

} // namespace zen::action

#endif // ZEN_ACTION_EVM_MODULE_LOADER_H
