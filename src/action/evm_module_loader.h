// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_ACTION_EVM_MODULE_LOADER_H
#define ZEN_ACTION_EVM_MODULE_LOADER_H

#include "action/module_loader.h"
#include "runtime/evm_module.h"

namespace zen::action {

class EVMModuleLoader final {
public:
  explicit EVMModuleLoader(runtime::EVMModule &Mod,
                           const std::vector<uint8_t> &Data)
      : Mod(Mod), Data(Data) {}

  void load() {
    if (Data.empty()) {
      throw common::getError(common::ErrorCode::InvalidRawData);
    }
    Mod.Code = Mod.initCode(Data.size());
    std::memcpy(Mod.Code, Data.data(), Data.size());
    Mod.CodeSize = Data.size();
  }

private:
  runtime::EVMModule &Mod;
  const std::vector<uint8_t> Data;
};

} // namespace zen::action

#endif // ZEN_ACTION_EVM_MODULE_LOADER_H
