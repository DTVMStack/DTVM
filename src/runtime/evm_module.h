// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_RUNTIME_EVM_MODULE_H
#define ZEN_RUNTIME_EVM_MODULE_H

#include "evmc/evmc.hpp"
#include "runtime/module.h"

namespace zen {

namespace runtime {

class EVMModule final : public BaseModule<EVMModule> {
  friend class RuntimeObjectDestroyer;
  friend class action::EVMModuleLoader;

public:
  static EVMModuleUniquePtr newEVMModule(Runtime &RT,
                                         CodeHolderUniquePtr CodeHolder);

  virtual ~EVMModule();

  uint8_t *Code;
  size_t CodeSize;
  evmc::Host *Host;

private:
  EVMModule(Runtime *RT);
  EVMModule(const EVMModule &Other) = delete;
  EVMModule &operator=(const EVMModule &Other) = delete;
  CodeHolderUniquePtr CodeHolder;

  uint8_t *initCode(size_t Size) { return (uint8_t *)allocateZeros(Size); }
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_EVM_MODULE_H
