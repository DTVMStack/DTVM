// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_RUNTIME_EVM_MODULE_H
#define ZEN_RUNTIME_EVM_MODULE_H

#include "evm/evm_cache.h"
#include "evmc/evmc.hpp"
#include "runtime/module.h"

#ifdef ZEN_ENABLE_JIT
namespace COMPILER {
class EVMJITCompiler;
}; // namespace COMPILER
#endif

namespace zen {

namespace runtime {

class EVMModule final : public BaseModule<EVMModule> {
  friend class RuntimeObjectDestroyer;
  friend class action::EVMModuleLoader;

public:
  using Byte = zen::common::Byte;
  static EVMModuleUniquePtr newEVMModule(Runtime &RT,
                                         CodeHolderUniquePtr CodeHolder);

  virtual ~EVMModule();

  Byte *Code;
  size_t CodeSize;
  evmc::Host *Host;

  const evm::EVMInterpreterCache &getInterpreterCache() const;

#ifdef ZEN_ENABLE_JIT
  common::CodeMemPool &getJITCodeMemPool() { return JITCodeMemPool; }

  void *getJITCode() const { return JITCode; }

  size_t getJITCodeSize() const { return JITCodeSize; }

  void setJITCodeAndSize(void *Code, size_t Size) {
    JITCode = Code;
    JITCodeSize = Size;
  }
#endif // ZEN_ENABLE_JIT

private:
  EVMModule(Runtime *RT);
  EVMModule(const EVMModule &Other) = delete;
  EVMModule &operator=(const EVMModule &Other) = delete;
  CodeHolderUniquePtr CodeHolder;

  Byte *initCode(size_t Size) { return (Byte *)allocateZeros(Size); }

  void initInterpreterCache() const;
  mutable bool InterpreterCacheInitialized = false;
  mutable evm::EVMInterpreterCache InterpCache;

#ifdef ZEN_ENABLE_JIT
  common::CodeMemPool JITCodeMemPool;
  void *JITCode = nullptr;
  size_t JITCodeSize = 0;
#endif // ZEN_ENABLE_JIT
};

} // namespace runtime
} // namespace zen

#endif // ZEN_RUNTIME_EVM_MODULE_H
