// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_DESTROYER_H
#define ZEN_RUNTIME_DESTROYER_H

#include "common/mem_pool.h"
#include <memory>

namespace zen::runtime {

class CodeHolder;
class HostModule;
class Module;
class Instance;
class Isolation;
class SymbolWrapper;

#ifdef ZEN_ENABLE_EVM
class EVMModule;
class EVMInstance;
#endif // ZEN_ENABLE_EVM

class RuntimeObjectDestroyer {
public:
  template <typename T> void operator()(T *Ptr);
  ~RuntimeObjectDestroyer() = default;
};

template <typename T>
using RuntimeObjectUniquePtr = std::unique_ptr<T, RuntimeObjectDestroyer>;
using CodeHolderUniquePtr = RuntimeObjectUniquePtr<CodeHolder>;
using HostModuleUniquePtr = RuntimeObjectUniquePtr<HostModule>;
using ModuleUniquePtr = RuntimeObjectUniquePtr<Module>;
using InstanceUniquePtr = RuntimeObjectUniquePtr<Instance>;
using IsolationUniquePtr = RuntimeObjectUniquePtr<Isolation>;
using SymbolWrapperUniquePtr = RuntimeObjectUniquePtr<SymbolWrapper>;
#ifdef ZEN_ENABLE_EVM
using EVMModuleUniquePtr = RuntimeObjectUniquePtr<EVMModule>;
using EVMInstanceUniquePtr = RuntimeObjectUniquePtr<EVMInstance>;
#endif // ZEN_ENABLE_EVM

} // namespace zen::runtime

#endif // ZEN_RUNTIME_DESTROYER_H
