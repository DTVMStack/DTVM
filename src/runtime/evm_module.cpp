// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/evm_module.h"

#include "action/compiler.h"
#include "action/evm_module_loader.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/codeholder.h"
#include "runtime/symbol_wrapper.h"
#include "utils/statistics.h"
#include "utils/wasm.h"

#include <memory>
#include <string>

#ifdef ZEN_ENABLE_MULTIPASS_JIT
#include "compiler/evm_compiler.h"
#endif

namespace zen::runtime {

EVMModule::EVMModule(Runtime *RT)
    : BaseModule(RT, ModuleType::EVM), Code(nullptr), CodeSize(0) {
  // do nothing
}

EVMModule::~EVMModule() {
  if (Name) {
    this->freeSymbol(Name);
    Name = common::WASM_SYMBOL_NULL;
  }

  if (Code) {
    deallocate(Code);
  }
}

EVMModuleUniquePtr EVMModule::newEVMModule(Runtime &RT,
                                           CodeHolderUniquePtr CodeHolder) {
  void *ObjBuf = RT.allocate(sizeof(EVMModule));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) EVMModule(&RT);
  EVMModuleUniquePtr Mod(RawMod);

  const uint8_t *Data = static_cast<const uint8_t *>(CodeHolder->getData());
  size_t CodeSize = CodeHolder->getSize();

  action::EVMModuleLoader Loader(*Mod, reinterpret_cast<const Byte *>(Data),
                                 CodeSize);

  auto &Stats = RT.getStatistics();
  auto Timer = Stats.startRecord(utils::StatisticPhase::Load);

  Loader.load();

  Stats.stopRecord(Timer);

  Mod->CodeHolder = std::move(CodeHolder);

  ZEN_ASSERT(RT.getEVMHost());
  Mod->Host = RT.getEVMHost();

  if (RT.getConfig().Mode != common::RunMode::InterpMode) {
    action::performEVMJITCompile(*Mod);
  }

  return Mod;
}

const evm::EVMInterpreterCache &EVMModule::getInterpreterCache() const {
  if (!InterpreterCacheInitialized) {
    initInterpreterCache();
    InterpreterCacheInitialized = true;
  }
  return InterpCache;
}

void EVMModule::initInterpreterCache() const {
  evm::buildInterpreterCache(InterpCache, Code, CodeSize);
}

} // namespace zen::runtime
