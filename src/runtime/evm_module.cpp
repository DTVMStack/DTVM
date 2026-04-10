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

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#include "compiler/evm_frontend/evm_analyzer.h"
#endif

#ifdef ZEN_ENABLE_MULTIPASS_JIT
#include "compiler/evm_compiler.h"
#endif

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#include "compiler/evm_frontend/evm_analyzer.h"
#endif

namespace zen::runtime {

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
namespace {

bool hasUnresolvedCompatibleDynamicReturnTrampoline(
    const COMPILER::EVMAnalyzer &Analyzer) {
  for (const auto &[EntryPC, Info] : Analyzer.getBlockInfos()) {
    if (!Info.HasDynamicJump) {
      continue;
    }
    if (Analyzer.getOutgoingCompatibleDynamicJumpShapeClassForBlock(EntryPC) ==
        0) {
      continue;
    }
    if (!Analyzer
             .canTransferCompatibleDynamicJumpTargetsWithoutRuntimeMaterialization(
                 EntryPC)) {
      return true;
    }
  }
  return false;
}

} // namespace
#endif

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
                                           CodeHolderUniquePtr CodeHolder,
                                           evmc_revision Rev) {
  void *ObjBuf = RT.allocate(sizeof(EVMModule));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) EVMModule(&RT);
  EVMModuleUniquePtr Mod(RawMod);
  Mod->setRevision(Rev);

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
#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
    // Run the EVMAnalyzer once at module creation to determine if this
    // contract should fall back to interpreter. This avoids per-call O(n)
    // bytecode scans in the execute() hot path.
    COMPILER::EVMAnalyzer Analyzer(Rev);
    Analyzer.analyze(reinterpret_cast<const uint8_t *>(Mod->Code),
                     Mod->CodeSize);
    Mod->ShouldFallbackToInterp =
        Analyzer.getJITSuitability().ShouldFallback ||
        hasUnresolvedCompatibleDynamicReturnTrampoline(Analyzer);
    if (!Mod->ShouldFallbackToInterp)
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
    {
      action::performEVMJITCompile(*Mod);
    }
  }

  return Mod;
}

const evm::EVMBytecodeCache &EVMModule::getBytecodeCache() const {
  if (!BytecodeCacheInitialized) {
    initBytecodeCache();
    BytecodeCacheInitialized = true;
  }
  return BytecodeCache;
}

void EVMModule::initBytecodeCache() const {
  evm::buildBytecodeCache(BytecodeCache, Code, CodeSize, Revision);
}

} // namespace zen::runtime
