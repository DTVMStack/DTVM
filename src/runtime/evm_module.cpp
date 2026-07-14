// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/evm_module.h"

#include "action/compiler.h"
#include "action/evm_module_loader.h"
#include "common/enums.h"
#include "common/errors.h"
#include "runtime/codeholder.h"
#include "runtime/symbol_wrapper.h"
#include "host/evm/crypto.h"
#include "utils/others.h"
#include "utils/statistics.h"
#include "utils/wasm.h"

#include <memory>
#include <string>

#ifdef ZEN_ENABLE_MULTIPASS_JIT
#include "compiler/evm_compiler.h"
#endif
#include "compiler/evm_frontend/evm_analyzer.h"

namespace zen::runtime {

namespace {

#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
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
#endif

} // namespace

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

EVMModuleUniquePtr
EVMModule::newEVMModule(Runtime &RT, CodeHolderUniquePtr CodeHolder,
                        evmc_revision Rev,
                        const std::string &DiagnosticModuleName,
                        EVMMemorySpecializationProfile MemoryProfile) {
  void *ObjBuf = RT.allocate(sizeof(EVMModule));
  ZEN_ASSERT(ObjBuf);

  auto *RawMod = new (ObjBuf) EVMModule(&RT);
  EVMModuleUniquePtr Mod(RawMod);
  Mod->setRevision(Rev);
  Mod->setMemorySpecializationProfile(MemoryProfile);

  const uint8_t *Data = static_cast<const uint8_t *>(CodeHolder->getData());
  size_t CodeSize = CodeHolder->getSize();
  auto &Stats = RT.getStatistics();
  Mod->DiagnosticModuleName = DiagnosticModuleName.empty()
                                  ? std::string("unknown")
                                  : DiagnosticModuleName;
  Mod->DiagnosticCodeHash = "unknown";
  if (Stats.isEnabled()) {
    uint8_t CodeHash[32] = {};
    zen::host::evm::crypto::keccak256(Data, CodeSize, CodeHash);
    Mod->DiagnosticCodeHash =
        std::string("0x") + zen::utils::toHex(CodeHash, sizeof(CodeHash));
  }

  action::EVMModuleLoader Loader(*Mod, reinterpret_cast<const Byte *>(Data),
                                 CodeSize);

  auto Timer = Stats.startRecord(utils::StatisticPhase::Load);

  Loader.load();

  Stats.stopRecord(Timer);

  Mod->CodeHolder = std::move(CodeHolder);

  ZEN_ASSERT(RT.getEVMHost());
  Mod->Host = RT.getEVMHost();

  if (RT.getConfig().Mode != common::RunMode::InterpMode) {
    // Run the EVMAnalyzer once at module creation to determine if this
    // contract should fall back to interpreter. This avoids per-call O(n)
    // bytecode scans in the execute() hot path.
    COMPILER::EVMAnalyzer Analyzer(Rev);
    auto AnalyzerTimer =
        Stats.startRecord(utils::StatisticPhase::EVMAnalyzer);
    Analyzer.analyze(reinterpret_cast<const uint8_t *>(Mod->Code),
                     Mod->CodeSize);
    Stats.stopRecord(AnalyzerTimer);
    {
      auto FallbackTimer =
          Stats.startRecord(utils::StatisticPhase::EVMFallbackDecision);
      bool ShouldFallback = Analyzer.getJITSuitability().ShouldFallback;
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
      ShouldFallback =
          ShouldFallback ||
          hasUnresolvedCompatibleDynamicReturnTrampoline(Analyzer) ||
          Analyzer.hasUnresolvedDeepEntryJITRisk();
#endif
      Mod->ShouldFallbackToInterp = ShouldFallback;
      Stats.stopRecord(FallbackTimer);
    }
    if (!Mod->ShouldFallbackToInterp) {
      // JIT is about to compile this module -- mark the bytecode cache so the
      // SPP metering pipeline runs on first access.
      Mod->CacheNeedsSPP = true;
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
  evm::buildBytecodeCache(BytecodeCache, Code, CodeSize, Revision,
                          CacheNeedsSPP);
}

} // namespace zen::runtime
