// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/isolation.h"

#include "runtime/evm_instance.h"
#include "runtime/instance.h"

extern struct WNINativeInterface_ *wni_functions();
namespace zen::runtime {

IsolationUniquePtr Isolation::newIsolation(Runtime &RT) noexcept {
  void *Buf = RT.allocate(sizeof(Isolation));
  ZEN_ASSERT(Buf);
  IsolationUniquePtr Iso(new (Buf) Isolation(RT));
  return Iso;
}

common::MayBe<Instance *>
Isolation::createInstance(Module &Mod, uint64_t GasLimit) noexcept {
#ifdef ZEN_ENABLE_BUILTIN_WASI
  // disable it temporally
  // if (!initWasi()) {
  //    return nullptr;
  //}
#endif

  InstanceUniquePtr Inst;

  auto &Stats = getRuntime()->getStatistics();
  auto Timer = Stats.startRecord(utils::StatisticPhase::Instantiation);
  try {
    Inst = Instance::newInstance(*this, Mod, GasLimit);
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    return Err;
  }
  Stats.stopRecord(Timer);
  ZEN_ASSERT(Inst);

  Instance *RawInst = Inst.get();
  auto EmplaceRet =
      InstancePool.emplace(RawInst, std::forward<InstanceUniquePtr>(Inst));
  if (!EmplaceRet.second) {
    return nullptr;
  }

  WNIEnv *Env = reinterpret_cast<WNIEnv *>(&WniEnv);
  Env->_functions = wni_functions();
  if (RawInst->hasMemory()) {
    const auto &MemInst = RawInst->getDefaultMemoryInst();
    Env->_linear_mem_base = reinterpret_cast<uintptr_t>(MemInst.MemBase);
    Env->_linear_mem_size = MemInst.MemSize;
    Env->_linear_mem_end = Env->_linear_mem_base + Env->_linear_mem_size;
  } else {
    Env->_linear_mem_base = 0;
    Env->_linear_mem_size = 0;
    Env->_linear_mem_end = 0;
  }

  return RawInst;
}

common::MayBe<EVMInstance *>
Isolation::createEVMInstance(EVMModule &Mod, uint64_t GasLimit) noexcept {
  ZEN_ASSERT(GasLimit <= INT64_MAX && "EVM gas limit overflow");
  EVMInstanceUniquePtr Inst;

  auto &Stats = getRuntime()->getStatistics();
  auto Timer = Stats.startRecord(utils::StatisticPhase::Instantiation);
  try {
    Inst = EVMInstance::newEVMInstance(*this, Mod, GasLimit);
  } catch (const Error &Err) {
    Stats.clearAllTimers();
    return Err;
  }
  Stats.stopRecord(Timer);
  ZEN_ASSERT(Inst);

  EVMInstance *RawInst = Inst.get();
  auto EmplaceRet = EVMInstancePool.emplace(
      RawInst, std::forward<EVMInstanceUniquePtr>(Inst));
  if (!EmplaceRet.second) {
    return nullptr;
  }

  // todo: Storage

  return RawInst;
}

bool Isolation::deleteInstance(Instance *Inst) noexcept {
  return InstancePool.erase(Inst) != 0;
}

bool Isolation::deleteEVMInstance(EVMInstance *Inst) noexcept {
  return EVMInstancePool.erase(Inst) != 0;
}

bool Isolation::initWasi() {
  return initNativeModuleCtx(common::WASM_SYMBOL_wasi_snapshot_preview1);
}

bool Isolation::initNativeModuleCtx(WASMSymbol ModName) {
  HostModule *HostMod = getRuntime()->resolveHostModule(ModName);
  if (!HostMod) {
    return false;
  }

  const auto &FuncList = HostMod->getHostFuntionList();
  uint32_t NumHostFunctions = HostMod->getNumHostFunctions();
  if (!NumHostFunctions) {
    return false;
  }

  // check if initCtx exists and signature is valid
  uint32_t InitCtxFuncId = 0;
  for (InitCtxFuncId = 0; InitCtxFuncId < NumHostFunctions; ++InitCtxFuncId) {
    if (FuncList[InitCtxFuncId]->_name == common::WASM_SYMBOL_init_ctx) {
      break;
    }
  }

  if (InitCtxFuncId >= NumHostFunctions) {
    return true; // not necessary to call initCtx for this module. it's not
                 // an error.
  }

  if (!FuncList[InitCtxFuncId]->_isReserved ||
      FuncList[InitCtxFuncId]->_param_count != 6 ||
      FuncList[InitCtxFuncId]->_ret_count != 1) {
    // not match initCtx signature, it's a user defined initCtx, not
    // reserved initCtx.
    return true;
  }

  // check signature

  // call initCtx
  VNMI_RESERVED_INIT_CTX_TYPE InitCtxFn =
      reinterpret_cast<VNMI_RESERVED_INIT_CTX_TYPE>(
          FuncList[InitCtxFuncId]->_ptr);
  void *Ctx = InitCtxFn(HostMod->getVNMIEnv(), nullptr, 0, nullptr, 0, nullptr,
                        0, nullptr, 0, nullptr, 0);

  // note: for simplicity, currently only supports one WNIEnv and only one
  // user defined ctx certainly.
  WNIEnv *Env = reinterpret_cast<WNIEnv *>(&WniEnv);
  Env->_user_defined_ctx = Ctx;

  return true;
}

} // namespace zen::runtime
