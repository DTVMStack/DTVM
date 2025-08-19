// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_RUNTIME_H
#define ZEN_RUNTIME_RUNTIME_H

#include "common/const_string_pool.h"
#include "common/enums.h"
#include "common/errors.h"
#include "common/mem_pool.h"
#include "common/type.h"
#include "evmc/evmc.hpp"
#include "runtime/config.h"
#include "runtime/destroyer.h"
#include "runtime/vnmi.h"
#include "utils/logging.h"
#include "utils/statistics.h"

#include <unordered_map>
#include <utility>
#include <vector>

namespace zen::runtime {

class HostModule;
class Module;
class EVMModule;
class Instance;
class Runtime;
class Isolation;

typedef struct VNMIEnvInternal_ {
  VNMIEnv _env;
  Runtime *_runtime;
} VNMIEnvInternal;

#define LOAD_HOST_MODULE(RT, Namespace, ModName)                               \
  RT->loadHostModule(Namespace::m_##ModName##_desc)
#define MERGE_HOST_MODULE(RT, OriginMod, Namespace, ModName)                   \
  RT->mergeHostModule(OriginMod, Namespace::m_##ModName##_desc)

// Only some of the methods of the Runtime class are thread-safe

class Runtime final {
  using MemPool = common::SysMemPool;
  using ConstStringPool = common::ConstStringPool;
  using Error = common::Error;
  using ErrorCode = common::ErrorCode;
  using TypedValue = common::TypedValue;
  using RunMode = common::RunMode;

public:
  Runtime(const Runtime &Other) = delete;
  Runtime &operator=(const Runtime &Other) = delete;
  ~Runtime() { cleanRuntime(); }

  static std::unique_ptr<Runtime>
  newRuntime(RuntimeConfig Config = {}) noexcept {
    if (!Config.validate()) {
      ZEN_LOG_ERROR("runtime config validation failed");
      return nullptr;
    }

    std::unique_ptr<Runtime> RT(new Runtime(Config));

    if (!RT->initRuntime()) {
      ZEN_LOG_ERROR("initialize runtime failed");
      return nullptr;
    }

#ifdef ZEN_ENABLE_DWASM
    RT->setVmMaxMemoryPages(DWASM_DEFAULT_MAX_VM_LINEAR_MEMORY_PAGES);
#endif // ZEN_ENABLE_DWASM

    return RT;
  }

  static std::unique_ptr<Runtime>
  newEVMRuntime(RuntimeConfig Config = {},
                evmc::Host *EVMHost = nullptr) noexcept {
    auto RT = newRuntime(Config);

    // SinglepassMode is not supported for EVMRuntime
    ZEN_ASSERT(Config.Mode != RunMode::SinglepassMode);

    RT->EVMHost = EVMHost;

    return RT;
  }

  // ==================== Runtime Base Methods ====================

  /// \warning not thread-safe
  WASMSymbol newSymbol(const char *Str, size_t Len) {
    return SymbolPool.newSymbol(Str, Len);
  }

  WASMSymbol probeSymbol(const char *Str, size_t Len) {
    return SymbolPool.probeSymbol(Str, Len);
  }

  /// \warning not thread-safe
  void freeSymbol(WASMSymbol Symbol) { return SymbolPool.freeSymbol(Symbol); }

  const char *dumpSymbolString(WASMSymbol Symbol) {
    return SymbolPool.dumpSymbolString(Symbol);
  }

  void *allocate(size_t Size, size_t Align = 0) {
    return MPool.allocate(Size, Align);
  }

  void *allocateZeros(size_t Size, size_t Align = 0) {
    return MPool.allocateZeros(Size, Align);
  }

  void *reallocate(void *Ptr, size_t OldSize, size_t NewSize) {
    return MPool.reallocate(Ptr, OldSize, NewSize);
  }

  void deallocate(void *Ptr) { MPool.deallocate(Ptr); }

  MemPool *getMemAllocator() { return &MPool; }

  /// \warning not thread-safe using the returned result
  ConstStringPool *getSymbolPool() { return &SymbolPool; }

  // ==================== Runtime Tool Methods ====================

  /// \warning not thread-safe
  HostModule *loadHostModule(BuiltinModuleDesc &HostModDesc) noexcept;

  /// \warning not thread-safe
  bool mergeHostModule(HostModule *HostMod,
                       BuiltinModuleDesc &OtherHostModDesc) noexcept;

  /// \warning not thread-safe
  /// \return true if the module existed otherwise false
  bool unloadHostModule(HostModule *HostMod) noexcept;

  HostModule *resolveHostModule(WASMSymbol HostModName) const;

  /// \warning not thread-safe
  common::MayBe<Module *>
  loadModule(const std::string &Filename,
             const std::string &EntryHint = "") noexcept;

  /// \warning not thread-safe
  common::MayBe<Module *>
  loadModule(const std::string &ModName, const void *Data, size_t DataSize,
             const std::string &EntryHint = "") noexcept;

  /// \warning not thread-safe
  common::MayBe<EVMModule *>
  loadEVMModule(const std::string &Filename) noexcept;

  /// \warning not thread-safe
  common::MayBe<EVMModule *> loadEVMModule(const std::string &ModName,
                                           const void *Data,
                                           size_t DataSize) noexcept;

  /// \warning not thread-safe
  bool unloadModule(const Module *Mod) noexcept;

  /// \warning not thread-safe
  bool unloadEVMModule(const EVMModule *Mod) noexcept;

  Isolation *createManagedIsolation() noexcept;

  bool deleteManagedIsolation(Isolation *Iso) noexcept;

  // Please ensure that the lifecycle of the islocation is a subset of the
  // runtime lifecycle, because the instance in the unmanaged Isolation still
  // uses the runtime internally
  IsolationUniquePtr createUnmanagedIsolation() noexcept;

  bool callWasmMain(Instance &Inst, std::vector<TypedValue> &Results);

  bool callWasmFunction(Instance &Inst, const std::string &FuncName,
                        const std::vector<std::string> &Args,
                        std::vector<TypedValue> &Results);

  bool callWasmFunction(Instance &Inst, uint32_t FuncIdx,
                        const std::vector<TypedValue> &Args,
                        std::vector<TypedValue> &Results);

#ifdef ZEN_ENABLE_BUILTIN_WASI
  /// \warning not thread-safe
  void setWASIArgs(const std::string &wasm_name,
                   const std::vector<std::string> &args) {
    if (_argv_list || _argv_buf) {
      return;
    }

    std::vector<std::string> wasi_args = std::move(args);
    wasi_args.insert(wasi_args.begin(), wasm_name);

    _argv_buf_size = 0;
    for (const std::string &arg : wasi_args) {
      _argv_buf_size += arg.size() + 1;
    }

    if (_argv_buf_size > 0) {
      _argv_buf = (char *)allocateZeros(_argv_buf_size);
    }
    _argc = wasi_args.size();
    uint64_t argv_list_size = sizeof(char *) * _argc;
    if (argv_list_size > 0) {
      _argv_list = (char **)allocate(argv_list_size);
    }
    ZEN_ASSERT(_argv_list && _argv_buf);
    uint32_t argv_buf_offset = 0;
    for (uint32_t i = 0; i < _argc; i++) {
      const std::string &arg = wasi_args[i];
      _argv_list[i] = _argv_buf + argv_buf_offset;
      memcpy(_argv_list[i], arg.c_str(), arg.size());
      argv_buf_offset += arg.size() + 1;
    }
  }

  /// \warning not thread-safe
  void setWASIEnvs(const std::vector<std::string> &envs) {
    if (_env_buf || _env_list) {
      return;
    }
    _env_buf_size = 0;
    for (const std::string &env : envs) {
      _env_buf_size += env.size() + 1;
    }

    if (_env_buf_size > 0) {
      _env_buf = static_cast<char *>(allocateZeros(_env_buf_size));
    }
    _env_count = envs.size();
    uint64_t env_list_size = sizeof(char *) * _env_count;

    if (env_list_size > 0) {
      _env_list = static_cast<char **>(allocate(env_list_size));
    }
    uint32_t env_buf_offset = 0;
    for (uint32_t i = 0; i < _env_count; i++) {
      const std::string &env = envs[i];
      ZEN_ASSERT(_env_list);
      _env_list[i] = _env_buf + env_buf_offset;
      memcpy(_env_list[i], env.c_str(), env.size());
      env_buf_offset += env.size() + 1;
    }
  }

  /// \warning not thread-safe
  void setWASIDirs(const std::vector<std::string> &dirs) {
    if (_dirs_buf || _dirs_list) {
      return;
    }
    uint64_t dirs_buf_size = 0;
    for (const std::string &dir : dirs) {
      dirs_buf_size += dir.size() + 1;
    }

    if (dirs_buf_size > 0) {
      _dirs_buf = static_cast<char *>(allocateZeros(dirs_buf_size));
    }
    _dirs_count = dirs.size();
    uint64_t dirs_list_size = sizeof(char *) * _dirs_count;

    if (dirs_list_size > 0) {
      _dirs_list = static_cast<char **>(allocate(dirs_list_size));
    }
    uint32_t dirs_buf_offset = 0;
    for (uint32_t i = 0; i < _dirs_count; i++) {
      const std::string &dir = dirs[i];
      ZEN_ASSERT(_dirs_list);
      _dirs_list[i] = _dirs_buf + dirs_buf_offset;
      memcpy(_dirs_list[i], dir.c_str(), dir.size());
      dirs_buf_offset += dir.size() + 1;
    }
  }

  const char **getWASIArgs(uint32_t &argc) const {
    argc = _argc;
    return const_cast<const char **>(_argv_list);
  }
  char *getWASIArgsBuf(uint32_t &argv_buf_size) const {
    argv_buf_size = _argv_buf_size;
    return _argv_buf;
  }
  const char **getWASIEnvs(uint32_t &env_count) const {
    env_count = _env_count;
    return const_cast<const char **>(_env_list);
  }
  char *getWASIEnvsBuf(uint32_t &env_buf_size) const {
    env_buf_size = _env_buf_size;
    return _env_buf;
  }
  const char **getWASIDirs(uint32_t &dirs_count) const {
    dirs_count = _dirs_count;
    return const_cast<const char **>(_dirs_list);
  }
#endif

  /// \warning not thread-safe
  void setVmMaxMemoryPages(uint32_t V) { VMMaxMemPages = V; }

  uint32_t getVmMaxMemoryPages() const { return VMMaxMemPages; }

  const RuntimeConfig &getConfig() const { return Config; }

  utils::Statistics &getStatistics() { return Stats; }

  void startCPUTracing();

  void endCPUTracing();

  void callWasmFunctionOnPhysStack(
      Instance &Inst, uint32_t FuncIdx, const std::vector<TypedValue> &Args,
      std::vector<common::TypedValue> &Results) noexcept;

  void callEVMMain(EVMInstance &Inst, std::vector<uint8_t> &Result);

  evmc::Host *getEVMHost() const { return EVMHost; }

  /* **************** [End] Runtime Tool Methods  **************** */
private:
  Runtime(const RuntimeConfig &Configuration)
      : Config(Configuration), Stats(Config.EnableStatistics) {}

  bool initRuntime() { return SymbolPool.initPool(); }

  void cleanRuntime();

  Module *loadModule(WASMSymbol ModName, CodeHolderUniquePtr CodeHolder,
                     const std::string &EntryHint = "");

  EVMModule *loadEVMModule(EVMSymbol ModName, CodeHolderUniquePtr CodeHolder);

  void callWasmFunctionInInterpMode(Instance &Inst, uint32_t FuncIdx,
                                    const std::vector<TypedValue> &Args,
                                    std::vector<common::TypedValue> &Results);

  void callEVMInInterpMode(EVMInstance &Inst, std::vector<uint8_t> &Result);

#ifdef ZEN_ENABLE_JIT
  void callWasmFunctionInJITMode(Instance &Inst, uint32_t FuncIdx,
                                 const std::vector<TypedValue> &Args,
                                 std::vector<common::TypedValue> &Results);

  void callEVMInJITMode(EVMInstance &Inst, std::vector<uint8_t> &Result);
#endif

  common::Mutex Mtx;

  MemPool MPool;

  ConstStringPool SymbolPool;

  evmc::Host *EVMHost = nullptr;

  // supplementary module, libc, wasi, and other user defined native modules
  std::unordered_map<WASMSymbol, HostModuleUniquePtr> HostModulePool;
  // multiple module mode
  std::unordered_map<WASMSymbol, ModuleUniquePtr> ModulePool;

  std::unordered_map<EVMSymbol, EVMModuleUniquePtr> EVMModulePool;

  std::unordered_map<Isolation *, IsolationUniquePtr> Isolations;

#ifdef ZEN_ENABLE_BUILTIN_WASI
  /* WASI releated */
  char *_argv_buf = nullptr;
  uint32_t _argv_buf_size = 0;
  char **_argv_list = nullptr;
  uint32_t _argc = 0;

  char *_env_buf = nullptr;
  uint32_t _env_buf_size = 0;
  char **_env_list = nullptr;
  uint32_t _env_count = 0;

  char *_dirs_buf = nullptr;
  char **_dirs_list = nullptr;
  uint32_t _dirs_count = 0;
#endif

  // _vm_max_memory_pages is the max-allowed linear memory pages count
  // limited by vm. if _vm_max_memory_pages == 0, it means no-limit
  uint32_t VMMaxMemPages = 0;

  RuntimeConfig Config;

  utils::Statistics Stats;
};

} // namespace zen::runtime

#endif // ZEN_RUNTIME_RUNTIME_H
