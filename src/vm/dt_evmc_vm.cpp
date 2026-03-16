// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "dt_evmc_vm.h"
#include "common/enums.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "runtime/config.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "wrapped_host.h"
#include <algorithm>

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/helpers.h>

#include <cstdlib>
#include <cstring>

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
#include "compiler/evm_frontend/evm_analyzer.h"
#endif

namespace {

using namespace zen::runtime;
using namespace zen::common;

// RAII helper for temporarily changing runtime configuration
class ScopedConfig {
public:
  ScopedConfig(Runtime *Runtime, const RuntimeConfig &NewConfig)
      : RT(Runtime), PreviousConfig(Runtime->getConfig()) {
    RT->setConfig(NewConfig);
  }

  ~ScopedConfig() { RT->setConfig(PreviousConfig); }

private:
  Runtime *RT;
  RuntimeConfig PreviousConfig;
};

// Forward declaration for InstanceGuard
struct DTVM;

// RAII guard for unloading transient modules that must not be persisted in the
// address-based cache. Destruction order matters: instance guards must run
// before unloading the module they execute.
struct ModuleGuard {
  DTVM *VM;
  EVMModule *Mod;
  bool ShouldUnload;

  ModuleGuard(DTVM *VM, EVMModule *Mod, bool ShouldUnload)
      : VM(VM), Mod(Mod), ShouldUnload(ShouldUnload) {}

  ModuleGuard(const ModuleGuard &) = delete;
  ModuleGuard &operator=(const ModuleGuard &) = delete;

  ~ModuleGuard();

  void release() { ShouldUnload = false; }
};

// RAII helper for host context save/restore (exception safety).
// Ensures host context is always restored on all exit paths, including
// exceptions.
struct HostContextScope {
  ::WrappedHost *ExecHost;
  const evmc_host_interface *PrevInterface;
  evmc_host_context *PrevContext;

  HostContextScope(::WrappedHost *Host, const evmc_host_interface *Interface,
                   evmc_host_context *Context)
      : ExecHost(Host), PrevInterface(Host->getInterface()),
        PrevContext(Host->getContext()) {
    ExecHost->reinitialize(Interface, Context);
  }

  ~HostContextScope() { ExecHost->reinitialize(PrevInterface, PrevContext); }

  // Non-copyable
  HostContextScope(const HostContextScope &) = delete;
  HostContextScope &operator=(const HostContextScope &) = delete;
};

// ---- Address-based module cache types ----

struct CodeAddrRevKey {
  evmc_address Addr;
  evmc_revision Rev;
};

struct CodeAddrRevHash {
  size_t operator()(const CodeAddrRevKey &K) const {
    uint64_t H;
    std::memcpy(&H, K.Addr.bytes + 12, sizeof(H));
    return H ^ (static_cast<size_t>(K.Rev) * 2654435761u);
  }
};

struct CodeAddrRevEqual {
  bool operator()(const CodeAddrRevKey &A, const CodeAddrRevKey &B) const {
    return A.Rev == B.Rev &&
           std::memcmp(A.Addr.bytes, B.Addr.bytes, sizeof(A.Addr.bytes)) == 0;
  }
};

/// Validate that the cached module's code matches the provided code.
/// Note: This relies on the host guaranteeing that deployed code at a given
/// address is immutable. We only check the head and tail (up to 256 bytes each)
/// as a defense-in-depth measure against accidental cache corruption.
/// For fully untrusted environments where hosts might reuse addresses for
/// different bytecode, a full CRC/hash check should be implemented instead.
bool validateCodeMatch(const uint8_t *Code, size_t CodeSize,
                       const EVMModule *Mod) {
  if (CodeSize != Mod->CodeSize)
    return false;
  if (CodeSize == 0)
    return true;
  auto *ModCode = reinterpret_cast<const uint8_t *>(Mod->Code);
  size_t HeadLen = std::min(CodeSize, static_cast<size_t>(256));
  if (std::memcmp(Code, ModCode, HeadLen) != 0)
    return false;
  if (CodeSize > 256) {
    size_t TailLen = std::min(CodeSize, static_cast<size_t>(256));
    size_t TailOffset = CodeSize - TailLen;
    if (std::memcmp(Code + TailOffset, ModCode + TailOffset, TailLen) != 0)
      return false;
  }
  return true;
}

bool parseBoolEnvValue(const char *Value, bool &ParsedValue) {
  if (std::strcmp(Value, "1") == 0 || std::strcmp(Value, "true") == 0 ||
      std::strcmp(Value, "TRUE") == 0) {
    ParsedValue = true;
    return true;
  }
  if (std::strcmp(Value, "0") == 0 || std::strcmp(Value, "false") == 0 ||
      std::strcmp(Value, "FALSE") == 0) {
    ParsedValue = false;
    return true;
  }
  return false;
}

// VM interface for DTVM
struct DTVM : evmc_vm {
  DTVM();
  ~DTVM() {
    // Clean up cached instance first (before modules it may reference)
    if (CachedMainInst && Iso) {
      Iso->deleteEVMInstance(CachedMainInst);
      CachedMainInst = nullptr;
    }

    // Clean up cached instance for depth > 0
    if (CacheInsts.size() > 0 && Iso) {
      for (auto It : CacheInsts) {
        Iso->deleteEVMInstance(It);
      }
    }

    // Unload all address-cached modules
    if (RT) {
      for (auto &P : AddrCache) {
        if (!RT->unloadEVMModule(P.second)) {
          ZEN_LOG_ERROR("failed to unload EVM module");
        }
      }
    }
    if (Iso) {
      RT->deleteManagedIsolation(Iso);
    }
  }
  RuntimeConfig Config = {.Format = InputFormat::EVM,
                          .Mode = RunMode::MultipassMode,
                          .EnableEvmGasMetering = true};
  std::unique_ptr<Runtime> RT;
  std::unique_ptr<::WrappedHost> ExecHost;
  Isolation *Iso = nullptr;

  // ---- Module & instance cache (shared by interpreter and multipass) ----
  // L0: pointer-based inline cache (fastest, 2 integer comparisons)
  const uint8_t *LastCodePtr = nullptr;
  size_t LastCodeSize = 0;
  EVMModule *L0Mod = nullptr;
  // L1: address-based cache map (code_address + rev -> module)
  std::unordered_map<CodeAddrRevKey, EVMModule *, CodeAddrRevHash,
                     CodeAddrRevEqual>
      AddrCache;
  uint64_t ModCounter = 0;
  // Cached EVMInstance to avoid alloc/free (~33KB) on every call
  EVMInstance *CachedMainInst = nullptr;
  // Cached InterpreterExecContext (interpreter mode only)
  std::unique_ptr<zen::evm::InterpreterExecContext> CachedCtx;
  // Instance pool for depth > 0
  std::vector<EVMInstance *> CacheInsts;
};

ModuleGuard::~ModuleGuard() {
  if (ShouldUnload && Mod && VM && VM->RT) {
    if (!VM->RT->unloadEVMModule(Mod)) {
      ZEN_LOG_ERROR("failed to unload transient EVM module");
    }
  }
}

/// The implementation of the evmc_vm::destroy() method.
void destroy(evmc_vm *VMInstance) { delete static_cast<DTVM *>(VMInstance); }

/// The implementation of the evmc_vm::get_capabilities() method.
evmc_capabilities_flagset get_capabilities(evmc_vm * /*instance*/) {
  return EVMC_CAPABILITY_EVM1;
}

/// VM options.
///
/// The implementation of the evmc_vm::set_option() method.
/// VMs are allowed to omit this method implementation.
enum evmc_set_option_result set_option(evmc_vm *VMInstance, const char *Name,
                                       const char *Value) {
  auto *VM = static_cast<DTVM *>(VMInstance);
  if (std::strcmp(Name, "mode") == 0) {
    if (std::strcmp(Value, "interpreter") == 0) {
      VM->Config.Mode = RunMode::InterpMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "multipass") == 0) {
      VM->Config.Mode = RunMode::MultipassMode;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  } else if (std::strcmp(Name, "enable_gas_metering") == 0) {
    if (std::strcmp(Value, "true") == 0) {
      VM->Config.EnableEvmGasMetering = true;
      return EVMC_SET_OPTION_SUCCESS;
    } else if (std::strcmp(Value, "false") == 0) {
      VM->Config.EnableEvmGasMetering = false;
      return EVMC_SET_OPTION_SUCCESS;
    } else {
      return EVMC_SET_OPTION_INVALID_VALUE;
    }
  }
  return EVMC_SET_OPTION_INVALID_NAME;
}

/// Ensure RT and Iso are initialized. Returns false on failure.
bool ensureRuntimeAndIsolation(DTVM *VM) {
  if (!VM->RT) {
    VM->RT = Runtime::newEVMRuntime(VM->Config, VM->ExecHost.get());
    if (!VM->RT)
      return false;
  }
  if (!VM->Iso) {
    VM->Iso = VM->RT->createManagedIsolation();
    if (!VM->Iso)
      return false;
  }
  return true;
}

bool shouldUsePersistentModuleCache(const evmc_message *Msg) {
  // CREATE/CREATE2 initcode and nested execution can change code frequently
  // and may recurse. Reusing address-keyed cached modules for those cases can
  // evict a module that is still active on the current execution stack.
  return Msg != nullptr && Msg->depth == 0 && Msg->kind != EVMC_CREATE &&
         Msg->kind != EVMC_CREATE2;
}

EVMModule *loadTransientModule(DTVM *VM, const uint8_t *Code, size_t CodeSize,
                               evmc_revision Rev) {
  std::string ModName = "tmp_mod_" + std::to_string(VM->ModCounter++);
  auto ModRet = VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev);
  if (!ModRet)
    return nullptr;
  return *ModRet;
}

/// Find or load a cached EVMModule using two-level cache:
///   L0 (code pointer+size) -> L1 (address map) -> Cold load.
/// Shared by both interpreter and multipass paths.
/// Returns nullptr on failure.
EVMModule *findModuleCached(DTVM *VM, const uint8_t *Code, size_t CodeSize,
                            evmc_revision Rev, const evmc_message *Msg,
                            bool &IsTransient) {
  if (!shouldUsePersistentModuleCache(Msg)) {
    IsTransient = true;
    return loadTransientModule(VM, Code, CodeSize, Rev);
  }

  IsTransient = false;

  // L0 disabled: pointer comparison is unsafe when callers reuse addresses
  // for different bytecode (e.g. test frameworks, repeated allocations).
  // Fall through to L1 address-based lookup with content validation.

  EVMModule *Mod = nullptr;

  // L1: Address-based map lookup
  CodeAddrRevKey AddrKey{Msg->code_address, Rev};
  auto It = VM->AddrCache.find(AddrKey);
  if (It != VM->AddrCache.end() &&
      validateCodeMatch(Code, CodeSize, It->second)) {
    Mod = It->second;
  } else {
    // Cold path: full module load
    // If validation failed for an existing entry, evict the stale module
    if (It != VM->AddrCache.end()) {
      EVMModule *OldMod = It->second;
      if (VM->L0Mod == OldMod && Msg->depth == 0)
        VM->L0Mod = nullptr;
      VM->RT->unloadEVMModule(OldMod);
      VM->AddrCache.erase(It);
    }
    std::string ModName = "mod_" + std::to_string(VM->ModCounter++);
    auto ModRet = VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev);
    if (!ModRet)
      return nullptr;
    Mod = *ModRet;
    VM->AddrCache[AddrKey] = Mod;
  }

  // Update L0 cache members. Even though L0 lookup is disabled, we maintain
  // these state variables for two reasons:
  // 1. Eviction tracking: If a stale L1 entry is replaced, we need to
  // invalidate
  //    L0Mod if it pointed to the old module (done in the eviction path above).
  // 2. Future extensibility: It keeps the door open for re-enabling L0 later
  //    with a safer validation scheme (e.g., pointer + size + hash).
  VM->LastCodePtr = Code;
  VM->LastCodeSize = CodeSize;
  VM->L0Mod = Mod;
  return Mod;
}

/// Get or create an EVMInstance for the given module.
/// For top-level calls (Depth == 0), reuses a single cached main instance
/// when possible; for nested calls (Depth > 0), uses per-depth cached
/// instances stored in VM->CacheInsts, creating them lazily as needed.
/// The lifetime of all returned instances is managed by the DTVM object;
/// callers must not delete the returned pointer.
EVMInstance *getOrCreateInstance(DTVM *VM, EVMModule *Mod, evmc_revision Rev,
                                 int32_t Depth) {
  // if depth > 0, use cached instance
  if (Depth > 0) {
    EVMInstance *TempInst = nullptr;
    if (VM->CacheInsts.size() < static_cast<size_t>(Depth)) {
      auto InstRet = VM->Iso->createEVMInstance(*Mod, 0);
      if (!InstRet)
        return nullptr;
      TempInst = *InstRet;
      VM->CacheInsts.push_back(TempInst);
    } else {
      size_t Idx = Depth - 1;
      TempInst = VM->CacheInsts[Idx];
    }
    TempInst->resetForNewCall(Rev, *Mod);
    return TempInst;
  }

  // if depth == 0, reuse cached main instance
  EVMInstance *TheInst = VM->CachedMainInst;
  // Create new instance if cache is empty or module mismatch
  if (!TheInst || TheInst->getModule() != Mod) {
    if (TheInst) {
      // Reuse existing instance with new module
      TheInst->resetForNewCall(Rev, *Mod);
    } else {
      // Allocate new instance and cache it
      auto InstRet = VM->Iso->createEVMInstance(*Mod, 0);
      if (!InstRet)
        return nullptr;
      TheInst = *InstRet;
      VM->CachedMainInst = TheInst;
    }
  } else {
    // Cache hit: same module, just reset with new revision
    TheInst->resetForNewCall(Rev);
  }

  return TheInst;
}

/// Fast path for interpreter mode: reuse cached instance, call interpreter
/// directly. This avoids per-call EVMInstance alloc/free and bypasses
/// Runtime::callEVMMain overhead.
evmc_result executeInterpreterFastPath(DTVM *VM,
                                       const evmc_host_interface *Host,
                                       evmc_host_context *Context,
                                       evmc_revision Rev,
                                       const evmc_message *Msg,
                                       const uint8_t *Code, size_t CodeSize) {
  // RAII guard for host context save/restore (exception safety)
  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  // Ensure runtime and isolation exist
  if (!ensureRuntimeAndIsolation(VM)) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Module lookup: L1 address-based cache -> Cold load
  bool IsTransientMod = false;
  EVMModule *Mod =
      findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
  if (!Mod) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  ModuleGuard ModGuard(VM, Mod, IsTransientMod);

  // Instance reuse (shared only for cacheable top-level calls)
  EVMInstance *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Trigger bytecodeCache build if not yet done (lazy, cached on module)
  (void)Mod->getBytecodeCache();

  // Call interpreter directly, bypassing Runtime::callEVMMain overhead
  evmc_message MsgWithCode = *Msg;
  MsgWithCode.code = reinterpret_cast<uint8_t *>(Mod->Code);
  MsgWithCode.code_size = Mod->CodeSize;
  TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
  TheInst->pushMessage(&MsgWithCode);

  const bool ReuseCachedInstance = !IsTransientMod && Msg->depth == 0;
  const bool DeleteInstanceAfterCall = Msg->depth > 0 || !ReuseCachedInstance;

  // For nested calls, create a new InterpreterExecContext
  // For cacheable top-level calls, reuse cached context
  std::unique_ptr<zen::evm::InterpreterExecContext> TempCtx;
  zen::evm::InterpreterExecContext *CtxPtr = nullptr;
  if (!ReuseCachedInstance) {
    // Nested call or transient module: create temporary context
    TempCtx = std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    CtxPtr = TempCtx.get();
  } else {
    // Top-level call: reuse cached context
    if (!VM->CachedCtx) {
      VM->CachedCtx =
          std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    } else {
      VM->CachedCtx->resetForNewCall(TheInst);
    }
    CtxPtr = VM->CachedCtx.get();
  }

  auto &Ctx = *CtxPtr;
  zen::evm::BaseInterpreter Interpreter(Ctx);
  Ctx.allocTopFrame(&MsgWithCode);
  Interpreter.interpret();

  evmc::Result Result =
      std::move(const_cast<evmc::Result &>(Ctx.getExeResult()));
  Result.gas_left = TheInst->getGas();

  return Result.release_raw();
}

/// The implementation of the evmc_vm::execute() method.
evmc_result execute(evmc_vm *EVMInstance, const evmc_host_interface *Host,
                    evmc_host_context *Context, enum evmc_revision Rev,
                    const evmc_message *Msg, const uint8_t *Code,
                    size_t CodeSize) {
  auto *VM = static_cast<DTVM *>(EVMInstance);

  // Interpreter mode: use optimized fast path (bypasses callEVMMain)
  if (VM->Config.Mode == RunMode::InterpMode) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }

  // ---- Multipass / other modes: use callEVMMain for JIT execution ----
  // RAII guard for host context save/restore (exception safety)
  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  if (!ensureRuntimeAndIsolation(VM)) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
  // Use interpreter mode for bytecode that would be too expensive to JIT.
  // The EVMAnalyzer performs a pattern-aware O(n) scan that detects:
  //  - raw bytecode size / estimated MIR instruction count too large
  //  - high density of RA-expensive opcodes (SHL/SHR/SAR/MUL/SIGNEXTEND)
  //  - long consecutive runs of RA-expensive ops
  //  - DUP-induced feedback loops (b0 pattern)
  std::unique_ptr<ScopedConfig> TempConfig;
  if (VM->Config.Mode == RunMode::MultipassMode) {
    COMPILER::EVMAnalyzer Analyzer(Rev);
    Analyzer.analyze(Code, CodeSize);
    const auto &JITResult = Analyzer.getJITSuitability();
    if (JITResult.ShouldFallback) {
      RuntimeConfig NewConfig = VM->Config;
      NewConfig.Mode = RunMode::InterpMode;
      TempConfig = std::make_unique<ScopedConfig>(VM->RT.get(), NewConfig);
    }
  }
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK

  // Module lookup: L0 -> L1 -> Cold (shared with interpreter path)
  bool IsTransientMod = false;
  EVMModule *Mod =
      findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
  if (!Mod) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  ModuleGuard ModGuard(VM, Mod, IsTransientMod);

  // Instance reuse (shared only for cacheable top-level calls)
  auto *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Execute via callEVMMain (handles both JIT and interpreter fallback)
  evmc_message Message = *Msg;
  evmc::Result Result;
  VM->RT->callEVMMain(*TheInst, Message, Result);

  return Result.release_raw();
}

/// @cond internal
#if !defined(PROJECT_VERSION)
/// The dummy project version if not provided by the build system.
#define PROJECT_VERSION "0.0.0"
#endif
/// @endcond

DTVM::DTVM()
    : evmc_vm{EVMC_ABI_VERSION, "dtvm",    PROJECT_VERSION,
              ::destroy,        ::execute, ::get_capabilities,
              ::set_option},
      ExecHost(new WrappedHost) {
  if (const char *Mode = std::getenv("DTVM_EVM_MODE"); Mode != nullptr) {
    if (std::strcmp(Mode, "interpreter") == 0) {
      Config.Mode = RunMode::InterpMode;
    } else if (std::strcmp(Mode, "multipass") == 0) {
      Config.Mode = RunMode::MultipassMode;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_MODE=%s", Mode);
    }
  }

  if (const char *EnableGas = std::getenv("DTVM_EVM_ENABLE_GAS_METERING");
      EnableGas != nullptr) {
    bool ParsedEnableGas = false;
    if (parseBoolEnvValue(EnableGas, ParsedEnableGas)) {
      Config.EnableEvmGasMetering = ParsedEnableGas;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_ENABLE_GAS_METERING=%s", EnableGas);
    }
  }
}
} // namespace

extern "C" evmc_vm *evmc_create_dtvmapi() { return new DTVM; }
