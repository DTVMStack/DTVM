// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "dt_evmc_vm.h"
#include "common/enums.h"
#include "common/errors.h"
#include "evm/interpreter.h"
#include "evm/opcode_handlers.h"
#include "runtime/config.h"
#include "runtime/evm_instance.h"
#include "runtime/isolation.h"
#include "runtime/runtime.h"
#include "wrapped_host.h"

#include <evmc/evmc.h>
#include <evmc/evmc.hpp>
#include <evmc/helpers.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>

#ifdef ZEN_ENABLE_VIRTUAL_STACK
#include "utils/virtual_stack.h"
#endif // ZEN_ENABLE_VIRTUAL_STACK

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

static constexpr size_t MAX_MODULE_CACHE_SIZE = 4096;

struct CodeAddrRevKey {
  evmc_address Addr;
  evmc_revision Rev;
  zen::runtime::EVMMemorySpecializationProfile MemoryProfile = {};
};

struct CodeAddrRevHash {
  size_t operator()(const CodeAddrRevKey &K) const {
    const auto CodegenKey =
        getEVMMemorySpecializationCodegenKey(K.MemoryProfile);
    uint64_t H;
    std::memcpy(&H, K.Addr.bytes + 12, sizeof(H));
    return H ^ (static_cast<size_t>(K.Rev) * 2654435761u) ^
           (static_cast<size_t>(CodegenKey.SkipLeadingZeroLimbStores) << 20);
  }
};

struct CodeAddrRevEqual {
  bool operator()(const CodeAddrRevKey &A, const CodeAddrRevKey &B) const {
    // Keep the cache-key dependency explicit: today only the codegen-relevant
    // specialization fields participate in module identity. If additional
    // EVMMemorySpecializationProfile fields start affecting lowering or JIT
    // codegen, update getEVMMemorySpecializationCodegenKey() accordingly.
    const auto ACodegenKey =
        getEVMMemorySpecializationCodegenKey(A.MemoryProfile);
    const auto BCodegenKey =
        getEVMMemorySpecializationCodegenKey(B.MemoryProfile);
    return A.Rev == B.Rev &&
           ACodegenKey.SkipLeadingZeroLimbStores ==
               BCodegenKey.SkipLeadingZeroLimbStores &&
           std::memcmp(A.Addr.bytes, B.Addr.bytes, sizeof(A.Addr.bytes)) == 0;
  }
};

zen::runtime::EVMMemorySpecializationProfile
deriveMemorySpecializationProfile(const evmc_message *Msg) {
  return deriveEVMMemorySpecializationProfileFromCallData(
      Msg ? Msg->input_data : nullptr, Msg ? Msg->input_size : 0);
}

/// Validate that the cached module's code matches the provided code.
/// Strict mode performs full-bytecode comparison for hostile/non-standard hosts
/// that may reuse the same code address for different bytecode.
/// Relaxed mode checks head/tail windows (fast path for trusted immutable-code
/// hosts). EIP-170 caps contract code size at 24 KiB.
bool validateCodeMatch(const uint8_t *Code, size_t CodeSize,
                       const EVMModule *Mod, bool StrictValidation) {
  if (CodeSize != Mod->CodeSize)
    return false;
  if (CodeSize == 0)
    return true;
  auto *ModCode = reinterpret_cast<const uint8_t *>(Mod->Code);
  if (StrictValidation) {
    return std::memcmp(Code, ModCode, CodeSize) == 0;
  }
  constexpr size_t kWindow = 256;
  const size_t HeadLen = std::min(CodeSize, kWindow);
  if (std::memcmp(Code, ModCode, HeadLen) != 0)
    return false;
  if (CodeSize > kWindow) {
    const size_t TailLen = std::min(CodeSize, kWindow);
    const size_t TailOffset = CodeSize - TailLen;
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

bool isLikelyPrecompile(const evmc_address &Addr) {
  for (size_t I = 0; I < 19; ++I) {
    if (Addr.bytes[I] != 0) {
      return false;
    }
  }
  return Addr.bytes[19] >= 1 && Addr.bytes[19] <= 9;
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
        if (!RT->unloadEVMModule(P.second.first)) {
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
  // Default to strict (full bytecode equality) for correctness in tests and
  // non-standard hosts. Trusted hosts can opt out via env.
  bool EnableStrictAddrCacheValidation = true;

  // ---- Module & instance cache (shared by interpreter and multipass) ----
  // L0: pointer-based inline cache (fastest, 2 integer comparisons)
  const uint8_t *LastCodePtr = nullptr;
  size_t LastCodeSize = 0;
  EVMModule *L0Mod = nullptr;

  // L1: address-based LRU cache (code_address + rev -> module)
  // LRUOrder tracks access recency: front = most recent, back = least recent.
  // AddrCache maps key -> (module, iterator into LRUOrder) for O(1) lookup
  // and O(1) LRU maintenance via std::list::splice.
  using LRUList = std::list<CodeAddrRevKey>;
  LRUList LRUOrder;
  std::unordered_map<CodeAddrRevKey, std::pair<EVMModule *, LRUList::iterator>,
                     CodeAddrRevHash, CodeAddrRevEqual>
      AddrCache;

  uint64_t ModCounter = 0;
  // Cached EVMInstance to avoid alloc/free (~33KB) on every call
  EVMInstance *CachedMainInst = nullptr;
  // Cached InterpreterExecContext for the top-level call (depth == 0).
  std::unique_ptr<zen::evm::InterpreterExecContext> CachedCtx;
  // Per-depth InterpreterExecContext pool for nested calls (depth > 0).
  // Indexed by Msg->depth.  Each entry persists across calls so that the
  // 32 KB EVMFrame stack array inside InterpreterExecContext::FrameStack
  // is allocated *at most once per depth* and reused on subsequent
  // recursive calls.  Without this pool, every nested CALL/CREATE went
  // through std::make_unique<InterpreterExecContext>() + a fresh
  // FrameStack.emplace_back() (32 KB zero-init), which dominated runtime
  // in deeply recursive workloads (e.g. transStorageOK, ~24x slowdown
  // vs evmone baseline).  DTVM is single-threaded per VM instance, so a
  // depth-indexed pool is safe without locking.
  std::vector<std::unique_ptr<zen::evm::InterpreterExecContext>> NestedCtxPool;
  // Instance pool for depth > 0
  std::vector<EVMInstance *> CacheInsts;
  // Serialize execute() for nested host calls (re-entrancy-safe via recursive_mutex).
  std::recursive_mutex ExecuteMutex;

  bool isModuleInUse(const EVMModule *Mod) const {
    if (CachedMainInst && CachedMainInst->getModule() == Mod)
      return true;
    for (const auto *Inst : CacheInsts) {
      if (Inst && Inst->getModule() == Mod)
        return true;
    }
    return false;
  }
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
  // CREATE/CREATE2 initcode must not be cached: the same address can receive
  // different initcode across transactions, and initcode is one-shot.
  // Regular calls (CALL/DELEGATECALL/STATICCALL/CALLCODE) at any depth are
  // safe to cache: EVM guarantees that deployed code at a given address is
  // immutable. The module is keyed by (code_address, revision) and
  // configurable validation (strict full compare vs relaxed head/tail) runs
  // before reuse. Each
  // nested call gets its own EVMInstance so reentrancy is safe.
  return Msg != nullptr && Msg->kind != EVMC_CREATE &&
         Msg->kind != EVMC_CREATE2;
}

bool shouldRetryModuleLoadWithFastRA(const DTVM *VM, const Error &Err) {
  return VM->Config.Mode == RunMode::MultipassMode &&
         !VM->Config.DisableMultipassGreedyRA &&
         Err.getPhase() == ErrorPhase::Compilation &&
         Err.getSubphase() == ErrorSubphase::RegAlloc;
}

zen::common::MayBe<EVMModule *> loadEVMModuleWithRegAllocRetry(
    DTVM *VM, const std::string &ModName, const uint8_t *Code, size_t CodeSize,
    evmc_revision Rev, EVMMemorySpecializationProfile MemoryProfile = {}) {
  auto ModRet =
      VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev, MemoryProfile);
  if (ModRet || !shouldRetryModuleLoadWithFastRA(VM, ModRet.getError())) {
    return ModRet;
  }

  RuntimeConfig RetryConfig = VM->Config;
  RetryConfig.DisableMultipassGreedyRA = true;
  ScopedConfig Retry(VM->RT.get(), RetryConfig);
  return VM->RT->loadEVMModule(ModName, Code, CodeSize, Rev, MemoryProfile);
}

EVMModule *loadTransientModule(DTVM *VM, const uint8_t *Code, size_t CodeSize,
                               evmc_revision Rev) {
  std::string ModName = "tmp_mod_" + std::to_string(VM->ModCounter++);
  auto ModRet = loadEVMModuleWithRegAllocRetry(
      VM, ModName, Code, CodeSize, Rev, EVMMemorySpecializationProfile{});
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
  const EVMMemorySpecializationProfile Profile =
      deriveMemorySpecializationProfile(Msg);

  // L0 disabled: pointer comparison is unsafe when callers reuse addresses
  // for different bytecode (e.g. test frameworks, repeated allocations).
  // Fall through to L1 address-based lookup with content validation.

  EVMModule *Mod = nullptr;

  // L1: Address-based LRU cache lookup
  CodeAddrRevKey AddrKey{Msg->code_address, Rev, Profile};
  auto It = VM->AddrCache.find(AddrKey);
  if (It != VM->AddrCache.end() &&
      validateCodeMatch(Code, CodeSize, It->second.first,
                        VM->EnableStrictAddrCacheValidation)) {
    Mod = It->second.first;
    // LRU touch: move to front (most recently used)
    VM->LRUOrder.splice(VM->LRUOrder.begin(), VM->LRUOrder, It->second.second);
  } else {
    // Cold path: full module load
    // If validation failed for an existing entry, evict the stale module
    if (It != VM->AddrCache.end()) {
      EVMModule *OldMod = It->second.first;
      if (VM->L0Mod == OldMod && Msg->depth == 0)
        VM->L0Mod = nullptr;
      VM->RT->unloadEVMModule(OldMod);
      VM->LRUOrder.erase(It->second.second);
      VM->AddrCache.erase(It);
    }

    // LRU eviction: if cache is at capacity, evict least recently used
    while (VM->AddrCache.size() >= MAX_MODULE_CACHE_SIZE &&
           !VM->LRUOrder.empty()) {
      auto &VictimKey = VM->LRUOrder.back();
      auto VictimIt = VM->AddrCache.find(VictimKey);
      if (VictimIt != VM->AddrCache.end()) {
        EVMModule *VictimMod = VictimIt->second.first;
        if (VM->isModuleInUse(VictimMod))
          break; // never evict a module referenced by an active instance
        if (VM->L0Mod == VictimMod)
          VM->L0Mod = nullptr;
        VM->RT->unloadEVMModule(VictimMod);
        VM->AddrCache.erase(VictimIt);
      }
      VM->LRUOrder.pop_back();
    }

    std::string ModName = "mod_" + std::to_string(VM->ModCounter++);
    auto ModRet = loadEVMModuleWithRegAllocRetry(VM, ModName, Code, CodeSize,
                                                 Rev, Profile);
    if (!ModRet)
      return nullptr;
    Mod = *ModRet;
    VM->LRUOrder.push_front(AddrKey);
    VM->AddrCache[AddrKey] = {Mod, VM->LRUOrder.begin()};
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
      // Ensure revision is initialized for the first use of cached main
      // instance; default is DEFAULT_REVISION (CANCUN), which can overcharge
      // pre-fork blocks if not reset.
      TheInst->resetForNewCall(Rev, *Mod);
    }
  } else {
    // Cache hit: same module, just reset with new revision
    TheInst->resetForNewCall(Rev, *Mod);
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
  if (Msg->depth == 0) {
    TheInst->clearMessageCache();
  }
  TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
  TheInst->pushMessage(&MsgWithCode);

  const bool ReuseTopLevel = !IsTransientMod && Msg->depth == 0;

  // Pick the InterpreterExecContext to run this call in:
  //  * Top-level (depth == 0, non-transient): reuse VM->CachedCtx.
  //  * Nested:    reuse VM->NestedCtxPool[depth] (grow on demand).
  // The previous implementation allocated a *fresh* InterpreterExecContext
  // for every nested call, which silently triggered a 32 KB EVMFrame
  // zero-init via FrameStack.emplace_back() on every recursion level.
  // Tests that recurse hundreds of times (e.g. transStorageOK) became
  // 24x slower than evmone baseline; the pool below makes the EVMFrame
  // allocation amortized O(1) per depth.
  zen::evm::InterpreterExecContext *CtxPtr = nullptr;
  if (ReuseTopLevel) {
    if (!VM->CachedCtx) {
      VM->CachedCtx =
          std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    } else {
      VM->CachedCtx->resetForNewCall(TheInst);
    }
    CtxPtr = VM->CachedCtx.get();
  } else {
    ZEN_ASSERT(Msg->depth >= 0 && Msg->depth <= 1024 &&
               "EVMC depth out of valid range [0, 1024]");
    const size_t Depth = static_cast<size_t>(Msg->depth);
    auto &Pool = VM->NestedCtxPool;
    if (Depth >= Pool.size()) {
      Pool.resize(Depth + 1);
    }
    auto &Slot = Pool[Depth];
    if (!Slot) {
      Slot = std::make_unique<zen::evm::InterpreterExecContext>(TheInst);
    } else {
      Slot->resetForNewCall(TheInst);
    }
    CtxPtr = Slot.get();
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

#ifdef ZEN_ENABLE_JIT

#ifdef ZEN_ENABLE_VIRTUAL_STACK
/// Virtual stack callback for JIT fast path: invoked with RSP on the virtual
/// stack. Follows the same pattern as callEVMFuncFromVirtualStack in
/// runtime.cpp.
static void callJITFromVirtualStack(zen::utils::VirtualStackInfo *StackInfo) {
  auto *Inst = static_cast<EVMInstance *>(StackInfo->SavedPtr1);
  auto *Msg = static_cast<evmc_message *>(StackInfo->SavedPtr2);
  auto *Result = static_cast<evmc::Result *>(StackInfo->SavedPtr3);
  Inst->getRuntime()->callEVMInJITMode(*Inst, *Msg, *Result);
}
#endif // ZEN_ENABLE_VIRTUAL_STACK

/// Fast path for multipass JIT mode: reuse cached instance, call JIT code
/// directly. This avoids per-call callEVMMain overhead while delegating
/// actual JIT execution to Runtime::callEVMInJITMode (single source of truth
/// for CPU exception handling, error mapping, etc.).
evmc_result executeMultipassFastPath(DTVM *VM, const evmc_host_interface *Host,
                                     evmc_host_context *Context,
                                     evmc_revision Rev, const evmc_message *Msg,
                                     const uint8_t *Code, size_t CodeSize) {
  // RAII guard for host context save/restore (exception safety)
  HostContextScope HostScope(VM->ExecHost.get(), Host, Context);

  // Ensure runtime and isolation exist
  if (!ensureRuntimeAndIsolation(VM)) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Empty-code top-level CALL to a non-precompile has no bytecode execution.
  if (Msg && Msg->depth == 0 && CodeSize == 0 && Msg->kind == EVMC_CALL &&
      !isLikelyPrecompile(Msg->recipient)) {
    evmc::Result NoCodeResult{EVMC_SUCCESS, static_cast<int64_t>(Msg->gas), 0};
    return NoCodeResult.release_raw();
  }

  // Nested empty-code CALLs: use interpreter path (precompiles may have no code).
  if (Msg && Msg->depth > 0 && CodeSize == 0 && Msg->kind == EVMC_CALL) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }

  // Module lookup: L1 address-based cache -> Cold load
  bool IsTransientMod = false;
  EVMModule *Mod =
      findModuleCached(VM, Code, CodeSize, Rev, Msg, IsTransientMod);
  if (!Mod) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }
  ModuleGuard ModGuard(VM, Mod, IsTransientMod);

#ifdef ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK
  // O(1) flag check replaces per-call O(n) EVMAnalyzer scan.
  // The flag was set once at module creation in EVMModule::newEVMModule().
  if (Mod->ShouldFallbackToInterp) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }
#endif // ZEN_ENABLE_JIT_PRECOMPILE_FALLBACK

  // Instance reuse (shared only for cacheable top-level calls)
  EVMInstance *TheInst = getOrCreateInstance(VM, Mod, Rev, Msg->depth);
  if (!TheInst) {
    return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
  }

  // Setup message with code pointers (same pattern as interpreter fast path)
  evmc_message MsgWithCode = *Msg;
  MsgWithCode.code = reinterpret_cast<uint8_t *>(Mod->Code);
  MsgWithCode.code_size = Mod->CodeSize;
  if (Msg->depth == 0) {
    TheInst->clearMessageCache();
  }
  TheInst->setExeResult(evmc::Result{EVMC_SUCCESS, 0, 0});
  TheInst->pushMessage(&MsgWithCode);

  evmc::Result Result;

#ifdef ZEN_ENABLE_VIRTUAL_STACK
  if (Msg->depth == 0) {
    // depth==0: set up virtual stack for stack overflow protection via guard
    // pages. The virtual stack switches RSP to a separate mmap'd region.
    zen::utils::VirtualStackInfo StackInfo;
    StackInfo.SavedPtr1 = TheInst;
    StackInfo.SavedPtr2 = &MsgWithCode;
    StackInfo.SavedPtr3 = &Result;
    TheInst->pushVirtualStack(&StackInfo);
    StackInfo.runInVirtualStack(&callJITFromVirtualStack);
    TheInst->popVirtualStack();
  } else {
    // depth>0: re-entered via EVMC host callback, already on physical stack
    VM->RT->callEVMInJITMode(*TheInst, MsgWithCode, Result);
  }
#else
  VM->RT->callEVMInJITMode(*TheInst, MsgWithCode, Result);
#endif // ZEN_ENABLE_VIRTUAL_STACK

  Result.gas_left = TheInst->getGas();
  return Result.release_raw();
}
#endif // ZEN_ENABLE_JIT

/// The implementation of the evmc_vm::execute() method.
evmc_result execute(evmc_vm *EVMInstance, const evmc_host_interface *Host,
                    evmc_host_context *Context, enum evmc_revision Rev,
                    const evmc_message *Msg, const uint8_t *Code,
                    size_t CodeSize) {
  auto *VM = static_cast<DTVM *>(EVMInstance);
  std::lock_guard<std::recursive_mutex> Guard(VM->ExecuteMutex);

  // Interpreter mode: use optimized fast path (bypasses callEVMMain)
  if (VM->Config.Mode == RunMode::InterpMode) {
    return executeInterpreterFastPath(VM, Host, Context, Rev, Msg, Code,
                                      CodeSize);
  }

#ifdef ZEN_ENABLE_JIT
  // JIT mode: use optimized fast path (bypasses callEVMMain/virtual stack)
  return executeMultipassFastPath(VM, Host, Context, Rev, Msg, Code, CodeSize);
#else
  return evmc_make_result(EVMC_FAILURE, 0, 0, nullptr, 0);
#endif // ZEN_ENABLE_JIT
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

  if (const char *StrictValidation =
          std::getenv("DTVM_EVM_STRICT_ADDR_CACHE_VALIDATION");
      StrictValidation != nullptr) {
    bool ParsedStrictValidation = true;
    if (parseBoolEnvValue(StrictValidation, ParsedStrictValidation)) {
      EnableStrictAddrCacheValidation = ParsedStrictValidation;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_STRICT_ADDR_CACHE_VALIDATION=%s",
                   StrictValidation);
    }
  }

  // Greedy RA has been observed to crash in long-running EVM multipass JIT
  // compilation. Disabled by default; override with DTVM_EVM_DISABLE_MULTIPASS_GREEDYRA.
  Config.DisableMultipassGreedyRA = true;
  if (const char *DisableGreedyRA =
          std::getenv("DTVM_EVM_DISABLE_MULTIPASS_GREEDYRA");
      DisableGreedyRA != nullptr) {
    bool ParsedDisableGreedyRA = true;
    if (parseBoolEnvValue(DisableGreedyRA, ParsedDisableGreedyRA)) {
      Config.DisableMultipassGreedyRA = ParsedDisableGreedyRA;
    } else {
      ZEN_LOG_WARN("ignore invalid DTVM_EVM_DISABLE_MULTIPASS_GREEDYRA=%s",
                   DisableGreedyRA);
    }
  }
}
} // namespace

extern "C" evmc_vm *evmc_create_dtvmapi() { return new DTVM; }
