// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_COMPILER_H
#define ZEN_COMPILER_COMPILER_H

#include "compiler/common/common_defs.h"
#include "compiler/stub/stub_builder.h"

#include <atomic>
#include <cstdint>
#include <mutex>

namespace COMPILER {

class CompileContext;
class WasmFrontendContext;
class MModule;
class MFunction;
class CgFunction;
class LazyPromotionBudget;

class JITCompilerBase : public NonCopyable {
protected:
  virtual ~JITCompilerBase() = default;

  static void compileMIRToCgIR(MModule &Mod, MFunction &MFunc,
                               CgFunction &CgFunc, bool DisableGreedyRA,
                               bool KeepFirstParamInRegister = false);
  static void emitObjectBuffer(CompileContext *Ctx);
};

class WasmJITCompiler : public JITCompilerBase {
protected:
  WasmJITCompiler(runtime::Module *WasmMod)
      : WasmMod(WasmMod),
        NumInternalFunctions(WasmMod->getNumInternalFunctions()),
        Config(WasmMod->getRuntime()->getConfig()),
        Stats(WasmMod->getRuntime()->getStatistics()) {}

  ~WasmJITCompiler() override = default;

  void compileWasmToMC(WasmFrontendContext &Ctx, MModule &Mod, uint32_t FuncIdx,
                       bool DisableGreedyRA, uint8_t *LoopTick = nullptr);

  runtime::Module *WasmMod;
  const uint32_t NumInternalFunctions;
  const runtime::RuntimeConfig &Config;
  utils::Statistics &Stats;
};

class EagerJITCompiler final : public WasmJITCompiler {
public:
  EagerJITCompiler(runtime::Module *WasmMod) : WasmJITCompiler(WasmMod) {}

  ~EagerJITCompiler() override = default;

  void compile();
};

class LazyJITCompiler final : public WasmJITCompiler {
public:
  LazyJITCompiler(runtime::Module *WasmMod);

  ~LazyJITCompiler() override;

  void dispatchCompileTask(uint32_t FuncIdx);

  void dispatchCompileTasksDepthFirst(WasmFrontendContext &Ctx);

  void dispatchCompileTasksInOrder(WasmFrontendContext &Ctx);

  void dispatchEntryCompileTasks(WasmFrontendContext &Ctx);

  void precompile();

  uint8_t *compileFunction(WasmFrontendContext &Ctx, uint32_t FuncIdx,
                           bool DisableGreedyRA, uint8_t *LoopTick = nullptr);

  void compileFunctionInBackgroud(WasmFrontendContext &Ctx, uint32_t FuncIdx);

  uint8_t *compileFunctionOnRequest(uint8_t *FuncStubCodePtr);

  /// Test seam: false for single-internal-function lazy modules (no FastRA
  /// FG / Greedy BG split) and for single-thread lazy.
  bool hasBackgroundCompilePool() const {
    return static_cast<bool>(ThreadPool);
  }

  /// Attempt/start counts: incremented when a compile path is entered, before
  /// the body is produced, `Done` is stored, or the stub is patched. An acquire
  /// load is not a completion barrier. Use `getBackgroundPublishCount()` for
  /// completed background Greedy publication.
  uint32_t getForegroundCompileCount() const {
    return ForegroundCompileCount.load(std::memory_order_acquire);
  }
  uint32_t getBackgroundCompileCount() const {
    return BackgroundCompileCount.load(std::memory_order_acquire);
  }

  /// Completed background Greedy publications. Incremented with release after
  /// the canonical pointer store, `Done`, and stub `xchg`. An acquire load that
  /// observes N happens-after those N publishes.
  uint32_t getBackgroundPublishCount() const {
    return BackgroundPublishCount.load(std::memory_order_acquire);
  }

  /// Canonical background GreedyRA body, or nullptr if there is no pool or
  /// this function has not been published yet.
  const uint8_t *getGreedyRACodePtr(uint32_t FuncIdx) const {
    if (!GreedyRACodePtrs || FuncIdx >= NumInternalFunctions) {
      return nullptr;
    }
    return GreedyRACodePtrs[FuncIdx].load(std::memory_order_acquire);
  }

  struct PrivateTieringStats {
    uint32_t AdmittedFunctions = 0;
    uint64_t AdmittedBytes = 0;
    uint64_t CompileTimeNs = 0;
    uint32_t ProfilingPublishes = 0;
    uint32_t GreedyPublishes = 0;
  };
  PrivateTieringStats getPrivateTieringStats() const;
  uint64_t getObservedLoopHeat(uint32_t FuncIdx) const;

private:
  enum class CompileStatus : uint8_t {
    None,
    Pending,
    InProgress,
    /// Background GreedyRA is the canonical body in GreedyRACodePtrs. After
    /// Done, foreground FastRA must not patch the stub (monotonic publish).
    Done,
  };

  enum class PrivateStatus : uint8_t {
    Cold,
    ProfilingPending,
    Profiling,
    WaitingHeat,
    GreedyPending,
    Done,
    Stopped
  };
  struct PrivateFunction {
    LazyJITCompiler *Owner = nullptr;
    uint32_t Index = 0;
    bool Eligible = false;
    PrivateStatus Status = PrivateStatus::Cold;
    alignas(8) std::atomic<uint64_t> EntryRemaining{0};
    alignas(8) std::atomic<uint64_t> LoopRemaining{0};
    uint64_t ObservedLoops = 0;
    uint64_t EstimatedLoops = 0;
    uint64_t CountedCalls = 0;
    uint64_t EntryQuantum = 0;
    uint64_t SampledCalls = 0;
    uint64_t SampledLoops = 0;
    alignas(8) std::atomic<uint64_t> SampleEntries{0};
    uint64_t FastCompileNs = 0;
    uint64_t ProfileCompileNs = 0;
    uint32_t SpillSlots = 0;
    uint8_t *OriginalFast = nullptr;
    uint8_t *ProfileFast = nullptr;
    uint8_t *ProfileEntryGate = nullptr;
    uint8_t *EntryGate = nullptr;
    uint8_t *LoopGate = nullptr;
  };
  static void privateLoopCallback(void *Cookie) noexcept;
  void recordPrivateLoops(uint32_t FuncIdx) noexcept;
  uint8_t *handlePrivateEntry(uint32_t FuncIdx);
  void stopPrivateProfiling(uint32_t FuncIdx);
  void compilePrivateProfile(WasmFrontendContext &Ctx, uint32_t FuncIdx);
  void compilePrivateGreedy(WasmFrontendContext &Ctx, uint32_t FuncIdx);
  bool isPrivateCandidate(uint32_t FuncIdx) const;
  void retireExhaustedProfilers();
  mutable std::mutex PrivateMutex;
  std::mutex ForegroundMutex;
  std::unique_ptr<PrivateFunction[]> PrivateFunctions;
  std::unique_ptr<LazyPromotionBudget> PrivateBudget;
  std::atomic<uint32_t> PrivateEntryGates{0};
  std::atomic<bool> PrivateProfilersRetired{false};
  std::atomic<uint32_t> PrivateProfilePublishes{0};
  std::atomic<uint32_t> PrivateGreedyPublishes{0};

  JITStubBuilder StubBuilder;
  WasmFrontendContext *MainContext;
  MModule *Mod;

  // Background pool fields: only when multithread lazy is on and the module
  // has more than one internal function. One-internal-function modules skip
  // the FastRA FG / Greedy BG split as a measured policy for fib-like
  // workloads (a large one-fn module can still theoretically benefit from
  // FastRA-first tiering).
  std::vector<WasmFrontendContext> AuxContexts;
  // must be declared before ThreadPool
  std::unique_ptr<std::atomic<CompileStatus>[]> CompileStatuses;
  // must be declared before ThreadPool
  std::unique_ptr<std::atomic<uint8_t *>[]> GreedyRACodePtrs;
  std::unique_ptr<common::ThreadPool<WasmFrontendContext>> ThreadPool;
  std::atomic<uint32_t> ForegroundCompileCount{0};
  std::atomic<uint32_t> BackgroundCompileCount{0};
  std::atomic<uint32_t> BackgroundPublishCount{0};
};

class MIRTextJITCompiler final : public JITCompilerBase {
public:
  MIRTextJITCompiler() = default;

  ~MIRTextJITCompiler() override = default;

  std::pair<std::unique_ptr<MModule>, std::vector<void *>>
  compile(CompileContext &Context, const char *Ptr, size_t Size);
};

} // namespace COMPILER

#endif // ZEN_COMPILER_COMPILER_H
