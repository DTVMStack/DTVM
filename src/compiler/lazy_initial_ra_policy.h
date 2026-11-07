// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_COMPILER_LAZY_INITIAL_RA_POLICY_H
#define ZEN_COMPILER_LAZY_INITIAL_RA_POLICY_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>

namespace COMPILER {

// Controls automatic initial allocation only, not configured eager/background
// Greedy or subsequent private tiering. Zero limits mean unlimited.
class LazyInitialRAPolicy {
public:
  struct Options {
    bool Enabled = true;
    uint64_t MaxModuleBytes = 0;
    uint32_t MaxFunctionBytes = 2048;
    uint64_t BudgetNs = 0;
  };
  enum class Decision {
    Eligible,
    GreedyFP,
    GreedyWord,
    Disabled,
    ModuleSize,
    FunctionSize,
    Budget,
    NoLoop
  };
  struct Region {
    uint32_t Depth;
    bool FP, Call;
    uint8_t WordLoads;
    bool WordStore, OtherMemory;
  };
  static bool trackFP(uint32_t Depth) { return Depth >= FPLoopDepth; }
  static bool trackWord(uint32_t Depth) { return Depth >= WordLoopDepth; }
  static uint8_t addWordLoads(uint8_t A, uint8_t B) {
    return unsigned(A) + B >= WordLoadThreshold ? WordLoadThreshold : A + B;
  }
  static bool matchesFP(const Region &R) {
    return trackFP(R.Depth) && R.FP && !R.Call;
  }
  static bool matchesWord(const Region &R) {
    return R.Depth == WordLoopDepth && R.WordLoads >= WordLoadThreshold &&
           R.WordStore && !R.OtherMemory && !R.Call;
  }
  static bool isGreedy(Decision D) {
    return D == Decision::GreedyFP || D == Decision::GreedyWord;
  }

  LazyInitialRAPolicy(Options Opt, uint64_t ModuleBytes)
      : Opt(Opt), ModuleBytes(ModuleBytes) {}

  Decision eligibility(bool Allowed, uint32_t FunctionBytes,
                       uint64_t InFlightNs = 0) const {
    if (!Allowed || !Opt.Enabled)
      return Decision::Disabled;
    if (Opt.MaxModuleBytes && ModuleBytes > Opt.MaxModuleBytes)
      return Decision::ModuleSize;
    if (Opt.MaxFunctionBytes && FunctionBytes > Opt.MaxFunctionBytes)
      return Decision::FunctionSize;
    if (Opt.BudgetNs) {
      const auto Used = UsedNs.load(std::memory_order_relaxed);
      if (Used >= Opt.BudgetNs || InFlightNs >= Opt.BudgetNs - Used)
        return Decision::Budget;
    }
    return Decision::Eligible;
  }
  Decision select(bool Allowed, uint32_t Bytes, bool FP, bool Word,
                  uint64_t InFlightNs = 0) const {
    auto D = eligibility(Allowed, Bytes, InFlightNs);
    if (D != Decision::Eligible)
      return D;
    return FP     ? Decision::GreedyFP
           : Word ? Decision::GreedyWord
                  : Decision::NoLoop;
  }
  void recordTime(uint64_t Ns) {
    auto Old = UsedNs.load(std::memory_order_relaxed);
    uint64_t Next;
    do {
      Next = Ns > std::numeric_limits<uint64_t>::max() - Old
                 ? std::numeric_limits<uint64_t>::max()
                 : Old + Ns;
    } while (
        !UsedNs.compare_exchange_weak(Old, Next, std::memory_order_relaxed));
  }
  uint64_t usedTime() const { return UsedNs.load(std::memory_order_relaxed); }

  // Soft cumulative foreground budget: includes stubs and complete demanded
  // compiles, even on failure. No clock calls in the default unlimited mode.
  // Already admitted work completes; this is not a latency deadline.
  class Timer {
  public:
    Timer(LazyInitialRAPolicy &Policy, bool Foreground)
        : Policy(Policy), Active(Foreground && Policy.Opt.BudgetNs != 0) {
      if (Active)
        Start = std::chrono::steady_clock::now();
    }
    Timer(const Timer &) = delete;
    Timer &operator=(const Timer &) = delete;
    ~Timer() {
      if (Active)
        Policy.recordTime(elapsed());
    }
    uint64_t elapsed() const {
      return Active ? static_cast<uint64_t>(
                          std::chrono::duration_cast<std::chrono::nanoseconds>(
                              std::chrono::steady_clock::now() - Start)
                              .count())
                    : 0;
    }

  private:
    LazyInitialRAPolicy &Policy;
    const bool Active;
    std::chrono::steady_clock::time_point Start;
  };

private:
  static constexpr uint32_t FPLoopDepth = 2;
  static constexpr uint32_t WordLoopDepth = 3;
  static constexpr uint8_t WordLoadThreshold = 2;
  const Options Opt;
  const uint64_t ModuleBytes;
  std::atomic<uint64_t> UsedNs{0};
};
} // namespace COMPILER
#endif // ZEN_COMPILER_LAZY_INITIAL_RA_POLICY_H
