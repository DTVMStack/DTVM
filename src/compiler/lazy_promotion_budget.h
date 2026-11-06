// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_LAZY_PROMOTION_BUDGET_H
#define ZEN_COMPILER_LAZY_PROMOTION_BUDGET_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>

namespace COMPILER {

// Module-lifetime admission budget. Function/byte limits are hard limits.
// Time is a soft limit: previously admitted work is allowed to complete.
class LazyPromotionBudget {
public:
  LazyPromotionBudget(uint32_t MaxFunctions, uint64_t MaxBytes,
                      uint64_t MaxTimeNs)
      : MaxFunctions(MaxFunctions), MaxBytes(MaxBytes), MaxTimeNs(MaxTimeNs) {}

  bool tryReserve(uint32_t Bytes) {
    std::lock_guard<std::mutex> Lock(Mutex);
    if (Functions >= MaxFunctions || MaxBytes == 0 ||
        Bytes > MaxBytes - UsedBytes ||
        UsedTimeNs.load(std::memory_order_acquire) >= MaxTimeNs) {
      return false;
    }
    ++Functions;
    UsedBytes += Bytes;
    return true;
  }

  void recordTime(uint64_t Ns) {
    uint64_t Old = UsedTimeNs.load(std::memory_order_relaxed);
    uint64_t Next;
    do {
      Next = Ns > std::numeric_limits<uint64_t>::max() - Old
                 ? std::numeric_limits<uint64_t>::max()
                 : Old + Ns;
    } while (!UsedTimeNs.compare_exchange_weak(
        Old, Next, std::memory_order_release, std::memory_order_relaxed));
  }

  // Serialize private promotions and check time immediately before compiling.
  // Otherwise a burst of queued work could overshoot the soft cap by every
  // worker/queued function. At most the currently running compile can overrun.
  template <typename Task> bool runIfTimeAvailable(Task &&Compile) {
    std::lock_guard<std::mutex> Lock(CompilationMutex);
    if (getTimeNs() >= MaxTimeNs) {
      return false;
    }
    const auto Start = std::chrono::steady_clock::now();
    try {
      Compile();
    } catch (...) {
      recordTime(static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(
              std::chrono::steady_clock::now() - Start)
              .count()));
      throw;
    }
    const auto Elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - Start)
                             .count();
    recordTime(static_cast<uint64_t>(Elapsed));
    return true;
  }

  uint32_t getFunctions() const {
    std::lock_guard<std::mutex> Lock(Mutex);
    return Functions;
  }
  uint64_t getBytes() const {
    std::lock_guard<std::mutex> Lock(Mutex);
    return UsedBytes;
  }
  uint64_t getTimeNs() const {
    return UsedTimeNs.load(std::memory_order_acquire);
  }

private:
  const uint32_t MaxFunctions;
  const uint64_t MaxBytes;
  const uint64_t MaxTimeNs;
  mutable std::mutex Mutex;
  std::mutex CompilationMutex;
  uint32_t Functions = 0;
  uint64_t UsedBytes = 0;
  std::atomic<uint64_t> UsedTimeNs{0};
};

} // namespace COMPILER

#endif // ZEN_COMPILER_LAZY_PROMOTION_BUDGET_H
