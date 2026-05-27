// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Profile-guided JIT: data structures and thread pool.
//
// Extracted from dt_evmc_vm.cpp so that the VM entry point file stays
// focused on the EVMC interface while profiling/compilation types live
// in their own header.

#ifndef ZEN_VM_JIT_PROFILE_H
#define ZEN_VM_JIT_PROFILE_H

#include "utils/logging.h"

#include <evmc/evmc.hpp>

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>
#include <vector>

namespace zen::vm {

// ---- Profile-Guided JIT: tunable parameters ----
namespace profile {
// Ring buffer capacity: number of recent global contract call records.
static constexpr size_t RING_BUFFER_CAPACITY = 100;
// Maximum allowed ring buffer capacity (each entry is ~28 bytes, so 10000
// entries ≈ 280 KB — a conservative upper bound to prevent misuse).
static constexpr size_t MAX_RING_BUFFER_CAPACITY = 10000;
// JIT trigger conditions: both must be met within the sliding window.
static constexpr uint64_t JIT_TRIGGER_CALL_COUNT = 32;
static constexpr uint64_t JIT_TRIGGER_TOTAL_GAS = 100000;
} // namespace profile

// ---- Profile-Guided JIT: data structures ----

struct CallRecord {
  // Use the 20-byte EVM address directly as the profile key. A
  // string-formatted hex name was previously allocated on every call
  // (~46 bytes + heap alloc), which showed up on the hot path of every EVM
  // execution. evmc::address is POD-like, trivially copyable, and has a
  // std::hash specialization shipped by evmc, so it works as an
  // unordered_map key without any extra plumbing.
  evmc::address ModAddr;
  uint64_t GasUsed = 0;
};

struct ContractProfile {
  uint64_t WindowCallCount = 0;
  uint64_t WindowGasUsed = 0;
  bool JITTriggered = false;
  bool JITRejected = false;
};

struct CallRingBuffer {
  std::vector<CallRecord> Buffer;
  size_t Head = 0;
  size_t Count = 0;
  size_t Capacity;

  explicit CallRingBuffer(size_t Cap) : Buffer(Cap), Capacity(Cap) {}

  std::optional<CallRecord> push(CallRecord NewRecord) {
    std::optional<CallRecord> Evicted;
    if (Count == Capacity) {
      Evicted = std::move(Buffer[Head]);
    } else {
      Count++;
    }
    Buffer[Head] = std::move(NewRecord);
    Head = (Head + 1) % Capacity;
    return Evicted;
  }
};

// ---- JIT Compile Thread Pool ----
// A simple fixed-size thread pool for background JIT compilation tasks.
// Limits the number of concurrent compilations to avoid resource exhaustion.
class JITCompilePool {
public:
  explicit JITCompilePool(uint32_t NumThreads) : Shutdown(false) {
    for (uint32_t I = 0; I < NumThreads; ++I) {
      Workers.emplace_back([this]() { workerLoop(); });
    }
  }

  ~JITCompilePool() {
    {
      std::lock_guard<std::mutex> Lock(QueueMutex);
      Shutdown = true;
    }
    QueueCV.notify_all();
    for (auto &Worker : Workers) {
      Worker.join();
    }
  }

  // Maximum number of pending tasks. When the queue is full, submit()
  // returns an invalid future and the caller should skip JIT for this
  // contract. This prevents unbounded memory growth when many distinct
  // contracts trigger JIT simultaneously.
  static constexpr size_t MAX_TASK_QUEUE_SIZE = 256;

  // Submit a compilation task. Returns a future that completes when
  // the task finishes. Returns an invalid (default-constructed) future
  // if the queue is full -- callers must check future.valid() before
  // calling wait().
  std::future<void> submit(std::function<void()> Task) {
    auto Promise = std::make_shared<std::promise<void>>();
    std::future<void> Future = Promise->get_future();
    {
      std::lock_guard<std::mutex> Lock(QueueMutex);
      if (TaskQueue.size() >= MAX_TASK_QUEUE_SIZE) {
        ZEN_LOG_WARN("JIT compile queue full (%zu tasks), dropping request",
                     TaskQueue.size());
        return std::future<void>();
      }
      TaskQueue.push(
          [Task = std::move(Task), Promise = std::move(Promise)]() mutable {
            try {
              Task();
              Promise->set_value();
            } catch (...) {
              Promise->set_exception(std::current_exception());
            }
          });
    }
    QueueCV.notify_one();
    return Future;
  }

  // Non-copyable, non-movable.
  JITCompilePool(const JITCompilePool &) = delete;
  JITCompilePool &operator=(const JITCompilePool &) = delete;

private:
  void workerLoop() {
    while (true) {
      std::function<void()> Task;
      {
        std::unique_lock<std::mutex> Lock(QueueMutex);
        QueueCV.wait(Lock, [this]() { return Shutdown || !TaskQueue.empty(); });
        if (Shutdown && TaskQueue.empty())
          return;
        Task = std::move(TaskQueue.front());
        TaskQueue.pop();
      }
      Task();
    }
  }

  std::vector<std::thread> Workers;
  std::queue<std::function<void()>> TaskQueue;
  std::mutex QueueMutex;
  std::condition_variable QueueCV;
  bool Shutdown;
};

} // namespace zen::vm

#endif // ZEN_VM_JIT_PROFILE_H
