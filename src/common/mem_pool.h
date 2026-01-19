// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMMON_MEM_POOL_H
#define ZEN_COMMON_MEM_POOL_H

#include "common/defines.h"
#include "common/errors.h"
#include "platform/map.h"
#include <memory>
#include <vector>

#ifndef NDEBUG
#include <unordered_map>
#ifdef ZEN_BUILD_PLATFORM_LINUX
#ifndef ZEN_ENABLE_SGX
#include <malloc.h>
#define malloc_usable_size malloc_usable_size
#endif
#elif defined(ZEN_BUILD_PLATFORM_DARWIN)
#include <malloc/malloc.h>
#define malloc_usable_size malloc_size
#endif // ZEN_BUILD_PLATFORM_LINUX
#endif // NDEBUG

namespace zen::common {

#include "common/mem_pool_log.def"

#ifdef ZEN_ENABLE_EVM
// Custom allocator that uses malloc/free to avoid alloc-dealloc-mismatch
// across shared library boundaries
template <typename T> struct MallocAllocator {
  using value_type = T;
  using pointer = T *;
  using const_pointer = const T *;
  using reference = T &;
  using const_reference = const T &;
  using size_type = std::size_t;
  using difference_type = std::ptrdiff_t;

  template <class U> struct rebind {
    using other = MallocAllocator<U>;
  };

  MallocAllocator() noexcept = default;
  template <class U> MallocAllocator(const MallocAllocator<U> &) noexcept {}

  T *allocate(std::size_t n) {
    if (n == 0 || n > (std::numeric_limits<std::size_t>::max() / sizeof(T))) {
      ZEN_ABORT();
      return nullptr;
    }
    void *p = std::malloc(n * sizeof(T));
    if (!p) {
      ZEN_ABORT();
      return nullptr;
    }
    return static_cast<T *>(p);
  }

  void deallocate(T *p, std::size_t) noexcept { std::free(p); }
};

template <typename T, typename U>
bool operator==(const MallocAllocator<T> &, const MallocAllocator<U> &) {
  return true;
}

template <typename T, typename U>
bool operator!=(const MallocAllocator<T> &, const MallocAllocator<U> &) {
  return false;
}
#endif // ZEN_ENABLE_EVM

enum MemPoolKind {
  SYS_POOL,               // system malloc/free
  ALLOC_ONLY_POOL,        // allocate only pool
  STAGED_ALLOC_ONLY_POOL, // allocate only pool with push/pop
  CODE_POOL,              // for code cache, thread safe
};

template <MemPoolKind kind> class MemPool {
public:
  void *allocate(size_t Size, const void *Hint = 0);
  void deallocate(void *Ptr, size_t Size = 0);

  void *push();
  void pop(void *Mark);

  template <class T, typename... Arguments> T *New(Arguments &&...Args);

  template <class T> void Delete(T *Ptr);
};

template <> class MemPool<SYS_POOL> {
public:
  MemPool() = default;

  ~MemPool() {
#ifndef NDEBUG
    if (NumAllocs > 0) {
      for (const auto [Ptr, TypeName] : AllocTypeNames) {
        printf("not freed object %s addr %p in mempool\n",
               (TypeName ? TypeName : "<unknown>"), (void *)Ptr);
      }
    }
    ZEN_ASSERT(NumAllocs == 0);
    ZEN_ASSERT(AllocSize == 0);
#endif
  }

  void *allocate(size_t Size, size_t Align = 0,
                 const char *TypeName = nullptr) {
    if (!Size) {
      return nullptr;
    }
// Use default alignment if Align is 0
#ifndef ZEN_ENABLE_SGX
    void *Ptr = Align ? ::aligned_alloc(Align, Size) : std::malloc(Size);
#else
    void *Ptr = std::malloc(Size);
#endif
    if (!Ptr) {
      ZEN_ABORT();
      return nullptr;
    }
#ifndef NDEBUG
    NumAllocs++;
    AllocSize += malloc_usable_size(Ptr);
    UniqueLock<SharedMutex> Lock(AllocMutex);
    AllocTypeNames[(uintptr_t)Ptr] = TypeName;
#endif
    return Ptr;
  }

  void *allocateZeros(size_t Size, size_t Align = 0,
                      const char *TypeName = nullptr) {
    if (!Size) {
      return nullptr;
    }
    // Use default alignment if Align is 0
    bool NeedClearZeros = false;
#ifndef ZEN_ENABLE_SGX
    void *Ptr = Align ? ::aligned_alloc(Align, Size) : std::calloc(Size, 1);
    NeedClearZeros = !!Align;
#else
    void *Ptr = std::malloc(Size);
    NeedClearZeros = true;
#endif
    if (!Ptr) {
      ZEN_ABORT();
      return nullptr;
    }
    if (NeedClearZeros && Size > 0) {
      std::memset(Ptr, 0, Size);
    }
#ifndef NDEBUG
    NumAllocs++;
    AllocSize += malloc_usable_size(Ptr);
    UniqueLock<SharedMutex> Lock(AllocMutex);
    AllocTypeNames[(uintptr_t)Ptr] = TypeName;
#endif
    return Ptr;
  }

  void deallocate(void *Ptr) {
    if (!Ptr) {
      return;
    }

#ifndef NDEBUG
    NumAllocs--;
    AllocSize -= malloc_usable_size(Ptr);
    UniqueLock<SharedMutex> Lock(AllocMutex);
    if (AllocTypeNames.count((uintptr_t)Ptr) > 0) {
      AllocTypeNames.erase((uintptr_t)Ptr);
    }
#endif
    free(Ptr);
  }

  void deallocate(void *Ptr, [[maybe_unused]] size_t Size) {
#ifndef NDEBUG
    ZEN_ASSERT(Size == malloc_usable_size(Ptr));
#endif
    deallocate(Ptr);
  }

  void *reallocate(void *OldPtr, size_t OldSize, size_t NewSize) {
    if (!OldPtr) {
      if (!NewSize) {
        return nullptr;
      }
      const char *Tag = nullptr;
#ifndef NDEBUG
      {
        SharedLock<SharedMutex> Lock(AllocMutex);
        if (AllocTypeNames.count((uintptr_t)OldPtr) > 0) {
          Tag = AllocTypeNames[(uintptr_t)OldPtr];
        }
      }
#endif
      return allocate(NewSize, 0, Tag);
    }

    if (!NewSize) {
      deallocate(OldPtr);
      return nullptr;
    }

#ifndef NDEBUG
    size_t OldActualSize = malloc_usable_size(OldPtr);
#endif
    void *NewPtr = std::realloc(OldPtr, NewSize);
#ifndef NDEBUG
    size_t NewActualSize = malloc_usable_size(NewPtr);
    // Although subtraction may overflow, it doesn't affect the result
    AllocSize += NewActualSize - OldActualSize;
#endif
    return NewPtr;
  }

  void push() {}
  void pop() {}

#ifndef NDEBUG
  size_t getNumAllocs() const { return NumAllocs; }
  size_t getAllocSize() const { return AllocSize; }
#endif

  template <typename T, typename... Arguments>
  T *newObject(Arguments &&...Args) {
    void *Ptr = allocate(sizeof(T), alignof(T));
    Ptr = new (Ptr) T(std::forward<Arguments>(Args)...);
    return static_cast<T *>(Ptr);
  }

  template <typename T> void deleteObject(T *Ptr) {
    Ptr->~T();
    deallocate(Ptr);
  }

private:
#ifndef NDEBUG
  std::atomic<size_t> NumAllocs{0};
  std::atomic<size_t> AllocSize{0};
  SharedMutex AllocMutex;
#ifdef ZEN_ENABLE_EVM
  std::unordered_map<uintptr_t, const char *, std::hash<uintptr_t>,
                     std::equal_to<uintptr_t>,
                     MallocAllocator<std::pair<const uintptr_t, const char *>>>
      AllocTypeNames;
#else
  std::unordered_map<uintptr_t, const char *> AllocTypeNames;
#endif // ZEN_ENABLE_EVM
#endif
};

using SysMemPool = MemPool<SYS_POOL>;

#ifndef ZEN_ENABLE_SGX
template <> class MemPool<CODE_POOL> {
public:
  MemPool() {
    MemStart = reinterpret_cast<uint8_t *>(platform::mmap(
        NULL, MaxCodeSize, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    MemEnd = MemStart;
    MemPageEnd = MemStart;
  }

  ~MemPool() { platform::munmap(MemStart, MaxCodeSize); }

  NONCOPYABLE(MemPool);

  void *allocate(size_t Size, size_t Align = DefaultAlign) {
    if (!Size) {
      return nullptr;
    }
    LockGuard<Mutex> Lock(Mtx);
    uint8_t *Ptr = reinterpret_cast<uint8_t *>(
        ZEN_ALIGN(reinterpret_cast<uintptr_t>(MemEnd), Align));
    size_t NewSize = reinterpret_cast<uintptr_t>(Ptr) + Size -
                     reinterpret_cast<uintptr_t>(MemStart);
    if (NewSize > MaxCodeSize) {
      ZEN_ABORT(); // not supported, exit
    }
    MemEnd = MemStart + NewSize;
    if (MemEnd > MemPageEnd) {
      uint8_t *NewMemPageEnd = reinterpret_cast<uint8_t *>(
          ZEN_ALIGN(reinterpret_cast<uintptr_t>(MemEnd), PageSize));
      platform::mprotect(MemPageEnd, NewMemPageEnd - MemPageEnd, PROT_WRITE);
      MemPageEnd = NewMemPageEnd;
    }
    return Ptr;
  }

  const auto *getMemStart() const { return MemStart; }
  const auto *getMemEnd() const { return MemEnd; }
  const auto *getMemPageEnd() const { return MemPageEnd; }

  // not too large to avoid mmap failure
#ifndef ZEN_ENABLE_OCCLUM
  static constexpr const size_t MaxCodeSize = INT32_MAX;
#else
  // for occlum, we need to limit the code size to avoid mmap failure
  static constexpr const size_t MaxCodeSize = 32 * 1024 * 1024; // 32MB
#endif // ZEN_ENABLE_OCCLUM
  static constexpr const size_t PageSize = 4096;
  static constexpr const size_t DefaultAlign = 16;

private:
  uint8_t *MemStart;
  uint8_t *MemEnd;
  uint8_t *MemPageEnd;
  Mutex Mtx;
};
#else
template <> class MemPool<CODE_POOL> {
public:
  MemPool() = default;

  ~MemPool() {
    for (const auto [Ptr, Size] : AllocRecords) {
      platform::munmap(Ptr, Size);
    }
  }

  NONCOPYABLE(MemPool);

  void *allocate(size_t Size, [[maybe_unused]] size_t Align = DefaultAlign) {
    if (!Size) {
      return nullptr;
    }
    void *Ptr = platform::mmap(nullptr, Size, PROT_NONE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    AllocRecords.emplace_back(Ptr, Size);
    return Ptr;
  }

  static constexpr const size_t DefaultAlign = 16;

private:
  std::vector<std::pair<void *, size_t>> AllocRecords;
};
#endif

using CodeMemPool = MemPool<CODE_POOL>;

template <> class MemPool<ALLOC_ONLY_POOL> {
private:
  struct Block {
    Block *Prev;
    Block *Next;
    uint8_t *Avail;
    uint8_t *Ceil;
  };

#if 0 // unused yet
    Block *BLK;
    uint32_t BlockSize;
    uint32_t Level;
#endif

public:
  MemPool(uint32_t BlockSize) {}
};

template <typename MemPoolType> class Destroyer {
public:
  Destroyer(MemPoolType &MPool) : MPool(MPool) {}
  template <typename T> void operator()(T *Ptr) {
    MPool.template Delete<T>(Ptr);
  }

private:
  MemPoolType &MPool;
};

template <typename T, typename MemPoolType>
using MemPoolUniquePtr = std::unique_ptr<T, Destroyer<MemPoolType>>;

template <typename T>
using SysMemPoolUniquePtr = MemPoolUniquePtr<T, SysMemPool>;

// NOLINTBEGIN(readability-identifier-naming)
template <typename T, typename MemPoolType> class MemPoolAllocator {
public:
  using value_type = T;
  using pointer = T *;
  using const_pointer = const T *;
  using reference = T &;
  using const_reference = const T &;
  using size_type = std::size_t;
  using difference_type = std::ptrdiff_t;
  template <class U> struct rebind {
    using other = MemPoolAllocator<U, MemPoolType>;
  };

  MemPoolAllocator(MemPoolType &MPool) : MemPool(MPool) {}

  template <typename U>
  MemPoolAllocator(const MemPoolAllocator<U, MemPoolType> &Other)
      : MemPool(Other.MemPool) {}

  MemPoolAllocator(const MemPoolAllocator &Other) = default;

  MemPoolAllocator &operator=(const MemPoolAllocator &Other) = default;

  ~MemPoolAllocator() = default;

  pointer address(reference X) const { return std::addressof(X); }

  const_pointer address(const_reference X) const { return std::addressof(X); }

  pointer allocate(size_type N = 1) const {
    return static_cast<pointer>(MemPool.allocate(N * sizeof(T), alignof(T)));
  }

  void deallocate(pointer Ptr, size_type N = 1) const {
    MemPool.deallocate(Ptr, N * sizeof(T));
  }

  size_type max_size() const { return size_type(~0) / sizeof(T); }

  template <typename U, typename... Arguments>
  void construct(U *Ptr, Arguments &&...Args) const {
    new (static_cast<void *>(Ptr)) U(std::forward<Arguments>(Args)...);
  }

  template <typename U> void destroy(U *Ptr) { Ptr->~U(); }

private:
  template <typename U, typename MemPoolTypeU> friend class MemPoolAllocator;

  template <typename U, typename MemPoolTypeU>
  friend bool operator==(const MemPoolAllocator<U, MemPoolTypeU> &LHS,
                         const MemPoolAllocator<U, MemPoolTypeU> &RHS);

  MemPoolType &MemPool;
};
// NOLINTEND(readability-identifier-naming)

template <typename T, typename MemPoolType>
inline bool operator==(const MemPoolAllocator<T, MemPoolType> &LHS,
                       const MemPoolAllocator<T, MemPoolType> &RHS) {
  return std::addressof(LHS.MemPool) == std::addressof(RHS.MemPool);
}

template <typename T, typename MemPoolType>
inline bool operator!=(const MemPoolAllocator<T, MemPoolType> &LHS,
                       const MemPoolAllocator<T, MemPoolType> &RHS) {
  return !(LHS == RHS);
}

template <typename T>
using SysMemPoolAllocator = MemPoolAllocator<T, SysMemPool>;

} // namespace zen::common

#endif // ZEN_COMMON_MEM_POOL_H
