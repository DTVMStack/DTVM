// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef COMPILER_COMMON_COMMON_DEFS_H
#define COMPILER_COMMON_COMMON_DEFS_H

#include "common/defines.h"
#include "common/errors.h"
#include "common/mem_pool.h"
#include "common/operators.h"
#include "common/thread_pool.h"
#include "common/type.h"
#include "platform/platform.h"
#include "runtime/instance.h"
#include "runtime/module.h"
#include "utils/others.h"
#include "llvm/Support/Allocator.h"
#include <cstdlib>
#include <list>
#include <map>
#include <memory>
#include <queue>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace COMPILER {

using namespace zen;
using common::BinaryOperator;
using common::CompareOperator;
using common::ErrorCode;
using common::ErrorPhase;
using common::ErrorSubphase;
using common::FloatAttr;
using common::isWASMTypeFloat;
using common::isWASMTypeInteger;
using common::UnaryOperator;
using common::WASMType;
using common::WASMTypeAttr;
using common::WASMTypeKind;
using runtime::CodeEntry;
using runtime::Instance;
using runtime::MemoryInstance;
using runtime::Module;
using runtime::TableInstance;
using runtime::TypeEntry;

struct NonCopyable {
  NonCopyable() = default;
  NonCopyable(const NonCopyable &) = delete;
  NonCopyable &operator=(const NonCopyable &) = delete;
};

template <class BaseIterator> class DereferenceIterator : public BaseIterator {
public:
  using value_type = typename BaseIterator::value_type::element_type;
  using pointer = value_type *;
  using reference = value_type &;

  DereferenceIterator(const BaseIterator &Other) : BaseIterator(Other) {}

  pointer operator*() const { return this->BaseIterator::operator*().get(); }
  pointer operator->() const { return this->BaseIterator::operator*().get(); }
  /*
  reference operator[](size_t n) const
  {
      return *(this->BaseIterator::operator[](n));
  }
  */
};

template <typename Iterator>
DereferenceIterator<Iterator>
dereference_iterator(Iterator It) { // NOLINT(readability-identifier-naming)
  return DereferenceIterator<Iterator>(It);
}

class MonotonicMemPool final {
public:
  MonotonicMemPool() = default;

  ~MonotonicMemPool() {
    // Note: In a bump allocator, individual deallocations are optional.
    // The pool can be reset via move assignment without deallocating
    // individual objects. The underlying BumpPtrAllocator will free
    // all memory when destroyed. The AllocSizes tracking is only for
    // debug diagnostics, not a hard requirement.
  }

  MonotonicMemPool(const MonotonicMemPool &Other) = delete;

  MonotonicMemPool &operator=(const MonotonicMemPool &Other) = delete;

  MonotonicMemPool(MonotonicMemPool &&Other) {
    AllocImpl = std::move(Other.AllocImpl);
#ifndef NDEBUG
    AllocSizes = std::move(Other.AllocSizes);
    Other.AllocSizes.clear();
#endif
  }

  MonotonicMemPool &operator=(MonotonicMemPool &&Other) {
    if (this != &Other) {
      AllocImpl = std::move(Other.AllocImpl);
#ifndef NDEBUG
      AllocSizes.clear(); // Clear old tracked allocations before move
      AllocSizes = std::move(Other.AllocSizes);
      Other.AllocSizes.clear();
#endif
    }
    return *this;
  }

  void *allocate(size_t Size, size_t Alignment = alignof(std::max_align_t)) {
    void *Ptr = AllocImpl.Allocate(Size, Alignment);
    if (!Ptr) {
      ZEN_ABORT();
    }
#ifndef NDEBUG
    common::LockGuard<common::Mutex> Lock(AllocMutex);
    AllocSizes[Ptr] = Size;
#endif
    return Ptr;
  }

  void deallocate([[maybe_unused]] void *Ptr,
                  [[maybe_unused]] size_t Size = 0) {
#ifndef NDEBUG
    if (!Ptr) {
      return;
    }
    common::LockGuard<common::Mutex> Lock(AllocMutex);
    auto It = AllocSizes.find(Ptr);
    ZEN_ASSERT(It != AllocSizes.end());
    if (Size == 0) {
      Size = It->second;
    } else {
      ZEN_ASSERT(Size == It->second);
    }
    AllocSizes.erase(It);
    AllocImpl.Deallocate(Ptr, Size, 0);
#endif
  }

  template <typename T, typename... Arguments>
  T *newObject(Arguments &&...Args) {
    void *Ptr = allocate(sizeof(T), alignof(T));
    Ptr = new (Ptr) T(std::forward<Arguments>(Args)...);
    return static_cast<T *>(Ptr);
  }

  template <typename T> void deleteObject(T *Ptr) {
    if (!Ptr) {
      return;
    }
    Ptr->~T();
    deallocate(Ptr);
  }

private:
  llvm::BumpPtrAllocator AllocImpl;
#ifndef NDEBUG
  common::Mutex AllocMutex;
  std::unordered_map<void *, size_t> AllocSizes;
#endif
};

using CompileMemPool = MonotonicMemPool;

class MemPoolObject : public NonCopyable {
public:
  virtual ~MemPoolObject() = default;

  CompileMemPool &getMemPool() { return MemPool; }

protected:
  MemPoolObject(CompileMemPool &MPool) : MemPool(MPool) {}

  CompileMemPool &MemPool;
};

// Only for STL containers
template <typename T>
using CompileAllocator = common::MemPoolAllocator<T, CompileMemPool>;

template <typename T> using CompileVector = std::vector<T, CompileAllocator<T>>;

template <typename T> using CompileList = std::list<T, CompileAllocator<T>>;

template <typename V, typename Hash = std::hash<V>,
          typename Equal = std::equal_to<V>>
using CompileUnorderedSet =
    std::unordered_set<V, Hash, Equal, CompileAllocator<V>>;

template <typename K, typename Compare = std::less<K>>
using CompileSet = std::set<K, Compare, CompileAllocator<K>>;

template <typename K, typename V, typename Hash = std::hash<K>,
          typename Equal = std::equal_to<K>>
using CompileUnorderedMap =
    std::unordered_map<K, V, Hash, Equal,
                       CompileAllocator<std::pair<const K, V>>>;

template <typename K, typename V, typename Compare = std::less<K>>
using CompileMap =
    std::map<K, V, Compare, CompileAllocator<std::pair<const K, V>>>;

template <typename T> using CompileDeque = std::deque<T, CompileAllocator<T>>;

template <typename T> using CompileQueue = std::queue<T, CompileDeque<T>>;

using VariableIdx = uint32_t;
using OperandNum = uint16_t;
using BlockNum = uint32_t;

} // namespace COMPILER

#endif // COMPILER_COMMON_COMMON_DEFS_H
