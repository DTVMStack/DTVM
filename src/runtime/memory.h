// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_RUNTIME_MEMORY_H
#define ZEN_RUNTIME_MEMORY_H

#include "common/defines.h"
#include "platform/memory.h"
#include <cstdint>
#include <list>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace zen::runtime {

class Module;
class EVMModule;
class Runtime;

// allocated memory data type
enum WasmMemoryDataType : uint32_t {
  WM_MEMORY_DATA_TYPE_NO_DATA = 0,
  WM_MEMORY_DATA_TYPE_MALLOC = 1,
  WM_MEMORY_DATA_TYPE_SINGLE_MMAP = 2,
  // when the wasm memory from mmaped-bucket(1/n of one mmap instance)
  WM_MEMORY_DATA_TYPE_BUCKET_MMAP = 3,
};

struct WasmMemoryData {
  WasmMemoryDataType Type;
  uint8_t *MemoryData;
  size_t MemorySize;
  bool NeedMprotect;
};

struct WasmMemoryAllocatorOptions {
  bool UseMmap;
  uint32_t MemoryIndex;
};

struct WasmMemoryBucketSlice {
  uint8_t *Address = nullptr;
  uint8_t *BucketBegin = nullptr;
  size_t BucketSize = 0;
};

// the init-linear-memory duplicates count that init linear-memory file contains
constexpr size_t WasmMemoryAllocatorBucketDuplicates = 10;

// when use cpu-trap to check memory overflow, must use 4GB mmap size, to avoid
// visit other used addresses
// mmap 8GB to avoid visit other used addresses. use (size_t)8 to avoid expr as
// int32(4GB in int32 is zero)
// use 8GB not 4GB reason is i8.load base=INT32_MAX offset=UINT32_MAX will cause
// very large addr visit
constexpr size_t WasmMemoryAllocatorMmapSize = ((size_t)8) * 1024 * 1024 * 1024;

class MmapBucketInstance {
public:
  MmapBucketInstance(uint8_t *Addr, size_t BucketSize, size_t ItemSize,
                     size_t BucketMmapSize)
      : MmapAddr(Addr), Size(BucketSize), BucketItemSize(ItemSize),
        MmapSize(BucketMmapSize) {
    ItemsUsedSizes.fill(0);
  }
  MmapBucketInstance(const MmapBucketInstance &&Other)
      : MmapAddr(Other.MmapAddr), ItemsUsedSizes(Other.ItemsUsedSizes),
        NextOffset(Other.NextOffset), Size(Other.Size),
        BucketItemSize(Other.BucketItemSize), MmapSize(Other.MmapSize) {}
  ~MmapBucketInstance() = default;

  // the mmap bucket starting address
  uint8_t *MmapAddr = nullptr;
  // each bucket-item used size
  std::array<size_t, WasmMemoryAllocatorBucketDuplicates> ItemsUsedSizes;
  // next available offset of mmap-addr bucket
  size_t NextOffset = 0;
  size_t Size = 0;
  size_t BucketItemSize = 0;
  size_t MmapSize = 0;
};

/**
 * wasm linear-memory allocator(not thread safe)
 */
class WasmMemoryAllocator {
public:
  WasmMemoryAllocator(Module *Mod, const WasmMemoryAllocatorOptions *Options);
  WasmMemoryAllocator(const WasmMemoryAllocator &Other) = delete;
  WasmMemoryAllocator &operator=(const WasmMemoryAllocator &Other) = delete;
  ~WasmMemoryAllocator();

  bool checkWasmMemoryCanUseMmap();
  WasmMemoryData allocInitWasmMemory(uint8_t *BucketAllocSand,
                                     size_t MemorySize,
                                     bool ThisInstanceUseMmap,
                                     /* out */ bool *FilledInitData,
                                     /* out */ char *ErrorBuf,
                                     uint32_t ErrorBufSize);
  WasmMemoryData enlargeWasmMemory(const WasmMemoryData &OldMemoryData,
                                   size_t NewMemorySize);
  void freeWasmMemory(const WasmMemoryData &WasmMemoryData);

  WasmMemoryData allocateNonBucketMemory(size_t MemorySize);
  WasmMemoryData reallocateNonBucketMemoryAndFillZerosToNew(
      const WasmMemoryData &OldMemoryData, size_t NewMemorySize);

  void mprotectReadWriteWasmMemoryData(const WasmMemoryData &Data,
                                       bool UnprotectBucket);

  inline WasmMemoryDataType getDefaultMemoryType() const {
    return DefaultMemoryType;
  }

private:
  Module *CurModule;
  Runtime *CurRuntime;
  WasmMemoryDataType DefaultMemoryType;

  bool UseMmap = false;
  size_t MmapMemoryInitFileSize = 0;
  // the bucket contains init-size + grow-max-size(zeros)
  // when grow to not larger then it, just inc the size.
  // otherwise mmap another copy and copy data
  size_t MmapMemoryBucketGrowMaxSize = 0;
  int MmapMemoryInitFd = -1; // when <0, means not create memory file
  char *MmapMemoryFilepath = nullptr;
  // use pointers so when MMAP_BUCKET enabled but the module has no memory,
  // then no need to create the objects

  // set of mmap-addr
  std::unordered_set<uint8_t *> *MmapAddresses = nullptr;
  // memory-data-addr => mmap-bucket-addr
  std::unordered_map<uint8_t *, uint8_t *> *MemoryAddrToMmapAddr = nullptr;
  // the freed times of mmap-bucket, when meet
  // WasmMemoryAllocatorBucketDuplicates, then munmap the bucket
  std::unordered_map<uint8_t *, size_t *> *MmapBucketsFreedCount = nullptr;
  // each mmap bucket bytes size
  size_t MmapBucketSize = 0;
  // each item in mmap bucket bytes size
  size_t MmapBucketItemSize = 0;

  common::Mutex BucketLock;
  // bucket starting addr => bucket-instance
  std::unordered_map<uint8_t *, std::shared_ptr<MmapBucketInstance>>
      ActiveBuckets;
  // the last bucket instance created. wasm memory instances will use it
  // it refers to the memory in ActiveBuckets
  MmapBucketInstance *BucketInstanceForAllocate = nullptr;

  void internalFreeWasmMemory(const WasmMemoryData &Data);

  WasmMemoryBucketSlice getOrCreateMmapSpace(
      const uint8_t
          *BucketAllocSand, // sand to alloc bucket. eg. MemoryInstance*
      size_t InitLinearMemorySize);
};

} // namespace zen::runtime

#endif // ZEN_RUNTIME_MEMORY_H
