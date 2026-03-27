// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/memory.h"
#include "common/enums.h"
#include "runtime/module.h"
#include "utils/logging.h"
#include "utils/others.h"
#include <cstdio>

namespace zen::runtime {

using namespace zen::common;

constexpr size_t MmapMemoryFileMaxSize = 32 * 1024 * 1024; // 32MB

static bool verifyCanUseMmapBucketByModuleDataSegments(Module *Mod) {
  if (Mod->getNumInternalMemories() != 1) {
    return false;
  }
  const auto &Mem = Mod->getDefaultMemoryEntry();
  size_t InitMemorySize = Mem.InitSize * DefaultBytesNumPerPage;
  if (InitMemorySize == 0) {
    return false;
  }
  if (InitMemorySize > MmapMemoryFileMaxSize) {
    return false;
  }
  if (WasmMemoryAllocatorMmapSize > 0 &&
      InitMemorySize >
          WasmMemoryAllocatorMmapSize / WasmMemoryAllocatorBucketDuplicates) {
    return false;
  }
  if (Mod->getNumTotalMemories() != 1 || Mem.InitSize == 0) {
    return false;
  }
  for (size_t I = 0; I < Mod->getNumDataSegments(); I++) {
    auto *Seg = Mod->getDataEntry(I);
    if (Seg->MemIdx != 0) {
      return false;
    }
    int64_t BaseOffset = 0;
    if (Seg->InitExprKind != Opcode::I32_CONST &&
        Seg->InitExprKind != Opcode::I64_CONST) {
      return false;
    }
    if (Seg->InitExprKind == Opcode::I32_CONST) {
      BaseOffset = (int64_t)Seg->InitExprVal.I32;
    } else if (Seg->InitExprKind == Opcode::I64_CONST) {
      BaseOffset = Seg->InitExprVal.I64;
    } else {
      return false;
    }
    if (BaseOffset < 0 || BaseOffset + Seg->Size > (int64_t)InitMemorySize) {
      return false;
    }
  }
  return true;
}

WasmMemoryAllocator::WasmMemoryAllocator(
    Module *Mod, const WasmMemoryAllocatorOptions *Options) {
  CurModule = Mod;
  CurRuntime = Mod->getRuntime();
  DefaultMemoryType = WM_MEMORY_DATA_TYPE_MALLOC;
  if (Options->UseMmap) {
#ifdef ZEN_ENABLE_CPU_EXCEPTION
    UseMmap = true;
#endif // ZEN_ENABLE_CPU_EXCEPTION
    bool UseMmapBucket = UseMmap;
    // if wasm module data segments has init-expr which not use i32/i64,
    // then not use mmap
    UseMmapBucket =
        UseMmapBucket && verifyCanUseMmapBucketByModuleDataSegments(Mod);
    UseMmapBucket = UseMmapBucket && utils::checkSupportRamDisk();
  try_use_mmap_init:
    if (UseMmapBucket) {
      utils::Statistics &Stats = Mod->getRuntime()->getStatistics();
      auto Timer = Stats.startRecord(utils::StatisticPhase::MemoryBucketMap);
      int MmapFileFd;
      char Path[80] = {0};
      static uint64_t PathIdBegin = 0;
      if (PathIdBegin == 0) {
        PathIdBegin = static_cast<uint64_t>((intptr_t)Mod);
      } else {
        PathIdBegin++;
      }
#ifdef ZEN_BUILD_PLATFORM_DARWIN
      ::sprintf((char *)Path,
                "/Volumes/RAMDisk/zetaengine_init_memory_%ld_%d.memory",
                PathIdBegin, Options->MemoryIndex);
#else
      ::sprintf(Path, "/dev/shm/zetaengine_init_memory_%ld_%d.memory",
                PathIdBegin, Options->MemoryIndex);
#endif // ZEN_BUILD_PLATFORM_DARWIN
      MmapFileFd = ::open(Path, O_RDWR | O_CREAT, 644);
      if (MmapFileFd < 0) {
        ZEN_LOG_WARN("failed to create mmap memory file due to '%s'", Path,
                     std::strerror(errno));
        UseMmapBucket = false;
        Stats.revertRecord(Timer);
        goto try_use_mmap_init;
      }
      // Remove the directory entry while keeping the fd open. On POSIX,
      // remove() on a regular file is equivalent to unlink(): it deletes the
      // name from the filesystem but the file data remains accessible through
      // any open fd or mmap. The kernel reclaims the storage automatically
      // when the last fd/mmap reference is closed — even on abnormal exit
      // (SIGKILL, crash). This prevents /dev/shm file accumulation.
      if (::remove(Path) != 0) {
        ZEN_LOG_WARN("failed to early-unlink mmap file %s due to '%s', "
                     "disabling mmap-bucket for this module",
                     Path, std::strerror(errno));
        ::close(MmapFileFd);
        MmapFileFd = -1;
        UseMmapBucket = false;
        Stats.revertRecord(Timer);
        goto try_use_mmap_init;
      }
      MmapMemoryFilepath = ::strdup(Path);
      DefaultMemoryType = WM_MEMORY_DATA_TYPE_BUCKET_MMAP;
      MmapMemoryBucketGrowMaxSize = MmapMemoryFileMaxSize;
      MmapAddresses = new std::unordered_set<uint8_t *>();
      MemoryAddrToMmapAddr = new std::unordered_map<uint8_t *, uint8_t *>();
      MmapBucketsFreedCount = new std::unordered_map<uint8_t *, size_t *>();
      // create default linear memory and write to new memory file, open the
      // memory file
      if (Mod->getNumTotalMemories() == 1 &&
          Mod->getDefaultMemoryEntry().InitSize > 0) {
        const auto &Mem = Mod->getDefaultMemoryEntry();
        size_t InitMemorySize = Mem.InitSize * DefaultBytesNumPerPage;
        size_t MaxMemorySize = Mem.MaxSize * DefaultBytesNumPerPage;
        if (MaxMemorySize < InitMemorySize) {
          MaxMemorySize = InitMemorySize;
        }
        size_t SingleInitFileSize = InitMemorySize;
        if (MaxMemorySize < SingleInitFileSize) {
          SingleInitFileSize = MaxMemorySize;
        }
        ZEN_ASSERT(SingleInitFileSize <= MmapMemoryBucketGrowMaxSize);

        size_t BucketFileSize =
            MmapMemoryBucketGrowMaxSize * WasmMemoryAllocatorBucketDuplicates;

        if (0 != ::ftruncate(MmapFileFd, BucketFileSize)) {
          ZEN_ABORT();
        }

        for (size_t I = 0; I < Mod->getNumDataSegments(); I++) {
          auto *Seg = Mod->getDataEntry(I);
          if (Seg->MemIdx != 0) {
            continue;
          }
          int64_t BaseOffset = 0;
          if (Seg->InitExprKind == Opcode::I32_CONST) {
            BaseOffset = (int64_t)Seg->InitExprVal.I32;
          } else if (Seg->InitExprKind == Opcode::I64_CONST) {
            BaseOffset = Seg->InitExprVal.I64;
          } else {
            ZEN_ASSERT(false);
          }
          ZEN_ASSERT(BaseOffset + (int64_t)Seg->Size <=
                     (int64_t)InitMemorySize);
          for (size_t I = 0; I < WasmMemoryAllocatorBucketDuplicates; I++) {
            // copy segments to all copies in memory bucket file
            ::lseek(MmapFileFd, I * MmapMemoryBucketGrowMaxSize + BaseOffset,
                    SEEK_SET);
            if (Seg->Size != os_write(MmapFileFd,
                                      Mod->getWASMBytecode() + Seg->Offset,
                                      Seg->Size)) {
              ZEN_ABORT();
            }
          }
        }
        MmapMemoryInitFileSize = BucketFileSize;
        MmapMemoryInitFd = MmapFileFd;
        MmapBucketItemSize = SingleInitFileSize;
        MmapBucketSize = BucketFileSize;
      }
      Stats.stopRecord(Timer);
    } else {
      // when cpu-trap enabled, jit will not generate soft-memory check
      // so at least use single mmap mode to mprotect the memory
      DefaultMemoryType = WasmMemoryDataType::WM_MEMORY_DATA_TYPE_SINGLE_MMAP;
      MmapMemoryBucketGrowMaxSize = WasmMemoryAllocatorMmapSize;
    }
  }
}
WasmMemoryAllocator::~WasmMemoryAllocator() {
  if (UseMmap) {
    if (MmapAddresses) {
      for (const auto &P : *MmapAddresses) {
        auto MmapSize = (size_t)MmapMemoryInitFileSize;
        if (0 != ::munmap(P, MmapSize)) {
          ZEN_ABORT();
        }
      }
      delete MmapAddresses;
    }
    if (MmapMemoryInitFd >= 0) {
      ::close(MmapMemoryInitFd);
    }
    if (MmapMemoryFilepath) {
      ::free(MmapMemoryFilepath);
    }
    delete MemoryAddrToMmapAddr;
    if (MmapBucketsFreedCount) {
      for (const auto &P : *MmapBucketsFreedCount) {
        ::free(P.second);
      }
      delete MmapBucketsFreedCount;
    }
  }
}
bool WasmMemoryAllocator::checkWasmMemoryCanUseMmap() {
  bool CanUseMmap = false;
  if (UseMmap) {
    if (DefaultMemoryType == WM_MEMORY_DATA_TYPE_BUCKET_MMAP &&
        MmapMemoryInitFd >= 0) {
      CanUseMmap = true;
    }
  }
  return CanUseMmap;
}
WasmMemoryBucketSlice WasmMemoryAllocator::getOrCreateMmapSpace(
    const uint8_t
        *BucketAllocSand, // sand to alloc bucket. eg. Module*Instance*
    size_t InitLinearMemorySize) {
  if (UseMmap) {
    common::LockGuard<common::Mutex> _(BucketLock);

    if (!BucketInstanceForAllocate) {
      // private mmap from memory file fd
      // mprotect 8GB to use cpu-trap to check memory load/store
      size_t MmapSize = WasmMemoryAllocatorMmapSize;
      ZEN_ASSERT(sizeof(size_t) > 4);

      auto BucketMemAddr =
          (uint8_t *)::mmap(nullptr, MmapSize, PROT_NONE,
                            MAP_FILE | MAP_PRIVATE, MmapMemoryInitFd, 0);
      if (!BucketMemAddr || (BucketMemAddr == (uint8_t *)-1)) {
        ZEN_ABORT();
      }
      MmapAddresses->insert(BucketMemAddr);
      auto *BucketFreeCount = (size_t *)::malloc(sizeof(size_t));
      if (!BucketFreeCount) {
        ZEN_ABORT();
      }
      *BucketFreeCount = 0;
      MmapBucketsFreedCount->emplace(BucketMemAddr, BucketFreeCount);
      uint8_t *MemoryData = BucketMemAddr;
      MemoryAddrToMmapAddr->emplace(MemoryData, BucketMemAddr);

      ActiveBuckets.insert(std::make_pair(
          BucketMemAddr,
          std::make_shared<MmapBucketInstance>(
              BucketMemAddr,
              MmapMemoryBucketGrowMaxSize * WasmMemoryAllocatorBucketDuplicates,
              MmapMemoryBucketGrowMaxSize, MmapSize)));
      auto *NewBucketInstance = ActiveBuckets[BucketMemAddr].get();
      BucketInstanceForAllocate = NewBucketInstance;

      NewBucketInstance->ItemsUsedSizes[0] = InitLinearMemorySize;
      NewBucketInstance->NextOffset += NewBucketInstance->BucketItemSize;

      MemoryAddrToMmapAddr->insert(
          std::make_pair(BucketMemAddr, BucketMemAddr));

      return WasmMemoryBucketSlice{
          .Address = MemoryData,
          .BucketBegin = BucketMemAddr,
          .BucketSize = NewBucketInstance->Size,
      };
    }
    // use the last bucket instance to allocate.
    // when the last bucket instance used out, then set
    // BucketInstanceForAllocate to nullptr
    auto Result = WasmMemoryBucketSlice{
        .Address = BucketInstanceForAllocate->MmapAddr +
                   BucketInstanceForAllocate->NextOffset,
        .BucketBegin = BucketInstanceForAllocate->MmapAddr,
        .BucketSize = BucketInstanceForAllocate->Size,
    };
    BucketInstanceForAllocate->NextOffset +=
        BucketInstanceForAllocate->BucketItemSize;
    if (BucketInstanceForAllocate->NextOffset >=
        BucketInstanceForAllocate->Size) {
      BucketInstanceForAllocate = nullptr;
    }
    MemoryAddrToMmapAddr->insert(
        std::make_pair(Result.Address, Result.BucketBegin));

    return Result;
  } else {
    ZEN_ASSERT(false);
    return WasmMemoryBucketSlice{
        .Address = nullptr,
    };
  }
}

void WasmMemoryAllocator::mprotectReadWriteWasmMemoryData(
    const WasmMemoryData &Data, bool UnprotectBucket) {
  if (Data.Type != WasmMemoryDataType::WM_MEMORY_DATA_TYPE_BUCKET_MMAP &&
      Data.Type != WasmMemoryDataType::WM_MEMORY_DATA_TYPE_SINGLE_MMAP) {
    return;
  }
  if (!Data.MemoryData) {
    return;
  }
  if (UseMmap) {
    if (UnprotectBucket &&
        Data.Type == WasmMemoryDataType::WM_MEMORY_DATA_TYPE_BUCKET_MMAP) {

      auto BucketIt = MemoryAddrToMmapAddr->find(Data.MemoryData);
      ZEN_ASSERT(BucketIt != MemoryAddrToMmapAddr->end());
      auto *Bucket = BucketIt->second;
      auto *BucketInstance = ActiveBuckets[Bucket].get();
      for (size_t I = 0; I < BucketInstance->ItemsUsedSizes.size(); I++) {
        auto ItemSize = BucketInstance->ItemsUsedSizes[I];
        if (ItemSize <= 0) {
          continue;
        }
        auto ItemBeginAddr =
            BucketInstance->MmapAddr + I * BucketInstance->BucketItemSize;
        if (0 != ::mprotect(ItemBeginAddr, ItemSize, PROT_NONE)) {
          ZEN_ABORT();
        }
      }
    }
  }
  if (0 !=
      ::mprotect(Data.MemoryData, Data.MemorySize, PROT_WRITE | PROT_WRITE)) {
    ZEN_ABORT();
  }
}

// allocate linear memory space when not use mmap-bucket
WasmMemoryData WasmMemoryAllocator::allocateNonBucketMemory(size_t MemorySize) {
  if (UseMmap) {
    // when wasm memory overflow check by cpu,
    // then all linear memories should allocated by mmap
    size_t MmapSize = WasmMemoryAllocatorMmapSize;
    ZEN_ASSERT(sizeof(size_t) > 4);

    auto *MemoryData =
        (uint8_t *)::mmap(nullptr, MmapSize, PROT_NONE,
                          MAP_ANONYMOUS | MAP_FILE | MAP_PRIVATE, -1, 0);
    if (!MemoryData || (MemoryData == (uint8_t *)-1)) {
      ZEN_ABORT();
    }

    WasmMemoryData Result = {
        .Type = WM_MEMORY_DATA_TYPE_SINGLE_MMAP,
        .MemoryData = MemoryData,
        .MemorySize = MemorySize,
        .NeedMprotect = true,
    };
    mprotectReadWriteWasmMemoryData(Result, false);
    return Result;
  } else {
    auto *MemoryData = (uint8_t *)CurRuntime->allocateZeros(MemorySize);
    ZEN_ASSERT(MemoryData);
    return WasmMemoryData{
        .Type = WM_MEMORY_DATA_TYPE_MALLOC,
        .MemoryData = MemoryData,
        .MemorySize = MemorySize,
        .NeedMprotect = false,
    };
  }
}

// allocate linear memory space when not use mmap-bucket
WasmMemoryData WasmMemoryAllocator::reallocateNonBucketMemoryAndFillZerosToNew(
    const WasmMemoryData &OldMemoryData, size_t NewMemorySize) {
  if (UseMmap) {
    // when wasm memory overflow check by cpu,
    // then all linear memories should allocated by mmap
    size_t MmapSize = WasmMemoryAllocatorMmapSize;
    ZEN_ASSERT(sizeof(size_t) > 4);
    auto *NewMemoryData =
        (uint8_t *)::mmap(nullptr, MmapSize, PROT_NONE,
                          MAP_ANONYMOUS | MAP_FILE | MAP_PRIVATE, -1, 0);
    if (!NewMemoryData || (NewMemoryData == (uint8_t *)-1)) {
      ZEN_ABORT();
    }

    WasmMemoryData Result = {
        .Type = WM_MEMORY_DATA_TYPE_SINGLE_MMAP,
        .MemoryData = NewMemoryData,
        .MemorySize = NewMemorySize,
        .NeedMprotect = true,
    };
    WasmMemoryAllocator::mprotectReadWriteWasmMemoryData(Result, false);

    if (OldMemoryData.MemoryData) {
      ZEN_ASSERT(NewMemorySize >= OldMemoryData.MemorySize);
      std::memcpy(NewMemoryData, OldMemoryData.MemoryData,
                  OldMemoryData.MemorySize);
      internalFreeWasmMemory(OldMemoryData);
    }
    return Result;
  }
  uint8_t *NewMemoryAddr = nullptr;
  if (!OldMemoryData.MemoryData) {
    NewMemoryAddr = (uint8_t *)CurRuntime->allocateZeros(NewMemorySize);
  } else if (!(NewMemoryAddr = (uint8_t *)CurRuntime->reallocate(
                   OldMemoryData.MemoryData, OldMemoryData.MemorySize,
                   NewMemorySize))) {
    NewMemoryAddr = (uint8_t *)CurRuntime->allocateZeros(NewMemorySize);
    ZEN_ASSERT(NewMemoryAddr);
    if (OldMemoryData.MemoryData) {
      std::memcpy(NewMemoryAddr, OldMemoryData.MemoryData,
                  OldMemoryData.MemorySize);
      internalFreeWasmMemory(OldMemoryData);
    }
  }
  ZEN_ASSERT(NewMemoryAddr);
  if (OldMemoryData.MemoryData) {
    std::memset(NewMemoryAddr + OldMemoryData.MemorySize, 0x0,
                (uint32_t)NewMemorySize - OldMemoryData.MemorySize);
  }
  return WasmMemoryData{
      .Type = WM_MEMORY_DATA_TYPE_MALLOC,
      .MemoryData = NewMemoryAddr,
      .MemorySize = NewMemorySize,
      .NeedMprotect = false,
  };
}

WasmMemoryData WasmMemoryAllocator::allocInitWasmMemory(
    uint8_t *BucketAllocSand, size_t MemorySize, bool ThisInstanceUseMmap,
    /* out */ bool *FilledInitData,
    /* out */ char *ErrorBuf, uint32_t ErrorBufSize) {
  if (MemorySize == 0) {
    return WasmMemoryData{
        .Type = WasmMemoryDataType::WM_MEMORY_DATA_TYPE_NO_DATA,
        .MemoryData = nullptr,
        .MemorySize = 0,
        .NeedMprotect = false,
    };
  }
  bool InstanceUseMmap = ThisInstanceUseMmap && checkWasmMemoryCanUseMmap();
  WasmMemoryData Result;

  if (InstanceUseMmap) {
    const auto &MmapSlice = getOrCreateMmapSpace(BucketAllocSand, MemorySize);
    ZEN_ASSERT(MmapSlice.Address);
    if (FilledInitData)
      *FilledInitData = true;
    Result.Type = WM_MEMORY_DATA_TYPE_BUCKET_MMAP;
    Result.MemoryData = MmapSlice.Address;
    Result.MemorySize = MemorySize;
    Result.NeedMprotect = true;
    // unmprotect other region of the whole bucket
    // not mmap_slice.bucket_size to avoid soft-check of memory visit
    ZEN_ASSERT(sizeof(size_t) > 4);

    auto *BucketInstance = ActiveBuckets[MmapSlice.BucketBegin].get();
    for (size_t I = 0; I < BucketInstance->ItemsUsedSizes.size(); I++) {
      auto ItemUsedSize = BucketInstance->ItemsUsedSizes[I];
      if (ItemUsedSize <= 0) {
        continue;
      }
      auto ItemBeginAddr =
          BucketInstance->MmapAddr + I * BucketInstance->BucketItemSize;
      if (0 != ::mprotect(ItemBeginAddr, ItemUsedSize, PROT_NONE)) {
        ZEN_ABORT();
      }
    }

    // mprotect the bucket slice
    mprotectReadWriteWasmMemoryData(Result, false);
    return Result;
  }
  Result = allocateNonBucketMemory(MemorySize);
  if (FilledInitData)
    *FilledInitData = false;
  return Result;
}

void WasmMemoryAllocator::internalFreeWasmMemory(const WasmMemoryData &Data) {
  if (Data.Type == WM_MEMORY_DATA_TYPE_SINGLE_MMAP) {
    if (0 != ::munmap(Data.MemoryData, Data.MemorySize)) {
      ZEN_ABORT();
    }
  } else if (Data.Type == WM_MEMORY_DATA_TYPE_MALLOC) {
    CurRuntime->deallocate(Data.MemoryData);
  } else if (Data.Type == WM_MEMORY_DATA_TYPE_BUCKET_MMAP) {
    auto MmapBucketIt = MemoryAddrToMmapAddr->find(Data.MemoryData);
    ZEN_ASSERT(MmapBucketIt != MemoryAddrToMmapAddr->end());
    auto *MmapBucket = MmapBucketIt->second;
    auto BucketFreedCountPtrIt = MmapBucketsFreedCount->find(MmapBucket);
    if (BucketFreedCountPtrIt != MmapBucketsFreedCount->end()) {
      // when bucket_freed_count_ptr means the bucket freed before
      auto *BucketFreedCountPtr = BucketFreedCountPtrIt->second;
      *BucketFreedCountPtr += 1;
      if (*BucketFreedCountPtr >= WasmMemoryAllocatorBucketDuplicates) {
        // all freed, need munmap
        size_t UnmapSize = MmapBucketSize;

        // mprotect 8GB to use cpu-trap to check memory load/store
        UnmapSize = WasmMemoryAllocatorMmapSize;
        ZEN_ASSERT(sizeof(size_t) > 4);

        if (0 != ::munmap(MmapBucket, UnmapSize)) {
          ZEN_ABORT();
        }
        MmapAddresses->erase(MmapBucket);

        ::free(BucketFreedCountPtr);

        MmapBucketsFreedCount->erase(MmapBucket);

        ActiveBuckets.erase(MmapBucket);
      }
    }
    MemoryAddrToMmapAddr->erase(Data.MemoryData);
  } else {
    CurRuntime->deallocate(Data.MemoryData);
  }
}

WasmMemoryData
WasmMemoryAllocator::enlargeWasmMemory(const WasmMemoryData &OldMemoryData,
                                       size_t NewMemorySize) {
  bool NeedFreeOldMmap = false;
  if (UseMmap) {
    // when use bucket with mmap linear-memory,
    // memory.grow must re-alloc memory to grow
    bool OldUseMmap = (OldMemoryData.Type == WM_MEMORY_DATA_TYPE_BUCKET_MMAP ||
                       OldMemoryData.Type == WM_MEMORY_DATA_TYPE_SINGLE_MMAP);
    bool InstanceUseMmap =
        OldUseMmap && (NewMemorySize <= MmapMemoryBucketGrowMaxSize);
    if (OldUseMmap && InstanceUseMmap) {
      // the mmap item space has enough space to grow
      const auto &NewMemoryData = WasmMemoryData{
          .Type = OldMemoryData.Type,
          .MemoryData = OldMemoryData.MemoryData,
          .MemorySize = NewMemorySize,
          .NeedMprotect = false,
      };
      if (OldMemoryData.Type == WM_MEMORY_DATA_TYPE_BUCKET_MMAP) {
        auto *BucketMemAddr = (*MemoryAddrToMmapAddr)[OldMemoryData.MemoryData];
        auto *BucketInstance = ActiveBuckets[BucketMemAddr].get();
        auto IndexInBucket = (OldMemoryData.MemoryData - BucketMemAddr) /
                             BucketInstance->BucketItemSize;
        BucketInstance->ItemsUsedSizes[IndexInBucket] = NewMemorySize;
      }

      mprotectReadWriteWasmMemoryData(NewMemoryData, false);
      return NewMemoryData;
    }

    if (OldUseMmap && !InstanceUseMmap) {
      NeedFreeOldMmap = true;
    }
  }
  auto *OldMemoryAddr = OldMemoryData.MemoryData;
  auto OldMemorySize = OldMemoryData.MemorySize;
  WasmMemoryData NewMemoryData;
  if (NeedFreeOldMmap) {
    NewMemoryData = allocateNonBucketMemory(NewMemorySize);
    ZEN_ASSERT(NewMemoryData.MemoryData != nullptr);
    if (OldMemoryAddr) {
      std::memcpy(NewMemoryData.MemoryData, OldMemoryData.MemoryData,
                  OldMemorySize);
      internalFreeWasmMemory(OldMemoryData);
    }
  } else {
    NewMemoryData = reallocateNonBucketMemoryAndFillZerosToNew(OldMemoryData,
                                                               NewMemorySize);
  }
  return NewMemoryData;
}
void WasmMemoryAllocator::freeWasmMemory(const WasmMemoryData &WasmMemoryData) {
  internalFreeWasmMemory(WasmMemoryData);
}

} // namespace zen::runtime
