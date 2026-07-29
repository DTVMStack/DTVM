//===- CgInterferenceCache.h - Caching per-block interference ----*- C++
//-*--===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// CgInterferenceCache remembers per-block interference from LiveIntervalUnions,
// fixed RegUnit interference, and register masks.
//
//===----------------------------------------------------------------------===//

#pragma once

#include <cstdint>

#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/Compiler.h"
#include <cassert>
#include <cstddef>
#include <cstdlib>

#include "live_interval.h"
#include "live_interval_union.h"
#include "slot_indexes.h"

namespace llvm {
class TargetRegisterInfo;
}

namespace COMPILER {

class CgLiveIntervals;
class CgFunction;

class LLVM_LIBRARY_VISIBILITY CgInterferenceCache {
  /// BlockInterference - information about the interference in a single basic
  /// block.
  struct BlockInterference {
    unsigned Tag = 0;
    CgSlotIndex First;
    CgSlotIndex Last;

    BlockInterference() = default;
  };

  /// Entry - A cache entry containing interference information for all aliases
  /// of PhysReg in all basic blocks.
  class Entry {
    /// PhysReg - The register currently represented.
    MCRegister PhysReg = 0;

    /// Tag - Cache tag is changed when any of the underlying LiveIntervalUnions
    /// change.
    unsigned Tag = 0;

    /// RefCount - The total number of Cursor instances referring to this Entry.
    unsigned RefCount = 0;

    /// MF - The current function.
    CgFunction *MF = nullptr;

    /// Indexes - Mapping block numbers to CgSlotIndex ranges.
    CgSlotIndexes *Indexes = nullptr;

    /// LIS - Used for accessing register mask interference maps.
    CgLiveIntervals *LIS = nullptr;

    /// PrevPos - The previous position the iterators were moved to.
    CgSlotIndex PrevPos;

    /// RegUnitInfo - Information tracked about each RegUnit in PhysReg.
    /// When PrevPos is set, the iterators are valid as if advanceTo(PrevPos)
    /// had just been called.
    struct RegUnitInfo {
      /// Iterator pointing into the CgLiveIntervalUnion containing virtual
      /// register interference.
      CgLiveIntervalUnion::SegmentIter VirtI;

      /// Tag of the LIU last time we looked.
      unsigned VirtTag = 0;

      /// Fixed interference in RegUnit.
      CgLiveRange *Fixed = nullptr;

      /// Iterator pointing into the fixed RegUnit interference.
      CgLiveInterval::iterator FixedI{};

      RegUnitInfo(CgLiveIntervalUnion &LIU) : VirtTag(LIU.getTag()) {
        VirtI.setMap(LIU.getMap());
      }
    };

    /// Info for each RegUnit in PhysReg. It is very rare ofr a PHysReg to have
    /// more than 4 RegUnits.
    SmallVector<RegUnitInfo, 4> RegUnits;

    /// Blocks - Interference for each block in the function.
    SmallVector<BlockInterference, 8> Blocks;

    /// update - Recompute Blocks[MBBNum]
    void update(unsigned MBBNum);

  public:
    Entry() = default;

    void clear(CgFunction *mf, CgSlotIndexes *indexes, CgLiveIntervals *lis) {
      assert(!hasRefs() && "Cannot clear cache entry with references");
      PhysReg = MCRegister::NoRegister;
      MF = mf;
      Indexes = indexes;
      LIS = lis;
    }

    MCRegister getPhysReg() const { return PhysReg; }

    void addRef(int Delta) { RefCount += Delta; }

    bool hasRefs() const { return RefCount > 0; }

    void revalidate(CgLiveIntervalUnion *LIUArray,
                    const TargetRegisterInfo *TRI);

    /// valid - Return true if this is a valid entry for physReg.
    bool valid(CgLiveIntervalUnion *LIUArray, const TargetRegisterInfo *TRI);

    /// reset - Initialize entry to represent physReg's aliases.
    void reset(MCRegister physReg, CgLiveIntervalUnion *LIUArray,
               const TargetRegisterInfo *TRI, const CgFunction *MF);

    /// get - Return an up to date BlockInterference.
    BlockInterference *get(unsigned MBBNum) {
      if (Blocks[MBBNum].Tag != Tag)
        update(MBBNum);
      return &Blocks[MBBNum];
    }
  };

  // We don't keep a cache entry for every physical register, that would use too
  // much memory. Instead, a fixed number of cache entries are used in a round-
  // robin manner.
  enum { CacheEntries = 32 };

  const TargetRegisterInfo *TRI = nullptr;
  CgLiveIntervalUnion *LIUArray = nullptr;
  CgFunction *MF = nullptr;

  // Point to an entry for each physreg. The entry pointed to may not be up to
  // date, and it may have been reused for a different physreg.
  unsigned char *PhysRegEntries = nullptr;
  size_t PhysRegEntriesCount = 0;

  // Next round-robin entry to be picked.
  unsigned RoundRobin = 0;

  // The actual cache entries.
  Entry Entries[CacheEntries];

  // get - Get a valid entry for PhysReg.
  Entry *get(MCRegister PhysReg);

public:
  CgInterferenceCache() = default;
  CgInterferenceCache(const CgInterferenceCache &Other) = delete;
  CgInterferenceCache &operator=(const CgInterferenceCache &Other) = delete;

  ~CgInterferenceCache() { free(PhysRegEntries); }

  void reinitPhysRegEntries();

  /// init - Prepare cache for a new function.
  void init(CgFunction *mf, CgLiveIntervalUnion *liuarray,
            CgSlotIndexes *indexes, CgLiveIntervals *lis,
            const TargetRegisterInfo *tri);

  /// getMaxCursors - Return the maximum number of concurrent cursors that can
  /// be supported.
  unsigned getMaxCursors() const { return CacheEntries; }

  /// Cursor - The primary query interface for the block interference cache.
  class Cursor {
    Entry *CacheEntry = nullptr;
    const BlockInterference *Current = nullptr;
    static const BlockInterference NoInterference;

    void setEntry(Entry *E) {
      Current = nullptr;
      // Update reference counts. Nothing happens when RefCount reaches 0, so
      // we don't have to check for E == CacheEntry etc.
      if (CacheEntry)
        CacheEntry->addRef(-1);
      CacheEntry = E;
      if (CacheEntry)
        CacheEntry->addRef(+1);
    }

  public:
    /// Cursor - Create a dangling cursor.
    Cursor() = default;

    Cursor(const Cursor &O) { setEntry(O.CacheEntry); }

    Cursor &operator=(const Cursor &O) {
      setEntry(O.CacheEntry);
      return *this;
    }

    ~Cursor() { setEntry(nullptr); }

    /// setPhysReg - Point this cursor to PhysReg's interference.
    void setPhysReg(CgInterferenceCache &Cache, MCRegister PhysReg) {
      // Release reference before getting a new one. That guarantees we can
      // actually have CacheEntries live cursors.
      setEntry(nullptr);
      if (PhysReg.isValid())
        setEntry(Cache.get(PhysReg));
    }

    /// moveTo - Move cursor to basic block MBBNum.
    void moveToBlock(unsigned MBBNum) {
      Current = CacheEntry ? CacheEntry->get(MBBNum) : &NoInterference;
    }

    /// hasInterference - Return true if the current block has any interference.
    bool hasInterference() { return Current->First.isValid(); }

    /// first - Return the starting index of the first interfering range in the
    /// current block.
    CgSlotIndex first() { return Current->First; }

    /// last - Return the ending index of the last interfering range in the
    /// current block.
    CgSlotIndex last() { return Current->Last; }
  };
};

} // namespace COMPILER
