// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_EVM_FRONTEND_EVM_MEMORY_GROUPING_H
#define COMPILER_EVM_FRONTEND_EVM_MEMORY_GROUPING_H

#include "compiler/evm_frontend/evm_memory_precheck.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace COMPILER {

// Consumer result: a consecutive run of MemoryOps that can share one memory
// expansion precheck. It carries no store optimization decision.
struct ContiguousGroup {
  uint64_t EntryPC = 0;
  uint64_t FirstOpPC = 0;
  uint64_t LastOpPC = 0;
  uint64_t OpCount = 0;
  std::vector<uint32_t> OpIds;
  MemoryInterval UnionInterval;
};

// Consumer result: proof that the entire group interval can be prechecked once.
struct SharedPrecheck {
  ContiguousGroup Group;
  ProvenMemoryRange Range;
};

// Consumer: groups adjacent proven MemoryOps for shared memory precheck only.
// Expansion depends on the union end, not on alias or contiguity.
class MemoryGroupingConsumer final : public MemoryOptimizationPlanProvider {
public:
  MemoryGroupingConsumer(const MemoryAnalysisView &View,
                         const MemoryPrecheckConsumer &Prechecks)
      : View(View), Prechecks(Prechecks) {}

  std::optional<MemoryExpansionPlan>
  buildMemoryExpansionPlan(uint64_t EntryPC,
                           uint64_t BodyEndPC) const override {
    std::optional<SharedPrecheck> Shared =
        getSharedPrecheck(EntryPC, BodyEndPC);
    if (!Shared) {
      return std::nullopt;
    }
    return MemoryExpansionPlan::fromProvenRange(
        Shared->Range, MemoryExpansionKind::ContiguousGroup);
  }

  std::optional<SharedPrecheck> getSharedPrecheck(uint64_t EntryPC,
                                                  uint64_t BodyEndPC) const {
    std::optional<ContiguousGroup> Best;
    std::optional<ContiguousGroup> Current;

    for (const MemoryOp &Op : View.getFacts().Ops) {
      if (Op.Pc < EntryPC) {
        continue;
      }
      if (Op.Pc >= BodyEndPC) {
        break;
      }

      std::optional<ProvenMemoryRange> Proof =
          Prechecks.getOpPrecheckRange(EntryPC, Op);
      if (!Proof) {
        const MemoryBarrierKind Barrier = View.getBarrierKind(Op);
        finishGroup(Current, Best);
        if (Barrier != MemoryBarrierKind::None) {
          continue;
        }
        continue;
      }

      if (!Current) {
        Current = makeGroup(EntryPC, *Proof);
      } else if (!append(*Current, *Proof)) {
        finishGroup(Current, Best);
        Current = makeGroup(EntryPC, *Proof);
      }
    }

    finishGroup(Current, Best);
    if (!Best || Best->OpCount < 2) {
      return std::nullopt;
    }

    SharedPrecheck Result;
    Result.Group = *Best;
    Result.Range.EntryPC = Best->EntryPC;
    Result.Range.FirstOpPC = Best->FirstOpPC;
    Result.Range.LastOpPC = Best->LastOpPC;
    Result.Range.CoveredOpCount = Best->OpCount;
    Result.Range.CoveredOpIds = Best->OpIds;
    Result.Range.Interval = Best->UnionInterval;
    return Result;
  }

private:
  static bool getBounds(const MemoryInterval &Interval, uint64_t &Begin,
                        uint64_t &End) {
    if (Interval.Space != AddressSpace::Memory || !Interval.Addr.isKnown() ||
        Interval.Addr.Kind != AddressBaseKind::Const || !Interval.Size.Known ||
        Interval.Addr.Offset < 0) {
      return false;
    }
    Begin = static_cast<uint64_t>(Interval.Addr.Offset);
    if (Interval.Size.Value > UINT64_MAX - Begin) {
      return false;
    }
    End = Begin + Interval.Size.Value;
    return true;
  }

  static ContiguousGroup makeGroup(uint64_t EntryPC,
                                   const ProvenMemoryRange &Proof) {
    ContiguousGroup Group;
    Group.EntryPC = EntryPC;
    Group.FirstOpPC = Proof.FirstOpPC;
    Group.LastOpPC = Proof.LastOpPC;
    Group.OpCount = 1;
    Group.OpIds = Proof.CoveredOpIds;
    Group.UnionInterval = Proof.Interval;
    return Group;
  }

  static bool append(ContiguousGroup &Group, const ProvenMemoryRange &Proof) {
    uint64_t GroupBegin = 0;
    uint64_t GroupEnd = 0;
    uint64_t ProofBegin = 0;
    uint64_t ProofEnd = 0;
    if (!getBounds(Group.UnionInterval, GroupBegin, GroupEnd) ||
        !getBounds(Proof.Interval, ProofBegin, ProofEnd)) {
      return false;
    }

    const uint64_t UnionBegin = std::min(GroupBegin, ProofBegin);
    const uint64_t UnionEnd = std::max(GroupEnd, ProofEnd);
    Group.LastOpPC = Proof.LastOpPC;
    ++Group.OpCount;
    Group.OpIds.insert(Group.OpIds.end(), Proof.CoveredOpIds.begin(),
                       Proof.CoveredOpIds.end());
    Group.UnionInterval.Space = AddressSpace::Memory;
    Group.UnionInterval.Addr = AddressExpr::constant(UnionBegin);
    Group.UnionInterval.Size = SizeExpr::constant(UnionEnd - UnionBegin);
    Group.UnionInterval.Empty = UnionBegin == UnionEnd;
    return true;
  }

  static void finishGroup(std::optional<ContiguousGroup> &Current,
                          std::optional<ContiguousGroup> &Best) {
    if (Current && Current->OpCount >= 2 &&
        (!Best || Current->OpCount > Best->OpCount)) {
      Best = Current;
    }
    Current.reset();
  }

  const MemoryAnalysisView &View;
  const MemoryPrecheckConsumer &Prechecks;
};

// Consumer: builds one expansion precheck for a single-entry, single-successor
// straight-line CFG chain. The head block emits the precheck; later blocks in
// the chain reuse it through planner-provided guaranteed entry bytes.
class MemoryLinearRegionConsumer final : public MemoryOptimizationPlanProvider {
public:
  explicit MemoryLinearRegionConsumer(const MemoryAnalysisView &View)
      : View(View) {
    buildRegions();
  }

  std::optional<MemoryExpansionPlan>
  buildMemoryExpansionPlan(uint64_t EntryPC,
                           uint64_t BodyEndPC) const override {
    (void)BodyEndPC;
    auto It = PlansByHead.find(EntryPC);
    if (It == PlansByHead.end()) {
      return std::nullopt;
    }
    return It->second;
  }

  uint64_t getGuaranteedMinBytesAtEntry(uint64_t EntryPC) const {
    auto It = GuaranteedEntryBytes.find(EntryPC);
    return It == GuaranteedEntryBytes.end() ? 0 : It->second;
  }

  MemoryLinearRegionRejectReason getRejectReason(uint64_t EntryPC) const {
    if (PlansByHead.find(EntryPC) != PlansByHead.end() ||
        AcceptedRegionBodies.count(EntryPC) != 0 ||
        DelegatedEmptyEntries.count(EntryPC) != 0) {
      return MemoryLinearRegionRejectReason::None;
    }
    auto It = RejectReasons.find(EntryPC);
    return It == RejectReasons.end()
               ? MemoryLinearRegionRejectReason::NotStraightLine
               : It->second;
  }

  MemoryLinearRegionPrefixInfo getPrefixInfo(uint64_t EntryPC) const {
    auto It = PrefixInfos.find(EntryPC);
    return It == PrefixInfos.end() ? MemoryLinearRegionPrefixInfo()
                                   : It->second;
  }

  MemoryLinearRegionHeadSelectionInfo
  getHeadSelectionInfo(uint64_t EntryPC) const {
    auto It = HeadSelectionInfos.find(EntryPC);
    return It == HeadSelectionInfos.end()
               ? MemoryLinearRegionHeadSelectionInfo()
               : It->second;
  }

private:
  static bool isDirectMemoryOp(const MemoryOp &Op) {
    return Op.Kind == MemoryOpKind::MLoad || Op.Kind == MemoryOpKind::MStore ||
           Op.Kind == MemoryOpKind::MStore8;
  }

  static const MemoryInterval *getDirectMemoryInterval(const MemoryOp &Op) {
    switch (Op.Kind) {
    case MemoryOpKind::MLoad:
      return Op.Reads.size() == 1 ? &Op.Reads[0] : nullptr;
    case MemoryOpKind::MStore:
    case MemoryOpKind::MStore8:
      return Op.Writes.size() == 1 ? &Op.Writes[0] : nullptr;
    default:
      return nullptr;
    }
  }

  static bool getIntervalEnd(const MemoryInterval &Interval, uint64_t &End) {
    if (Interval.Space != AddressSpace::Memory || Interval.Empty ||
        !Interval.Addr.isKnown() ||
        Interval.Addr.Kind != AddressBaseKind::Const || !Interval.Size.Known ||
        Interval.Addr.Offset < 0) {
      return false;
    }
    const uint64_t Begin = static_cast<uint64_t>(Interval.Addr.Offset);
    if (Interval.Size.Value > UINT64_MAX - Begin) {
      return false;
    }
    End = Begin + Interval.Size.Value;
    return true;
  }

  static uint64_t
  countDirectMemoryOps(const MemoryFacts &Facts,
                       const std::vector<const MemoryBlockFacts *> &Chain) {
    uint64_t Count = 0;
    for (const MemoryBlockFacts *Block : Chain) {
      for (size_t I = Block->OpsBegin;
           I < Block->OpsEnd && I < Facts.Ops.size(); ++I) {
        if (isDirectMemoryOp(Facts.Ops[I])) {
          ++Count;
        }
      }
    }
    return Count;
  }

  static bool blockHasDirectMemoryOp(const MemoryFacts &Facts,
                                     const MemoryBlockFacts &Block) {
    for (size_t I = Block.OpsBegin; I < Block.OpsEnd && I < Facts.Ops.size();
         ++I) {
      if (isDirectMemoryOp(Facts.Ops[I])) {
        return true;
      }
    }
    return false;
  }

  static MemoryLinearRegionRejectReason
  mapHardBarrierKind(MemoryHardBarrierKind Kind) {
    switch (Kind) {
    case MemoryHardBarrierKind::None:
      return MemoryLinearRegionRejectReason::HardBarrier;
    case MemoryHardBarrierKind::MSize:
      return MemoryLinearRegionRejectReason::BarrierMSize;
    case MemoryHardBarrierKind::Gas:
      return MemoryLinearRegionRejectReason::BarrierGas;
    case MemoryHardBarrierKind::Call:
      return MemoryLinearRegionRejectReason::BarrierCall;
    case MemoryHardBarrierKind::Create:
      return MemoryLinearRegionRejectReason::BarrierCreate;
    case MemoryHardBarrierKind::Return:
      return MemoryLinearRegionRejectReason::BarrierReturn;
    case MemoryHardBarrierKind::Revert:
      return MemoryLinearRegionRejectReason::BarrierRevert;
    case MemoryHardBarrierKind::Log:
      return MemoryLinearRegionRejectReason::BarrierLog;
    case MemoryHardBarrierKind::Storage:
      return MemoryLinearRegionRejectReason::BarrierStorage;
    case MemoryHardBarrierKind::SelfDestruct:
      return MemoryLinearRegionRejectReason::BarrierSelfDestruct;
    case MemoryHardBarrierKind::Invalid:
      return MemoryLinearRegionRejectReason::BarrierInvalid;
    case MemoryHardBarrierKind::UnknownEffect:
      return MemoryLinearRegionRejectReason::BarrierUnknownEffect;
    case MemoryHardBarrierKind::Escape:
      return MemoryLinearRegionRejectReason::BarrierEscape;
    }
    return MemoryLinearRegionRejectReason::HardBarrier;
  }

  static MemoryLinearRegionRejectReason mapHardBarrierOp(const MemoryOp &Op) {
    switch (Op.Kind) {
    case MemoryOpKind::MSize:
      return MemoryLinearRegionRejectReason::BarrierMSize;
    case MemoryOpKind::Gas:
      return MemoryLinearRegionRejectReason::BarrierGas;
    case MemoryOpKind::Call:
      return MemoryLinearRegionRejectReason::BarrierCall;
    case MemoryOpKind::Create:
      return MemoryLinearRegionRejectReason::BarrierCreate;
    case MemoryOpKind::Return:
      return MemoryLinearRegionRejectReason::BarrierReturn;
    case MemoryOpKind::Revert:
      return MemoryLinearRegionRejectReason::BarrierRevert;
    case MemoryOpKind::Log:
      return MemoryLinearRegionRejectReason::BarrierLog;
    default:
      break;
    }

    switch (Op.Opcode) {
    case OP_SSTORE:
    case OP_TSTORE:
      return MemoryLinearRegionRejectReason::BarrierStorage;
    case OP_SELFDESTRUCT:
      return MemoryLinearRegionRejectReason::BarrierSelfDestruct;
    case OP_INVALID:
      return MemoryLinearRegionRejectReason::BarrierInvalid;
    default:
      break;
    }

    switch (Op.Effect) {
    case MemoryEffect::Escape:
      return MemoryLinearRegionRejectReason::BarrierEscape;
    case MemoryEffect::MemorySizeObserver:
      return MemoryLinearRegionRejectReason::BarrierMSize;
    case MemoryEffect::GasSensitive:
      return MemoryLinearRegionRejectReason::BarrierGas;
    case MemoryEffect::Unknown:
      return MemoryLinearRegionRejectReason::BarrierUnknownEffect;
    case MemoryEffect::None:
    case MemoryEffect::Read:
    case MemoryEffect::Write:
    case MemoryEffect::ReadWrite:
      break;
    }
    return MemoryLinearRegionRejectReason::HardBarrier;
  }

  static std::optional<MemoryLinearRegionRejectReason>
  getHardBarrierRejectReason(const MemoryAnalysisView &View,
                             const MemoryBlockFacts &Block,
                             const MemoryFacts &Facts) {
    if (Block.HasBarrier) {
      return mapHardBarrierKind(Block.FirstHardBarrierKind);
    }
    for (size_t I = Block.OpsBegin; I < Block.OpsEnd && I < Facts.Ops.size();
         ++I) {
      const MemoryOp &Op = Facts.Ops[I];
      switch (View.getBarrierKind(Op)) {
      case MemoryBarrierKind::Escape:
      case MemoryBarrierKind::MemorySizeObserver:
      case MemoryBarrierKind::GasSensitive:
      case MemoryBarrierKind::Unknown:
        return mapHardBarrierOp(Op);
      case MemoryBarrierKind::None:
      case MemoryBarrierKind::Read:
      case MemoryBarrierKind::Write:
      case MemoryBarrierKind::ReadWrite:
        break;
      }
    }
    return std::nullopt;
  }

  bool selectRegionHead(uint64_t EntryPC, uint64_t &HeadPC,
                        std::vector<uint64_t> &SkippedEmptyEntries,
                        MemoryLinearRegionHeadSelectionInfo &Info) const {
    const MemoryFacts &Facts = View.getFacts();
    std::set<uint64_t> Seen;
    uint64_t CurrentPC = EntryPC;

    while (true) {
      auto BlockIt = Facts.Blocks.find(CurrentPC);
      if (BlockIt == Facts.Blocks.end() || Seen.count(CurrentPC) != 0) {
        Info.RejectedPredecessorNotStraight = true;
        return false;
      }
      Seen.insert(CurrentPC);

      const MemoryBlockFacts &Block = BlockIt->second;
      if (blockHasDirectMemoryOp(Facts, Block)) {
        ++Info.CandidateBlocks;
        HeadPC = CurrentPC;
        return true;
      }

      // A block with any memory fact is not an empty prefix. Let the normal
      // region validation classify barriers and unsupported operations.
      if (Block.OpsBegin != Block.OpsEnd ||
          getHardBarrierRejectReason(View, Block, Facts).has_value()) {
        HeadPC = CurrentPC;
        return true;
      }

      ++Info.SkippedEmptyBlocks;
      SkippedEmptyEntries.push_back(CurrentPC);
      if (Block.Successors.size() != 1) {
        Info.RejectedPredecessorNotStraight = true;
        return false;
      }

      const uint64_t SuccPC = Block.Successors[0];
      auto SuccIt = Facts.Blocks.find(SuccPC);
      if (SuccIt == Facts.Blocks.end() || SuccPC <= Block.EntryPC ||
          Seen.count(SuccPC) != 0) {
        Info.RejectedPredecessorNotStraight = true;
        return false;
      }
      if (SuccIt->second.Predecessors.size() != 1 ||
          SuccIt->second.Predecessors[0] != Block.EntryPC) {
        if (blockHasDirectMemoryOp(Facts, SuccIt->second)) {
          ++Info.CandidateBlocks;
        }
        Info.RejectedHeadNotDominatingChain = true;
        return false;
      }

      CurrentPC = SuccPC;
    }
  }

  bool
  collectStraightLineChain(uint64_t EntryPC,
                           std::vector<const MemoryBlockFacts *> &Chain,
                           MemoryLinearRegionRejectReason &RejectReason,
                           MemoryLinearRegionPrefixInfo &PrefixInfo) const {
    const MemoryFacts &Facts = View.getFacts();
    std::set<uint64_t> Seen;
    uint64_t CurrentPC = EntryPC;

    auto RecordPrefixInfo = [&](MemoryLinearRegionPrefixStopReason StopReason) {
      PrefixInfo.Blocks = Chain.size();
      PrefixInfo.Ops = countDirectMemoryOps(Facts, Chain);
      PrefixInfo.StopReason = StopReason;
    };

    auto FinishAtCurrentTail =
        [&](MemoryLinearRegionPrefixStopReason StopReason,
            MemoryLinearRegionRejectReason NoPrefixReason) {
          RecordPrefixInfo(StopReason);
          if (Chain.size() >= 2) {
            return true;
          }
          RejectReason = NoPrefixReason;
          return false;
        };

    while (true) {
      auto BlockIt = Facts.Blocks.find(CurrentPC);
      if (BlockIt == Facts.Blocks.end()) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::MissingSuccessorBlock,
            MemoryLinearRegionRejectReason::NotStraightLine);
      }
      if (Seen.count(CurrentPC) != 0) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::BackedgeAfterSafePrefix,
            MemoryLinearRegionRejectReason::BackedgeOrNonForward);
      }

      const MemoryBlockFacts &Block = BlockIt->second;
      if (std::optional<MemoryLinearRegionRejectReason> BarrierReason =
              getHardBarrierRejectReason(View, Block, Facts)) {
        if (Chain.size() >= 2) {
          RecordPrefixInfo(
              MemoryLinearRegionPrefixStopReason::BarrierAfterSafePrefix);
          return true;
        }
        RecordPrefixInfo(MemoryLinearRegionPrefixStopReason::None);
        RejectReason = *BarrierReason;
        return false;
      }

      Seen.insert(CurrentPC);
      Chain.push_back(&Block);

      if (Block.Successors.empty()) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::TerminalAfterSafePrefix,
            MemoryLinearRegionRejectReason::NotStraightLine);
      }
      if (Block.Successors.size() != 1) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::BranchingAfterSafePrefix,
            Chain.size() == 1
                ? MemoryLinearRegionRejectReason::BranchingHead
                : MemoryLinearRegionRejectReason::NotStraightLine);
      }

      const uint64_t SuccPC = Block.Successors[0];
      auto SuccIt = Facts.Blocks.find(SuccPC);
      if (SuccIt == Facts.Blocks.end()) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::MissingSuccessorBlock,
            MemoryLinearRegionRejectReason::NotStraightLine);
      }
      if (SuccIt->second.Predecessors.size() != 1 ||
          SuccIt->second.Predecessors[0] != Block.EntryPC) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::MergeAfterSafePrefix,
            MemoryLinearRegionRejectReason::MergeSuccessor);
      }
      if (SuccPC <= Block.EntryPC || Seen.count(SuccPC) != 0) {
        return FinishAtCurrentTail(
            MemoryLinearRegionPrefixStopReason::BackedgeAfterSafePrefix,
            MemoryLinearRegionRejectReason::BackedgeOrNonForward);
      }

      CurrentPC = SuccPC;
    }
  }

  std::optional<ProvenMemoryRange>
  buildRangeForChain(const std::vector<const MemoryBlockFacts *> &Chain,
                     MemoryLinearRegionRejectReason &RejectReason) const {
    const MemoryFacts &Facts = View.getFacts();
    uint64_t MaxEnd = 0;
    uint64_t CoveredOps = 0;
    uint64_t HeadCoveredOps = 0;
    uint64_t FirstOpPC = 0;
    uint64_t LastOpPC = 0;
    std::vector<uint32_t> CoveredOpIds;

    for (size_t BlockIndex = 0; BlockIndex < Chain.size(); ++BlockIndex) {
      const MemoryBlockFacts &Block = *Chain[BlockIndex];
      for (size_t I = Block.OpsBegin; I < Block.OpsEnd && I < Facts.Ops.size();
           ++I) {
        const MemoryOp &Op = Facts.Ops[I];
        if (!isDirectMemoryOp(Op)) {
          RejectReason = MemoryLinearRegionRejectReason::NonDirectMemoryOp;
          return std::nullopt;
        }

        const MemoryInterval *Interval = getDirectMemoryInterval(Op);
        uint64_t End = 0;
        if (Interval == nullptr || !getIntervalEnd(*Interval, End)) {
          RejectReason = MemoryLinearRegionRejectReason::UnknownInterval;
          return std::nullopt;
        }

        MaxEnd = std::max(MaxEnd, End);
        if (CoveredOps == 0) {
          FirstOpPC = Op.Pc;
        }
        LastOpPC = Op.Pc;
        CoveredOpIds.push_back(Op.Id);
        ++CoveredOps;
        if (BlockIndex == 0) {
          ++HeadCoveredOps;
        }
      }
    }

    if (HeadCoveredOps == 0) {
      RejectReason = MemoryLinearRegionRejectReason::NoHeadMemoryOp;
      return std::nullopt;
    }
    if (CoveredOps < 2) {
      RejectReason = MemoryLinearRegionRejectReason::TooFewOps;
      return std::nullopt;
    }

    ProvenMemoryRange Range;
    Range.EntryPC = Chain.front()->EntryPC;
    Range.FirstOpPC = FirstOpPC;
    Range.LastOpPC = LastOpPC;
    Range.CoveredOpCount = CoveredOps;
    Range.CoveredOpIds = std::move(CoveredOpIds);
    Range.Interval.Space = AddressSpace::Memory;
    Range.Interval.Addr = AddressExpr::constant(0);
    Range.Interval.Size = SizeExpr::constant(MaxEnd);
    Range.Interval.Empty = MaxEnd == 0;
    return Range;
  }

  static MemoryLinearRegionRejectReason
  mapPlanRejectReason(MemoryExpansionPlanRejectReason Reason) {
    switch (Reason) {
    case MemoryExpansionPlanRejectReason::None:
      return MemoryLinearRegionRejectReason::None;
    case MemoryExpansionPlanRejectReason::Unprofitable:
      return MemoryLinearRegionRejectReason::Unprofitable;
    case MemoryExpansionPlanRejectReason::UnknownInterval:
    case MemoryExpansionPlanRejectReason::InvalidRange:
    case MemoryExpansionPlanRejectReason::Overflow:
    case MemoryExpansionPlanRejectReason::TooLarge:
    case MemoryExpansionPlanRejectReason::ZeroSize:
    case MemoryExpansionPlanRejectReason::NoCandidate:
      return MemoryLinearRegionRejectReason::UnknownInterval;
    }
    return MemoryLinearRegionRejectReason::UnknownInterval;
  }

  void
  recordGuaranteedEntries(const std::vector<const MemoryBlockFacts *> &Chain,
                          uint64_t GuaranteedBytes) {
    for (size_t I = 1; I < Chain.size(); ++I) {
      uint64_t &EntryBytes = GuaranteedEntryBytes[Chain[I]->EntryPC];
      EntryBytes = std::max(EntryBytes, GuaranteedBytes);
    }
  }

  void buildRegions() {
    const MemoryFacts &Facts = View.getFacts();

    for (const auto &[EntryPC, Block] : Facts.Blocks) {
      (void)Block;
      if (AcceptedRegionBodies.count(EntryPC) != 0 ||
          ProcessedRegionHeads.count(EntryPC) != 0 ||
          DelegatedEmptyEntries.count(EntryPC) != 0) {
        continue;
      }

      uint64_t HeadPC = EntryPC;
      std::vector<uint64_t> SkippedEmptyEntries;
      MemoryLinearRegionHeadSelectionInfo HeadSelectionInfo;
      if (!selectRegionHead(EntryPC, HeadPC, SkippedEmptyEntries,
                            HeadSelectionInfo)) {
        HeadSelectionInfos[EntryPC] = HeadSelectionInfo;
        RejectReasons[EntryPC] =
            MemoryLinearRegionRejectReason::NotStraightLine;
        continue;
      }

      ProcessedRegionHeads.insert(HeadPC);
      if (HeadPC != EntryPC) {
        DelegatedEmptyEntries.insert(SkippedEmptyEntries.begin(),
                                     SkippedEmptyEntries.end());
      }

      MemoryLinearRegionRejectReason RejectReason =
          MemoryLinearRegionRejectReason::None;
      MemoryLinearRegionPrefixInfo PrefixInfo;
      std::vector<const MemoryBlockFacts *> Chain;
      if (!collectStraightLineChain(HeadPC, Chain, RejectReason, PrefixInfo)) {
        PrefixInfos[HeadPC] = PrefixInfo;
        RejectReasons[HeadPC] = RejectReason;
        HeadSelectionInfos[EntryPC] = HeadSelectionInfo;
        continue;
      }
      PrefixInfo.Blocks = Chain.size();
      PrefixInfo.Ops = countDirectMemoryOps(Facts, Chain);

      std::optional<ProvenMemoryRange> Range =
          buildRangeForChain(Chain, RejectReason);
      if (!Range) {
        PrefixInfos[HeadPC] = PrefixInfo;
        RejectReasons[HeadPC] = RejectReason;
        HeadSelectionInfos[EntryPC] = HeadSelectionInfo;
        continue;
      }
      PrefixInfo.Ops = Range->CoveredOpCount;

      MemoryExpansionPlanRejectReason PlanRejectReason =
          MemoryExpansionPlanRejectReason::None;
      std::optional<MemoryExpansionPlan> Plan =
          MemoryExpansionPlan::fromProvenRange(
              *Range, MemoryExpansionKind::LinearRegion, true,
              &PlanRejectReason);
      if (!Plan) {
        PrefixInfos[HeadPC] = PrefixInfo;
        RejectReasons[HeadPC] = mapPlanRejectReason(PlanRejectReason);
        HeadSelectionInfos[EntryPC] = HeadSelectionInfo;
        continue;
      }

      HeadSelectionInfo.SelectedNonEntryBlock = HeadPC != EntryPC;
      HeadSelectionInfos[EntryPC] = HeadSelectionInfo;
      PlansByHead[HeadPC] = *Plan;
      PrefixInfos[HeadPC] = PrefixInfo;
      recordGuaranteedEntries(Chain, Plan->RequiredMemorySize);
      for (size_t I = 1; I < Chain.size(); ++I) {
        AcceptedRegionBodies.insert(Chain[I]->EntryPC);
      }
    }
  }

  const MemoryAnalysisView &View;
  std::map<uint64_t, MemoryExpansionPlan> PlansByHead;
  std::map<uint64_t, uint64_t> GuaranteedEntryBytes;
  std::map<uint64_t, MemoryLinearRegionRejectReason> RejectReasons;
  std::map<uint64_t, MemoryLinearRegionPrefixInfo> PrefixInfos;
  std::map<uint64_t, MemoryLinearRegionHeadSelectionInfo> HeadSelectionInfos;
  std::set<uint64_t> AcceptedRegionBodies;
  std::set<uint64_t> ProcessedRegionHeads;
  std::set<uint64_t> DelegatedEmptyEntries;
};

// Facade used by lowering: tries consumer providers in priority order and
// returns only a MemoryExpansionPlan.
class MemoryExpansionPlanner final : public MemoryOptimizationPlanProvider {
public:
  explicit MemoryExpansionPlanner(const MemoryAnalysisView &View)
      : View(View), Prechecks(View), Grouping(View, Prechecks),
        LinearRegions(View), GuaranteedMinBytes(View.getFacts()),
        DeadStores(View.getFacts()), LoadForwarding(View.getFacts()) {}

  std::optional<MemoryExpansionPlan>
  buildMemoryExpansionPlan(uint64_t EntryPC,
                           uint64_t BodyEndPC) const override {
    LastDiagnostics.clear();
    LastDiagnostics.noteLinearRegionHeadSelection(
        LinearRegions.getHeadSelectionInfo(EntryPC));

    if (std::optional<MemoryExpansionPlan> LinearRegionPlan =
            LinearRegions.buildMemoryExpansionPlan(EntryPC, BodyEndPC)) {
      ++LastDiagnostics.LinearRegionCandidates;
      ++LastDiagnostics.LinearRegionAccepted;
      LastDiagnostics.noteLinearRegionPrefix(
          LinearRegions.getPrefixInfo(EntryPC), true);
      return LinearRegionPlan;
    }
    LastDiagnostics.noteLinearRegionPrefix(LinearRegions.getPrefixInfo(EntryPC),
                                           false);
    LastDiagnostics.noteLinearRegionReject(
        LinearRegions.getRejectReason(EntryPC));

    if (std::optional<SharedPrecheck> Shared =
            Grouping.getSharedPrecheck(EntryPC, BodyEndPC)) {
      ++LastDiagnostics.GroupingCandidates;
      MemoryExpansionPlanRejectReason Reason =
          MemoryExpansionPlanRejectReason::None;
      if (std::optional<MemoryExpansionPlan> GroupPlan =
              MemoryExpansionPlan::fromProvenRange(
                  Shared->Range, MemoryExpansionKind::ContiguousGroup, true,
                  &Reason)) {
        ++LastDiagnostics.GroupingAccepted;
        return GroupPlan;
      }
      LastDiagnostics.noteReject(Reason);
    } else {
      LastDiagnostics.noteReject(MemoryExpansionPlanRejectReason::NoCandidate);
    }

    if (std::optional<ProvenMemoryRange> Range =
            Prechecks.getBlockPrecheckRange(EntryPC, BodyEndPC)) {
      ++LastDiagnostics.PrecheckCandidates;
      MemoryExpansionPlanRejectReason Reason =
          MemoryExpansionPlanRejectReason::None;
      if (std::optional<MemoryExpansionPlan> PrecheckPlan =
              MemoryExpansionPlan::fromProvenRange(
                  *Range, MemoryExpansionKind::ProvenRange, true, &Reason)) {
        ++LastDiagnostics.PrecheckAccepted;
        return PrecheckPlan;
      }
      LastDiagnostics.noteReject(Reason);
    } else {
      LastDiagnostics.noteReject(MemoryExpansionPlanRejectReason::NoCandidate);
    }

    return std::nullopt;
  }

  const MemoryExpansionPlanDiagnostics &getLastDiagnostics() const {
    return LastDiagnostics;
  }

  uint64_t getGuaranteedMinBytesAtEntry(uint64_t EntryPC) const {
    return std::max(GuaranteedMinBytes.getGuaranteedMinBytesAtEntry(EntryPC),
                    LinearRegions.getGuaranteedMinBytesAtEntry(EntryPC));
  }

  uint64_t getGuaranteedMinBytesBeforeOp(uint64_t PC) const {
    for (const MemoryOp &Op : View.getFacts().Ops) {
      if (Op.Pc != PC) {
        continue;
      }
      return std::max(
          GuaranteedMinBytes.getGuaranteedMinBytesBeforeOp(Op.Id),
          LinearRegions.getGuaranteedMinBytesAtEntry(Op.BlockEntryPC));
    }
    return 0;
  }

  bool isDeadStore(uint64_t PC) const {
    for (const MemoryOp &Op : View.getFacts().Ops) {
      if (Op.Pc == PC) {
        return DeadStores.isDeadStore(Op.Id);
      }
    }
    return false;
  }

  std::optional<uint64_t> getForwardingStorePC(uint64_t LoadPC) const {
    for (const MemoryOp &Op : View.getFacts().Ops) {
      if (Op.Pc != LoadPC) {
        continue;
      }
      std::optional<uint32_t> StoreId =
          LoadForwarding.getReachingStoreId(Op.Id);
      if (!StoreId) {
        return std::nullopt;
      }
      const MemoryOp *Store = View.getOp(*StoreId);
      return Store == nullptr ? std::nullopt
                              : std::optional<uint64_t>(Store->Pc);
    }
    return std::nullopt;
  }

private:
  const MemoryAnalysisView &View;
  MemoryPrecheckConsumer Prechecks;
  MemoryGroupingConsumer Grouping;
  MemoryLinearRegionConsumer LinearRegions;
  MemoryGuaranteedMinBytesAnalysis GuaranteedMinBytes;
  MemoryDeadStoreAnalysis DeadStores;
  MemoryLoadForwardingAnalysis LoadForwarding;
  mutable MemoryExpansionPlanDiagnostics LastDiagnostics;
};

} // namespace COMPILER

#endif // COMPILER_EVM_FRONTEND_EVM_MEMORY_GROUPING_H
