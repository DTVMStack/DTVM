// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_EVM_FRONTEND_EVM_MEMORY_PRECHECK_H
#define COMPILER_EVM_FRONTEND_EVM_MEMORY_PRECHECK_H

#include "compiler/evm_frontend/evm_memory_analysis.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

namespace COMPILER {

// Consumer proof: describes a proven memory interval. It intentionally does
// not encode how lowering should emit expansion, gas, or base reloads.
struct ProvenMemoryRange {
  uint64_t EntryPC = 0;
  uint64_t FirstOpPC = 0;
  uint64_t LastOpPC = 0;
  uint64_t CoveredOpCount = 0;
  std::vector<uint32_t> CoveredOpIds;
  MemoryInterval Interval;

  bool getKnownEndOffset(uint64_t &EndOffset) const {
    if (!Interval.Addr.isKnown() ||
        Interval.Addr.Kind != AddressBaseKind::Const || !Interval.Size.Known ||
        Interval.Addr.Offset < 0) {
      return false;
    }
    const uint64_t Begin = static_cast<uint64_t>(Interval.Addr.Offset);
    if (Interval.Size.Value > std::numeric_limits<uint64_t>::max() - Begin) {
      return false;
    }
    EndOffset = Begin + Interval.Size.Value;
    return true;
  }
};

enum class MemoryExpansionKind : uint8_t {
  ProvenRange,
  ContiguousGroup,
  LinearRegion
};

enum class MemoryExpansionPlanRejectReason : uint8_t {
  None,
  NoCandidate,
  UnknownInterval,
  InvalidRange,
  Overflow,
  TooLarge,
  ZeroSize,
  Unprofitable
};

enum class MemoryLinearRegionRejectReason : uint8_t {
  None,
  NotStraightLine,
  BranchingHead,
  MergeSuccessor,
  BackedgeOrNonForward,
  HardBarrier,
  NoHeadMemoryOp,
  UnknownInterval,
  NonDirectMemoryOp,
  TooFewOps,
  Unprofitable,
  BarrierMSize,
  BarrierGas,
  BarrierCall,
  BarrierCreate,
  BarrierReturn,
  BarrierRevert,
  BarrierLog,
  BarrierStorage,
  BarrierSelfDestruct,
  BarrierInvalid,
  BarrierUnknownEffect,
  BarrierEscape
};

enum class MemoryLinearRegionPrefixStopReason : uint8_t {
  None,
  TerminalAfterSafePrefix,
  BranchingAfterSafePrefix,
  MergeAfterSafePrefix,
  MissingSuccessorBlock,
  BackedgeAfterSafePrefix,
  BarrierAfterSafePrefix
};

struct MemoryLinearRegionPrefixInfo {
  uint64_t Blocks = 0;
  uint64_t Ops = 0;
  MemoryLinearRegionPrefixStopReason StopReason =
      MemoryLinearRegionPrefixStopReason::None;
};

struct MemoryLinearRegionHeadSelectionInfo {
  uint64_t CandidateBlocks = 0;
  uint64_t SkippedEmptyBlocks = 0;
  bool SelectedNonEntryBlock = false;
  bool RejectedPredecessorNotStraight = false;
  bool RejectedHeadNotDominatingChain = false;
  // A B-local precheck does not require an incoming memory-size guarantee.
  // Keep this bit for future plan forms that do require one.
  bool RejectedEntryGuaranteeMissing = false;
};

// Stable consumer plan: describes the memory expansion coverage required by a
// consumer, independent of how the Builder lowers it.
struct MemoryExpansionPlan {
  static constexpr uint64_t MaxRequiredMemorySize = 128ull * 1024ull * 1024ull;

  MemoryExpansionKind ExpansionKind = MemoryExpansionKind::ProvenRange;
  uint64_t FirstOpPC = 0;
  uint64_t LastOpPC = 0;
  uint64_t CoveredOps = 0;
  std::vector<uint32_t> CoveredOpIds;
  MemoryInterval RequiredInterval;
  uint64_t RequiredMemorySize = 0;
  bool Reusable = true;
  uint64_t EstimatedReducedExpansions = 0;

  bool coversPC(uint64_t PC) const { return FirstOpPC <= PC && PC <= LastOpPC; }

  static uint64_t
  getEstimatedReducedExpansions(uint64_t CoveredOps,
                                uint64_t PlanExpansionCount = 1) {
    return CoveredOps > PlanExpansionCount ? CoveredOps - PlanExpansionCount
                                           : 0;
  }

  static bool
  validateProvenRange(const ProvenMemoryRange &Range,
                      uint64_t &RequiredMemorySize,
                      MemoryExpansionPlanRejectReason *RejectReason = nullptr) {
    auto Reject = [RejectReason](MemoryExpansionPlanRejectReason Reason) {
      if (RejectReason != nullptr) {
        *RejectReason = Reason;
      }
      return false;
    };

    if (!Range.Interval.Size.Known || !Range.Interval.Addr.isKnown() ||
        Range.Interval.Addr.Kind != AddressBaseKind::Const) {
      return Reject(MemoryExpansionPlanRejectReason::UnknownInterval);
    }
    if (Range.Interval.Empty || Range.Interval.Size.Value == 0) {
      return Reject(MemoryExpansionPlanRejectReason::ZeroSize);
    }
    if (Range.Interval.Space != AddressSpace::Memory ||
        Range.Interval.Addr.Offset < 0) {
      return Reject(MemoryExpansionPlanRejectReason::InvalidRange);
    }
    if (!Range.getKnownEndOffset(RequiredMemorySize)) {
      return Reject(MemoryExpansionPlanRejectReason::Overflow);
    }
    const uint64_t Begin = static_cast<uint64_t>(Range.Interval.Addr.Offset);
    if (RequiredMemorySize < Begin) {
      return Reject(MemoryExpansionPlanRejectReason::InvalidRange);
    }
    if (RequiredMemorySize > MaxRequiredMemorySize) {
      return Reject(MemoryExpansionPlanRejectReason::TooLarge);
    }
    if (RejectReason != nullptr) {
      *RejectReason = MemoryExpansionPlanRejectReason::None;
    }
    return true;
  }

  static bool isProfitable(const ProvenMemoryRange &Range,
                           MemoryExpansionKind Kind) {
    const uint64_t EstimatedReducedExpansions =
        getEstimatedReducedExpansions(Range.CoveredOpCount);
    switch (Kind) {
    case MemoryExpansionKind::ContiguousGroup:
    case MemoryExpansionKind::LinearRegion:
      return Range.CoveredOpCount >= 2 && EstimatedReducedExpansions >= 1;
    case MemoryExpansionKind::ProvenRange:
      return Range.CoveredOpCount >= 2 && EstimatedReducedExpansions >= 1;
    }
    return false;
  }

  static std::optional<MemoryExpansionPlan>
  fromProvenRange(const ProvenMemoryRange &Range, MemoryExpansionKind Kind,
                  bool Reusable = true,
                  MemoryExpansionPlanRejectReason *RejectReason = nullptr) {
    uint64_t RequiredMemorySize = 0;
    if (!validateProvenRange(Range, RequiredMemorySize, RejectReason)) {
      return std::nullopt;
    }
    if (!isProfitable(Range, Kind)) {
      if (RejectReason != nullptr) {
        *RejectReason = MemoryExpansionPlanRejectReason::Unprofitable;
      }
      return std::nullopt;
    }

    MemoryExpansionPlan Plan;
    Plan.ExpansionKind = Kind;
    Plan.FirstOpPC = Range.FirstOpPC;
    Plan.LastOpPC = Range.LastOpPC;
    Plan.CoveredOps = Range.CoveredOpCount;
    Plan.CoveredOpIds = Range.CoveredOpIds;
    Plan.RequiredInterval = Range.Interval;
    Plan.RequiredMemorySize = RequiredMemorySize;
    Plan.Reusable = Reusable;
    Plan.EstimatedReducedExpansions =
        getEstimatedReducedExpansions(Range.CoveredOpCount);
    return Plan;
  }
};

struct MemoryExpansionPlanDiagnostics {
  uint64_t GroupingCandidates = 0;
  uint64_t LinearRegionCandidates = 0;
  uint64_t PrecheckCandidates = 0;
  uint64_t GroupingAccepted = 0;
  uint64_t LinearRegionAccepted = 0;
  uint64_t PrecheckAccepted = 0;
  uint64_t RejectedNoCandidate = 0;
  uint64_t RejectedUnknownInterval = 0;
  uint64_t RejectedInvalidRange = 0;
  uint64_t RejectedOverflow = 0;
  uint64_t RejectedTooLarge = 0;
  uint64_t RejectedZeroSize = 0;
  uint64_t RejectedUnprofitable = 0;
  uint64_t LinearRegionRejectedNotStraightLine = 0;
  uint64_t LinearRegionRejectedBranchingHead = 0;
  uint64_t LinearRegionRejectedMergeSuccessor = 0;
  uint64_t LinearRegionRejectedBackedgeOrNonForward = 0;
  uint64_t LinearRegionRejectedHardBarrier = 0;
  uint64_t LinearRegionRejectedNoHeadMemoryOp = 0;
  uint64_t LinearRegionRejectedUnknownInterval = 0;
  uint64_t LinearRegionRejectedNonDirectMemoryOp = 0;
  uint64_t LinearRegionRejectedTooFewOps = 0;
  uint64_t LinearRegionRejectedUnprofitable = 0;
  uint64_t LinearRegionRejectedBarrierMSize = 0;
  uint64_t LinearRegionRejectedBarrierGas = 0;
  uint64_t LinearRegionRejectedBarrierCall = 0;
  uint64_t LinearRegionRejectedBarrierCreate = 0;
  uint64_t LinearRegionRejectedBarrierReturn = 0;
  uint64_t LinearRegionRejectedBarrierRevert = 0;
  uint64_t LinearRegionRejectedBarrierLog = 0;
  uint64_t LinearRegionRejectedBarrierStorage = 0;
  uint64_t LinearRegionRejectedBarrierSelfDestruct = 0;
  uint64_t LinearRegionRejectedBarrierInvalid = 0;
  uint64_t LinearRegionRejectedBarrierUnknownEffect = 0;
  uint64_t LinearRegionRejectedBarrierEscape = 0;
  uint64_t LinearRegionPrefixCandidateBlocks = 0;
  uint64_t LinearRegionPrefixCandidateOps = 0;
  uint64_t LinearRegionPrefixAcceptedBlocks = 0;
  uint64_t LinearRegionPrefixAcceptedOps = 0;
  uint64_t LinearRegionPrefixRejectedTooShort = 0;
  uint64_t LinearRegionPrefixRejectedNoHeadMemoryOp = 0;
  uint64_t LinearRegionPrefixBranchingAfterSafePrefix = 0;
  uint64_t LinearRegionPrefixMergeAfterSafePrefix = 0;
  uint64_t LinearRegionPrefixTerminalAfterSafePrefix = 0;
  uint64_t LinearRegionPrefixMissingSuccessorBlock = 0;
  uint64_t LinearRegionPrefixBackedgeAfterSafePrefix = 0;
  uint64_t LinearRegionPrefixBarrierAfterSafePrefix = 0;
  uint64_t LinearRegionRejectedBranchingHeadNoSafePrefix = 0;
  uint64_t LinearRegionRejectedMergeSuccessorNoSafePrefix = 0;
  uint64_t LinearRegionHeadCandidateBlocks = 0;
  uint64_t LinearRegionHeadSkippedEmptyBlocks = 0;
  uint64_t LinearRegionHeadSelectedNonEntryBlock = 0;
  uint64_t LinearRegionHeadRejectedPredecessorNotStraight = 0;
  uint64_t LinearRegionHeadRejectedHeadNotDominatingChain = 0;
  uint64_t LinearRegionHeadRejectedEntryGuaranteeMissing = 0;

  void clear() { *this = MemoryExpansionPlanDiagnostics(); }

  void noteReject(MemoryExpansionPlanRejectReason Reason) {
    switch (Reason) {
    case MemoryExpansionPlanRejectReason::None:
      break;
    case MemoryExpansionPlanRejectReason::NoCandidate:
      ++RejectedNoCandidate;
      break;
    case MemoryExpansionPlanRejectReason::UnknownInterval:
      ++RejectedUnknownInterval;
      break;
    case MemoryExpansionPlanRejectReason::InvalidRange:
      ++RejectedInvalidRange;
      break;
    case MemoryExpansionPlanRejectReason::Overflow:
      ++RejectedOverflow;
      break;
    case MemoryExpansionPlanRejectReason::TooLarge:
      ++RejectedTooLarge;
      break;
    case MemoryExpansionPlanRejectReason::ZeroSize:
      ++RejectedZeroSize;
      break;
    case MemoryExpansionPlanRejectReason::Unprofitable:
      ++RejectedUnprofitable;
      break;
    }
  }

  void noteLinearRegionReject(MemoryLinearRegionRejectReason Reason) {
    switch (Reason) {
    case MemoryLinearRegionRejectReason::None:
      break;
    case MemoryLinearRegionRejectReason::NotStraightLine:
      ++LinearRegionRejectedNotStraightLine;
      break;
    case MemoryLinearRegionRejectReason::BranchingHead:
      ++LinearRegionRejectedBranchingHead;
      ++LinearRegionRejectedBranchingHeadNoSafePrefix;
      break;
    case MemoryLinearRegionRejectReason::MergeSuccessor:
      ++LinearRegionRejectedMergeSuccessor;
      ++LinearRegionRejectedMergeSuccessorNoSafePrefix;
      break;
    case MemoryLinearRegionRejectReason::BackedgeOrNonForward:
      ++LinearRegionRejectedBackedgeOrNonForward;
      break;
    case MemoryLinearRegionRejectReason::HardBarrier:
      ++LinearRegionRejectedHardBarrier;
      break;
    case MemoryLinearRegionRejectReason::NoHeadMemoryOp:
      ++LinearRegionRejectedNoHeadMemoryOp;
      ++LinearRegionPrefixRejectedNoHeadMemoryOp;
      break;
    case MemoryLinearRegionRejectReason::UnknownInterval:
      ++LinearRegionRejectedUnknownInterval;
      break;
    case MemoryLinearRegionRejectReason::NonDirectMemoryOp:
      ++LinearRegionRejectedNonDirectMemoryOp;
      break;
    case MemoryLinearRegionRejectReason::TooFewOps:
      ++LinearRegionRejectedTooFewOps;
      ++LinearRegionPrefixRejectedTooShort;
      break;
    case MemoryLinearRegionRejectReason::Unprofitable:
      ++LinearRegionRejectedUnprofitable;
      break;
    case MemoryLinearRegionRejectReason::BarrierMSize:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierMSize;
      break;
    case MemoryLinearRegionRejectReason::BarrierGas:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierGas;
      break;
    case MemoryLinearRegionRejectReason::BarrierCall:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierCall;
      break;
    case MemoryLinearRegionRejectReason::BarrierCreate:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierCreate;
      break;
    case MemoryLinearRegionRejectReason::BarrierReturn:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierReturn;
      break;
    case MemoryLinearRegionRejectReason::BarrierRevert:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierRevert;
      break;
    case MemoryLinearRegionRejectReason::BarrierLog:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierLog;
      break;
    case MemoryLinearRegionRejectReason::BarrierStorage:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierStorage;
      break;
    case MemoryLinearRegionRejectReason::BarrierSelfDestruct:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierSelfDestruct;
      break;
    case MemoryLinearRegionRejectReason::BarrierInvalid:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierInvalid;
      break;
    case MemoryLinearRegionRejectReason::BarrierUnknownEffect:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierUnknownEffect;
      break;
    case MemoryLinearRegionRejectReason::BarrierEscape:
      ++LinearRegionRejectedHardBarrier;
      ++LinearRegionRejectedBarrierEscape;
      break;
    }
  }

  void noteLinearRegionPrefix(const MemoryLinearRegionPrefixInfo &Info,
                              bool Accepted) {
    if (Info.Blocks == 0) {
      return;
    }
    LinearRegionPrefixCandidateBlocks += Info.Blocks;
    LinearRegionPrefixCandidateOps += Info.Ops;
    if (Accepted) {
      LinearRegionPrefixAcceptedBlocks += Info.Blocks;
      LinearRegionPrefixAcceptedOps += Info.Ops;
    } else if (Info.Blocks < 2) {
      ++LinearRegionPrefixRejectedTooShort;
    }

    if (Info.Blocks < 2) {
      return;
    }

    switch (Info.StopReason) {
    case MemoryLinearRegionPrefixStopReason::None:
      break;
    case MemoryLinearRegionPrefixStopReason::TerminalAfterSafePrefix:
      ++LinearRegionPrefixTerminalAfterSafePrefix;
      break;
    case MemoryLinearRegionPrefixStopReason::BranchingAfterSafePrefix:
      ++LinearRegionPrefixBranchingAfterSafePrefix;
      break;
    case MemoryLinearRegionPrefixStopReason::MergeAfterSafePrefix:
      ++LinearRegionPrefixMergeAfterSafePrefix;
      break;
    case MemoryLinearRegionPrefixStopReason::MissingSuccessorBlock:
      ++LinearRegionPrefixMissingSuccessorBlock;
      break;
    case MemoryLinearRegionPrefixStopReason::BackedgeAfterSafePrefix:
      ++LinearRegionPrefixBackedgeAfterSafePrefix;
      break;
    case MemoryLinearRegionPrefixStopReason::BarrierAfterSafePrefix:
      ++LinearRegionPrefixBarrierAfterSafePrefix;
      break;
    }
  }

  void noteLinearRegionHeadSelection(
      const MemoryLinearRegionHeadSelectionInfo &Info) {
    LinearRegionHeadCandidateBlocks += Info.CandidateBlocks;
    LinearRegionHeadSkippedEmptyBlocks += Info.SkippedEmptyBlocks;
    LinearRegionHeadSelectedNonEntryBlock += Info.SelectedNonEntryBlock;
    LinearRegionHeadRejectedPredecessorNotStraight +=
        Info.RejectedPredecessorNotStraight;
    LinearRegionHeadRejectedHeadNotDominatingChain +=
        Info.RejectedHeadNotDominatingChain;
    LinearRegionHeadRejectedEntryGuaranteeMissing +=
        Info.RejectedEntryGuaranteeMissing;
  }
};

// Common consumer interface for memory optimization plan providers. Phase 3.5
// only exposes expansion plans; future consumers can implement separate plan
// types without changing Facts or Inference.
class MemoryOptimizationPlanProvider {
public:
  virtual ~MemoryOptimizationPlanProvider() = default;

  virtual std::optional<MemoryExpansionPlan>
  buildMemoryExpansionPlan(uint64_t EntryPC, uint64_t BodyEndPC) const = 0;
};

// Consumer: turns analysis query results into precheck proofs. It does not emit
// MIR and does not choose a lowering strategy.
class MemoryPrecheckConsumer final : public MemoryOptimizationPlanProvider {
public:
  explicit MemoryPrecheckConsumer(const MemoryAnalysisView &View)
      : View(View) {}

  std::optional<MemoryExpansionPlan>
  buildMemoryExpansionPlan(uint64_t EntryPC,
                           uint64_t BodyEndPC) const override {
    std::optional<ProvenMemoryRange> Range =
        getBlockPrecheckRange(EntryPC, BodyEndPC);
    if (!Range) {
      return std::nullopt;
    }
    return MemoryExpansionPlan::fromProvenRange(
        *Range, MemoryExpansionKind::ProvenRange);
  }

  std::optional<ProvenMemoryRange>
  getOpPrecheckRange(uint64_t EntryPC, const MemoryOp &Op) const {
    MemoryInterval Interval;
    if (!getMemoryExpansionInterval(Op, Interval)) {
      return std::nullopt;
    }

    ProvenMemoryRange Proof;
    Proof.EntryPC = EntryPC;
    Proof.FirstOpPC = Op.Pc;
    Proof.LastOpPC = Op.Pc;
    Proof.CoveredOpCount = 1;
    Proof.CoveredOpIds.push_back(Op.Id);
    Proof.Interval = Interval;
    return Proof;
  }

  std::optional<ProvenMemoryRange>
  getBlockPrecheckRange(uint64_t EntryPC, uint64_t BodyEndPC) const {
    ProvenMemoryRange Current;
    ProvenMemoryRange Best;
    Current.EntryPC = EntryPC;
    Best.EntryPC = EntryPC;

    auto FinishWindow = [&]() {
      if (Current.CoveredOpCount >= 2 &&
          Current.CoveredOpCount > Best.CoveredOpCount) {
        Best = Current;
      }
      Current = ProvenMemoryRange();
      Current.EntryPC = EntryPC;
    };

    for (const MemoryOp &Op : View.getFacts().Ops) {
      if (Op.Pc < EntryPC) {
        continue;
      }
      if (Op.Pc >= BodyEndPC) {
        break;
      }

      const MemoryInterval *Interval = getDirectMemoryInterval(Op);
      if (Interval == nullptr) {
        if (View.getBarrierKind(Op) != MemoryBarrierKind::None) {
          FinishWindow();
        }
        continue;
      }

      uint64_t End = 0;
      if (!getIntervalEnd(*Interval, End)) {
        FinishWindow();
        continue;
      }
      if (Current.CoveredOpCount == 0) {
        Current.FirstOpPC = Op.Pc;
        Current.Interval.Space = AddressSpace::Memory;
        Current.Interval.Addr = AddressExpr::constant(0);
      }
      Current.LastOpPC = Op.Pc;
      ++Current.CoveredOpCount;
      Current.CoveredOpIds.push_back(Op.Id);
      Current.Interval.Size =
          SizeExpr::constant(std::max(Current.Interval.Size.Value, End));
      Current.Interval.Empty = Current.Interval.Size.Value == 0;
    }
    FinishWindow();

    if (Best.CoveredOpCount < 2) {
      return std::nullopt;
    }
    return Best;
  }

private:
  static bool getMemoryExpansionInterval(const MemoryOp &Op,
                                         MemoryInterval &Result) {
    switch (Op.Kind) {
    case MemoryOpKind::MStore:
    case MemoryOpKind::MStore8:
      if (Op.Writes.size() != 1 || !isKnownMemoryInterval(Op.Writes[0])) {
        return false;
      }
      Result = Op.Writes[0];
      return true;
    case MemoryOpKind::MLoad:
      if (Op.Reads.size() != 1 || !isKnownMemoryInterval(Op.Reads[0])) {
        return false;
      }
      Result = Op.Reads[0];
      return true;
    case MemoryOpKind::MCopy:
      return getUnionMemoryInterval(Op, Result);
    default:
      return false;
    }
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

  static bool isKnownMemoryInterval(const MemoryInterval &Interval) {
    uint64_t End = 0;
    return getIntervalEnd(Interval, End);
  }

  static bool mergeBounds(const MemoryInterval &Interval, bool &HasBounds,
                          uint64_t &Begin, uint64_t &End) {
    uint64_t IntervalEnd = 0;
    if (!getIntervalEnd(Interval, IntervalEnd)) {
      return false;
    }
    const uint64_t IntervalBegin = static_cast<uint64_t>(Interval.Addr.Offset);
    if (!HasBounds) {
      Begin = IntervalBegin;
      End = IntervalEnd;
      HasBounds = true;
      return true;
    }
    Begin = std::min(Begin, IntervalBegin);
    End = std::max(End, IntervalEnd);
    return true;
  }

  static bool getUnionMemoryInterval(const MemoryOp &Op,
                                     MemoryInterval &Result) {
    bool HasBounds = false;
    uint64_t Begin = 0;
    uint64_t End = 0;
    for (const MemoryInterval &Read : Op.Reads) {
      if (!mergeBounds(Read, HasBounds, Begin, End)) {
        return false;
      }
    }
    for (const MemoryInterval &Write : Op.Writes) {
      if (!mergeBounds(Write, HasBounds, Begin, End)) {
        return false;
      }
    }
    if (!HasBounds || End < Begin) {
      return false;
    }

    Result.Space = AddressSpace::Memory;
    Result.Addr = AddressExpr::constant(Begin);
    Result.Size = SizeExpr::constant(End - Begin);
    Result.Empty = Begin == End;
    return true;
  }

  static bool getIntervalEnd(const MemoryInterval &Interval, uint64_t &End) {
    if (Interval.Space != AddressSpace::Memory || Interval.Empty ||
        !Interval.Addr.isKnown() ||
        Interval.Addr.Kind != AddressBaseKind::Const || !Interval.Size.Known ||
        Interval.Addr.Offset < 0) {
      return false;
    }
    const uint64_t Begin = static_cast<uint64_t>(Interval.Addr.Offset);
    if (Interval.Size.Value > std::numeric_limits<uint64_t>::max() - Begin) {
      return false;
    }
    End = Begin + Interval.Size.Value;
    return true;
  }

  const MemoryAnalysisView &View;
};

} // namespace COMPILER

#endif // COMPILER_EVM_FRONTEND_EVM_MEMORY_PRECHECK_H
