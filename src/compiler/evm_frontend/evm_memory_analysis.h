// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef COMPILER_EVM_FRONTEND_EVM_MEMORY_ANALYSIS_H
#define COMPILER_EVM_FRONTEND_EVM_MEMORY_ANALYSIS_H

#include "compiler/evm_frontend/evm_analyzer.h"
#include "compiler/evm_frontend/evm_memory_facts.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <queue>
#include <set>
#include <vector>

namespace COMPILER {

// Inference: normalized memory barrier category for a MemoryOp. This is not a
// lowering decision; consumers decide how to use the barrier.
enum class MemoryBarrierKind : uint8_t {
  None,
  Read,
  Write,
  ReadWrite,
  Escape,
  MemorySizeObserver,
  GasSensitive,
  Unknown
};

enum class MemoryAliasResult : uint8_t {
  NoAlias,
  MustAlias,
  PartialAlias,
  MayAlias
};

enum class IntervalRelationKind : uint8_t { Unknown, Disjoint, Equal, Overlap };

struct MemoryIntervalBounds {
  AddressBaseKind BaseKind = AddressBaseKind::Unknown;
  uint64_t Const = 0;
  uint32_t ValueId = 0;
  int64_t MinBegin = 0;
  int64_t MaxBegin = 0;
  int64_t MinEnd = 0;
  int64_t MaxEnd = 0;
  bool Exact = false;
};

// Inference: derives exact or conservative bounded relations between intervals.
class IntervalRelation {
public:
  static IntervalRelationKind compare(const MemoryInterval &LHS,
                                      const MemoryInterval &RHS) {
    if (LHS.Empty || RHS.Empty) {
      return IntervalRelationKind::Disjoint;
    }
    if (LHS.Space != RHS.Space) {
      if (LHS.Space == AddressSpace::Unknown ||
          RHS.Space == AddressSpace::Unknown) {
        return IntervalRelationKind::Unknown;
      }
      return IntervalRelationKind::Disjoint;
    }

    std::optional<MemoryIntervalBounds> LHSBounds = getBounds(LHS);
    std::optional<MemoryIntervalBounds> RHSBounds = getBounds(RHS);
    if (!LHSBounds || !RHSBounds || !sameBase(*LHSBounds, *RHSBounds)) {
      return IntervalRelationKind::Unknown;
    }

    if (LHSBounds->MaxEnd <= RHSBounds->MinBegin ||
        RHSBounds->MaxEnd <= LHSBounds->MinBegin) {
      return IntervalRelationKind::Disjoint;
    }
    if (LHSBounds->Exact && RHSBounds->Exact &&
        LHSBounds->MinBegin == RHSBounds->MinBegin &&
        LHSBounds->MinEnd == RHSBounds->MinEnd) {
      return IntervalRelationKind::Equal;
    }
    if (LHSBounds->Exact && RHSBounds->Exact) {
      return IntervalRelationKind::Overlap;
    }
    return IntervalRelationKind::Unknown;
  }

  static bool isKnownDisjoint(const MemoryInterval &LHS,
                              const MemoryInterval &RHS) {
    return compare(LHS, RHS) == IntervalRelationKind::Disjoint;
  }

  static bool contains(const MemoryInterval &Container,
                       const MemoryInterval &Contained) {
    if (Container.Space != Contained.Space ||
        Container.Space == AddressSpace::Unknown) {
      return false;
    }
    std::optional<MemoryIntervalBounds> ContainerBounds = getBounds(Container);
    std::optional<MemoryIntervalBounds> ContainedBounds = getBounds(Contained);
    return ContainerBounds && ContainedBounds &&
           sameBase(*ContainerBounds, *ContainedBounds) &&
           ContainerBounds->MinBegin <= ContainedBounds->MinBegin &&
           ContainerBounds->MaxEnd >= ContainedBounds->MaxEnd;
  }

  static std::optional<MemoryIntervalBounds>
  getBounds(const MemoryInterval &Interval) {
    if (!Interval.Addr.hasBounds() || !Interval.Size.hasBounds()) {
      return std::nullopt;
    }
    if (Interval.Addr.MinOffset < 0 || Interval.Addr.MaxOffset < 0) {
      return std::nullopt;
    }
    if (Interval.Size.MaxValue >
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
      return std::nullopt;
    }

    const int64_t MinSize = static_cast<int64_t>(Interval.Size.MinValue);
    const int64_t MaxSize = static_cast<int64_t>(Interval.Size.MaxValue);
    if (Interval.Addr.MinOffset >
            std::numeric_limits<int64_t>::max() - MinSize ||
        Interval.Addr.MaxOffset >
            std::numeric_limits<int64_t>::max() - MaxSize) {
      return std::nullopt;
    }

    MemoryIntervalBounds Result;
    Result.BaseKind = Interval.Addr.Kind;
    Result.Const = Interval.Addr.Const;
    Result.ValueId = Interval.Addr.ValueId;
    Result.MinBegin = Interval.Addr.MinOffset;
    Result.MaxBegin = Interval.Addr.MaxOffset;
    Result.MinEnd = Result.MinBegin + MinSize;
    Result.MaxEnd = Result.MaxBegin + MaxSize;
    Result.Exact = Interval.Addr.Exact && Interval.Size.Known;
    return Result;
  }

private:
  static bool sameBase(const MemoryIntervalBounds &LHS,
                       const MemoryIntervalBounds &RHS) {
    if (LHS.BaseKind != RHS.BaseKind) {
      return false;
    }
    switch (LHS.BaseKind) {
    case AddressBaseKind::Const:
      return LHS.Const == RHS.Const;
    case AddressBaseKind::StackValue:
      return LHS.ValueId == RHS.ValueId;
    case AddressBaseKind::Unknown:
      return false;
    }
    return false;
  }
};

// Inference: classifies each MemoryOp as a barrier. It only consumes
// MemoryFacts and never emits MIR or runtime helpers.
class BarrierAnalysis {
public:
  explicit BarrierAnalysis(const MemoryFacts &Facts) : Facts(Facts) {}

  MemoryBarrierKind getBarrierKind(const MemoryOp &Op) const {
    switch (Op.Effect) {
    case MemoryEffect::None:
      break;
    case MemoryEffect::Read:
      return MemoryBarrierKind::Read;
    case MemoryEffect::Write:
      return MemoryBarrierKind::Write;
    case MemoryEffect::ReadWrite:
      return MemoryBarrierKind::ReadWrite;
    case MemoryEffect::Escape:
      return MemoryBarrierKind::Escape;
    case MemoryEffect::MemorySizeObserver:
      return MemoryBarrierKind::MemorySizeObserver;
    case MemoryEffect::GasSensitive:
      return MemoryBarrierKind::GasSensitive;
    case MemoryEffect::Unknown:
      return MemoryBarrierKind::Unknown;
    }

    const bool HasReads = !Op.Reads.empty();
    const bool HasWrites = !Op.Writes.empty();
    if (HasReads && HasWrites) {
      return MemoryBarrierKind::ReadWrite;
    }
    if (HasReads) {
      return MemoryBarrierKind::Read;
    }
    if (HasWrites) {
      return MemoryBarrierKind::Write;
    }
    return MemoryBarrierKind::None;
  }

  MemoryBarrierKind getBarrierKind(uint32_t OpId) const {
    const MemoryOp *Op = findOp(OpId);
    return Op ? getBarrierKind(*Op) : MemoryBarrierKind::Unknown;
  }

  bool isBarrier(const MemoryOp &Op) const {
    return getBarrierKind(Op) != MemoryBarrierKind::None;
  }

private:
  const MemoryOp *findOp(uint32_t OpId) const {
    for (const MemoryOp &Op : Facts.Ops) {
      if (Op.Id == OpId) {
        return &Op;
      }
    }
    return nullptr;
  }

  const MemoryFacts &Facts;
};

// Inference: conservative alias query API over MemoryIntervals and MemoryOps.
class AliasAnalysis {
public:
  explicit AliasAnalysis(const MemoryFacts &Facts) : Facts(Facts) {}

  MemoryAliasResult alias(const MemoryInterval &LHS,
                          const MemoryInterval &RHS) const {
    switch (IntervalRelation::compare(LHS, RHS)) {
    case IntervalRelationKind::Disjoint:
      return MemoryAliasResult::NoAlias;
    case IntervalRelationKind::Equal:
      return MemoryAliasResult::MustAlias;
    case IntervalRelationKind::Overlap:
      return MemoryAliasResult::PartialAlias;
    case IntervalRelationKind::Unknown:
      return MemoryAliasResult::MayAlias;
    }
    return MemoryAliasResult::MayAlias;
  }

  MemoryAliasResult alias(const MemoryOp &LHS, const MemoryOp &RHS) const {
    MemoryAliasResult Result = MemoryAliasResult::NoAlias;
    for (const MemoryInterval &LHSInterval : LHS.Reads) {
      Result = mergeAliasResult(Result, aliasAny(LHSInterval, RHS));
    }
    for (const MemoryInterval &LHSInterval : LHS.Writes) {
      Result = mergeAliasResult(Result, aliasAny(LHSInterval, RHS));
    }
    return Result;
  }

private:
  static MemoryAliasResult mergeAliasResult(MemoryAliasResult LHS,
                                            MemoryAliasResult RHS) {
    if (LHS == MemoryAliasResult::MayAlias ||
        RHS == MemoryAliasResult::MayAlias) {
      return MemoryAliasResult::MayAlias;
    }
    if (LHS == MemoryAliasResult::NoAlias) {
      return RHS;
    }
    if (RHS == MemoryAliasResult::NoAlias) {
      return LHS;
    }
    return LHS == RHS ? LHS : MemoryAliasResult::MayAlias;
  }

  MemoryAliasResult aliasAny(const MemoryInterval &Interval,
                             const MemoryOp &Op) const {
    MemoryAliasResult Result = MemoryAliasResult::NoAlias;
    for (const MemoryInterval &Other : Op.Reads) {
      Result = mergeAliasResult(Result, alias(Interval, Other));
    }
    for (const MemoryInterval &Other : Op.Writes) {
      Result = mergeAliasResult(Result, alias(Interval, Other));
    }
    return Result;
  }

  const MemoryFacts &Facts;
};

// Inference: bounded ordered clobber queries. The first version intentionally
// scans only within one analyzer block; consumers may compose it with an
// already-proven straight-line region without changing the alias rules.
class MemoryClobberAnalysis {
public:
  explicit MemoryClobberAnalysis(const MemoryFacts &Facts)
      : Facts(Facts), Barriers(Facts), Aliases(Facts) {}

  bool hasMayAliasRead(uint32_t BeginOpId, uint32_t EndOpId,
                       const MemoryInterval &Location) const {
    return hasClobber(BeginOpId, EndOpId, Location, true);
  }

  bool hasMayAliasWrite(uint32_t BeginOpId, uint32_t EndOpId,
                        const MemoryInterval &Location) const {
    return hasClobber(BeginOpId, EndOpId, Location, false);
  }

  const MemoryOp *findReachingMustAliasStore(const MemoryOp &Load) const {
    if (Load.Reads.size() != 1) {
      return nullptr;
    }
    const size_t LoadIndex = findIndex(Load.Id);
    if (LoadIndex == Facts.Ops.size()) {
      return nullptr;
    }

    for (size_t I = LoadIndex; I-- > 0;) {
      const MemoryOp &Op = Facts.Ops[I];
      if (Op.BlockEntryPC != Load.BlockEntryPC || isHardBarrier(Op)) {
        return nullptr;
      }
      for (const MemoryInterval &Write : Op.Writes) {
        const MemoryAliasResult Result = Aliases.alias(Write, Load.Reads[0]);
        if (Result == MemoryAliasResult::MustAlias) {
          return Op.Kind == MemoryOpKind::MStore ? &Op : nullptr;
        }
        if (Result != MemoryAliasResult::NoAlias) {
          return nullptr;
        }
      }
    }
    return nullptr;
  }

  const MemoryOp *findOverwritingMustAliasStore(const MemoryOp &Store) const {
    if (Store.Writes.size() != 1) {
      return nullptr;
    }
    const size_t StoreIndex = findIndex(Store.Id);
    if (StoreIndex == Facts.Ops.size()) {
      return nullptr;
    }

    for (size_t I = StoreIndex + 1; I < Facts.Ops.size(); ++I) {
      const MemoryOp &Op = Facts.Ops[I];
      if (Op.BlockEntryPC != Store.BlockEntryPC || isHardBarrier(Op)) {
        return nullptr;
      }
      for (const MemoryInterval &Read : Op.Reads) {
        if (Aliases.alias(Read, Store.Writes[0]) !=
            MemoryAliasResult::NoAlias) {
          return nullptr;
        }
      }
      for (const MemoryInterval &Write : Op.Writes) {
        const MemoryAliasResult Result = Aliases.alias(Write, Store.Writes[0]);
        if (Result == MemoryAliasResult::MustAlias) {
          return Op.Kind == Store.Kind ? &Op : nullptr;
        }
        if (Result != MemoryAliasResult::NoAlias) {
          return nullptr;
        }
      }
    }
    return nullptr;
  }

private:
  static bool isHardBarrierKind(MemoryBarrierKind Kind) {
    return Kind == MemoryBarrierKind::Escape ||
           Kind == MemoryBarrierKind::MemorySizeObserver ||
           Kind == MemoryBarrierKind::GasSensitive ||
           Kind == MemoryBarrierKind::Unknown;
  }

  bool isHardBarrier(const MemoryOp &Op) const {
    return isHardBarrierKind(Barriers.getBarrierKind(Op));
  }

  size_t findIndex(uint32_t OpId) const {
    for (size_t I = 0; I < Facts.Ops.size(); ++I) {
      if (Facts.Ops[I].Id == OpId) {
        return I;
      }
    }
    return Facts.Ops.size();
  }

  bool hasClobber(uint32_t BeginOpId, uint32_t EndOpId,
                  const MemoryInterval &Location, bool Reads) const {
    const size_t Begin = findIndex(BeginOpId);
    const size_t End = findIndex(EndOpId);
    if (Begin == Facts.Ops.size() || End == Facts.Ops.size() || Begin >= End) {
      return true;
    }
    const uint64_t BlockEntryPC = Facts.Ops[Begin].BlockEntryPC;
    if (Facts.Ops[End].BlockEntryPC != BlockEntryPC) {
      return true;
    }

    for (size_t I = Begin + 1; I < End; ++I) {
      const MemoryOp &Op = Facts.Ops[I];
      if (Op.BlockEntryPC != BlockEntryPC || isHardBarrier(Op)) {
        return true;
      }
      const std::vector<MemoryInterval> &Intervals =
          Reads ? Op.Reads : Op.Writes;
      for (const MemoryInterval &Interval : Intervals) {
        if (Aliases.alias(Location, Interval) != MemoryAliasResult::NoAlias) {
          return true;
        }
      }
    }
    return false;
  }

  const MemoryFacts &Facts;
  BarrierAnalysis Barriers;
  AliasAnalysis Aliases;
};

// Consumer-ready proof set for stores whose write is fully overwritten before
// any possible observation. Expansion and gas at the original opcode remain.
class MemoryDeadStoreAnalysis {
public:
  explicit MemoryDeadStoreAnalysis(const MemoryFacts &Facts) : Clobbers(Facts) {
    for (const MemoryOp &Op : Facts.Ops) {
      if (Op.Kind != MemoryOpKind::MStore && Op.Kind != MemoryOpKind::MStore8) {
        continue;
      }
      if (Clobbers.findOverwritingMustAliasStore(Op) != nullptr) {
        DeadStoreIds.insert(Op.Id);
      }
    }
  }

  bool isDeadStore(uint32_t OpId) const {
    return DeadStoreIds.count(OpId) != 0;
  }

private:
  MemoryClobberAnalysis Clobbers;
  std::set<uint32_t> DeadStoreIds;
};

class MemoryLoadForwardingAnalysis {
public:
  explicit MemoryLoadForwardingAnalysis(const MemoryFacts &Facts)
      : Clobbers(Facts) {
    for (const MemoryOp &Op : Facts.Ops) {
      if (Op.Kind != MemoryOpKind::MLoad) {
        continue;
      }
      const MemoryOp *Store = Clobbers.findReachingMustAliasStore(Op);
      if (Store != nullptr) {
        ReachingStoreIds[Op.Id] = Store->Id;
      }
    }
  }

  std::optional<uint32_t> getReachingStoreId(uint32_t LoadOpId) const {
    auto It = ReachingStoreIds.find(LoadOpId);
    if (It == ReachingStoreIds.end()) {
      return std::nullopt;
    }
    return It->second;
  }

private:
  MemoryClobberAnalysis Clobbers;
  std::map<uint32_t, uint32_t> ReachingStoreIds;
};

// Inference facade: the only public entry point intended for consumers. It
// keeps analysis internals private and exposes query APIs over MemoryFacts.
class MemoryAnalysisView {
public:
  explicit MemoryAnalysisView(const MemoryFacts &Facts)
      : Facts(Facts), Barriers(Facts), Aliases(Facts), Clobbers(Facts) {}

  const MemoryFacts &getFacts() const { return Facts; }

  const MemoryOp *getOp(uint32_t OpId) const {
    for (const MemoryOp &Op : Facts.Ops) {
      if (Op.Id == OpId) {
        return &Op;
      }
    }
    return nullptr;
  }

  MemoryBarrierKind getBarrierKind(const MemoryOp &Op) const {
    return Barriers.getBarrierKind(Op);
  }

  MemoryBarrierKind getBarrierKind(uint32_t OpId) const {
    return Barriers.getBarrierKind(OpId);
  }

  bool isBarrier(const MemoryOp &Op) const { return Barriers.isBarrier(Op); }

  IntervalRelationKind getIntervalRelation(const MemoryInterval &LHS,
                                           const MemoryInterval &RHS) const {
    return IntervalRelation::compare(LHS, RHS);
  }

  MemoryAliasResult alias(const MemoryInterval &LHS,
                          const MemoryInterval &RHS) const {
    return Aliases.alias(LHS, RHS);
  }

  MemoryAliasResult alias(const MemoryOp &LHS, const MemoryOp &RHS) const {
    return Aliases.alias(LHS, RHS);
  }

  bool hasMayAliasRead(uint32_t BeginOpId, uint32_t EndOpId,
                       const MemoryInterval &Location) const {
    return Clobbers.hasMayAliasRead(BeginOpId, EndOpId, Location);
  }

  bool hasMayAliasWrite(uint32_t BeginOpId, uint32_t EndOpId,
                        const MemoryInterval &Location) const {
    return Clobbers.hasMayAliasWrite(BeginOpId, EndOpId, Location);
  }

  const MemoryOp *findReachingMustAliasStore(const MemoryOp &Load) const {
    return Clobbers.findReachingMustAliasStore(Load);
  }

  const MemoryOp *findOverwritingMustAliasStore(const MemoryOp &Store) const {
    return Clobbers.findOverwritingMustAliasStore(Store);
  }

private:
  const MemoryFacts &Facts;
  BarrierAnalysis Barriers;
  AliasAnalysis Aliases;
  MemoryClobberAnalysis Clobbers;
};

class MemoryEntryAddressAnalysis {
public:
  using EntryValues = std::vector<MemoryEntryValue>;

  MemoryEntryAddressAnalysis(const EVMAnalyzer &Analyzer,
                             const uint8_t *Bytecode, size_t BytecodeSize) {
    run(Analyzer, Bytecode, BytecodeSize);
  }

  EntryValues getEntryValues(uint64_t EntryPC, uint32_t EntryDepth) const {
    auto It = Entries.find(EntryPC);
    if (It == Entries.end() || !It->second.Initialized ||
        It->second.Values.size() != EntryDepth) {
      return EntryValues(EntryDepth, MemoryEntryValue::unknown());
    }
    return It->second.Values;
  }

private:
  struct BlockState {
    bool Initialized = false;
    EntryValues Values;
  };

  static MemoryEntryValue meetValue(const MemoryEntryValue &LHS,
                                    const MemoryEntryValue &RHS) {
    if (LHS.ConstKnown && RHS.ConstKnown && LHS.ConstValue == RHS.ConstValue) {
      return LHS;
    }
    return MemoryEntryValue::unknown();
  }

  static MemoryEntryValue pop(EntryValues &Stack) {
    if (Stack.empty()) {
      return MemoryEntryValue::unknown();
    }
    MemoryEntryValue Value = Stack.back();
    Stack.pop_back();
    return Value;
  }

  static MemoryEntryValue peek(const EntryValues &Stack, size_t IndexFromTop) {
    if (Stack.size() <= IndexFromTop) {
      return MemoryEntryValue::unknown();
    }
    return Stack[Stack.size() - 1 - IndexFromTop];
  }

  static void popN(EntryValues &Stack, size_t Count) {
    while (Count-- != 0) {
      (void)pop(Stack);
    }
  }

  static uint64_t readPushU64(const uint8_t *Bytecode, size_t BytecodeSize,
                              size_t Start, size_t Size, bool &Known) {
    Known = false;
    if (Size > 8 || Start + Size > BytecodeSize) {
      return 0;
    }
    uint64_t Value = 0;
    for (size_t I = 0; I < Size; ++I) {
      Value = (Value << 8) | Bytecode[Start + I];
    }
    Known = true;
    return Value;
  }

  void applyTransferForBlock(const EVMAnalyzer::BlockInfo &Info,
                             const uint8_t *Bytecode, size_t BytecodeSize,
                             EntryValues &Stack) const {
    size_t PC = Info.BodyStartPC;
    const size_t EndPC = std::min<size_t>(Info.BodyEndPC, BytecodeSize);

    while (PC < EndPC) {
      const evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
      if (InstructionNames[Opcode] == nullptr) {
        return;
      }

      if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
        const size_t Size =
            static_cast<size_t>(Opcode) - static_cast<size_t>(OP_PUSH0);
        bool Known = false;
        uint64_t Value =
            readPushU64(Bytecode, BytecodeSize, PC + 1, Size, Known);
        Stack.push_back(Known ? MemoryEntryValue::constant(Value)
                              : MemoryEntryValue::unknown());
        PC += 1 + Size;
        continue;
      }

      if (Opcode >= OP_DUP1 && Opcode <= OP_DUP16) {
        const size_t Index =
            static_cast<size_t>(Opcode) - static_cast<size_t>(OP_DUP1);
        Stack.push_back(peek(Stack, Index));
        ++PC;
        continue;
      }

      if (Opcode >= OP_SWAP1 && Opcode <= OP_SWAP16) {
        const size_t Index =
            static_cast<size_t>(Opcode) - static_cast<size_t>(OP_SWAP1) + 1;
        if (Stack.size() > Index) {
          std::swap(Stack.back(), Stack[Stack.size() - 1 - Index]);
        }
        ++PC;
        continue;
      }

      if (Opcode >= OP_LOG0 && Opcode <= OP_LOG4) {
        popN(Stack, 2 + static_cast<size_t>(Opcode - OP_LOG0));
        ++PC;
        continue;
      }

      switch (Opcode) {
      case OP_ADD: {
        MemoryEntryValue A = pop(Stack);
        MemoryEntryValue B = pop(Stack);
        if (A.ConstKnown && B.ConstKnown &&
            A.ConstValue <=
                std::numeric_limits<uint64_t>::max() - B.ConstValue) {
          Stack.push_back(
              MemoryEntryValue::constant(A.ConstValue + B.ConstValue));
        } else {
          Stack.push_back(MemoryEntryValue::unknown());
        }
        break;
      }
      case OP_SUB: {
        MemoryEntryValue Subtrahend = pop(Stack);
        MemoryEntryValue Minuend = pop(Stack);
        if (Subtrahend.ConstKnown && Minuend.ConstKnown &&
            Minuend.ConstValue >= Subtrahend.ConstValue) {
          Stack.push_back(MemoryEntryValue::constant(Minuend.ConstValue -
                                                     Subtrahend.ConstValue));
        } else {
          Stack.push_back(MemoryEntryValue::unknown());
        }
        break;
      }
      case OP_POP:
        (void)pop(Stack);
        break;
      case OP_JUMP:
        popN(Stack, 1);
        return;
      case OP_JUMPI:
        popN(Stack, 2);
        return;
      case OP_STOP:
      case OP_RETURN:
      case OP_REVERT:
      case OP_SELFDESTRUCT:
      case OP_INVALID:
        return;
      default: {
        const auto &Metric = InstructionMetrics[static_cast<uint8_t>(Opcode)];
        const int PopCount = Metric.stack_height_required;
        const int PushCount = PopCount + Metric.stack_height_change;
        if (PopCount > 0) {
          popN(Stack, static_cast<size_t>(PopCount));
        }
        for (int I = 0; I < PushCount; ++I) {
          Stack.push_back(MemoryEntryValue::unknown());
        }
        break;
      }
      }

      ++PC;
    }
  }

  void run(const EVMAnalyzer &Analyzer, const uint8_t *Bytecode,
           size_t BytecodeSize) {
    InstructionMetrics =
        evmc_get_instruction_metrics_table(Analyzer.getRevision());
    if (!InstructionMetrics) {
      InstructionMetrics =
          evmc_get_instruction_metrics_table(zen::evm::DEFAULT_REVISION);
    }
    InstructionNames = evmc_get_instruction_names_table(Analyzer.getRevision());
    if (!InstructionNames) {
      InstructionNames =
          evmc_get_instruction_names_table(zen::evm::DEFAULT_REVISION);
    }

    const auto &Blocks = Analyzer.getBlockInfos();
    std::queue<uint64_t> WorkList;
    std::map<uint64_t, bool> InQueue;

    for (const auto &[EntryPC, Info] : Blocks) {
      const uint32_t Depth =
          Info.ResolvedEntryStackDepth >= 0
              ? static_cast<uint32_t>(Info.ResolvedEntryStackDepth)
              : 0;
      BlockState &State = Entries[EntryPC];
      if (Info.ResolvedEntryStackDepth < 0 || Info.HasInconsistentEntryDepth ||
          Info.HasUndefinedInstr || Info.IsDynamicJumpTargetCandidate) {
        State.Initialized = true;
        State.Values.assign(Depth, MemoryEntryValue::unknown());
      } else if (Info.Predecessors.empty()) {
        State.Initialized = true;
        State.Values.assign(Depth, MemoryEntryValue::unknown());
      }
      if (State.Initialized) {
        WorkList.push(EntryPC);
        InQueue[EntryPC] = true;
      }
    }

    while (!WorkList.empty()) {
      const uint64_t EntryPC = WorkList.front();
      WorkList.pop();
      InQueue[EntryPC] = false;

      auto BlockIt = Blocks.find(EntryPC);
      auto StateIt = Entries.find(EntryPC);
      if (BlockIt == Blocks.end() || StateIt == Entries.end() ||
          !StateIt->second.Initialized) {
        continue;
      }

      const EVMAnalyzer::BlockInfo &Info = BlockIt->second;
      if (Info.ResolvedEntryStackDepth < 0 || Info.HasInconsistentEntryDepth ||
          Info.HasUndefinedInstr || Info.HasDynamicJump) {
        continue;
      }

      EntryValues ExitStack = StateIt->second.Values;
      applyTransferForBlock(Info, Bytecode, BytecodeSize, ExitStack);

      for (uint64_t SuccPC : Info.Successors) {
        auto SuccIt = Blocks.find(SuccPC);
        if (SuccIt == Blocks.end()) {
          continue;
        }
        const EVMAnalyzer::BlockInfo &SuccInfo = SuccIt->second;
        if (SuccInfo.ResolvedEntryStackDepth < 0 ||
            SuccInfo.HasInconsistentEntryDepth) {
          continue;
        }
        const size_t SuccDepth =
            static_cast<size_t>(SuccInfo.ResolvedEntryStackDepth);
        if (ExitStack.size() != SuccDepth) {
          continue;
        }

        BlockState &SuccState = Entries[SuccPC];
        bool Changed = false;
        if (!SuccState.Initialized) {
          SuccState.Initialized = true;
          SuccState.Values = ExitStack;
          Changed = true;
        } else {
          if (SuccState.Values.size() != SuccDepth) {
            SuccState.Values.assign(SuccDepth, MemoryEntryValue::unknown());
            Changed = true;
          }
          for (size_t I = 0; I < SuccDepth; ++I) {
            MemoryEntryValue NewValue =
                meetValue(SuccState.Values[I], ExitStack[I]);
            if (NewValue.ConstKnown != SuccState.Values[I].ConstKnown ||
                NewValue.ConstValue != SuccState.Values[I].ConstValue) {
              SuccState.Values[I] = NewValue;
              Changed = true;
            }
          }
        }

        if (Changed && !InQueue[SuccPC]) {
          WorkList.push(SuccPC);
          InQueue[SuccPC] = true;
        }
      }
    }
  }

  std::map<uint64_t, BlockState> Entries;
  const evmc_instruction_metrics *InstructionMetrics = nullptr;
  const char *const *InstructionNames = nullptr;
};

class MemoryGuaranteedMinBytesAnalysis {
public:
  explicit MemoryGuaranteedMinBytesAnalysis(const MemoryFacts &Facts)
      : Facts(Facts) {
    run();
  }

  uint64_t getGuaranteedMinBytesAtEntry(uint64_t EntryPC) const {
    auto It = EntryBytes.find(EntryPC);
    return It == EntryBytes.end() ? 0 : It->second;
  }

  uint64_t getGuaranteedMinBytesBeforeOp(uint32_t OpId) const {
    auto It = BeforeOpBytes.find(OpId);
    return It == BeforeOpBytes.end() ? 0 : It->second;
  }

private:
  static bool isHardBarrier(const MemoryOp &Op) {
    switch (Op.Kind) {
    case MemoryOpKind::Log:
    case MemoryOpKind::Call:
    case MemoryOpKind::Create:
    case MemoryOpKind::Return:
    case MemoryOpKind::Revert:
    case MemoryOpKind::MSize:
    case MemoryOpKind::Gas:
      return true;
    default:
      break;
    }

    return Op.Effect == MemoryEffect::Escape ||
           Op.Effect == MemoryEffect::MemorySizeObserver ||
           Op.Effect == MemoryEffect::GasSensitive ||
           Op.Effect == MemoryEffect::Unknown;
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

  static bool getDirectRequiredBytes(const MemoryOp &Op, uint64_t &End) {
    switch (Op.Kind) {
    case MemoryOpKind::MLoad:
      return Op.Reads.size() == 1 && getIntervalEnd(Op.Reads[0], End);
    case MemoryOpKind::MStore:
    case MemoryOpKind::MStore8:
      return Op.Writes.size() == 1 && getIntervalEnd(Op.Writes[0], End);
    case MemoryOpKind::MCopy: {
      if (Op.Reads.size() != 1 || Op.Writes.size() != 1) {
        return false;
      }
      uint64_t ReadEnd = 0;
      uint64_t WriteEnd = 0;
      if (!getIntervalEnd(Op.Reads[0], ReadEnd) ||
          !getIntervalEnd(Op.Writes[0], WriteEnd)) {
        return false;
      }
      End = std::max(ReadEnd, WriteEnd);
      return true;
    }
    default:
      return false;
    }
  }

  uint64_t transfer(const MemoryBlockFacts &Block,
                    uint64_t EntryBytesValue) const {
    uint64_t Current = EntryBytesValue;
    for (size_t I = Block.OpsBegin; I < Block.OpsEnd && I < Facts.Ops.size();
         ++I) {
      const MemoryOp &Op = Facts.Ops[I];
      if (isHardBarrier(Op)) {
        return Current;
      }
      uint64_t RequiredBytes = 0;
      if (getDirectRequiredBytes(Op, RequiredBytes)) {
        Current = std::max(Current, RequiredBytes);
      }
    }
    return Current;
  }

  void recordBeforeOpBytes(const MemoryBlockFacts &Block,
                           uint64_t EntryBytesValue) {
    uint64_t Current = EntryBytesValue;
    bool SeenBarrier = false;
    for (size_t I = Block.OpsBegin; I < Block.OpsEnd && I < Facts.Ops.size();
         ++I) {
      const MemoryOp &Op = Facts.Ops[I];
      BeforeOpBytes[Op.Id] = Current;
      if (isHardBarrier(Op)) {
        SeenBarrier = true;
        continue;
      }
      if (SeenBarrier) {
        continue;
      }
      uint64_t RequiredBytes = 0;
      if (getDirectRequiredBytes(Op, RequiredBytes)) {
        Current = std::max(Current, RequiredBytes);
      }
    }
  }

  uint64_t computeEntryFromPredecessors(const MemoryBlockFacts &Block) const {
    if (Block.Predecessors.empty()) {
      return 0;
    }
    uint64_t Result = std::numeric_limits<uint64_t>::max();
    for (uint64_t PredPC : Block.Predecessors) {
      auto PredExitIt = ExitBytes.find(PredPC);
      const uint64_t PredExit =
          PredExitIt == ExitBytes.end() ? 0 : PredExitIt->second;
      Result = std::min(Result, PredExit);
    }
    return Result == std::numeric_limits<uint64_t>::max() ? 0 : Result;
  }

  void run() {
    std::queue<uint64_t> WorkList;
    std::map<uint64_t, bool> InQueue;
    for (const auto &[EntryPC, Block] : Facts.Blocks) {
      (void)Block;
      EntryBytes[EntryPC] = 0;
      ExitBytes[EntryPC] = 0;
      WorkList.push(EntryPC);
      InQueue[EntryPC] = true;
    }

    while (!WorkList.empty()) {
      const uint64_t EntryPC = WorkList.front();
      WorkList.pop();
      InQueue[EntryPC] = false;

      auto BlockIt = Facts.Blocks.find(EntryPC);
      if (BlockIt == Facts.Blocks.end()) {
        continue;
      }
      const MemoryBlockFacts &Block = BlockIt->second;
      const uint64_t NewEntry = computeEntryFromPredecessors(Block);
      EntryBytes[EntryPC] = NewEntry;
      const uint64_t NewExit = transfer(Block, NewEntry);
      if (NewExit == ExitBytes[EntryPC]) {
        continue;
      }
      ExitBytes[EntryPC] = NewExit;

      for (uint64_t SuccPC : Block.Successors) {
        if (Facts.Blocks.find(SuccPC) == Facts.Blocks.end()) {
          continue;
        }
        if (!InQueue[SuccPC]) {
          WorkList.push(SuccPC);
          InQueue[SuccPC] = true;
        }
      }
    }

    for (const auto &[EntryPC, Block] : Facts.Blocks) {
      recordBeforeOpBytes(Block, getGuaranteedMinBytesAtEntry(EntryPC));
    }
  }

  const MemoryFacts &Facts;
  std::map<uint64_t, uint64_t> EntryBytes;
  std::map<uint64_t, uint64_t> ExitBytes;
  std::map<uint32_t, uint64_t> BeforeOpBytes;
};

} // namespace COMPILER

#endif // COMPILER_EVM_FRONTEND_EVM_MEMORY_ANALYSIS_H
