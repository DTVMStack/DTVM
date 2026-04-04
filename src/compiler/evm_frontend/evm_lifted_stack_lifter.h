// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_LIFTED_STACK_LIFTER_H
#define EVM_FRONTEND_EVM_LIFTED_STACK_LIFTER_H

#include "compiler/evm_frontend/evm_analyzer.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

namespace COMPILER {

template <typename IRBuilder> class EVMLiftedStackLifter {
public:
  using Operand = typename IRBuilder::Operand;

  struct StackValueId {
    uint64_t Value = 0;

    bool operator==(const StackValueId &Other) const {
      return Value == Other.Value;
    }

    bool operator!=(const StackValueId &Other) const {
      return !(*this == Other);
    }
  };

  struct StackValue {
    StackValueId Id;
    Operand Value;
  };

  struct VirtualStackState {
    std::vector<StackValue> Slots;
  };

  struct EdgeState {
    uint64_t PredBlockPC = 0;
    VirtualStackState StackState;
  };

  struct PendingPhi {
    enum class ResolutionKind : uint8_t {
      Pending,
      Folded,
      RequiresMaterialization,
    };

    uint32_t SlotIndex = 0;
    std::map<uint64_t, StackValue> IncomingValues;
    std::map<uint64_t, Operand> IncomingPhiValues;
    ResolutionKind Resolution = ResolutionKind::Pending;
    bool IsComplete = false;
    StackValueId FoldedValueId = {};
  };

  struct MergeIncomingValue {
    uint64_t PredBlockPC;
    StackValueId ValueId;
    Operand Value;
  };

  struct MergeMaterializationRequest {
    uint64_t BlockPC;
    uint32_t SlotIndex;
    Operand MergeOperand;
    std::vector<uint64_t> ExpectedPredBlockPCs;
    std::vector<MergeIncomingValue> IncomingValues;
    typename PendingPhi::ResolutionKind Resolution =
        PendingPhi::ResolutionKind::Pending;
    bool IsComplete = false;
  };

  struct BlockEntryState {
    size_t EntryDepth = 0;
    std::vector<Operand> EntryOperands;
    std::vector<Operand> MergeOperands;
    std::map<uint64_t, EdgeState> IncomingStates;
    VirtualStackState ResolvedEntryState;
    std::vector<PendingPhi> PendingPhis;
    std::vector<uint64_t> PredecessorOrder;
    size_t ExpectedIncomingCount = 0;
  };

  explicit EVMLiftedStackLifter(IRBuilder &Builder) : Builder(Builder) {}

  void initialize(const EVMAnalyzer &Analyzer) {
    LiftedBlocks.clear();
    BlockEntryStates.clear();
    ValueIds.clear();
    NextValueId = 1;
    NextOpaqueValueId = 1;
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    for (const auto &[EntryPC, BlockInfo] : Analyzer.getBlockInfos()) {
      if (!BlockInfo.CanLiftStack) {
        continue;
      }
      LiftedBlocks.insert(EntryPC);
      auto &EntryState = BlockEntryStates[EntryPC];
      EntryState.PredecessorOrder =
          Analyzer.getPotentialEntryPredecessorsForBlock(EntryPC);
      EntryState.ExpectedIncomingCount = EntryState.PredecessorOrder.size();
      EntryState.EntryDepth =
          static_cast<size_t>(std::max(BlockInfo.FullEntryStateDepth, 0));
      if (BlockInfo.FullEntryStateDepth <= 0) {
        continue;
      }
      EntryState.EntryOperands.reserve(
          static_cast<size_t>(BlockInfo.FullEntryStateDepth));
      for (int32_t Depth = 0; Depth < BlockInfo.FullEntryStateDepth; ++Depth) {
        EntryState.EntryOperands.push_back(Builder.createStackEntryOperand());
      }
      EntryState.ResolvedEntryState =
          makeVirtualStackState(EntryState.EntryOperands);
      if (BlockInfo.RequiresEntryMergeState) {
        EntryState.MergeOperands.resize(EntryState.EntryDepth);
        EntryState.PendingPhis.reserve(EntryState.EntryDepth);
        for (size_t SlotIndex = 0; SlotIndex < EntryState.EntryDepth;
             ++SlotIndex) {
          EntryState.PendingPhis.push_back(
              PendingPhi{static_cast<uint32_t>(SlotIndex), {}, {}});
        }
      }
    }
#else
    (void)Analyzer;
#endif
  }

  bool isLiftedBlock(uint64_t BlockPC) const {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    return LiftedBlocks.count(BlockPC) != 0;
#else
    (void)BlockPC;
    return false;
#endif
  }

  const std::vector<Operand> *getEntryState(uint64_t BlockPC) const {
    const auto *EntryState = getBlockEntryState(BlockPC);
    if (!EntryState) {
      return nullptr;
    }
    return &EntryState->EntryOperands;
  }

  bool hasCompleteEntryState(uint64_t BlockPC) const {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    const auto *EntryState = getBlockEntryState(BlockPC);
    if (!EntryState) {
      return false;
    }
    if (EntryState->ExpectedIncomingCount == 0) {
      return true;
    }
    if (EntryState->IncomingStates.size() < EntryState->ExpectedIncomingCount) {
      return false;
    }
    for (const PendingPhi &Phi : EntryState->PendingPhis) {
      if (!Phi.IsComplete) {
        return false;
      }
    }
    return true;
#else
    (void)BlockPC;
    return false;
#endif
  }

  std::vector<Operand> getLogicalEntryState(uint64_t BlockPC) const {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    std::vector<Operand> LogicalState;
    const auto *EntryState = getBlockEntryState(BlockPC);
    if (!EntryState) {
      return LogicalState;
    }

    LogicalState = EntryState->EntryOperands;
    if (LogicalState.empty() && !EntryState->ResolvedEntryState.Slots.empty()) {
      LogicalState.reserve(EntryState->ResolvedEntryState.Slots.size());
      for (const StackValue &Slot : EntryState->ResolvedEntryState.Slots) {
        LogicalState.push_back(Slot.Value);
      }
    }
    for (const PendingPhi &Phi : EntryState->PendingPhis) {
      ZEN_ASSERT(Phi.SlotIndex < LogicalState.size());
      if (Phi.SlotIndex < EntryState->MergeOperands.size() &&
          !EntryState->MergeOperands[Phi.SlotIndex].isEmpty()) {
        LogicalState[Phi.SlotIndex] = EntryState->MergeOperands[Phi.SlotIndex];
        continue;
      }
      if (Phi.Resolution == PendingPhi::ResolutionKind::Folded &&
          Phi.IsComplete && !Phi.IncomingValues.empty()) {
        auto It = Phi.IncomingValues.begin();
        ZEN_ASSERT(It != Phi.IncomingValues.end());
        LogicalState[Phi.SlotIndex] = It->second.Value;
        continue;
      }
    }
    return LogicalState;
#else
    (void)BlockPC;
    return {};
#endif
  }

  std::vector<MergeMaterializationRequest>
  getMergeMaterializationRequests(uint64_t BlockPC) const {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    std::vector<MergeMaterializationRequest> Requests;
    const auto *EntryState = getBlockEntryState(BlockPC);
    if (!EntryState) {
      return Requests;
    }

    Requests.reserve(EntryState->PendingPhis.size());
    for (const PendingPhi &Phi : EntryState->PendingPhis) {
      if (Phi.IsComplete &&
          Phi.Resolution == PendingPhi::ResolutionKind::Folded) {
        continue;
      }

      ZEN_ASSERT(Phi.SlotIndex < EntryState->MergeOperands.size());
      MergeMaterializationRequest Request = {
          BlockPC,
          Phi.SlotIndex,
          EntryState->MergeOperands[Phi.SlotIndex],
          EntryState->PredecessorOrder,
          {},
          Phi.Resolution,
          Phi.IsComplete,
      };
      Request.IncomingValues.reserve(Phi.IncomingPhiValues.size());
      for (const auto &[PredBlockPC, IncomingValue] : Phi.IncomingValues) {
        auto PhiValueIt = Phi.IncomingPhiValues.find(PredBlockPC);
        ZEN_ASSERT(PhiValueIt != Phi.IncomingPhiValues.end());
        Request.IncomingValues.push_back(
            {PredBlockPC, IncomingValue.Id, PhiValueIt->second});
      }
      Requests.push_back(Request);
    }
    return Requests;
#else
    (void)BlockPC;
    return {};
#endif
  }

  const BlockEntryState *getBlockEntryState(uint64_t BlockPC) const {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    auto It = BlockEntryStates.find(BlockPC);
    if (It == BlockEntryStates.end()) {
      return nullptr;
    }
    return &It->second;
#else
    (void)BlockPC;
    return nullptr;
#endif
  }

  void assignEntryState(uint64_t PredBlockPC, uint64_t BlockPC,
                        const std::vector<Operand> &Values) {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    auto It = BlockEntryStates.find(BlockPC);
    if (It == BlockEntryStates.end()) {
      return;
    }
    auto &EntryState = It->second;
    ZEN_ASSERT(EntryState.EntryDepth == Values.size() &&
               "Lifted entry state size mismatch");
    VirtualStackState State = makeVirtualStackState(Values);
    EntryState.IncomingStates[PredBlockPC] = EdgeState{PredBlockPC, State};
    EntryState.ResolvedEntryState = State;
    for (size_t Index = 0; Index < EntryState.EntryDepth; ++Index) {
      if (Index < EntryState.PendingPhis.size()) {
        EntryState.PendingPhis[Index].IncomingValues[PredBlockPC] =
            State.Slots[Index];
        EntryState.PendingPhis[Index].IncomingPhiValues[PredBlockPC] =
            prepareStackPhiIncomingCompat(Values[Index]);
        updatePendingPhi(EntryState.PendingPhis[Index],
                         EntryState.ExpectedIncomingCount);
      }
      if (Index < EntryState.MergeOperands.size()) {
        if (!EntryState.MergeOperands[Index].isEmpty()) {
          assignStackMergeOperandCompat(
              EntryState.MergeOperands[Index], PredBlockPC,
              EntryState.PendingPhis[Index].IncomingPhiValues[PredBlockPC]);
        }
      } else if (Index < EntryState.EntryOperands.size()) {
        Builder.assignStackEntryOperand(EntryState.EntryOperands[Index],
                                        Values[Index]);
      }
    }
#else
    (void)PredBlockPC;
    (void)BlockPC;
    (void)Values;
#endif
  }

  void assignMergeOperand(uint64_t BlockPC, uint32_t SlotIndex,
                          const Operand &MergeOperand) {
#ifdef ZEN_ENABLE_EVM_STACK_SSA_LIFT
    auto It = BlockEntryStates.find(BlockPC);
    if (It == BlockEntryStates.end()) {
      return;
    }
    auto &EntryState = It->second;
    ZEN_ASSERT(SlotIndex < EntryState.MergeOperands.size());
    EntryState.MergeOperands[SlotIndex] = MergeOperand;
#else
    (void)BlockPC;
    (void)SlotIndex;
    (void)MergeOperand;
#endif
  }

private:
  template <typename T, typename = void>
  struct HasGetInstr : std::false_type {};
  template <typename T>
  struct HasGetInstr<
      T, std::void_t<decltype(std::declval<const T &>().getInstr())>>
      : std::true_type {};

  template <typename T, typename = void> struct HasGetVar : std::false_type {};
  template <typename T>
  struct HasGetVar<T, std::void_t<decltype(std::declval<const T &>().getVar())>>
      : std::true_type {};

  template <typename T, typename = void>
  struct HasGetU256VarComponents : std::false_type {};
  template <typename T>
  struct HasGetU256VarComponents<
      T,
      std::void_t<decltype(std::declval<const T &>().getU256VarComponents())>>
      : std::true_type {};

  template <typename T, typename = void>
  struct HasPrepareStackPhiIncoming : std::false_type {};
  template <typename T>
  struct HasPrepareStackPhiIncoming<
      T, std::void_t<decltype(std::declval<T &>().prepareStackPhiIncoming(
             std::declval<const Operand &>()))>> : std::true_type {};

  template <typename T, typename = void>
  struct HasAssignStackMergeOperand : std::false_type {};
  template <typename T>
  struct HasAssignStackMergeOperand<
      T, std::void_t<decltype(std::declval<T &>().assignStackMergeOperand(
             std::declval<const Operand &>(), uint64_t{},
             std::declval<const Operand &>()))>> : std::true_type {};

  Operand prepareStackPhiIncomingCompat(const Operand &Value) {
    if constexpr (HasPrepareStackPhiIncoming<IRBuilder>::value) {
      return Builder.prepareStackPhiIncoming(Value);
    } else {
      return Value;
    }
  }

  void assignStackMergeOperandCompat(const Operand &Dest, uint64_t PredBlockPC,
                                     const Operand &Value) {
    if constexpr (HasAssignStackMergeOperand<IRBuilder>::value) {
      Builder.assignStackMergeOperand(Dest, PredBlockPC, Value);
    } else {
      (void)PredBlockPC;
      Builder.assignStackEntryOperand(Dest, Value);
    }
  }

  static void appendPointerKey(std::string &Key, const void *Ptr) {
    Key += std::to_string(reinterpret_cast<uintptr_t>(Ptr));
  }

  std::string getOperandIdentityKey(const Operand &Value) {
    if (Value.isConstant()) {
      const auto &ConstValue = Value.getConstValue();
      std::string Key = "const";
      for (uint64_t Word : ConstValue) {
        Key += ':';
        Key += std::to_string(Word);
      }
      return Key;
    }

    if constexpr (HasGetInstr<Operand>::value) {
      if (auto *Instr = Value.getInstr()) {
        std::string Key = "instr:";
        appendPointerKey(Key, Instr);
        return Key;
      }
    }

    if constexpr (HasGetVar<Operand>::value) {
      if (auto *Var = Value.getVar()) {
        std::string Key = "var:";
        appendPointerKey(Key, Var);
        return Key;
      }
    }

    if constexpr (HasGetU256VarComponents<Operand>::value) {
      const auto &VarComponents = Value.getU256VarComponents();
      std::string Key = "u256vars";
      for (const auto *Var : VarComponents) {
        Key += ':';
        appendPointerKey(Key, Var);
      }
      return Key;
    }

    std::string Key = "opaque:";
    Key += std::to_string(NextOpaqueValueId++);
    return Key;
  }

  StackValueId getOrCreateStackValueId(const Operand &Value) {
    const std::string Key = getOperandIdentityKey(Value);
    auto It = ValueIds.find(Key);
    if (It != ValueIds.end()) {
      return StackValueId{It->second};
    }
    const uint64_t NewId = NextValueId++;
    ValueIds.emplace(Key, NewId);
    return StackValueId{NewId};
  }

  void updatePendingPhi(PendingPhi &Phi, size_t ExpectedIncomingCount) {
    Phi.IsComplete = ExpectedIncomingCount > 0 &&
                     Phi.IncomingValues.size() >= ExpectedIncomingCount;
    Phi.FoldedValueId = {};
    if (!Phi.IsComplete) {
      Phi.Resolution = PendingPhi::ResolutionKind::Pending;
      return;
    }

    auto It = Phi.IncomingValues.begin();
    ZEN_ASSERT(It != Phi.IncomingValues.end());
    StackValueId CandidateId = It->second.Id;
    ++It;
    for (; It != Phi.IncomingValues.end(); ++It) {
      if (It->second.Id != CandidateId) {
        Phi.Resolution = PendingPhi::ResolutionKind::RequiresMaterialization;
        return;
      }
    }

    Phi.Resolution = PendingPhi::ResolutionKind::Folded;
    Phi.FoldedValueId = CandidateId;
  }

  VirtualStackState makeVirtualStackState(const std::vector<Operand> &Values) {
    VirtualStackState State;
    State.Slots.reserve(Values.size());
    for (const Operand &Value : Values) {
      State.Slots.push_back(StackValue{getOrCreateStackValueId(Value), Value});
    }
    return State;
  }

  IRBuilder &Builder;
  std::set<uint64_t> LiftedBlocks;
  std::map<uint64_t, BlockEntryState> BlockEntryStates;
  std::map<std::string, uint64_t> ValueIds;
  uint64_t NextValueId = 1;
  uint64_t NextOpaqueValueId = 1;
};

} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_LIFTED_STACK_LIFTER_H
