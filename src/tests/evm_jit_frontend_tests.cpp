// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/evm_bytecode_visitor.h"
#include "compiler/evm_frontend/evm_analyzer.h"
#include "compiler/evm_frontend/evm_memory_analysis.h"
#include "compiler/evm_frontend/evm_memory_facts.h"
#include "compiler/evm_frontend/evm_memory_grouping.h"
#include "compiler/evm_frontend/evm_memory_precheck.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/mir/module.h"
#include "compiler/mir/pass/verifier.h"

#include "llvm/Support/raw_ostream.h"
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

using COMPILER::EVMAnalyzer;
using COMPILER::EVMMirBuilder;
using COMPILER::EVMValueRange;
using zen::common::BinaryOperator;
using zen::common::CompareOperator;

EVMAnalyzer analyzeBytecode(const std::vector<uint8_t> &Bytecode) {
  EVMAnalyzer Analyzer(EVMC_CANCUN);
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  Analyzer.analyze(Data, Bytecode.size());
  return Analyzer;
}

EVMAnalyzer
analyzeSuitabilityOnlyBytecode(const std::vector<uint8_t> &Bytecode) {
  EVMAnalyzer Analyzer(EVMC_CANCUN);
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  Analyzer.analyzeSuitabilityOnly(Data, Bytecode.size());
  return Analyzer;
}

bool verifyMirForBytecode(const std::vector<uint8_t> &Bytecode,
                          bool EnableGasMetering, std::string *VerifierOutput) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setGasMeteringEnabled(EnableGasMetering);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  COMPILER::MModule Mod(Ctx);
  std::array<COMPILER::MType *, 1> ParamTypes = {
      COMPILER::MPointerType::create(Ctx, Ctx.VoidType)};
  COMPILER::MFunctionType *FuncType = COMPILER::MFunctionType::create(
      Ctx, Ctx.VoidType, llvm::ArrayRef<COMPILER::MType *>(ParamTypes));
  Mod.addFuncType(FuncType);

  COMPILER::MFunction Func(Ctx, 0);
  Func.setFunctionType(FuncType);
  EVMMirBuilder Builder(Ctx, Func);
  if (!Builder.compile(&Ctx)) {
    if (VerifierOutput) {
      *VerifierOutput = "EVM frontend compile failed";
    }
    return false;
  }

  std::string Output;
  llvm::raw_string_ostream OS(Output);
  COMPILER::MVerifier Verifier(Mod, Func, OS);
  const bool Ok = Verifier.verify();
  OS.flush();
  if (VerifierOutput) {
    *VerifierOutput = Output;
  }
  return Ok;
}

const EVMAnalyzer::BlockInfo *findBlock(const EVMAnalyzer &Analyzer,
                                        uint64_t EntryPC) {
  const auto &Blocks = Analyzer.getBlockInfos();
  auto It = Blocks.find(EntryPC);
  if (It == Blocks.end()) {
    return nullptr;
  }
  return &It->second;
}

class MirBuilderConstFoldHarness {
public:
  MirBuilderConstFoldHarness() : Func(Ctx, 0), Builder(Ctx, Func) {
    Ctx.setRevision(EVMC_OSAKA);
    Ctx.setBytecode(nullptr, 0);

    std::array<COMPILER::MType *, 1> ParamTypes = {
        COMPILER::MPointerType::create(Ctx, Ctx.VoidType)};
    Func.setFunctionType(COMPILER::MFunctionType::create(
        Ctx, Ctx.VoidType, llvm::ArrayRef<COMPILER::MType *>(ParamTypes)));
    Builder.initEVM(&Ctx);
  }

  ~MirBuilderConstFoldHarness() { Builder.finalizeEVMBase(); }

  COMPILER::EVMFrontendContext Ctx;
  COMPILER::MFunction Func;
  EVMMirBuilder Builder;
};

void expectPCList(const std::vector<uint64_t> &Actual,
                  std::initializer_list<uint64_t> Expected) {
  ASSERT_EQ(Actual.size(), Expected.size());
  size_t Index = 0;
  for (uint64_t ExpectedPC : Expected) {
    EXPECT_EQ(Actual[Index], ExpectedPC) << "mismatch at index " << Index;
    ++Index;
  }
}

void appendPushU64(std::vector<uint8_t> &Bytecode, uint64_t Value) {
  if (Value == 0) {
    Bytecode.push_back(OP_PUSH0);
    return;
  }

  uint8_t Bytes = 0;
  uint64_t Tmp = Value;
  while (Tmp != 0) {
    ++Bytes;
    Tmp >>= 8;
  }
  Bytecode.push_back(static_cast<uint8_t>(OP_PUSH0) + Bytes);
  for (int Shift = static_cast<int>(Bytes) - 1; Shift >= 0; --Shift) {
    Bytecode.push_back(static_cast<uint8_t>((Value >> (Shift * 8)) & 0xff));
  }
}

std::vector<uint8_t> makeLargeStaticConstMStoreBlock(uint64_t Ops) {
  std::vector<uint8_t> Bytecode;
  for (uint64_t I = 0; I < Ops; ++I) {
    appendPushU64(Bytecode, I + 1);
    appendPushU64(Bytecode, I * 32);
    Bytecode.push_back(OP_MSTORE);
  }
  Bytecode.push_back(OP_STOP);
  return Bytecode;
}

std::vector<uint8_t> makeLargeStaticDynamicOffsetMStoreBlock(uint64_t Ops) {
  std::vector<uint8_t> Bytecode;
  for (uint64_t I = 0; I < Ops; ++I) {
    appendPushU64(Bytecode, I + 1);
    Bytecode.push_back(OP_PUSH0);
    Bytecode.push_back(OP_CALLDATALOAD);
    Bytecode.push_back(OP_MSTORE);
  }
  Bytecode.push_back(OP_STOP);
  return Bytecode;
}

COMPILER::MemoryFacts collectMemoryFacts(const std::vector<uint8_t> &Bytecode) {
  COMPILER::MemoryFactsBuilder FactsBuilder;
  FactsBuilder.beginBlock(0, 0);

  size_t PC = 0;
  while (PC < Bytecode.size()) {
    evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
    FactsBuilder.observeOpcode(Opcode, PC, Bytecode.data(), Bytecode.size());
    ++PC;
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      PC += static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    }
  }

  return FactsBuilder.takeFacts();
}

COMPILER::MemoryFacts
collectAnalyzerMemoryFacts(const std::vector<uint8_t> &Bytecode) {
  EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  COMPILER::MemoryEntryAddressAnalysis EntryAddresses(Analyzer, Data,
                                                      Bytecode.size());
  COMPILER::MemoryFactsBuilder FactsBuilder;
  const auto &Blocks = Analyzer.getBlockInfos();
  for (const auto &[EntryPC, BlockInfo] : Blocks) {
    const int32_t EntryDepth = std::max(BlockInfo.ResolvedEntryStackDepth, 0);
    std::vector<COMPILER::MemoryEntryValue> EntryValues =
        EntryAddresses.getEntryValues(EntryPC,
                                      static_cast<uint32_t>(EntryDepth));
    FactsBuilder.beginBlock(EntryPC, BlockInfo.BodyStartPC, BlockInfo.BodyEndPC,
                            EntryValues, BlockInfo.Successors,
                            BlockInfo.Predecessors);

    size_t PC = static_cast<size_t>(BlockInfo.BodyStartPC);
    const size_t EndPC = std::min<size_t>(BlockInfo.BodyEndPC, Bytecode.size());
    while (PC < EndPC) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
      FactsBuilder.observeOpcode(Opcode, PC, Data, Bytecode.size());
      ++PC;
      if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
        PC += static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
      }
    }
  }
  return FactsBuilder.takeFacts();
}

struct MemoryFactBlockSpec {
  uint64_t EntryPC = 0;
  uint64_t BodyStartPC = 0;
  uint64_t BodyEndPC = 0;
  std::vector<uint64_t> Successors;
  std::vector<uint64_t> Predecessors;
};

COMPILER::MemoryFacts
collectManualBlockMemoryFacts(const std::vector<uint8_t> &Bytecode,
                              const std::vector<MemoryFactBlockSpec> &Blocks) {
  COMPILER::MemoryFactsBuilder FactsBuilder;
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  for (const MemoryFactBlockSpec &Block : Blocks) {
    FactsBuilder.beginBlock(Block.EntryPC, Block.BodyStartPC, Block.BodyEndPC,
                            {}, Block.Successors, Block.Predecessors);

    size_t PC = static_cast<size_t>(Block.BodyStartPC);
    const size_t EndPC = std::min<size_t>(Block.BodyEndPC, Bytecode.size());
    while (PC < EndPC) {
      evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
      FactsBuilder.observeOpcode(Opcode, PC, Data, Bytecode.size());
      ++PC;
      if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
        PC += static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
      }
    }
  }
  return FactsBuilder.takeFacts();
}

TEST(EVMMemoryFactsBuilderTest, RecordsConstMStoreWriteInterval) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x2a, OP_PUSH1, 0x80,
                                         OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Facts.Ops[0];
  EXPECT_EQ(Op.Pc, 4u);
  EXPECT_EQ(Op.Opcode, OP_MSTORE);
  EXPECT_EQ(Op.Kind, COMPILER::MemoryOpKind::MStore);
  EXPECT_EQ(Op.Effect, COMPILER::MemoryEffect::Write);
  ASSERT_TRUE(Op.Reads.empty());
  ASSERT_EQ(Op.Writes.size(), 1u);
  EXPECT_EQ(Op.Writes[0].Space, COMPILER::AddressSpace::Memory);
  EXPECT_EQ(Op.Writes[0].Addr.Kind, COMPILER::AddressBaseKind::Const);
  EXPECT_EQ(Op.Writes[0].Addr.Offset, 0x80);
  ASSERT_TRUE(Op.Writes[0].Size.Known);
  EXPECT_EQ(Op.Writes[0].Size.Value, 32u);
}

TEST(EVMMemoryFactsBuilderTest, AttributesOpsToAnalyzerBlocks) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x0b,      OP_JUMPI,  OP_PUSH1,
      0x01,     OP_PUSH1, 0x20,     OP_MSTORE, OP_STOP,   OP_JUMPDEST,
      OP_PUSH1, 0x02,     OP_PUSH1, 0x40,      OP_MSTORE, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Facts.Ops[0].Pc, 9u);
  EXPECT_EQ(Facts.Ops[0].BlockEntryPC, 5u);
  EXPECT_EQ(Facts.Ops[1].Pc, 16u);
  EXPECT_EQ(Facts.Ops[1].BlockEntryPC, 11u);

  const COMPILER::MemoryBlockFacts *Fallthrough = Facts.getBlock(5);
  ASSERT_NE(Fallthrough, nullptr);
  EXPECT_EQ(Fallthrough->OpsEnd - Fallthrough->OpsBegin, 1u);
  EXPECT_EQ(Fallthrough->MaxConstRequiredSize, 0x40u);

  const COMPILER::MemoryBlockFacts *JumpTarget = Facts.getBlock(11);
  ASSERT_NE(JumpTarget, nullptr);
  EXPECT_EQ(JumpTarget->OpsEnd - JumpTarget->OpsBegin, 1u);
  EXPECT_EQ(JumpTarget->MaxConstRequiredSize, 0x60u);
}

TEST(EVMMemoryEntryAddressAnalysisTest,
     PropagatesConstAddressAcrossUnconditionalJump) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,    0x80,     OP_PUSH1,
                                         0x06,        OP_JUMP,  OP_STOP,
                                         OP_JUMPDEST, OP_MLOAD, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Facts.Ops[0];
  EXPECT_EQ(Op.Pc, 7u);
  ASSERT_EQ(Op.Reads.size(), 1u);
  EXPECT_EQ(Op.Reads[0].Addr.Kind, COMPILER::AddressBaseKind::Const);
  EXPECT_EQ(Op.Reads[0].Addr.Offset, 0x80);
}

TEST(EVMMemoryEntryAddressAnalysisTest, RejectsConflictingMergeConstants) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1,    0x0b,     OP_JUMPI, OP_PUSH1,
      0x80,     OP_PUSH1, 0x0e,        OP_JUMP,  OP_STOP,  OP_JUMPDEST,
      OP_PUSH1, 0xa0,     OP_JUMPDEST, OP_MLOAD, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Facts.Ops[0];
  EXPECT_EQ(Op.Pc, 15u);
  ASSERT_EQ(Op.Reads.size(), 1u);
  EXPECT_EQ(Op.Reads[0].Addr.Kind, COMPILER::AddressBaseKind::Unknown);
}

TEST(EVMMemoryEntryAddressAnalysisTest, RejectsOverflowedU64ConstAddress) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH8, 0xff, 0xff,    0xff,        0xff,     0xff,
      0xff,     0xff, 0xff,    OP_PUSH1,    0x01,     OP_ADD,
      OP_PUSH1, 0x0f, OP_JUMP, OP_JUMPDEST, OP_MLOAD, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Facts.Ops[0];
  ASSERT_EQ(Op.Reads.size(), 1u);
  EXPECT_EQ(Op.Reads[0].Addr.Kind, COMPILER::AddressBaseKind::Unknown);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     SuccessorSkipExpansionWhenPredecessorGuaranteesBytes) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,  0x01,        OP_PUSH1, 0x00,
                                         OP_MSTORE, OP_JUMPDEST, OP_PUSH1, 0x00,
                                         OP_MLOAD,  OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(5), 32u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, RejectedMergeKeepsMinimumZero) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x0d,        OP_JUMPI,
      OP_PUSH1, 0x01, OP_PUSH1, 0x00,        OP_MSTORE,
      OP_PUSH1, 0x0e, OP_JUMP,  OP_JUMPDEST, OP_JUMPDEST,
      OP_PUSH1, 0x00, OP_MLOAD, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(14), 0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, RecordsGuaranteeBeforeEachOp) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE, OP_PUSH1, 0x40, OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[0].Id), 0u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0xa0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     DoesNotLearnNewGuaranteesAfterBarrier) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x00,      OP_MSTORE, OP_GAS, OP_PUSH1,
      0x02,     OP_PUSH1, 0x80,     OP_MSTORE, OP_PUSH1,  0x80,   OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 4u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[3].Id), 32u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, LearnsConstMCopyUnionEnd) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x20,    OP_PUSH1, 0x00,
                                         OP_PUSH1, 0x20,    OP_MCOPY, OP_PUSH1,
                                         0x00,     OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0x40u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, IgnoresZeroLengthMCopy) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x00,    OP_PUSH1, 0x80,
                                         OP_PUSH1, 0xa0,    OP_MCOPY, OP_PUSH1,
                                         0x00,     OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0u);
}

TEST(EVMMemoryFactsBuilderTest, RecordsCopyAddressSpaces) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x20, OP_PUSH1,       0x04,
                                         OP_PUSH1, 0x80, OP_CALLDATACOPY};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Facts.Ops[0];
  EXPECT_EQ(Op.Kind, COMPILER::MemoryOpKind::CallDataCopy);
  EXPECT_EQ(Op.Effect, COMPILER::MemoryEffect::ReadWrite);
  ASSERT_EQ(Op.Reads.size(), 1u);
  ASSERT_EQ(Op.Writes.size(), 1u);
  EXPECT_EQ(Op.Reads[0].Space, COMPILER::AddressSpace::CallData);
  EXPECT_EQ(Op.Reads[0].Addr.Offset, 0x04);
  ASSERT_TRUE(Op.Reads[0].Size.Known);
  EXPECT_EQ(Op.Reads[0].Size.Value, 0x20u);
  EXPECT_EQ(Op.Writes[0].Space, COMPILER::AddressSpace::Memory);
  EXPECT_EQ(Op.Writes[0].Addr.Offset, 0x80);
  ASSERT_TRUE(Op.Writes[0].Size.Known);
  EXPECT_EQ(Op.Writes[0].Size.Value, 0x20u);
}

TEST(EVMMemoryAnalysisViewTest, ClassifiesBarriersFromMemoryOps) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x00,     OP_MLOAD, OP_PUSH1,
                                         0x00,     OP_MSIZE, OP_PUSH1, 0x00,
                                         OP_PUSH1, 0x20,     OP_RETURN};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_EQ(View.getBarrierKind(Facts.Ops[0]),
            COMPILER::MemoryBarrierKind::Read);
  EXPECT_EQ(View.getBarrierKind(Facts.Ops[1]),
            COMPILER::MemoryBarrierKind::MemorySizeObserver);
  EXPECT_EQ(View.getBarrierKind(Facts.Ops[2]),
            COMPILER::MemoryBarrierKind::Escape);
  EXPECT_TRUE(View.isBarrier(Facts.Ops[2]));
}

TEST(EVMMemoryAnalysisViewTest, ProvesNoAliasForDisjointConstIntervals) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  ASSERT_EQ(Facts.Ops[0].Writes.size(), 1u);
  ASSERT_EQ(Facts.Ops[1].Writes.size(), 1u);
  EXPECT_EQ(
      View.getIntervalRelation(Facts.Ops[0].Writes[0], Facts.Ops[1].Writes[0]),
      COMPILER::IntervalRelationKind::Disjoint);
  EXPECT_EQ(View.alias(Facts.Ops[0], Facts.Ops[1]),
            COMPILER::MemoryAliasResult::NoAlias);
}

TEST(EVMMemoryAnalysisViewTest, ClassifiesOverlappingConstIntervals) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x90, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(
      View.getIntervalRelation(Facts.Ops[0].Writes[0], Facts.Ops[1].Writes[0]),
      COMPILER::IntervalRelationKind::Overlap);
  EXPECT_EQ(View.alias(Facts.Ops[0], Facts.Ops[1]),
            COMPILER::MemoryAliasResult::PartialAlias);
}

TEST(EVMMemoryAnalysisViewTest, ProvesMustAliasForEqualConstIntervals) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x80, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(
      View.getIntervalRelation(Facts.Ops[0].Writes[0], Facts.Ops[1].Writes[0]),
      COMPILER::IntervalRelationKind::Equal);
  EXPECT_EQ(View.alias(Facts.Ops[0], Facts.Ops[1]),
            COMPILER::MemoryAliasResult::MustAlias);
}

TEST(EVMMemoryAnalysisViewTest, ProvesNoAliasForBoundedSameBaseIntervals) {
  COMPILER::MemoryInterval LHS{
      COMPILER::AddressSpace::Memory,
      COMPILER::AddressExpr::boundedStackValue(7, 0, 8),
      COMPILER::SizeExpr::constant(8), false};
  COMPILER::MemoryInterval RHS{
      COMPILER::AddressSpace::Memory,
      COMPILER::AddressExpr::boundedStackValue(7, 32, 40),
      COMPILER::SizeExpr::constant(8), false};

  COMPILER::MemoryFacts Facts;
  COMPILER::MemoryAnalysisView View(Facts);

  EXPECT_EQ(View.getIntervalRelation(LHS, RHS),
            COMPILER::IntervalRelationKind::Disjoint);
  EXPECT_EQ(View.alias(LHS, RHS), COMPILER::MemoryAliasResult::NoAlias);
}

TEST(EVMMemoryAnalysisViewTest, KeepsMayAliasForUncertainBoundedOverlap) {
  COMPILER::MemoryInterval LHS{
      COMPILER::AddressSpace::Memory,
      COMPILER::AddressExpr::boundedStackValue(7, 0, 32),
      COMPILER::SizeExpr::constant(32), false};
  COMPILER::MemoryInterval RHS{
      COMPILER::AddressSpace::Memory,
      COMPILER::AddressExpr::boundedStackValue(7, 16, 48),
      COMPILER::SizeExpr::constant(32), false};

  COMPILER::MemoryFacts Facts;
  COMPILER::MemoryAnalysisView View(Facts);

  EXPECT_EQ(View.getIntervalRelation(LHS, RHS),
            COMPILER::IntervalRelationKind::Unknown);
  EXPECT_EQ(View.alias(LHS, RHS), COMPILER::MemoryAliasResult::MayAlias);
}

TEST(EVMMemoryAnalysisViewTest, ProvesNoAliasAcrossAddressSpaces) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x20, OP_PUSH1,       0x04,
                                         OP_PUSH1, 0x80, OP_CALLDATACOPY};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  ASSERT_EQ(Facts.Ops[0].Reads.size(), 1u);
  ASSERT_EQ(Facts.Ops[0].Writes.size(), 1u);
  EXPECT_EQ(View.alias(Facts.Ops[0].Reads[0], Facts.Ops[0].Writes[0]),
            COMPILER::MemoryAliasResult::NoAlias);
}

TEST(EVMMemoryClobberAnalysisTest, FindsReachingMustAliasStore) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1,  0x80,     OP_MSTORE, OP_PUSH1, 0x02,
      OP_PUSH1, 0xa0, OP_MSTORE, OP_PUSH1, 0x80,      OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_EQ(View.findReachingMustAliasStore(Facts.Ops[2]), &Facts.Ops[0]);
}

TEST(EVMMemoryClobberAnalysisTest, FindsUnreadOverwrittenStore) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x80, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(View.findOverwritingMustAliasStore(Facts.Ops[0]), &Facts.Ops[1]);
}

TEST(EVMMemoryClobberAnalysisTest, ReadPreventsDeadStoreProof) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x80,     OP_MSTORE, OP_PUSH1, 0x80,
      OP_MLOAD, OP_PUSH1, 0x02,     OP_PUSH1, 0x80,      OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_EQ(View.findOverwritingMustAliasStore(Facts.Ops[0]), nullptr);
  EXPECT_TRUE(View.hasMayAliasRead(Facts.Ops[0].Id, Facts.Ops[2].Id,
                                   Facts.Ops[0].Writes[0]));
}

TEST(EVMMemoryDeadStoreAnalysisTest, MarksOnlyFullyOverwrittenStore) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x80, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryDeadStoreAnalysis DeadStores(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_TRUE(DeadStores.isDeadStore(Facts.Ops[0].Id));
  EXPECT_FALSE(DeadStores.isDeadStore(Facts.Ops[1].Id));
}

TEST(EVMMemoryDeadStoreAnalysisTest, DoesNotCrossMemoryObserver) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,  0x01,     OP_PUSH1, 0x80,
                                         OP_MSTORE, OP_MSIZE, OP_PUSH1, 0x02,
                                         OP_PUSH1,  0x80,     OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryDeadStoreAnalysis DeadStores(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_FALSE(DeadStores.isDeadStore(Facts.Ops[0].Id));
}

TEST(EVMMemoryDeadStoreAnalysisTest, RejectsSameBasePartialOverlap) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH0, OP_CALLDATALOAD, OP_DUP1, OP_PUSH1, 0x01,
      OP_SWAP1, OP_MSTORE,       OP_DUP1, OP_PUSH1, 0x04,
      OP_ADD,   OP_PUSH1,        0x02,    OP_SWAP1, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryDeadStoreAnalysis DeadStores(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_EQ(View.alias(Facts.Ops[1], Facts.Ops[2]),
            COMPILER::MemoryAliasResult::PartialAlias);
  EXPECT_FALSE(DeadStores.isDeadStore(Facts.Ops[1].Id));
}

TEST(EVMMemoryLoadForwardingAnalysisTest, FindsExactReachingMStore) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x2a, OP_PUSH1, 0x80, OP_MSTORE, OP_PUSH1, 0x80, OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryLoadForwardingAnalysis Forwarding(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  std::optional<uint32_t> StoreId =
      Forwarding.getReachingStoreId(Facts.Ops[1].Id);
  ASSERT_TRUE(StoreId.has_value());
  EXPECT_EQ(*StoreId, Facts.Ops[0].Id);
}

TEST(EVMMemoryLoadForwardingAnalysisTest, RejectsInterveningMayAliasWrite) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x2a, OP_PUSH1,   0x80,     OP_MSTORE, OP_PUSH1, 0x01,
      OP_PUSH1, 0x90, OP_MSTORE8, OP_PUSH1, 0x80,      OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryLoadForwardingAnalysis Forwarding(Facts);

  ASSERT_EQ(Facts.Ops.size(), 3u);
  EXPECT_FALSE(Forwarding.getReachingStoreId(Facts.Ops[2].Id).has_value());
}

TEST(EVMMemoryPrecheckConsumerTest,
     ProducesProvenMemoryPrefixForConstDirectOps) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Consumer(View);

  std::optional<COMPILER::ProvenMemoryRange> Proof =
      Consumer.getBlockPrecheckRange(0, Bytecode.size());

  ASSERT_TRUE(Proof.has_value());
  EXPECT_EQ(Proof->EntryPC, 0u);
  EXPECT_EQ(Proof->CoveredOpCount, 2u);
  EXPECT_EQ(Proof->Interval.Space, COMPILER::AddressSpace::Memory);
  EXPECT_EQ(Proof->Interval.Addr.Kind, COMPILER::AddressBaseKind::Const);
  EXPECT_EQ(Proof->Interval.Addr.Offset, 0);
  ASSERT_TRUE(Proof->Interval.Size.Known);
  EXPECT_EQ(Proof->Interval.Size.Value, 0xc0u);
  uint64_t EndOffset = 0;
  ASSERT_TRUE(Proof->getKnownEndOffset(EndOffset));
  EXPECT_EQ(EndOffset, 0xc0u);
}

TEST(EVMMemoryPrecheckConsumerTest, RejectsHelperBarrierInBlockRange) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x00, OP_PUSH1, 0x20, OP_KECCAK256,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Consumer(View);

  EXPECT_FALSE(Consumer.getBlockPrecheckRange(0, Bytecode.size()).has_value());
}

TEST(EVMMemoryPrecheckConsumerTest, SelectsSafeWindowBeforeBarrier) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,     0x01,     OP_PUSH1,  0x80,     OP_MSTORE, OP_PUSH1, 0x02,
      OP_PUSH1,     0xa0,     OP_MSTORE, OP_PUSH1, 0x00,      OP_PUSH1, 0x20,
      OP_KECCAK256, OP_PUSH1, 0x03,      OP_PUSH1, 0xc0,      OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Consumer(View);

  std::optional<COMPILER::ProvenMemoryRange> Proof =
      Consumer.getBlockPrecheckRange(0, Bytecode.size());

  ASSERT_TRUE(Proof.has_value());
  EXPECT_EQ(Proof->CoveredOpCount, 2u);
  ASSERT_EQ(Proof->CoveredOpIds.size(), 2u);
  EXPECT_EQ(Proof->CoveredOpIds[0], Facts.Ops[0].Id);
  EXPECT_EQ(Proof->CoveredOpIds[1], Facts.Ops[1].Id);
  EXPECT_EQ(Proof->LastOpPC, Facts.Ops[1].Pc);
}

TEST(EVMMemoryGroupingConsumerTest, GroupsContinuousStores) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::SharedPrecheck> Shared =
      Grouping.getSharedPrecheck(0, Bytecode.size());

  ASSERT_TRUE(Shared.has_value());
  EXPECT_EQ(Shared->Group.OpCount, 2u);
  EXPECT_EQ(Shared->Group.UnionInterval.Addr.Offset, 0x80);
  ASSERT_TRUE(Shared->Group.UnionInterval.Size.Known);
  EXPECT_EQ(Shared->Group.UnionInterval.Size.Value, 0x40u);
  uint64_t EndOffset = 0;
  ASSERT_TRUE(Shared->Range.getKnownEndOffset(EndOffset));
  EXPECT_EQ(EndOffset, 0xc0u);
}

TEST(EVMMemoryGroupingConsumerTest, GroupsContinuousMStore8) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE8,
      OP_PUSH1, 0x02, OP_PUSH1, 0x81, OP_MSTORE8};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::SharedPrecheck> Shared =
      Grouping.getSharedPrecheck(0, Bytecode.size());

  ASSERT_TRUE(Shared.has_value());
  EXPECT_EQ(Shared->Group.OpCount, 2u);
  EXPECT_EQ(Shared->Group.UnionInterval.Addr.Offset, 0x80);
  ASSERT_TRUE(Shared->Group.UnionInterval.Size.Known);
  EXPECT_EQ(Shared->Group.UnionInterval.Size.Value, 2u);
}

TEST(EVMMemoryGroupingConsumerTest, GroupsContinuousMCopy) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x20, OP_PUSH1, 0x00, OP_PUSH1, 0x20, OP_MCOPY,
      OP_PUSH1, 0x20, OP_PUSH1, 0x40, OP_PUSH1, 0x60, OP_MCOPY};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::SharedPrecheck> Shared =
      Grouping.getSharedPrecheck(0, Bytecode.size());

  ASSERT_TRUE(Shared.has_value());
  EXPECT_EQ(Shared->Group.OpCount, 2u);
  EXPECT_EQ(Shared->Group.UnionInterval.Addr.Offset, 0);
  ASSERT_TRUE(Shared->Group.UnionInterval.Size.Known);
  EXPECT_EQ(Shared->Group.UnionInterval.Size.Value, 0x80u);
}

TEST(EVMMemoryGroupingConsumerTest, BarrierBreaksGroup) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x00, OP_PUSH1, 0x20, OP_KECCAK256,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  EXPECT_FALSE(Grouping.getSharedPrecheck(0, Bytecode.size()).has_value());
}

TEST(EVMMemoryGroupingConsumerTest, GroupsOverlappingIntervalsForExpansion) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x90, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::SharedPrecheck> Shared =
      Grouping.getSharedPrecheck(0, Bytecode.size());
  ASSERT_TRUE(Shared.has_value());
  EXPECT_EQ(Shared->Group.OpCount, 2u);
  uint64_t EndOffset = 0;
  ASSERT_TRUE(Shared->Range.getKnownEndOffset(EndOffset));
  EXPECT_EQ(EndOffset, 0xb0u);
}

TEST(EVMMemoryGroupingConsumerTest, UnknownIntervalBreaksGroup) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_CALLDATALOAD, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x80, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  EXPECT_FALSE(Grouping.getSharedPrecheck(0, Bytecode.size()).has_value());
}

TEST(EVMMemoryGroupingConsumerTest, DifferentAddressSpaceBreaksGroup) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x80,     OP_MSTORE, OP_PUSH1,
      0x20,     OP_PUSH1, 0x04,     OP_PUSH1, 0xa0,      OP_CALLDATACOPY,
      OP_PUSH1, 0x02,     OP_PUSH1, 0xc0,     OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  EXPECT_FALSE(Grouping.getSharedPrecheck(0, Bytecode.size()).has_value());
}

TEST(EVMMemoryGroupingConsumerTest, GroupsNonContiguousIntervalsForExpansion) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xc0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::SharedPrecheck> Shared =
      Grouping.getSharedPrecheck(0, Bytecode.size());
  ASSERT_TRUE(Shared.has_value());
  EXPECT_EQ(Shared->Group.OpCount, 2u);
  uint64_t EndOffset = 0;
  ASSERT_TRUE(Shared->Range.getKnownEndOffset(EndOffset));
  EXPECT_EQ(EndOffset, 0xe0u);
}

TEST(EVMMemoryConsumerFrameworkTest, PrecheckConsumerBuildsExpansionPlan) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xc0, OP_MSTORE,
      OP_PUSH1, 0x03, OP_PUSH1, 0xf0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Prechecks.buildMemoryExpansionPlan(0, Bytecode.size());

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind, COMPILER::MemoryExpansionKind::ProvenRange);
  EXPECT_EQ(Plan->CoveredOps, 3u);
  EXPECT_EQ(Plan->RequiredMemorySize, 0x110u);
  EXPECT_TRUE(Plan->Reusable);
  EXPECT_TRUE(Plan->coversPC(Facts.Ops[0].Pc));
  EXPECT_TRUE(Plan->coversPC(Facts.Ops[2].Pc));
}

TEST(EVMMemoryConsumerFrameworkTest, GroupingConsumerBuildsExpansionPlan) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Grouping.buildMemoryExpansionPlan(0, Bytecode.size());

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind,
            COMPILER::MemoryExpansionKind::ContiguousGroup);
  EXPECT_EQ(Plan->CoveredOps, 2u);
  EXPECT_EQ(Plan->RequiredInterval.Addr.Offset, 0x80);
  ASSERT_TRUE(Plan->RequiredInterval.Size.Known);
  EXPECT_EQ(Plan->RequiredInterval.Size.Value, 0x40u);
  EXPECT_EQ(Plan->RequiredMemorySize, 0xc0u);
}

TEST(EVMMemoryConsumerFrameworkTest, ExpansionPlannerPrefersGroupingPlan) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xa0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, Bytecode.size());

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind,
            COMPILER::MemoryExpansionKind::ContiguousGroup);
  EXPECT_EQ(Plan->RequiredMemorySize, 0xc0u);
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.GroupingCandidates, 1u);
  EXPECT_EQ(Diag.GroupingAccepted, 1u);
  EXPECT_EQ(Diag.PrecheckCandidates, 0u);
}

TEST(EVMMemoryConsumerFrameworkTest, ExpansionPlannerGroupsIntervalsWithGaps) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xc0, OP_MSTORE,
      OP_PUSH1, 0x03, OP_PUSH1, 0xf0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, Bytecode.size());

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind,
            COMPILER::MemoryExpansionKind::ContiguousGroup);
  EXPECT_EQ(Plan->RequiredMemorySize, 0x110u);
}

TEST(EVMMemoryConsumerFrameworkTest,
     ExpansionPlannerBuildsLinearRegionAcrossStraightLineSuccessor) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE, OP_JUMPDEST,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  const COMPILER::MemoryBlockFacts *Head = Facts.getBlock(0);
  const COMPILER::MemoryBlockFacts *Successor = Facts.getBlock(5);
  ASSERT_NE(Head, nullptr);
  ASSERT_NE(Successor, nullptr);

  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(Head->EntryPC, Head->BodyEndPC);

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind, COMPILER::MemoryExpansionKind::LinearRegion);
  EXPECT_EQ(Plan->FirstOpPC, 4u);
  EXPECT_EQ(Plan->LastOpPC, 10u);
  EXPECT_EQ(Plan->CoveredOps, 2u);
  EXPECT_EQ(Plan->RequiredMemorySize, 0x40u);
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(Successor->EntryPC), 0x40u);

  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.LinearRegionCandidates, 1u);
  EXPECT_EQ(Diag.LinearRegionAccepted, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest,
     ExpansionPlannerBuildsLinearRegionAcrossLongStraightLineChain) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE, OP_JUMPDEST,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE, OP_JUMPDEST,
      OP_PUSH1, 0x03, OP_PUSH1, 0x40, OP_MSTORE, OP_STOP};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  const COMPILER::MemoryBlockFacts *Head = Facts.getBlock(0);
  const COMPILER::MemoryBlockFacts *Middle = Facts.getBlock(5);
  const COMPILER::MemoryBlockFacts *Tail = Facts.getBlock(11);
  ASSERT_NE(Head, nullptr);
  ASSERT_NE(Middle, nullptr);
  ASSERT_NE(Tail, nullptr);

  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(Head->EntryPC, Head->BodyEndPC);

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind, COMPILER::MemoryExpansionKind::LinearRegion);
  EXPECT_EQ(Plan->FirstOpPC, 4u);
  EXPECT_EQ(Plan->LastOpPC, 16u);
  EXPECT_EQ(Plan->CoveredOps, 3u);
  EXPECT_EQ(Plan->RequiredMemorySize, 0x60u);
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(Middle->EntryPC), 0x60u);
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(Tail->EntryPC), 0x60u);
}

TEST(EVMMemoryConsumerFrameworkTest, LinearRegionRejectsBranchingHead) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE,
      OP_PUSH1, 0x03, OP_PUSH1, 0x40, OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5, 10}, {}},
      {5, 5, 10, {}, {0}},
      {10, 10, 15, {}, {0}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, 5);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Planner.getLastDiagnostics().LinearRegionCandidates, 0u);
  EXPECT_EQ(Planner.getLastDiagnostics().LinearRegionRejectedBranchingHead, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest, LinearRegionRejectsMergeSuccessor) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5}, {}},
      {5, 5, 10, {}, {0, 12}},
      {12, 10, 10, {5}, {}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, 5);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(5), 0u);
  EXPECT_EQ(Planner.getLastDiagnostics().LinearRegionRejectedMergeSuccessor,
            1u);
}

TEST(EVMMemoryConsumerFrameworkTest, LinearRegionRejectsBarrier) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,  0x01,     OP_PUSH1, 0x00,
                                         OP_MSTORE, OP_MSIZE, OP_PUSH1, 0x02,
                                         OP_PUSH1,  0x20,     OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 6, {6}, {}},
      {6, 6, 11, {}, {0}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, 6);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(6), 0x20u);
  EXPECT_EQ(Planner.getLastDiagnostics().LinearRegionRejectedHardBarrier, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest, LinearRegionRejectsUnknownEffectBarrier) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE,
      OP_PUSH1, 0x00, OP_PUSH1, 0x00, OP_SSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 10, {10}, {}},
      {10, 10, 15, {}, {0}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  const COMPILER::MemoryBlockFacts *Head = Facts.getBlock(0);
  ASSERT_NE(Head, nullptr);
  EXPECT_TRUE(Head->HasBarrier);

  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, 10);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(10), 0x20u);
  EXPECT_EQ(Planner.getLastDiagnostics().LinearRegionRejectedHardBarrier, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest,
     SelectsFirstMemoryBlockAsLinearRegionHead) {
  const std::vector<uint8_t> Bytecode = {
      OP_JUMPDEST, OP_PUSH1, 0x01,     OP_PUSH1, 0x00,     OP_MSTORE,
      OP_PUSH1,    0x02,     OP_PUSH1, 0x20,     OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 1, {1}, {}},
      {1, 1, 6, {6}, {0}},
      {6, 6, 11, {}, {1}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(Planner.buildMemoryExpansionPlan(0, 1).has_value());
  const COMPILER::MemoryExpansionPlanDiagnostics &HeadDiag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(HeadDiag.LinearRegionHeadCandidateBlocks, 1u);
  EXPECT_EQ(HeadDiag.LinearRegionHeadSkippedEmptyBlocks, 1u);
  EXPECT_EQ(HeadDiag.LinearRegionHeadSelectedNonEntryBlock, 1u);
  EXPECT_EQ(HeadDiag.LinearRegionHeadRejectedEntryGuaranteeMissing, 0u);
  EXPECT_EQ(HeadDiag.LinearRegionRejectedNoHeadMemoryOp, 0u);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(1, 6);

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind, COMPILER::MemoryExpansionKind::LinearRegion);
  EXPECT_EQ(Plan->FirstOpPC, 5u);
  EXPECT_EQ(Plan->LastOpPC, 10u);
  EXPECT_EQ(Plan->CoveredOps, 2u);
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(6), 0x40u);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsHeadSelectionAcrossBranch) {
  const std::vector<uint8_t> Bytecode = {
      OP_JUMPDEST, OP_PUSH1, 0x01,     OP_PUSH1, 0x00,     OP_MSTORE,
      OP_PUSH1,    0x02,     OP_PUSH1, 0x20,     OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 1, {1, 6}, {}},
      {1, 1, 6, {6}, {0}},
      {6, 6, 11, {}, {0, 1}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(Planner.buildMemoryExpansionPlan(0, 1).has_value());
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.LinearRegionHeadSkippedEmptyBlocks, 1u);
  EXPECT_EQ(Diag.LinearRegionHeadSelectedNonEntryBlock, 0u);
  EXPECT_EQ(Diag.LinearRegionHeadRejectedPredecessorNotStraight, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsHeadSelectionAcrossMerge) {
  const std::vector<uint8_t> Bytecode = {
      OP_JUMPDEST, OP_PUSH1, 0x01,     OP_PUSH1, 0x00,     OP_MSTORE,
      OP_PUSH1,    0x02,     OP_PUSH1, 0x20,     OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 1, {1}, {}},
      {1, 1, 6, {6}, {0, 11}},
      {6, 6, 11, {}, {1}},
      {11, 11, 11, {1}, {}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(Planner.buildMemoryExpansionPlan(0, 1).has_value());
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.LinearRegionHeadCandidateBlocks, 1u);
  EXPECT_EQ(Diag.LinearRegionHeadSelectedNonEntryBlock, 0u);
  EXPECT_EQ(Diag.LinearRegionHeadRejectedHeadNotDominatingChain, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsHeadSelectionAcrossBarrier) {
  const std::vector<uint8_t> Bytecode = {
      OP_GAS,   OP_PUSH1, 0x01,     OP_PUSH1, 0x00,     OP_MSTORE,
      OP_PUSH1, 0x02,     OP_PUSH1, 0x20,     OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 1, {1}, {}},
      {1, 1, 6, {6}, {0}},
      {6, 6, 11, {}, {1}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(Planner.buildMemoryExpansionPlan(0, 1).has_value());
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.LinearRegionHeadSelectedNonEntryBlock, 0u);
  EXPECT_EQ(Diag.LinearRegionHeadSkippedEmptyBlocks, 0u);
  EXPECT_EQ(Diag.LinearRegionRejectedBarrierGas, 1u);
}

TEST(EVMMemoryConsumerFrameworkTest, KeepsExistingEntryHeadRegion) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5}, {}},
      {5, 5, 10, {}, {0}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Planner.buildMemoryExpansionPlan(0, 5);

  ASSERT_TRUE(Plan.has_value());
  EXPECT_EQ(Plan->ExpansionKind, COMPILER::MemoryExpansionKind::LinearRegion);
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.LinearRegionHeadCandidateBlocks, 1u);
  EXPECT_EQ(Diag.LinearRegionHeadSkippedEmptyBlocks, 0u);
  EXPECT_EQ(Diag.LinearRegionHeadSelectedNonEntryBlock, 0u);
}

TEST(EVMMemoryConsumerFrameworkTest, AcceptsTwoOpPrecheckPlan) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0xc0, OP_MSTORE};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);

  std::optional<COMPILER::ProvenMemoryRange> Proof =
      Prechecks.getBlockPrecheckRange(0, Bytecode.size());
  ASSERT_TRUE(Proof.has_value());
  COMPILER::MemoryExpansionPlanRejectReason Reason =
      COMPILER::MemoryExpansionPlanRejectReason::None;
  EXPECT_TRUE(
      COMPILER::MemoryExpansionPlan::fromProvenRange(
          *Proof, COMPILER::MemoryExpansionKind::ProvenRange, true, &Reason)
          .has_value());
  EXPECT_EQ(Reason, COMPILER::MemoryExpansionPlanRejectReason::None);

  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      Prechecks.buildMemoryExpansionPlan(0, Bytecode.size());

  EXPECT_TRUE(Plan.has_value());

  COMPILER::MemoryExpansionPlanner Planner(View);
  EXPECT_TRUE(Planner.buildMemoryExpansionPlan(0, Bytecode.size()).has_value());
  const COMPILER::MemoryExpansionPlanDiagnostics &Diag =
      Planner.getLastDiagnostics();
  EXPECT_EQ(Diag.GroupingCandidates, 1u);
  EXPECT_EQ(Diag.PrecheckCandidates, 0u);
  EXPECT_EQ(Diag.RejectedNoCandidate, 0u);
  EXPECT_EQ(Diag.RejectedUnprofitable, 0u);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsTooLargeExpansionPlan) {
  COMPILER::ProvenMemoryRange Range;
  Range.EntryPC = 0;
  Range.FirstOpPC = 0;
  Range.LastOpPC = 0;
  Range.CoveredOpCount = 2;
  Range.Interval.Space = COMPILER::AddressSpace::Memory;
  Range.Interval.Addr = COMPILER::AddressExpr::constant(0);
  Range.Interval.Size = COMPILER::SizeExpr::constant(
      COMPILER::MemoryExpansionPlan::MaxRequiredMemorySize + 1);

  COMPILER::MemoryExpansionPlanRejectReason Reason =
      COMPILER::MemoryExpansionPlanRejectReason::None;
  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      COMPILER::MemoryExpansionPlan::fromProvenRange(
          Range, COMPILER::MemoryExpansionKind::ProvenRange, true, &Reason);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Reason, COMPILER::MemoryExpansionPlanRejectReason::TooLarge);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsZeroSizeExpansionPlan) {
  COMPILER::ProvenMemoryRange Range;
  Range.EntryPC = 0;
  Range.FirstOpPC = 0;
  Range.LastOpPC = 0;
  Range.CoveredOpCount = 2;
  Range.Interval.Space = COMPILER::AddressSpace::Memory;
  Range.Interval.Addr = COMPILER::AddressExpr::constant(0);
  Range.Interval.Size = COMPILER::SizeExpr::constant(0);
  Range.Interval.Empty = true;

  COMPILER::MemoryExpansionPlanRejectReason Reason =
      COMPILER::MemoryExpansionPlanRejectReason::None;
  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      COMPILER::MemoryExpansionPlan::fromProvenRange(
          Range, COMPILER::MemoryExpansionKind::ProvenRange, true, &Reason);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Reason, COMPILER::MemoryExpansionPlanRejectReason::ZeroSize);
}

TEST(EVMMemoryConsumerFrameworkTest, RejectsUnknownExpansionPlanInterval) {
  COMPILER::ProvenMemoryRange Range;
  Range.EntryPC = 0;
  Range.FirstOpPC = 0;
  Range.LastOpPC = 0;
  Range.CoveredOpCount = 2;
  Range.Interval.Space = COMPILER::AddressSpace::Memory;
  Range.Interval.Addr = COMPILER::AddressExpr::unknown();
  Range.Interval.Size = COMPILER::SizeExpr::unknown();

  COMPILER::MemoryExpansionPlanRejectReason Reason =
      COMPILER::MemoryExpansionPlanRejectReason::None;
  std::optional<COMPILER::MemoryExpansionPlan> Plan =
      COMPILER::MemoryExpansionPlan::fromProvenRange(
          Range, COMPILER::MemoryExpansionKind::ProvenRange, true, &Reason);

  EXPECT_FALSE(Plan.has_value());
  EXPECT_EQ(Reason, COMPILER::MemoryExpansionPlanRejectReason::UnknownInterval);
}

struct MockOperand {
  using U256Value = std::array<uint64_t, 4>;

  MockOperand() = default;
  explicit MockOperand(uint64_t Low) : Value{Low, 0, 0, 0}, Constant(true) {}
  explicit MockOperand(std::shared_ptr<U256Value> Slot)
      : Slot(std::move(Slot)) {}

  bool isConstant() const { return Constant; }
  bool isEmpty() const { return !Constant && !Slot; }

  const U256Value &getConstValue() const {
    ZEN_ASSERT(Constant && "mock operand must be constant");
    return Value;
  }

  U256Value resolvedValue() const {
    if (Slot) {
      return *Slot;
    }
    return Value;
  }

  void assign(const MockOperand &Other) {
    ZEN_ASSERT(Slot && "mock operand slot missing");
    *Slot = Other.resolvedValue();
  }

  void setRange(COMPILER::EVMValueRange) {}

private:
  U256Value Value = {0, 0, 0, 0};
  bool Constant = false;
  std::shared_ptr<U256Value> Slot;
};

struct MockStackAccessStats {
  uint32_t StackPopCount = 0;
  uint32_t StackPushCount = 0;
  uint32_t StackGetCount = 0;
  uint32_t StackSetCount = 0;
};

struct MockMeterOpcodeRangeRecord {
  uint64_t StartPC = 0;
  uint64_t EndPCExclusive = 0;
};

struct MockConstPrecheckPlanRecord {
  uint64_t MaxRequiredSize = 0;
  uint64_t CoveredDirectOps = 0;
};

struct MockMStoreRecord {
  MockOperand::U256Value Addr = {0, 0, 0, 0};
  MockOperand::U256Value Value = {0, 0, 0, 0};
};

struct MockKeccakCallDataSlotRecord {
  MockOperand::U256Value Offset = {0, 0, 0, 0};
  MockOperand::U256Value CallDataOffset = {0, 0, 0, 0};
  MockOperand::U256Value Slot = {0, 0, 0, 0};
};

struct MockKeccakCallerSlotRecord {
  MockOperand::U256Value Offset = {0, 0, 0, 0};
  MockOperand::U256Value Slot = {0, 0, 0, 0};
};

class MockEVMBuilder {
public:
  using CompilerContext = COMPILER::EVMFrontendContext;
  using Operand = MockOperand;

#define MOCK_OPERAND_STUB(Name)                                                \
  template <typename... Args> Operand Name(Args...) { return Operand(0); }

#define MOCK_VOID_STUB(Name)                                                   \
  template <typename... Args> void Name(Args...) {}

  void initEVM(CompilerContext *) {
    CurrentOpcode = 0xff;
    Trapped = false;
    Undefined = false;
  }

  void finalizeEVMBase() {}

  bool isOpcodeDefined(evmc_opcode Opcode) const {
    const auto *InstructionNames =
        evmc_get_instruction_names_table(EVMC_CANCUN);
    return InstructionNames && InstructionNames[Opcode] != nullptr;
  }

  void meterOpcode(evmc_opcode Opcode, uint64_t) {
    CurrentOpcode = static_cast<uint8_t>(Opcode);
    MeteredOpcodeCounts[static_cast<uint8_t>(Opcode)]++;
  }

  void meterOpcodeRange(uint64_t StartPC, uint64_t EndPCExclusive) {
    MeteredRanges.push_back({StartPC, EndPCExclusive});
  }

  void enableRuntimeStackChecks() { EnableRuntimeStackChecks = true; }

  void createStackCheckBlock(int32_t MinSize, int32_t MaxSize) {
    if (!EnableRuntimeStackChecks) {
      return;
    }
    if (RuntimeStack.size() < static_cast<size_t>(std::max(MinSize, 0))) {
      Trapped = true;
      return;
    }
    if (RuntimeStack.size() > static_cast<size_t>(std::max(MaxSize, 0))) {
      Trapped = true;
    }
  }

  Operand handlePush(const zen::common::Bytes &Data) {
    uint64_t Low = 0;
    for (zen::common::Byte Byte : Data) {
      Low = (Low << 8) | static_cast<uint64_t>(std::to_integer<uint8_t>(Byte));
    }
    LastPushValue = {Low, 0, 0, 0};
    HasLastPushValue = true;
    return Operand(Low);
  }

  void stackPush(Operand PushValue) {
    Stats[CurrentOpcode].StackPushCount++;
    RuntimeStack.push_back(PushValue);
  }

  Operand stackPop() {
    Stats[CurrentOpcode].StackPopCount++;
    ZEN_ASSERT(!RuntimeStack.empty() && "mock runtime stack underflow");
    Operand Top = RuntimeStack.back();
    RuntimeStack.pop_back();
    return Top;
  }

  void stackSet(int32_t IndexFromTop, Operand SetValue) {
    Stats[CurrentOpcode].StackSetCount++;
    size_t Index = RuntimeStack.size() - static_cast<size_t>(IndexFromTop) - 1;
    RuntimeStack[Index] = SetValue;
  }

  Operand stackGet(int32_t IndexFromTop) {
    Stats[CurrentOpcode].StackGetCount++;
    size_t Index = RuntimeStack.size() - static_cast<size_t>(IndexFromTop) - 1;
    return RuntimeStack[Index];
  }

  void setTrackedStackDepth(uint32_t Depth) {
    if (RuntimeStack.size() > Depth) {
      RuntimeStack.resize(Depth);
    }
  }

  Operand createStackEntryOperand(
      COMPILER::EVMValueRange = COMPILER::EVMValueRange::U256) {
    return Operand(std::make_shared<MockOperand::U256Value>(
        MockOperand::U256Value{0, 0, 0, 0}));
  }

  void assignStackEntryOperand(const Operand &Dest, const Operand &Value) {
    Operand Copy = Dest;
    Copy.assign(Value);
  }

  void spillTrackedStack(const std::vector<Operand> &TrackedStack) {
    RuntimeStack = TrackedStack;
  }

  void setCurrentDebugBlockPC(uint64_t) {}

  template <zen::common::BinaryOperator Opr>
  Operand handleBinaryArithmetic(Operand LHS, Operand RHS) {
    if constexpr (Opr == zen::common::BinaryOperator::BO_ADD) {
      const auto LHSValue = LHS.resolvedValue();
      const auto RHSValue = RHS.resolvedValue();
      return Operand(LHSValue[0] + RHSValue[0]);
    }
    return Operand(0);
  }

  template <zen::common::CompareOperator Opr>
  Operand handleCompareOp(Operand, Operand) {
    return Operand(0);
  }

  template <zen::common::BinaryOperator Opr>
  Operand handleBitwiseOp(Operand, Operand) {
    return Operand(0);
  }

  template <zen::common::BinaryOperator Opr>
  Operand handleShift(Operand, Operand) {
    return Operand(0);
  }

  template <size_t NumTopics, typename... Args>
  void handleLogWithTopics(Args...) {}

  Operand handleCall(Operand, Operand, Operand, Operand, Operand, Operand,
                     Operand) {
    return Operand(0);
  }

  Operand handleCallCode(Operand, Operand, Operand, Operand, Operand, Operand,
                         Operand) {
    return Operand(0);
  }

  Operand handleDelegateCall(Operand, Operand, Operand, Operand, Operand,
                             Operand) {
    return Operand(0);
  }

  Operand handleStaticCall(Operand, Operand, Operand, Operand, Operand,
                           Operand) {
    return Operand(0);
  }

  MOCK_OPERAND_STUB(handleAddMod);
  MOCK_OPERAND_STUB(handleAddress);
  MOCK_OPERAND_STUB(handleBalance);
  MOCK_OPERAND_STUB(handleBaseFee);
  MOCK_OPERAND_STUB(handleBlobBaseFee);
  MOCK_OPERAND_STUB(handleBlobHash);
  MOCK_OPERAND_STUB(handleBlockHash);
  MOCK_OPERAND_STUB(handleByte);
  MOCK_OPERAND_STUB(handleCallDataLoad);
  MOCK_OPERAND_STUB(handleCallDataSize);
  MOCK_OPERAND_STUB(handleCallValue);
  MOCK_OPERAND_STUB(handleCaller);
  MOCK_OPERAND_STUB(handleChainId);
  MOCK_OPERAND_STUB(handleClz);
  MOCK_OPERAND_STUB(handleCodeSize);
  MOCK_OPERAND_STUB(handleCoinBase);
  MOCK_OPERAND_STUB(handleCreate);
  MOCK_OPERAND_STUB(handleCreate2);
  MOCK_OPERAND_STUB(handleDiv);
  MOCK_OPERAND_STUB(handleExp);
  MOCK_OPERAND_STUB(handleExtCodeHash);
  MOCK_OPERAND_STUB(handleExtCodeSize);
  MOCK_OPERAND_STUB(handleGas);
  MOCK_OPERAND_STUB(handleGasLimit);
  MOCK_OPERAND_STUB(handleGasPrice);
  MOCK_OPERAND_STUB(handleMLoad);
  MOCK_OPERAND_STUB(handleMSize);
  MOCK_OPERAND_STUB(handleMod);
  MOCK_OPERAND_STUB(handleMul);
  MOCK_OPERAND_STUB(handleMulMod);
  MOCK_OPERAND_STUB(handleNot);
  MOCK_OPERAND_STUB(handleNumber);
  MOCK_OPERAND_STUB(handleOrigin);
  MOCK_OPERAND_STUB(handlePC);
  MOCK_OPERAND_STUB(handlePrevRandao);
  MOCK_OPERAND_STUB(handleReturnDataSize);
  MOCK_OPERAND_STUB(handleSDiv);
  MOCK_OPERAND_STUB(handleSLoad);
  MOCK_OPERAND_STUB(handleSMod);
  MOCK_OPERAND_STUB(handleSelfBalance);
  MOCK_OPERAND_STUB(handleSignextend);
  MOCK_OPERAND_STUB(handleTimestamp);
  MOCK_OPERAND_STUB(handleTLoad);

  MOCK_VOID_STUB(handleCallDataCopy);
  MOCK_VOID_STUB(handleCodeCopy);
  MOCK_VOID_STUB(handleExtCodeCopy);
  MOCK_VOID_STUB(handleMStore8);

  void handleMStore(Operand Addr, Operand Value) {
    LastMStore = {Addr.resolvedValue(), Value.resolvedValue()};
    MStoreCount++;
  }

  void handleMCopy(Operand, Operand, Operand) { MCopyCount++; }

  Operand handleKeccak256(Operand, Operand) {
    KeccakCount++;
    return Operand(0);
  }

  Operand handleKeccak256TwoWord(Operand Offset, Operand Word0, Operand Word1) {
    KeccakTwoWordLastOffset = Offset.resolvedValue();
    KeccakTwoWordLastWord0 = Word0.resolvedValue();
    KeccakTwoWordLastWord1 = Word1.resolvedValue();
    KeccakTwoWordCount++;
    return Operand(0);
  }

  Operand handleKeccak256CallDataConstSlot(Operand Offset,
                                           Operand CallDataOffset,
                                           Operand SlotWord) {
    LastKeccakCallDataSlot = {Offset.resolvedValue(),
                              CallDataOffset.resolvedValue(),
                              SlotWord.resolvedValue()};
    KeccakCallDataSlotCount++;
    return Operand(0);
  }

  Operand handleKeccak256CallerConstSlot(Operand Offset, Operand SlotWord) {
    LastKeccakCallerSlot = {Offset.resolvedValue(), SlotWord.resolvedValue()};
    KeccakCallerSlotCount++;
    return Operand(0);
  }

  MOCK_VOID_STUB(handleReturn);
  MOCK_VOID_STUB(handleReturnDataCopy);
  MOCK_VOID_STUB(handleRevert);
  MOCK_VOID_STUB(handleSStore);
  MOCK_VOID_STUB(handleSelfDestruct);
  MOCK_VOID_STUB(handleTStore);

  void beginMemoryCompileBlock(uint64_t) {}
  void setMemoryCompileBlockConstPrecheckPlan(uint64_t MaxRequiredSize,
                                              uint64_t CoveredDirectOps) {
    ConstPrecheckPlanCount++;
    ConstPrecheckMaxRequiredSize = MaxRequiredSize;
    ConstPrecheckCoveredDirectOps = CoveredDirectOps;
    ConstPrecheckPlans.push_back({MaxRequiredSize, CoveredDirectOps});
  }
  void setMemoryCompileBlockLinearPrecheckPlan(uint64_t AccessWidth,
                                               uint64_t CoveredDirectOps,
                                               bool ValueEqualsFirstAddr) {
    LinearPrecheckPlanCount++;
    LastLinearPrecheckAccessWidth = AccessWidth;
    LastLinearPrecheckCoveredDirectOps = CoveredDirectOps;
    LastLinearPrecheckValueEqualsFirstAddr = ValueEqualsFirstAddr;
  }
  void setMemoryCompileBlockLargeStaticWorkspacePrecheckPlan(
      uint64_t, uint64_t, uint64_t MaxRequiredSize, uint64_t CoveredDirectOps,
      uint64_t CoveredMLoadOps, uint64_t CoveredMStoreOps,
      uint64_t CoveredMStore8Ops) {
    ++LargeStaticWorkspaceLoweringPlans;
    LargeStaticWorkspaceLoweringMaxRequiredSize = MaxRequiredSize;
    LargeStaticWorkspaceLoweringCoveredOps = CoveredDirectOps;
    LargeStaticWorkspaceLoweringCoveredMLoadOps = CoveredMLoadOps;
    LargeStaticWorkspaceLoweringCoveredMStoreOps = CoveredMStoreOps;
    LargeStaticWorkspaceLoweringCoveredMStore8Ops = CoveredMStore8Ops;
  }
  void noteLargeStaticWorkspaceVerifierResult(
      uint64_t Candidates, uint64_t VerifiedSegments, uint64_t VerifiedOps,
      uint64_t VerifiedMLoadOps, uint64_t VerifiedMStoreOps,
      uint64_t VerifiedMStore8Ops, uint64_t MaxRequiredSize, uint64_t Rejected,
      uint64_t RejectDynamicOffset, uint64_t RejectUnknownBase,
      uint64_t RejectUnboundedInterval, uint64_t RejectOverflowRisk,
      uint64_t RejectSideEffect, uint64_t RejectHelperByteExactRisk,
      uint64_t RejectTooFewOps) {
    LargeStaticWorkspaceCandidates += Candidates;
    LargeStaticWorkspaceVerifiedSegments += VerifiedSegments;
    LargeStaticWorkspaceVerifiedOps += VerifiedOps;
    LargeStaticWorkspaceVerifiedMLoadOps += VerifiedMLoadOps;
    LargeStaticWorkspaceVerifiedMStoreOps += VerifiedMStoreOps;
    LargeStaticWorkspaceVerifiedMStore8Ops += VerifiedMStore8Ops;
    LargeStaticWorkspaceMaxRequiredSize =
        std::max(LargeStaticWorkspaceMaxRequiredSize, MaxRequiredSize);
    LargeStaticWorkspaceRejected += Rejected;
    LargeStaticWorkspaceRejectDynamicOffset += RejectDynamicOffset;
    LargeStaticWorkspaceRejectUnknownBase += RejectUnknownBase;
    LargeStaticWorkspaceRejectUnboundedInterval += RejectUnboundedInterval;
    LargeStaticWorkspaceRejectOverflowRisk += RejectOverflowRisk;
    LargeStaticWorkspaceRejectSideEffect += RejectSideEffect;
    LargeStaticWorkspaceRejectHelperByteExactRisk += RejectHelperByteExactRisk;
    LargeStaticWorkspaceRejectTooFewOps += RejectTooFewOps;
  }
  void prepareLinearBlockMemoryPrecheck(Operand) {
    LinearPrecheckPrepareCount++;
  }
  void noteMemoryOpcodeInBlock(evmc_opcode, uint64_t) {}
  void noteHelperOpcodeInBlock(evmc_opcode, uint64_t) {}
  void endMemoryCompileBlock() {}

  void handleJump(Operand) {}
  void handleJump(Operand, const std::vector<uint64_t> *) {}
  void handleJumpI(Operand, Operand) {}
  void handleJumpI(Operand, Operand, const std::vector<uint64_t> *) {}
  void handleJumpDest(const uint64_t &, bool) {}
  void handleStop() {}
  void handleUndefined() { Undefined = true; }
  void handleInvalid() { Undefined = true; }
  void handleTrap(zen::common::ErrorCode) { Trapped = true; }
  void fallbackToInterpreter(uint64_t) {}
  void releaseOperand(Operand) {}

  const MockStackAccessStats &accessStats(evmc_opcode Opcode) const {
    return Stats[static_cast<uint8_t>(Opcode)];
  }

  uint32_t meteredOpcodeCount(evmc_opcode Opcode) const {
    return MeteredOpcodeCounts[static_cast<uint8_t>(Opcode)];
  }

  const std::vector<MockMeterOpcodeRangeRecord> &meteredRanges() const {
    return MeteredRanges;
  }

  const std::vector<MockConstPrecheckPlanRecord> &constPrecheckPlans() const {
    return ConstPrecheckPlans;
  }

  uint32_t mstoreCount() const { return MStoreCount; }

  uint32_t mcopyCount() const { return MCopyCount; }

  uint32_t constPrecheckPlanCount() const { return ConstPrecheckPlanCount; }

  uint64_t constPrecheckMaxRequiredSize() const {
    return ConstPrecheckMaxRequiredSize;
  }

  uint64_t constPrecheckCoveredDirectOps() const {
    return ConstPrecheckCoveredDirectOps;
  }

  uint32_t keccakCount() const { return KeccakCount; }

  uint32_t keccakTwoWordCount() const { return KeccakTwoWordCount; }

  uint32_t keccakCallDataSlotCount() const { return KeccakCallDataSlotCount; }

  uint32_t keccakCallerSlotCount() const { return KeccakCallerSlotCount; }

  const MockMStoreRecord &lastMStore() const {
    ZEN_ASSERT(MStoreCount != 0 && "mock mstore record is missing");
    return LastMStore;
  }

  const MockKeccakCallDataSlotRecord &lastKeccakCallDataSlot() const {
    ZEN_ASSERT(KeccakCallDataSlotCount != 0 &&
               "mock calldata+slot keccak record is missing");
    return LastKeccakCallDataSlot;
  }

  const MockKeccakCallerSlotRecord &lastKeccakCallerSlot() const {
    ZEN_ASSERT(KeccakCallerSlotCount != 0 &&
               "mock caller+slot keccak record is missing");
    return LastKeccakCallerSlot;
  }

  bool hasLastPushValue() const { return HasLastPushValue; }

  MockOperand::U256Value lastPushValue() const {
    ZEN_ASSERT(HasLastPushValue && "mock push value is missing");
    return LastPushValue;
  }

  size_t runtimeStackDepth() const { return RuntimeStack.size(); }

  MockOperand::U256Value topStackValue() const {
    ZEN_ASSERT(!RuntimeStack.empty() && "mock runtime stack is empty");
    return RuntimeStack.back().resolvedValue();
  }

  uint32_t linearPrecheckPlanCount() const { return LinearPrecheckPlanCount; }

  uint64_t lastLinearPrecheckAccessWidth() const {
    return LastLinearPrecheckAccessWidth;
  }

  uint64_t lastLinearPrecheckCoveredDirectOps() const {
    return LastLinearPrecheckCoveredDirectOps;
  }

  bool lastLinearPrecheckValueEqualsFirstAddr() const {
    return LastLinearPrecheckValueEqualsFirstAddr;
  }

  uint32_t linearPrecheckPrepareCount() const {
    return LinearPrecheckPrepareCount;
  }

  bool Trapped = false;
  bool Undefined = false;
  uint64_t LargeStaticWorkspaceCandidates = 0;
  uint64_t LargeStaticWorkspaceVerifiedSegments = 0;
  uint64_t LargeStaticWorkspaceVerifiedOps = 0;
  uint64_t LargeStaticWorkspaceVerifiedMLoadOps = 0;
  uint64_t LargeStaticWorkspaceVerifiedMStoreOps = 0;
  uint64_t LargeStaticWorkspaceVerifiedMStore8Ops = 0;
  uint64_t LargeStaticWorkspaceMaxRequiredSize = 0;
  uint64_t LargeStaticWorkspaceRejected = 0;
  uint64_t LargeStaticWorkspaceRejectDynamicOffset = 0;
  uint64_t LargeStaticWorkspaceRejectUnknownBase = 0;
  uint64_t LargeStaticWorkspaceRejectUnboundedInterval = 0;
  uint64_t LargeStaticWorkspaceRejectOverflowRisk = 0;
  uint64_t LargeStaticWorkspaceRejectSideEffect = 0;
  uint64_t LargeStaticWorkspaceRejectHelperByteExactRisk = 0;
  uint64_t LargeStaticWorkspaceRejectTooFewOps = 0;
  uint64_t LargeStaticWorkspaceLoweringPlans = 0;
  uint64_t LargeStaticWorkspaceLoweringMaxRequiredSize = 0;
  uint64_t LargeStaticWorkspaceLoweringCoveredOps = 0;
  uint64_t LargeStaticWorkspaceLoweringCoveredMLoadOps = 0;
  uint64_t LargeStaticWorkspaceLoweringCoveredMStoreOps = 0;
  uint64_t LargeStaticWorkspaceLoweringCoveredMStore8Ops = 0;

private:
  bool EnableRuntimeStackChecks = false;
  uint8_t CurrentOpcode = 0xff;
  std::array<MockStackAccessStats, 256> Stats = {};
  std::array<uint32_t, 256> MeteredOpcodeCounts = {};
  std::vector<MockMeterOpcodeRangeRecord> MeteredRanges;
  std::vector<MockConstPrecheckPlanRecord> ConstPrecheckPlans;
  MockMStoreRecord LastMStore = {};
  uint32_t MStoreCount = 0;
  uint32_t MCopyCount = 0;
  uint32_t ConstPrecheckPlanCount = 0;
  uint64_t ConstPrecheckMaxRequiredSize = 0;
  uint64_t ConstPrecheckCoveredDirectOps = 0;
  MockOperand::U256Value KeccakTwoWordLastOffset = {0, 0, 0, 0};
  MockOperand::U256Value KeccakTwoWordLastWord0 = {0, 0, 0, 0};
  MockOperand::U256Value KeccakTwoWordLastWord1 = {0, 0, 0, 0};
  uint32_t KeccakCount = 0;
  uint32_t KeccakTwoWordCount = 0;
  MockKeccakCallDataSlotRecord LastKeccakCallDataSlot = {};
  uint32_t KeccakCallDataSlotCount = 0;
  MockKeccakCallerSlotRecord LastKeccakCallerSlot = {};
  uint32_t KeccakCallerSlotCount = 0;
  std::vector<Operand> RuntimeStack;
  MockOperand::U256Value LastPushValue = {0, 0, 0, 0};
  bool HasLastPushValue = false;
  uint32_t LinearPrecheckPlanCount = 0;
  uint64_t LastLinearPrecheckAccessWidth = 0;
  uint64_t LastLinearPrecheckCoveredDirectOps = 0;
  bool LastLinearPrecheckValueEqualsFirstAddr = false;
  uint32_t LinearPrecheckPrepareCount = 0;

#undef MOCK_OPERAND_STUB
#undef MOCK_VOID_STUB
};

class DynamicPushMockEVMBuilder : public MockEVMBuilder {
public:
  Operand handlePush(const zen::common::Bytes &) { return Operand(); }
};

TEST(EVMMirBuilderConstFoldTest, ExpFoldsConstantOperands) {
  MirBuilderConstFoldHarness Harness;
  using Operand = EVMMirBuilder::Operand;
  using U256Value = EVMMirBuilder::U256Value;

  auto fold = [&](U256Value Base, U256Value Exp) {
    return Harness.Builder.handleExp(Operand(Base), Operand(Exp));
  };

  // 10 ** 2 == 100
  auto R = fold({10, 0, 0, 0}, {2, 0, 0, 0});
  ASSERT_TRUE(R.isConstant());
  EXPECT_EQ(R.getConstValue(), (U256Value{100, 0, 0, 0}));

  // 2 ** 64 carries into limb 1
  EXPECT_EQ(fold({2, 0, 0, 0}, {64, 0, 0, 0}).getConstValue(),
            (U256Value{0, 1, 0, 0}));

  // 2 ** 256 wraps to 0 (mod 2^256)
  EXPECT_EQ(fold({2, 0, 0, 0}, {256, 0, 0, 0}).getConstValue(),
            (U256Value{0, 0, 0, 0}));

  // 0 ** 0 == 1 (EVM convention)
  EXPECT_EQ(fold({0, 0, 0, 0}, {0, 0, 0, 0}).getConstValue(),
            (U256Value{1, 0, 0, 0}));
}

// Pins the gas charged on the EXP const-fold path (the soundness-critical half:
// the exponent magnitude is observable in gas), independent of the folded
// value. Values are the EIP-160 spec constants, not the impl's own constants.
TEST(EVMMirBuilderConstFoldTest, ExpConstDynamicGasMatchesEip160) {
  // Post-Spurious-Dragon: 50 gas / significant exponent byte; 0 for exponent 0.
  EXPECT_EQ(EVMMirBuilder::constExpDynamicGas(intx::uint256{0}, EVMC_CANCUN),
            0u);
  EXPECT_EQ(EVMMirBuilder::constExpDynamicGas(intx::uint256{0xFF}, EVMC_CANCUN),
            50u);
  EXPECT_EQ(
      EVMMirBuilder::constExpDynamicGas(intx::uint256{0x100}, EVMC_CANCUN),
      100u);
  EXPECT_EQ(
      EVMMirBuilder::constExpDynamicGas(intx::uint256{0x010000}, EVMC_CANCUN),
      150u);
  // Full 32-byte exponent: 32 * 50 = 1600.
  EXPECT_EQ(EVMMirBuilder::constExpDynamicGas(~intx::uint256{0}, EVMC_CANCUN),
            1600u);
  // Pre-Spurious-Dragon: 10 gas / byte.
  EXPECT_EQ(
      EVMMirBuilder::constExpDynamicGas(intx::uint256{0xFF}, EVMC_FRONTIER),
      10u);
  EXPECT_EQ(
      EVMMirBuilder::constExpDynamicGas(intx::uint256{0x100}, EVMC_FRONTIER),
      20u);
}

TEST(EVMMirBuilderConstFoldTest, SignextendFoldsConstantOperands) {
  MirBuilderConstFoldHarness Harness;
  using Operand = EVMMirBuilder::Operand;
  using U256Value = EVMMirBuilder::U256Value;
  const uint64_t Ones = ~0ULL;

  auto fold = [&](U256Value Index, U256Value Value) {
    return Harness.Builder.handleSignextend(Operand(Index), Operand(Value));
  };

  // SIGNEXTEND(0, 0xFF): byte 0 sign bit set -> fills all higher bits with 1
  auto R = fold({0, 0, 0, 0}, {0xFF, 0, 0, 0});
  ASSERT_TRUE(R.isConstant());
  EXPECT_EQ(R.getConstValue(), (U256Value{Ones, Ones, Ones, Ones}));

  // SIGNEXTEND(0, 0x7F): byte 0 sign bit clear -> unchanged
  EXPECT_EQ(fold({0, 0, 0, 0}, {0x7F, 0, 0, 0}).getConstValue(),
            (U256Value{0x7F, 0, 0, 0}));

  // SIGNEXTEND(0, 0x1234): low byte 0x34, sign bit clear -> 0x34
  EXPECT_EQ(fold({0, 0, 0, 0}, {0x1234, 0, 0, 0}).getConstValue(),
            (U256Value{0x34, 0, 0, 0}));

  // SIGNEXTEND(1, 0x80FF): sign bit is bit 15 (set) -> ones above bit 15
  EXPECT_EQ(fold({1, 0, 0, 0}, {0x80FF, 0, 0, 0}).getConstValue(),
            (U256Value{0xFFFFFFFFFFFF80FFULL, Ones, Ones, Ones}));

  // SIGNEXTEND(31, x): index >= 31 leaves the value untouched
  EXPECT_EQ(fold({31, 0, 0, 0}, {1, 0, 0, Ones}).getConstValue(),
            (U256Value{1, 0, 0, Ones}));
}

bool compileWithMockBuilder(const std::vector<uint8_t> &Bytecode,
                            MockEVMBuilder &Builder) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  return Visitor.compile();
}

TEST(EVMJITFrontendVisitorTest, DynamicJumpConsistencyErrorEscapesVisitor) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x04, // PC0 PUSH1 0x04 (analyzer resolves a constant destination)
      0x56,       // PC2 JUMP
      0xfe,       // PC3 INVALID padding
      0x5b,       // PC4 JUMPDEST
      0x00,       // PC5 STOP
  };
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  DynamicPushMockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<DynamicPushMockEVMBuilder> Visitor(Builder,
                                                                  &Ctx);
  try {
    (void)Visitor.compile();
    FAIL() << "dynamic-jump consistency error was swallowed";
  } catch (const zen::common::Error &Error) {
    EXPECT_EQ(Error.getCode(),
              zen::common::ErrorCode::EVMDynamicJumpConsistencyFailed);
  }
}

TEST(EVMJITFrontendAnalyzerTest, ConstantJumpCanonicalizesJumpDestRuns) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x04, // PUSH1 0x04
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  EXPECT_TRUE(Analyzer.hasCanonicalJumpDest(3));
  EXPECT_TRUE(Analyzer.hasCanonicalJumpDest(4));
  EXPECT_EQ(Analyzer.getCanonicalJumpDestPC(3), 4U);
  EXPECT_EQ(Analyzer.getCanonicalJumpDestPC(4), 4U);

  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *JumpDestBlock = findBlock(Analyzer, 4);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(JumpDestBlock, nullptr);
  EXPECT_EQ(findBlock(Analyzer, 3), nullptr);

  EXPECT_TRUE(EntryBlock->HasConstantJump);
  EXPECT_EQ(EntryBlock->ConstantJumpTargetPC, 4U);
  expectPCList(EntryBlock->Successors, {4});

  EXPECT_TRUE(JumpDestBlock->IsJumpDest);
  expectPCList(JumpDestBlock->Predecessors, {0});
}

TEST(EVMJITFrontendMirVerifierTest,
     OrphanJumpDestEntryThunkDoesNotBecomePhiPredecessor) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PC0  PUSH1 0x11  (taken-edge stack value)
      0x60, 0x01, // PC2  PUSH1 cond
      0x60, 0x10, // PC4  PUSH1 canonical JUMPDEST PC
      0x57,       // PC6  JUMPI
      0x50,       // PC7  POP
      0x60, 0x22, // PC8  PUSH1 0x22  (fallthrough-edge stack value)
      0x60, 0x10, // PC10 PUSH1 canonical JUMPDEST PC
      0x56,       // PC12 JUMP
      0xfe,       // PC13 INVALID padding
      0xfe,       // PC14 INVALID padding
      0x5b,       // PC15 JUMPDEST (non-canonical entry thunk, unreferenced)
      0x5b,       // PC16 JUMPDEST (shared body)
      0x50,       // PC17 POP merged stack value
      0x00        // PC18 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *MergeBlock = findBlock(Analyzer, 16);
  ASSERT_NE(MergeBlock, nullptr);
  EXPECT_FALSE(MergeBlock->CanLiftStack);
  expectPCList(MergeBlock->Predecessors, {0, 7});

  std::string VerifierOutput;
  EXPECT_TRUE(verifyMirForBytecode(Bytecode, true, &VerifierOutput))
      << VerifierOutput;
  EXPECT_TRUE(verifyMirForBytecode(Bytecode, false, &VerifierOutput))
      << VerifierOutput;
}

TEST(EVMJITFrontendAnalyzerTest,
     SuitabilityOnlyKeepsFallbackMetricsWithoutBuildingCfg) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x04, // PUSH1 0x04
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer FullAnalyzer = analyzeBytecode(Bytecode);
  const EVMAnalyzer SuitabilityOnlyAnalyzer =
      analyzeSuitabilityOnlyBytecode(Bytecode);

  const auto &Full = FullAnalyzer.getJITSuitability();
  const auto &SuitabilityOnly = SuitabilityOnlyAnalyzer.getJITSuitability();

  EXPECT_EQ(SuitabilityOnly.ShouldFallback, Full.ShouldFallback);
  EXPECT_EQ(SuitabilityOnly.BytecodeSize, Full.BytecodeSize);
  EXPECT_EQ(SuitabilityOnly.MirEstimate, Full.MirEstimate);
  EXPECT_EQ(SuitabilityOnly.RAExpensiveCount, Full.RAExpensiveCount);
  EXPECT_EQ(SuitabilityOnly.MaxConsecutiveExpensive,
            Full.MaxConsecutiveExpensive);
  EXPECT_EQ(SuitabilityOnly.MaxBlockExpensiveCount,
            Full.MaxBlockExpensiveCount);
  EXPECT_EQ(SuitabilityOnly.DupFeedbackPatternCount,
            Full.DupFeedbackPatternCount);

  EXPECT_TRUE(SuitabilityOnlyAnalyzer.getBlockInfos().empty());
  EXPECT_FALSE(SuitabilityOnlyAnalyzer.hasCanonicalJumpDest(3));
  EXPECT_FALSE(SuitabilityOnlyAnalyzer.hasCanonicalJumpDest(4));
  EXPECT_FALSE(SuitabilityOnlyAnalyzer.hasUnknownDynamicJumpTargets());
}

TEST(EVMJITFrontendAnalyzerTest,
     ConstantJumpiKeepsMatchingEntryDepthSuccessorsLiftable) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x60, 0x06, // PUSH1 0x06
      0x57,       // JUMPI
      0x00,       // STOP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *FallthroughBlock = findBlock(Analyzer, 5);
  const auto *JumpDestBlock = findBlock(Analyzer, 6);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(FallthroughBlock, nullptr);
  ASSERT_NE(JumpDestBlock, nullptr);

  EXPECT_TRUE(EntryBlock->HasConditionalJump);
  EXPECT_TRUE(EntryBlock->HasConstantJump);
  EXPECT_FALSE(EntryBlock->HasDynamicJump);
  expectPCList(EntryBlock->Successors, {5, 6});

  EXPECT_EQ(FallthroughBlock->ResolvedEntryStackDepth, 0);
  EXPECT_TRUE(FallthroughBlock->CanLiftStack);
  expectPCList(FallthroughBlock->Predecessors, {0});

  EXPECT_TRUE(JumpDestBlock->IsJumpDest);
  EXPECT_EQ(JumpDestBlock->ResolvedEntryStackDepth, 0);
  EXPECT_TRUE(JumpDestBlock->CanLiftStack);
  expectPCList(JumpDestBlock->Predecessors, {0});
}

TEST(EVMJITFrontendAnalyzerTest,
     JumpiFallthroughSharedJumpDestRequiresLiftedMerge) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PC0  PUSH1 0xaa (first incoming value)
      0x5f,       // PC2  PUSH0 (first condition offset)
      0x35,       // PC3  CALLDATALOAD
      0x60, 0x10, // PC4  PUSH1 16 (shared merge target)
      0x57,       // PC6  JUMPI
      0x50,       // PC7  POP
      0x60, 0xbb, // PC8  PUSH1 0xbb (second incoming value)
      0x60, 0x20, // PC10 PUSH1 32 (independent second condition offset)
      0x35,       // PC12 CALLDATALOAD
      0x60, 0x17, // PC13 PUSH1 23 (unused taken target)
      0x57,       // PC15 JUMPI (fallthrough = shared target)
      0x5b,       // PC16 JUMPDEST (shared merge target)
      0x5f,       // PC17 PUSH0
      0x52,       // PC18 MSTORE
      0x60, 0x20, // PC19 PUSH1 32
      0x5f,       // PC21 PUSH0
      0xf3,       // PC22 RETURN
      0x5b,       // PC23 JUMPDEST (unused taken target)
      0x00,       // PC24 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *SecondPredBlock = findBlock(Analyzer, 7);
  const auto *SharedTarget = findBlock(Analyzer, 16);
  const auto *TakenTarget = findBlock(Analyzer, 23);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(SecondPredBlock, nullptr);
  ASSERT_NE(SharedTarget, nullptr);
  ASSERT_NE(TakenTarget, nullptr);

  expectPCList(EntryBlock->Successors, {7, 16});
  expectPCList(SecondPredBlock->Successors, {16, 23});

  EXPECT_TRUE(SharedTarget->IsJumpDest);
  EXPECT_EQ(SharedTarget->ResolvedEntryStackDepth, 1);
  EXPECT_EQ(SharedTarget->FullEntryStateDepth, 1);
  EXPECT_TRUE(SharedTarget->RequiresEntryMergeState);
  EXPECT_TRUE(SharedTarget->CanLiftStack);
  expectPCList(SharedTarget->Predecessors, {0, 7});
  expectPCList(Analyzer.getPotentialEntryPredecessorsForBlock(16), {0, 7});

  EXPECT_TRUE(TakenTarget->IsJumpDest);
  EXPECT_EQ(TakenTarget->ResolvedEntryStackDepth, 1);
  EXPECT_TRUE(TakenTarget->CanLiftStack);
  expectPCList(TakenTarget->Predecessors, {7});
}

TEST(EVMJITFrontendAnalyzerTest,
     ConsecutiveJumpDestSharedMergeDisablesStackLifting) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PC0  PUSH1 0xaa (first incoming value)
      0x5f,       // PC2  PUSH0 (first condition offset)
      0x35,       // PC3  CALLDATALOAD
      0x60, 0x11, // PC4  PUSH1 17 (canonical shared merge target)
      0x57,       // PC6  JUMPI
      0x50,       // PC7  POP
      0x60, 0xbb, // PC8  PUSH1 0xbb (second incoming value)
      0x60, 0x20, // PC10 PUSH1 32 (independent second condition offset)
      0x35,       // PC12 CALLDATALOAD
      0x60, 0x18, // PC13 PUSH1 24 (unused taken target)
      0x57,       // PC15 JUMPI (fallthrough begins JUMPDEST run)
      0x5b,       // PC16 JUMPDEST (alias of PC17)
      0x5b,       // PC17 JUMPDEST (canonical shared merge target)
      0x5f,       // PC18 PUSH0
      0x52,       // PC19 MSTORE
      0x60, 0x20, // PC20 PUSH1 32
      0x5f,       // PC22 PUSH0
      0xf3,       // PC23 RETURN
      0x5b,       // PC24 JUMPDEST (unused taken target)
      0x00,       // PC25 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *SecondPredBlock = findBlock(Analyzer, 7);
  const auto *SharedTarget = findBlock(Analyzer, 17);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(SecondPredBlock, nullptr);
  ASSERT_NE(SharedTarget, nullptr);

  EXPECT_TRUE(Analyzer.hasCanonicalJumpDest(16));
  EXPECT_EQ(Analyzer.getCanonicalJumpDestPC(16), 17U);
  EXPECT_EQ(findBlock(Analyzer, 16), nullptr);
  expectPCList(EntryBlock->Successors, {7, 17});
  expectPCList(SecondPredBlock->Successors, {17, 24});

  EXPECT_TRUE(SharedTarget->IsJumpDest);
  EXPECT_EQ(SharedTarget->ResolvedEntryStackDepth, 1);
  EXPECT_TRUE(SharedTarget->RequiresEntryMergeState);
  EXPECT_FALSE(SharedTarget->CanLiftStack);
  expectPCList(SharedTarget->Predecessors, {0, 7});
}

TEST(EVMJITFrontendAnalyzerTest,
     ConsecutiveJumpDestSinglePredecessorRemainsLiftable) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x03, // PC0 PUSH1 3 (raw alias destination)
      0x56,       // PC2 JUMP
      0x5b,       // PC3 JUMPDEST (alias of PC4)
      0x5b,       // PC4 JUMPDEST (canonical target)
      0x00,       // PC5 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *CanonicalTarget = findBlock(Analyzer, 4);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(CanonicalTarget, nullptr);

  EXPECT_TRUE(Analyzer.hasCanonicalJumpDest(3));
  EXPECT_EQ(Analyzer.getCanonicalJumpDestPC(3), 4U);
  EXPECT_EQ(findBlock(Analyzer, 3), nullptr);
  expectPCList(EntryBlock->Successors, {4});

  EXPECT_TRUE(CanonicalTarget->IsJumpDest);
  EXPECT_EQ(CanonicalTarget->ResolvedEntryStackDepth, 0);
  EXPECT_FALSE(CanonicalTarget->RequiresEntryMergeState);
  EXPECT_TRUE(CanonicalTarget->CanLiftStack);
  expectPCList(CanonicalTarget->Predecessors, {0});
}

TEST(EVMJITFrontendAnalyzerTest,
     ConsecutiveJumpDestEmptySharedEntryRemainsLiftable) {
  const std::vector<uint8_t> Bytecode = {
      0x5f,       // PC0 PUSH0 (condition offset)
      0x35,       // PC1 CALLDATALOAD
      0x60, 0x09, // PC2 PUSH1 9 (canonical shared target)
      0x57,       // PC4 JUMPI
      0x60, 0x09, // PC5 PUSH1 9 (second edge target)
      0x56,       // PC7 JUMP
      0x5b,       // PC8 JUMPDEST (alias of PC9)
      0x5b,       // PC9 JUMPDEST (canonical shared target)
      0x00,       // PC10 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *SecondPredBlock = findBlock(Analyzer, 5);
  const auto *CanonicalTarget = findBlock(Analyzer, 9);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(SecondPredBlock, nullptr);
  ASSERT_NE(CanonicalTarget, nullptr);

  EXPECT_TRUE(Analyzer.hasCanonicalJumpDest(8));
  EXPECT_EQ(Analyzer.getCanonicalJumpDestPC(8), 9U);
  EXPECT_EQ(findBlock(Analyzer, 8), nullptr);
  expectPCList(EntryBlock->Successors, {5, 9});
  expectPCList(SecondPredBlock->Successors, {9});

  EXPECT_TRUE(CanonicalTarget->IsJumpDest);
  EXPECT_EQ(CanonicalTarget->ResolvedEntryStackDepth, 0);
  EXPECT_EQ(CanonicalTarget->FullEntryStateDepth, 0);
  EXPECT_TRUE(CanonicalTarget->RequiresEntryMergeState);
  EXPECT_TRUE(CanonicalTarget->CanLiftStack);
  expectPCList(CanonicalTarget->Predecessors, {0, 5});
}

TEST(EVMJITFrontendAnalyzerTest,
     DynamicJumpForcesReachableJumpDestsToFallback) {
  // The dynamic-jump source block pushes the CALLDATALOAD offset itself so it
  // does not underflow its resolved entry depth: an underflowing block (whose
  // ResolvedEntryStackDepth + MinStackHeight < 0) is never lifted, which would
  // otherwise mask the property under test -- that a *reachable JUMPDEST* is
  // forced to fall back because it is a dynamic-jump target candidate.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x60, 0x09, // PUSH1 0x09
      0x57,       // JUMPI
      0x60, 0x00, // PUSH1 0x00 (CALLDATALOAD offset)
      0x35,       // CALLDATALOAD
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *DynamicJumpBlock = findBlock(Analyzer, 5);
  const auto *JumpDestBlock = findBlock(Analyzer, 9);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(DynamicJumpBlock, nullptr);
  ASSERT_NE(JumpDestBlock, nullptr);

  EXPECT_TRUE(Analyzer.hasUnknownDynamicJumpTargets());
  EXPECT_TRUE(EntryBlock->HasConditionalJump);
  EXPECT_TRUE(DynamicJumpBlock->HasDynamicJump);
  EXPECT_TRUE(DynamicJumpBlock->CanLiftStack);

  EXPECT_TRUE(JumpDestBlock->IsJumpDest);
  EXPECT_EQ(JumpDestBlock->ResolvedEntryStackDepth, 0);
  EXPECT_FALSE(JumpDestBlock->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest,
     UnderResolvedEntryDepthInvalidatesStaticSuccessors) {
  // A block whose resolved entry depth cannot cover its own stack pops
  // (ResolvedEntryStackDepth + MinStackHeight < 0) has an untrustworthy
  // absolute depth. Any static successor whose depth may depend on that exit
  // is equally untrustworthy and must not feed entry-shape or range analysis.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PC0 PUSH1 0x01 (cond)
      0x60, 0x0b, // PC2 PUSH1 0x0b (jumpi dest)
      0x57,       // PC4 JUMPI
      0x01,       // PC5 ADD (fallthrough block pops two slots at entry depth 0)
      0x60, 0x00, // PC6 PUSH1 0x00
      0x60, 0x0b, // PC8 PUSH1 0x0b
      0x56,       // PC10 JUMP
      0x5b,       // PC11 JUMPDEST
      0x00        // PC12 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *UnderflowBlock = findBlock(Analyzer, 5);
  const auto *SuccessorBlock = findBlock(Analyzer, 11);
  ASSERT_NE(UnderflowBlock, nullptr);
  ASSERT_NE(SuccessorBlock, nullptr);

  EXPECT_EQ(UnderflowBlock->MinStackHeight, -2);
  EXPECT_EQ(UnderflowBlock->ResolvedEntryStackDepth, -1);
  EXPECT_TRUE(UnderflowBlock->HasInconsistentEntryDepth);
  EXPECT_FALSE(UnderflowBlock->CanLiftStack);
  EXPECT_TRUE(UnderflowBlock->EntryStackRanges.empty());

  EXPECT_EQ(SuccessorBlock->ResolvedEntryStackDepth, -1);
  EXPECT_TRUE(SuccessorBlock->HasInconsistentEntryDepth);
  EXPECT_FALSE(SuccessorBlock->CanLiftStack);
  EXPECT_TRUE(SuccessorBlock->EntryStackRanges.empty());
}

TEST(EVMJITFrontendAnalyzerTest,
     InvalidConstantJumpDoesNotMakeDeadDeepEntryBlocksReachable) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xff, // PC0 PUSH1 0xff (invalid jump destination)
      0x56,       // PC2 JUMP
      0x5b,       // PC3 JUMPDEST (dead predecessor)
      0x50,       // PC4 POP
      0x5b,       // PC5 JUMPDEST (dead, requires two entry slots)
      0x01,       // PC6 ADD
      0x00,       // PC7 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *SourceBlock = findBlock(Analyzer, 0);
  const auto *DeepEntryBlock = findBlock(Analyzer, 5);
  ASSERT_NE(SourceBlock, nullptr);
  ASSERT_NE(DeepEntryBlock, nullptr);
  EXPECT_FALSE(Analyzer.hasUnknownDynamicJumpTargets());
  EXPECT_FALSE(SourceBlock->HasDynamicJump);
  EXPECT_FALSE(SourceBlock->HasConstantJump);
  EXPECT_TRUE(SourceBlock->Successors.empty());
  EXPECT_EQ(DeepEntryBlock->MinStackHeight, -2);
}

TEST(EVMJITFrontendAnalyzerTest,
     HighLimbConstantJumpiKeepsOnlyFallthroughReachable) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01,                                     // PC0 condition
      0x68, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PC2 PUSH9 2^64
      0x00, 0x00,
      0x57, // PC12 JUMPI
      0x00, // PC13 STOP (fallthrough)
      0x5b, // PC14 JUMPDEST (invalid taken target is not this block)
      0x00, // PC15 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *SourceBlock = findBlock(Analyzer, 0);
  ASSERT_NE(SourceBlock, nullptr);
  EXPECT_FALSE(Analyzer.hasUnknownDynamicJumpTargets());
  EXPECT_TRUE(SourceBlock->HasConditionalJump);
  EXPECT_FALSE(SourceBlock->HasDynamicJump);
  EXPECT_FALSE(SourceBlock->HasConstantJump);
  expectPCList(SourceBlock->Successors, {13});
}

TEST(EVMJITFrontendAnalyzerTest,
     RegionHeuristicDepthTaintPropagatesAndBlocksLifting) {
  // A block whose resolved entry depth was produced by the dynamic-jump region
  // uniform-entry heuristic -- rather than by static propagation from the
  // function entry -- must never be lifted, and the taint must follow the depth
  // along static edges. Here the entry block ends in a dynamic JUMP, so the
  // JUMPDEST region behind it (PC4) is not statically reachable and receives
  // its entry depth from the heuristic. PC4 then flows statically into a plain
  // continuation block (PC10) that inherits the heuristic depth by propagation.
  // Both must be tainted and unlifted; PC10 -- a non-JUMPDEST block with a
  // clean depth-0 entry that would otherwise lift -- is the observable proof
  // that the taint propagated. Without the taint rule PC10 (entry depth 0,
  // MinStackHeight 0) would satisfy the >= 0 sanity check and lift with a
  // heuristic-derived absolute depth.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, // PC0  PUSH1 0x00 (CALLDATALOAD offset)
      0x35,       // PC2  CALLDATALOAD (dynamic jump value)
      0x56,       // PC3  JUMP (dynamic; region entry = PC4)
      0x5b,       // PC4  JUMPDEST (region target, reached only dynamically)
      0x60, 0x01, // PC5  PUSH1 0x01 (cond)
      0x60, 0x0b, // PC7  PUSH1 0x0b (jumpi dest = PC11)
      0x57,       // PC9  JUMPI (fallthrough = PC10, taken = PC11)
      0x00,       // PC10 STOP (static continuation, inherits heuristic depth)
      0x5b,       // PC11 JUMPDEST
      0x00        // PC12 STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *RegionJumpDest = findBlock(Analyzer, 4);
  const auto *Continuation = findBlock(Analyzer, 10);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(RegionJumpDest, nullptr);
  ASSERT_NE(Continuation, nullptr);

  EXPECT_TRUE(Analyzer.hasUnknownDynamicJumpTargets());

  // The entry block resolves purely from the function entry (seed depth 0), so
  // it is trusted -- never tainted -- even though it carries the dynamic jump.
  EXPECT_TRUE(EntryBlock->HasDynamicJump);
  EXPECT_FALSE(EntryBlock->EntryDepthMayComeFromDynamicDispatch);

  // The region JUMPDEST's depth is the heuristic's guess: tainted and unlifted.
  EXPECT_EQ(RegionJumpDest->ResolvedEntryStackDepth, 0);
  EXPECT_TRUE(RegionJumpDest->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_FALSE(RegionJumpDest->CanLiftStack);

  // The static successor inherits the tainted depth by propagation. It is not a
  // JUMPDEST (not a dynamic-jump candidate) and enters at a clean depth 0, so
  // only the taint keeps it out of lifting.
  EXPECT_EQ(Continuation->ResolvedEntryStackDepth, 0);
  EXPECT_EQ(Continuation->MinStackHeight, 0);
  EXPECT_FALSE(Continuation->IsDynamicJumpTargetCandidate);
  EXPECT_TRUE(Continuation->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_FALSE(Continuation->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest,
     BackwardDynamicTargetTaintsPlainStaticSuccessor) {
  // PC23 is a reachable dynamic jump. At runtime it can jump backward to PC3
  // with a hidden caller-frame value, even though PC3 also has a statically
  // resolved depth-0 predecessor from PC14. PC8 is a plain (non-JUMPDEST)
  // static successor of PC3, so the dynamic-entry depth taint must reach it and
  // prevent lifting with the incorrect static depth.
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x0e, // PC0  PUSH1 14
      0x56,       // PC2  JUMP
      0x5b,       // PC3  JUMPDEST (backward dynamic target)
      0x5f,       // PC4  PUSH0 (condition false)
      0x60, 0x0b, // PC5  PUSH1 11
      0x57,       // PC7  JUMPI
      0x60, 0x0b, // PC8  PUSH1 11 (plain static successor)
      0x56,       // PC10 JUMP
      0x5b,       // PC11 JUMPDEST
      0x50,       // PC12 POP
      0x00,       // PC13 STOP
      0x5b,       // PC14 JUMPDEST
      0x5f,       // PC15 PUSH0 (condition false)
      0x60, 0x03, // PC16 PUSH1 3
      0x57,       // PC18 JUMPI (static depth-0 edge to PC3)
      0x60, 0xaa, // PC19 PUSH1 0xaa (hidden caller-frame value)
      0x5f,       // PC21 PUSH0 (CALLDATALOAD offset)
      0x35,       // PC22 CALLDATALOAD
      0x56,       // PC23 dynamic backward JUMP to PC3
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *BackwardTarget = findBlock(Analyzer, 3);
  const auto *PlainSuccessor = findBlock(Analyzer, 8);
  const auto *DynamicSource = findBlock(Analyzer, 19);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(BackwardTarget, nullptr);
  ASSERT_NE(PlainSuccessor, nullptr);
  ASSERT_NE(DynamicSource, nullptr);

  EXPECT_TRUE(DynamicSource->HasDynamicJump);
  EXPECT_FALSE(EntryBlock->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_TRUE(BackwardTarget->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_TRUE(PlainSuccessor->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_EQ(PlainSuccessor->ResolvedEntryStackDepth, 0);
  EXPECT_FALSE(PlainSuccessor->IsDynamicJumpTargetCandidate);
  EXPECT_FALSE(PlainSuccessor->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest,
     StaticallyDisconnectedDynamicSourceDoesNotTaintLiveSuccessor) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x04, // PC0 PUSH1 4
      0x56,       // PC2 JUMP
      0xfe,       // PC3 INVALID padding
      0x5b,       // PC4 JUMPDEST
      0x60, 0x01, // PC5 PUSH1 1
      0x60, 0x0b, // PC7 PUSH1 11
      0x57,       // PC9 JUMPI
      0x00,       // PC10 STOP (live plain successor)
      0x5b,       // PC11 JUMPDEST
      0x00,       // PC12 STOP
      0x5b,       // PC13 JUMPDEST (disconnected dynamic source)
      0x5f,       // PC14 PUSH0
      0x35,       // PC15 CALLDATALOAD
      0x56,       // PC16 JUMP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *LiveSuccessor = findBlock(Analyzer, 10);
  const auto *DynamicSource = findBlock(Analyzer, 13);
  ASSERT_NE(LiveSuccessor, nullptr);
  ASSERT_NE(DynamicSource, nullptr);

  EXPECT_TRUE(DynamicSource->HasDynamicJump);
  EXPECT_FALSE(LiveSuccessor->EntryDepthMayComeFromDynamicDispatch);
  EXPECT_TRUE(LiveSuccessor->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest, HiddenEntryPrefixKeepsStaticMergesLiftable) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PUSH1 preserved prefix
      0x60, 0x01, // PUSH1 cond
      0x60, 0x0a, // PUSH1 jumpdest
      0x57,       // JUMPI
      0x60, 0x00, // PUSH1 0x00
      0x00,       // STOP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *FallthroughBlock = findBlock(Analyzer, 7);
  const auto *JumpDestBlock = findBlock(Analyzer, 10);
  ASSERT_NE(FallthroughBlock, nullptr);
  ASSERT_NE(JumpDestBlock, nullptr);

  EXPECT_EQ(FallthroughBlock->ResolvedEntryStackDepth, 1);
  EXPECT_EQ(FallthroughBlock->EntryStackDepth, 0);
  EXPECT_TRUE(FallthroughBlock->CanLiftStack);

  EXPECT_EQ(JumpDestBlock->ResolvedEntryStackDepth, 1);
  EXPECT_EQ(JumpDestBlock->EntryStackDepth, 0);
  EXPECT_TRUE(JumpDestBlock->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest,
     HiddenBoundaryUnliftingPropagatesAcrossMultipleBlocks) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PC0 PUSH1 preserved prefix
      0x60, 0x05, // PC2 PUSH1 first block
      0x56,       // PC4 JUMP
      0x5b,       // PC5 JUMPDEST
      0x60, 0x09, // PC6 PUSH1 second block
      0x56,       // PC8 JUMP
      0x5b,       // PC9 JUMPDEST
      0x60, 0x0d, // PC10 PUSH1 third block
      0x56,       // PC12 JUMP
      0x5b,       // PC13 JUMPDEST
      0x60, 0x11, // PC14 PUSH1 runtime boundary
      0x56,       // PC16 JUMP
      0x5b,       // PC17 JUMPDEST
      0x0c,       // PC18 undefined instruction
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *FirstBlock = findBlock(Analyzer, 5);
  const auto *SecondBlock = findBlock(Analyzer, 9);
  const auto *ThirdBlock = findBlock(Analyzer, 13);
  const auto *BoundaryBlock = findBlock(Analyzer, 17);
  ASSERT_NE(FirstBlock, nullptr);
  ASSERT_NE(SecondBlock, nullptr);
  ASSERT_NE(ThirdBlock, nullptr);
  ASSERT_NE(BoundaryBlock, nullptr);

  EXPECT_GT(FirstBlock->HiddenLiveInPrefixDepth, 0);
  EXPECT_GT(SecondBlock->HiddenLiveInPrefixDepth, 0);
  EXPECT_GT(ThirdBlock->HiddenLiveInPrefixDepth, 0);
  EXPECT_FALSE(BoundaryBlock->CanLiftStack);
  EXPECT_FALSE(ThirdBlock->CanLiftStack);
  EXPECT_FALSE(SecondBlock->CanLiftStack);
  EXPECT_FALSE(FirstBlock->CanLiftStack);
}

TEST(EVMJITFrontendAnalyzerTest, MergeDepthConflictDisablesLiftedEntry) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x60, 0x0a, // PUSH1 0x0a
      0x57,       // JUMPI
      0x60, 0x02, // PUSH1 0x02
      0x60, 0x0a, // PUSH1 0x0a
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *FallthroughBlock = findBlock(Analyzer, 5);
  const auto *MergeBlock = findBlock(Analyzer, 10);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(FallthroughBlock, nullptr);
  ASSERT_NE(MergeBlock, nullptr);

  EXPECT_TRUE(EntryBlock->HasConditionalJump);
  EXPECT_EQ(FallthroughBlock->ResolvedEntryStackDepth, 0);
  EXPECT_EQ(FallthroughBlock->ResolvedExitStackDepth, 1);
  EXPECT_TRUE(FallthroughBlock->CanLiftStack);

  EXPECT_TRUE(MergeBlock->IsJumpDest);
  EXPECT_EQ(MergeBlock->ResolvedEntryStackDepth, -1);
  EXPECT_EQ(MergeBlock->ResolvedExitStackDepth, -1);
  EXPECT_TRUE(MergeBlock->HasInconsistentEntryDepth);
  EXPECT_FALSE(MergeBlock->CanLiftStack);
  expectPCList(MergeBlock->Predecessors, {0, 5});
}

TEST(EVMJITFrontendAnalyzerTest,
     InconsistentMergeInvalidatesReachableSuccessors) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x60, 0x0a, // PUSH1 0x0a
      0x57,       // JUMPI
      0x60, 0x02, // PUSH1 0x02
      0x60, 0x0a, // PUSH1 0x0a
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x60, 0x03, // PUSH1 0x03
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);

  const auto *MergeBlock = findBlock(Analyzer, 10);
  const auto *SuccessorBlock = findBlock(Analyzer, 13);
  ASSERT_NE(MergeBlock, nullptr);
  ASSERT_NE(SuccessorBlock, nullptr);

  EXPECT_EQ(MergeBlock->ResolvedEntryStackDepth, -1);
  EXPECT_EQ(MergeBlock->ResolvedExitStackDepth, -1);
  EXPECT_TRUE(MergeBlock->HasInconsistentEntryDepth);
  EXPECT_FALSE(MergeBlock->CanLiftStack);

  EXPECT_TRUE(SuccessorBlock->IsJumpDest);
  EXPECT_EQ(SuccessorBlock->ResolvedEntryStackDepth, -1);
  EXPECT_EQ(SuccessorBlock->ResolvedExitStackDepth, -1);
  EXPECT_TRUE(SuccessorBlock->HasInconsistentEntryDepth);
  EXPECT_FALSE(SuccessorBlock->CanLiftStack);
  expectPCList(SuccessorBlock->Predecessors, {10});
}

TEST(EVMJITFrontendVisitorTest,
     LargeStaticWorkspaceVerifierCountsConstDirectStores) {
  const std::vector<uint8_t> Bytecode = makeLargeStaticConstMStoreBlock(16);

  MockEVMBuilder Builder;
  EXPECT_TRUE(compileWithMockBuilder(Bytecode, Builder));
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.LargeStaticWorkspaceCandidates, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedSegments, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedOps, 16U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedMLoadOps, 0U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedMStoreOps, 16U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedMStore8Ops, 0U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceMaxRequiredSize, 512U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceRejected, 0U);
#ifdef ZEN_ENABLE_EVM_MEM_LARGE_STATIC_WORKSPACE_LOWERING
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringPlans, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringMaxRequiredSize, 512U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringCoveredOps, 16U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringCoveredMStoreOps, 16U);
#else
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringPlans, 0U);
#endif
}

TEST(EVMJITFrontendVisitorTest,
     LargeStaticWorkspaceVerifierRejectsDynamicOffsets) {
  const std::vector<uint8_t> Bytecode =
      makeLargeStaticDynamicOffsetMStoreBlock(16);

  MockEVMBuilder Builder;
  EXPECT_TRUE(compileWithMockBuilder(Bytecode, Builder));
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.LargeStaticWorkspaceCandidates, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedSegments, 0U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceVerifiedOps, 0U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceRejected, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceRejectDynamicOffset, 1U);
  EXPECT_EQ(Builder.LargeStaticWorkspaceLoweringPlans, 0U);
}

TEST(EVMJITFrontendVisitorTest,
     MaterializedBlockKeepsPopDupSwapAndAddOnLogicalStack) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PUSH1 0xaa
      0x60, 0xbb, // PUSH1 0xbb
      0x60, 0x01, // PUSH1 cond
      0x60, 0x0e, // PUSH1 jumpdest
      0x57,       // JUMPI
      0x60, 0xcc, // PUSH1 0xcc
      0x60, 0x0e, // PUSH1 jumpdest
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x50,       // POP
      0x80,       // DUP1
      0x90,       // SWAP1
      0x01,       // ADD
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *TargetBlock = findBlock(Analyzer, 14);
  ASSERT_NE(TargetBlock, nullptr);
  EXPECT_FALSE(TargetBlock->CanLiftStack);
  EXPECT_EQ(TargetBlock->ResolvedEntryStackDepth, -1);
  EXPECT_EQ(TargetBlock->ResolvedExitStackDepth, -1);
  EXPECT_TRUE(TargetBlock->HasInconsistentEntryDepth);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  const auto &PopStats = Builder.accessStats(OP_POP);
  EXPECT_EQ(PopStats.StackPopCount, 0U);
  EXPECT_EQ(PopStats.StackGetCount, 0U);
  EXPECT_EQ(PopStats.StackSetCount, 0U);

  const auto &DupStats = Builder.accessStats(OP_DUP1);
  EXPECT_EQ(DupStats.StackPopCount, 0U);
  EXPECT_EQ(DupStats.StackGetCount, 0U);
  EXPECT_EQ(DupStats.StackSetCount, 0U);

  const auto &SwapStats = Builder.accessStats(OP_SWAP1);
  EXPECT_EQ(SwapStats.StackPopCount, 0U);
  EXPECT_EQ(SwapStats.StackGetCount, 0U);
  EXPECT_EQ(SwapStats.StackSetCount, 0U);

  const auto &AddStats = Builder.accessStats(OP_ADD);
  EXPECT_EQ(AddStats.StackPopCount, 0U);
  EXPECT_EQ(AddStats.StackGetCount, 0U);
  EXPECT_EQ(AddStats.StackSetCount, 0U);
}

TEST(EVMJITFrontendVisitorTest,
     LiftedJumpDestEntryDoesNotDependOnRuntimeStackDepth) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 0x01
      0x5b,       // JUMPDEST
      0x80,       // DUP1
      0x50,       // POP
      0x00        // STOP
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  const auto *JumpDestBlock = findBlock(Analyzer, 2);
  ASSERT_NE(EntryBlock, nullptr);
  ASSERT_NE(JumpDestBlock, nullptr);
  EXPECT_TRUE(EntryBlock->CanLiftStack);
  EXPECT_TRUE(JumpDestBlock->CanLiftStack);
  EXPECT_EQ(JumpDestBlock->ResolvedEntryStackDepth, 1);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  Builder.enableRuntimeStackChecks();
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);
}

TEST(EVMJITFrontendVisitorTest, FusesPushConstJumpIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x03, // PUSH1 0x03
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_JUMP), 1U);
}

TEST(EVMJITFrontendVisitorTest, FusesPushConstJumpiIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 cond
      0x60, 0x06, // PUSH1 jumpdest
      0x57,       // JUMPI
      0x00,       // STOP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_JUMPI), 1U);
}

TEST(EVMJITFrontendVisitorTest, FusesIszeroPushConstJumpiIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, // PUSH1 value
      0x15,       // ISZERO
      0x60, 0x06, // PUSH1 jumpdest
      0x57,       // JUMPI
      0x00,       // STOP
      0x5b,       // JUMPDEST
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ISZERO), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_JUMPI), 1U);
}

TEST(EVMJITFrontendVisitorTest, FusesDupAddIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, // PUSH1 base
      0x60, 0x04, // PUSH1 offset
      0x5f,       // PUSH0
      0x50,       // POP
      0x81,       // DUP2
      0x01,       // ADD
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_DUP2), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ADD), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 2U);
  EXPECT_EQ(Builder.topStackValue()[0], 0x24U);
}

TEST(EVMJITFrontendVisitorTest, FusesPushConstAddIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, // PUSH1 base
      0x60, 0x04, // PUSH1 offset
      0x01,       // ADD
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ADD), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
  EXPECT_EQ(Builder.topStackValue()[0], 0x24U);
}

TEST(EVMJITFrontendVisitorTest, FusesPushConstDupAddIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, // PUSH1 base
      0x60, 0x04, // PUSH1 offset
      0x81,       // DUP2
      0x01,       // ADD
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_DUP2), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ADD), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 2U);
  EXPECT_EQ(Builder.topStackValue()[0], 0x24U);
}

TEST(EVMJITFrontendVisitorTest, FusesPushConstMStoreIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PUSH1 value
      0x60, 0x20, // PUSH1 addr
      0x52,       // MSTORE
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0U);
  EXPECT_EQ(Builder.mstoreCount(), 1U);
  EXPECT_EQ(Builder.lastMStore().Addr[0], 0x20U);
  EXPECT_EQ(Builder.lastMStore().Value[0], 0xaaU);
}

TEST(EVMJITFrontendVisitorTest, FusesAddMStoreIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa, // PUSH1 value
      0x60, 0x20, // PUSH1 base
      0x60, 0x04, // PUSH1 delta
      0x01,       // ADD
      0x52,       // MSTORE
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ADD), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0U);
  EXPECT_EQ(Builder.mstoreCount(), 1U);
  EXPECT_EQ(Builder.lastMStore().Addr[0], 0x24U);
  EXPECT_EQ(Builder.lastMStore().Value[0], 0xaaU);
}

TEST(EVMJITFrontendVisitorTest, FusesLinearMStoreNextMotifIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, // PUSH1 stride
      0x60, 0x40, // PUSH1 current
      0x80,       // DUP1
      0x80,       // DUP1
      0x52,       // MSTORE
      0x81,       // DUP2
      0x01,       // ADD
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_DUP1), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_DUP2), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_ADD), 1U);
  EXPECT_EQ(Builder.mstoreCount(), 1U);
  EXPECT_EQ(Builder.lastMStore().Addr[0], 0x40U);
  EXPECT_EQ(Builder.lastMStore().Value[0], 0x40U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 2U);
  EXPECT_EQ(Builder.topStackValue()[0], 0x60U);
}

TEST(EVMJITFrontendVisitorTest, PlansLinearMStore8NextMotifMemoryPrecheck) {
  const std::vector<uint8_t> Bytecode = {
      0x5f, // PUSH0 calldata offset for stride
      0x35, // CALLDATALOAD
      0x5f, // PUSH0 current
      0x80, // DUP1
      0x80, // DUP1
      0x53, // MSTORE8
      0x81, // DUP2
      0x01, // ADD
      0x80, // DUP1
      0x80, // DUP1
      0x53, // MSTORE8
      0x81, // DUP2
      0x01, // ADD
      0x00  // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.linearPrecheckPlanCount(), 1U);
  EXPECT_EQ(Builder.lastLinearPrecheckAccessWidth(), 1U);
  EXPECT_EQ(Builder.lastLinearPrecheckCoveredDirectOps(), 2U);
  EXPECT_FALSE(Builder.lastLinearPrecheckValueEqualsFirstAddr());
  EXPECT_EQ(Builder.linearPrecheckPrepareCount(), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE8), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 2U);
}

TEST(EVMJITFrontendVisitorTest, ConstMcopyRangesUseBlockMemoryPrecheck) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x20, // PUSH1 length 32
      0x60, 0x00, // PUSH1 src 0
      0x60, 0x40, // PUSH1 dest 64
      0x5e,       // MCOPY
      0x60, 0x10, // PUSH1 length 16
      0x60, 0x20, // PUSH1 src 32
      0x60, 0x60, // PUSH1 dest 96
      0x5e,       // MCOPY
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.constPrecheckPlanCount(), 1U);
  EXPECT_EQ(Builder.constPrecheckCoveredDirectOps(), 2U);
  EXPECT_EQ(Builder.constPrecheckMaxRequiredSize(), 0x70U);
  EXPECT_EQ(Builder.mcopyCount(), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0U);
}

TEST(EVMJITFrontendVisitorTest,
     ZeroLengthMcopyDoesNotEnterBlockMemoryPrecheckPlan) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, // PUSH1 length 0
      0x60, 0xff, // PUSH1 src
      0x60, 0xff, // PUSH1 dest
      0x5e,       // MCOPY
      0x60, 0x01, // PUSH1 value
      0x60, 0x00, // PUSH1 addr
      0x52,       // MSTORE
      0x60, 0x02, // PUSH1 value
      0x60, 0x20, // PUSH1 addr
      0x52,       // MSTORE
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.constPrecheckPlanCount(), 1U);
  EXPECT_EQ(Builder.constPrecheckCoveredDirectOps(), 2U);
  EXPECT_EQ(Builder.constPrecheckMaxRequiredSize(), 0x40U);
  EXPECT_EQ(Builder.mcopyCount(), 1U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0U);
}

TEST(EVMJITFrontendVisitorTest, MSizeStopsConstMemoryPrecheckBeforeMcopy) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 value
      0x60, 0x00, // PUSH1 addr
      0x52,       // MSTORE
      0x59,       // MSIZE
      0x50,       // POP
      0x60, 0x20, // PUSH1 length
      0x60, 0x00, // PUSH1 src
      0x60, 0x40, // PUSH1 dest
      0x5e,       // MCOPY
      0x60, 0x02, // PUSH1 value
      0x60, 0x80, // PUSH1 addr
      0x52,       // MSTORE
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.constPrecheckPlanCount(), 0U);
  EXPECT_EQ(Builder.mcopyCount(), 1U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0U);
}

TEST(EVMJITFrontendVisitorTest, FusesCallerSlotKeccakIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x33,       // CALLER
      0x60, 0x00, // PUSH1 base
      0x52,       // MSTORE
      0x60, 0x05, // PUSH1 slot
      0x60, 0x20, // PUSH1 base + 0x20
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x60, 0x00, // PUSH1 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_CALLER), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_KECCAK256), 1U);
  EXPECT_EQ(Builder.keccakCallerSlotCount(), 1U);
  EXPECT_EQ(Builder.keccakCount(), 0U);
  EXPECT_EQ(Builder.mstoreCount(), 0U);
  EXPECT_EQ(Builder.lastKeccakCallerSlot().Offset[0], 0U);
  EXPECT_EQ(Builder.lastKeccakCallerSlot().Slot[0], 5U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest, FusesCallDataSlotKeccakIntoMeteredRange) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x04, // PUSH1 calldata offset
      0x35,       // CALLDATALOAD
      0x60, 0x00, // PUSH1 base
      0x52,       // MSTORE
      0x60, 0x07, // PUSH1 slot
      0x60, 0x20, // PUSH1 base + 0x20
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x60, 0x00, // PUSH1 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_PUSH1), 6U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_CALLDATALOAD), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_KECCAK256), 1U);
  EXPECT_EQ(Builder.keccakCallDataSlotCount(), 1U);
  EXPECT_EQ(Builder.keccakCount(), 0U);
  EXPECT_EQ(Builder.mstoreCount(), 0U);
  EXPECT_EQ(Builder.lastKeccakCallDataSlot().Offset[0], 0U);
  EXPECT_EQ(Builder.lastKeccakCallDataSlot().CallDataOffset[0], 4U);
  EXPECT_EQ(Builder.lastKeccakCallDataSlot().Slot[0], 7U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest,
     KeepsGenericKeccakPathWhenTwoWordLayoutDoesNotMatch) {
  const std::vector<uint8_t> Bytecode = {
      0x33,       // CALLER
      0x60, 0x00, // PUSH1 base
      0x52,       // MSTORE
      0x60, 0x05, // PUSH1 slot
      0x60, 0x21, // PUSH1 mismatched base + 0x21
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x60, 0x00, // PUSH1 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.meteredRanges().empty());
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_CALLER), 1U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 2U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_KECCAK256), 1U);
  EXPECT_EQ(Builder.keccakCallerSlotCount(), 0U);
  EXPECT_EQ(Builder.keccakCallDataSlotCount(), 0U);
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest, PrechecksGenericHashPrepMStoreRegion) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PUSH1 word0
      0x5f,       // PUSH0 base
      0x52,       // MSTORE
      0x60, 0x22, // PUSH1 word1
      0x60, 0x20, // PUSH1 base + 0x20
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x5f,       // PUSH0 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  ASSERT_EQ(Builder.constPrecheckPlans().size(), 1U);
  EXPECT_EQ(Builder.constPrecheckPlans()[0].MaxRequiredSize, 64U);
  EXPECT_EQ(Builder.constPrecheckPlans()[0].CoveredDirectOps, 2U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest, PrechecksNonZeroHashPrepMStoreRegion) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PUSH1 word0
      0x60, 0x40, // PUSH1 base
      0x52,       // MSTORE
      0x60, 0x22, // PUSH1 word1
      0x60, 0x60, // PUSH1 base + 0x20
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x60, 0x40, // PUSH1 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  ASSERT_EQ(Builder.constPrecheckPlans().size(), 1U);
  EXPECT_EQ(Builder.constPrecheckPlans()[0].MaxRequiredSize, 128U);
  EXPECT_EQ(Builder.constPrecheckPlans()[0].CoveredDirectOps, 2U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest,
     DoesNotPrecheckHashPrepWhenKeccakRangeIsNotCovered) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PUSH1 word0
      0x5f,       // PUSH0 base
      0x52,       // MSTORE
      0x60, 0x22, // PUSH1 word1
      0x5f,       // PUSH0 same base, leaves 0x20..0x3f untouched
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x5f,       // PUSH0 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.constPrecheckPlans().empty());
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest,
     DoesNotPrecheckHashPrepWhenWordStoreOffsetsDoNotMatch) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PUSH1 word0
      0x5f,       // PUSH0 base
      0x52,       // MSTORE
      0x60, 0x22, // PUSH1 unrelated word
      0x60, 0x40, // PUSH1 outside the two-word preimage
      0x52,       // MSTORE
      0x60, 0x40, // PUSH1 0x40
      0x5f,       // PUSH0 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.constPrecheckPlans().empty());
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest, DoesNotPrecheckHashPrepWithoutTwoWordStores) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x11, // PUSH1 byte0
      0x60, 0x3f, // PUSH1 last byte in the two-word range
      0x53,       // MSTORE8
      0x60, 0x22, // PUSH1 byte1
      0x60, 0x3e, // PUSH1 previous byte in the two-word range
      0x53,       // MSTORE8
      0x60, 0x40, // PUSH1 0x40
      0x5f,       // PUSH0 base
      0x20,       // KECCAK256
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_TRUE(Builder.constPrecheckPlans().empty());
  EXPECT_EQ(Builder.keccakCount(), 1U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
}

TEST(EVMJITFrontendVisitorTest,
     ImplicitStopMaterializesLiftedStackOnFallthrough) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0xaa // PUSH1 0xaa
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  ASSERT_NE(EntryBlock, nullptr);
  EXPECT_TRUE(EntryBlock->CanLiftStack);
  EXPECT_EQ(EntryBlock->ResolvedExitStackDepth, 1);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);
  EXPECT_EQ(Builder.runtimeStackDepth(), 1U);
  EXPECT_EQ(Builder.topStackValue()[0], 0xaaU);
}

TEST(EVMJITFrontendVisitorTest,
     UndefinedInstructionAfterProducerDoesNotTriggerStackOverflowTrap) {
  const std::vector<uint8_t> Bytecode = {
      0x30, // ADDRESS
      0x2a  // undefined
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  ASSERT_NE(EntryBlock, nullptr);
  EXPECT_TRUE(EntryBlock->HasUndefinedInstr);
  EXPECT_EQ(EntryBlock->MaxStackHeight, 1);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  Builder.enableRuntimeStackChecks();
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_TRUE(Builder.Undefined);
}

TEST(EVMJITFrontendVisitorTest, TruncatedPushIsRightPaddedWithZeros) {
  const std::vector<uint8_t> Bytecode = {
      0x62, 0x12, 0x34 // PUSH3 0x12 0x34 <missing byte>
  };

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *EntryBlock = findBlock(Analyzer, 0);
  ASSERT_NE(EntryBlock, nullptr);
  EXPECT_EQ(EntryBlock->ResolvedExitStackDepth, 1);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);
  ASSERT_TRUE(Builder.hasLastPushValue());
  EXPECT_EQ(Builder.lastPushValue()[0], 0x123400ULL);
  EXPECT_EQ(Builder.lastPushValue()[1], 0ULL);
  EXPECT_EQ(Builder.lastPushValue()[2], 0ULL);
  EXPECT_EQ(Builder.lastPushValue()[3], 0ULL);
}

} // namespace
