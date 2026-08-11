// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "action/evm_bytecode_visitor.h"
#include "compiler/cgir/cg_function.h"
#include "compiler/cgir/pass/dead_cg_instruction_elim.h"
#include "compiler/evm_frontend/evm_analyzer.h"
#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/evm_frontend/evm_memory_analysis.h"
#include "compiler/evm_frontend/evm_memory_facts.h"
#include "compiler/evm_frontend/evm_memory_grouping.h"
#include "compiler/evm_frontend/evm_memory_precheck.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/evm_frontend/evm_runtime_helper_effects.h"
#include "compiler/mir/module.h"
#include "compiler/mir/pass/verifier.h"

#include "llvm/Support/raw_ostream.h"
#include <gtest/gtest.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/CodeGen/TargetOpcodes.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace COMPILER {

struct MemoryExpansionPlannerTestPeer {
  static bool hasLinearRegions(const MemoryExpansionPlanner &Planner) {
    return Planner.LinearRegions != nullptr;
  }
  static bool hasGuaranteedExtent(const MemoryExpansionPlanner &Planner) {
    return Planner.GuaranteedExtent != nullptr;
  }
  static bool hasDeadStores(const MemoryExpansionPlanner &Planner) {
    return Planner.DeadStores != nullptr;
  }
  static bool hasLoadForwarding(const MemoryExpansionPlanner &Planner) {
    return Planner.LoadForwarding != nullptr;
  }
};

} // namespace COMPILER

namespace {

using COMPILER::EVMAnalyzer;
using COMPILER::EVMMirBuilder;
using COMPILER::EVMValueRange;
using zen::common::BinaryOperator;
using zen::common::CompareOperator;

#ifdef ZEN_ENABLE_MULTIPASS_JIT_LOGGING
class CapturingLogger final : public zen::utils::ILogger {
public:
  void trace(const std::string &, const char *, int, const char *) override {}
  void debug(const std::string &Message, const char *, int,
             const char *) override {
    DebugMessages.push_back(Message);
  }
  void info(const std::string &, const char *, int, const char *) override {}
  void warn(const std::string &, const char *, int, const char *) override {}
  void error(const std::string &, const char *, int, const char *) override {}
  void fatal(const std::string &, const char *, int, const char *) override {}

  std::vector<std::string> DebugMessages;
};
#endif

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

struct MirControlFlowStats {
  bool Compiled = false;
  uint32_t BasicBlocks = 0;
  uint32_t Switches = 0;
};

MirControlFlowStats
compileMirControlFlowStats(const std::vector<uint8_t> &Bytecode) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setGasMeteringEnabled(false);
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
  MirControlFlowStats Stats;
  Stats.Compiled = Builder.compile(&Ctx);
  Stats.BasicBlocks = Func.getNumBasicBlocks();
  for (COMPILER::MBasicBlock *BB : Func) {
    for (COMPILER::MInstruction *Inst : *BB) {
      if (Inst->getKind() == COMPILER::MInstruction::SWITCH) {
        ++Stats.Switches;
      }
    }
  }
  return Stats;
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

TEST(EVMMirBuilderControlFlowTest, FullDynamicDispatchIsSharedAcrossSources) {
  constexpr uint32_t DynamicSources = 16;
  std::vector<uint8_t> Bytecode;
  for (uint32_t Index = 0; Index < DynamicSources; ++Index) {
    Bytecode.push_back(OP_JUMPDEST);
    Bytecode.push_back(OP_PUSH0);
    Bytecode.push_back(OP_CALLDATALOAD);
    Bytecode.push_back(OP_JUMP);
  }

  const MirControlFlowStats Stats = compileMirControlFlowStats(Bytecode);
  ASSERT_TRUE(Stats.Compiled);
  EXPECT_LT(Stats.Switches, DynamicSources);
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

TEST(MFunctionBasicBlockTest, MembershipUsesIndexAndPointerIdentity) {
  COMPILER::EVMFrontendContext Ctx;
  COMPILER::MFunction Func(Ctx, 0);
  COMPILER::MBasicBlock *First = Func.createBasicBlock();
  COMPILER::MBasicBlock *Second = Func.createBasicBlock();

  EXPECT_FALSE(Func.containsBasicBlock(First));
  Func.appendBlock(First);
  EXPECT_TRUE(Func.containsBasicBlock(First));

  EXPECT_EQ(Second->getIdx(), 0U);
  EXPECT_FALSE(Func.containsBasicBlock(Second));
  Func.appendBlock(Second);
  EXPECT_TRUE(Func.containsBasicBlock(Second));

  EXPECT_EQ(Func.getNumBasicBlocks(), 2U);
  EXPECT_EQ(Func.getBasicBlock(First->getIdx()), First);
  EXPECT_EQ(Func.getBasicBlock(Second->getIdx()), Second);
}

TEST(EVMMirBuilderBasicBlockTest, InitDoesNotReappendEntryBlock) {
  MirBuilderConstFoldHarness Harness;

  EXPECT_EQ(Harness.Func.getNumBasicBlocks(), 1U);
}

TEST(CgDeadInstructionElimTest, PreservesExternalUsesAndDeletesSelfUses) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.initialize();
  COMPILER::MFunction MFunc(Ctx, 0);
  COMPILER::CgFunction CgFunc(Ctx, MFunc);
  COMPILER::CgBasicBlock *FirstDefBB = CgFunc.createCgBasicBlock();
  COMPILER::CgBasicBlock *SecondDefBB = CgFunc.createCgBasicBlock();
  COMPILER::CgBasicBlock *SelfCopyBB = CgFunc.createCgBasicBlock();
  COMPILER::CgBasicBlock *UseBB = CgFunc.createCgBasicBlock();
  CgFunc.appendCgBasicBlock(FirstDefBB);
  CgFunc.appendCgBasicBlock(SecondDefBB);
  CgFunc.appendCgBasicBlock(SelfCopyBB);
  CgFunc.appendCgBasicBlock(UseBB);
  FirstDefBB->addSuccessorWithoutProb(SecondDefBB);
  SecondDefBB->addSuccessorWithoutProb(SelfCopyBB);
  SelfCopyBB->addSuccessorWithoutProb(UseBB);

  auto &MRI = CgFunc.getRegInfo();
  const auto &TII = CgFunc.getTargetInstrInfo();
  auto AddInstruction =
      [&](COMPILER::CgBasicBlock &BB, unsigned Opcode,
          llvm::SmallVector<COMPILER::CgOperand, 2> Operands) {
        return CgFunc.createCgInstruction(BB, TII.get(Opcode), Operands,
                                          /*no_implicit=*/true);
      };

  COMPILER::CgRegister LiveReg = MRI.createIncompleteVirtualRegister();
  AddInstruction(*FirstDefBB, llvm::TargetOpcode::IMPLICIT_DEF,
                 {COMPILER::CgOperand::createRegOperand(LiveReg, true)});
  AddInstruction(*SecondDefBB, llvm::TargetOpcode::IMPLICIT_DEF,
                 {COMPILER::CgOperand::createRegOperand(LiveReg, true)});

  COMPILER::CgRegister SelfReg = MRI.createIncompleteVirtualRegister();
  AddInstruction(*SelfCopyBB, llvm::TargetOpcode::COPY,
                 {COMPILER::CgOperand::createRegOperand(SelfReg, true),
                  COMPILER::CgOperand::createRegOperand(SelfReg, false)});

  COMPILER::CgInstruction *InlineAsm = AddInstruction(
      *UseBB, llvm::TargetOpcode::INLINEASM,
      {COMPILER::CgOperand::createRegOperand(LiveReg, false,
                                             /*IsImplicit=*/true)});

  MRI.freezeReservedRegs(CgFunc);
  (void)COMPILER::CgDeadCgInstructionElim(CgFunc);
  EXPECT_FALSE(FirstDefBB->empty());
  EXPECT_FALSE(SecondDefBB->empty());
  EXPECT_TRUE(SelfCopyBB->empty());
  EXPECT_FALSE(UseBB->empty());

  InlineAsm->eraseFromParent();
  (void)COMPILER::CgDeadCgInstructionElim(CgFunc);
  EXPECT_TRUE(FirstDefBB->empty());
  EXPECT_TRUE(SecondDefBB->empty());
  EXPECT_TRUE(SelfCopyBB->empty());
  EXPECT_TRUE(UseBB->empty());
}

void expectPCList(const std::vector<uint64_t> &Actual,
                  std::initializer_list<uint64_t> Expected) {
  ASSERT_EQ(Actual.size(), Expected.size());
  size_t Index = 0;
  for (uint64_t ExpectedPC : Expected) {
    EXPECT_EQ(Actual[Index], ExpectedPC) << "mismatch at index " << Index;
    ++Index;
  }
}

#if defined(ZEN_ENABLE_MULTIPASS_JIT_LOGGING) &&                               \
    defined(ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK)
size_t countRuntimeCalls(const COMPILER::MFunction &Func, uint64_t Address) {
  std::string Mir;
  llvm::raw_string_ostream OS(Mir);
  Func.print(OS);
  OS.flush();

  const std::string Needle =
      "target = const.i64 " + std::to_string(Address) + ", ";
  size_t Count = 0;
  for (size_t Pos = Mir.find(Needle); Pos != std::string::npos;
       Pos = Mir.find(Needle, Pos + Needle.size())) {
    ++Count;
  }
  return Count;
}

std::optional<size_t>
countExpandMemoryCallsForBytecode(const std::vector<uint8_t> &Bytecode) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
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
    return std::nullopt;
  }

  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  return countRuntimeCalls(
      Func, COMPILER::getFunctionAddress(RuntimeFunctions.ExpandMemoryNoGas));
}
#endif

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

COMPILER::MemoryFacts collectMemoryFacts(const std::vector<uint8_t> &Bytecode,
                                         evmc_revision Revision = EVMC_CANCUN) {
  COMPILER::MemoryFactsBuilder FactsBuilder(Revision);
  FactsBuilder.reset(Bytecode.size());
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
  COMPILER::MemoryFactsBuilder FactsBuilder(EVMC_CANCUN);
  FactsBuilder.reset(Bytecode.size());
  const std::vector<uint64_t> DynamicDispatchSources =
      Analyzer.getDynamicJumpDispatchSourceBlocks();
  const auto &Blocks = Analyzer.getBlockInfos();
  for (const auto &[EntryPC, BlockInfo] : Blocks) {
    const bool HasReliableEntryStack =
        BlockInfo.ResolvedEntryStackDepth >= 0 &&
        !BlockInfo.HasInconsistentEntryDepth &&
        !BlockInfo.EntryDepthMayComeFromDynamicDispatch;
    const int32_t EntryDepth =
        HasReliableEntryStack ? BlockInfo.ResolvedEntryStackDepth : 0;
    std::vector<COMPILER::MemoryEntryValue> EntryValues =
        EntryAddresses.getEntryValues(EntryPC,
                                      static_cast<uint32_t>(EntryDepth));
    const std::vector<uint64_t> PotentialPredecessors =
        Analyzer.getPotentialEntryPredecessorsForBlock(EntryPC);
    const bool PredecessorsAreStatic =
        Analyzer.getDynamicJumpSourceBlocksForBlock(EntryPC).empty();
    const bool PredecessorsComplete =
        Analyzer.dynamicJumpTargetPredecessorsAreComplete(
            EntryPC, DynamicDispatchSources);
    FactsBuilder.beginBlock(EntryPC, BlockInfo.BodyStartPC, BlockInfo.BodyEndPC,
                            EntryValues, BlockInfo.Successors,
                            PotentialPredecessors, HasReliableEntryStack,
                            PredecessorsComplete, PredecessorsAreStatic);

    if (!HasReliableEntryStack) {
      continue;
    }

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
  bool HasCompleteOpcodeFacts = true;
  bool PredecessorsComplete = true;
  bool PredecessorsAreStatic = true;
};

COMPILER::MemoryFacts
collectManualBlockMemoryFacts(const std::vector<uint8_t> &Bytecode,
                              const std::vector<MemoryFactBlockSpec> &Blocks) {
  COMPILER::MemoryFactsBuilder FactsBuilder;
  FactsBuilder.reset(Bytecode.size());
  const uint8_t *Data = Bytecode.empty() ? nullptr : Bytecode.data();
  for (const MemoryFactBlockSpec &Block : Blocks) {
    FactsBuilder.beginBlock(
        Block.EntryPC, Block.BodyStartPC, Block.BodyEndPC, {}, Block.Successors,
        Block.Predecessors, Block.HasCompleteOpcodeFacts,
        Block.PredecessorsComplete, Block.PredecessorsAreStatic);

    if (!Block.HasCompleteOpcodeFacts) {
      continue;
    }

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

TEST(EVMMemoryFactsBuilderTest, SeparatesPlacementBaseAndLogicalSizeEffects) {
  const std::vector<uint8_t> MStoreBytecode = {OP_PUSH1, 0x2a, OP_PUSH1, 0x80,
                                               OP_MSTORE};
  COMPILER::MemoryFacts MStoreFacts = collectMemoryFacts(MStoreBytecode);

  ASSERT_EQ(MStoreFacts.Ops.size(), 1u);
  const COMPILER::MemoryEffectSummary &MStore =
      MStoreFacts.Ops[0].ObservableEffects;
  EXPECT_EQ(MStore.StackPop, 2u);
  EXPECT_EQ(MStore.StackPush, 0u);
  EXPECT_TRUE(MStore.readsOrWritesMemory());
  EXPECT_TRUE(MStore.mayGrowMemory());
  EXPECT_TRUE(MStore.mayRebaseMemory());
  EXPECT_TRUE(MStore.chargesDynamicGas());
  EXPECT_TRUE(MStore.mayExhaustGas());
  EXPECT_FALSE(MStore.requiresOrderToken());
  EXPECT_TRUE(MStore.preservesLogicalSizeProof());
  EXPECT_FALSE(MStore.preservesCachedMemoryBase());

  COMPILER::MemoryFacts GasFacts = collectMemoryFacts({OP_GAS, OP_POP});
  ASSERT_EQ(GasFacts.Ops.size(), 1u);
  const COMPILER::MemoryEffectSummary &Gas = GasFacts.Ops[0].ObservableEffects;
  EXPECT_TRUE(Gas.observesGas());
  EXPECT_TRUE(Gas.requiresOrderToken());
  EXPECT_TRUE(Gas.preservesLogicalSizeProof());
  EXPECT_TRUE(Gas.preservesCachedMemoryBase());

  COMPILER::MemoryFacts MSizeFacts = collectMemoryFacts({OP_MSIZE, OP_POP});
  ASSERT_EQ(MSizeFacts.Ops.size(), 1u);
  const COMPILER::MemoryEffectSummary &MSize =
      MSizeFacts.Ops[0].ObservableEffects;
  EXPECT_TRUE(MSize.observesMemorySize());
  EXPECT_TRUE(MSize.requiresOrderToken());
  EXPECT_TRUE(MSize.preservesLogicalSizeProof());
  EXPECT_TRUE(MSize.preservesCachedMemoryBase());
}

TEST(EVMMemoryFactsBuilderTest, RecordsDynamicGasOpcodesAsOrderEffects) {
  const evmc_opcode Opcodes[] = {OP_EXP, OP_BALANCE, OP_EXTCODESIZE,
                                 OP_EXTCODEHASH, OP_SLOAD};
  for (evmc_opcode Opcode : Opcodes) {
    COMPILER::MemoryFacts Facts =
        collectMemoryFacts({static_cast<uint8_t>(Opcode)});
    ASSERT_EQ(Facts.Ops.size(), 1u) << static_cast<int>(Opcode);
    const COMPILER::MemoryEffectSummary &Effect =
        Facts.Ops[0].ObservableEffects;
    EXPECT_TRUE(Effect.observesGas());
    EXPECT_TRUE(Effect.chargesDynamicGas());
    EXPECT_TRUE(Effect.mayExhaustGas());
    EXPECT_TRUE(Effect.requiresOrderToken());
    EXPECT_TRUE(Effect.mayTrapOrHalt());
    EXPECT_TRUE(Effect.preservesLogicalSizeProof());
  }
}

TEST(EVMMemoryFactsBuilderTest, RecordsSelfDestructGasAndTerminationEffects) {
  COMPILER::MemoryFacts Facts = collectMemoryFacts({OP_SELFDESTRUCT});
  ASSERT_EQ(Facts.Ops.size(), 1u);
  const COMPILER::MemoryEffectSummary &Effect = Facts.Ops[0].ObservableEffects;
  EXPECT_TRUE(Effect.observesGas());
  EXPECT_TRUE(Effect.chargesDynamicGas());
  EXPECT_TRUE(Effect.mayExhaustGas());
  EXPECT_TRUE(Effect.requiresOrderToken());
  EXPECT_TRUE(Effect.mayTrapOrHalt());
  EXPECT_TRUE(Effect.terminatesFrame());
}

TEST(EVMMemoryFactsBuilderTest, TreatsPreForkCallOpcodesAsTerminatingBarriers) {
  struct InvalidOpcodeCase {
    evmc_opcode Opcode;
    evmc_revision Revision;
  };
  const InvalidOpcodeCase Cases[] = {
      {OP_DELEGATECALL, EVMC_FRONTIER},
      {OP_STATICCALL, EVMC_SPURIOUS_DRAGON},
  };

  for (const InvalidOpcodeCase &Case : Cases) {
    COMPILER::MemoryFacts Facts =
        collectMemoryFacts({static_cast<uint8_t>(Case.Opcode)}, Case.Revision);
    ASSERT_EQ(Facts.Ops.size(), 1u);
    const COMPILER::MemoryOp &Op = Facts.Ops[0];
    EXPECT_EQ(Op.Kind, COMPILER::MemoryOpKind::Other);
    EXPECT_EQ(Op.Effect, COMPILER::MemoryEffect::Unknown);
    EXPECT_TRUE(Op.ObservableEffects.requiresOrderToken());
    EXPECT_TRUE(Op.ObservableEffects.mayTrapOrHalt());
    EXPECT_TRUE(Op.ObservableEffects.terminatesFrame());
    EXPECT_TRUE(Op.Reads.empty());
    EXPECT_TRUE(Op.Writes.empty());
  }
}

TEST(EVMRuntimeMemoryHelperContractTest,
     SeparatesPreparedRangeAndExpansionHelperContracts) {
  using COMPILER::RuntimeMemoryHelperId;
  using COMPILER::RuntimeProofRequirementFlag;
  const COMPILER::RuntimeMemoryHelperContract Copy =
      COMPILER::getRuntimeMemoryHelperContract(
          RuntimeMemoryHelperId::CodeCopyNoExpand);
  EXPECT_TRUE(Copy.hasRequirement(RuntimeProofRequirementFlag::LogicalSize));
  EXPECT_TRUE(Copy.hasRequirement(RuntimeProofRequirementFlag::AccessRange));
  EXPECT_TRUE(
      Copy.hasRequirement(RuntimeProofRequirementFlag::DynamicGasCharged));
  EXPECT_TRUE(Copy.Effects.has(COMPILER::MemoryEffectFlag::WritesMemory));
  EXPECT_FALSE(Copy.Effects.mayGrowMemory());

  const COMPILER::RuntimeMemoryHelperContract Expand =
      COMPILER::getRuntimeMemoryHelperContract(
          RuntimeMemoryHelperId::ExpandMemoryNoGas);
  EXPECT_TRUE(
      Expand.hasRequirement(RuntimeProofRequirementFlag::DynamicGasCharged));
  EXPECT_TRUE(
      Expand.hasRequirement(RuntimeProofRequirementFlag::BoundsValidated));
  EXPECT_TRUE(Expand.EstablishesLogicalSize);
  EXPECT_TRUE(Expand.Effects.mayGrowMemory());
  EXPECT_TRUE(Expand.Effects.mayRebaseMemory());
}

TEST(EVMRuntimeMemoryHelperContractTest,
     RecordsTwoWordKeccakDynamicGasAndFailureEffects) {
  const COMPILER::RuntimeMemoryHelperContract Contract =
      COMPILER::getRuntimeMemoryHelperContract(
          COMPILER::RuntimeMemoryHelperId::TwoWordKeccakNoExpand);
  EXPECT_TRUE(Contract.Valid);
  EXPECT_TRUE(Contract.Effects.observesGas());
  EXPECT_TRUE(Contract.Effects.chargesDynamicGas());
  EXPECT_TRUE(Contract.Effects.mayExhaustGas());
  EXPECT_TRUE(Contract.Effects.mayTrapOrHalt());
  EXPECT_TRUE(Contract.Effects.requiresOrderToken());
}

TEST(EVMRuntimeMemoryHelperContractTest,
     RequiresIndependentCallArgumentAndReturnProofs) {
  using COMPILER::RuntimeMemoryHelperId;
  using COMPILER::RuntimeProofRequirementFlag;
  const COMPILER::RuntimeMemoryHelperContract Contract =
      COMPILER::getRuntimeMemoryHelperContract(
          RuntimeMemoryHelperId::CallNoExpand);
  const RuntimeProofRequirementFlag Required[] = {
      RuntimeProofRequirementFlag::LogicalSize,
      RuntimeProofRequirementFlag::CallArgumentsRange,
      RuntimeProofRequirementFlag::CallReturnRange,
      RuntimeProofRequirementFlag::OrderToken,
  };
  EXPECT_TRUE(Contract.Valid);
  for (RuntimeProofRequirementFlag Missing : Required) {
    COMPILER::RuntimeProofToken Incomplete;
    for (RuntimeProofRequirementFlag Requirement : Required) {
      if (Requirement != Missing) {
        Incomplete.establish(Requirement);
      }
    }
    EXPECT_FALSE(
        COMPILER::satisfiesRuntimeMemoryHelperContract(Contract, Incomplete));
  }
}

TEST(EVMRuntimeMemoryHelperContractTest,
     RejectsSelectionsMissingAnyPreparedHelperRequirement) {
  using COMPILER::RuntimeMemoryHelperId;
  using COMPILER::RuntimeProofRequirementFlag;
  const COMPILER::RuntimeMemoryHelperContract Contract =
      COMPILER::getRuntimeMemoryHelperContract(
          RuntimeMemoryHelperId::CallDataCopyNoExpand);
  const RuntimeProofRequirementFlag Required[] = {
      RuntimeProofRequirementFlag::LogicalSize,
      RuntimeProofRequirementFlag::AccessRange,
      RuntimeProofRequirementFlag::DynamicGasCharged,
  };
  COMPILER::RuntimeProofToken Complete;
  for (RuntimeProofRequirementFlag Requirement : Required) {
    Complete.establish(Requirement);
  }
  EXPECT_TRUE(
      COMPILER::satisfiesRuntimeMemoryHelperContract(Contract, Complete));
  for (RuntimeProofRequirementFlag Missing : Required) {
    COMPILER::RuntimeProofToken Incomplete;
    for (RuntimeProofRequirementFlag Requirement : Required) {
      if (Requirement != Missing) {
        Incomplete.establish(Requirement);
      }
    }
    EXPECT_FALSE(
        COMPILER::satisfiesRuntimeMemoryHelperContract(Contract, Incomplete));
  }
}

TEST(EVMRuntimeMemoryHelperContractTest,
     EveryPreparedHelperRejectsEachMissingObligation) {
  using COMPILER::RuntimeMemoryHelperId;
  using COMPILER::RuntimeProofRequirementFlag;

  const auto ExpectExactRequirements =
      [](RuntimeMemoryHelperId Helper,
         std::initializer_list<RuntimeProofRequirementFlag> Requirements) {
        const COMPILER::RuntimeMemoryHelperContract Contract =
            COMPILER::getRuntimeMemoryHelperContract(Helper);
        ASSERT_TRUE(Contract.Valid);

        COMPILER::RuntimeProofToken Complete;
        for (RuntimeProofRequirementFlag Requirement : Requirements) {
          Complete.establish(Requirement);
        }
        EXPECT_TRUE(
            COMPILER::satisfiesRuntimeMemoryHelperContract(Contract, Complete));

        for (RuntimeProofRequirementFlag Missing : Requirements) {
          COMPILER::RuntimeProofToken Incomplete;
          for (RuntimeProofRequirementFlag Requirement : Requirements) {
            if (Requirement != Missing) {
              Incomplete.establish(Requirement);
            }
          }
          EXPECT_FALSE(COMPILER::satisfiesRuntimeMemoryHelperContract(
              Contract, Incomplete));
        }
      };

  const auto PreparedRangeAndGas = {
      RuntimeProofRequirementFlag::LogicalSize,
      RuntimeProofRequirementFlag::AccessRange,
      RuntimeProofRequirementFlag::DynamicGasCharged,
  };
  ExpectExactRequirements(RuntimeMemoryHelperId::CodeCopyNoExpand,
                          PreparedRangeAndGas);
  ExpectExactRequirements(RuntimeMemoryHelperId::CallDataCopyNoExpand,
                          PreparedRangeAndGas);
  ExpectExactRequirements(RuntimeMemoryHelperId::KeccakNoExpand,
                          PreparedRangeAndGas);

  const auto PreparedRangeAndOrder = {
      RuntimeProofRequirementFlag::LogicalSize,
      RuntimeProofRequirementFlag::AccessRange,
      RuntimeProofRequirementFlag::OrderToken,
  };
  ExpectExactRequirements(RuntimeMemoryHelperId::TwoWordKeccakNoExpand,
                          PreparedRangeAndOrder);
  ExpectExactRequirements(RuntimeMemoryHelperId::ReturnNoExpand,
                          PreparedRangeAndOrder);
  ExpectExactRequirements(RuntimeMemoryHelperId::RevertNoExpand,
                          PreparedRangeAndOrder);

  ExpectExactRequirements(RuntimeMemoryHelperId::ExpandMemoryNoGas,
                          {RuntimeProofRequirementFlag::DynamicGasCharged,
                           RuntimeProofRequirementFlag::BoundsValidated,
                           RuntimeProofRequirementFlag::OrderToken});
  ExpectExactRequirements(RuntimeMemoryHelperId::CallNoExpand,
                          {RuntimeProofRequirementFlag::LogicalSize,
                           RuntimeProofRequirementFlag::CallArgumentsRange,
                           RuntimeProofRequirementFlag::CallReturnRange,
                           RuntimeProofRequirementFlag::OrderToken});
}

TEST(EVMRuntimeMemoryHelperContractTest, RejectsUnknownHelperFailClosed) {
  const COMPILER::RuntimeMemoryHelperContract Contract =
      COMPILER::getRuntimeMemoryHelperContract(
          static_cast<COMPILER::RuntimeMemoryHelperId>(255));
  COMPILER::RuntimeProofToken Empty;
  EXPECT_FALSE(Contract.Valid);
  EXPECT_FALSE(COMPILER::satisfiesRuntimeMemoryHelperContract(Contract, Empty));
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

TEST(EVMMemoryFactsBuilderTest,
     IncompleteBlockIgnoresOpcodesWithoutPollutingNextBlock) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,        0x01, OP_PUSH1, 0x00,     OP_MSTORE,
      OP_PUSH1,        0x40, OP_PUSH0, OP_SWAP1, OP_KECCAK256,
      OP_CALLDATASIZE, // PC10: first opcode in the complete block.
      OP_MLOAD,        // PC11
      OP_STOP};

  COMPILER::MemoryFactsBuilder FactsBuilder;
  FactsBuilder.beginBlock(0, 0, 10, {}, {}, {}, false);
  size_t PC = 0;
  while (PC < 10) {
    evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
    FactsBuilder.observeOpcode(Opcode, PC, Bytecode.data(), Bytecode.size());
    ++PC;
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      PC += static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    }
  }

  const COMPILER::MemoryFacts &IncompleteOnlyFacts = FactsBuilder.getFacts();
  const COMPILER::MemoryBlockFacts *IncompleteOnly =
      IncompleteOnlyFacts.getBlock(0);
  ASSERT_NE(IncompleteOnly, nullptr);
  EXPECT_FALSE(IncompleteOnly->HasCompleteOpcodeFacts);
  EXPECT_EQ(IncompleteOnly->OpsBegin, IncompleteOnly->OpsEnd);
  EXPECT_TRUE(IncompleteOnlyFacts.Ops.empty());

  FactsBuilder.beginBlock(10, 10, Bytecode.size(), {});
  while (PC < Bytecode.size()) {
    evmc_opcode Opcode = static_cast<evmc_opcode>(Bytecode[PC]);
    FactsBuilder.observeOpcode(Opcode, PC, Bytecode.data(), Bytecode.size());
    ++PC;
    if (Opcode >= OP_PUSH0 && Opcode <= OP_PUSH32) {
      PC += static_cast<uint8_t>(Opcode) - static_cast<uint8_t>(OP_PUSH0);
    }
  }

  COMPILER::MemoryFacts Facts = FactsBuilder.takeFacts();
  const COMPILER::MemoryBlockFacts *Incomplete = Facts.getBlock(0);
  const COMPILER::MemoryBlockFacts *Complete = Facts.getBlock(10);
  ASSERT_NE(Incomplete, nullptr);
  ASSERT_NE(Complete, nullptr);
  EXPECT_FALSE(Incomplete->HasCompleteOpcodeFacts);
  EXPECT_EQ(Incomplete->OpsBegin, Incomplete->OpsEnd);
  EXPECT_TRUE(Complete->HasCompleteOpcodeFacts);
  ASSERT_EQ(Facts.Ops.size(), 1u);
  ASSERT_EQ(Facts.Ops[0].Pc, 11u);
  ASSERT_EQ(Facts.Ops[0].Kind, COMPILER::MemoryOpKind::MLoad);
  ASSERT_EQ(Facts.Ops[0].Reads.size(), 1u);
  EXPECT_EQ(Facts.Ops[0].Reads[0].Addr.Kind,
            COMPILER::AddressBaseKind::StackValue);
  EXPECT_EQ(Facts.Ops[0].Reads[0].Addr.ValueId, 1u);
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

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     DynamicDispatchPredecessorPreventsStaticPathProof) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH0,    OP_CALLDATALOAD,
                                         OP_PUSH1,    0x09,
                                         OP_JUMPI,    OP_PUSH1,
                                         0x20,        OP_CALLDATALOAD,
                                         OP_JUMP,     OP_JUMPDEST,
                                         OP_PUSH1,    0x01,
                                         OP_PUSH1,    0x00,
                                         OP_MSTORE,   OP_PUSH1,
                                         0x12,        OP_JUMP,
                                         OP_JUMPDEST, OP_PUSH1,
                                         0x00,        OP_MLOAD,
                                         OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  const COMPILER::MemoryBlockFacts *Target = Facts.getBlock(18);
  ASSERT_NE(Target, nullptr);
  EXPECT_EQ(Target->Predecessors, std::vector<uint64_t>({5, 9}));
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(18), 0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     IncompleteDynamicDispatchPredecessorsDropProof) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,    0x01,     OP_PUSH1,    0x00,     OP_MSTORE, OP_PUSH1,
      0x0c,        OP_JUMP,  OP_JUMPDEST, OP_JUMP,  OP_STOP,   OP_STOP,
      OP_JUMPDEST, OP_PUSH1, 0x00,        OP_MLOAD, OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  const COMPILER::MemoryBlockFacts *Target = Facts.getBlock(12);
  ASSERT_NE(Target, nullptr);
  EXPECT_FALSE(Target->PredecessorsComplete);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(12), 0u);
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

TEST(EVMMemoryProofLifetimeAnalysisTest,
     ReusesRangeButRejectsExpansionMotionAcrossGas) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x80,     OP_MSTORE, OP_GAS,
      OP_POP,   OP_PUSH1, 0x80,     OP_MLOAD, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryProofLifetimeAnalysis Lifetime(Facts);
  ASSERT_EQ(Facts.Ops.size(), 3u);
  const COMPILER::MemoryProofAvailability Proof =
      Lifetime.queryBeforeOp(Facts.Ops[2].Id, Facts.Ops[2].Reads[0]);
  EXPECT_EQ(Proof.GuaranteedMinBytes, 0xa0u);
  EXPECT_TRUE(Proof.canReuseWithoutExpansion());
  EXPECT_FALSE(
      Lifetime.canMoveExpansionBetween(Facts.Ops[0].Id, Facts.Ops[2].Id));
}

TEST(EVMMemoryProofLifetimeAnalysisTest,
     ReusesRangeButRejectsExpansionMotionAcrossMSize) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x40,     OP_MSTORE, OP_MSIZE,
      OP_POP,   OP_PUSH1, 0x40,     OP_MLOAD, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryProofLifetimeAnalysis Lifetime(Facts);
  ASSERT_EQ(Facts.Ops.size(), 3u);
  const COMPILER::MemoryProofAvailability Proof =
      Lifetime.queryBeforeOp(Facts.Ops[2].Id, Facts.Ops[2].Reads[0]);
  EXPECT_EQ(Proof.GuaranteedMinBytes, 0x60u);
  EXPECT_TRUE(Proof.canReuseWithoutExpansion());
  EXPECT_FALSE(
      Lifetime.canMoveExpansionBetween(Facts.Ops[0].Id, Facts.Ops[2].Id));
}

TEST(EVMMemoryProofLifetimeAnalysisTest, CachesCompletedDemandQuery) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,        OP_PUSH1, 0x00, OP_MSTORE, OP_PUSH1, 0x08,
      OP_JUMP,  OP_JUMPDEST, OP_PUSH1, 0x00, OP_MLOAD,  OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryProofLifetimeAnalysis Lifetime(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_TRUE(Lifetime.queryBeforeOp(Facts.Ops[1].Id, Facts.Ops[1].Reads[0])
                  .canReuseWithoutExpansion());
  const COMPILER::MemoryExtentOracleStats AfterFirst =
      Lifetime.getExtentOracleStats();
  EXPECT_EQ(AfterFirst.QueryCount, 1u);
  EXPECT_EQ(AfterFirst.QueryCacheHits, 0u);
  EXPECT_GT(AfterFirst.BlockVisits, 0u);

  EXPECT_TRUE(Lifetime.queryBeforeOp(Facts.Ops[1].Id, Facts.Ops[1].Reads[0])
                  .canReuseWithoutExpansion());
  const COMPILER::MemoryExtentOracleStats AfterSecond =
      Lifetime.getExtentOracleStats();
  EXPECT_EQ(AfterSecond.QueryCacheHits, 1u);
  EXPECT_EQ(AfterSecond.BlockVisits, AfterFirst.BlockVisits);
  EXPECT_EQ(AfterSecond.OpVisits, AfterFirst.OpVisits);
}

TEST(EVMMemoryProofLifetimeAnalysisTest,
     FailsClosedAtPerQueryBudgetWithoutPublishingPartialCache) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,        OP_PUSH1, 0x00, OP_MSTORE, OP_PUSH1, 0x08,
      OP_JUMP,  OP_JUMPDEST, OP_PUSH1, 0x00, OP_MLOAD,  OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryProofQueryBudget Budget;
  Budget.MaxBlockVisits = 1;
  Budget.MaxOpVisits = 1;
  COMPILER::MemoryProofLifetimeAnalysis Lifetime(Facts, Budget);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_FALSE(Lifetime.queryBeforeOp(Facts.Ops[1].Id, Facts.Ops[1].Reads[0])
                   .canReuseWithoutExpansion());
  EXPECT_FALSE(Lifetime.queryBeforeOp(Facts.Ops[1].Id, Facts.Ops[1].Reads[0])
                   .canReuseWithoutExpansion());
  const COMPILER::MemoryExtentOracleStats Stats =
      Lifetime.getExtentOracleStats();
  EXPECT_EQ(Stats.BudgetExhaustions, 2u);
  EXPECT_EQ(Stats.QueryCacheHits, 0u);
  EXPECT_EQ(Stats.DemandComputations, 2u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     EnforcesCompilationWideBudgetAcrossDistinctQueries) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x00,      OP_MSTORE,   OP_STOP,
      OP_STOP,  OP_STOP,  OP_STOP,  OP_STOP,   OP_JUMPDEST, OP_PUSH1,
      0x02,     OP_PUSH1, 0x20,     OP_MSTORE, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {.EntryPC = 0,
       .BodyStartPC = 0,
       .BodyEndPC = 6,
       .Successors = {},
       .Predecessors = {},
       .PredecessorsComplete = true},
      {.EntryPC = 10,
       .BodyStartPC = 11,
       .BodyEndPC = 17,
       .Successors = {},
       .Predecessors = {},
       .PredecessorsComplete = true}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryProofQueryBudget Budget;
  Budget.MaxBlockVisits = 4;
  Budget.MaxOpVisits = 4;
  Budget.MaxCompilationBlockVisits = 1;
  Budget.MaxCompilationOpVisits = 4;
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts, Budget);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  const COMPILER::MemoryExtentQueryResult Second =
      Oracle.queryBeforeOp(Facts.Ops[1].Id);
  EXPECT_EQ(Second.Status,
            COMPILER::MemoryExtentQueryStatus::CompilationBudgetExhausted);
  EXPECT_EQ(Oracle.getStats().CompilationBudgetExhaustions, 1u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest, HonorsExactQueryBudgetBoundary) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,        OP_PUSH1, 0x00, OP_MSTORE, OP_PUSH1, 0x08,
      OP_JUMP,  OP_JUMPDEST, OP_PUSH1, 0x00, OP_MLOAD,  OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  ASSERT_EQ(Facts.Ops.size(), 2u);

  COMPILER::MemoryProofQueryBudget Exact;
  Exact.MaxBlockVisits = 2;
  Exact.MaxOpVisits = 2;
  COMPILER::MemoryGuaranteedExtentOracle ExactOracle(Facts, Exact);
  EXPECT_TRUE(ExactOracle.queryBeforeOp(Facts.Ops[1].Id).available());
  EXPECT_EQ(ExactOracle.getStats().BlockVisits, 2u);
  EXPECT_EQ(ExactOracle.getStats().OpVisits, 2u);
  EXPECT_EQ(ExactOracle.getStats().EdgeVisits, 1u);

  COMPILER::MemoryProofQueryBudget TooSmall = Exact;
  TooSmall.MaxBlockVisits = 1;
  COMPILER::MemoryGuaranteedExtentOracle SmallOracle(Facts, TooSmall);
  EXPECT_EQ(SmallOracle.queryBeforeOp(Facts.Ops[1].Id).Status,
            COMPILER::MemoryExtentQueryStatus::BudgetExhausted);
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     FailsClosedForIncompleteOrDynamicPredecessors) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,    OP_PUSH1, 0x00,     OP_MSTORE, OP_STOP,  OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,  OP_PUSH1, 0x00,      OP_MLOAD, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {.EntryPC = 0,
       .BodyStartPC = 0,
       .BodyEndPC = 6,
       .Successors = {10},
       .Predecessors = {}},
      {.EntryPC = 10,
       .BodyStartPC = 10,
       .BodyEndPC = 14,
       .Successors = {},
       .Predecessors = {0},
       .PredecessorsComplete = false,
       .PredecessorsAreStatic = false}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  ASSERT_EQ(Facts.Ops.size(), 2u);
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts);

  EXPECT_EQ(Oracle.queryBeforeOp(Facts.Ops[1].Id).Status,
            COMPILER::MemoryExtentQueryStatus::IncompleteCFG);
  EXPECT_EQ(Oracle.getStats().QueryCacheHits, 0u);
  EXPECT_EQ(Oracle.getStats().IncompleteCFGRejects, 1u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest, FailsClosedForStaticCycle) {
  const std::vector<uint8_t> Bytecode = {
      OP_STOP,  OP_STOP, OP_STOP,   OP_STOP, OP_STOP,  OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,   OP_STOP, OP_PUSH1, 0x01,
      OP_PUSH1, 0x00,    OP_MSTORE, OP_STOP, OP_STOP,  OP_STOP,
      OP_STOP,  OP_STOP, OP_PUSH1,  0x00,    OP_MLOAD, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {{.EntryPC = 10,
                                                    .BodyStartPC = 10,
                                                    .BodyEndPC = 16,
                                                    .Successors = {20},
                                                    .Predecessors = {20}},
                                                   {.EntryPC = 20,
                                                    .BodyStartPC = 20,
                                                    .BodyEndPC = 24,
                                                    .Successors = {10},
                                                    .Predecessors = {10}}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  ASSERT_EQ(Facts.Ops.size(), 2u);
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts);

  EXPECT_EQ(Oracle.queryBeforeOp(Facts.Ops[1].Id).Status,
            COMPILER::MemoryExtentQueryStatus::Cycle);
  EXPECT_EQ(Oracle.getStats().CycleCutoffs, 1u);
  EXPECT_EQ(Oracle.getStats().QueryCacheHits, 0u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     NeverExceedsEagerResultOnCompleteDag) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,        OP_PUSH1, 0x00, OP_MSTORE, OP_PUSH1, 0x08,
      OP_JUMP,  OP_JUMPDEST, OP_PUSH1, 0x00, OP_MLOAD,  OP_STOP};
  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Eager(Facts);
  ASSERT_TRUE(Eager.isComplete());
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts);

  for (const COMPILER::MemoryOp &Op : Facts.Ops) {
    const COMPILER::MemoryExtentQueryResult Demand =
        Oracle.queryBeforeOp(Op.Id);
    ASSERT_TRUE(Demand.available());
    EXPECT_LE(Demand.GuaranteedMinBytes,
              Eager.getGuaranteedMinBytesBeforeOp(Op.Id));
  }
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     BoundsPredecessorEdgesAndDoesNotPublishPartialQueryState) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,  0x01,    OP_PUSH1, 0x00,     OP_MSTORE, OP_STOP,  OP_STOP,
      OP_STOP,   OP_STOP, OP_STOP,  OP_PUSH1, 0x02,      OP_PUSH1, 0x20,
      OP_MSTORE, OP_STOP, OP_STOP,  OP_STOP,  OP_STOP,   OP_STOP,  OP_JUMPDEST,
      OP_PUSH1,  0x00,    OP_MLOAD, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {.EntryPC = 0,
       .BodyStartPC = 0,
       .BodyEndPC = 6,
       .Successors = {20},
       .Predecessors = {}},
      {.EntryPC = 10,
       .BodyStartPC = 10,
       .BodyEndPC = 16,
       .Successors = {20},
       .Predecessors = {}},
      {.EntryPC = 20,
       .BodyStartPC = 21,
       .BodyEndPC = 25,
       .Successors = {},
       .Predecessors = {10, 0, 10}}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  ASSERT_EQ(Facts.Ops.size(), 3u);
  ASSERT_EQ(Facts.getBlock(20)->Predecessors, (std::vector<uint64_t>{0, 10}));
  COMPILER::MemoryProofQueryBudget Budget;
  Budget.MaxBlockVisits = 8;
  Budget.MaxOpVisits = 8;
  Budget.MaxEdgeVisits = 1;
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts, Budget);

  EXPECT_EQ(Oracle.queryBeforeOp(Facts.Ops[2].Id).Status,
            COMPILER::MemoryExtentQueryStatus::BudgetExhausted);
  EXPECT_EQ(Oracle.getStats().EdgeVisits, 1u);
  EXPECT_EQ(Oracle.getStats().QueryCacheHits, 0u);

  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  EXPECT_EQ(Oracle.getStats().QueryCacheHits, 0u);
  EXPECT_EQ(Oracle.getStats().DemandComputations, 2u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     BoundedRunPublishesOnlyCompleteResults) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x01,      OP_PUSH1,
                                         0x80,     OP_MSTORE, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGlobalAnalysisBudget Budget;
  Budget.MaxBlockTransfers = 0;
  Budget.MaxOpVisits = 0;

  COMPILER::MemoryGuaranteedMinBytesAnalysis Analysis(Facts, Budget);

  EXPECT_FALSE(Analysis.isComplete());
  EXPECT_EQ(Analysis.getGuaranteedMinBytesAtEntry(0), 0u);
  EXPECT_EQ(Analysis.getGuaranteedMinBytesBeforeOp(Facts.Ops.front().Id), 0u);
  EXPECT_EQ(Analysis.getStats().BudgetExhaustions, 1u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     CountsDependencyPropagationAtExactEdgeBudgetBoundary) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,    OP_PUSH1, 0x00,     OP_MSTORE, OP_STOP,  OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,  OP_PUSH1, 0x00,      OP_MLOAD, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {{.EntryPC = 0,
                                                    .BodyStartPC = 0,
                                                    .BodyEndPC = 6,
                                                    .Successors = {10},
                                                    .Predecessors = {}},
                                                   {.EntryPC = 10,
                                                    .BodyStartPC = 10,
                                                    .BodyEndPC = 14,
                                                    .Successors = {},
                                                    .Predecessors = {0}}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  ASSERT_EQ(Facts.Ops.size(), 2u);

  COMPILER::MemoryGlobalAnalysisBudget TooSmall;
  TooSmall.MaxEdgeVisits = 3;
  COMPILER::MemoryGuaranteedMinBytesAnalysis Rejected(Facts, TooSmall);
  EXPECT_FALSE(Rejected.isComplete());
  EXPECT_EQ(Rejected.getStats().EdgeVisits, 3u);
  EXPECT_EQ(Rejected.getStats().BudgetExhaustions, 1u);

  COMPILER::MemoryGlobalAnalysisBudget Exact;
  Exact.MaxEdgeVisits = 4;
  COMPILER::MemoryGuaranteedMinBytesAnalysis Accepted(Facts, Exact);
  EXPECT_TRUE(Accepted.isComplete());
  EXPECT_EQ(Accepted.getStats().EdgeVisits, 4u);
  EXPECT_EQ(Accepted.getStats().BudgetExhaustions, 0u);
  EXPECT_EQ(Accepted.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0x20u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     CountsRepeatedDependencyPropagationAcrossStaticBackedge) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,    OP_PUSH1,  0x00,    OP_MSTORE, OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,   OP_STOP, OP_PUSH1,  0x02,
      OP_PUSH1, 0x20,    OP_MSTORE, OP_STOP, OP_STOP,   OP_STOP,
      OP_STOP,  OP_STOP, OP_PUSH1,  0x00,    OP_MLOAD,  OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {{.EntryPC = 0,
                                                    .BodyStartPC = 0,
                                                    .BodyEndPC = 6,
                                                    .Successors = {10},
                                                    .Predecessors = {}},
                                                   {.EntryPC = 10,
                                                    .BodyStartPC = 10,
                                                    .BodyEndPC = 16,
                                                    .Successors = {20},
                                                    .Predecessors = {0, 20}},
                                                   {.EntryPC = 20,
                                                    .BodyStartPC = 20,
                                                    .BodyEndPC = 24,
                                                    .Successors = {10},
                                                    .Predecessors = {10}}};
  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  ASSERT_EQ(Facts.Ops.size(), 3u);

  COMPILER::MemoryGlobalAnalysisBudget TooSmall;
  TooSmall.MaxEdgeVisits = 13;
  COMPILER::MemoryGuaranteedMinBytesAnalysis Rejected(Facts, TooSmall);
  EXPECT_FALSE(Rejected.isComplete());
  EXPECT_EQ(Rejected.getStats().EdgeVisits, 13u);
  EXPECT_EQ(Rejected.getStats().BudgetExhaustions, 1u);

  COMPILER::MemoryGlobalAnalysisBudget Exact;
  Exact.MaxEdgeVisits = 14;
  COMPILER::MemoryGuaranteedMinBytesAnalysis Accepted(Facts, Exact);
  EXPECT_TRUE(Accepted.isComplete());
  EXPECT_EQ(Accepted.getStats().EdgeVisits, 14u);
  EXPECT_EQ(Accepted.getStats().BudgetExhaustions, 0u);
  EXPECT_EQ(Accepted.getGuaranteedMinBytesBeforeOp(Facts.Ops[2].Id), 0x40u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     DefersPromotionUntilNextUncachedQuery) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1,  0x40,      OP_MSTORE, OP_PUSH1,
      0x02,     OP_PUSH1, 0x80,      OP_MSTORE, OP_PUSH1,  0x03,
      OP_PUSH1, 0xc0,     OP_MSTORE, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  ASSERT_EQ(Facts.Ops.size(), 3u);
  COMPILER::MemoryProofPromotionPolicy Promotion;
  Promotion.Enabled = true;
  Promotion.DemandComputationThreshold = 1;
  Promotion.DemandWorkMultiplier = 0;
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts, {}, Promotion);

  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  EXPECT_EQ(Oracle.getStats().PromotionSchedules, 1u);
  EXPECT_EQ(Oracle.getStats().GlobalPromotionAttempts, 0u);
  EXPECT_EQ(Oracle.getStats().PromotionPending, 1u);

  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  EXPECT_EQ(Oracle.getStats().GlobalPromotionAttempts, 0u);
  EXPECT_EQ(Oracle.getStats().PromotionPending, 1u);

  const COMPILER::MemoryExtentQueryResult Second =
      Oracle.queryBeforeOp(Facts.Ops[1].Id);
  EXPECT_TRUE(Second.available());
  EXPECT_EQ(Second.GuaranteedMinBytes, 0x60u);
  EXPECT_EQ(Oracle.getStats().GlobalPromotionAttempts, 1u);
  EXPECT_EQ(Oracle.getStats().GlobalPromotions, 1u);
  EXPECT_EQ(Oracle.getStats().PromotionPending, 0u);
}

TEST(EVMMemoryGuaranteedExtentOracleTest,
     FailedPromotionDoesNotPublishGlobalResults) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x40,      OP_MSTORE, OP_PUSH1,
      0x02,     OP_PUSH1, 0x80,     OP_MSTORE, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  ASSERT_EQ(Facts.Ops.size(), 2u);
  COMPILER::MemoryProofPromotionPolicy Promotion;
  Promotion.Enabled = true;
  Promotion.DemandComputationThreshold = 1;
  Promotion.DemandWorkMultiplier = 0;
  Promotion.MaxGlobalBlockTransfers = 0;
  Promotion.MaxGlobalOpVisits = 0;
  COMPILER::MemoryGuaranteedExtentOracle Oracle(Facts, {}, Promotion);

  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[1].Id).available());
  EXPECT_EQ(Oracle.getStats().GlobalPromotionAttempts, 1u);
  EXPECT_EQ(Oracle.getStats().GlobalPromotions, 0u);
  EXPECT_EQ(Oracle.getStats().GlobalBudgetExhaustions, 1u);
  EXPECT_TRUE(Oracle.queryBeforeOp(Facts.Ops[0].Id).available());
  EXPECT_EQ(Oracle.getStats().GlobalPromotionAttempts, 1u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     ContinuesLearningLogicalExtentAcrossGasObserver) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x00,      OP_MSTORE, OP_GAS, OP_PUSH1,
      0x02,     OP_PUSH1, 0x80,     OP_MSTORE, OP_PUSH1,  0x80,   OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 4u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[3].Id), 0xa0u);
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

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, LearnsConstKeccakReadEnd) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x40,         OP_PUSH1,
                                         0x20,     OP_KECCAK256, OP_POP,
                                         OP_PUSH1, 0x20,         OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0x60u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     PropagatesConstKeccakGuaranteeToSuccessor) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x40,        OP_PUSH1, 0x20, OP_KECCAK256,
      OP_POP,   OP_JUMPDEST, OP_PUSH1, 0x20, OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(6), 0x60u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, IgnoresZeroLengthKeccak) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x00,         OP_PUSH1,
                                         0x80,     OP_KECCAK256, OP_POP,
                                         OP_PUSH1, 0x00,         OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0u);
}

#ifdef ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK
std::optional<std::string>
compileKeccakMemoryMir(const std::vector<uint8_t> &Bytecode) {
  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
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
    return std::nullopt;
  }

  std::string Mir;
  llvm::raw_string_ostream OS(Mir);
  Func.print(OS);
  OS.flush();
  return Mir;
}

template <typename FuncType>
bool containsKeccakRuntimeCall(const std::string &Mir, FuncType Function) {
  const std::string Needle =
      "target = const.i64 " +
      std::to_string(COMPILER::getFunctionAddress(Function)) + ", ";
  return Mir.find(Needle) != std::string::npos;
}

TEST(EVMMirBuilderMemoryProofTest,
     ReusesCrossBlockGuaranteedSizeForKeccakConsumer) {
  const std::vector<uint8_t> CoveredKeccak = {
      OP_PUSH1, 0x01,         OP_PUSH1,    0x80,     OP_MSTORE, OP_PUSH1,
      0x08,     OP_JUMP,      OP_JUMPDEST, OP_PUSH1, 0x20,      OP_PUSH1,
      0x80,     OP_KECCAK256, OP_POP,      OP_STOP};
  const std::vector<uint8_t> UncoveredKeccak = {
      OP_PUSH1, 0x01,         OP_PUSH1,    0x80,     OP_MSTORE, OP_PUSH1,
      0x08,     OP_JUMP,      OP_JUMPDEST, OP_PUSH1, 0x20,      OP_PUSH1,
      0xa0,     OP_KECCAK256, OP_POP,      OP_STOP};

  const auto CoveredMir = compileKeccakMemoryMir(CoveredKeccak);
  const auto UncoveredMir = compileKeccakMemoryMir(UncoveredKeccak);
  ASSERT_TRUE(CoveredMir.has_value());
  ASSERT_TRUE(UncoveredMir.has_value());

  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  EXPECT_TRUE(containsKeccakRuntimeCall(*CoveredMir,
                                        RuntimeFunctions.GetKeccak256NoExpand));
  EXPECT_FALSE(
      containsKeccakRuntimeCall(*CoveredMir, RuntimeFunctions.GetKeccak256));
  EXPECT_TRUE(
      containsKeccakRuntimeCall(*UncoveredMir, RuntimeFunctions.GetKeccak256));
  EXPECT_FALSE(containsKeccakRuntimeCall(
      *UncoveredMir, RuntimeFunctions.GetKeccak256NoExpand));
}

TEST(EVMMirBuilderMemoryProofTest, ReusesPriorKeccakProofAtExactOpcodePC) {
  const std::vector<uint8_t> OneKeccak = {OP_PUSH1,     0x20,   OP_PUSH1, 0x80,
                                          OP_KECCAK256, OP_POP, OP_STOP};
  const std::vector<uint8_t> TwoKeccaks = {
      OP_PUSH1,     0x20,     OP_PUSH1, 0x80,     OP_KECCAK256,
      OP_POP,       OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256, OP_POP,   OP_STOP};

  const auto OneMir = compileKeccakMemoryMir(OneKeccak);
  const auto TwoMir = compileKeccakMemoryMir(TwoKeccaks);
  ASSERT_TRUE(OneMir.has_value());
  ASSERT_TRUE(TwoMir.has_value());

  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  EXPECT_TRUE(
      containsKeccakRuntimeCall(*OneMir, RuntimeFunctions.GetKeccak256));
  EXPECT_TRUE(
      containsKeccakRuntimeCall(*TwoMir, RuntimeFunctions.GetKeccak256));
  EXPECT_TRUE(containsKeccakRuntimeCall(*TwoMir,
                                        RuntimeFunctions.GetKeccak256NoExpand));
}
#endif

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, IgnoresZeroLengthMCopy) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x00,    OP_PUSH1, 0x80,
                                         OP_PUSH1, 0xa0,    OP_MCOPY, OP_PUSH1,
                                         0x00,     OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     LearnsConstCallDataCopyDestinationEnd) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,        0x20,     OP_PUSH1, 0x00,    OP_PUSH1, 0x80,
      OP_CALLDATACOPY, OP_PUSH1, 0x80,     OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0xa0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     LearnsConstCodeCopyDestinationEnd) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x20,        OP_PUSH1, 0x00, OP_PUSH1,
      0x40,     OP_CODECOPY, OP_PUSH1, 0x40, OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0x60u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest, IgnoresZeroLengthCallDataCopy) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,        0x00,     OP_PUSH1, 0x00,    OP_PUSH1, 0x80,
      OP_CALLDATACOPY, OP_PUSH1, 0x00,     OP_MLOAD};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesBeforeOp(Facts.Ops[1].Id), 0u);
}

TEST(EVMMemoryGuaranteedMinBytesAnalysisTest,
     IncompleteBlockResetsGuaranteeAndBlocksSuccessorPropagation) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,    OP_PUSH1, 0x80,     OP_MSTORE, OP_STOP,  OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,  OP_PUSH1, 0x00,      OP_MLOAD, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5}, {}},
      {5, 5, 10, {10}, {0}, false},
      {10, 10, 14, {}, {5}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  const COMPILER::MemoryBlockFacts *Incomplete = Facts.getBlock(5);
  ASSERT_NE(Incomplete, nullptr);
  ASSERT_FALSE(Incomplete->HasCompleteOpcodeFacts);
  ASSERT_EQ(Facts.Ops.size(), 2u);

  COMPILER::MemoryGuaranteedMinBytesAnalysis Guaranteed(Facts);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtExit(0), 0xa0u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(5), 0u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtExit(5), 0u);
  EXPECT_EQ(Guaranteed.getGuaranteedMinBytesAtEntry(10), 0u);
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

#if defined(ZEN_ENABLE_MULTIPASS_JIT_LOGGING) &&                               \
    defined(ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK)
TEST(EVMMirBuilderMemoryStatsTest,
     ReusesCrossBlockGuaranteedSizeForCopyConsumers) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 value
      0x60, 0x80, // PUSH1 memory offset
      0x52,       // MSTORE: guarantees memory through 0x9f
      0x60, 0x08, // PUSH1 successor block
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x60, 0x20, // PUSH1 CALLDATACOPY size
      0x60, 0x00, // PUSH1 calldata source
      0x60, 0x80, // PUSH1 memory destination
      0x37,       // CALLDATACOPY: covered by the predecessor proof
      0x60, 0x20, // PUSH1 CODECOPY size
      0x60, 0x00, // PUSH1 code source
      0x60, 0x40, // PUSH1 memory destination
      0x39,       // CODECOPY: covered by the predecessor proof
      0x60, 0x20, // PUSH1 CODECOPY size
      0x60, 0x00, // PUSH1 code source
      0x60, 0xa0, // PUSH1 memory destination
      0x39,       // CODECOPY: extends beyond the predecessor proof
      0x00        // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
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
  ASSERT_TRUE(Builder.compile(&Ctx));

  auto Logger = std::make_shared<CapturingLogger>();
  auto &Logging = zen::utils::Logging::getInstance();
  auto PreviousLogger = Logging.getLogger();
  Logging.setLogger(Logger);
  Builder.dumpMemoryCompileStats();
  Logging.setLogger(std::move(PreviousLogger));

  auto Summary = std::find_if(
      Logger->DebugMessages.begin(), Logger->DebugMessages.end(),
      [](const std::string &Message) {
        return Message.find("[EVM-MEM-SUMMARY]") != std::string::npos;
      });
  ASSERT_NE(Summary, Logger->DebugMessages.end());
  EXPECT_NE(Summary->find("copy_guaranteed_elision=2 "), std::string::npos)
      << *Summary;
  EXPECT_EQ(Summary->find("copy_guaranteed_elision=3 "), std::string::npos)
      << *Summary;
}

TEST(EVMMirBuilderMemoryStatsTest,
     TracksCopyProofAtEachOpcodePCAndRetainsFallbackExpansion) {
  const std::vector<uint8_t> ProducerOnly = {0x60, 0x01, 0x60, 0x80, 0x52,
                                             0x60, 0x08, 0x56, 0x5b, 0x00};
  const std::vector<uint8_t> WithUncoveredCopy = {
      0x60, 0x01, // PUSH1 value
      0x60, 0x80, // PUSH1 memory offset
      0x52,       // MSTORE: guarantees memory through 0x9f
      0x60, 0x08, // PUSH1 successor block
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x60, 0x20, // PUSH1 CODECOPY size
      0x60, 0x00, // PUSH1 code source
      0x60, 0xa0, // PUSH1 memory destination
      0x39,       // CODECOPY: uncovered, grows memory through 0xbf
      0x00        // STOP
  };
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x01, // PUSH1 value
      0x60, 0x80, // PUSH1 memory offset
      0x52,       // MSTORE: guarantees memory through 0x9f
      0x60, 0x08, // PUSH1 successor block
      0x56,       // JUMP
      0x5b,       // JUMPDEST
      0x60, 0x20, // PUSH1 CODECOPY size
      0x60, 0x00, // PUSH1 code source
      0x60, 0xa0, // PUSH1 memory destination
      0x39,       // CODECOPY: uncovered, grows memory through 0xbf
      0x60, 0x20, // PUSH1 CALLDATACOPY size
      0x60, 0x00, // PUSH1 calldata source
      0x60, 0xa0, // PUSH1 memory destination
      0x37,       // CALLDATACOPY: covered by the preceding COPY proof
      0x00        // STOP
  };

  const std::optional<size_t> ProducerExpansionCalls =
      countExpandMemoryCallsForBytecode(ProducerOnly);
  const std::optional<size_t> FallbackExpansionCalls =
      countExpandMemoryCallsForBytecode(WithUncoveredCopy);
  const std::optional<size_t> CoveredSuccessorExpansionCalls =
      countExpandMemoryCallsForBytecode(Bytecode);
  ASSERT_TRUE(ProducerExpansionCalls.has_value());
  ASSERT_TRUE(FallbackExpansionCalls.has_value());
  ASSERT_TRUE(CoveredSuccessorExpansionCalls.has_value());
  EXPECT_EQ(*FallbackExpansionCalls, *ProducerExpansionCalls + 1);
  EXPECT_EQ(*CoveredSuccessorExpansionCalls, *FallbackExpansionCalls);

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
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
  ASSERT_TRUE(Builder.compile(&Ctx));

  auto Logger = std::make_shared<CapturingLogger>();
  auto &Logging = zen::utils::Logging::getInstance();
  auto PreviousLogger = Logging.getLogger();
  Logging.setLogger(Logger);
  Builder.dumpMemoryCompileStats();
  Logging.setLogger(std::move(PreviousLogger));

  auto Summary = std::find_if(
      Logger->DebugMessages.begin(), Logger->DebugMessages.end(),
      [](const std::string &Message) {
        return Message.find("[EVM-MEM-SUMMARY]") != std::string::npos;
      });
  ASSERT_NE(Summary, Logger->DebugMessages.end());
  EXPECT_NE(Summary->find("copy_guaranteed_elision=1 "), std::string::npos)
      << *Summary;
}
#endif

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

TEST(EVMMemoryDeadStoreAnalysisTest,
     SelectorStoreObservedByTwoWordKeccakIsNotDead) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH0, OP_CALLDATALOAD, OP_PUSH1, 0x20, OP_CALLDATALOAD, OP_PUSH1,
      0x40, OP_CALLDATALOAD,
      // Exact selector-to-storage-key stack motif used by the failing proxy.
      OP_PUSH32, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, OP_SWAP3,
      OP_SWAP1, OP_SWAP3, OP_AND, OP_PUSH0, OP_SWAP1, OP_DUP2, OP_MSTORE,
      OP_PUSH1, 0x20, OP_SWAP3, OP_SWAP1, OP_SWAP3, OP_MSTORE, OP_POP, OP_PUSH1,
      0x40, OP_SWAP1, OP_KECCAK256};

  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryDeadStoreAnalysis DeadStores(Facts);

  ASSERT_GE(Facts.Ops.size(), 6u);
  const COMPILER::MemoryOp &SelectorStore = Facts.Ops[Facts.Ops.size() - 3];
  const COMPILER::MemoryOp &SlotStore = Facts.Ops[Facts.Ops.size() - 2];
  const COMPILER::MemoryOp &Keccak = Facts.Ops.back();
  ASSERT_EQ(SelectorStore.Kind, COMPILER::MemoryOpKind::MStore);
  ASSERT_EQ(SlotStore.Kind, COMPILER::MemoryOpKind::MStore);
  ASSERT_EQ(Keccak.Kind, COMPILER::MemoryOpKind::Keccak);
  ASSERT_EQ(SelectorStore.Writes.size(), 1u);
  ASSERT_EQ(SlotStore.Writes.size(), 1u);
  ASSERT_EQ(Keccak.Reads.size(), 1u);
  EXPECT_EQ(SelectorStore.Writes[0].Addr.Offset, 0);
  EXPECT_EQ(SlotStore.Writes[0].Addr.Offset, 32);
  EXPECT_EQ(Keccak.Reads[0].Addr.Offset, 0);
  ASSERT_TRUE(Keccak.Reads[0].Size.Known);
  EXPECT_EQ(Keccak.Reads[0].Size.Value, 64u);
  EXPECT_FALSE(DeadStores.isDeadStore(SelectorStore.Id));
}

TEST(EVMMemoryDeadStoreAnalysisTest,
     UnresolvedDynamicEntryDoesNotProduceFalseSelectorAliasFacts) {
  const std::vector<uint8_t> Bytecode = {
      // Two reachable dynamic-JUMP sources enter PC24 with different hidden
      // live-in depths, so its absolute entry stack is unresolved.
      OP_PUSH0, OP_CALLDATALOAD, OP_PUSH1, 0x0d, OP_JUMPI, OP_PUSH1, 0x11,
      OP_PUSH1, 0x22, OP_PUSH1, 0x20, OP_CALLDATALOAD, OP_JUMP, OP_JUMPDEST,
      OP_PUSH1, 0x11, OP_PUSH1, 0x22, OP_PUSH1, 0x33, OP_PUSH1, 0x20,
      OP_CALLDATALOAD, OP_JUMP, OP_JUMPDEST,
      // Exact selector-to-storage-key motif from the failing proxy.
      OP_PUSH32, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, OP_SWAP3,
      OP_SWAP1, OP_SWAP3, OP_AND, OP_PUSH0, OP_SWAP1, OP_DUP2, OP_MSTORE,
      OP_PUSH1, 0x20, OP_SWAP3, OP_SWAP1, OP_SWAP3, OP_MSTORE, OP_POP, OP_PUSH1,
      0x40, OP_SWAP1, OP_KECCAK256, OP_STOP};

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *TargetBlock = findBlock(Analyzer, 24);
  ASSERT_NE(TargetBlock, nullptr);
  ASSERT_LT(TargetBlock->ResolvedEntryStackDepth, 0);

  COMPILER::MemoryFacts Facts = collectAnalyzerMemoryFacts(Bytecode);
  const COMPILER::MemoryBlockFacts *TargetFacts = Facts.getBlock(24);
  ASSERT_NE(TargetFacts, nullptr);
  EXPECT_FALSE(TargetFacts->HasCompleteOpcodeFacts);
  for (const COMPILER::MemoryOp &Op : Facts.Ops) {
    EXPECT_NE(Op.Pc, 65u);
    EXPECT_NE(Op.Pc, 71u);
    EXPECT_NE(Op.Pc, 76u);
  }
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

TEST(EVMMemoryPrecheckConsumerTest,
     RestrictsBlockPrecheckToIndexedOperationSpan) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x00, OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x20, OP_MSTORE,
      OP_PUSH1, 0x03, OP_PUSH1, 0x40, OP_MSTORE};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5}, {}},
      {5, 5, 15, {}, {0}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Consumer(View);

  // Even if a caller supplies a wider bytecode interval, the block index is
  // authoritative. The first block contains only one direct memory operation
  // and therefore cannot form a shared precheck.
  EXPECT_FALSE(Consumer.getBlockPrecheckRange(0, Bytecode.size()).has_value());
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

TEST(EVMMemoryExpansionPlannerLazyTest,
     StartsWithoutMaterializingOptionalAnalyses) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,     0x20,     OP_PUSH1, 0x80,     OP_KECCAK256,
      OP_POP,       OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256, OP_POP,   OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLinearRegions(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasGuaranteedExtent(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasDeadStores(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLoadForwarding(Planner));
}

TEST(EVMMemoryExpansionPlannerLazyTest,
     ExtentQueryMaterializesOnlyExtentOracle) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,     0x20,     OP_PUSH1, 0x80,     OP_KECCAK256,
      OP_POP,       OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256, OP_POP,   OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  ASSERT_GE(Facts.Ops.size(), 2u);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_EQ(Planner.getGuaranteedMinBytesBeforeOp(Facts.Ops.back().Pc), 0xa0u);
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLinearRegions(Planner));
  EXPECT_TRUE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasGuaranteedExtent(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasDeadStores(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLoadForwarding(Planner));
}

TEST(EVMMemoryExpansionPlannerLazyTest,
     SharedPrecheckDoesNotMaterializeGlobalAnalyses) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x20,     OP_PUSH1, 0x40,
                                         OP_PUSH1, 0x00,     OP_MCOPY, OP_PUSH1,
                                         0x20,     OP_PUSH1, 0x80,     OP_PUSH1,
                                         0x40,     OP_MCOPY, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_TRUE(Planner.buildMemoryExpansionPlan(0, Bytecode.size()).has_value());
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLinearRegions(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasGuaranteedExtent(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasDeadStores(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLoadForwarding(Planner));
}

TEST(EVMMemoryExpansionPlannerLazyTest, DeadStoreQueryMaterializesOnlyDSE) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,     OP_PUSH1, 0x80,      OP_MSTORE, OP_PUSH1,
      0x02,     OP_PUSH1, 0x80,     OP_MSTORE, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  ASSERT_GE(Facts.Ops.size(), 2u);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_TRUE(Planner.isDeadStore(Facts.Ops.front().Pc));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLinearRegions(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasGuaranteedExtent(Planner));
  EXPECT_TRUE(COMPILER::MemoryExpansionPlannerTestPeer::hasDeadStores(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLoadForwarding(Planner));
}

TEST(EVMMemoryExpansionPlannerLazyTest,
     ForwardingQueryMaterializesOnlyForwardingAnalysis) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80,   OP_MSTORE,
      OP_PUSH1, 0x80, OP_MLOAD, OP_POP, OP_STOP};
  COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);
  ASSERT_GE(Facts.Ops.size(), 2u);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_EQ(Planner.getForwardingStorePC(Facts.Ops.back().Pc),
            std::optional<uint64_t>(Facts.Ops.front().Pc));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLinearRegions(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasGuaranteedExtent(Planner));
  EXPECT_FALSE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasDeadStores(Planner));
  EXPECT_TRUE(
      COMPILER::MemoryExpansionPlannerTestPeer::hasLoadForwarding(Planner));
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

TEST(EVMMemoryConsumerFrameworkTest, LinearRegionDoesNotCrossIncompleteBlock) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01,    OP_PUSH1,  0x00,    OP_MSTORE, OP_STOP,
      OP_STOP,  OP_STOP, OP_STOP,   OP_STOP, OP_PUSH1,  0x02,
      OP_PUSH1, 0x20,    OP_MSTORE, OP_STOP};
  const std::vector<MemoryFactBlockSpec> Blocks = {
      {0, 0, 5, {5}, {}},
      {5, 5, 10, {10}, {0}, false},
      {10, 10, 16, {}, {5}},
  };

  COMPILER::MemoryFacts Facts = collectManualBlockMemoryFacts(Bytecode, Blocks);
  COMPILER::MemoryAnalysisView View(Facts);
  COMPILER::MemoryPrecheckConsumer Prechecks(View);
  COMPILER::MemoryGroupingConsumer Grouping(View, Prechecks);
  COMPILER::MemoryExpansionPlanner Planner(View);

  EXPECT_FALSE(Prechecks.buildMemoryExpansionPlan(5, 10).has_value());
  EXPECT_FALSE(Grouping.buildMemoryExpansionPlan(5, 10).has_value());
  EXPECT_FALSE(Planner.isDeadStore(5));
  EXPECT_FALSE(Planner.getForwardingStorePC(5).has_value());
  EXPECT_FALSE(Planner.buildMemoryExpansionPlan(0, 5).has_value());
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(5), 0u);
  EXPECT_EQ(Planner.getGuaranteedMinBytesAtEntry(10), 0u);
  EXPECT_EQ(
      Planner.getLastDiagnostics().LinearRegionRejectedBarrierUnknownEffect,
      1u);
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

struct MockBatchStackAccessStats {
  uint32_t PeekCalls = 0;
  uint32_t PeekSlots = 0;
  uint32_t DropCalls = 0;
  uint32_t DropSlots = 0;
  uint32_t PushCalls = 0;
  uint32_t PushSlots = 0;
  uint32_t StackTopUpdates = 0;
  uint32_t StackSizeUpdates = 0;
};

struct MockMeterOpcodeRangeRecord {
  uint64_t StartPC = 0;
  uint64_t EndPCExclusive = 0;
};

struct MockHelperOpcodeRecord {
  evmc_opcode Opcode = OP_STOP;
  uint64_t PC = 0;
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

  void setMemoryFacts(const COMPILER::MemoryFacts &Facts) {
    CapturedMemoryFacts = Facts;
  }

  const COMPILER::MemoryFacts &memoryFacts() const {
    return CapturedMemoryFacts;
  }

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

  std::vector<Operand> peekStackBatch(uint32_t Count, uint32_t SkipTop = 0) {
    if (Count == 0) {
      return {};
    }
    ZEN_ASSERT(static_cast<uint64_t>(Count) + SkipTop <= RuntimeStack.size() &&
               "mock runtime stack batch peek underflow");
    BatchStats.PeekCalls++;
    BatchStats.PeekSlots += Count;
    const size_t Begin =
        RuntimeStack.size() - static_cast<size_t>(SkipTop) - Count;
    return std::vector<Operand>(RuntimeStack.begin() + Begin,
                                RuntimeStack.begin() + Begin + Count);
  }

  void dropStackBatch(uint32_t Count) {
    if (Count == 0) {
      return;
    }
    ZEN_ASSERT(Count <= RuntimeStack.size() &&
               "mock runtime stack batch drop underflow");
    RuntimeStack.resize(RuntimeStack.size() - Count);
    BatchStats.DropCalls++;
    BatchStats.DropSlots += Count;
    BatchStats.StackTopUpdates++;
    BatchStats.StackSizeUpdates++;
  }

  void pushStackBatch(const std::vector<Operand> &Values) {
    if (Values.empty()) {
      return;
    }
    RuntimeStack.insert(RuntimeStack.end(), Values.begin(), Values.end());
    BatchStats.PushCalls++;
    BatchStats.PushSlots += Values.size();
    BatchStats.StackTopUpdates++;
    BatchStats.StackSizeUpdates++;
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
  Operand handleCallDataLoad(Operand) { return Operand(CallDataLoadResult); }
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
  void prepareLinearBlockMemoryPrecheck(Operand Stride) {
    LinearPrecheckPrepareCount++;
    LastLinearPrecheckStride = Stride.resolvedValue()[0];
  }
  void noteMemoryOpcodeInBlock(evmc_opcode, uint64_t) {}
  void noteHelperOpcodeInBlock(evmc_opcode Opcode, uint64_t PC) {
    HelperOpcodes.push_back({Opcode, PC});
  }
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

  const MockBatchStackAccessStats &batchAccessStats() const {
    return BatchStats;
  }

  uint32_t meteredOpcodeCount(evmc_opcode Opcode) const {
    return MeteredOpcodeCounts[static_cast<uint8_t>(Opcode)];
  }

  const std::vector<MockMeterOpcodeRangeRecord> &meteredRanges() const {
    return MeteredRanges;
  }

  const std::vector<MockHelperOpcodeRecord> &helperOpcodes() const {
    return HelperOpcodes;
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

  MockOperand::U256Value runtimeStackValueFromBottom(size_t Index) const {
    ZEN_ASSERT(Index < RuntimeStack.size() &&
               "mock runtime stack index is out of range");
    return RuntimeStack[Index].resolvedValue();
  }

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

  void setCallDataLoadResult(uint64_t Value) { CallDataLoadResult = Value; }

  uint64_t lastLinearPrecheckStride() const { return LastLinearPrecheckStride; }

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
  COMPILER::MemoryFacts CapturedMemoryFacts;
  bool EnableRuntimeStackChecks = false;
  uint8_t CurrentOpcode = 0xff;
  std::array<MockStackAccessStats, 256> Stats = {};
  MockBatchStackAccessStats BatchStats = {};
  std::array<uint32_t, 256> MeteredOpcodeCounts = {};
  std::vector<MockMeterOpcodeRangeRecord> MeteredRanges;
  std::vector<MockHelperOpcodeRecord> HelperOpcodes;
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
  uint64_t LastLinearPrecheckStride = 0;
  uint64_t CallDataLoadResult = 0;

#undef MOCK_OPERAND_STUB
#undef MOCK_VOID_STUB
};

class DynamicPushMockEVMBuilder : public MockEVMBuilder {
public:
  Operand handlePush(const zen::common::Bytes &) { return Operand(); }
};

class MemoryFactsCapturingBuilder : public MockEVMBuilder {
public:
  void setMemoryFacts(const COMPILER::MemoryFacts &Facts) {
    ++SetMemoryFactsCount;
    CapturedFacts = Facts;
  }

  COMPILER::MemoryFacts CapturedFacts;
  uint32_t SetMemoryFactsCount = 0;
};

TEST(EVMMemoryFactsIndexTest, MapsOpcodePCWithoutAcceptingPushPayload) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x2a,      OP_PUSH1,
                                         0x80,     OP_MSTORE, OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  const COMPILER::MemoryOp *Store = Facts.getOpByPC(4);
  ASSERT_NE(Store, nullptr);
  EXPECT_EQ(Store->Kind, COMPILER::MemoryOpKind::MStore);
  EXPECT_EQ(Facts.getOpByPC(1), nullptr);
  EXPECT_EQ(Facts.getOpByPC(Bytecode.size()), nullptr);
}

TEST(EVMMemoryPlannerAdmissionTest, RejectsSingleDynamicMemoryNoHit) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,        0x01,      OP_PUSH0,
                                         OP_CALLDATALOAD, OP_MSTORE, OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  EXPECT_FALSE(Facts.Opportunities.hasPlannerOpportunity());
}

TEST(EVMMemoryPlannerAdmissionTest, AdmitsExactProducerConsumerPair) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,     0x20,     OP_PUSH1, 0x80,     OP_KECCAK256,
      OP_POP,       OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256, OP_POP,   OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_TRUE(Facts.Opportunities.hasPlannerOpportunity());
}

TEST(EVMMemoryPlannerAdmissionTest, RejectsSingleExactMemoryOperation) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x2a,      OP_PUSH1,
                                         0x80,     OP_MSTORE, OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 1u);
  EXPECT_FALSE(Facts.Opportunities.hasPlannerOpportunity());
}

TEST(EVMMemoryPlannerAdmissionTest, RejectsStaticallyEmptyCopies) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH0,        OP_PUSH0,    OP_PUSH0,
                                         OP_CALLDATACOPY, OP_PUSH0,    OP_PUSH0,
                                         OP_PUSH0,        OP_CODECOPY, OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_FALSE(Facts.Opportunities.hasPlannerOpportunity());
}

TEST(EVMMemoryPlannerAdmissionTest, AdmitsCopyToKeccakExtentReuse) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,        0x20,     OP_PUSH0, OP_PUSH1, 0x80,
      OP_CALLDATACOPY, OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256,    OP_POP,   OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  ASSERT_EQ(Facts.Ops.size(), 2u);
  EXPECT_TRUE(Facts.Opportunities.HasExtentReuseOpportunity);
  EXPECT_TRUE(Facts.Opportunities.hasPlannerOpportunity());
}

TEST(EVMMemoryPlannerAdmissionTest, AdmitsStoreDSEAndForwardingShapes) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x01, OP_PUSH1, 0x80,   OP_MSTORE,
      OP_PUSH1, 0x02, OP_PUSH1, 0x80,   OP_MSTORE,
      OP_PUSH1, 0x80, OP_MLOAD, OP_POP, OP_STOP};

  const COMPILER::MemoryFacts Facts = collectMemoryFacts(Bytecode);

  EXPECT_TRUE(Facts.Opportunities.HasDeadStoreOpportunity);
  EXPECT_TRUE(Facts.Opportunities.HasLoadForwardingOpportunity);
  EXPECT_TRUE(Facts.Opportunities.hasPlannerOpportunity());
}

#ifdef ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK
TEST(EVMJITFrontendVisitorTest, DoesNotSetMemoryFactsForNoHitProgram) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, 0x01,   OP_PUSH1, 0x02,
                                         OP_ADD,   OP_POP, OP_STOP};

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MemoryFactsCapturingBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MemoryFactsCapturingBuilder> Visitor(Builder,
                                                                    &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_EQ(Builder.SetMemoryFactsCount, 0u);
}

TEST(EVMJITFrontendVisitorTest, IgnoresMemoryOpcodeInPushPayload) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1, OP_MSTORE, OP_POP, OP_STOP};

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MemoryFactsCapturingBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MemoryFactsCapturingBuilder> Visitor(Builder,
                                                                    &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_EQ(Builder.SetMemoryFactsCount, 0u);
}

TEST(EVMJITFrontendVisitorTest, ConservativelyAdmitsPotentialMultiBlockCFG) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH1,  0x01,        OP_PUSH1, 0x80,
                                         OP_MSTORE, OP_JUMPDEST, OP_STOP};

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MemoryFactsCapturingBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MemoryFactsCapturingBuilder> Visitor(Builder,
                                                                    &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_EQ(Builder.SetMemoryFactsCount, 1u);
}

TEST(EVMJITFrontendVisitorTest, PreservesDenseExactProofOpportunity) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1,     0x20,     OP_PUSH1, 0x80,     OP_KECCAK256,
      OP_POP,       OP_PUSH1, 0x20,     OP_PUSH1, 0x80,
      OP_KECCAK256, OP_POP,   OP_STOP};

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MemoryFactsCapturingBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MemoryFactsCapturingBuilder> Visitor(Builder,
                                                                    &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_EQ(Builder.SetMemoryFactsCount, 1u);
  EXPECT_EQ(Builder.CapturedFacts.Ops.size(), 2u);
}
#endif

TEST(EVMJITFrontendVisitorTest, UsesActiveRevisionForMemoryEffectFacts) {
  const std::vector<uint8_t> Bytecode = {OP_PUSH0, OP_PUSH0, OP_PUSH0, OP_MCOPY,
                                         OP_STOP};

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_SHANGHAI);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MemoryFactsCapturingBuilder Builder;
  COMPILER::EVMByteCodeVisitor<MemoryFactsCapturingBuilder> Visitor(Builder,
                                                                    &Ctx);
  EXPECT_TRUE(Visitor.compile());
  ASSERT_EQ(Builder.CapturedFacts.Ops.size(), 1u);
  const COMPILER::MemoryOp &Op = Builder.CapturedFacts.Ops[0];
  EXPECT_EQ(Op.Opcode, OP_MCOPY);
  EXPECT_EQ(Op.Kind, COMPILER::MemoryOpKind::Other);
  EXPECT_EQ(Op.Effect, COMPILER::MemoryEffect::Unknown);
  EXPECT_TRUE(Op.ObservableEffects.mayTrapOrHalt());
  EXPECT_TRUE(Op.ObservableEffects.terminatesFrame());
}

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

TEST(EVMMirBuilderStackBoundaryBatchTest,
     EmptyOneSixteenAndSeventeenSlotBatchesBuild) {
  MirBuilderConstFoldHarness Harness;
  using Operand = EVMMirBuilder::Operand;

  const size_t InitialStatements =
      Harness.Func.getBasicBlock(0)->getNumStatements();
  EXPECT_TRUE(Harness.Builder.peekStackBatch(0).empty());
  Harness.Builder.dropStackBatch(0);
  Harness.Builder.pushStackBatch({});
  EXPECT_EQ(Harness.Func.getBasicBlock(0)->getNumStatements(),
            InitialStatements);

  for (uint32_t Count : {1u, 16u, 17u}) {
    std::vector<Operand> Values;
    Values.reserve(Count);
    for (uint32_t Index = 0; Index < Count; ++Index) {
      Values.emplace_back(
          EVMMirBuilder::U256Value{Index, Index + 1, Index + 2, Index + 3});
    }
    Harness.Builder.pushStackBatch(Values);
    EXPECT_EQ(Harness.Builder.peekStackBatch(Count).size(), Count);
    Harness.Builder.dropStackBatch(Count);
  }
}

TEST(EVMJITFrontendVisitorTest,
     BatchProtocolPreservesBottomToTopOrderAndSkipTop) {
  MockEVMBuilder Builder;
  for (uint64_t Value = 1; Value <= 17; ++Value) {
    Builder.stackPush(MockOperand(Value));
  }

  std::vector<MockOperand> Bottom =
      Builder.peekStackBatch(/*Count=*/1, /*SkipTop=*/16);
  ASSERT_EQ(Bottom.size(), 1u);
  EXPECT_EQ(Bottom[0].resolvedValue()[0], 1u);

  std::vector<MockOperand> All = Builder.peekStackBatch(17);
  ASSERT_EQ(All.size(), 17u);
  for (uint64_t Index = 0; Index < All.size(); ++Index) {
    EXPECT_EQ(All[Index].resolvedValue()[0], Index + 1);
  }
  Builder.dropStackBatch(17);
  EXPECT_EQ(Builder.runtimeStackDepth(), 0u);

  Builder.pushStackBatch(All);
  ASSERT_EQ(Builder.runtimeStackDepth(), 17u);
  for (uint64_t Index = 0; Index < All.size(); ++Index) {
    EXPECT_EQ(Builder.runtimeStackValueFromBottom(Index)[0], Index + 1);
  }

  const MockBatchStackAccessStats &Stats = Builder.batchAccessStats();
  EXPECT_EQ(Stats.PeekCalls, 2u);
  EXPECT_EQ(Stats.PeekSlots, 18u);
  EXPECT_EQ(Stats.DropCalls, 1u);
  EXPECT_EQ(Stats.DropSlots, 17u);
  EXPECT_EQ(Stats.PushCalls, 1u);
  EXPECT_EQ(Stats.PushSlots, 17u);
  EXPECT_EQ(Stats.StackTopUpdates, 2u);
  EXPECT_EQ(Stats.StackSizeUpdates, 2u);
}

TEST(EVMJITFrontendVisitorTest, TerminatingMemoryHelpersRetainExactOpcodePC) {
  const std::vector<uint8_t> ReturnBytecode = {OP_PUSH0, OP_PUSH0, OP_RETURN};
  const std::vector<uint8_t> RevertBytecode = {OP_PUSH0, OP_PUSH0, OP_REVERT};

  MockEVMBuilder ReturnBuilder;
  ASSERT_TRUE(compileWithMockBuilder(ReturnBytecode, ReturnBuilder));
  ASSERT_EQ(ReturnBuilder.helperOpcodes().size(), 1u);
  EXPECT_EQ(ReturnBuilder.helperOpcodes()[0].Opcode, OP_RETURN);
  EXPECT_EQ(ReturnBuilder.helperOpcodes()[0].PC, 2u);

  MockEVMBuilder RevertBuilder;
  ASSERT_TRUE(compileWithMockBuilder(RevertBytecode, RevertBuilder));
  ASSERT_EQ(RevertBuilder.helperOpcodes().size(), 1u);
  EXPECT_EQ(RevertBuilder.helperOpcodes()[0].Opcode, OP_REVERT);
  EXPECT_EQ(RevertBuilder.helperOpcodes()[0].PC, 2u);
}

TEST(EVMJITFrontendVisitorTest,
     DynamicDispatchTaintedEntryRetainsTopologyWithoutMemoryOps) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH0,    OP_CALLDATALOAD,
      OP_JUMP,
      OP_JUMPDEST, // PC3: dynamically dispatched region target.
      OP_PUSH1,    0x01,
      OP_PUSH0,
      OP_MSTORE, // PC7
      OP_STOP};

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *TargetBlock = findBlock(Analyzer, 3);
  ASSERT_NE(TargetBlock, nullptr);
  ASSERT_EQ(TargetBlock->ResolvedEntryStackDepth, 0);
  ASSERT_TRUE(TargetBlock->EntryDepthMayComeFromDynamicDispatch);

  MockEVMBuilder Builder;
  ASSERT_TRUE(compileWithMockBuilder(Bytecode, Builder));

  const COMPILER::MemoryFacts &Facts = Builder.memoryFacts();
  const COMPILER::MemoryBlockFacts *TargetFacts = Facts.getBlock(3);
  ASSERT_NE(TargetFacts, nullptr);
  EXPECT_FALSE(TargetFacts->HasCompleteOpcodeFacts);
  for (const COMPILER::MemoryOp &Op : Facts.Ops) {
    EXPECT_NE(Op.Pc, 7u);
  }
}

TEST(EVMJITFrontendVisitorTest,
     UnresolvedDynamicEntryRetainsTopologyWithoutMemoryOps) {
  const std::vector<uint8_t> Bytecode = {
      // Two dynamic sources reach PC24 with different hidden live-in depths.
      OP_PUSH0,
      OP_CALLDATALOAD,
      OP_PUSH1,
      0x0d,
      OP_JUMPI,
      OP_PUSH1,
      0x11,
      OP_PUSH1,
      0x22,
      OP_PUSH1,
      0x20,
      OP_CALLDATALOAD,
      OP_JUMP,
      OP_JUMPDEST,
      OP_PUSH1,
      0x11,
      OP_PUSH1,
      0x22,
      OP_PUSH1,
      0x33,
      OP_PUSH1,
      0x20,
      OP_CALLDATALOAD,
      OP_JUMP,
      OP_JUMPDEST, // PC24: unresolved dynamic-dispatch target.
      OP_PUSH1,
      0x01,
      OP_PUSH0,
      OP_MSTORE, // PC28
      OP_STOP};

  const EVMAnalyzer Analyzer = analyzeBytecode(Bytecode);
  const auto *TargetBlock = findBlock(Analyzer, 24);
  ASSERT_NE(TargetBlock, nullptr);
  ASSERT_LT(TargetBlock->ResolvedEntryStackDepth, 0);

  MockEVMBuilder Builder;
  ASSERT_TRUE(compileWithMockBuilder(Bytecode, Builder));

  const COMPILER::MemoryFacts &Facts = Builder.memoryFacts();
  const COMPILER::MemoryBlockFacts *TargetFacts = Facts.getBlock(24);
  ASSERT_NE(TargetFacts, nullptr);
  EXPECT_FALSE(TargetFacts->HasCompleteOpcodeFacts);
  for (const COMPILER::MemoryOp &Op : Facts.Ops) {
    EXPECT_NE(Op.Pc, 28u);
  }
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

TEST(EVMJITFrontendVisitorTest,
     PlansFusedLinearMStoreMemoryPrecheckWithDynamicStride) {
  const std::vector<uint8_t> Bytecode = {
      0x5f, // PUSH0 calldata offset for stride
      0x35, // CALLDATALOAD
      0x5f, // PUSH0 current
      0x80, // DUP1
      0x80, // DUP1
      0x52, // MSTORE
      0x81, // DUP2
      0x01, // ADD
      0x80, // DUP1
      0x80, // DUP1
      0x52, // MSTORE
      0x81, // DUP2
      0x01, // ADD
      0x00  // STOP
  };

  COMPILER::EVMFrontendContext Ctx;
  Ctx.setRevision(EVMC_CANCUN);
  Ctx.setBytecode(reinterpret_cast<const zen::common::Byte *>(Bytecode.data()),
                  Bytecode.size());

  MockEVMBuilder Builder;
  Builder.setCallDataLoadResult(7);
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.linearPrecheckPlanCount(), 1U);
  EXPECT_EQ(Builder.lastLinearPrecheckAccessWidth(), 32U);
  EXPECT_EQ(Builder.lastLinearPrecheckCoveredDirectOps(), 2U);
  EXPECT_TRUE(Builder.lastLinearPrecheckValueEqualsFirstAddr());
  EXPECT_EQ(Builder.linearPrecheckPrepareCount(), 2U);
  EXPECT_EQ(Builder.lastLinearPrecheckStride(), 7U);
  EXPECT_EQ(Builder.meteredOpcodeCount(OP_MSTORE), 2U);
  EXPECT_EQ(Builder.mstoreCount(), 2U);
  EXPECT_EQ(Builder.runtimeStackDepth(), 2U);
  EXPECT_EQ(Builder.topStackValue()[0], 14U);
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
  Builder.setCallDataLoadResult(11);
  COMPILER::EVMByteCodeVisitor<MockEVMBuilder> Visitor(Builder, &Ctx);
  EXPECT_TRUE(Visitor.compile());
  EXPECT_FALSE(Builder.Trapped);
  EXPECT_FALSE(Builder.Undefined);

  EXPECT_EQ(Builder.linearPrecheckPlanCount(), 1U);
  EXPECT_EQ(Builder.lastLinearPrecheckAccessWidth(), 1U);
  EXPECT_EQ(Builder.lastLinearPrecheckCoveredDirectOps(), 2U);
  EXPECT_FALSE(Builder.lastLinearPrecheckValueEqualsFirstAddr());
  EXPECT_EQ(Builder.linearPrecheckPrepareCount(), 2U);
  EXPECT_EQ(Builder.lastLinearPrecheckStride(), 11U);
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
