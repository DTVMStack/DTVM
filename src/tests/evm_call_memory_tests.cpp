// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/evm_frontend/evm_imported.h"
#include "compiler/evm_frontend/evm_mir_compiler.h"
#include "compiler/mir/module.h"
#include "runtime/evm_instance.h"

#include "llvm/Support/raw_ostream.h"
#include <gtest/gtest.h>

#include <array>
#include <optional>
#include <string>
#include <vector>

namespace {

using COMPILER::EVMMirBuilder;

#ifdef ZEN_ENABLE_EVM_MEMORY_PLAN_FRAMEWORK
std::optional<std::string>
compileCallMemoryMir(const std::vector<uint8_t> &Bytecode) {
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
bool containsRuntimeCall(const std::string &Mir, FuncType Function) {
  const std::string Needle =
      "target = const.i64 " +
      std::to_string(COMPILER::getFunctionAddress(Function)) + ", ";
  return Mir.find(Needle) != std::string::npos;
}

std::vector<uint8_t> makeCallBytecode(evmc_opcode Opcode,
                                      uint8_t RetOffset = 0xa0) {
  std::vector<uint8_t> Bytecode = {
      OP_PUSH1,  0x01,     OP_PUSH1,    0xa0,     OP_MSTORE, OP_PUSH1,
      0x08,      OP_JUMP,  OP_JUMPDEST, OP_PUSH1, 0x20,      OP_PUSH1,
      RetOffset, OP_PUSH1, 0x20,        OP_PUSH1, 0x80};
  if (Opcode == OP_CALL || Opcode == OP_CALLCODE) {
    Bytecode.push_back(OP_PUSH0);
  }
  Bytecode.insert(Bytecode.end(), {OP_PUSH1, 0x04, OP_PUSH2, 0xff, 0xff,
                                   static_cast<uint8_t>(Opcode), OP_STOP});
  return Bytecode;
}

TEST(EVMMirBuilderCallMemoryProofTest, SelectsPreparedHelpersForAllCallKinds) {
  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();

  const auto CallMir = compileCallMemoryMir(makeCallBytecode(OP_CALL));
  const auto CallCodeMir = compileCallMemoryMir(makeCallBytecode(OP_CALLCODE));
  const auto DelegateCallMir =
      compileCallMemoryMir(makeCallBytecode(OP_DELEGATECALL));
  const auto StaticCallMir =
      compileCallMemoryMir(makeCallBytecode(OP_STATICCALL));
  ASSERT_TRUE(CallMir.has_value());
  ASSERT_TRUE(CallCodeMir.has_value());
  ASSERT_TRUE(DelegateCallMir.has_value());
  ASSERT_TRUE(StaticCallMir.has_value());

  EXPECT_TRUE(
      containsRuntimeCall(*CallMir, RuntimeFunctions.HandleCallNoExpand));
  EXPECT_TRUE(containsRuntimeCall(*CallCodeMir,
                                  RuntimeFunctions.HandleCallCodeNoExpand));
  EXPECT_TRUE(containsRuntimeCall(*DelegateCallMir,
                                  RuntimeFunctions.HandleDelegateCallNoExpand));
  EXPECT_TRUE(containsRuntimeCall(*StaticCallMir,
                                  RuntimeFunctions.HandleStaticCallNoExpand));
}

TEST(EVMMirBuilderCallMemoryProofTest,
     KeepsGenericHelperWhenEitherRangeIsUncovered) {
  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  const auto CallMir = compileCallMemoryMir(makeCallBytecode(OP_CALL, 0xc0));
  const auto StaticCallMir =
      compileCallMemoryMir(makeCallBytecode(OP_STATICCALL, 0xc0));
  ASSERT_TRUE(CallMir.has_value());
  ASSERT_TRUE(StaticCallMir.has_value());

  EXPECT_TRUE(containsRuntimeCall(*CallMir, RuntimeFunctions.HandleCall));
  EXPECT_FALSE(
      containsRuntimeCall(*CallMir, RuntimeFunctions.HandleCallNoExpand));
  EXPECT_TRUE(
      containsRuntimeCall(*StaticCallMir, RuntimeFunctions.HandleStaticCall));
  EXPECT_FALSE(containsRuntimeCall(*StaticCallMir,
                                   RuntimeFunctions.HandleStaticCallNoExpand));
}

TEST(EVMMirBuilderPreparedMemoryProofTest,
     KeepsGenericRangeHelpersForDynamicOffsets) {
  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  const std::vector<uint8_t> CodeCopyBytecode = {
      OP_PUSH1,        0x20, // copy size
      OP_PUSH0,              // code offset
      OP_PUSH0,              // calldata offset
      OP_CALLDATALOAD,
      OP_CODECOPY, // dynamic destination offset
      OP_STOP,
  };
  const std::vector<uint8_t> KeccakBytecode = {
      OP_PUSH1,        0x20, // hash size
      OP_PUSH0,              // calldata offset
      OP_CALLDATALOAD,
      OP_KECCAK256, // dynamic memory offset
      OP_STOP,
  };
  const std::vector<uint8_t> ReturnBytecode = {
      OP_PUSH1,        0x20, // return size
      OP_PUSH0,              // calldata offset
      OP_CALLDATALOAD,
      OP_RETURN, // dynamic memory offset
  };
  const std::vector<uint8_t> RevertBytecode = {
      OP_PUSH1,        0x20, // revert size
      OP_PUSH0,              // calldata offset
      OP_CALLDATALOAD,
      OP_REVERT, // dynamic memory offset
  };

  const auto CodeCopyMir = compileCallMemoryMir(CodeCopyBytecode);
  const auto KeccakMir = compileCallMemoryMir(KeccakBytecode);
  const auto ReturnMir = compileCallMemoryMir(ReturnBytecode);
  const auto RevertMir = compileCallMemoryMir(RevertBytecode);
  ASSERT_TRUE(CodeCopyMir.has_value());
  ASSERT_TRUE(KeccakMir.has_value());
  ASSERT_TRUE(ReturnMir.has_value());
  ASSERT_TRUE(RevertMir.has_value());

  EXPECT_TRUE(containsRuntimeCall(*CodeCopyMir, RuntimeFunctions.SetCodeCopy));
  EXPECT_FALSE(
      containsRuntimeCall(*CodeCopyMir, RuntimeFunctions.SetCodeCopyNoExpand));
  EXPECT_TRUE(containsRuntimeCall(*KeccakMir, RuntimeFunctions.GetKeccak256));
  EXPECT_FALSE(
      containsRuntimeCall(*KeccakMir, RuntimeFunctions.GetKeccak256NoExpand));
  EXPECT_TRUE(containsRuntimeCall(*ReturnMir, RuntimeFunctions.SetReturn));
  EXPECT_FALSE(
      containsRuntimeCall(*ReturnMir, RuntimeFunctions.SetReturnNoExpand));
  EXPECT_TRUE(containsRuntimeCall(*RevertMir, RuntimeFunctions.SetRevert));
  EXPECT_FALSE(
      containsRuntimeCall(*RevertMir, RuntimeFunctions.SetRevertNoExpand));
}

TEST(EVMMirBuilderPreparedMemoryProofTest,
     ReloadsMemoryBaseBeforeSizeAfterColdCodeCopy) {
  const std::vector<uint8_t> Bytecode = {
      OP_PUSH1, 0x20, OP_PUSH0, OP_PUSH1,  0x80,    OP_CODECOPY,
      OP_PUSH1, 0x01, OP_PUSH0, OP_MSTORE, OP_STOP,
  };
  const auto Mir = compileCallMemoryMir(Bytecode);
  ASSERT_TRUE(Mir.has_value());

  const auto &RuntimeFunctions = COMPILER::getRuntimeFunctionTable();
  const std::string CodeCopyCall = "target = const.i64 " +
                                   std::to_string(COMPILER::getFunctionAddress(
                                       RuntimeFunctions.SetCodeCopy)) +
                                   ", ";
  const std::string MemoryBaseLoad =
      "offset = " +
      std::to_string(zen::runtime::EVMInstance::getMemoryBaseOffset()) + ")";
  const std::string MemorySizeLoad =
      "offset = " +
      std::to_string(zen::runtime::EVMInstance::getMemorySizeOffset()) + ")";

  const size_t CallPos = Mir->find(CodeCopyCall);
  ASSERT_NE(CallPos, std::string::npos);
  const size_t BaseReloadPos = Mir->find(MemoryBaseLoad, CallPos);
  const size_t SizeReloadPos = Mir->find(MemorySizeLoad, CallPos);
  ASSERT_NE(BaseReloadPos, std::string::npos);
  ASSERT_NE(SizeReloadPos, std::string::npos);
  EXPECT_LT(BaseReloadPos, SizeReloadPos);
}
#endif

} // namespace
