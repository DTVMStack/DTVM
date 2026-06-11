// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "evm/evm.h"
#include "evm_test_host.hpp"
#include "runtime/evm_module.h"
#include "utils/evm.h"
#include "zetaengine.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

#ifdef ZEN_ENABLE_MULTIPASS_JIT

namespace {

std::filesystem::path getEvmAsmDirPath() {
  return std::filesystem::path(__FILE__).parent_path() /
         std::filesystem::path("../../tests/evm_asm");
}

struct EVMExecutionResult {
  evmc_status_code Status = EVMC_INTERNAL_ERROR;
  std::string OutputHex;
  bool JITCompiled = false;
};

// Run `Bytecode` in `Mode`, forcing synchronous multipass compilation so the
// multipass run actually executes JIT code. The default async/multithread
// config can fall back to the interpreter for a single call, which would make
// a differential test vacuous; DisableMultipassMultithread compiles before the
// run so the JIT side is non-vacuous.
EVMExecutionResult runEvmBytecode(const std::string &Label,
                                  const std::vector<uint8_t> &Bytecode,
                                  common::RunMode Mode,
                                  const std::vector<uint8_t> &CallData = {}) {
  EVMExecutionResult Empty;

  RuntimeConfig Config;
  Config.Mode = Mode;
  Config.DisableMultipassMultithread = true; // compile before run -> JIT used

  auto MockedHost = std::make_unique<zen::evm::ZenMockedEVMHost>();
  MockedHost->tx_context.tx_origin = zen::evm::DEFAULT_DEPLOYER_ADDRESS;
  auto RT = Runtime::newEVMRuntime(Config, MockedHost.get());
  if (!RT) {
    ADD_FAILURE() << "runtime create failed: " << Label;
    return Empty;
  }
  MockedHost->setRuntime(RT.get());

  auto ModRet = RT->loadEVMModule(Label, Bytecode.data(), Bytecode.size());
  if (!ModRet) {
    ADD_FAILURE() << "module load failed: " << Label;
    return Empty;
  }
  EVMModule *Mod = *ModRet;

  Isolation *Iso = RT->createManagedIsolation();
  if (!Iso) {
    ADD_FAILURE() << "isolation create failed: " << Label;
    return Empty;
  }

  const uint64_t GasLimit = 0xFFFF'FFFF'FFFF - zen::evm::BASIC_EXECUTION_COST;
  auto InstRet = Iso->createEVMInstance(*Mod, GasLimit);
  if (!InstRet) {
    ADD_FAILURE() << "instance create failed: " << Label;
    return Empty;
  }
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(evmc_revision::EVMC_OSAKA);

  evmc_message Msg = {
      .kind = EVMC_CALL,
      .flags = 0u,
      .depth = 0,
      .gas = static_cast<int64_t>(GasLimit),
      .recipient = {},
      .sender = zen::evm::DEFAULT_DEPLOYER_ADDRESS,
      .input_data = CallData.empty() ? nullptr : CallData.data(),
      .input_size = CallData.size(),
      .value = {},
      .create2_salt = {},
      .code_address = {},
      .code = reinterpret_cast<const uint8_t *>(Mod->Code),
      .code_size = Mod->CodeSize,
  };

  evmc::Result RawResult;
  EVMExecutionResult Exec;
#ifdef ZEN_ENABLE_JIT
  Exec.JITCompiled = Mod->getJITCode() != nullptr && Mod->getJITCodeSize() > 0;
#endif
  EXPECT_NO_THROW({ RT->callEVMMain(*Inst, Msg, RawResult); });
  Exec.Status = RawResult.status_code;
  Exec.OutputHex =
      zen::utils::toHex(RawResult.output_data, RawResult.output_size);
  return Exec;
}

EVMExecutionResult
runEvmBytecodeFile(const std::string &FilePath, common::RunMode Mode,
                   const std::vector<uint8_t> &CallData = {}) {
  EVMExecutionResult Empty;

  std::ifstream Fin(FilePath);
  if (!Fin.is_open()) {
    ADD_FAILURE() << "Failed to open test file: " << FilePath;
    return Empty;
  }

  std::string Hex;
  Fin >> Hex;
  zen::utils::trimString(Hex);
  auto BytecodeBuf = zen::utils::fromHex(Hex);
  if (!BytecodeBuf) {
    ADD_FAILURE() << "Failed to convert hex to bytecode: " << FilePath;
    return Empty;
  }

  return runEvmBytecode(FilePath, *BytecodeBuf, Mode, CallData);
}

// Run `Bytecode` through interpreter and multipass, assert the interpreter
// run succeeds (a shared failure such as out-of-gas would make the comparison
// vacuous), the multipass JIT compiled, and that status + output agree.
// Returns false on any violation so matrix callers can stop flooding output.
bool expectInterpMatchesMultipass(const std::string &Label,
                                  const std::vector<uint8_t> &Bytecode,
                                  const std::vector<uint8_t> &CallData) {
  auto Interp = runEvmBytecode(Label + "_interp", Bytecode,
                               common::RunMode::InterpMode, CallData);
  auto Multi = runEvmBytecode(Label + "_multipass", Bytecode,
                              common::RunMode::MultipassMode, CallData);
#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "multipass did not JIT-compile: " << Label;
#endif
  EXPECT_EQ(Interp.Status, EVMC_SUCCESS)
      << "interpreter did not succeed: " << Label;
  EXPECT_EQ(Multi.Status, Interp.Status) << "status diverged: " << Label;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex) << "output diverged: " << Label;
  return Interp.Status == EVMC_SUCCESS && Multi.Status == Interp.Status &&
         Multi.OutputHex == Interp.OutputHex;
}

// Fixture-file variant of the assertion above: load a hex fixture, run both
// engines, and require the multipass JIT output to match the interpreter (the
// full-width ground truth) for the named stem.
void expectFixtureInterpMatchesMultipass(const std::string &Stem) {
  const auto FilePath = (getEvmAsmDirPath() / (Stem + ".evm.hex")).string();

  auto Interp = runEvmBytecodeFile(FilePath, common::RunMode::InterpMode);
  auto Multi = runEvmBytecodeFile(FilePath, common::RunMode::MultipassMode);

#ifdef ZEN_ENABLE_JIT
  EXPECT_TRUE(Multi.JITCompiled) << "Multipass JIT should compile " << Stem;
#endif

  EXPECT_EQ(Interp.Status, EVMC_SUCCESS)
      << "Interpreter did not succeed for " << Stem;
  EXPECT_EQ(Multi.Status, Interp.Status)
      << "Multipass status diverged from interpreter for " << Stem;
  EXPECT_EQ(Multi.OutputHex, Interp.OutputHex)
      << "Multipass output diverged from interpreter for " << Stem;
}

std::string fixtureTestName(const testing::TestParamInfo<std::string> &Info) {
  return Info.param;
}

} // namespace

// ===========================================================================
// Fixture-based differential suite.
//
// Each fixture feeds a dynamic (analyzer-unprovable) operand through an opcode
// whose multipass lowering has a value-range fast path, then asserts the JIT
// output matches the interpreter (the full-width reference) exactly. A
// divergence means a narrowed fold produced a wrong value, not merely a slower
// one. The fixtures hold on the plain lowering as well as the narrowed one, so
// they guard the invariant independently of whether the fast paths are present.
// ===========================================================================

class EVMFixtureDifferentialTest
    : public ::testing::TestWithParam<std::string> {};

TEST_P(EVMFixtureDifferentialTest, InterpMatchesMultipass) {
  expectFixtureInterpMatchesMultipass(GetParam());
}

// Range-narrowed lowering paths: the range-narrowed ISZERO/JUMPI folds,
// U64-tagged OR/XOR, and the signed-compare (SLT/SGT) u64-const fast paths in
// the multipass lowering. Each fixture feeds a dynamic operand so the narrowed
// path is actually taken.
INSTANTIATE_TEST_SUITE_P(
    RangeNarrowing, EVMFixtureDifferentialTest,
    ::testing::Values("iszero_dyn_u64_nonzero", "iszero_dyn_highsparse",
                      "iszero_calldatasize", "jumpi_iszero_fused_taken",
                      "jumpi_iszero_fused_nottaken_highsparse",
                      "jumpi_iszero_iszero_fused", "jumpi_u64_cond_taken",
                      "jumpi_u64_cond_nottaken", "or_dyn_u64_u64",
                      "xor_dyn_u64_u64", "or_dyn_u64_wide", "xor_dyn_u64_wide",
                      "slt_dyn_neg_vs_const", "slt_dyn_highsparse_vs_const",
                      "slt_dyn_msb64_vs_const", "slt_dyn_eq_const",
                      "sgt_dyn_neg_vs_const", "sgt_dyn_highsparse_vs_const",
                      "sgt_dyn_msb64_vs_const", "slt_const_vs_dyn",
                      "sgt_const_vs_dyn"),
    fixtureTestName);

// Const-shift guard pruning and range-aware source-limb pruning in handleShift.
// Each fixture must yield identical output in the interpreter and the multipass
// JIT, and the multipass module must JIT.
INSTANTIATE_TEST_SUITE_P(
    ConstShiftPruning, EVMFixtureDifferentialTest,
    ::testing::Values("shl_const4_dyn", "shl_const96_dyn",
                      "shl_const136_u64val", "shl_const200_u64val",
                      "shl_const256_dyn", "shl_const_highlimb_dyn",
                      "shr_const4_dyn", "shr_const72_dyn", "shr_const8_u64val",
                      "shr_const256_dyn", "sar_const8_neg", "sar_const64_pos",
                      "shl_dyn_amount"),
    fixtureTestName);

// Range-based u64 SUB fast path. Each stem exercises (a - b) mod 2^256 with
// both operands range-proven u64 (except the wide control), including the
// adversarial underflow cases where the upper 192 bits sign-fill to all-ones.
// Interpreter and multipass JIT must agree.
INSTANTIATE_TEST_SUITE_P(
    SubWrapU64, EVMFixtureDifferentialTest,
    ::testing::Values("sub_u64_pair_nounderflow", "sub_u64_pair_underflow",
                      "sub_u64_pair_equal", "sub_u64_pair_wrap_boundary",
                      "sub_u64_pair_zero_rhs_dyn", "sub_wide_u64_control"),
    fixtureTestName);

// ===========================================================================
// Value-range lowering differential matrix harness.
//
// A multipass value-range fast path that emits a single- or double-limb result
// MUST be bit-identical to the full 4-limb path for every input the range tag
// claims to cover. A too-narrow tag silently miscompiles only on operands with
// non-zero high limbs, which ordinary corpora rarely carry. Each test drives an
// opcode with an adversarial operand matrix (value-range boundaries +
// high-sparse {0,x,0,0}/{0,0,0,x}) and asserts the multipass JIT agrees
// bit-for-bit with the interpreter (the full-width reference).
//
// Coverage split (the operands decide which lowering path fires):
//   - BinaryOpsMatchInterpreterOnAdversarialOperands feeds two CALLDATALOAD
//     operands, which are dynamic and U256-range, so they do NOT enter the
//     bothFitU64 / AND-narrow fast paths: this test gates the FULL-width
//     4-limb lowering (the #487-class high-limb-corruption surface). It sweeps
//     20 binary opcodes (arithmetic, comparison, bitwise, BYTE, SIGNEXTEND,
//     and the three shifts). EXP is excluded because its gas cost scales with
//     the exponent byte length, so high-limb operands would trip out-of-gas
//     instead of exposing a value-range divergence.
//   - ShiftAmountsMatchInterpreterOnLimbBoundaries sweeps SHL/SHR/SAR with
//     shift amounts in the limb-crossing region 2..255. The 11-value operand
//     matrix, used as a shift amount, only realizes {0, 1, >=2^64}, so the
//     dynamic-shift cross-limb carry/offset logic is unreachable from the
//     binary-op sweep above; this test covers it.
//   - The AndU64Mask* tests construct a provably-U64 operand (AND with a u64
//     constant) and feed it directly / through a bothFitU64 ADD, so they gate
//     the actual narrowing fast paths.
// ===========================================================================

namespace {

// Build a big-endian 32-byte word holding `Val` in 64-bit limb `Limb`
// (limb 0 = least significant). OR several together for multi-limb operands.
std::vector<uint8_t> matrixLimb(int Limb, uint64_t Val) {
  std::vector<uint8_t> W(32, 0);
  const int Base = 24 - Limb * 8; // limb 0 -> bytes [24..31]
  for (int I = 0; I < 8; ++I) {
    W[Base + 7 - I] = static_cast<uint8_t>((Val >> (8 * I)) & 0xff);
  }
  return W;
}

std::vector<uint8_t> matrixOr(std::vector<uint8_t> A,
                              const std::vector<uint8_t> &B) {
  for (size_t I = 0; I < A.size(); ++I) {
    A[I] |= B[I];
  }
  return A;
}

// Adversarial operand matrix: each entry is a 32-byte big-endian u256.
std::vector<std::vector<uint8_t>> matrixOperands() {
  const uint64_t Max = 0xFFFFFFFFFFFFFFFFull;
  std::vector<std::vector<uint8_t>> Ops;
  Ops.push_back(matrixLimb(0, 0));   // 0
  Ops.push_back(matrixLimb(0, 1));   // 1
  Ops.push_back(matrixLimb(0, Max)); // 2^64 - 1 (U64 boundary)
  Ops.push_back(matrixLimb(1, 1));   // 2^64
  Ops.push_back(matrixOr(matrixLimb(0, Max), matrixLimb(1, Max))); // U128-1
  Ops.push_back(matrixLimb(2, 1)); // 2^128 (U128 boundary)
  Ops.push_back(matrixLimb(3, 1)); // 2^192 (high-sparse {0,0,0,x})
  Ops.push_back(matrixOr(matrixLimb(3, 1), matrixLimb(0, 5))); // 2^192+5
  Ops.push_back(matrixLimb(1, 5));                     // high-sparse {0,x,0,0}
  Ops.push_back(matrixLimb(3, 0x8000000000000000ull)); // 2^255 (sign bit)
  Ops.push_back(
      matrixOr(matrixOr(matrixLimb(0, Max), matrixLimb(1, Max)),
               matrixOr(matrixLimb(2, Max), matrixLimb(3, Max)))); // 2^256-1
  return Ops;
}

std::vector<uint8_t> matrixCalldata(const std::vector<uint8_t> &A,
                                    const std::vector<uint8_t> &B) {
  std::vector<uint8_t> CD;
  CD.insert(CD.end(), A.begin(), A.end());
  CD.insert(CD.end(), B.begin(), B.end());
  return CD;
}

// "a = calldata[0:32]; b = calldata[32:64]; OP". After the two pushes, b is on
// top of the stack, so EVM evaluates `b OP a` (e.g. SUB = b - a; for shifts the
// shift amount is b). The exact convention is irrelevant to a differential test
// — both engines run identical bytecode — and the nested A*B sweep feeds every
// matrix value into both slots regardless.
std::vector<uint8_t> matrixBinOp(uint8_t Op) {
  return {0x60, 0x00, 0x35,              // PUSH1 0    CALLDATALOAD -> a
          0x60, 0x20, 0x35,              // PUSH1 0x20 CALLDATALOAD -> b
          Op,                            // b OP a
          0x60, 0x00, 0x52,              // PUSH1 0 MSTORE
          0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0, 32)
}

} // namespace

// Differential over every binary opcode whose lowering touches limbs. Operands
// are dynamic CALLDATALOAD (U256-range), so this gates the FULL-width 4-limb
// path, not the narrow fast paths (those are gated by the AndU64Mask* tests).
// On the first divergent (op, operand) pair the whole test returns, so a single
// regression reports one op and skips the rest — intentional output-flood
// control, not full per-op isolation.
//
// EXP (0x0a) is intentionally excluded: its gas cost scales with the byte
// length of the exponent, so the high-limb operands in this matrix (2^192,
// 2^255, 2^256-1) would charge enormous dynamic gas and obscure a pure
// value-range divergence behind out-of-gas noise. Shift amounts, which need
// the limb-crossing region 2..255, are swept separately by
// ShiftAmountsMatchInterpreterOnLimbBoundaries below.
TEST(EVMRangeDifferential, BinaryOpsMatchInterpreterOnAdversarialOperands) {
  struct OpCase {
    uint8_t Op;
    const char *Name;
  };
  const OpCase Cases[] = {
      {0x01, "ADD"},  {0x02, "MUL"}, {0x03, "SUB"},  {0x04, "DIV"},
      {0x05, "SDIV"}, {0x06, "MOD"}, {0x07, "SMOD"}, {0x0b, "SIGNEXTEND"},
      {0x10, "LT"},   {0x11, "GT"},  {0x12, "SLT"},  {0x13, "SGT"},
      {0x14, "EQ"},   {0x16, "AND"}, {0x17, "OR"},   {0x18, "XOR"},
      {0x1a, "BYTE"}, {0x1b, "SHL"}, {0x1c, "SHR"},  {0x1d, "SAR"},
  };
  const auto Operands = matrixOperands();
  for (const auto &C : Cases) {
    const auto Bytecode = matrixBinOp(C.Op);
    for (const auto &A : Operands) {
      for (const auto &B : Operands) {
        if (!expectInterpMatchesMultipass(C.Name, Bytecode,
                                          matrixCalldata(A, B))) {
          return; // one divergence is enough; avoid output flood
        }
      }
    }
  }
}

// Sweep SHL/SHR/SAR with shift amounts that land inside the limb-crossing
// region 2..255. The 11-value operand matrix, when fed as a shift amount, only
// realizes {0, 1, >=2^64}; it never produces an amount in 2..255, so the
// dynamic-shift lowering's cross-limb carry/offset logic (which moves bits
// across 64-bit limb boundaries at amounts 64/128/192 and within a limb at the
// rest) is never exercised by BinaryOpsMatchInterpreterOnAdversarialOperands.
//
// matrixBinOp puts the shift amount in slot b (calldata[32:64], the stack top
// SHL/SHR/SAR pops first) and the shifted value in slot a (calldata[0:32]).
// Both are CALLDATALOAD, so the full-width dynamic shift path fires. The
// shifted value sweeps the full adversarial matrix; the amount sweeps the
// boundary set below, covering both the on-limb-boundary amounts (64, 128, 192)
// and the in-limb amounts (2, 7, 31, 63, 65, 127, ...).
TEST(EVMRangeDifferential, ShiftAmountsMatchInterpreterOnLimbBoundaries) {
  struct OpCase {
    uint8_t Op;
    const char *Name;
  };
  const OpCase Cases[] = {
      {0x1b, "SHL"},
      {0x1c, "SHR"},
      {0x1d, "SAR"},
  };
  const uint64_t Amounts[] = {2,   7,   8,   31,  63,  64,  65, 127,
                              128, 129, 136, 191, 192, 200, 255};
  const auto Values = matrixOperands();
  for (const auto &C : Cases) {
    const auto Bytecode = matrixBinOp(C.Op);
    for (const auto &Value : Values) {
      for (uint64_t Amount : Amounts) {
        const auto AmountWord = matrixLimb(0, Amount);
        if (!expectInterpMatchesMultipass(C.Name, Bytecode,
                                          matrixCalldata(Value, AmountWord))) {
          return; // one divergence is enough; avoid output flood
        }
      }
    }
  }
}

// Directly exercise the AND-with-u64-constant fast path (CONST_U64): it tags
// the result U64 and MUST zero limbs[1..3]. Returning the result directly (not
// through a later narrow op that would discard the high limbs) is what makes a
// too-narrow / too-wide limb bug observable. Feeding high-sparse calldata, the
// masked result must equal the interpreter's.
//   a = calldata[0:32]; MSTORE(0, a AND 0xFFFFFFFFFFFFFFFF); RETURN 32.
TEST(EVMRangeDifferential, AndU64MaskMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, 0x35,                                     // CALLDATALOAD a
      0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // PUSH8 u64 mask
      0x16,                                                 // AND -> m (U64)
      0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3};      // RETURN(0,32)
  const auto Operands = matrixOperands();
  for (const auto &A : Operands) {
    if (!expectInterpMatchesMultipass("and_u64_mask", Bytecode,
                                      matrixCalldata(A, A))) {
      return;
    }
  }
}

// Exercise a narrow-result CONSUMER: AND with a u64 constant produces a U64
// value that feeds a self-ADD on the bothFitU64 narrow path. The summed result
// is returned; for any high-sparse input the narrowed two-limb sum must match
// the interpreter's full-width sum.
//   a = calldata[0:32]; m = a AND 0xFFFFFFFFFFFFFFFF; MSTORE(0, m + m); RETURN.
TEST(EVMRangeDifferential, AndU64MaskThenNarrowAddMatchesInterpreter) {
  const std::vector<uint8_t> Bytecode = {
      0x60, 0x00, 0x35,                                     // CALLDATALOAD a
      0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // PUSH8 u64 mask
      0x16,                                                 // AND -> m (U64)
      0x80,                                                 // DUP1
      0x01,                                            // ADD m + m (narrow)
      0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3}; // RETURN(0,32)
  const auto Operands = matrixOperands();
  for (const auto &A : Operands) {
    if (!expectInterpMatchesMultipass("and_u64_mask_then_add", Bytecode,
                                      matrixCalldata(A, A))) {
      return;
    }
  }
}

#endif
