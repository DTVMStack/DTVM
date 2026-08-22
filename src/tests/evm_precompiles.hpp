// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#ifndef ZEN_TESTS_EVM_PRECOMPILES_HPP
#define ZEN_TESTS_EVM_PRECOMPILES_HPP

#include "evm/evm.h"
#include <algorithm>
#include <array>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace zen::evm::precompile {

inline bool isPrecompileAddress(const evmc::address &Addr,
                                uint8_t Id) noexcept {
  for (size_t I = 0; I + 1 < sizeof(Addr.bytes); ++I) {
    if (Addr.bytes[I] != 0) {
      return false;
    }
  }
  return Addr.bytes[sizeof(Addr.bytes) - 1] == Id;
}

inline bool isModExpPrecompile(const evmc::address &Addr) noexcept {
  return isPrecompileAddress(Addr, 0x05);
}

inline bool isBlake2bPrecompile(const evmc::address &Addr,
                                evmc_revision Revision) noexcept {
  if (Revision < EVMC_ISTANBUL) {
    return false;
  }
  return isPrecompileAddress(Addr, 0x09);
}

inline bool isIdentityPrecompile(const evmc::address &Addr) noexcept {
  return isPrecompileAddress(Addr, 0x04);
}

inline bool isBnAddPrecompile(const evmc::address &Addr,
                              evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isPrecompileAddress(Addr, 0x06);
}

inline bool isBnMulPrecompile(const evmc::address &Addr,
                              evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isPrecompileAddress(Addr, 0x07);
}

inline bool isBnPairingPrecompile(const evmc::address &Addr,
                                  evmc_revision Revision) noexcept {
  if (Revision < EVMC_BYZANTIUM) {
    return false;
  }
  return isPrecompileAddress(Addr, 0x08);
}

inline intx::uint256 loadUint256Padded(const uint8_t *Data, size_t Size,
                                       size_t Offset) noexcept {
  uint8_t Buffer[32] = {0};
  if (Offset < Size) {
    size_t CopyLen = std::min<size_t>(32, Size - Offset);
    std::memcpy(Buffer, Data + Offset, CopyLen);
  }
  return intx::be::load<intx::uint256>(Buffer);
}

inline uint64_t toUint64Clamped(const intx::uint256 &Value,
                                bool &Overflow) noexcept {
  if (Value > std::numeric_limits<uint64_t>::max()) {
    Overflow = true;
    return std::numeric_limits<uint64_t>::max();
  }
  return static_cast<uint64_t>(Value);
}

inline uint64_t bitLength(const intx::uint256 &Value) noexcept {
  if (Value == 0) {
    return 0;
  }
  uint8_t Bytes[32];
  intx::be::store(Bytes, Value);
  for (size_t I = 0; I < 32; ++I) {
    if (Bytes[I] == 0) {
      continue;
    }
    const unsigned MsBit = 31U - static_cast<unsigned>(__builtin_clz(Bytes[I]));
    return static_cast<uint64_t>((31 - I) * 8 + MsBit + 1);
  }
  return 0;
}

inline uint64_t adjustedExponentLength(uint64_t ExpLen,
                                       const intx::uint256 &ExpHead) noexcept {
  const uint64_t HeadBits = bitLength(ExpHead);
  if (ExpLen <= 32) {
    return HeadBits == 0 ? 0 : (HeadBits - 1);
  }
  const uint64_t HeadIndex = HeadBits == 0 ? 0 : (HeadBits - 1);
  const unsigned __int128 Raw =
      (static_cast<unsigned __int128>(ExpLen) - 32) * 8u;
  const unsigned __int128 Adjusted = Raw + HeadIndex;
  const unsigned __int128 Max = std::numeric_limits<uint64_t>::max();
  return Adjusted > Max ? std::numeric_limits<uint64_t>::max()
                        : static_cast<uint64_t>(Adjusted);
}

inline boost::multiprecision::cpp_int
multComplexityEIP198(uint64_t MaxLen) noexcept {
  using boost::multiprecision::cpp_int;
  using cpp_int_et_off = boost::multiprecision::number<
      boost::multiprecision::cpp_int_backend<>, boost::multiprecision::et_off>;
  const cpp_int_et_off X(MaxLen);
  cpp_int_et_off Result = X * X;
  if (MaxLen <= 64) {
    return cpp_int(Result);
  }
  if (MaxLen <= 1024) {
    Result /= 4;
    Result += cpp_int_et_off(96) * MaxLen;
    Result -= 3072;
    return cpp_int(Result);
  }
  Result /= 16;
  Result += cpp_int_et_off(480) * MaxLen;
  Result -= 199680;
  return cpp_int(Result);
}

inline boost::multiprecision::cpp_int
multComplexityEIP2565(uint64_t MaxLen) noexcept {
  using boost::multiprecision::cpp_int;
  using cpp_int_et_off = boost::multiprecision::number<
      boost::multiprecision::cpp_int_backend<>, boost::multiprecision::et_off>;
  const uint64_t Words = (MaxLen + 7) / 8;
  const cpp_int_et_off W(Words);
  return cpp_int(W * W);
}

inline bool toUint64(const boost::multiprecision::cpp_int &Value,
                     uint64_t &Out) noexcept {
  if (Value < 0 || Value > boost::multiprecision::cpp_int(
                               std::numeric_limits<uint64_t>::max())) {
    return false;
  }
  Out = static_cast<uint64_t>(Value);
  return true;
}

inline std::vector<uint8_t> readSegment(const uint8_t *Data, size_t Size,
                                        uint64_t Offset, uint64_t Length) {
  std::vector<uint8_t> Segment(static_cast<size_t>(Length), 0);
  if (Length == 0) {
    return Segment;
  }
  if (Offset > std::numeric_limits<size_t>::max()) {
    return Segment;
  }
  size_t SafeOffset = static_cast<size_t>(Offset);
  if (SafeOffset >= Size) {
    return Segment;
  }
  size_t CopyLen = std::min<size_t>(Segment.size(), Size - SafeOffset);
  std::memcpy(Segment.data(), Data + SafeOffset, CopyLen);
  return Segment;
}

inline uint32_t loadUint32BE(const uint8_t *Data) noexcept {
  return (static_cast<uint32_t>(Data[0]) << 24) |
         (static_cast<uint32_t>(Data[1]) << 16) |
         (static_cast<uint32_t>(Data[2]) << 8) |
         static_cast<uint32_t>(Data[3]);
}

inline uint64_t loadUint64LE(const uint8_t *Data) noexcept {
  uint64_t Value = 0;
  for (size_t I = 0; I < 8; ++I) {
    Value |= static_cast<uint64_t>(Data[I]) << (8 * I);
  }
  return Value;
}

inline void storeUint64LE(uint64_t Value, uint8_t *Out) noexcept {
  for (size_t I = 0; I < 8; ++I) {
    Out[I] = static_cast<uint8_t>((Value >> (8 * I)) & 0xff);
  }
}

inline uint64_t rotr64(uint64_t Value, unsigned Shift) noexcept {
  return (Value >> Shift) | (Value << (64 - Shift));
}

inline void blake2bG(uint64_t &A, uint64_t &B, uint64_t &C, uint64_t &D,
                     uint64_t X, uint64_t Y) noexcept {
  A = A + B + X;
  D = rotr64(D ^ A, 32);
  C = C + D;
  B = rotr64(B ^ C, 24);
  A = A + B + Y;
  D = rotr64(D ^ A, 16);
  C = C + D;
  B = rotr64(B ^ C, 63);
}

inline void blake2bCompress(uint64_t H[8], const uint64_t M[16], uint64_t T0,
                            uint64_t T1, bool FinalBlock,
                            uint32_t Rounds) noexcept {
  static constexpr std::array<uint64_t, 8> IV = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
      0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
      0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
      0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
  static constexpr uint8_t Sigma[10][16] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
      {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
      {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
      {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
      {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
      {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
      {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
      {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
      {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
      {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

  uint64_t V[16];
  for (size_t I = 0; I < 8; ++I) {
    V[I] = H[I];
    V[I + 8] = IV[I];
  }
  V[12] ^= T0;
  V[13] ^= T1;
  if (FinalBlock) {
    V[14] = ~V[14];
  }

  for (uint32_t R = 0; R < Rounds; ++R) {
    const uint8_t *S = Sigma[R % 10];
    blake2bG(V[0], V[4], V[8], V[12], M[S[0]], M[S[1]]);
    blake2bG(V[1], V[5], V[9], V[13], M[S[2]], M[S[3]]);
    blake2bG(V[2], V[6], V[10], V[14], M[S[4]], M[S[5]]);
    blake2bG(V[3], V[7], V[11], V[15], M[S[6]], M[S[7]]);
    blake2bG(V[0], V[5], V[10], V[15], M[S[8]], M[S[9]]);
    blake2bG(V[1], V[6], V[11], V[12], M[S[10]], M[S[11]]);
    blake2bG(V[2], V[7], V[8], V[13], M[S[12]], M[S[13]]);
    blake2bG(V[3], V[4], V[9], V[14], M[S[14]], M[S[15]]);
  }

  for (size_t I = 0; I < 8; ++I) {
    H[I] ^= V[I] ^ V[I + 8];
  }
}

inline evmc::Result executeIdentity(const evmc_message &Msg,
                                    std::vector<uint8_t> &ReturnData) {
  constexpr uint64_t BaseGas = 15;
  constexpr uint64_t GasPerWord = 3;
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  const uint64_t InputSize = static_cast<uint64_t>(Msg.input_size);
  const uint64_t Words = (InputSize + 31) / 32;
  const uint64_t GasCost = BaseGas + GasPerWord * Words;

  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  if (InputSize != 0 && Msg.input_data == nullptr) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  if (InputSize == 0) {
    ReturnData.clear();
  } else {
    const auto *Input = static_cast<const uint8_t *>(Msg.input_data);
    ReturnData.assign(Input, Input + InputSize);
  }

  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0,
                      ReturnData.empty() ? nullptr : ReturnData.data(),
                      ReturnData.size());
}

inline uint64_t bnAddGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 150 : 500;
}

inline uint64_t bnMulGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 6000 : 40000;
}

inline uint64_t bnPairingBaseGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 45000 : 100000;
}

inline uint64_t bnPairingPerPointGasCost(evmc_revision Revision) noexcept {
  return Revision >= EVMC_ISTANBUL ? 34000 : 80000;
}

inline evmc::Result executeBnAdd(const evmc_message &Msg,
                                 evmc_revision Revision,
                                 std::vector<uint8_t> &ReturnData) {
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  const uint64_t GasCost = bnAddGasCost(Revision);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  ReturnData.assign(64, 0);
  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0, ReturnData.data(),
                      ReturnData.size());
}

inline evmc::Result executeBnMul(const evmc_message &Msg,
                                 evmc_revision Revision,
                                 std::vector<uint8_t> &ReturnData) {
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  const uint64_t GasCost = bnMulGasCost(Revision);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  ReturnData.assign(64, 0);
  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0, ReturnData.data(),
                      ReturnData.size());
}

inline evmc::Result executeBnPairing(const evmc_message &Msg,
                                     evmc_revision Revision,
                                     std::vector<uint8_t> &ReturnData) {
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  const uint64_t BaseGas = bnPairingBaseGasCost(Revision);
  const uint64_t PerPointGas = bnPairingPerPointGasCost(Revision);

  if (Msg.input_size % 192 != 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_PRECOMPILE_FAILURE, 0, 0, nullptr, 0);
  }

  const uint64_t PairCount = static_cast<uint64_t>(Msg.input_size / 192);
  if (PairCount > (std::numeric_limits<uint64_t>::max() - BaseGas) /
                      PerPointGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint64_t GasCost = BaseGas + PairCount * PerPointGas;
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  ReturnData.assign(32, 0);
  ReturnData.back() = 1;
  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0, ReturnData.data(),
                      ReturnData.size());
}

inline evmc::Result executeModExp(const evmc_message &Msg,
                                  evmc_revision Revision,
                                  std::vector<uint8_t> &ReturnData) {
  const uint8_t *Input = Msg.input_size == 0
                             ? nullptr
                             : static_cast<const uint8_t *>(Msg.input_data);
  const size_t InputSize = Msg.input_size;

  bool LengthOverflow = false;
  const uint64_t BaseLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 0), LengthOverflow);
  const uint64_t ExpLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 32), LengthOverflow);
  const uint64_t ModLen =
      toUint64Clamped(loadUint256Padded(Input, InputSize, 64), LengthOverflow);
  if (LengthOverflow) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint64_t MaxLen = std::max(BaseLen, ModLen);
  constexpr uint64_t BaseOffset = 96;
  if (BaseLen > std::numeric_limits<uint64_t>::max() - BaseOffset) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const uint64_t ExpOffset = BaseOffset + BaseLen;
  if (ExpLen > std::numeric_limits<uint64_t>::max() - ExpOffset) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const uint64_t ModOffset = ExpOffset + ExpLen;

  std::array<uint8_t, 32> ExpHeadBytes{};
  if (ExpLen != 0 && Input != nullptr && ExpOffset < InputSize) {
    const uint64_t HeadLen = std::min<uint64_t>(ExpLen, 32);
    auto Head = readSegment(Input, InputSize, ExpOffset, HeadLen);
    if (!Head.empty()) {
      std::memcpy(ExpHeadBytes.data() + (ExpHeadBytes.size() - Head.size()),
                  Head.data(), Head.size());
    }
  }
  intx::uint256 ExpHead = 0;
  for (auto B : ExpHeadBytes) {
    ExpHead = (ExpHead << 8) | static_cast<uint64_t>(B);
  }
  const uint64_t AdjustedExpLen = adjustedExponentLength(ExpLen, ExpHead);
  const uint64_t IterationCount = std::max<uint64_t>(AdjustedExpLen, 1);

  using boost::multiprecision::cpp_int;
  using cpp_int_et_off = boost::multiprecision::number<
      boost::multiprecision::cpp_int_backend<>, boost::multiprecision::et_off>;
  cpp_int_et_off GasCost = 0;
  if (Revision >= EVMC_BERLIN) {
    GasCost = cpp_int_et_off(multComplexityEIP2565(MaxLen));
    GasCost *= cpp_int_et_off(IterationCount);
    GasCost /= cpp_int_et_off(3);
    if (GasCost < 200) {
      GasCost = 200;
    }
  } else {
    GasCost = cpp_int_et_off(multComplexityEIP198(MaxLen));
    GasCost *= cpp_int_et_off(IterationCount);
    GasCost /= cpp_int_et_off(20);
  }

  uint64_t GasCost64 = 0;
  if (!toUint64(cpp_int(GasCost), GasCost64)) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost64 > MsgGas) {
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }
  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost64);

  if (ModLen == 0) {
    ReturnData.clear();
    return evmc::Result(EVMC_SUCCESS, GasLeft, 0, nullptr, 0);
  }

  auto BaseBytes = readSegment(Input, InputSize, BaseOffset, BaseLen);
  auto ExpBytes = readSegment(Input, InputSize, ExpOffset, ExpLen);
  auto ModBytes = readSegment(Input, InputSize, ModOffset, ModLen);

  cpp_int BaseInt = 0;
  cpp_int ExpInt = 0;
  cpp_int ModInt = 0;

  if (!BaseBytes.empty()) {
    boost::multiprecision::import_bits(BaseInt, BaseBytes.begin(),
                                       BaseBytes.end(), 8);
  }
  if (!ExpBytes.empty()) {
    boost::multiprecision::import_bits(ExpInt, ExpBytes.begin(), ExpBytes.end(),
                                       8);
  }
  if (!ModBytes.empty()) {
    boost::multiprecision::import_bits(ModInt, ModBytes.begin(), ModBytes.end(),
                                       8);
  }

  std::vector<uint8_t> Output(static_cast<size_t>(ModLen), 0);
  if (ModInt != 0) {
    BaseInt %= ModInt;
    cpp_int Result = boost::multiprecision::powm(BaseInt, ExpInt, ModInt);
    std::vector<uint8_t> Tmp;
    boost::multiprecision::export_bits(Result, std::back_inserter(Tmp), 8);
    if (Tmp.size() > Output.size()) {
      std::copy(Tmp.end() - Output.size(), Tmp.end(), Output.begin());
    } else if (!Tmp.empty()) {
      std::copy(Tmp.begin(), Tmp.end(),
                Output.begin() + (Output.size() - Tmp.size()));
    }
  }
  ReturnData = std::move(Output);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0,
                      ReturnData.empty() ? nullptr : ReturnData.data(),
                      ReturnData.size());
}

inline evmc::Result executeBlake2b(const evmc_message &Msg,
                                   std::vector<uint8_t> &ReturnData) {
  constexpr size_t InputSize = 213;
  constexpr uint64_t GasPerRound = 1;
  const uint8_t *Input = Msg.input_size == 0
                             ? nullptr
                             : static_cast<const uint8_t *>(Msg.input_data);

  if (Input == nullptr || Msg.input_size != InputSize) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint8_t FinalFlag = Input[InputSize - 1];
  if (FinalFlag != 0 && FinalFlag != 1) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  const uint32_t Rounds = loadUint32BE(Input);
  const uint64_t GasCost = GasPerRound * static_cast<uint64_t>(Rounds);
  const uint64_t MsgGas = Msg.gas < 0 ? 0 : static_cast<uint64_t>(Msg.gas);
  if (GasCost > MsgGas) {
    ReturnData.clear();
    return evmc::Result(EVMC_OUT_OF_GAS, 0, 0, nullptr, 0);
  }

  uint64_t H[8];
  uint64_t M[16];
  constexpr size_t HOffset = 4;
  constexpr size_t MOffset = HOffset + 64;
  constexpr size_t T0Offset = MOffset + 128;
  constexpr size_t T1Offset = T0Offset + 8;
  for (size_t I = 0; I < 8; ++I) {
    H[I] = loadUint64LE(Input + HOffset + I * 8);
  }
  for (size_t I = 0; I < 16; ++I) {
    M[I] = loadUint64LE(Input + MOffset + I * 8);
  }
  const uint64_t T0 = loadUint64LE(Input + T0Offset);
  const uint64_t T1 = loadUint64LE(Input + T1Offset);

  blake2bCompress(H, M, T0, T1, FinalFlag != 0, Rounds);

  ReturnData.assign(64, 0);
  for (size_t I = 0; I < 8; ++I) {
    storeUint64LE(H[I], ReturnData.data() + I * 8);
  }

  const int64_t GasLeft = static_cast<int64_t>(MsgGas - GasCost);
  return evmc::Result(EVMC_SUCCESS, GasLeft, 0, ReturnData.data(),
                      ReturnData.size());
}

} // namespace zen::evm::precompile

#endif // ZEN_TESTS_EVM_PRECOMPILES_HPP
