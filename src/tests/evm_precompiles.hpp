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

inline bool isModExpPrecompile(const evmc::address &Addr) noexcept {
  for (size_t I = 0; I + 1 < sizeof(Addr.bytes); ++I) {
    if (Addr.bytes[I] != 0) {
      return false;
    }
  }
  return Addr.bytes[sizeof(Addr.bytes) - 1] == 0x05;
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
  const cpp_int X(MaxLen);
  if (MaxLen <= 64) {
    return X * X;
  }
  if (MaxLen <= 1024) {
    return X * X / 4 + cpp_int(96) * MaxLen - 3072;
  }
  return X * X / 16 + cpp_int(480) * MaxLen - 199680;
}

inline boost::multiprecision::cpp_int
multComplexityEIP2565(uint64_t MaxLen) noexcept {
  using boost::multiprecision::cpp_int;
  const uint64_t Words = (MaxLen + 7) / 8;
  const cpp_int W(Words);
  return W * W;
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
  cpp_int GasCost = 0;
  if (Revision >= EVMC_BERLIN) {
    GasCost =
        multComplexityEIP2565(MaxLen) * cpp_int(IterationCount) / cpp_int(3);
    if (GasCost < 200) {
      GasCost = 200;
    }
  } else {
    GasCost =
        multComplexityEIP198(MaxLen) * cpp_int(IterationCount) / cpp_int(20);
    GasCost += cpp_int(LegacyModExpBaseGas);
  }

  uint64_t GasCost64 = 0;
  if (!toUint64(GasCost, GasCost64)) {
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

} // namespace zen::evm::precompile

#endif // ZEN_TESTS_EVM_PRECOMPILES_HPP
