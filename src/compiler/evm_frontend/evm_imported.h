// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef EVM_FRONTEND_EVM_IMPORTED_H
#define EVM_FRONTEND_EVM_IMPORTED_H

#include "intx/intx.hpp"
#include <cstdint>

namespace zen::runtime {
class EVMInstance;
} // namespace zen::runtime

namespace COMPILER {

using U256Fn = const intx::uint256 *(*)(zen::runtime::EVMInstance *);
using Bytes32Fn = const uint8_t *(*)(zen::runtime::EVMInstance *);
using SizeFn = uint64_t (*)(zen::runtime::EVMInstance *);
using Bytes32WithInt64Fn = const uint8_t *(*)(zen::runtime::EVMInstance *,
                                              int64_t);
using Bytes32WithUint64Fn = const uint8_t *(*)(zen::runtime::EVMInstance *,
                                               uint64_t);
using Bytes32WithBytes32Fn = const uint8_t *(*)(zen::runtime::EVMInstance *,
                                                const uint8_t *);
using SizeWithBytes32Fn = uint64_t (*)(zen::runtime::EVMInstance *,
                                       const uint8_t *);
using U256WithBytes32Fn = const intx::uint256 *(*)(zen::runtime::EVMInstance *,
                                                   const uint8_t *);
using U256WithUInt64Fn = const intx::uint256 *(*)(zen::runtime::EVMInstance *,
                                                  uint64_t);
using VoidWithUInt64U256Fn = void (*)(zen::runtime::EVMInstance *, uint64_t,
                                      const intx::uint256 &);
using VoidWithUInt64UInt64Fn = void (*)(zen::runtime::EVMInstance *, uint64_t,
                                        uint64_t);
using VoidWithUInt64UInt64UInt64Fn = void (*)(zen::runtime::EVMInstance *,
                                              uint64_t, uint64_t, uint64_t);
using VoidWithBytes32UInt64UInt64UInt64Fn = void (*)(
    zen::runtime::EVMInstance *, const uint8_t *, uint64_t, uint64_t, uint64_t);
using Bytes32WithUInt64UInt64Fn =
    const uint8_t *(*)(zen::runtime::EVMInstance *, uint64_t, uint64_t);
using VoidFn = void (*)(zen::runtime::EVMInstance *);
using U256WithU256Fn = const intx::uint256 *(*)(zen::runtime::EVMInstance *,
                                                const intx::uint256 &);
using VoidWithU256U256Fn = void (*)(zen::runtime::EVMInstance *,
                                    const intx::uint256 &,
                                    const intx::uint256 &);
using VoidWithBytes32Fn = void (*)(zen::runtime::EVMInstance *,
                                   const uint8_t *);
using U256WithU256U256Fn = const intx::uint256 *(*)(zen::runtime::EVMInstance *,
                                                    const intx::uint256 &,
                                                    const intx::uint256 &);
using U256WithU256U256U256Fn =
    const intx::uint256 *(*)(zen::runtime::EVMInstance *, const intx::uint256 &,
                             const intx::uint256 &, const intx::uint256 &);
using Log0Fn = void (*)(zen::runtime::EVMInstance *, uint64_t, uint64_t);
using Log1Fn = void (*)(zen::runtime::EVMInstance *, uint64_t, uint64_t,
                        const uint8_t *);
using Log2Fn = void (*)(zen::runtime::EVMInstance *, uint64_t, uint64_t,
                        const uint8_t *, const uint8_t *);
using Log3Fn = void (*)(zen::runtime::EVMInstance *, uint64_t, uint64_t,
                        const uint8_t *, const uint8_t *, const uint8_t *);
using Log4Fn = void (*)(zen::runtime::EVMInstance *, uint64_t, uint64_t,
                        const uint8_t *, const uint8_t *, const uint8_t *,
                        const uint8_t *);
using CreateFn = const uint8_t *(*)(zen::runtime::EVMInstance *, intx::uint128,
                                    uint64_t, uint64_t);
using Create2Fn = const uint8_t *(*)(zen::runtime::EVMInstance *, intx::uint128,
                                     uint64_t, uint64_t, const uint8_t *);

// Call function types for different call operations
using CallFn = uint64_t (*)(zen::runtime::EVMInstance *, uint64_t,
                            const uint8_t *, intx::uint128, uint64_t, uint64_t,
                            uint64_t, uint64_t); // CALL, CALLCODE
using DelegateCallFn = uint64_t (*)(zen::runtime::EVMInstance *, uint64_t,
                                    const uint8_t *, uint64_t, uint64_t,
                                    uint64_t,
                                    uint64_t); // DELEGATECALL, STATICCALL

struct RuntimeFunctions {
  U256WithU256U256Fn GetMul;
  U256WithU256U256Fn GetDiv;
  U256WithU256U256Fn GetSDiv;
  U256WithU256U256Fn GetMod;
  U256WithU256U256Fn GetSMod;
  U256WithU256U256U256Fn GetAddMod;
  U256WithU256U256U256Fn GetMulMod;
  U256WithU256U256Fn GetExp;
  Bytes32Fn GetAddress;
  U256WithBytes32Fn GetBalance;
  Bytes32Fn GetOrigin;
  Bytes32Fn GetCaller;
  Bytes32Fn GetCallValue;
  Bytes32WithUint64Fn GetCallDataLoad;
  SizeFn GetCallDataSize;
  SizeFn GetCodeSize;
  VoidWithUInt64UInt64UInt64Fn SetCodeCopy;
  U256Fn GetGasPrice;
  SizeWithBytes32Fn GetExtCodeSize;
  Bytes32WithBytes32Fn GetExtCodeHash;
  Bytes32WithInt64Fn GetBlockHash;
  Bytes32Fn GetCoinBase;
  U256Fn GetTimestamp;
  U256Fn GetNumber;
  Bytes32Fn GetPrevRandao;
  U256Fn GetGasLimit;
  Bytes32Fn GetChainId;
  U256Fn GetSelfBalance;
  U256Fn GetBaseFee;
  Bytes32WithUint64Fn GetBlobHash;
  U256Fn GetBlobBaseFee;
  SizeFn GetMSize;
  U256WithUInt64Fn GetMLoad;
  VoidWithUInt64U256Fn SetMStore;
  VoidWithUInt64U256Fn SetMStore8;
  U256WithU256Fn GetSLoad;
  VoidWithU256U256Fn SetSStore;
  SizeFn GetGas;
  U256WithU256Fn GetTLoad;
  VoidWithU256U256Fn SetTStore;
  VoidWithUInt64UInt64UInt64Fn SetMCopy;
  VoidWithUInt64UInt64UInt64Fn SetCallDataCopy;
  VoidWithBytes32UInt64UInt64UInt64Fn SetExtCodeCopy;
  VoidWithUInt64UInt64UInt64Fn SetReturnDataCopy;
  SizeFn GetReturnDataSize;
  Log0Fn EmitLog0;
  Log1Fn EmitLog1;
  Log2Fn EmitLog2;
  Log3Fn EmitLog3;
  Log4Fn EmitLog4;
  CreateFn HandleCreate;
  Create2Fn HandleCreate2;
  CallFn HandleCall;
  CallFn HandleCallCode;
  VoidWithUInt64UInt64Fn SetReturn;
  DelegateCallFn HandleDelegateCall;
  DelegateCallFn HandleStaticCall;
  VoidWithUInt64UInt64Fn SetRevert;
  VoidFn HandleInvalid;
  VoidWithBytes32Fn HandleSelfDestruct;
  Bytes32WithUInt64UInt64Fn GetKeccak256;
};

const RuntimeFunctions &getRuntimeFunctionTable();

template <typename FuncType> uint64_t getFunctionAddress(FuncType Func) {
  return reinterpret_cast<uint64_t>(Func);
}

const intx::uint256 *evmGetMul(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Multiplicand,
                               const intx::uint256 &Multiplier);
const intx::uint256 *evmGetDiv(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Dividend,
                               const intx::uint256 &Divisor);
const intx::uint256 *evmGetSDiv(zen::runtime::EVMInstance *Instance,
                                const intx::uint256 &Dividend,
                                const intx::uint256 &Divisor);
const intx::uint256 *evmGetMod(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Dividend,
                               const intx::uint256 &Divisor);
const intx::uint256 *evmGetSMod(zen::runtime::EVMInstance *Instance,
                                const intx::uint256 &Dividend,
                                const intx::uint256 &Divisor);
const intx::uint256 *evmGetAddMod(zen::runtime::EVMInstance *Instance,
                                  const intx::uint256 &Augend,
                                  const intx::uint256 &Addend,
                                  const intx::uint256 &Modulus);
const intx::uint256 *evmGetMulMod(zen::runtime::EVMInstance *Instance,
                                  const intx::uint256 &Multiplicand,
                                  const intx::uint256 &Multiplier,
                                  const intx::uint256 &Modulus);
const intx::uint256 *evmGetExp(zen::runtime::EVMInstance *Instance,
                               const intx::uint256 &Base,
                               const intx::uint256 &Exponent);
const uint8_t *evmGetAddress(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetBalance(zen::runtime::EVMInstance *Instance,
                                   const uint8_t *Address);
const uint8_t *evmGetOrigin(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetCaller(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetCallValue(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetCallDataLoad(zen::runtime::EVMInstance *Instance,
                                  uint64_t Offset);
uint64_t evmGetCallDataSize(zen::runtime::EVMInstance *Instance);
uint64_t evmGetCodeSize(zen::runtime::EVMInstance *Instance);
void evmSetCodeCopy(zen::runtime::EVMInstance *Instance, uint64_t DestOffset,
                    uint64_t Offset, uint64_t Size);
const intx::uint256 *evmGetGasPrice(zen::runtime::EVMInstance *Instance);
uint64_t evmGetExtCodeSize(zen::runtime::EVMInstance *Instance,
                           const uint8_t *Address);
const uint8_t *evmGetExtCodeHash(zen::runtime::EVMInstance *Instance,
                                 const uint8_t *Address);
const uint8_t *evmGetBlockHash(zen::runtime::EVMInstance *Instance,
                               int64_t BlockNumber);
const uint8_t *evmGetCoinBase(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetTimestamp(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetNumber(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetPrevRandao(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetGasLimit(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetChainId(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetSelfBalance(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetBaseFee(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetBlobHash(zen::runtime::EVMInstance *Instance,
                              uint64_t Index);
const intx::uint256 *evmGetBlobBaseFee(zen::runtime::EVMInstance *Instance);
uint64_t evmGetMSize(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetMLoad(zen::runtime::EVMInstance *Instance,
                                 uint64_t Addr);
void evmSetMStore(zen::runtime::EVMInstance *Instance, uint64_t Addr,
                  const intx::uint256 &Value);
void evmSetMStore8(zen::runtime::EVMInstance *Instance, uint64_t Addr,
                   const intx::uint256 &Value);
void evmSetMCopy(zen::runtime::EVMInstance *Instance, uint64_t DestAddr,
                 uint64_t SrcAddr, uint64_t Length);
void evmSetCallDataCopy(zen::runtime::EVMInstance *Instance,
                        uint64_t DestOffset, uint64_t Offset, uint64_t Size);
void evmSetExtCodeCopy(zen::runtime::EVMInstance *Instance,
                       const uint8_t *Address, uint64_t DestOffset,
                       uint64_t Offset, uint64_t Size);
void evmSetReturnDataCopy(zen::runtime::EVMInstance *Instance,
                          uint64_t DestOffset, uint64_t Offset, uint64_t Size);
uint64_t evmGetReturnDataSize(zen::runtime::EVMInstance *Instance);
void evmEmitLog0(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size);
void evmEmitLog1(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1);
void evmEmitLog2(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2);
void evmEmitLog3(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2,
                 const uint8_t *Topic3);
void evmEmitLog4(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                 uint64_t Size, const uint8_t *Topic1, const uint8_t *Topic2,
                 const uint8_t *Topic3, const uint8_t *Topic4);
const uint8_t *evmHandleCreate(zen::runtime::EVMInstance *Instance,
                               intx::uint128 Value, uint64_t Offset,
                               uint64_t Size);
const uint8_t *evmHandleCreate2(zen::runtime::EVMInstance *Instance,
                                intx::uint128 Value, uint64_t Offset,
                                uint64_t Size, const uint8_t *Salt);
uint64_t evmHandleCall(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                       const uint8_t *ToAddr, intx::uint128 Value,
                       uint64_t ArgsOffset, uint64_t ArgsSize,
                       uint64_t RetOffset, uint64_t RetSize);
uint64_t evmHandleCallCode(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                           const uint8_t *ToAddr, intx::uint128 Value,
                           uint64_t ArgsOffset, uint64_t ArgsSize,
                           uint64_t RetOffset, uint64_t RetSize);
void evmSetReturn(zen::runtime::EVMInstance *Instance, uint64_t MemOffset,
                  uint64_t Length);
uint64_t evmHandleDelegateCall(zen::runtime::EVMInstance *Instance,
                               uint64_t Gas, const uint8_t *ToAddr,
                               uint64_t ArgsOffset, uint64_t ArgsSize,
                               uint64_t RetOffset, uint64_t RetSize);
uint64_t evmHandleStaticCall(zen::runtime::EVMInstance *Instance, uint64_t Gas,
                             const uint8_t *ToAddr, uint64_t ArgsOffset,
                             uint64_t ArgsSize, uint64_t RetOffset,
                             uint64_t RetSize);
void evmSetRevert(zen::runtime::EVMInstance *Instance, uint64_t Offset,
                  uint64_t Size);
void evmHandleInvalid(zen::runtime::EVMInstance *Instance);
const uint8_t *evmGetKeccak256(zen::runtime::EVMInstance *Instance,
                               uint64_t Offset, uint64_t Length);
const intx::uint256 *evmGetSLoad(zen::runtime::EVMInstance *Instance,
                                 const intx::uint256 &Index);
void evmSetSStore(zen::runtime::EVMInstance *Instance,
                  const intx::uint256 &Index, const intx::uint256 &Value);
uint64_t evmGetGas(zen::runtime::EVMInstance *Instance);
const intx::uint256 *evmGetTLoad(zen::runtime::EVMInstance *Instance,
                                 const intx::uint256 &Index);
void evmSetTStore(zen::runtime::EVMInstance *Instance,
                  const intx::uint256 &Index, const intx::uint256 &Value);
void evmHandleSelfDestruct(zen::runtime::EVMInstance *Instance,
                           const uint8_t *Beneficiary);
} // namespace COMPILER

#endif // EVM_FRONTEND_EVM_IMPORTED_H
