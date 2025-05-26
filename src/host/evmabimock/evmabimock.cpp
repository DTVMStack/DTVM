// Copyright (C) 2024-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/instance.h"
// Note: must place evmabimock.h after instance.h to get correct
// EXPORT_MODULE_NAME
#include "common/errors.h"
#include "host/evmabimock/evmabimock.h"
#include "utils/others.h"
#include <iomanip>
#include <string>
#include <vector>

namespace zen::host {

using namespace zen::common;

static void *vnmi_init_ctx(VNMIEnv *vmenv, const char *dir_list[],
                           uint32_t dir_count, const char *envs[],
                           uint32_t env_count, char *env_buf,
                           uint32_t env_buf_size, char *argv[], uint32_t argc,
                           char *argv_buf, uint32_t argv_buf_size) {
  return nullptr;
}

static void vnmi_destroy_ctx(VNMIEnv *vmenv, void *ctx) {}

static const char *OUT_OF_BOUND_ERROR = "out of bound in hostapi";
static const char *EVM_ABI_CONTEXT_NOT_FOUND = "not found EVMAbi context";

// begin EVMAbiMockContext

std::shared_ptr<EVMAbiMockContext>
EVMAbiMockContext::create(std::vector<uint8_t> &WasmCode) {
  auto Ctx = std::make_shared<EVMAbiMockContext>();
  // prefix is big-endian 4bytes of wasm Length

  uint32_t CodeLength = WasmCode.size();
  uint8_t LengthPrefix[4];
  // big-endian 4bytes of wasm Length
  LengthPrefix[0] = (CodeLength >> 24) & 0xFF;
  LengthPrefix[1] = (CodeLength >> 16) & 0xFF;
  LengthPrefix[2] = (CodeLength >> 8) & 0xFF;
  LengthPrefix[3] = CodeLength & 0xFF;

  std::vector<uint8_t> PrefixedWasmCode(LengthPrefix, LengthPrefix + 4);
  PrefixedWasmCode.insert(PrefixedWasmCode.end(), WasmCode.begin(),
                          WasmCode.end());

  Ctx->CurMsgContractCode = PrefixedWasmCode;
  return Ctx;
}

const std::vector<uint8_t> &EVMAbiMockContext::getCurContractCode() {
  return CurMsgContractCode;
}

void EVMAbiMockContext::setCurContractStore(const std::string &Key,
                                            const std::vector<uint8_t> &Value) {
  auto It = CurMsgContractStores.find(Key);
  if (It != CurMsgContractStores.end()) {
    It->second = Value;
  } else {
    CurMsgContractStores.insert(std::make_pair(Key, Value));
  }
}

const std::vector<uint8_t> &
EVMAbiMockContext::getCurContractStore(const std::string &Key) {
  // bytes32 zero hex
  static const std::vector<uint8_t> ZERO_BYTES32(32, 0x0);
  auto It = CurMsgContractStores.find(Key);
  if (It != CurMsgContractStores.end()) {
    return It->second;
  } else {
    return ZERO_BYTES32;
  }
}

// end EVMAbiMockContext

static EVMAbiMockContext *getEVMAbiMockContext(Instance *instance) {
  auto CustomData = instance->getCustomData();
  return (EVMAbiMockContext *)CustomData;
}

static void getAddress(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_CUR_CONTRACt_ADDR[20] = {0x05};
  if (!VALIDATE_APP_ADDR(ResultOffset, 20)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_CUR_CONTRACt_ADDR, 20);
}

static int32_t getBlockHash(Instance *instance, int64_t BlockNum,
                            int32_t ResultOffset) {
  static uint8_t MOCK_BLOCK_HASH[32] = {0x06};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return -1;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_BLOCK_HASH, 32);
  return 0;
}

static int32_t getCallDataSize(Instance *instance) {
  // mock abi must be test() now
  return 4;
}

static void getCaller(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_CALLER[20] = {0x04};
  if (!VALIDATE_APP_ADDR(ResultOffset, 20)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_CALLER, 20);
}

// getCallValue(wasm_inst: *mut ZenInstanceExtern, ResultOffset: i32)
static void getCallValue(Instance *instance, int32_t ResultOffset) {
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memset(NativeResult, 0x0, 32);
}

// getChainId(wasm_inst: *mut ZenInstanceExtern, ResultOffset: i32)
static void getChainId(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_CHAIN_ID[32] = {0x07};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_CHAIN_ID, 32);
}

static void callDataCopy(Instance *instance, int32_t ResultOffset,
                         int32_t DataOffset, int32_t Length) {
  static uint8_t MOCK_CALL_DATA[4] = {0xf8, 0xa8, 0xfd,
                                      0x6d}; // selector of test() is 0xf8a8fd6d
  int32_t MockCalldataSize = 4;
  if (!VALIDATE_APP_ADDR(ResultOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);

  if (DataOffset >= MockCalldataSize) {
    // copy zeros to result
    memset(NativeResult, 0x0, Length);
    return;
  }

  memcpy(NativeResult, &MOCK_CALL_DATA[DataOffset],
         MockCalldataSize - DataOffset);
  // copy zeros to result of remaining Length
  if (Length > MockCalldataSize - DataOffset) {
    memset(NativeResult + MockCalldataSize - DataOffset, 0x0,
           Length - (MockCalldataSize - DataOffset));
  }
}

static int64_t getGasLeft(Instance *instance) { return 1000000; }

static int64_t getBlockGasLimit(Instance *instance) { return 1000000; }

static int64_t getBlockNumber(Instance *instance) { return 12345; }

static void getTxOrigin(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_TX_ORIGIN[20] = {0x03};
  if (!VALIDATE_APP_ADDR(ResultOffset, 20)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_TX_ORIGIN, 20);
}

static int64_t getBlockTimestamp(Instance *instance) { return 1234567890L; }

static void storageStore(Instance *instance, int32_t KeyBytesOffset,
                         int32_t ValueBytesOffset) {
  printf("storageStore hostapi called\n");
  auto EvmAbiMockCtx = getEVMAbiMockContext(instance);
  if (!EvmAbiMockCtx) {
    instance->setExceptionByHostapi(getErrorWithExtraMessage(
        ErrorCode::EnvAbort, EVM_ABI_CONTEXT_NOT_FOUND));
    return;
  }
  if (!VALIDATE_APP_ADDR(KeyBytesOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  if (!VALIDATE_APP_ADDR(ValueBytesOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  const uint8_t *native_key_bytes32 =
      (const uint8_t *)ADDR_APP_TO_NATIVE(KeyBytesOffset);
  const uint8_t *native_value_bytes32 =
      (const uint8_t *)ADDR_APP_TO_NATIVE(ValueBytesOffset);
  std::vector<uint8_t> native_value_bytes32_vec(native_value_bytes32,
                                                native_value_bytes32 + 32);
  printf("storageStore key: %s, value: %s\n",
         zen::utils::toHex(native_key_bytes32, 32).c_str(),
         zen::utils::toHex(native_value_bytes32, 32).c_str());
  EvmAbiMockCtx->setCurContractStore(zen::utils::toHex(native_key_bytes32, 32),
                                     native_value_bytes32_vec);
}

static void storageLoad(Instance *instance, int32_t KeyBytesOffset,
                        int32_t ResultOffset) {
  printf("storageLoad hostapi called\n");
  auto EvmAbiMockCtx = getEVMAbiMockContext(instance);
  if (!EvmAbiMockCtx) {
    instance->setExceptionByHostapi(getErrorWithExtraMessage(
        ErrorCode::EnvAbort, EVM_ABI_CONTEXT_NOT_FOUND));
    return;
  }

  if (!VALIDATE_APP_ADDR(KeyBytesOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  const uint8_t *native_key_bytes32 =
      (const uint8_t *)ADDR_APP_TO_NATIVE(KeyBytesOffset);
  const auto &native_value_bytes32 = EvmAbiMockCtx->getCurContractStore(
      zen::utils::toHex(native_key_bytes32, 32));

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, native_value_bytes32.data(), 32);
}

static void emitLogEvent(Instance *instance, int32_t DataOffset, int32_t Length,
                         int32_t NumTopics, int32_t Topic1Offset,
                         int32_t Topic2Offset, int32_t Topic3Offset,
                         int32_t Topic4Offset) {
  printf("emitLogEvent called\n");

  // Validate data offset and length
  if (!VALIDATE_APP_ADDR(DataOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  // Copy data from instance to native
  const uint8_t *NativeData = (const uint8_t *)ADDR_APP_TO_NATIVE(DataOffset);
  std::vector<uint8_t> LogData(NativeData, NativeData + Length);

  // Print log data
  printf("Log Data: %s\n",
         zen::utils::toHex(LogData.data(), LogData.size()).c_str());

  // Collect topics
  std::vector<std::string> topics;
  if (NumTopics > 0) {
    if (!VALIDATE_APP_ADDR(Topic1Offset, 32)) {
      instance->setExceptionByHostapi(
          getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
      return;
    }
    topics.push_back(zen::utils::toHex(
        (const uint8_t *)ADDR_APP_TO_NATIVE(Topic1Offset), 32));
  }
  if (NumTopics > 1) {
    if (!VALIDATE_APP_ADDR(Topic2Offset, 32)) {
      instance->setExceptionByHostapi(
          getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
      return;
    }
    topics.push_back(zen::utils::toHex(
        (const uint8_t *)ADDR_APP_TO_NATIVE(Topic2Offset), 32));
  }
  if (NumTopics > 2) {
    if (!VALIDATE_APP_ADDR(Topic3Offset, 32)) {
      instance->setExceptionByHostapi(
          getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
      return;
    }
    topics.push_back(zen::utils::toHex(
        (const uint8_t *)ADDR_APP_TO_NATIVE(Topic3Offset), 32));
  }
  if (NumTopics > 3) {
    if (!VALIDATE_APP_ADDR(Topic4Offset, 32)) {
      instance->setExceptionByHostapi(
          getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
      return;
    }
    topics.push_back(zen::utils::toHex(
        (const uint8_t *)ADDR_APP_TO_NATIVE(Topic4Offset), 32));
  }

  // Print topics
  for (int i = 0; i < NumTopics; ++i) {
    printf("Topic %d: %s\n", i + 1, topics[i].c_str());
  }
}

static void finish(Instance *instance, int32_t DataOffset, int32_t Length) {
  if (!VALIDATE_APP_ADDR(DataOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  if (Length < 0 || Length > 1024) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, ""));
    return;
  }
  if (Length == 0) {
    printf("evm finish with: \n");
    instance->setError(ErrorCode::InstanceExit);
    return;
  }

  const uint8_t *native_data = (const uint8_t *)ADDR_APP_TO_NATIVE(DataOffset);
  std::vector<uint8_t> finish_msg;
  finish_msg.resize(Length);
  memcpy((uint8_t *)finish_msg.data(), native_data, Length);
  printf("evm finish with: %s\n",
         zen::utils::toHex(finish_msg.data(), finish_msg.size()).c_str());
  instance->setError(ErrorCode::InstanceExit);
}

static void invalid(Instance *instance) {
  printf("evm invalid error\n");
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::EnvAbort, ""));
}

static void revert(Instance *instance, int32_t DataOffset, int32_t Length) {
  if (!VALIDATE_APP_ADDR(DataOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  if (Length <= 0 || Length > 1024) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, ""));
    return;
  }

  const uint8_t *native_data = (const uint8_t *)ADDR_APP_TO_NATIVE(DataOffset);
  std::vector<uint8_t> revert_msg;
  revert_msg.resize(Length);
  memcpy((uint8_t *)revert_msg.data(), native_data, Length);
  printf("evm revert with: %s\n",
         zen::utils::toHex(revert_msg.data(), revert_msg.size()).c_str());
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::EnvAbort, "revert"));
}

static int32_t getCodeSize(Instance *instance) {
  // return abi code size(with prefix)
  auto EvmAbiMockCtx = getEVMAbiMockContext(instance);
  if (!EvmAbiMockCtx) {
    instance->setExceptionByHostapi(getErrorWithExtraMessage(
        ErrorCode::EnvAbort, EVM_ABI_CONTEXT_NOT_FOUND));
    return 0;
  }
  auto AbiCode = EvmAbiMockCtx->getCurContractCode();
  return AbiCode.size();
}

static void codeCopy(Instance *instance, int32_t ResultOffset,
                     int32_t CodeOffset, int32_t Length) {
  auto EvmAbiMockCtx = getEVMAbiMockContext(instance);
  if (!EvmAbiMockCtx) {
    instance->setExceptionByHostapi(getErrorWithExtraMessage(
        ErrorCode::EnvAbort, EVM_ABI_CONTEXT_NOT_FOUND));
    return;
  }
  if (!VALIDATE_APP_ADDR(ResultOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  auto AbiCode = EvmAbiMockCtx->getCurContractCode();
  auto CurAbiCodeSize = AbiCode.size();
  if (CodeOffset >= CurAbiCodeSize) {
    memset(NativeResult, 0x0, Length);
  } else if (CodeOffset + Length > CurAbiCodeSize) {
    memcpy(NativeResult, AbiCode.data() + CodeOffset,
           CurAbiCodeSize - CodeOffset);
    // remaining use zeros to fill NativeResult
    memset(NativeResult + CurAbiCodeSize - CodeOffset, 0x0,
           Length - (CurAbiCodeSize - CodeOffset));
  } else {
    memcpy(NativeResult, AbiCode.data() + CodeOffset, Length);
  }
}

static void getBlobBaseFee(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_BLOB_BASE_FEE[32] = {0x00};
  MOCK_BLOB_BASE_FEE[31] = 1;
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_BLOB_BASE_FEE, 32);
}

static void getBaseFee(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_BASE_FEE[32] = {0x00};
  MOCK_BASE_FEE[31] = 1;
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_BASE_FEE, 32);
}

static void getBlockCoinbase(Instance *instance, int32_t ResultOffset) {
  static uint8_t MOCK_COINBASE[20] = {0x02};
  if (!VALIDATE_APP_ADDR(ResultOffset, 20)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_COINBASE, 20);
}

static void getTxGasPrice(Instance *instance, int32_t ValueOffset) {
  static uint8_t MOCK_GAS_PRICE[32] = {0x00};
  MOCK_GAS_PRICE[31] = 2;
  if (!VALIDATE_APP_ADDR(ValueOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *native_value = (uint8_t *)ADDR_APP_TO_NATIVE(ValueOffset);
  memcpy(native_value, MOCK_GAS_PRICE, 32);
}

static void getExternalBalance(Instance *instance, int32_t AddrOffset,
                               int32_t ResultOffset) {
  static uint8_t MOCK_EXT_BALANCE[32] = {0x00};
  MOCK_EXT_BALANCE[31] = 0x00; // 0 wei

  if (!VALIDATE_APP_ADDR(AddrOffset, 20) ||
      !VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_EXT_BALANCE, 32);
}

static int32_t getExternalCodeSize(Instance *instance, int32_t AddrOffset) {
  if (!VALIDATE_APP_ADDR(AddrOffset, 20)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return -1;
  }
  return 0; // asuming no other contract in mock
}

static void getExternalCodeHash(Instance *instance, int32_t AddrOffset,
                                int32_t ResultOffset) {
  static uint8_t MOCK_CODE_HASH[32] = {0xEC}; // 0xEC means external code hash

  if (!VALIDATE_APP_ADDR(AddrOffset, 20) ||
      !VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_CODE_HASH, 32);
}

static void externalCodeCopy(Instance *instance, int32_t AddrOffset,
                             int32_t ResultOffset, int32_t CodeOffset,
                             int32_t Length) {
  // no other contracts in mock env, always return empty data
  if (!VALIDATE_APP_ADDR(AddrOffset, 20) ||
      !VALIDATE_APP_ADDR(ResultOffset, Length)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }

  if (Length > 0) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, "invalid code range"));
    return;
  }
  // do nothing because extern contract always Length zero in mock env
}

static void getBlockPrevRandao(Instance *instance, int32_t ResultOffset) {
  // get the block’s difficulty.
  static uint8_t MOCK_BLOCK_PREVRANDAO[32] = {0x01};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_BLOCK_PREVRANDAO, 32);
}

static void selfDestruct(Instance *instance, int32_t _AddrOffset) {
  instance->setExceptionByHostapi(
      getErrorWithExtraMessage(ErrorCode::EnvAbort, "selfdestruct"));
}

static void sha256(Instance *instance, int32_t input_offset,
                   int32_t input_Length, int32_t ResultOffset) {
  static uint8_t MOCK_SHA256_RESULT[32] = {0x12};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_SHA256_RESULT, 32);
}

static void keccak256(Instance *instance, int32_t _InputOffset,
                      int32_t _InputLength, int32_t ResultOffset) {
  static uint8_t MOCK_SHA256_RESULT[32] = {0x23};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_SHA256_RESULT, 32);
}

static void addmod(Instance *instance, int32_t _AOffset, int32_t _BOffset,
                   int32_t _N_offset, int32_t ResultOffset) {
  static uint8_t MOCK_ADDMOD_RESULT[32] = {0x34};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_ADDMOD_RESULT, 32);
}

static void mulmod(Instance *instance, int32_t _AOffset, int32_t _BOffset,
                   int32_t _N_offset, int32_t ResultOffset) {
  static uint8_t MOCK_ADDMOD_RESULT[32] = {0x34};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_ADDMOD_RESULT, 32);
}

static void expmod(Instance *instance, int32_t _AOffset, int32_t _BOffset,
                   int32_t _N_offset, int32_t ResultOffset) {
  static uint8_t MOCK_ADDMOD_RESULT[32] = {0x45};
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  uint8_t *NativeResult = (uint8_t *)ADDR_APP_TO_NATIVE(ResultOffset);
  memcpy(NativeResult, MOCK_ADDMOD_RESULT, 32);
}

static int32_t callContract(Instance *instance, int64_t Gas, int32_t AddrOffset,
                            int32_t ValueOffset, int32_t DataOffset,
                            int32_t data_Length) {
  // value is big-endian u256 bytes32*
  // call sub contract not allowed in mock env now
  return 1;
}

static int32_t callCode(Instance *instance, int64_t Gas, int32_t AddrOffset,
                        int32_t ValueOffset, int32_t DataOffset,
                        int32_t data_Length) {
  // value is big-endian u256 bytes32*
  // call sub contract not allowed in mock env now
  return 1;
}

static int32_t callDelegate(Instance *instance, int64_t Gas, int32_t AddrOffset,
                            int32_t DataOffset, int32_t data_Length) {
  // call sub contract not allowed in mock env now
  return 1;
}

static int32_t callStatic(Instance *instance, int64_t Gas, int32_t AddrOffset,
                          int32_t DataOffset, int32_t data_Length) {
  // call sub contract not allowed in mock env now
  return 1;
}

static int32_t createContract(Instance *instance, int32_t ValueOffset,
                              int32_t CodeOffset, int32_t code_Length,
                              int32_t DataOffset, int32_t data_Length,
                              int32_t salt_offset, int32_t is_create2,
                              int32_t ResultOffset) {
  // salt is big endian bytes32*
  // creating sub contract not allowed in mock env now
  return 1;
}

static int32_t getReturnDataSize(Instance *_Inst) {
  // no allowing call sub contract in mock env
  return 0;
}

static void returnDataCopy(Instance *instance, int32_t ResultOffset,
                           int32_t DataOffset, int32_t Length) {
  // no allowing call sub contract in mock env
  if (!VALIDATE_APP_ADDR(ResultOffset, 32)) {
    instance->setExceptionByHostapi(
        getErrorWithExtraMessage(ErrorCode::EnvAbort, OUT_OF_BOUND_ERROR));
    return;
  }
  // copy nothing in mock env
}

#define FUNCTION_LISTS                                                         \
  NATIVE_FUNC_ENTRY(getAddress)                                                \
  NATIVE_FUNC_ENTRY(getBlockHash)                                              \
  NATIVE_FUNC_ENTRY(getCallDataSize)                                           \
  NATIVE_FUNC_ENTRY(getCaller)                                                 \
  NATIVE_FUNC_ENTRY(getCallValue)                                              \
  NATIVE_FUNC_ENTRY(getChainId)                                                \
  NATIVE_FUNC_ENTRY(callDataCopy)                                              \
  NATIVE_FUNC_ENTRY(getGasLeft)                                                \
  NATIVE_FUNC_ENTRY(getBlockGasLimit)                                          \
  NATIVE_FUNC_ENTRY(getBlockNumber)                                            \
  NATIVE_FUNC_ENTRY(getTxOrigin)                                               \
  NATIVE_FUNC_ENTRY(getBlockTimestamp)                                         \
  NATIVE_FUNC_ENTRY(storageStore)                                              \
  NATIVE_FUNC_ENTRY(storageLoad)                                               \
  NATIVE_FUNC_ENTRY(emitLogEvent)                                              \
  NATIVE_FUNC_ENTRY(finish)                                                    \
  NATIVE_FUNC_ENTRY(invalid)                                                   \
  NATIVE_FUNC_ENTRY(revert)                                                    \
  NATIVE_FUNC_ENTRY(getCodeSize)                                               \
  NATIVE_FUNC_ENTRY(codeCopy)                                                  \
  NATIVE_FUNC_ENTRY(getBlobBaseFee)                                            \
  NATIVE_FUNC_ENTRY(getBaseFee)                                                \
  NATIVE_FUNC_ENTRY(getBlockCoinbase)                                          \
  NATIVE_FUNC_ENTRY(getTxGasPrice)                                             \
  NATIVE_FUNC_ENTRY(getExternalBalance)                                        \
  NATIVE_FUNC_ENTRY(getExternalCodeSize)                                       \
  NATIVE_FUNC_ENTRY(getExternalCodeHash)                                       \
  NATIVE_FUNC_ENTRY(externalCodeCopy)                                          \
  NATIVE_FUNC_ENTRY(getBlockPrevRandao)                                        \
  NATIVE_FUNC_ENTRY(selfDestruct)                                              \
  NATIVE_FUNC_ENTRY(sha256)                                                    \
  NATIVE_FUNC_ENTRY(keccak256)                                                 \
  NATIVE_FUNC_ENTRY(addmod)                                                    \
  NATIVE_FUNC_ENTRY(mulmod)                                                    \
  NATIVE_FUNC_ENTRY(expmod)                                                    \
  NATIVE_FUNC_ENTRY(callContract)                                              \
  NATIVE_FUNC_ENTRY(callCode)                                                  \
  NATIVE_FUNC_ENTRY(callDelegate)                                              \
  NATIVE_FUNC_ENTRY(callStatic)                                                \
  NATIVE_FUNC_ENTRY(createContract)                                            \
  NATIVE_FUNC_ENTRY(getReturnDataSize)                                         \
  NATIVE_FUNC_ENTRY(returnDataCopy)

/*
    the following code are auto generated,
    don't modify it unless you know it exactly.
*/
#include "wni/boilerplate.cpp"

} // namespace zen::host
