// Copyright (C) 2024-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_HOST_EVMABIMOCK_EVMABIMOCK_H
#define ZEN_HOST_EVMABIMOCK_EVMABIMOCK_H

#include "wni/helper.h"
#include <memory>
#include <unordered_map>
#include <vector>

namespace zen::host {

// cli with evm abi mock hosts need set EVMAbiMockContext* in
// instance->setCustomData(...)
class EVMAbiMockContext {
private:
  std::vector<uint8_t> CurMsgContractCode;
  // key(byte32) hex => value(byte32) hex without 0x prefix
  std::unordered_map<std::string, std::vector<uint8_t>> CurMsgContractStores;

public:
  static std::shared_ptr<EVMAbiMockContext>
  create(std::vector<uint8_t> &WasmCode);
  void setCurContractStore(const std::string &Key,
                           const std::vector<uint8_t> &Value);
  const std::vector<uint8_t> &getCurContractStore(const std::string &Key);
  const std::vector<uint8_t> &getCurContractCode();
};

#undef EXPORT_MODULE_NAME
#define EXPORT_MODULE_NAME env

AUTO_GENERATED_FUNCS_DECL

} // namespace zen::host

#endif // ZEN_HOST_EVMABIMOCK_EVMABIMOCK_H
