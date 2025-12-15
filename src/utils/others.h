// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_UTILS_OTHERS_H
#define ZEN_UTILS_OTHERS_H

#include "common/enums.h"
#include "common/type.h"
#include "utils/logging.h"

#include <chrono>
#include <sstream>
#include <string>
#include <vector>

namespace zen::utils {

template <typename DestType, typename SrcType> DestType bitCast(SrcType From) {
  union {
    SrcType From;
    DestType To;
  } U;
  U.From = From;
  return U.To;
}

std::vector<std::string> split(const std::string &Str, char Delim);

inline std::string getOpcodeHexString(uint8_t Opcode) {
  char Buf[5];
  snprintf(Buf, 5, "0x%x", Opcode);
  return {Buf};
}

void printTypedValueArray(const std::vector<common::TypedValue> &Results);

bool checkSupportRamDisk();

#ifndef ZEN_ENABLE_SGX
bool readBinaryFile(const std::string &Path, std::vector<uint8_t> &Data);
#endif // ZEN_ENABLE_SGX

std::string toHex(const uint8_t *Bytes, size_t BytesCount);

} // namespace zen::utils

#endif // ZEN_UTILS_OTHERS_H
