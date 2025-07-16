// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/others.h"

#include <cinttypes>
#include <cstdio>
#ifdef ZEN_BUILD_PLATFORM_DARWIN
#include <dirent.h>
#endif

namespace zen::utils {

std::vector<std::string> split(const std::string &Str, char Delim) {
  std::vector<std::string> Tokens;
  std::stringstream SS(Str);
  std::string Item;
  while (std::getline(SS, Item, Delim)) {
    Tokens.push_back(Item);
  }
  return Tokens;
}

void printTypedValueArray(const std::vector<common::TypedValue> &Results) {
  using common::WASMType;
  for (const auto &Result : Results) {
    const auto &Output = Result.Value;
    switch (Result.Type) {
    case WASMType::I32: {
      printf("0x%" PRIx32 ":i32\n", Output.I32);
      break;
    }
    case WASMType::I64: {
      printf("0x%" PRIx64 ":i64\n", Output.I64);
      break;
    }
    case WASMType::F32: {
      printf("%.7g:f32\n", Output.F32);
      break;
    }
    case WASMType::F64: {
      printf("%.7g:f64\n", Output.F64);
      break;
    }
    default:
      ZEN_ASSERT_TODO();
    }
  }
}

bool checkSupportRamDisk() {
#ifdef ZEN_BUILD_PLATFORM_DARWIN
  // 0: not checked, 1: has, -1: not has
  static int checkedDarwinHasRandisk = 0;
  // check darwin created /Volumes/RAMDisk
  if (checkedDarwinHasRandisk == 0) {
    DIR *Dir = opendir("/Volumes/RAMDisk");
    if (Dir) {
      closedir(Dir);
      checkedDarwinHasRandisk = 1;
    } else {
      checkedDarwinHasRandisk = -1;
      // fallback to malloc when ramdisk disabled. so just warning.
      ZEN_LOG_WARN("Darwin RAMDisk is disabled due to '%s', fallback to malloc",
                   std::strerror(errno));
    }
  }
  return checkedDarwinHasRandisk > 0;
#elif defined(ZEN_BUILD_PLATFORM_POSIX)
  return true;
#else
  ZEN_ASSERT(false);
  return false;
#endif
}

#ifndef ZEN_ENABLE_SGX
bool readBinaryFile(const std::string &Path, std::vector<uint8_t> &Data) {
  FILE *File = ::fopen(Path.c_str(), "rb");
  if (!File) {
    return false;
  }
  ::fseek(File, 0, SEEK_END);
  size_t Size = ::ftell(File);
  ::rewind(File);
  Data.resize(Size);
  ::fread(Data.data(), 1, Size, File);
  ::fclose(File);
  return true;
}
#endif // ZEN_ENABLE_SGX

const char HEX_CHARS[] = "0123456789ABCDEF";

std::string toHex(const uint8_t *Bytes, size_t BytesCount) {
  std::string HexStr;
  HexStr.reserve(BytesCount * 2);

  for (size_t I = 0; I < BytesCount; I++) {
    unsigned char B = (unsigned char)Bytes[I];
    HexStr += HEX_CHARS[(B >> 4) & 0x0F]; // high 4 bits
    HexStr += HEX_CHARS[B & 0x0F];        // low 4 bits
  }
  return HexStr;
}

void trimString(std::string &Str) {
  Str.erase(0, Str.find_first_not_of(" \n\r\t"));
  Str.erase(Str.find_last_not_of(" \n\r\t") + 1);
}

std::optional<std::vector<uint8_t>> fromHex(std::string_view HexStr) {
  std::vector<uint8_t> Result;

  // Remove 0x prefix if present
  if (HexStr.size() >= 2 && HexStr.substr(0, 2) == "0x") {
    HexStr = HexStr.substr(2);
  }

  // Hex string must have even length
  if (HexStr.size() % 2 != 0) {
    return std::nullopt;
  }

  Result.reserve(HexStr.size() / 2);

  for (size_t I = 0; I < HexStr.size(); I += 2) {
    char High = HexStr[I];
    char Low = HexStr[I + 1];

    // Convert hex characters to values
    auto hexCharToValue = [](char C) -> int {
      if (C >= '0' && C <= '9')
        return C - '0';
      if (C >= 'A' && C <= 'F')
        return C - 'A' + 10;
      if (C >= 'a' && C <= 'f')
        return C - 'a' + 10;
      return -1;
    };

    int HighValue = hexCharToValue(High);
    int LowValue = hexCharToValue(Low);

    if (HighValue == -1 || LowValue == -1) {
      return std::nullopt;
    }

    Result.push_back((HighValue << 4) | LowValue);
  }

  return Result;
}

} // namespace zen::utils
