// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
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

} // namespace zen::utils
