// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/codeholder.h"
#include "common/errors.h"
#include "platform/map.h"
#include "runtime/module.h"

namespace zen::runtime {

using namespace common;
using namespace platform;

CodeHolderUniquePtr CodeHolder::newFileCodeHolder(Runtime &RT,
                                                  const std::string &Filename) {
  ZEN_ASSERT(!Filename.empty());

  FileMapInfo MapInfo = {.Addr = nullptr, .Length = size_t(-1)};

  if (!mapFile(&MapInfo, Filename.c_str())) {
    if (MapInfo.Length == 0) {
      // Empty File
      throw getError(ErrorCode::UnexpectedEnd);
    }
    throw getError(ErrorCode::FileAccessFailed);
  }

  if (MapInfo.Length > PresetMaxModuleSize) {
    throw getError(ErrorCode::ModuleSizeTooLarge);
  }

  void *Buf = RT.allocate(sizeof(CodeHolder));
  ZEN_ASSERT(Buf);

  CodeHolderUniquePtr File(new (Buf) CodeHolder(RT, HolderKind::kFile));

  File->Data = MapInfo.Addr;
  File->Size = MapInfo.Length;

  return File;
}

CodeHolderUniquePtr
CodeHolder::newRawDataCodeHolder(Runtime &RT, const void *Data, size_t Size) {
  if (Size > PresetMaxModuleSize) {
    throw getError(ErrorCode::ModuleSizeTooLarge);
  }
  if (Size != 0 && Data == nullptr) {
    throw getError(ErrorCode::InvalidRawData);
  }

  void *Buf = RT.allocate(sizeof(CodeHolder));
  ZEN_ASSERT(Buf);

  CodeHolderUniquePtr RawData(new (Buf) CodeHolder(RT, HolderKind::kRawData));

  void *DataCopy = nullptr;
  if (Size != 0) {
    DataCopy = RT.allocate(Size);
    ZEN_ASSERT(DataCopy);
    std::memcpy(DataCopy, Data, Size);
  }

  RawData->Data = DataCopy;
  RawData->Size = Size;

  return RawData;
}

CodeHolder::~CodeHolder() {
  switch (Kind) {
  case HolderKind::kFile:
    releaseFileCodeHolder();
    break;
  case HolderKind::kRawData:
    releaseRawDataCodeHolder();
    break;
  default:
    ZEN_UNREACHABLE();
  }
}

void CodeHolder::releaseFileCodeHolder() {
  if (Data && Size) {
    FileMapInfo MapInfo;
    MapInfo.Addr = const_cast<void *>(Data);
    MapInfo.Length = Size;
    unmapFile(&MapInfo);
  }
  Data = nullptr;
  Size = 0;
}

void CodeHolder::releaseRawDataCodeHolder() {
  if (Data && Size) {
    deallocate(const_cast<void *>(Data));
  }
  Data = nullptr;
  Size = 0;
}

} // namespace zen::runtime
