// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "zetaengine-c.h"
#include "zetaengine.h"

#include <gtest/gtest.h>

namespace zen::test {

using namespace zen;
using namespace common;

static ZenRuntimeConfig RuntimeConfig = {
#ifdef ZEN_ENABLE_SINGLEPASS_JIT
    .Mode = ZenModeSinglepass,
#else
    .Mode = ZenModeInterp,
#endif
    .DisableWasmMemoryMap = false,
    .DisableWASI = true,
    .EnableStatistics = false,
    .EnableGdbTracingHook = false,
};

static void envPrintStr(ZenInstanceRef Instance, uint32_t Offset) {
  char *Str = reinterpret_cast<char *>(ZenGetHostMemAddr(Instance, Offset));
  printf("print_str: %s", Str);
}

TEST(C_API, Normal) {
  ZenEnableLogging();
  ZenRuntimeRef Runtime = ZenCreateRuntime(&RuntimeConfig);
  EXPECT_NE(Runtime, nullptr);

  ZenType ArgTypesI32[] = {ZenTypeI32};
  ZenHostFuncDesc HostFuncDescs[] = {
      {
          .Name = "print_str",
          .NumArgs = 1,
          .ArgTypes = ArgTypesI32,
          .NumReturns = 0,
          .RetTypes = NULL,
          .Ptr = (void *)envPrintStr,
      },
  };
  ZenHostModuleDescRef HostModuleDesc =
      ZenCreateHostModuleDesc(Runtime, "env", HostFuncDescs, 1);
  EXPECT_NE(HostModuleDesc, nullptr);

  ZenHostModuleRef HostModule = ZenLoadHostModule(Runtime, HostModuleDesc);
  EXPECT_NE(HostModule, nullptr);

  // From <project_root>/example/c_api/t2.wat
  static uint8_t WASMBuffer[] = {
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x09, 0x02, 0x60,
      0x01, 0x7f, 0x00, 0x60, 0x00, 0x01, 0x7f, 0x02, 0x11, 0x01, 0x03, 0x65,
      0x6e, 0x76, 0x09, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x5f, 0x73, 0x74, 0x72,
      0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07,
      0x09, 0x01, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x00, 0x01, 0x0a, 0x0b,
      0x01, 0x09, 0x00, 0x41, 0x14, 0x10, 0x00, 0x41, 0xe4, 0x00, 0x0b, 0x0b,
      0x15, 0x01, 0x00, 0x41, 0x14, 0x0b, 0x0f, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
      0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x0a, 0x00,
  };
  char ErrBuf[128] = {0};
  const uint32_t ErrBufSize = sizeof(ErrBuf);
  ZenModuleRef Module = ZenLoadModuleFromBuffer(
      Runtime, "test", WASMBuffer, sizeof(WASMBuffer), ErrBuf, ErrBufSize);
  EXPECT_NE(Module, nullptr);

  ZenIsolationRef Isolation = ZenCreateIsolation(Runtime);
  EXPECT_NE(Isolation, nullptr);

  ZenInstanceRef Instance =
      ZenCreateInstance(Isolation, Module, ErrBuf, ErrBufSize);
  EXPECT_NE(Instance, nullptr);
  EXPECT_FALSE(ZenGetInstanceError(Instance, ErrBuf, ErrBufSize));

  ZenValue Results[1];
  uint32_t NumOutResults;
  bool Ret = ZenCallWasmFuncByName(Runtime, Instance, "entry", nullptr, 0,
                                   Results, &NumOutResults);

  EXPECT_TRUE(Ret);
  EXPECT_EQ(NumOutResults, 1);
  EXPECT_EQ(Results[0].Type, ZenTypeI32);
  EXPECT_EQ(Results[0].Value.I32, 100);
  EXPECT_FALSE(ZenGetInstanceError(Instance, ErrBuf, ErrBufSize));

  EXPECT_TRUE(ZenDeleteInstance(Isolation, Instance));

  EXPECT_TRUE(ZenDeleteIsolation(Runtime, Isolation));

  EXPECT_TRUE(ZenDeleteModule(Runtime, Module));

  EXPECT_TRUE(ZenDeleteHostModule(Runtime, HostModule));

  ZenDeleteHostModuleDesc(Runtime, HostModuleDesc);
  ZenDeleteRuntime(Runtime);
}

TEST(C_API, LoadError) {
  ZenEnableLogging();
  ZenRuntimeRef Runtime = ZenCreateRuntime(&RuntimeConfig);
  EXPECT_NE(Runtime, nullptr);

  static uint8_t WASMBufferTmp[] = {
      0x28, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x0a, 0x20,
  };
  char ErrBuf[128] = {0};
  const uint32_t ErrBufSize = sizeof(ErrBuf);
  ZenModuleRef Module =
      ZenLoadModuleFromBuffer(Runtime, "test", WASMBufferTmp,
                              sizeof(WASMBufferTmp), ErrBuf, ErrBufSize);
  EXPECT_EQ(Module, nullptr);
  EXPECT_STREQ(ErrBuf, "load error: magic header not detected");

  ZenDeleteRuntime(Runtime);
}

TEST(C_API, Trap) {
  ZenEnableLogging();
  ZenRuntimeRef Runtime = ZenCreateRuntime(&RuntimeConfig);
  EXPECT_NE(Runtime, nullptr);

  // From <project_root>/example/c_api/t2.wat
  static uint8_t WASMBuffer[] = {
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60,
      0x00, 0x00, 0x03, 0x03, 0x02, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01,
      0x07, 0x09, 0x01, 0x05, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x00, 0x00, 0x0a,
      0x0b, 0x02, 0x04, 0x00, 0x10, 0x01, 0x0b, 0x04, 0x00, 0x10, 0x01, 0x0b,
  };
  char ErrBuf[128] = {0};
  const uint32_t ErrBufSize = sizeof(ErrBuf);
  ZenModuleRef Module = ZenLoadModuleFromBuffer(
      Runtime, "test", WASMBuffer, sizeof(WASMBuffer), ErrBuf, ErrBufSize);
  EXPECT_NE(Module, nullptr);

  ZenIsolationRef Isolation = ZenCreateIsolation(Runtime);
  EXPECT_NE(Isolation, nullptr);

  ZenInstanceRef Instance =
      ZenCreateInstance(Isolation, Module, ErrBuf, ErrBufSize);
  EXPECT_NE(Instance, nullptr);
  EXPECT_FALSE(ZenGetInstanceError(Instance, ErrBuf, ErrBufSize));

  ZenValue Results[1];
  uint32_t NumOutResults;
  bool Ret = ZenCallWasmFuncByName(Runtime, Instance, "entry", nullptr, 0,
                                   Results, &NumOutResults);

  EXPECT_FALSE(Ret);
  EXPECT_EQ(NumOutResults, 0);
  EXPECT_TRUE(ZenGetInstanceError(Instance, ErrBuf, ErrBufSize));
  EXPECT_STREQ(ErrBuf, "execution error: call stack exhausted");

  EXPECT_TRUE(ZenDeleteInstance(Isolation, Instance));

  EXPECT_TRUE(ZenDeleteIsolation(Runtime, Isolation));

  EXPECT_TRUE(ZenDeleteModule(Runtime, Module));

  ZenDeleteRuntime(Runtime);
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

} // namespace zen::test
