// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/runtime.h"
#include "tests/evm_test_host.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

using namespace zen::common;
using namespace zen::runtime;

namespace {

std::unique_ptr<Runtime>
newTestRuntime(std::unique_ptr<zen::evm::ZenMockedEVMHost> &Host,
               RunMode Mode = RunMode::InterpMode) {
  RuntimeConfig Config;
  Config.Format = InputFormat::EVM;
  Config.Mode = Mode;
  Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  if (RT) {
    Host->setRuntime(RT.get());
  }
  return RT;
}

} // namespace

TEST(EVMCodeCacheTest, ReusesSameBytecodeAndConfig) {
  std::unique_ptr<zen::evm::ZenMockedEVMHost> Host;
  auto RT = newTestRuntime(Host);
  ASSERT_NE(RT, nullptr);

  const std::vector<uint8_t> Code = {0x00};
  EVMCodeCacheLookupInfo FirstInfo;
  auto First =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_CANCUN,
                                      {}, &FirstInfo);
  ASSERT_TRUE(First);
  EXPECT_FALSE(FirstInfo.CacheHit);
  EXPECT_EQ(FirstInfo.EntryCount, 1U);

  EVMCodeCacheLookupInfo SecondInfo;
  auto Second =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_CANCUN,
                                      {}, &SecondInfo);
  ASSERT_TRUE(Second);
  EXPECT_TRUE(SecondInfo.CacheHit);
  EXPECT_EQ(SecondInfo.EntryCount, 1U);
  EXPECT_EQ(*First, *Second);
  EXPECT_EQ(FirstInfo.CodeHashHex, SecondInfo.CodeHashHex);
}

TEST(EVMCodeCacheTest, SeparatesRevisionAndMemoryProfile) {
  std::unique_ptr<zen::evm::ZenMockedEVMHost> Host;
  auto RT = newTestRuntime(Host);
  ASSERT_NE(RT, nullptr);

  const std::vector<uint8_t> Code = {0x00};
  auto Cancun =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_CANCUN);
  ASSERT_TRUE(Cancun);

  EVMCodeCacheLookupInfo PragueInfo;
  auto Prague =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_PRAGUE,
                                      {}, &PragueInfo);
  ASSERT_TRUE(Prague);
  EXPECT_FALSE(PragueInfo.CacheHit);
  EXPECT_NE(*Cancun, *Prague);
  EXPECT_EQ(PragueInfo.EntryCount, 2U);

  EVMMemorySpecializationProfile Profile;
  Profile.SkipLeadingZeroLimbStores = 1;
  EVMCodeCacheLookupInfo ProfileInfo;
  auto Specialized = RT->getOrCompileCachedEVMModule(
      Code.data(), Code.size(), EVMC_CANCUN, Profile, &ProfileInfo);
  ASSERT_TRUE(Specialized);
  EXPECT_FALSE(ProfileInfo.CacheHit);
  EXPECT_NE(*Cancun, *Specialized);
  EXPECT_EQ(ProfileInfo.EntryCount, 3U);
}

#ifdef ZEN_ENABLE_MULTIPASS_JIT
TEST(EVMCodeCacheTest, ReusesJITCompiledModule) {
  std::unique_ptr<zen::evm::ZenMockedEVMHost> Host;
  auto RT = newTestRuntime(Host, RunMode::MultipassMode);
  ASSERT_NE(RT, nullptr);

  const std::vector<uint8_t> Code = {0x00};
  EVMCodeCacheLookupInfo FirstInfo;
  auto First =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_CANCUN,
                                      {}, &FirstInfo);
  ASSERT_TRUE(First);
  ASSERT_NE((*First)->getJITCode(), nullptr);
  EXPECT_FALSE(FirstInfo.CacheHit);

  EVMCodeCacheLookupInfo SecondInfo;
  auto Second =
      RT->getOrCompileCachedEVMModule(Code.data(), Code.size(), EVMC_CANCUN,
                                      {}, &SecondInfo);
  ASSERT_TRUE(Second);
  EXPECT_TRUE(SecondInfo.CacheHit);
  EXPECT_EQ(*First, *Second);
  EXPECT_EQ((*First)->getJITCode(), (*Second)->getJITCode());
}
#endif // ZEN_ENABLE_MULTIPASS_JIT
