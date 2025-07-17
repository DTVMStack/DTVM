#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "evm/interpreter.h"
#include "runtime/runtime.h"
#include "utils/others.h"

using namespace zen;
using namespace zen::evm;
using namespace zen::runtime;

namespace {

std::vector<std::string> getAllEvmBytecodeFiles() {
  std::vector<std::string> Files;
  std::filesystem::path DirPath =
      std::filesystem::path(__FILE__).parent_path() /
      std::filesystem::path("../../tests/evm_asm");

  if (!std::filesystem::exists(DirPath)) {
    std::cerr << "tests/evm_asm does not exist: " << DirPath.string()
              << std::endl;
    return Files;
  }

  for (const auto &Entry : std::filesystem::directory_iterator(DirPath)) {
    if (Entry.is_regular_file() && Entry.path().extension() == ".hex") {
      Files.push_back(Entry.path().string());
    }
  }

  std::sort(Files.begin(), Files.end());

  if (Files.empty()) {
    std::cerr << "No EVM hex files found in tests/evm_asm, "
              << "maybe you should convert the asm to hex first" << std::endl;
  }

  return Files;
}

void appendResult(const std::string &SampleName, const std::string &HexRet) {
  static std::mutex Mtx;
  std::lock_guard<std::mutex> Guard(Mtx);
  std::ofstream Fout("evm_results.txt", std::ios::app);
  Fout << SampleName << ": " << HexRet << '\n';
}

std::string readAnswerFile(const std::string &FilePath) {
  std::filesystem::path InputFilePath(FilePath);

  // Use filesystem API instead of manual path parsing
  std::filesystem::path AnswerPath =
      InputFilePath.parent_path() /
      (InputFilePath.stem().stem().string() + ".answer");

  // Read file content
  std::ifstream Fin(AnswerPath);
  if (!Fin) {
    return "";
  }

  std::string Answer;
  Fin >> Answer;
  return Answer;
}

} // namespace

class EVMSampleTest : public ::testing::TestWithParam<std::string> {};

TEST_P(EVMSampleTest, ExecuteSample) {
  const std::string &FilePath = GetParam();

  std::ifstream Fin(FilePath);
  ASSERT_TRUE(Fin.is_open()) << "Failed to open test file: " << FilePath;

  std::string Hex;
  Fin >> Hex;
  zen::utils::trimString(Hex);
  auto BytecodeBuf = zen::utils::fromHex(Hex);
  ASSERT_TRUE(BytecodeBuf) << "Failed to convert hex to bytecode";

  RuntimeConfig Config;
  Config.Mode = common::RunMode::InterpMode;

  auto RT = Runtime::newRuntime(Config);
  ASSERT_TRUE(RT != nullptr) << "Failed to create runtime";

  auto ModRet = RT->loadEVMModule(FilePath);
  ASSERT_TRUE(ModRet) << "Failed to load module: " << FilePath;

  EVMModule *Mod = *ModRet;

  InterpreterExecContext Ctx(Mod);

  BaseInterpreter Interpreter(Ctx);
  EXPECT_NO_THROW({ Interpreter.interpret(); });

  const auto &Ret = Ctx.getReturnData();
  std::string HexRet = zen::utils::toHex(Ret.data(), Ret.size());
  appendResult(std::filesystem::path(FilePath).filename().string(), HexRet);

  // Read expected answer
  std::string ExpectedAnswer = readAnswerFile(FilePath);
  if (!ExpectedAnswer.empty()) {
    EXPECT_EQ(HexRet, ExpectedAnswer)
        << "Test: " << std::filesystem::path(FilePath).filename().string()
        << "\nExpected: " << ExpectedAnswer << "\nActual:   " << HexRet;
  } else {
    ASSERT_TRUE(false) << "No answer file found for: " << FilePath;
  }

  EXPECT_EQ(Ctx.getCurFrame(), nullptr)
      << "Frame should be deallocated after execution";
}

INSTANTIATE_TEST_SUITE_P(EVMSamples, EVMSampleTest,
                         ::testing::ValuesIn(getAllEvmBytecodeFiles()));
