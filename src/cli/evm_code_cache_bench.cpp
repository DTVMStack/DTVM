// Copyright (C) 2026 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "runtime/codeholder.h"
#include "runtime/evm_memory_specialization.h"
#include "tests/evm_test_host.hpp"
#include "utils/evm.h"
#include "utils/logging.h"
#include "utils/others.h"
#include "zetaengine.h"

#include <CLI/CLI.hpp>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <rapidjson/document.h>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

using namespace zen::common;
using namespace zen::runtime;

namespace {

struct PreparedReplay {
  std::string Dataset;
  std::string TxHash;
  std::filesystem::path PreparedPath;
  std::filesystem::path BytecodePath;
  std::filesystem::path StatePath;
  std::string ContractAddress;
  std::string Sender;
  std::string CalldataHex;
  uint64_t GasLimit = 0;
  evmc_revision Revision = zen::evm::DEFAULT_REVISION;
};

struct RunResult {
  PreparedReplay Replay;
  std::string Mode;
  std::string CodeHash;
  bool CacheHit = false;
  bool FallbackToInterpreter = false;
  bool HasJITCode = false;
  size_t CacheEntries = 0;
  size_t BytecodeSize = 0;
  size_t JITCodeSize = 0;
  uint64_t InternalCacheHits = 0;
  uint64_t InternalCacheMisses = 0;
  double LookupCompileMs = 0.0;
  double ExecutionMs = 0.0;
  int ReturnCode = -1;
  bool Success = false;
  std::string Error;
};

double elapsedMs(zen::common::SteadyClock::time_point Start,
                 zen::common::SteadyClock::time_point End) {
  return std::chrono::duration<double, std::milli>(End - Start).count();
}

std::string jsonEscape(const std::string &Input) {
  std::string Out;
  Out.reserve(Input.size() + 8);
  for (char C : Input) {
    switch (C) {
    case '"':
      Out += "\\\"";
      break;
    case '\\':
      Out += "\\\\";
      break;
    case '\n':
      Out += "\\n";
      break;
    case '\r':
      Out += "\\r";
      break;
    case '\t':
      Out += "\\t";
      break;
    default:
      Out += C;
      break;
    }
  }
  return Out;
}

std::optional<std::string> getString(const rapidjson::Value &Obj,
                                     const char *Key) {
  if (!Obj.IsObject() || !Obj.HasMember(Key) || !Obj[Key].IsString()) {
    return std::nullopt;
  }
  return std::string(Obj[Key].GetString());
}

std::optional<uint64_t> parseU64(const std::string &Value) {
  try {
    size_t Pos = 0;
    int Base = 10;
    std::string Text = Value;
    if (Text.rfind("0x", 0) == 0 || Text.rfind("0X", 0) == 0) {
      Base = 16;
      Text = Text.substr(2);
    }
    uint64_t Parsed = std::stoull(Text, &Pos, Base);
    if (Pos != Text.size()) {
      return std::nullopt;
    }
    return Parsed;
  } catch (...) {
    return std::nullopt;
  }
}

evmc_revision parseRevision(const std::string &Revision) {
  static const std::map<std::string, evmc_revision> Revisions = {
      {"frontier", EVMC_FRONTIER},
      {"homestead", EVMC_HOMESTEAD},
      {"tangerine", EVMC_TANGERINE_WHISTLE},
      {"tangerine_whistle", EVMC_TANGERINE_WHISTLE},
      {"spurious", EVMC_SPURIOUS_DRAGON},
      {"spurious_dragon", EVMC_SPURIOUS_DRAGON},
      {"byzantium", EVMC_BYZANTIUM},
      {"constantinople", EVMC_CONSTANTINOPLE},
      {"petersburg", EVMC_PETERSBURG},
      {"istanbul", EVMC_ISTANBUL},
      {"berlin", EVMC_BERLIN},
      {"london", EVMC_LONDON},
      {"paris", EVMC_PARIS},
      {"shanghai", EVMC_SHANGHAI},
      {"cancun", EVMC_CANCUN},
      {"prague", EVMC_PRAGUE},
      {"osaka", EVMC_OSAKA},
  };
  auto It = Revisions.find(Revision);
  return It == Revisions.end() ? zen::evm::DEFAULT_REVISION : It->second;
}

std::string normalizeTxHash(std::string TxHash) {
  for (char &C : TxHash) {
    C = static_cast<char>(std::tolower(static_cast<unsigned char>(C)));
  }
  return TxHash;
}

std::filesystem::path resolvePath(const std::filesystem::path &Path) {
  if (Path.is_absolute() && std::filesystem::exists(Path)) {
    return Path;
  }
  if (std::filesystem::exists(Path)) {
    return Path;
  }
  return std::filesystem::absolute(Path);
}

bool extractCommandOption(const rapidjson::Value &Command,
                          const std::string &Option, std::string &Value) {
  if (!Command.IsArray()) {
    return false;
  }
  for (rapidjson::SizeType I = 0; I + 1 < Command.Size(); ++I) {
    if (!Command[I].IsString() || !Command[I + 1].IsString()) {
      continue;
    }
    if (Option == Command[I].GetString()) {
      Value = Command[I + 1].GetString();
      return true;
    }
  }
  return false;
}

std::optional<PreparedReplay>
loadPrepared(const std::filesystem::path &PreparedPath,
             const std::filesystem::path &PreparedRoot) {
  std::ifstream File(PreparedPath);
  if (!File.is_open()) {
    return std::nullopt;
  }
  std::string Text((std::istreambuf_iterator<char>(File)),
                   std::istreambuf_iterator<char>());
  rapidjson::Document Doc;
  Doc.Parse(Text.data(), Text.size());
  if (Doc.HasParseError() || !Doc.IsObject()) {
    return std::nullopt;
  }

  PreparedReplay Replay;
  Replay.PreparedPath = PreparedPath;
  Replay.Dataset = getString(Doc, "dataset").value_or(
      PreparedPath.parent_path().parent_path().filename().string());
  Replay.TxHash = normalizeTxHash(
      getString(Doc, "tx_hash").value_or(PreparedPath.parent_path().string()));

  const auto BytecodePath = getString(Doc, "bytecode_path");
  const auto StatePath = getString(Doc, "state_path");
  if (!BytecodePath || !StatePath || !Doc.HasMember("command")) {
    return std::nullopt;
  }
  Replay.BytecodePath = resolvePath(*BytecodePath);
  Replay.StatePath = resolvePath(*StatePath);
  if (!std::filesystem::exists(Replay.BytecodePath)) {
    auto Relative = std::filesystem::relative(PreparedPath.parent_path(),
                                             PreparedRoot);
    auto Candidate = PreparedRoot / Relative / "bytecode.evm.hex";
    if (std::filesystem::exists(Candidate)) {
      Replay.BytecodePath = Candidate;
    }
  }
  if (!std::filesystem::exists(Replay.StatePath)) {
    auto Relative = std::filesystem::relative(PreparedPath.parent_path(),
                                             PreparedRoot);
    auto Candidate = PreparedRoot / Relative / "state.json";
    if (std::filesystem::exists(Candidate)) {
      Replay.StatePath = Candidate;
    }
  }

  const auto &Command = Doc["command"];
  std::string GasLimit;
  std::string Revision;
  extractCommandOption(Command, "--contract-address", Replay.ContractAddress);
  extractCommandOption(Command, "--sender", Replay.Sender);
  extractCommandOption(Command, "--calldata", Replay.CalldataHex);
  extractCommandOption(Command, "--gas-limit", GasLimit);
  extractCommandOption(Command, "--evm-revision", Revision);
  if (Replay.ContractAddress.empty() || Replay.Sender.empty() ||
      GasLimit.empty()) {
    return std::nullopt;
  }
  auto ParsedGas = parseU64(GasLimit);
  if (!ParsedGas) {
    return std::nullopt;
  }
  Replay.GasLimit = *ParsedGas;
  Replay.Revision = Revision.empty() ? zen::evm::DEFAULT_REVISION
                                     : parseRevision(Revision);
  return Replay;
}

std::vector<PreparedReplay>
loadPreparedReplays(const std::filesystem::path &PreparedRoot,
                    const std::set<std::string> &Datasets,
                    const std::set<std::string> &TxHashes, size_t Limit) {
  std::vector<PreparedReplay> Replays;
  for (auto It = std::filesystem::recursive_directory_iterator(PreparedRoot);
       It != std::filesystem::recursive_directory_iterator(); ++It) {
    if (!It->is_regular_file() || It->path().filename() != "prepared.json") {
      continue;
    }
    auto Replay = loadPrepared(It->path(), PreparedRoot);
    if (!Replay) {
      continue;
    }
    if (!Datasets.empty() && Datasets.count(Replay->Dataset) == 0) {
      continue;
    }
    if (!TxHashes.empty() && TxHashes.count(Replay->TxHash) == 0) {
      continue;
    }
    Replays.push_back(std::move(*Replay));
    if (Limit != 0 && Replays.size() >= Limit) {
      break;
    }
  }
  std::sort(Replays.begin(), Replays.end(), [](const auto &LHS,
                                               const auto &RHS) {
    return std::tie(LHS.Dataset, LHS.TxHash) < std::tie(RHS.Dataset, RHS.TxHash);
  });
  return Replays;
}

std::optional<std::vector<uint8_t>>
readEVMBytecode(const std::filesystem::path &Path) {
  std::ifstream File(Path);
  if (!File.is_open()) {
    return std::nullopt;
  }
  std::string Hex((std::istreambuf_iterator<char>(File)),
                  std::istreambuf_iterator<char>());
  zen::utils::trimString(Hex);
  return zen::utils::fromHex(Hex);
}

RunResult runReplay(Runtime &RT, zen::evm::ZenMockedEVMHost &Host,
                    const PreparedReplay &Replay,
                    const std::string &ModeName,
                    bool EnableMemorySpecialization) {
  RunResult Result;
  Result.Replay = Replay;
  Result.Mode = ModeName;

  auto Bytecode = readEVMBytecode(Replay.BytecodePath);
  if (!Bytecode) {
    Result.Error = "failed to read bytecode";
    return Result;
  }
  auto Calldata = zen::utils::fromHex(Replay.CalldataHex);
  if (!Calldata) {
    Result.Error = "failed to decode calldata";
    return Result;
  }

  Host.tx_context.tx_origin = zen::utils::parseAddress(Replay.Sender);
  if (!zen::utils::loadState(Host, Replay.StatePath.string(),
                             &RT.getStatistics())) {
    Result.Error = "failed to load state";
    return Result;
  }

  EVMMemorySpecializationProfile MemoryProfile;
  if (EnableMemorySpecialization) {
    MemoryProfile = deriveEVMMemorySpecializationProfileFromCallData(
        Calldata->data(), Calldata->size());
  }

  EVMCodeCacheLookupInfo LookupInfo;
  const auto CompileStart = zen::common::SteadyClock::now();
  auto ModRet = RT.getOrCompileCachedEVMModule(
      Bytecode->data(), Bytecode->size(), Replay.Revision, MemoryProfile,
      &LookupInfo);
  const auto CompileEnd = zen::common::SteadyClock::now();
  Result.LookupCompileMs = elapsedMs(CompileStart, CompileEnd);
  Result.CodeHash = LookupInfo.CodeHashHex;
  Result.CacheHit = LookupInfo.CacheHit;
  Result.FallbackToInterpreter = LookupInfo.FallbackToInterpreter;
  Result.HasJITCode = LookupInfo.HasJITCode;
  Result.CacheEntries = LookupInfo.EntryCount;
  Result.BytecodeSize = LookupInfo.BytecodeSize;
  Result.JITCodeSize = LookupInfo.JITCodeSize;
  if (!ModRet) {
    Result.Error = ModRet.getError().getFormattedMessage(false);
    return Result;
  }

  EVMModule *Mod = *ModRet;
  Isolation *Iso = RT.createManagedIsolation();
  if (!Iso) {
    Result.Error = "failed to create isolation";
    return Result;
  }

  auto InstRet = Iso->createEVMInstance(*Mod, Replay.GasLimit);
  if (!InstRet) {
    Result.Error = InstRet.getError().getFormattedMessage(false);
    RT.deleteManagedIsolation(Iso);
    return Result;
  }
  EVMInstance *Inst = *InstRet;
  Inst->setRevision(Replay.Revision);

  evmc_message Msg{};
  Msg.kind = EVMC_CALL;
  Msg.gas = static_cast<int64_t>(Replay.GasLimit);
  Msg.recipient = zen::utils::parseAddress(Replay.ContractAddress);
  Msg.sender = zen::utils::parseAddress(Replay.Sender);
  Msg.code_address = Msg.recipient;
  Msg.input_data = Calldata->data();
  Msg.input_size = Calldata->size();

  const int64_t IntrinsicGas = zen::utils::computeIntrinsicGas(
      Replay.Revision, Msg.kind, Msg.input_data, Msg.input_size);
  if (Msg.gas < IntrinsicGas) {
    Result.Error = "intrinsic gas exceeds gas limit";
    Iso->deleteEVMInstance(Inst);
    RT.deleteManagedIsolation(Iso);
    return Result;
  }
  Msg.gas -= IntrinsicGas;
  zen::utils::prewarmTransactionAccounts(
      Host, Replay.Revision, Msg.sender, Msg.recipient,
      Host.tx_context.block_coinbase);

  const uint64_t InternalHitsBefore = Host.getRuntimeCodeCacheInternalHits();
  const uint64_t InternalMissesBefore = Host.getRuntimeCodeCacheInternalMisses();
  evmc::Result ExecResult;
  const auto ExecStart = zen::common::SteadyClock::now();
  RT.callEVMMain(*Inst, Msg, ExecResult);
  const auto ExecEnd = zen::common::SteadyClock::now();
  Result.ExecutionMs = elapsedMs(ExecStart, ExecEnd);
  Result.InternalCacheHits =
      Host.getRuntimeCodeCacheInternalHits() - InternalHitsBefore;
  Result.InternalCacheMisses =
      Host.getRuntimeCodeCacheInternalMisses() - InternalMissesBefore;
  Result.ReturnCode = static_cast<int>(ExecResult.status_code);
  Result.Success = true;

  Iso->deleteEVMInstance(Inst);
  RT.deleteManagedIsolation(Iso);
  return Result;
}

void writeRunJson(std::ostream &OS, const RunResult &Run) {
  OS << "{"
     << "\"mode\":\"" << jsonEscape(Run.Mode) << "\","
     << "\"dataset\":\"" << jsonEscape(Run.Replay.Dataset) << "\","
     << "\"tx_hash\":\"" << jsonEscape(Run.Replay.TxHash) << "\","
     << "\"prepared_path\":\"" << jsonEscape(Run.Replay.PreparedPath.string())
     << "\","
     << "\"code_hash\":\"" << jsonEscape(Run.CodeHash) << "\","
     << "\"cache_hit\":" << (Run.CacheHit ? "true" : "false") << ","
     << "\"fallback_to_interpreter\":"
     << (Run.FallbackToInterpreter ? "true" : "false") << ","
     << "\"has_jit_code\":" << (Run.HasJITCode ? "true" : "false") << ","
     << "\"cache_entries\":" << Run.CacheEntries << ","
     << "\"bytecode_size\":" << Run.BytecodeSize << ","
     << "\"jit_code_size\":" << Run.JITCodeSize << ","
     << "\"internal_cache_hits\":" << Run.InternalCacheHits << ","
     << "\"internal_cache_misses\":" << Run.InternalCacheMisses << ","
     << "\"lookup_compile_ms\":" << Run.LookupCompileMs << ","
     << "\"execution_ms\":" << Run.ExecutionMs << ","
     << "\"returncode\":" << Run.ReturnCode << ","
     << "\"success\":" << (Run.Success ? "true" : "false") << ","
     << "\"error\":\"" << jsonEscape(Run.Error) << "\""
     << "}\n";
}

double meanOrZero(const std::vector<double> &Values) {
  if (Values.empty()) {
    return 0.0;
  }
  double Sum = 0.0;
  for (double Value : Values) {
    Sum += Value;
  }
  return Sum / static_cast<double>(Values.size());
}

double sumValues(const std::vector<double> &Values) {
  double Sum = 0.0;
  for (double Value : Values) {
    Sum += Value;
  }
  return Sum;
}

struct ModeCodeSummary {
  size_t Runs = 0;
  size_t Successes = 0;
  size_t Hits = 0;
  uint64_t InternalHits = 0;
  uint64_t InternalMisses = 0;
  size_t BytecodeSize = 0;
  size_t JITCodeSize = 0;
  bool FallbackToInterpreter = false;
  bool HasJITCode = false;
  std::vector<double> LookupCompileMs;
  std::vector<double> MissCompileMs;
  std::vector<double> ExecutionMs;
};

using SummaryMap = std::map<std::string, std::map<std::string, ModeCodeSummary>>;

SummaryMap buildSummaryMap(const std::vector<RunResult> &Runs) {
  SummaryMap ByModeAndCode;
  for (const auto &Run : Runs) {
    auto &Summary =
        ByModeAndCode[Run.Mode][Run.CodeHash.empty() ? "unknown" : Run.CodeHash];
    Summary.Runs++;
    Summary.Successes += Run.Success ? 1 : 0;
    Summary.Hits += Run.CacheHit ? 1 : 0;
    Summary.InternalHits += Run.InternalCacheHits;
    Summary.InternalMisses += Run.InternalCacheMisses;
    Summary.BytecodeSize = std::max(Summary.BytecodeSize, Run.BytecodeSize);
    Summary.JITCodeSize = std::max(Summary.JITCodeSize, Run.JITCodeSize);
    Summary.FallbackToInterpreter =
        Summary.FallbackToInterpreter || Run.FallbackToInterpreter;
    Summary.HasJITCode = Summary.HasJITCode || Run.HasJITCode;
    Summary.LookupCompileMs.push_back(Run.LookupCompileMs);
    if (!Run.CacheHit) {
      Summary.MissCompileMs.push_back(Run.LookupCompileMs);
    }
    if (Run.Success) {
      Summary.ExecutionMs.push_back(Run.ExecutionMs);
    }
  }
  return ByModeAndCode;
}

void writeSummary(const std::filesystem::path &OutputPath,
                  const std::vector<RunResult> &Runs) {
  auto ByModeAndCode = buildSummaryMap(Runs);
  size_t Hits = 0;
  size_t Successes = 0;
  for (const auto &Run : Runs) {
    Hits += Run.CacheHit ? 1 : 0;
    Successes += Run.Success ? 1 : 0;
  }

  std::ofstream OS(OutputPath);
  OS << "{\n";
  OS << "  \"runs\": " << Runs.size() << ",\n";
  OS << "  \"successes\": " << Successes << ",\n";
  OS << "  \"cache_hits\": " << Hits << ",\n";
  OS << "  \"cache_misses\": " << (Runs.size() - Hits) << ",\n";
  OS << "  \"modes\": [\n";
  bool FirstMode = true;
  for (const auto &[ModeName, ByCodeHash] : ByModeAndCode) {
    if (!FirstMode) {
      OS << ",\n";
    }
    FirstMode = false;
    OS << "    {\"mode\":\"" << jsonEscape(ModeName) << "\",\"code_hashes\":[";
    bool FirstCode = true;
    for (const auto &[CodeHash, Summary] : ByCodeHash) {
      if (!FirstCode) {
        OS << ",";
      }
      FirstCode = false;
      OS << "{\"code_hash\":\"" << jsonEscape(CodeHash)
         << "\",\"runs\":" << Summary.Runs << ",\"successes\":"
         << Summary.Successes << ",\"cache_hits\":" << Summary.Hits
         << ",\"cache_misses\":" << (Summary.Runs - Summary.Hits)
         << ",\"internal_cache_hits\":" << Summary.InternalHits
         << ",\"internal_cache_misses\":" << Summary.InternalMisses
         << ",\"bytecode_size\":" << Summary.BytecodeSize
         << ",\"jit_code_size\":" << Summary.JITCodeSize
         << ",\"fallback_to_interpreter\":"
         << (Summary.FallbackToInterpreter ? "true" : "false")
         << ",\"has_jit_code\":" << (Summary.HasJITCode ? "true" : "false")
         << ",\"lookup_compile_ms_sum\":"
         << sumValues(Summary.LookupCompileMs)
         << ",\"miss_compile_ms_sum\":" << sumValues(Summary.MissCompileMs)
         << ",\"execution_ms_mean\":" << meanOrZero(Summary.ExecutionMs)
         << ",\"execution_ms_sum\":" << sumValues(Summary.ExecutionMs)
         << "}";
    }
    OS << "]}";
  }
  OS << "\n  ],\n";

  OS << "  \"break_even_by_code_hash\": [\n";
  const auto InterpMode = ByModeAndCode.find("interpreter");
  const auto JitMode = ByModeAndCode.find("multipass");
  bool FirstBreakEven = true;
  if (InterpMode != ByModeAndCode.end() && JitMode != ByModeAndCode.end()) {
    const std::vector<int> Ns = {1, 8, 16, 32, 64, 128, 256};
    for (const auto &[CodeHash, JitSummary] : JitMode->second) {
      auto InterpIt = InterpMode->second.find(CodeHash);
      if (InterpIt == InterpMode->second.end()) {
        continue;
      }
      const auto &InterpSummary = InterpIt->second;
      const double CompileOnceMs = sumValues(JitSummary.MissCompileMs);
      const double JitExecMs = meanOrZero(JitSummary.ExecutionMs);
      const double InterpExecMs = meanOrZero(InterpSummary.ExecutionMs);
      const double SavingPerExec = InterpExecMs - JitExecMs;
      const double BreakEven =
          SavingPerExec > 0.0 ? CompileOnceMs / SavingPerExec : -1.0;
      if (!FirstBreakEven) {
        OS << ",\n";
      }
      FirstBreakEven = false;
      OS << "    {\"code_hash\":\"" << jsonEscape(CodeHash)
         << "\",\"jit_compile_once_ms\":" << CompileOnceMs
         << ",\"jit_exec_ms_mean\":" << JitExecMs
         << ",\"interp_exec_ms_mean\":" << InterpExecMs
         << ",\"saving_ms_per_exec\":" << SavingPerExec
         << ",\"break_even_execs\":" << BreakEven
         << ",\"speedups\":[";
      bool FirstN = true;
      for (int N : Ns) {
        const double JitTotal = CompileOnceMs + JitExecMs * N;
        const double InterpTotal = InterpExecMs * N;
        const double Speedup = JitTotal > 0.0 ? InterpTotal / JitTotal : 0.0;
        if (!FirstN) {
          OS << ",";
        }
        FirstN = false;
        OS << "{\"n\":" << N << ",\"jit_total_ms\":" << JitTotal
           << ",\"interp_total_ms\":" << InterpTotal
           << ",\"speedup\":" << Speedup << "}";
      }
      OS << "]}";
    }
  }
  OS << "\n  ]\n";
  OS << "}\n";
}

std::vector<RunResult> runBatch(const std::vector<PreparedReplay> &Replays,
                                const std::string &ModeName,
                                bool EnableMemorySpecialization,
                                bool EnableStatistics,
                                const std::filesystem::path &RunsPath) {
  RuntimeConfig Config;
  Config.Format = InputFormat::EVM;
  Config.EnableStatistics = EnableStatistics;
  if (ModeName == "interpreter") {
    Config.Mode = RunMode::InterpMode;
  } else if (ModeName == "multipass") {
    Config.Mode = RunMode::MultipassMode;
  } else {
    throw std::runtime_error("unsupported mode: " + ModeName);
  }

  auto Host = std::make_unique<zen::evm::ZenMockedEVMHost>();
  auto RT = Runtime::newEVMRuntime(Config, Host.get());
  if (!RT) {
    throw std::runtime_error("failed to create EVM runtime");
  }
  Host->setRuntime(RT.get());

  std::ofstream RunsJsonl(RunsPath);
  std::vector<RunResult> Results;
  Results.reserve(Replays.size());
  for (const auto &Replay : Replays) {
    RunResult Result =
        runReplay(*RT, *Host, Replay, ModeName, EnableMemorySpecialization);
    writeRunJson(RunsJsonl, Result);
    Results.push_back(std::move(Result));
  }
  return Results;
}

} // namespace

int main(int argc, char **argv) {
  std::string PreparedRoot = "data/tx_replay_prepare_200";
  std::string OutputDir = "data/tx_replay_benchmarks/code_cache_inprocess";
  std::vector<std::string> Datasets;
  std::vector<std::string> TxHashes;
  std::string Mode = "multipass";
  size_t Limit = 0;
  bool EnableMemorySpecialization = false;
  bool EnableStatistics = false;
  bool CompareJitInterpreter = false;

  CLI::App App{"DTVM EVM in-process codehash cache benchmark"};
  App.add_option("--prepared-root", PreparedRoot, "prepared transaction root");
  App.add_option("--output-dir", OutputDir, "output directory");
  App.add_option("--dataset", Datasets, "dataset filter");
  App.add_option("--tx-hash", TxHashes, "transaction hash filter");
  App.add_option("--limit", Limit, "maximum number of prepared transactions");
  App.add_option("--mode", Mode, "interpreter or multipass");
  App.add_flag("--compare-jit-interpreter", CompareJitInterpreter,
               "run interpreter and multipass in one invocation");
  App.add_flag("--enable-memory-specialization", EnableMemorySpecialization,
               "derive memory specialization from calldata");
  App.add_flag("--enable-statistics", EnableStatistics,
               "enable DTVM statistics while replaying");
  CLI11_PARSE(App, argc, argv);

  if (!CompareJitInterpreter && Mode != "interpreter" && Mode != "multipass") {
    std::cerr << "unsupported mode: " << Mode << "\n";
    return EXIT_FAILURE;
  }

  std::set<std::string> DatasetFilter(Datasets.begin(), Datasets.end());
  std::set<std::string> TxFilter;
  for (auto TxHash : TxHashes) {
    TxFilter.insert(normalizeTxHash(std::move(TxHash)));
  }

  auto Replays = loadPreparedReplays(PreparedRoot, DatasetFilter, TxFilter,
                                     Limit);
  std::filesystem::create_directories(OutputDir);
  std::vector<RunResult> Results;

  try {
    if (CompareJitInterpreter) {
      auto InterpResults = runBatch(
          Replays, "interpreter", EnableMemorySpecialization, EnableStatistics,
          std::filesystem::path(OutputDir) / "runs_interpreter.jsonl");
      auto JitResults = runBatch(
          Replays, "multipass", EnableMemorySpecialization, EnableStatistics,
          std::filesystem::path(OutputDir) / "runs_multipass.jsonl");
      Results.reserve(InterpResults.size() + JitResults.size());
      Results.insert(Results.end(), std::make_move_iterator(InterpResults.begin()),
                     std::make_move_iterator(InterpResults.end()));
      Results.insert(Results.end(), std::make_move_iterator(JitResults.begin()),
                     std::make_move_iterator(JitResults.end()));
    } else {
      Results = runBatch(Replays, Mode, EnableMemorySpecialization,
                         EnableStatistics,
                         std::filesystem::path(OutputDir) / "runs.jsonl");
    }
  } catch (const std::exception &E) {
    std::cerr << E.what() << "\n";
    return EXIT_FAILURE;
  }

  writeSummary(std::filesystem::path(OutputDir) / "summary.json", Results);
  return EXIT_SUCCESS;
}
