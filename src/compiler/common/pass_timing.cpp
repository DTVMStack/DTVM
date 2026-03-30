// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "compiler/common/pass_timing.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>

namespace COMPILER {

namespace {

constexpr const char *COMPILER_PASS_TIMING_PATH_ENV =
    "DTVM_COMPILER_PASS_TIMING_JSON";

double durationToMs(std::chrono::steady_clock::duration Duration) {
  return std::chrono::duration<double, std::milli>(Duration).count();
}

} // namespace

CompilerPassTimingSink &CompilerPassTimingSink::get() {
  static CompilerPassTimingSink Sink;
  return Sink;
}

CompilerPassTimingSink::CompilerPassTimingSink()
    : Enabled(std::getenv(COMPILER_PASS_TIMING_PATH_ENV) != nullptr),
      OutputPath(Enabled ? std::getenv(COMPILER_PASS_TIMING_PATH_ENV) : "") {}

void CompilerPassTimingSink::appendRecord(CompilerPassTimingRecord Record) {
  if (!Enabled) {
    return;
  }

  std::lock_guard<std::mutex> Lock(Mutex);
  Records.emplace_back(std::move(Record));
}

CompilerPassTimingSink::~CompilerPassTimingSink() {
  if (!Enabled || Records.empty()) {
    return;
  }
  std::lock_guard<std::mutex> Lock(Mutex);
  writeReportLocked();
}

void CompilerPassTimingSink::writeReportLocked() const {
  const std::string TempPath = OutputPath + ".tmp";
  std::ofstream Out(TempPath, std::ios::out | std::ios::trunc);
  if (!Out.is_open()) {
    return;
  }

  Out << std::fixed << std::setprecision(6);
  Out << "{\n  \"records\": [\n";
  for (size_t RecordIdx = 0; RecordIdx < Records.size(); ++RecordIdx) {
    const auto &Record = Records[RecordIdx];
    Out << "    {\n";
    Out << "      \"pipeline\": \"" << escapeJson(Record.Pipeline) << "\",\n";
    Out << "      \"func_idx\": " << Record.FuncIdx << ",\n";
    Out << "      \"total_time_ms\": " << Record.TotalTimeMs << ",\n";
    Out << "      \"phases\": [\n";
    for (size_t EntryIdx = 0; EntryIdx < Record.Entries.size(); ++EntryIdx) {
      const auto &Entry = Record.Entries[EntryIdx];
      Out << "        {\"name\": \"" << escapeJson(Entry.Name)
          << "\", \"time_ms\": " << Entry.TimeMs << "}";
      if (EntryIdx + 1 != Record.Entries.size()) {
        Out << ",";
      }
      Out << "\n";
    }
    Out << "      ]\n";
    Out << "    }";
    if (RecordIdx + 1 != Records.size()) {
      Out << ",";
    }
    Out << "\n";
  }
  Out << "  ]\n}\n";
  Out.close();

  std::rename(TempPath.c_str(), OutputPath.c_str());
}

std::string CompilerPassTimingSink::escapeJson(const std::string &Value) {
  std::string Escaped;
  Escaped.reserve(Value.size());
  for (char Ch : Value) {
    switch (Ch) {
    case '\\':
      Escaped += "\\\\";
      break;
    case '"':
      Escaped += "\\\"";
      break;
    case '\n':
      Escaped += "\\n";
      break;
    case '\r':
      Escaped += "\\r";
      break;
    case '\t':
      Escaped += "\\t";
      break;
    default:
      Escaped += Ch;
      break;
    }
  }
  return Escaped;
}

CompilerPassTimingSession::CompilerPassTimingSession(std::string PipelineName,
                                                     uint32_t FuncIdx)
    : Enabled(CompilerPassTimingSink::get().isEnabled()),
      StartTime(std::chrono::steady_clock::now()),
      Record{std::move(PipelineName), FuncIdx, {}, 0.0} {}

void CompilerPassTimingSession::addEntry(std::string Name, double TimeMs) {
  if (!Enabled) {
    return;
  }

  Record.Entries.push_back({std::move(Name), TimeMs});
}

void CompilerPassTimingSession::flush() {
  if (!Enabled) {
    return;
  }

  Record.TotalTimeMs =
      durationToMs(std::chrono::steady_clock::now() - StartTime);
  CompilerPassTimingSink::get().appendRecord(std::move(Record));
  Record = {};
}

ScopedCompilerPassTimer::ScopedCompilerPassTimer(
    CompilerPassTimingSession *Session, const char *Name)
    : Session(Session), Name(Name),
      StartTime(Session && Session->isEnabled()
                    ? std::chrono::steady_clock::now()
                    : std::chrono::steady_clock::time_point{}) {}

ScopedCompilerPassTimer::~ScopedCompilerPassTimer() {
  if (!Session || !Session->isEnabled()) {
    return;
  }

  Session->addEntry(Name,
                    durationToMs(std::chrono::steady_clock::now() - StartTime));
}

} // namespace COMPILER
