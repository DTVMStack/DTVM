// Copyright (C) 2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_COMPILER_COMMON_PASS_TIMING_H
#define ZEN_COMPILER_COMMON_PASS_TIMING_H

#include "compiler/common/common_defs.h"

#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace COMPILER {

struct CompilerPassTimingEntry {
  std::string Name;
  double TimeMs = 0.0;
};

struct CompilerPassTimingRecord {
  std::string Pipeline;
  uint32_t FuncIdx = 0;
  std::vector<CompilerPassTimingEntry> Entries;
  double TotalTimeMs = 0.0;
};

class CompilerPassTimingSink final : public NonCopyable {
public:
  static CompilerPassTimingSink &get();

  bool isEnabled() const { return Enabled; }

  void appendRecord(CompilerPassTimingRecord Record);

private:
  CompilerPassTimingSink();
  ~CompilerPassTimingSink();

  void writeReportLocked() const;
  static std::string escapeJson(const std::string &Value);

  const bool Enabled = false;
  const std::string OutputPath;
  mutable std::mutex Mutex;
  std::vector<CompilerPassTimingRecord> Records;
};

class CompilerPassTimingSession final : public NonCopyable {
public:
  CompilerPassTimingSession(std::string PipelineName, uint32_t FuncIdx);

  bool isEnabled() const { return Enabled; }

  void addEntry(std::string Name, double TimeMs);
  void flush();

private:
  const bool Enabled = false;
  const std::chrono::steady_clock::time_point StartTime;
  CompilerPassTimingRecord Record;
};

class ScopedCompilerPassTimer final : public NonCopyable {
public:
  ScopedCompilerPassTimer(CompilerPassTimingSession *Session, const char *Name);

  ~ScopedCompilerPassTimer();

private:
  CompilerPassTimingSession *Session = nullptr;
  const char *Name = nullptr;
  std::chrono::steady_clock::time_point StartTime;
};

} // namespace COMPILER

#endif // ZEN_COMPILER_COMMON_PASS_TIMING_H
