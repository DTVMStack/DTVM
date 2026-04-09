// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef ZEN_UTILS_LOGGING_H
#define ZEN_UTILS_LOGGING_H

#include "common/defines.h"
#include "platform/platform.h"
#include <cstdio>
#include <memory>
#include <string>

#ifdef ZEN_ENABLE_SPDLOG
namespace spdlog {
class logger;
} // namespace spdlog
#endif // ZEN_ENABLE_SPDLOG

namespace zen::utils {

enum class LoggerLevel {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
  Fatal,
  Off,
};

class ILogger {
public:
  virtual ~ILogger() = default;
  virtual void trace(const std::string &Msg, const char *Filename, int Line,
                     const char *FuncName) = 0;
  virtual void debug(const std::string &Msg, const char *Filename, int Line,
                     const char *FuncName) = 0;
  virtual void info(const std::string &Msg, const char *Filename, int Line,
                    const char *FuncName) = 0;
  virtual void warn(const std::string &Msg, const char *Filename, int Line,
                    const char *FuncName) = 0;
  virtual void error(const std::string &Msg, const char *Filename, int Line,
                     const char *FuncName) = 0;
  virtual void fatal(const std::string &Msg, const char *Filename, int Line,
                     const char *FuncName) = 0;
};

class Logging final {
public:
  static Logging &getInstance() {
    static Logging L;
    return L;
  }

  std::shared_ptr<ILogger> getLogger() const { return Logger; }

  void setLogger(std::shared_ptr<ILogger> NewLogger) {
    common::LockGuard<common::Mutex> Guard(Mtx);
    Logger = std::move(NewLogger);
  }

private:
  Logging() = default;

  ~Logging() = default;

  common::Mutex Mtx;
  std::shared_ptr<ILogger> Logger;
};

// Used by command line tools
std::shared_ptr<ILogger> createConsoleLogger(const std::string &LoggerName,
                                             LoggerLevel Level);

// Used by command line tools
std::shared_ptr<ILogger> createAsyncFileLogger(const std::string &LoggerName,
                                               const std::string &Filename,
                                               LoggerLevel Level);

#ifdef ZEN_ENABLE_SPDLOG
std::shared_ptr<ILogger>
createSpdLogger(std::shared_ptr<spdlog::logger> SpdLogger);
#endif // ZEN_ENABLE_SPDLOG

template <typename... ArgsTypes>
inline std::string fmtString(const char *Format, ArgsTypes... Args) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security"
  int Size = std::snprintf(nullptr, 0, Format, Args...);
  if (Size < 0) {
    ZEN_ABORT();
  }
  std::string Formatted(Size + 1, '\0');
  std::snprintf(&Formatted[0], Size + 1, Format, Args...);
#pragma GCC diagnostic pop
  Formatted.pop_back();
  return Formatted;
}

} // namespace zen::utils

#define ZEN_LOG_CALL(LOG_IMPL, FORMAT, ...)                                    \
  do {                                                                         \
    auto Logger = zen::utils::Logging::getInstance().getLogger();              \
    if (!Logger) {                                                             \
      break;                                                                   \
    }                                                                          \
    Logger->LOG_IMPL(zen::utils::fmtString(FORMAT, ##__VA_ARGS__), __FILE__,   \
                     __LINE__, __FUNCTION__);                                  \
  } while (false)

#define ZEN_LOG_TRACE(FORMAT, ...) ZEN_LOG_CALL(trace, FORMAT, ##__VA_ARGS__)

#define ZEN_LOG_DEBUG(FORMAT, ...) ZEN_LOG_CALL(debug, FORMAT, ##__VA_ARGS__)

#define ZEN_LOG_INFO(FORMAT, ...) ZEN_LOG_CALL(info, FORMAT, ##__VA_ARGS__)

#define ZEN_LOG_WARN(FORMAT, ...) ZEN_LOG_CALL(warn, FORMAT, ##__VA_ARGS__)

#define ZEN_LOG_ERROR(FORMAT, ...) ZEN_LOG_CALL(error, FORMAT, ##__VA_ARGS__)

#define ZEN_LOG_FATAL(FORMAT, ...) ZEN_LOG_CALL(fatal, FORMAT, ##__VA_ARGS__)

#endif // ZEN_UTILS_LOGGING_H
