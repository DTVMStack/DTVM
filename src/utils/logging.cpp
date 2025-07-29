// Copyright (C) 2021-2023 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "utils/logging.h"
#include <unistd.h>

#ifdef ZEN_ENABLE_SPDLOG
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#define SPDLOG_LEVEL_NAMES                                                     \
  { "trace", "debug", "info", "warn", "error", "fatal", "off" }
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#else
#include <chrono>
#endif // ZEN_ENABLE_SPDLOG

namespace zen::utils {

#ifdef ZEN_ENABLE_SPDLOG
inline spdlog::level::level_enum getSpdLogLevel(LoggerLevel Level) {
  switch (Level) {
  case LoggerLevel::Trace:
    return spdlog::level::level_enum::trace;
  case LoggerLevel::Debug:
    return spdlog::level::level_enum::debug;
  case LoggerLevel::Info:
    return spdlog::level::level_enum::info;
  case LoggerLevel::Warn:
    return spdlog::level::level_enum::warn;
  case LoggerLevel::Error:
    return spdlog::level::level_enum::err;
  case LoggerLevel::Fatal:
    return spdlog::level::level_enum::critical;
  case LoggerLevel::Off:
    return spdlog::level::level_enum::off;
  default:
    return spdlog::level::level_enum::err;
  }
}

class SpdLoggerImpl : public ILogger {
public:
  SpdLoggerImpl(std::shared_ptr<spdlog::logger> SpdLogger)
      : Logger(SpdLogger) {}
  SpdLoggerImpl(const SpdLoggerImpl &&Other) : Logger(Other.Logger) {}
  ~SpdLoggerImpl() override = default;

  void trace(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::trace,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }
  void debug(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::debug,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }
  void info(const std::string &Msg, const char *Filename, int Line,
            const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::info,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }
  void warn(const std::string &Msg, const char *Filename, int Line,
            const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::warn,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }
  void error(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::err,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }
  void fatal(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    Logger->log(spdlog::source_loc{Filename, Line, FuncName},
                spdlog::level::critical,
                spdlog::string_view_t(Msg.data(), Msg.length()));
  }

private:
  std::shared_ptr<spdlog::logger> Logger;
};
#else
class SimpleLoggerImpl : public ILogger {
public:
  SimpleLoggerImpl(LoggerLevel Level) : ActiveLevel(Level) {}

  SimpleLoggerImpl(LoggerLevel Level, const std::string &Filename)
      : ActiveLevel(Level) {
    TargetFile = ::fopen(Filename.c_str(), "a");
    if (!TargetFile) {
      TargetFile = os_sdtout;
      ::fprintf(os_stderr,
                "failed to open log file %s, fallback to console logger\n",
                Filename.c_str());
    }
  }

  ~SimpleLoggerImpl() override {
    if (TargetFile && TargetFile != os_sdtout) {
      ::fclose(TargetFile);
    }
  }

  void trace(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    if (LoggerLevel::Trace < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Trace);
  }
  void debug(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    if (LoggerLevel::Debug < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Debug);
  }
  void info(const std::string &Msg, const char *Filename, int Line,
            const char *FuncName) override {
    if (LoggerLevel::Info < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Info);
  }
  void warn(const std::string &Msg, const char *Filename, int Line,
            const char *FuncName) override {
    if (LoggerLevel::Warn < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Warn);
  }
  void error(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    if (LoggerLevel::Error < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Error);
  }
  void fatal(const std::string &Msg, const char *Filename, int Line,
             const char *FuncName) override {
    if (LoggerLevel::Fatal < ActiveLevel) {
      return;
    }
    log(Msg, Filename, Line, FuncName, LoggerLevel::Fatal);
  }

private:
  static void getCurrentTime(char *Buf, size_t BufSize) {
    ZEN_ASSERT(BufSize >= 24);
    using namespace common::chrono;
    SystemClock::time_point NowTimePoint = SystemClock::now();
    time_t NowTime = SystemClock::to_time_t(NowTimePoint);
    std::tm *NowLocalTime = ::localtime(&NowTime);
    auto MsDur = duration_cast<milliseconds>(NowTimePoint.time_since_epoch());
    uint64_t NumMs = static_cast<uint64_t>(MsDur.count()) % 1000;
    std::strftime(Buf, BufSize, "%Y-%m-%d %H:%M:%S.", NowLocalTime);
    constexpr size_t HalfWidth = 20;
    std::snprintf(Buf + HalfWidth, BufSize - HalfWidth, "%03ld", NumMs);
  }

  static const char *getLevelStr(LoggerLevel Level) {
    switch (Level) {
    case LoggerLevel::Trace:
      return "trace";
    case LoggerLevel::Debug:
      return "debug";
    case LoggerLevel::Info:
      return "info";
    case LoggerLevel::Warn:
      return "warn";
    case LoggerLevel::Error:
      return "error";
    case LoggerLevel::Fatal:
      return "fatal";
    default:
      ZEN_UNREACHABLE();
    }
  }

  static const char *getANSIColorStr(LoggerLevel Level) {
    switch (Level) {
    case LoggerLevel::Trace:
      return ColorWhite;
    case LoggerLevel::Debug:
      return ColorCyan;
    case LoggerLevel::Info:
      return ColorGreen;
    case LoggerLevel::Warn:
      return ColorYellowBold;
    case LoggerLevel::Error:
      return ColorRedBold;
    case LoggerLevel::Fatal:
      return ColorBoldOnRed;
    default:
      ZEN_UNREACHABLE();
    }
  }

  // Determine if the terminal supports colors
  // Source: https://github.com/agauniyal/rang/
  static bool isColorTerminal() {
    static constexpr std::array<const char *, 14> Terms = {
        {"ansi", "color", "console", "cygwin", "gnome", "konsole", "kterm",
         "linux", "msys", "putty", "rxvt", "screen", "vt100", "xterm"}};

    const char *ActualTerm = ::getenv("TERM");
    if (!ActualTerm) {
      return false;
    }

    static const bool Result =
        std::any_of(std::begin(Terms), std::end(Terms), [&](const char *Term) {
          return std::strstr(ActualTerm, Term) != nullptr;
        });
    return Result;
  }

  // Detrmine if the terminal attached
  // Source: https://github.com/agauniyal/rang/
  static bool isTerminal(common::STDFile *F) {
    return ::isatty(::fileno(F)) != 0;
  }

  void log(const std::string &Msg, const char *Filename, int Line,
           [[maybe_unused]] const char *FuncName, LoggerLevel Level) {
    char TimeBuf[24];
    getCurrentTime(TimeBuf, sizeof(TimeBuf));
    bool Colored = isTerminal(TargetFile) && isColorTerminal();
    const char *ColorStr = Colored ? getANSIColorStr(Level) : "";
    const char *ColorResetStr = Colored ? ColorReset : "";
    const char *LevelStr = getLevelStr(Level);
    const char *LastSlash = std::strrchr(Filename, '/');
    const char *BaseFilename = LastSlash ? LastSlash + 1 : Filename;
    common::LockGuard<common::Mutex> Guard(Mtx);
    ::fprintf(TargetFile, "[%s] [%s%s%s] [%s:%d] %s\n", TimeBuf, ColorStr,
              LevelStr, ColorResetStr, BaseFilename, Line, Msg.data());
  }

  static constexpr const char *ColorWhite = "\033[37m";
  static constexpr const char *ColorCyan = "\033[36m";
  static constexpr const char *ColorGreen = "\033[32m";
  static constexpr const char *ColorYellowBold = "\033[33m\033[1m";
  static constexpr const char *ColorRedBold = "\033[31m\033[1m";
  static constexpr const char *ColorBoldOnRed = "\033[1m\033[41m";
  static constexpr const char *ColorReset = "\033[0m";

  common::Mutex Mtx;
  LoggerLevel ActiveLevel;
  common::STDFile *TargetFile = ::os_sdtout;
};
#endif // ZEN_ENABLE_SPDLOG

std::shared_ptr<ILogger> createConsoleLogger(const std::string &LoggerName,
                                             LoggerLevel Level) {
#ifdef ZEN_ENABLE_SPDLOG
  auto LoggerImpl = spdlog::stdout_color_mt(LoggerName);
  LoggerImpl->set_level(getSpdLogLevel(Level));
  LoggerImpl->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%s:%#] %v");
  return std::make_shared<SpdLoggerImpl>(LoggerImpl);
#else
  return std::make_shared<SimpleLoggerImpl>(Level);
#endif // ZEN_ENABLE_SPDLOG
}

std::shared_ptr<ILogger> createAsyncFileLogger(const std::string &LoggerName,
                                               const std::string &Filename,
                                               LoggerLevel Level) {
#ifdef ZEN_ENABLE_SPDLOG
  auto LoggerImpl =
      spdlog::basic_logger_mt<spdlog::async_factory>(LoggerName, Filename);
  LoggerImpl->set_level(getSpdLogLevel(Level));
  LoggerImpl->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%s:%#] %v");
  return std::make_shared<SpdLoggerImpl>(LoggerImpl);
#else
  return std::make_shared<SimpleLoggerImpl>(Level, Filename);
#endif // ZEN_ENABLE_SPDLOG
}

#ifdef ZEN_ENABLE_SPDLOG
std::shared_ptr<ILogger>
createSpdLogger(std::shared_ptr<spdlog::logger> SpdLogger) {
  return std::make_shared<SpdLoggerImpl>(SpdLogger);
}
#endif // ZEN_ENABLE_SPDLOG

} // namespace zen::utils
