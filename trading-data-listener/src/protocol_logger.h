#pragma once
#include <iostream>
#include <sstream> // Include for std::ostringstream
#include <string>  // Include for std::string usage if needed later

// Logging levels
enum class LogLevel : int { // Use int for easier compile-time definition
                            // passing
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
  TRACE = 5
};

// Define COMPILE_TIME_LOG_LEVEL, default to INFO (3) if not set by build system
#ifndef COMPILE_TIME_LOG_LEVEL
#define COMPILE_TIME_LOG_LEVEL 3
#endif

// Convert compile-time int back to LogLevel enum for convenience
constexpr LogLevel CT_LOG_LEVEL = static_cast<LogLevel>(COMPILE_TIME_LOG_LEVEL);

class ProtocolLogger {
public:
  template <typename... Args> static void log(LogLevel level, Args... args) {
    // Compile-time check remains the primary optimization
    if (static_cast<int>(level) <= COMPILE_TIME_LOG_LEVEL) {
      std::ostringstream oss;
      oss << "[" << levelToString(level) << "] ";
      // Use fold expression to append all arguments to the ostringstream
      (oss << ... << args);
      oss << '\n'; // Add newline

      // Write the entire formatted string to std::clog in one go
      std::clog << oss.str();
    }
  }

  // Keep levelToString public for potential use (e.g., logging the compile-time
  // level)
  static const char *levelToString(LogLevel level) {
    switch (level) {
    case LogLevel::ERROR:
      return "ERROR";
    case LogLevel::WARN:
      return "WARN";
    case LogLevel::INFO:
      return "INFO";
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::TRACE:
      return "TRACE";
    default:
      return "NONE";
    }
  }

private:
};

// Logging macros - Conditionally compile the log call
#define LOG_IMPL(level, ...)                                                   \
  do {                                                                         \
    if (static_cast<int>(level) <= COMPILE_TIME_LOG_LEVEL) {                   \
      ProtocolLogger::log(level, __VA_ARGS__);                                 \
    }                                                                          \
  } while (0)

#define LOG_ERROR(...) LOG_IMPL(LogLevel::ERROR, __VA_ARGS__)
#define LOG_WARN(...) LOG_IMPL(LogLevel::WARN, __VA_ARGS__)
#define LOG_INFO(...) LOG_IMPL(LogLevel::INFO, __VA_ARGS__)

#if COMPILE_TIME_LOG_LEVEL >= 4
#define LOG_DEBUG(...) LOG_IMPL(LogLevel::DEBUG, __VA_ARGS__)
#else
#define LOG_DEBUG(...)                                                         \
  do {                                                                         \
  } while (0)
#endif

#if COMPILE_TIME_LOG_LEVEL >= 5
#define LOG_TRACE(...) LOG_IMPL(LogLevel::TRACE, __VA_ARGS__)
#else
#define LOG_TRACE(...)                                                         \
  do {                                                                         \
  } while (0)
#endif

// Macro to get the compile-time log level string
#define COMPILE_TIME_LOG_LEVEL_STR ProtocolLogger::levelToString(CT_LOG_LEVEL)