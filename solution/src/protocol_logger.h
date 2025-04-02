#pragma once
#include <iostream>
#include <string> // Include for std::string usage if needed later

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

// Define COMPILE_TIME_LOG_LEVEL, default to INFO if not set by build system
#ifndef COMPILE_TIME_LOG_LEVEL
#define COMPILE_TIME_LOG_LEVEL static_cast<int>(LogLevel::INFO)
#endif

// Convert compile-time int back to LogLevel enum for convenience
constexpr LogLevel CT_LOG_LEVEL = static_cast<LogLevel>(COMPILE_TIME_LOG_LEVEL);

class ProtocolLogger {
public:
  // Log function remains, but check is now implicit via macros
  template <typename... Args>
  static void log(LogLevel level, const char *file, int line, Args... args) {
    // This check is technically redundant if macros are used correctly,
    // but kept as a safeguard or if log() is called directly.
    if (static_cast<int>(level) <= COMPILE_TIME_LOG_LEVEL) {
      std::cerr << "[" << levelToString(level) << "] " << file << ":" << line
                << " - ";
      (std::cerr << ... << args);
      std::cerr << std::endl;
    }
  }

  // Keep levelToString public for potential use (e.g., logging the compile-time
  // level)
  static const char *levelToString(LogLevel level) {
    switch (level) {
    case LogLevel::ERROR:
      return "ERROR";
    case LogLevel::WARN:
      return "WARN ";
    case LogLevel::INFO:
      return "INFO ";
    case LogLevel::DEBUG:
      return "DEBUG";
    case LogLevel::TRACE:
      return "TRACE";
    default:
      return "NONE ";
    }
  }

private:
  // No static currentLevel needed anymore
  // No setGlobalLogLevel needed anymore
  // No getLevel needed anymore
};

// Logging macros - Conditionally compile the log call
#define LOG_IMPL(level, ...)                                                   \
  do {                                                                         \
    if (static_cast<int>(level) <= COMPILE_TIME_LOG_LEVEL) {                   \
      ProtocolLogger::log(level, __FILE__, __LINE__, __VA_ARGS__);             \
    }                                                                          \
  } while (0)

#define LOG_ERROR(...) LOG_IMPL(LogLevel::ERROR, __VA_ARGS__)
#define LOG_WARN(...) LOG_IMPL(LogLevel::WARN, __VA_ARGS__)
#define LOG_INFO(...) LOG_IMPL(LogLevel::INFO, __VA_ARGS__)
#define LOG_DEBUG(...) LOG_IMPL(LogLevel::DEBUG, __VA_ARGS__)
#define LOG_TRACE(...) LOG_IMPL(LogLevel::TRACE, __VA_ARGS__)

// Macro to get the compile-time log level string
#define COMPILE_TIME_LOG_LEVEL_STR ProtocolLogger::levelToString(CT_LOG_LEVEL)