#pragma once
#include <iostream>
#include <sstream> // Include for std::ostringstream
#include <string>  // Include for std::string usage if needed later

// Logging levels
enum class LogLevel : int {
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

// Default frame threshold - start logging immediately
#ifndef LOG_FRAME_THRESHOLD
#define LOG_FRAME_THRESHOLD 0
#endif

// Convert compile-time int back to LogLevel enum for convenience
constexpr LogLevel CT_LOG_LEVEL = static_cast<LogLevel>(COMPILE_TIME_LOG_LEVEL);

class ProtocolLogger {
public:
  // Static frame counter and threshold
  inline static int currentFrame = 0;
  inline static int frameThreshold = LOG_FRAME_THRESHOLD;

  // Update the current frame
  static void setCurrentFrame(int frame) { currentFrame = frame; }

  // Set the frame threshold (after which DEBUG/TRACE logging begins)
  static void setFrameThreshold(int threshold) { frameThreshold = threshold; }

  template <typename... Args> static void log(LogLevel level, Args... args) {
    // Runtime threshold: suppress all logs before threshold frame
    if (currentFrame < frameThreshold) {
      return;
    }
    // Compile-time severity check
    if (static_cast<int>(level) > COMPILE_TIME_LOG_LEVEL) {
      return;
    }
    // Construct and emit log message
    std::ostringstream oss;
    oss << "[" << levelToString(level) << "][Frame " << currentFrame << "] ";
    (oss << ... << args);
    oss << '\n';
    std::clog << oss.str();
  }

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
};

// Logging macros
#define LOG_ERROR(...) ProtocolLogger::log(LogLevel::ERROR, __VA_ARGS__)
#define LOG_WARN(...) ProtocolLogger::log(LogLevel::WARN, __VA_ARGS__)
#define LOG_INFO(...) ProtocolLogger::log(LogLevel::INFO, __VA_ARGS__)

#if COMPILE_TIME_LOG_LEVEL >= 4
#define LOG_DEBUG(...) ProtocolLogger::log(LogLevel::DEBUG, __VA_ARGS__)
#else
#define LOG_DEBUG(...)                                                         \
  do {                                                                         \
  } while (0)
#endif

#if COMPILE_TIME_LOG_LEVEL >= 5
#define LOG_TRACE(...) ProtocolLogger::log(LogLevel::TRACE, __VA_ARGS__)
#else
#define LOG_TRACE(...)                                                         \
  do {                                                                         \
  } while (0)
#endif

// Macros to manage frame threshold
#define SET_LOG_FRAME(frame) ProtocolLogger::setCurrentFrame(frame)
#define SET_LOG_FRAME_THRESHOLD(threshold)                                     \
  ProtocolLogger::setFrameThreshold(threshold)

// Macro to get compile-time log level string
#define COMPILE_TIME_LOG_LEVEL_STR ProtocolLogger::levelToString(CT_LOG_LEVEL)