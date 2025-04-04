#!/bin/bash
# Local build script for the latency solution
# Usage: ./build.sh [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>] [--build-type <TYPE>] [--enable-asan | --disable-asan]

set -euo pipefail

# Default values
USE_LIGHTPCAPNG=ON
LOG_LEVEL="NONE" # Default log level
BUILD_TYPE="Debug" # Default build type
ENABLE_ASAN="ON" # Default ASan state

# --- Argument Parsing ---
VALID_LOG_LEVELS=("NONE" "ERROR" "WARN" "INFO" "DEBUG" "TRACE")
VALID_BUILD_TYPES=("Debug" "Release")

function is_valid_log_level() {
  local level="$1"
  for valid_level in "${VALID_LOG_LEVELS[@]}"; do
    if [[ "$level" == "$valid_level" ]]; then
      return 0 # Valid
    fi
  done
  return 1 # Invalid
}

function is_valid_build_type() {
  local type="$1"
  for valid_type in "${VALID_BUILD_TYPES[@]}"; do
    if [[ "$type" == "$valid_type" ]]; then
      return 0 # Valid
    fi
  done
  return 1 # Invalid
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --with-lightpcapng)
      USE_LIGHTPCAPNG=ON
      shift
      ;;
    --no-lightpcapng)
      USE_LIGHTPCAPNG=OFF
      shift
      ;;
    --log-level)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
          if is_valid_log_level "$2"; then
              LOG_LEVEL="$2"
              shift 2
          else
              echo "Error: Invalid log level '$2'. Must be one of: ${VALID_LOG_LEVELS[*]}"
              exit 1
          fi
      else
        echo "Error: --log-level requires an argument."
        echo "Usage: $0 [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>] [--build-type <TYPE>] [--enable-asan | --disable-asan]"
        exit 1
      fi
      ;;
    --build-type)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
          if is_valid_build_type "$2"; then
              BUILD_TYPE="$2"
              shift 2
          else
              echo "Error: Invalid build type '$2'. Must be one of: ${VALID_BUILD_TYPES[*]}"
              exit 1
          fi
      else
        echo "Error: --build-type requires an argument."
        echo "Usage: $0 [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>] [--build-type <TYPE>] [--enable-asan | --disable-asan]"
        exit 1
      fi
      ;;
    --enable-asan)
      ENABLE_ASAN="ON"
      shift
      ;;
    --disable-asan)
      ENABLE_ASAN="OFF"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>] [--build-type <TYPE>] [--enable-asan | --disable-asan]"
      exit 1
      ;;
  esac
done

# --- Check for ccache ---
CMAKE_PREFIX_CMD=""
# --- Local Build ---
echo "=== Building solution locally ==="
SOLUTION_DIR="$(pwd)/solution"
BUILD_DIR="${SOLUTION_DIR}/build_${BUILD_TYPE,,}" # Create separate build dirs for Debug/Release
BIN_DIR="${BUILD_DIR}/bin"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "--- Running CMake ---"
# Pass the absolute path to the source directory to CMake
# Use ccache if available
${CMAKE_PREFIX_CMD} cmake "${SOLUTION_DIR}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG} \
    -DCMAKE_LOG_LEVEL=${LOG_LEVEL} \
    -DENABLE_ASAN=${ENABLE_ASAN}

echo "--- Building with Make ---"
# Use nproc if available, otherwise default to 1 core
NPROC=$(nproc 2>/dev/null || echo 1)
# Use ccache if available
${CMAKE_PREFIX_CMD} make -j${NPROC}

# Binaries are placed in ${BIN_DIR} by CMake install rule
echo "--- Binaries located in ${BIN_DIR} ---"

cd ../.. # Return to the root directory

echo "=== Local build completed successfully! ==="
if [ "${USE_LIGHTPCAPNG}" = "ON" ]; then
  echo "Built with LightPcapNg library support."
else
  echo "Built with custom PCAP parsing (no LightPcapNg)."
fi

echo "Built with compile-time log level: ${LOG_LEVEL}"
echo "Built with build type: ${BUILD_TYPE}"
if [ "${BUILD_TYPE}" = "Debug" ]; then
    if [ "${ENABLE_ASAN}" = "ON" ]; then
        echo "AddressSanitizer: Enabled"
    else
        echo "AddressSanitizer: Disabled"
    fi
fi

echo "Script finished."
