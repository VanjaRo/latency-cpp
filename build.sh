#!/bin/bash
# Local build script for the latency solution
# Usage: ./build.sh [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>]

set -euo pipefail

# Default values
USE_LIGHTPCAPNG=ON
LOG_LEVEL="NONE" # Default log level

# --- Argument Parsing ---
VALID_LOG_LEVELS=("NONE" "ERROR" "WARN" "INFO" "DEBUG" "TRACE")

function is_valid_log_level() {
  local level="$1"
  for valid_level in "${VALID_LOG_LEVELS[@]}"; do
    if [[ "$level" == "$valid_level" ]]; then
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
        echo "Usage: $0 [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>]"
        exit 1
      fi
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>]"
      exit 1
      ;;
  esac
done

# --- Local Build ---
echo "=== Building solution locally ==="
SOLUTION_DIR="$(pwd)/solution"
BUILD_DIR="${SOLUTION_DIR}/build"
BIN_DIR="${BUILD_DIR}/bin"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

echo "--- Running CMake ---"
# Pass the absolute path to the source directory to CMake
cmake "${SOLUTION_DIR}" \
    -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG} \
    -DCMAKE_LOG_LEVEL=${LOG_LEVEL}

echo "--- Building with Make ---"
# Use nproc if available, otherwise default to 1 core
NPROC=$(nproc 2>/dev/null || echo 1)
make -j${NPROC}

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

echo "Script finished."
