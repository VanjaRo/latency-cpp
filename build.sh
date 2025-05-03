#!/bin/bash
# Usage: ./build.sh [--with-lightpcapng | --no-lightpcapng] [--log-level <LEVEL>] [--build-type <TYPE>] [--enable-asan | --disable-asan]

set -euo pipefail

USE_LIGHTPCAPNG=OFF
LOG_LEVEL="NONE"
BUILD_TYPE="Release"
ENABLE_ASAN="OFF"
LOG_LEVEL_SET="OFF"

VALID_LOG_LEVELS=("NONE" "ERROR" "WARN" "INFO" "DEBUG" "TRACE")
VALID_BUILD_TYPES=("Debug" "Release")

function is_valid_log_level() {
  local level="$1"
  for valid_level in "${VALID_LOG_LEVELS[@]}"; do
    if [[ "$level" == "$valid_level" ]]; then
      return 0
    fi
  done
  return 1
}

function is_valid_build_type() {
  local type="$1"
  for valid_type in "${VALID_BUILD_TYPES[@]}"; do
    if [[ "$type" == "$valid_type" ]]; then
      return 0
    fi
  done
  return 1
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
              LOG_LEVEL_SET="ON"
              LOG_LEVEL="$2"
              shift 2
          else
              echo "Error: Invalid log level '$2'. Must be one of: ${VALID_LOG_LEVELS[*]}"
              exit 1
          fi
      else
        echo "Error: --log-level requires an argument."
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

# Override build type based on presence of --log-level
if [[ "$LOG_LEVEL_SET" == "ON" ]]; then
    BUILD_TYPE="Debug"
else
    BUILD_TYPE="Release"
fi

SOLUTION_DIR="$(pwd)/solution"
BUILD_DIR="${SOLUTION_DIR}/build_${BUILD_TYPE,,}"

mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake "${SOLUTION_DIR}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DCMAKE_CXX_FLAGS_RELEASE="-O3 -march=native -flto -funroll-loops" \
    -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG} \
    -DCMAKE_LOG_LEVEL=${LOG_LEVEL} \
    -DENABLE_ASAN=${ENABLE_ASAN}

NPROC=$(nproc 2>/dev/null || echo 1)
make -j${NPROC}

cd ../..

# Copy the built solution executable into the solution source directory for CI
cp "${BUILD_DIR}/solution" "${SOLUTION_DIR}"

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
