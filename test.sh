#!/bin/bash
# Local test script for latency challenge
# Usage: ./test.sh [--pcap-direct|--shm] [--file=public1|--file=public2] [--release] [--hugetables]

set -e

# Default to debug build unless --release is passed
BUILD_TYPE="debug"
# Default to disabling hugepages unless --hugetables is passed
USE_HUGEPAGES="false"
DATA_DIR="./lat-spring-data"
RESULTS_DIR="./results"

TEST_MODE="all"
PCAP_FILE="all"

while [[ $# -gt 0 ]]; do
  case $1 in
    --release)
      BUILD_TYPE="release"
      shift
      ;;
    --hugetables)
      USE_HUGEPAGES="true"
      shift
      ;;
    --pcap-direct)
      TEST_MODE="pcap-direct"
      shift
      ;;
    --shm)
      TEST_MODE="shm"
      shift
      ;;
    --file=*)
      PCAP_FILE="${1#*=}"
      if [[ "$PCAP_FILE" != "public1" && "$PCAP_FILE" != "public2" ]]; then
        echo "Error: Invalid file specified. Use --file=public1 or --file=public2"
        exit 1
      fi
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--pcap-direct|--shm] [--file=public1|--file=public2] [--release] [--hugetables]"
      exit 1
      ;;
  esac
done

# Determine the solution binary based on build type
SOLUTION_BIN="./solution/build_${BUILD_TYPE}/solution"

if [ ! -x "${SOLUTION_BIN}" ]; then
    echo "Error: Solution binary not found or not executable at ${SOLUTION_BIN}"
    echo "Please build the solution first using ./build.sh"
    exit 1
fi

mkdir -p "${RESULTS_DIR}"

run_pcap_direct_test() {
  local file=$1
  local pcap_path="${DATA_DIR}/${file}.pcapng"
  local meta_path="${DATA_DIR}/${file}.meta"
  local log_path="${RESULTS_DIR}/${file}_direct.log"
  export LSAN_OPTIONS="verbosity=1:log_threads=1"
  "${SOLUTION_BIN}" "${pcap_path}" "${meta_path}" &> "${log_path}"
  unset LSAN_OPTIONS
}

run_shm_test() {
  local file=$1
  local pcap_path="${DATA_DIR}/${file}.pcapng"
  local meta_path="${DATA_DIR}/${file}.meta"
  local runner_log_path="${RESULTS_DIR}/${file}_runner.log"
  local runner_another_log_path="${RESULTS_DIR}/${file}_runner_another.log"
  local runner_bin="./runner"

  if [ ! -x "${runner_bin}" ]; then
      echo "Error: Runner binary not found or not executable at ${runner_bin}"
      echo "Skipping SHM runner test for ${file}."
      return
  fi

  BUFFER_PREFIX="test_buffer_runner_${file}"
  local runner_cmd=(
      "${runner_bin}"
      -sol "${SOLUTION_BIN}"
      -meta "${meta_path}"
      -b "${BUFFER_PREFIX}"
      -o "${runner_another_log_path}"
  )

  # Disable hugepages only if --hugetables flag was NOT provided
  if [[ "$USE_HUGEPAGES" == "false" ]]; then
    runner_cmd+=("-disable-hugepages")
    BUFFER_PREFIX+="_no_huge"
  fi
  
  runner_cmd+=("${pcap_path}")

  export LSAN_OPTIONS="verbosity=1:log_threads=1"
  if "${runner_cmd[@]}" > "${runner_log_path}" 2>&1; then
      echo "Runner finished successfully. Check results/output in ${runner_log_path}"
  else
      echo "Runner failed. Check error details in ${runner_log_path}"
  fi
  unset LSAN_OPTIONS

  rm -f "/dev/shm/${BUFFER_PREFIX}"*
  echo "SHM runner test finished for ${file}. Check logs in ${RESULTS_DIR}"
}

run_tests_for_file() {
    local file=$1
    if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "pcap-direct" ]]; then
        run_pcap_direct_test "$file"
    fi
    if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "shm" ]]; then
        run_shm_test "$file"
    fi
}

if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public1" ]]; then
  run_tests_for_file "public1"
fi

if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public2" ]]; then
  run_tests_for_file "public2"
fi

echo "=== All specified tests completed ==="
echo "Results are saved in the '${RESULTS_DIR}' directory" 