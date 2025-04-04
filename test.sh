#!/bin/bash
# Local test script for latency challenge
# Usage: ./test.sh [--pcap-direct|--dumper|--shm] [--file=public1|--file=public2]
# Assumes binaries are built locally in ./solution/build/bin/

set -e

# --- Configuration ---
SOLUTION_BIN="./solution/build_debug/solution"
DUMPER_BIN="./solution/build_debug/pcap_dumper"
DATA_DIR="./lat-spring-data"
RESULTS_DIR="./results"

# --- Argument Parsing ---
TEST_MODE="all"
PCAP_FILE="all"

while [[ $# -gt 0 ]]; do
  case $1 in
    # Note: --with-lightpcapng is removed as build is separate
    --pcap-direct)
      TEST_MODE="pcap-direct"
      shift
      ;;
    --dumper)
      TEST_MODE="dumper"
      shift
      ;;
    --shm)
      TEST_MODE="shm"
      shift
      ;;
    --file=*) # Match --file=public1, --file=public2, etc.
      PCAP_FILE="${1#*=}"
      if [[ "$PCAP_FILE" != "public1" && "$PCAP_FILE" != "public2" ]]; then
        echo "Error: Invalid file specified. Use --file=public1 or --file=public2"
        exit 1
      fi
      shift
      ;;
    *) # Handle unknown options
      echo "Unknown option: $1"
      echo "Usage: $0 [--pcap-direct|--dumper|--shm] [--file=public1|--file=public2]"
      exit 1
      ;;
  esac
done

# --- Check if binaries exist ---
if [ ! -x "${SOLUTION_BIN}" ]; then
    echo "Error: Solution binary not found or not executable at ${SOLUTION_BIN}"
    echo "Please build the solution first using ./build.sh"
    exit 1
fi
if [ ! -x "${DUMPER_BIN}" ]; then
    echo "Error: Dumper binary not found or not executable at ${DUMPER_BIN}"
    echo "Please build the solution first using ./build.sh"
    exit 1
fi

# Create results directory if it doesn't exist
mkdir -p "${RESULTS_DIR}"

# --- Test Functions ---
run_pcap_direct_test() {
  local file=$1
  local pcap_path="${DATA_DIR}/${file}.pcapng"
  local meta_path="${DATA_DIR}/${file}.meta"
  local log_path="${RESULTS_DIR}/${file}_direct.log"
  echo "=== Running direct PCAP processing test for ${file}.pcapng ==="
  echo "Setting LSAN_OPTIONS=verbosity=1:log_threads=1"
  export LSAN_OPTIONS="verbosity=1:log_threads=1" # Set LSAN options
  echo "Command: ${SOLUTION_BIN} ${pcap_path} ${meta_path} &> ${log_path}"
  "${SOLUTION_BIN}" "${pcap_path}" "${meta_path}" &> "${log_path}"
  echo "Results saved to ${log_path}"
  unset LSAN_OPTIONS # Unset for subsequent tests if needed
}

run_dumper_test() {
  local file=$1
  local pcap_path="${DATA_DIR}/${file}.pcapng"
  local meta_path="${DATA_DIR}/${file}.meta"
  local log_path="${RESULTS_DIR}/${file}_dumper.log"

  # Extract IPs from meta file
  IP1=$(head -n 1 "${meta_path}" | awk '{print $1}')
  IP2=$(head -n 1 "${meta_path}" | awk '{print $2}')
  if [ -z "$IP1" ] || [ -z "$IP2" ]; then
      echo "Error: Could not extract IPs from ${meta_path}"
      exit 1
  fi
  echo "Using IPs: $IP1 and $IP2"

  echo "=== Running PCAP dumper test for ${file}.pcapng ==="
  # Note: Dumper might not be built with ASAN/LSAN, so adding options might not have effect
  echo "Command: ${DUMPER_BIN} ${pcap_path} ${IP1} ${IP2} &> ${log_path}"
  "${DUMPER_BIN}" "${pcap_path}" "${IP1}" "${IP2}" &> "${log_path}"
  echo "Results saved to ${log_path}"
}

run_shm_test() {
  local file=$1
  local pcap_path="${DATA_DIR}/${file}.pcapng"
  local meta_path="${DATA_DIR}/${file}.meta"
  local runner_log_path="${RESULTS_DIR}/${file}_runner.log"
  local runner_another_log_path="${RESULTS_DIR}/${file}_runner_another.log"
  # Use absolute path inside container
  local runner_bin="/app/runner" # Runner location inside the container

  echo "=== Running shared memory test via runner for ${file}.pcapng (Hugepages Disabled) ==="

  # Check if runner binary exists
  if [ ! -x "${runner_bin}" ]; then
      echo "Error: Runner binary not found or not executable at ${runner_bin}"
      echo "Skipping SHM runner test for ${file}."
      return # Skip this test if runner not found
  fi

  # Define SHM parameters for the runner's -b flag
  BUFFER_PREFIX="test_buffer_runner_${file}_no_huge" # Optional: change prefix slightly

  # Construct the runner command, adding -disable-hugepages
  local runner_cmd=(
      "${runner_bin}"
      -sol "${SOLUTION_BIN}"
      -meta "${meta_path}"
      -b "${BUFFER_PREFIX}"
      -disable-hugepages # <-- ADDED THIS FLAG
      -o "${runner_another_log_path}" # Direct runner output if needed
      "${pcap_path}"
  )

  echo "Setting LSAN_OPTIONS=verbosity=1:log_threads=1"
  export LSAN_OPTIONS="verbosity=1:log_threads=1" # Set LSAN options for runner & solution

  echo "Command: ${runner_cmd[@]}"

  # Execute the runner command
  if "${runner_cmd[@]}" > "${runner_log_path}" 2>&1; then
      echo "Runner finished successfully. Check results/output in ${runner_log_path}"
  else
      echo "Runner failed. Check error details in ${runner_log_path}"
      # tail "${runner_log_path}" # Uncomment to see log on failure
  fi

  unset LSAN_OPTIONS # Unset for subsequent tests

  # Cleanup SHM files - only /dev/shm should be relevant now
  echo "--- Attempting cleanup of potential SHM files (/dev/shm/${BUFFER_PREFIX}*) ---"
  rm -f "/dev/shm/${BUFFER_PREFIX}"*
  # No need to check /dev/hugepages anymore

  echo "SHM runner test finished for ${file}. Check logs in ${RESULTS_DIR}"
}

# --- Execute Tests ---
run_tests_for_file() {
    local file=$1
    echo "--- Running tests for ${file}.pcapng ---"
    if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "pcap-direct" ]]; then
        run_pcap_direct_test "$file"
    fi

    if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "dumper" ]]; then
        run_dumper_test "$file"
    fi

    if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "shm" ]]; then
        run_shm_test "$file"
    fi
    echo "--- Finished tests for ${file}.pcapng ---"
}

if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public1" ]]; then
  run_tests_for_file "public1"
fi

if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public2" ]]; then
  run_tests_for_file "public2"
fi

echo "=== All specified tests completed ==="
echo "Results are saved in the '${RESULTS_DIR}' directory" 