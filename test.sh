#!/bin/bash
# Local test script for latency challenge
# Usage: ./test.sh [--pcap-direct|--dumper|--shm] [--file=public1|--file=public2]
# Assumes binaries are built locally in ./solution/build/bin/

set -e

# --- Configuration ---
SOLUTION_BIN="./solution/build/solution"
DUMPER_BIN="./solution/build/pcap_dumper"
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
  echo "Command: ${SOLUTION_BIN} ${pcap_path} ${meta_path} &> ${log_path}"
  "${SOLUTION_BIN}" "${pcap_path}" "${meta_path}" &> "${log_path}"
  echo "Results saved to ${log_path}"
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
  echo "Command: ${DUMPER_BIN} ${pcap_path} ${IP1} ${IP2} &> ${log_path}"
  "${DUMPER_BIN}" "${pcap_path}" "${IP1}" "${IP2}" &> "${log_path}"
  echo "Results saved to ${log_path}"
}

run_shm_test() {
  local file=$1
  local meta_path="${DATA_DIR}/${file}.meta"
  local log_path="${RESULTS_DIR}/${file}_shm.log"
  echo "=== Running shared memory test simulation for ${file}.pcapng ==="

  # Define SHM parameters
  BUFFER_PREFIX="test_buffer_local_${file}" 
  SHM_DIR="/dev/shm" 
  INPUT_HEADER="${SHM_DIR}/${BUFFER_PREFIX}_input_header"
  INPUT_BUFFER="${SHM_DIR}/${BUFFER_PREFIX}_input_buffer"
  OUTPUT_HEADER="${SHM_DIR}/${BUFFER_PREFIX}_output_header"
  OUTPUT_BUFFER="${SHM_DIR}/${BUFFER_PREFIX}_output_buffer"
  BUFFER_SIZE=16777216

  # Cleanup previous SHM files if they exist
  echo "--- Cleaning up potential old SHM files ---"
  rm -f "${INPUT_HEADER}" "${INPUT_BUFFER}" "${OUTPUT_HEADER}" "${OUTPUT_BUFFER}"

  # Create dummy files (runner would normally do this)
  echo "--- Creating dummy SHM files (simulation) ---"
  touch "${INPUT_HEADER}" "${INPUT_BUFFER}" "${OUTPUT_HEADER}" "${OUTPUT_BUFFER}"

  echo "--- Running solution with SHM arguments (simulation) ---"
  # NOTE: This assumes the solution binary can accept SHM arguments directly.
  # A full SHM test requires the external 'runner' binary.
  echo "Command: ${SOLUTION_BIN} ${INPUT_HEADER} ${INPUT_BUFFER} ${OUTPUT_HEADER} ${OUTPUT_BUFFER} ${BUFFER_SIZE} ${meta_path} | tee ${log_path}"
  # Run in background to allow cleanup, but capture output
  ( "${SOLUTION_BIN}" "${INPUT_HEADER}" "${INPUT_BUFFER}" "${OUTPUT_HEADER}" "${OUTPUT_BUFFER}" "${BUFFER_SIZE}" "${meta_path}" &> "${log_path}" ) &
  SOLUTION_PID=$!
  echo "Solution running in background (PID: ${SOLUTION_PID}), outputting to ${log_path}"
  echo "Waiting a few seconds for the process to potentially run... (This is a simple simulation)"
  sleep 3 # Give the process a moment to run/fail

  # Check if process is still running (optional)
  if kill -0 $SOLUTION_PID 2>/dev/null; then
      echo "Solution process still running (PID: ${SOLUTION_PID}). This test only simulates startup."
      # Optionally kill it if needed for cleanup simulation
      # kill $SOLUTION_PID
  else
      echo "Solution process (PID: ${SOLUTION_PID}) finished or failed to start."
  fi

  echo "--- Cleaning up SHM files ---"
  rm -f "${INPUT_HEADER}" "${INPUT_BUFFER}" "${OUTPUT_HEADER}" "${OUTPUT_BUFFER}"

  echo "SHM test simulation finished. Check results in ${log_path}"
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