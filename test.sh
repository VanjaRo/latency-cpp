#!/bin/bash
# Comprehensive test script for latency challenge
# Usage: ./test.sh [--with-lightpcapng] [--pcap-direct|--dumper|--shm] [--file=public1|--file=public2]

set -e

# Parse command line arguments
USE_LIGHTPCAPNG=""
TEST_MODE="all"
PCAP_FILE="all"

while [[ $# -gt 0 ]]; do
  case $1 in
    --with-lightpcapng)
      USE_LIGHTPCAPNG="--with-lightpcapng"
      shift
      ;;
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
    --file=*)
      PCAP_FILE="${1#*=}"
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng] [--pcap-direct|--dumper|--shm] [--file=public1|--file=public2]"
      exit 1
      ;;
  esac
done

# Create results directory if it doesn't exist
mkdir -p results

# Run tests based on mode and file parameters
run_pcap_direct_test() {
  local file=$1
  echo "=== Running direct PCAP processing test for ${file}.pcapng ==="
  docker run --rm \
    --platform linux/amd64 \
    -v "$(pwd):/app" \
    -v "$(pwd)/lat-spring-data:/app/lat-spring-data" \
    -v "$(pwd)/results:/app/results" \
    latency-solution \
    bash -c "cd /app/solution && \
        ./build.sh ${USE_LIGHTPCAPNG} && \
        echo '--- Processing PCAP file directly ---' && \
        ./solution /app/lat-spring-data/${file}.pcapng /app/lat-spring-data/${file}.meta > /app/results/${file}_direct.log"
  
  echo "Results saved to results/${file}_direct.log"
}

run_dumper_test() {
  local file=$1
  echo "=== Running PCAP dumper test for ${file}.pcapng ==="
  docker run --rm \
    --platform linux/amd64 \
    -v "$(pwd):/app" \
    -v "$(pwd)/lat-spring-data:/app/lat-spring-data" \
    -v "$(pwd)/results:/app/results" \
    latency-solution \
    bash -c "cd /app/solution && \
        ./build.sh ${USE_LIGHTPCAPNG} && \
        echo '--- Running PCAP dumper ---' && \
        IP1=\$(head -n 1 /app/lat-spring-data/${file}.meta | awk '{print \$1}') && \
        IP2=\$(head -n 1 /app/lat-spring-data/${file}.meta | awk '{print \$2}') && \
        echo 'Using IPs: '\$IP1' and '\$IP2 && \
        ./pcap_dumper /app/lat-spring-data/${file}.pcapng \$IP1 \$IP2 | tee /app/results/${file}_dumper.log"
  
  echo "Results saved to results/${file}_dumper.log"
}

run_shm_test() {
  local file=$1
  echo "=== Running shared memory test for ${file}.pcapng ==="
  docker run --rm \
    --platform linux/amd64 \
    --ipc=host \
    --ulimit memlock=-1 \
    -v "$(pwd):/app" \
    -v "$(pwd)/lat-spring-data:/app/lat-spring-data" \
    -v "$(pwd)/results:/app/results" \
    latency-solution \
    bash -c "cd /app/solution && \
        ./build.sh ${USE_LIGHTPCAPNG} && \
        echo '--- Setting up shared memory environment ---' && \
        BUFFER_PREFIX=\"test_buffer\" && \
        SHM_DIR=\"/dev/shm\" && \
        INPUT_HEADER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_input_header\" && \
        INPUT_BUFFER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_input_buffer\" && \
        OUTPUT_HEADER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_output_header\" && \
        OUTPUT_BUFFER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_output_buffer\" && \
        rm -f \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER && \
        touch \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER && \
        BUFFER_SIZE=16777216 && \
        echo '--- Running with shared memory ---' && \
        ./solution \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER \$BUFFER_SIZE /app/lat-spring-data/${file}.meta | tee /app/results/${file}_shm.log && \
        echo '--- Cleaning up ---' && \
        rm -f \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER"
  
  echo "Results saved to results/${file}_shm.log"
}

# Execute tests based on parameters
if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public1" ]]; then
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "pcap-direct" ]]; then
    run_pcap_direct_test "public1"
  fi
  
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "dumper" ]]; then
    run_dumper_test "public1"
  fi
  
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "shm" ]]; then
    run_shm_test "public1"
  fi
fi

if [[ "$PCAP_FILE" == "all" || "$PCAP_FILE" == "public2" ]]; then
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "pcap-direct" ]]; then
    run_pcap_direct_test "public2"
  fi
  
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "dumper" ]]; then
    run_dumper_test "public2"
  fi
  
  if [[ "$TEST_MODE" == "all" || "$TEST_MODE" == "shm" ]]; then
    run_shm_test "public2"
  fi
fi

echo "=== All tests completed ==="
echo "Results are saved in the 'results' directory" 