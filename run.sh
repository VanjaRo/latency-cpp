#!/bin/bash
# Run script for latency challenge
# Usage: ./run.sh [--with-lightpcapng] [--docker] [--file=public1|--file=public2] [--shm]

set -e

# Parse command line arguments
USE_LIGHTPCAPNG=""
USE_DOCKER=false
PCAP_FILE="public1"
USE_SHM=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --with-lightpcapng)
      USE_LIGHTPCAPNG="--with-lightpcapng"
      shift
      ;;
    --docker)
      USE_DOCKER=true
      shift
      ;;
    --file=*)
      PCAP_FILE="${1#*=}"
      shift
      ;;
    --shm)
      USE_SHM=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng] [--docker] [--file=public1|--file=public2] [--shm]"
      exit 1
      ;;
  esac
done

# Ensure data directory exists
if [ ! -d "lat-spring-data" ]; then
  echo "Error: lat-spring-data directory not found."
  echo "Please make sure the data files are available."
  exit 1
fi

# Create results directory if it doesn't exist
mkdir -p results

# Run in Docker if requested
if [ "$USE_DOCKER" = true ]; then
  # Build Docker image
  ./build.sh --docker
  
  if [ "$USE_SHM" = true ]; then
    # Run with shared memory simulation in Docker
    docker run --rm \
      --platform linux/amd64 \
      --ipc=host \
      --ulimit memlock=-1 \
      -v "$(pwd):/app" \
      -v "$(pwd)/lat-spring-data:/app/data" \
      -v "$(pwd)/results:/app/results" \
      latency-solution \
      -c "cd /app/solution && \
          ./build.sh ${USE_LIGHTPCAPNG} && \
          BUFFER_PREFIX=\"test_buffer\" && \
          SHM_DIR=\"/dev/shm\" && \
          INPUT_HEADER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_input_header\" && \
          INPUT_BUFFER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_input_buffer\" && \
          OUTPUT_HEADER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_output_header\" && \
          OUTPUT_BUFFER=\"\${SHM_DIR}/\${BUFFER_PREFIX}_output_buffer\" && \
          rm -f \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER && \
          touch \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER && \
          BUFFER_SIZE=16777216 && \
          ./solution \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER \$BUFFER_SIZE /app/data/${PCAP_FILE}.meta | tee /app/results/${PCAP_FILE}_shm.log && \
          rm -f \$INPUT_HEADER \$INPUT_BUFFER \$OUTPUT_HEADER \$OUTPUT_BUFFER"
  else
    # Run direct PCAP processing in Docker
    docker run --rm \
      --platform linux/amd64 \
      -v "$(pwd):/app" \
      -v "$(pwd)/lat-spring-data:/app/data" \
      -v "$(pwd)/results:/app/results" \
      latency-solution \
      -c "cd /app/solution && \
          ./build.sh ${USE_LIGHTPCAPNG} && \
          ./solution /app/data/${PCAP_FILE}.pcapng /app/data/${PCAP_FILE}.meta | tee /app/results/${PCAP_FILE}_direct.log"
  fi
else
  # Run locally
  cd solution
  
  # Build locally first
  ./build.sh $USE_LIGHTPCAPNG
  
  if [ "$USE_SHM" = true ]; then
    # Run with shared memory simulation locally
    BUFFER_PREFIX="test_buffer"
    SHM_DIR="/dev/shm"
    INPUT_HEADER="${SHM_DIR}/${BUFFER_PREFIX}_input_header"
    INPUT_BUFFER="${SHM_DIR}/${BUFFER_PREFIX}_input_buffer"
    OUTPUT_HEADER="${SHM_DIR}/${BUFFER_PREFIX}_output_header"
    OUTPUT_BUFFER="${SHM_DIR}/${BUFFER_PREFIX}_output_buffer"
    
    rm -f "$INPUT_HEADER" "$INPUT_BUFFER" "$OUTPUT_HEADER" "$OUTPUT_BUFFER"
    touch "$INPUT_HEADER" "$INPUT_BUFFER" "$OUTPUT_HEADER" "$OUTPUT_BUFFER"
    
    BUFFER_SIZE=16777216
    
    ./solution "$INPUT_HEADER" "$INPUT_BUFFER" "$OUTPUT_HEADER" "$OUTPUT_BUFFER" "$BUFFER_SIZE" "../lat-spring-data/${PCAP_FILE}.meta" | tee "../results/${PCAP_FILE}_shm.log"
    
    rm -f "$INPUT_HEADER" "$INPUT_BUFFER" "$OUTPUT_HEADER" "$OUTPUT_BUFFER"
  else
    # Run direct PCAP processing locally
    ./solution "../lat-spring-data/${PCAP_FILE}.pcapng" "../lat-spring-data/${PCAP_FILE}.meta" | tee "../results/${PCAP_FILE}_direct.log"
  fi
  
  cd ..
fi 