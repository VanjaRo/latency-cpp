#!/bin/bash
# PCAP Dumper utility script
# Usage: ./dump.sh [--with-lightpcapng] [--docker] [--file=public1|--file=public2]

set -e

# Parse command line arguments
USE_LIGHTPCAPNG=""
USE_DOCKER=false
PCAP_FILE="public1"

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
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng] [--docker] [--file=public1|--file=public2]"
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

# Build the solution first
./build.sh $USE_LIGHTPCAPNG

# Extract IPs from metadata file
get_ips() {
  local meta_file="$1"
  local ip1=$(head -n 1 "$meta_file" | awk '{print $1}')
  local ip2=$(head -n 1 "$meta_file" | awk '{print $2}')
  echo "$ip1 $ip2"
}

# Run in Docker if requested
if [ "$USE_DOCKER" = true ]; then
  # Build Docker image
  ./build.sh --docker
  
  # Get IPs
  read -r IP1 IP2 <<< "$(get_ips "lat-spring-data/${PCAP_FILE}.meta")"
  
  echo "=== Running PCAP dumper in Docker ==="
  echo "Using IPs: $IP1 and $IP2"
  
  # Run PCAP dumper in Docker
  docker run --rm \
    --platform linux/amd64 \
    -v "$(pwd)/lat-spring-data:/app/data" \
    latency-solution \
    -c "cd /app && \
        ./build.sh ${USE_LIGHTPCAPNG} && \
        ./pcap_dumper data/${PCAP_FILE}.pcapng \"$IP1\" \"$IP2\""
else
  # Run locally
  cd solution
  
  # Get IPs
  read -r IP1 IP2 <<< "$(get_ips "../lat-spring-data/${PCAP_FILE}.meta")"
  
  echo "=== Running PCAP dumper locally ==="
  echo "Using IPs: $IP1 and $IP2"
  
  # Run PCAP dumper locally
  ./pcap_dumper "../lat-spring-data/${PCAP_FILE}.pcapng" "$IP1" "$IP2"
  
  cd ..
fi 