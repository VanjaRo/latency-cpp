#!/bin/bash
# Main build script for latency challenge
# Usage: ./build.sh [--with-lightpcapng] [--docker] [--run]

set -euo pipefail

# Parse command line arguments
USE_LIGHTPCAPNG=ON
BUILD_DOCKER=false
RUN_DOCKER=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --with-lightpcapng)
      USE_LIGHTPCAPNG=ON
      shift
      ;;
    --docker)
      BUILD_DOCKER=true
      shift
      ;;
    --run)
      RUN_DOCKER=true
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng] [--docker] [--run]"
      exit 1
      ;;
  esac
done

# Build Docker image if requested
if [ "$BUILD_DOCKER" = true ]; then
  echo "=== Building Docker image ==="
  docker build --platform linux/amd64 -t latency-solution solution/
  echo "Docker image built successfully."
  exit 0
fi

# Run Docker with volume mount if requested
if [ "$RUN_DOCKER" = true ]; then
  echo "=== Running Docker container with volume mount ==="
  docker run -it --rm \
    --platform linux/amd64 \
    -v "$(pwd):/app" \
    -v "$(pwd)/lat-spring-data:/app/data" \
    -v "$(pwd)/results:/app/results" \
    latency-solution
  exit 0
fi

# Otherwise build locally
echo "=== Building solution locally ==="
mkdir -p solution/build
cd solution/build

echo "=== Running CMake ==="
cmake .. -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG}

echo "=== Building with Make ==="
make -j$(nproc)

# Copy binaries to the solution directory for easier access
cp solution ../
cp pcap_dumper ../

echo "=== Build completed successfully! ==="
if [ "${USE_LIGHTPCAPNG}" = "ON" ]; then
  echo "Built with LightPcapNg library support."
else
  echo "Built with custom PCAP parsing (no LightPcapNg)."
fi

cd ../..
