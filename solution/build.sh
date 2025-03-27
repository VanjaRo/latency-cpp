#!/bin/bash
# Build script for the solution
# Usage: ./build.sh [--with-lightpcapng]

set -e

# Parse command line arguments
USE_LIGHTPCAPNG=ON
while [[ $# -gt 0 ]]; do
  case $1 in
    --with-lightpcapng)
      USE_LIGHTPCAPNG=ON
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: $0 [--with-lightpcapng]"
      exit 1
      ;;
  esac
done

# Create build directory if it doesn't exist
mkdir -p build

# Configure and build the project
cd build
cmake .. -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG}
make -j$(nproc)

echo "Build completed successfully!"
if [ "${USE_LIGHTPCAPNG}" = "ON" ]; then
  echo "Built with LightPcapNg library support."
else
  echo "Built with custom PCAP parsing (no LightPcapNg)."
fi