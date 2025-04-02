#!/bin/bash
# Builds the solution inside the running development container

set -e

CONTAINER_NAME="latency-dev-container"

# Check if container is running
if ! [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Error: Development container ${CONTAINER_NAME} is not running."
    echo "Start it first with ./dev/dev_start.sh"
    exit 1
fi

echo "--- Building solution inside ${CONTAINER_NAME} ---"

# Determine build arguments
USE_LIGHTPCAPNG=ON # Default
LOG_LEVEL="DEBUG"   # Default
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

# Parse arguments passed to this script
TEMP_ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
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
        exit 1
      fi
      ;;
    *)
      # Keep unknown args to pass to docker exec if needed (though unlikely)
      TEMP_ARGS+=("$1")
      shift
      ;;
  esac
done

# Execute CMake and Make inside the container
docker exec ${CONTAINER_NAME} bash -c \
  "cd /app/solution/build && \
   cmake .. -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG} -DCMAKE_LOG_LEVEL=${LOG_LEVEL} && \
   make -j\$(nproc)"

echo "--- Build completed inside ${CONTAINER_NAME} ---"
if [ "${USE_LIGHTPCAPNG}" = "ON" ]; then
  echo "Built with LightPcapNg library support."
else
  echo "Built with custom PCAP parsing (no LightPcapNg)."
fi
echo "Built with compile-time log level: ${LOG_LEVEL}" 