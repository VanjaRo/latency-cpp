#!/bin/bash
# Runs a command (solution or pcap_dumper) inside the running development container

set -e

CONTAINER_NAME="latency-dev-container"

# Check if container is running
if ! [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Error: Development container ${CONTAINER_NAME} is not running."
    echo "Start it first with ./dev/dev_start.sh"
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: ./dev/dev_run.sh <executable> [args...]"
    echo "  <executable>: 'solution' or 'pcap_dumper'"
    echo "Example: ./dev/dev_run.sh solution /app/data/public1.pcapng /app/data/public1.meta"
    echo "Example: ./dev/dev_run.sh pcap_dumper /app/data/public1.pcapng <ip1> <ip2>"
    exit 1
fi

EXECUTABLE_NAME=$1
shift # Remove executable name from args

# Path in the final container image (set by Dockerfile COPY)
EXECUTABLE_PATH="/app/${EXECUTABLE_NAME}"

echo "--- Running ${EXECUTABLE_PATH} inside ${CONTAINER_NAME} ---"

# Execute the command inside the container
docker exec -it ${CONTAINER_NAME} ${EXECUTABLE_PATH} "$@"

echo "--- Execution finished ---" 