#!/bin/bash
# Opens an interactive shell inside the running development container

set -e

CONTAINER_NAME="latency-dev-container"

# Check if container is running
if ! [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Error: Development container ${CONTAINER_NAME} is not running."
    echo "Start it first with ./dev/dev_start.sh"
    exit 1
fi

echo "--- Opening shell in ${CONTAINER_NAME} ---"
docker exec -it ${CONTAINER_NAME} bash 