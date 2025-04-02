#!/bin/bash
# Runs the main test.sh script INSIDE the running development container

set -e

CONTAINER_NAME="latency-dev-container"

# Check if container is running
if ! [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Error: Development container ${CONTAINER_NAME} is not running."
    echo "Start it first with ./dev/dev_start.sh"
    exit 1
fi

echo "--- Running /app/test.sh inside ${CONTAINER_NAME} ---"

# Execute the test script inside the container, passing all arguments
docker exec -it ${CONTAINER_NAME} /app/test.sh "$@"

echo "--- Test script finished inside container ---"
