#!/bin/bash
# Runs the main build.sh script INSIDE the running development container

set -e

CONTAINER_NAME="latency-dev-container"

# Check if container is running
if ! [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Error: Development container ${CONTAINER_NAME} is not running."
    echo "Start it first with ./dev/dev_start.sh"
    exit 1
fi

echo "--- Running /app/build.sh inside ${CONTAINER_NAME} ---"

# Execute the build script inside the container, passing all arguments
docker exec -it ${CONTAINER_NAME} /app/build.sh "$@"

echo "--- Build script finished inside container ---"
