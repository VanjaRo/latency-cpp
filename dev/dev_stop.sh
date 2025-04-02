#!/bin/bash
# Stops and removes the development container

set -e

CONTAINER_NAME="latency-dev-container"

echo "--- Stopping and removing container ${CONTAINER_NAME} ---"

if [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Stopping container..."
    docker stop ${CONTAINER_NAME}
else
    echo "Container not running."
fi

if [ "$(docker ps -aq -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Removing container..."
    docker rm ${CONTAINER_NAME}
else
    echo "Container already removed or never existed."
fi

echo "--- Cleanup finished ---" 