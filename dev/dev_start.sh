#!/bin/bash
# Starts a persistent development container for the latency solution

set -e

CONTAINER_NAME="latency-dev-container"
IMAGE_NAME="latency-solution-builder"

# --- Build the builder image specifically --- 
# We use the builder stage from the main Dockerfile for consistency
echo "--- Ensuring builder image (${IMAGE_NAME}) is available ---"
docker build --platform linux/amd64 --target builder -t ${IMAGE_NAME} -f ./solution/Dockerfile .

echo "--- Starting development container (${CONTAINER_NAME}) ---"

# Check if container exists
if [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Container ${CONTAINER_NAME} is already running."
    exit 0
fi

if [ "$(docker ps -aq -f status=exited -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Removing existing stopped container ${CONTAINER_NAME}..."
    docker rm ${CONTAINER_NAME}
fi

# Run the container in detached mode
# Mount the solution directory for live code changes
# Mount data and results for running/testing
docker run -itd \
    --platform linux/amd64 \
    --name ${CONTAINER_NAME} \
    -v "$(pwd)/solution:/app/solution" \
    -v "$(pwd)/lat-spring-data:/app/data" `# Mount data for testing` \
    -v "$(pwd)/results:/app/results" `# Mount results` \
    ${IMAGE_NAME} \
    bash # Keep the container running with a bash shell

echo "--- Container ${CONTAINER_NAME} started ---"
echo "Run ./dev/dev_build.sh to compile inside the container."
echo "Run ./dev/dev_run.sh <args> to execute the solution inside."
echo "Run ./dev/dev_shell.sh to get an interactive shell."
echo "Run ./dev/dev_stop.sh to stop and remove the container." 