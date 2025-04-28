#!/bin/bash
# Starts a persistent development container for the latency solution

set -e

CONTAINER_NAME="latency-dev-container"
# Let's name the image specifically to indicate it's the amd64 builder
IMAGE_NAME="latency-solution-builder-amd64"

# --- Build the builder image specifically for amd64 ---
echo "--- Ensuring amd64 builder image (${IMAGE_NAME}) is available ---"
# Build only the builder stage for the amd64 platform
docker build --platform linux/amd64 --target builder -t ${IMAGE_NAME} -f ./solution/Dockerfile .

echo "--- Starting development container (${CONTAINER_NAME}) using ${IMAGE_NAME} ---"

# Check if container exists and is running with the correct image
# A simple check might just be if it's running. For robustness, one could check the image.
if [ "$(docker ps -q -f name=^/${CONTAINER_NAME}$)" ]; then
    # Check if the running container uses the correct image
    CURRENT_IMAGE=$(docker inspect --format='{{.Config.Image}}' ${CONTAINER_NAME})
    if [ "${CURRENT_IMAGE}" == "${IMAGE_NAME}" ]; then
        echo "Container ${CONTAINER_NAME} is already running with the correct image (${IMAGE_NAME})."
        exit 0
    else
        echo "Container ${CONTAINER_NAME} is running with a different image (${CURRENT_IMAGE}). Stopping and removing it."
        docker stop ${CONTAINER_NAME} > /dev/null
        docker rm ${CONTAINER_NAME} > /dev/null
    fi
fi

# Remove exited container with the same name
if [ "$(docker ps -aq -f status=exited -f name=^/${CONTAINER_NAME}$)" ]; then
    echo "Removing existing stopped container ${CONTAINER_NAME}..."
    docker rm ${CONTAINER_NAME}
fi

# Run the container in detached mode using the amd64 builder image
# Ensure platform flag matches the build
docker run -itd \
    --platform linux/amd64 \
    --name ${CONTAINER_NAME} \
    --ipc=host \
    --ulimit memlock=-1 \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -p 1234:1234 \
    -v "$(pwd)/solution:/app/solution" \
    -v "$(pwd)/lat-spring-data:/app/lat-spring-data" \
    -v "$(pwd)/results:/app/results" \
    -v "$(pwd)/build.sh:/app/build.sh" \
    -v "$(pwd)/test.sh:/app/test.sh" \
    -w /app \
    ${IMAGE_NAME} \
    bash # Keep the container running with a bash shell

echo "--- Container ${CONTAINER_NAME} started as linux/amd64 (hugepages disabled by default) ---"
echo "Run ./dev/dev_build.sh to compile inside the container."
echo "Run ./dev/dev_run.sh <args> or ./dev/run_test_in_container.sh to execute."
echo "Run ./dev/dev_shell.sh to get an interactive shell."
echo "Run ./dev/dev_stop.sh to stop and remove the container." 