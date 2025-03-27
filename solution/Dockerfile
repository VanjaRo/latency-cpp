FROM ubuntu:24.04

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++-13 \
    clang-18 \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Make build script executable when mounted
CMD ["bash"] 