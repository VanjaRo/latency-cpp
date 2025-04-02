FROM ubuntu:24.04 AS builder

# Install necessary dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++-13 \
    clang-18 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy the entire project context
COPY . .

# Declare build arguments
ARG USE_LIGHTPCAPNG=ON

# Build the solution inside the container
RUN mkdir -p solution/build && cd solution/build && \
    cmake .. -DUSE_LIGHTPCAPNG=${USE_LIGHTPCAPNG} && \
    make -j$(nproc) && \
    # Install step will place binaries in /app/bin as per CMakeLists.txt
    make install

# --- Final Image ---
FROM ubuntu:24.04

# Install runtime dependencies (if any, currently none beyond base image)
# RUN apt-get update && apt-get install -y ... && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only the built binaries and necessary runtime files from the builder stage
COPY --from=builder /app/bin/solution /app/solution
COPY --from=builder /app/bin/pcap_dumper /app/pcap_dumper
# Add any other necessary files like scripts or configs if needed
# COPY --from=builder /app/some_script.sh /app/

# Define the entry point or default command
CMD ["bash"] 