FROM ubuntu:24.04 AS builder

# Install necessary dependencies for building AND DEBUGGING
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    g++-13 \
    clang-18 \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY runner /app/runner
# Copy GDB over if only installed in builder and needed here
# Add any other necessary files like scripts or configs if needed
# COPY --from=builder /app/some_script.sh /app/

# Define the entry point or default command
CMD ["bash"] 