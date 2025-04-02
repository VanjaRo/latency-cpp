# Latency Spring 2025 Solution

This is a solution for the Latency Spring 2025 competition, developed within the `solution` directory.

## Project Structure

- `src/` - Source code directory
  - `main.cpp` - Main entry point for the solution executable.
  - `pcap_reader.cpp/h` - PCAP file reader implementation (supports optional LightPcapNg).
  - `protocol_parser.cpp/h` - Protocol parser for market data messages.
  - `shared_queue.cpp/h` - SPSC queue implementation for shared memory.
  - `orderbook.cpp/h` - Orderbook management and VWAP calculation.
  - `pcap_dumper.cpp` - Source for the `pcap_dumper` debugging tool.
- `lib/` - External libraries
  - `lightpcapng/` - LightPcapNg library source (optional static dependency).
- `Dockerfile` - Defines the Docker build environment **(used by dev scripts)**.
- `CMakeLists.txt` - CMake build configuration for the solution.

**Note:** Build, test, and development helper scripts (`build.sh`, `test.sh`, `dev_*.sh`) are located in the **root directory** of the project.

## Building the Solution (Local Linux Environment)

Use the `build.sh` script located in the **project root directory**. This script assumes you are on a compatible Linux (x86_64) environment with necessary build tools (CMake, C++ compiler like g++ or clang) installed.

```bash
# Navigate to the project root directory
cd ..

# Build with LightPcapNg (default)
./build.sh

# Build without LightPcapNg
./build.sh --no-lightpcapng
```
This compiles the code and places the `solution` and `pcap_dumper` binaries in the `solution/build/bin/` directory.

## Running and Testing (Local Linux Environment)

Use the `test.sh` script in the project root directory **after building the solution locally** using `./build.sh`.

```bash
# Navigate to the project root directory
cd ..

# First, build the solution
./build.sh # Or --no-lightpcapng

# Then, run tests
./test.sh # Run all tests (pcap-direct, dumper, shm simulation)

# Run specific tests
./test.sh --pcap-direct --file=public1
./test.sh --shm
```
Test results are saved in the `results/` directory in the project root.

## Development Workflow for Non-Linux / Cross-Platform (using Docker)

If you are developing on macOS (including Apple Silicon/ARM) or Windows, or want a guaranteed consistent x86_64 Linux environment, use the Docker-based development workflow facilitated by the `dev_*.sh` scripts in the project root.

This workflow uses a persistent Docker container to provide the Linux environment and allows for rapid iteration without rebuilding the entire image each time.

1.  **Start the Container:**
    ```bash
    # In the project root directory
    ./dev_start.sh
    ```

2.  **Edit Code:** (Modify code locally in `solution/`)

3.  **Build Inside Container:**
    ```bash
    # In the project root directory
    ./dev_build.sh # Build with LightPcapNg (default)
    # or
    ./dev_build.sh --no-lightpcapng
    ```

4.  **Run/Test Inside Container:**
    ```bash
    # In the project root directory
    ./dev_run.sh solution /app/data/public1.pcapng /app/data/public1.meta
    ./dev_run.sh pcap_dumper /app/data/public1.pcapng <ip1> <ip2>
    ```

5.  **Interactive Shell:**
    ```bash
    # In the project root directory
    ./dev_shell.sh
    ```

6.  **Stop the Container:**
    ```bash
    # In the project root directory
    ./dev_stop.sh
    ```

## Running with the Official Runner

The solution is intended to be run by the official `runner` process, typically within the Docker environment for consistency.

1.  Build the Docker image: `cd .. && ./build.sh --docker`
2.  Execute the `runner` within the container, pointing it to `/app/solution`:
    ```bash
    # In the project root directory
    docker run --rm -it \
        --platform linux/amd64 \
        --ipc=host \
        --ulimit memlock=-1 \
        -v "$(pwd)/runner:/runner" `# Mount the runner binary` \
        -v "$(pwd)/lat-spring-data:/app/data" \
        -v "$(pwd)/results:/app/results" \
        latency-solution:latest \
        bash -c "/runner -b test_run -sol /app/solution -meta /app/data/public1.meta /app/data/public1.pcapng -o /app/results/runner_output.log"
    ```
    *(Adapt runner path, meta/pcap files, and output as needed)*

Example using the Docker dev environment (assuming container is started and code built):
```bash
# In the project root directory

# Mount the runner into the *running* dev container and execute
docker cp ./runner latency-dev-container:/runner # Copy runner into container
docker exec -it latency-dev-container \
    bash -c "/runner -b test_run -sol /app/solution/build/bin/solution -meta /app/data/public1.meta /app/data/public1.pcapng -o /app/results/runner_output.log"

# Alternatively, if using the pre-built image method:
docker run --rm -it \
    --platform linux/amd64 \
    --ipc=host \
    --ulimit memlock=-1 \
    -v "$(pwd)/runner:/runner" \
    -v "$(pwd)/lat-spring-data:/app/data" \
    -v "$(pwd)/results:/app/results" \
    latency-solution:latest \
    bash -c "/runner -b test_run -sol /app/solution -meta /app/data/public1.meta /app/data/public1.pcapng -o /app/results/runner_output.log"
```

## Implementation Notes

The current implementation is focused on the first milestone: successfully reading PCAP files and parsing the protocol. It includes:

1. PCAP file parser to extract UDP payloads (with optional LightPcapNg support)
2. Basic protocol parser for market data messages
3. Simple orderbook management
4. VWAP calculation
5. Shared memory queue implementation

### LightPcapNg Integration

The solution supports optional integration with the LightPcapNg library to improve PCAP parsing performance. When enabled:

- The library is included as a static dependency in the `lib/` directory
- All PCAP reading is delegated to the library instead of using our custom implementation
- The same API is maintained, ensuring compatibility with the rest of the codebase

Future optimizations will focus on:
- Improved memory management
- Faster protocol parsing
- More efficient orderbook updates
- SIMD and cache optimizations 