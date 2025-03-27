# Latency Spring 2025 Solution

This is a solution for the Latency Spring 2025 competition.

## Project Structure

- `src/` - Source code directory
  - `main.cpp` - Main entry point for the solution
  - `pcap_reader.cpp/h` - PCAP file reader implementation (supports optional LightPcapNg library)
  - `protocol_parser.cpp/h` - Protocol parser for market data messages
  - `shared_queue.cpp/h` - SPSC queue implementation for shared memory
  - `orderbook.cpp/h` - Orderbook management and VWAP calculation
  - `pcap_dumper.cpp` - Tool for debugging PCAP contents
- `lib/` - External libraries
  - `lightpcapng/` - LightPcapNg library for improved PCAP parsing (optional)

## Building the Solution

The project uses CMake for building. A build script is provided:

```bash
# Build with custom PCAP implementation
./build.sh

# Build with LightPcapNg library (recommended for performance)
./build.sh --with-lightpcapng
```

The LightPcapNg library is included as a static dependency in the `lib/` directory.

## Running the Solution

There are several ways to run the solution:

### 1. Direct PCAP File Testing (Debug Mode)

To test the solution with a PCAP file directly:

```bash
# With custom PCAP implementation
./solution <pcapng_file> <metadata_file>

# Build with LightPcapNg first
./build.sh --with-lightpcapng
./solution <pcapng_file> <metadata_file>
```

Example:
```bash
./solution ../lat-spring-data/public1.pcapng ../lat-spring-data/public1.meta
```

### 2. Competition Environment Simulation

To simulate the competition environment (uses shared memory queues):

```bash
# With custom PCAP implementation
./competition_env.sh

# With LightPcapNg library
./competition_env.sh --with-lightpcapng
```

### 3. Docker Environment (For x86-64 Testing)

If you're on a non-x86 platform (like ARM), you can use Docker for testing:

```bash
# Run PCAP reading test in Docker (with custom PCAP implementation)
./docker_pcap_test.sh

# Run PCAP reading test in Docker (with LightPcapNg)
./docker_pcap_test.sh --with-lightpcapng

# Run PCAP dumper in Docker (with custom PCAP implementation)
./docker_pcap_dumper.sh

# Run PCAP dumper in Docker (with LightPcapNg)
./docker_pcap_dumper.sh --with-lightpcapng
```

## Running in Production

The solution is intended to be run by the runner process:

```bash
<runner_path> -sol ./solution -meta <meta_file> -b <buffer_prefix> <pcap_file>
```

## Debugging Tools

The project includes a PCAP dumper tool that can show packet details:

```bash
./pcap_dumper <pcapng_file> <ip1> <ip2>
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