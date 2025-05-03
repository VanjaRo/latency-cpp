# Latency Spring 2025 Solution

A high-performance C++20 solution for processing market data frames, supporting both direct PCAP mode and shared‐memory queue (SPSC) mode. This document outlines the architecture, key components, build configuration, and usage scenarios.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture and Data Flow](#architecture-and-data-flow)
3. [Module Breakdown](#module-breakdown)
   - [main.cpp](#maincpp)
   - [FrameProcessor](#frameprocessor)
   - [SharedQueue](#sharedqueue)
   - [ProtocolParser](#protocolparser)
   - [OrderbookManager](#orderbookmanager)
   - [PcapReader](#pcapreader)
   - [ProtocolLogger](#protocollogger)
4. [Build & Configuration](#build--configuration)
5. [Running the Solution](#running-the-solution)
6. [Logging & Debugging](#logging--debugging)
7. [Performance Considerations](#performance-considerations)
8. [Contributing & Extending](#contributing--extending)

---

## Project Overview

This solution ingests UDP market data frames either via PCAP files (debug mode) or through a double-mapped shared memory queue (SPSC mode). It parses two message types—SNAPSHOT and UPDATE—maintains per-instrument orderbooks for a configurable set of instruments, and computes Volume-Weighted Average Price (VWAP) for the top 5 price levels on both bid and ask sides.

Supported modes:

- **PCAP Mode**: Read `.pcap` or `.pcapng` files via LightPcapNg (if enabled) or built-in parser.
- **Queue Mode**: Interact with a runner via `SharedQueue` in `/dev/shm`, using 8-byte alignment and optional hugepage support.

Key features:

- Zero‐copy frame processing with double‐mapped memory
- Custom varint + ZigZag decoder for compact update encoding
- Out‐of‐sequence update caching and replay
- SIMD‐friendly VWAP calculation limited to `MAX_PRICE_LEVELS=5`
- Flexible compile-time logging (`NONE` → `TRACE`)

---

## Architecture and Data Flow

```
+-----------------+       +------------------+       +---------------------+
|                 |  PCAP |                  |  MessageType/Length  |                 |
|   PcapReader    | ----> |  FrameProcessor  | ----> |   ProtocolParser    | ----> OrderbookManager
| (file input)    |       |  (runPcap/runQueue)|    | (parseSnapshot/Update)|   (maintains VWAP)
+-----------------+       +------------------+       +---------------------+
                                       ^                             |
                                       | Queue Mode                   |
                              SharedQueue<->FrameProcessor<->SharedQueue

```

1. **Ingress**: In PCAP mode, frames are filtered by IP and handed to the processor; in queue mode, frames flow through a double-mapped buffer.
2. **Frame Parsing**: `FrameProcessor::parseNextPacket` handles Ethernet/IPv4/UDP headers, FCS stripping, 8-byte alignment, and payload extraction.
3. **Protocol Parsing**: `ProtocolParser` demultiplexes SNAPSHOT vs UPDATE, decodes vint (varint+ZigZag), and invokes `OrderbookManager` methods.
4. **Orderbook Management**: Snapshots reset state; updates modify buckets, with out-of-sequence updates cached until a matching snapshot appears.
5. **VWAP Computation**: After each valid UPDATE, VWAP is computed for top N levels and written back (either to stdout in PCAP mode or to the output queue).

---

## Module Breakdown

### main.cpp

- Parses CLI arguments into PCAP or SharedQueue mode.
- Initializes `SharedQueue` (header + buffer files) and `FrameProcessor`.
- Invokes `processor->run()`, which loops indefinitely in queue mode or completes after PCAP processing.
- Error handling and compile-time log level checks.

### FrameProcessor

- **Constructors**:
  - **Queue Mode**: `FrameProcessor(SharedQueue&, SharedQueue&, metadataPath)`.
  - **PCAP Mode**: `FrameProcessor(pcapFilename, metadataPath)`.
- **loadMetadata()**: Reads target IPs and instruments from metadata file; populates the `OrderbookManager`.
- **runQueue()**:
  - Busy-waits for full frames using `waitForBytes`, with backoff (spin → yield → sleep).
  - Parses raw packet, handles non-target/non-UDP/invalid frames.
  - Delegates payload parsing, error detection, and writes 0 or k+triples to the output queue.
- **runPcap()**: Leverages `PcapReader::processFilteredFrames` to process PCAPs in a callback style.
- **writeOutput**: Consistent binary protocol: 4-byte zero or `<count><(instrumentId, num, den)>...`.

### SharedQueue

- **Double-mapping**: Creates an anonymous 2× buffer, then maps the same backing file into each half via `MAP_FIXED`.
- **Hugepage Detection**: `fstatfs` on buffer FD, toggles `MAP_HUGETLB` and `MADV_HUGEPAGE` if on hugetlbfs.
- **Lock-free SPSC** with 64-byte aligned `std::atomic<uint32_t>` offsets.
- Methods: `canRead`, `getReadPtr`, `advanceConsumer`, `canWrite`, `getWritePtr`, `advanceProducer`, `getReadableBytes`, `getWritableBytes`.

### ProtocolParser

- **Message Demux**: Reads `FrameHeader`, chooses SNAPSHOT vs UPDATE.
- **parseSnapshotMessage**:
  - Skips fixed‐length prefix fields.
  - Iterates `FieldHeader`s, handles:
    - `INSTRUMENT_INFO` → `OrderbookManager::processSnapshotInfo()`
    - `TRADING_SESSION_INFO` → `OrderbookManager::updateSnapshotChangeNo()`
    - `ORDERBOOK` → `OrderbookManager::processSnapshotOrderbook()`
  - Finalizes each instrument via `finalizeSnapshot`.
- **parseUpdateMessage**:
  - Decodes VINTable header (`instrumentId`, `changeNo`).
  - Collects `UPDATE_ENTRY` events (eventType, side, priceLevel, priceOffset, volume).
  - Invokes `OrderbookManager::handleUpdateMessage()` per instrument group.
- **VInt Decoder**: ZigZag + varint according to Protobuf spec.

### OrderbookManager

- **Instrument Tracking**: Maintains `trackedInstruments`, `idToName`, and per-instrument `Orderbook` struct.
- **Snapshot Workflow**:
  1. `processSnapshotInfo` resets book.
  2. `processSnapshotOrderbook` populates top levels.
  3. `finalizeSnapshot` computes initial VWAP and applies any cached updates.
- **Update Workflow**:
  - `handleUpdateMessage`: In-sequence updates modify/add/delete levels; out-of-seq updates are cached.
  - `applyCachedUpdates` applies buffered updates once a snapshot gap is closed.
- **VWAP Calculation**: Fast loop over `MAX_PRICE_LEVELS=5` bids + asks, numerator/denominator sums, truncation to `uint32_t`, `vwapChanged` flag.
- **Result Extraction**: `getUpdatedInstruments()` filters for valid, changed VWAP books.

### PcapReader

- **Conditional Compilation**: Enabled only if `USE_LIGHTPCAPNG=ON`.
- Wraps LightPcapNg API (`light_get_next_packet`) with optional IP filtering.
- Stub throws runtime error if LightPcapNg is disabled.

### ProtocolLogger

- Header-only logging with macros: `LOG_ERROR`, `LOG_WARN`, `LOG_INFO`, `LOG_DEBUG`, `LOG_TRACE`.
- Compile-time `COMPILE_TIME_LOG_LEVEL` drives zero-overhead exclusions.
- Writes to `std::clog` with file:line prefix and level tag.

---

## Build & Configuration

```bash
mkdir build && cd build
cmake .. \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_LOG_LEVEL=INFO \
  [-DUSE_LIGHTPCAPNG=ON]  # Enable for high-performance PCAP parsing
make -j$(nproc)
```

### Key CMake options

- `-DCMAKE_LOG_LEVEL`: ONE OF `[NONE, ERROR, WARN, INFO, DEBUG, TRACE]`
- `-DUSE_LIGHTPCAPNG`: `ON` / `OFF`
- `ENABLE_ASAN`: `ON` in Debug builds for AddressSanitizer
- `CMAKE_CXX_STANDARD=20`, `-D_GLIBCXX_ASSERTIONS` recommended for extra checks

---

## Running the Solution

### PCAP Mode

```bash
./solution <pcap_file> <metadata_path>
# e.g. ./solution data/public1.pcapng data/public1.meta
```

Outputs VWAP results per frame to `stdout`.

### Shared Queue Mode

```bash
./solution \  
  <in_header> <in_buffer> \        # Runner → Solution
  <out_header> <out_buffer> \      # Solution → Runner
  <buffer_size> \                  # Must be power of two
  <metadata_path>
```

Communication protocol: 4-byte count followed by N×(instrumentId, numerator, denominator), or single `0` on snapshot/error/no-change.

---

## Logging & Debugging

- Adjust `CMAKE_LOG_LEVEL` for compile-time log verbosity.
- Logs are emitted to `stderr` via `std::clog`.
- Use `LOG_TRACE` for step-by-step byte dumps (only in builds ≥TRACE).
- Key debug flags:
  - `FRAME_HEADER`, `IP_HEADER`, `FRAME_DATA` wait traces in `FrameProcessor`
  - `VWAP` calculation traces in `OrderbookManager`

---

## Performance Considerations

- **Zero-copy** double mapping avoids copies between pages.
- **8-byte alignment** and `SharedQueue::align8` for atomic safety.
- **Backoff strategy**: `_mm_pause()` → `std::this_thread::yield()` → `sleep_for(1µs)`.
- **Single‐producer/single‐consumer** queue eliminates locks.
- **LTO & -O3** with `-march=native` for maximum throughput.

---

## Contributing & Extending

- Follow Google C++ style: 2-space indent, named namespaces, and `constexpr` where applicable.
- Add new instrumentation by extending `OrderbookManager` and hooking into `ProtocolParser`.
- For new message types, update `ProtocolParser::detectMessageType` and add custom handlers.
- Ensure any new fields respect alignment and safe bounds checking.

---

**Enjoy low-latency market data processing!** 