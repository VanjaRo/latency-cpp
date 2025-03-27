# Orderbook Processing System Design

## 1. System Architecture

### High-Level Components
- **Packet Processor**: Handles parsing of PCAP data from shared memory queue
- **Protocol Parser**: Decodes the binary protocol (snapshots and incremental updates)
- **Orderbook Manager**: Maintains orderbooks for tracked instruments
- **VWAP Calculator**: Computes VWAP for orderbooks
- **Output Manager**: Formats and writes results to output queue

### Data Flow
1. Read raw data from input shared memory queue
2. Parse ETH/UDP frames and extract application payloads
3. Decode messages (snapshots and updates)
4. Update relevant orderbooks
5. Calculate VWAP for affected instruments
6. Write results to output shared memory queue

### Implementation Notes
- Use memory-mapped SPSC queues with proper alignment (64-byte cache line)
- File layout: `2N` bytes allocated for an `N`-sized buffer (for ring buffer wraparound)
- Reading protocol: `consumer_offset % N` for read position, process `producer_offset - consumer_offset` bytes
- Writing protocol: write at `producer_offset % N`, then atomically increment producer_offset
- All message frames in queue are 8-byte aligned

## 2. Core Data Structures

### Orderbook
```cpp
// Use fixed-size arrays for performance - vectors induce unnecessary allocations
// Cache line optimization: align hot fields to 64 bytes
struct alignas(64) PriceLevel {
    double price;
    int32_t volume;
};

// Consider using a struct-of-arrays layout instead of array-of-structs
// for better SIMD optimization in VWAP calculation
struct Orderbook {
    int32_t instrumentId;
    double tickSize;
    double referencePrice;
    int32_t changeNo;
    
    // Pre-allocated fixed arrays (avoid std::vector)
    // Keep more than 5 levels to handle intermediate states
    // during update application
    PriceLevel asks[16];
    PriceLevel bids[16];
    int askCount; // Actual number of valid levels
    int bidCount; // Actual number of valid levels
    
    // Pre-computed VWAP components for fast updates
    uint32_t vwapNumerator;
    uint32_t vwapDenominator;
    uint32_t lastVwapNumerator;   // For change detection
    uint32_t lastVwapDenominator; // For change detection
    
    // Flags
    bool isValid;
    bool vwapChanged;
};
```

### Instrument Tracker
```cpp
struct InstrumentTracker {
    // Use robin_hood::unordered_flat_map for better performance than std::unordered_map
    // Fixed capacity with no rehashing during runtime
    robin_hood::unordered_flat_map<int32_t, Orderbook> orderbooks; // By instrument ID
    std::unordered_set<std::string> trackedInstruments; // Names from metadata
    
    // Flat map of instrument IDs to their string names (for lookups)
    robin_hood::unordered_flat_map<int32_t, std::string_view> idToName;
    
    // Pre-allocated memory for cached updates to avoid allocations
    struct CachedUpdateList {
        std::vector<UpdateMessage> updates;
        size_t capacity;
    };
    robin_hood::unordered_flat_map<int32_t, CachedUpdateList> cachedUpdates;
    
    // IP addresses from metadata
    uint32_t snapshotIP;
    uint32_t updateIP;
};
```

### Protocol Messages
```cpp
// Use packed structs for direct parsing
#pragma pack(push, 1)
struct FrameHeader {
    uint8_t dummy;
    uint8_t typeId;
    uint16_t length;
    // Additional fields vary by message type
};

struct FieldHeader {
    uint16_t fieldId;
    uint16_t fieldLen;
};
#pragma pack(pop)

// Memory layout for zero-copy parsing
struct UpdateEvent {
    char eventType;  // '1' add, '2' modify, '3' delete
    char side;       // '0' bid, '1' ask
    int32_t priceLevel;
    int64_t priceOffset; // Decoded from vint
    int32_t volume;      // Decoded from vint
};

// Consider using a memory pool for these to avoid allocations
struct UpdateMessage {
    int32_t instrumentId;
    int32_t changeNo;
    UpdateEvent events[32]; // Pre-allocated fixed array
    int eventCount;
};
```

## 3. Core Algorithms

### Orderbook Maintenance

#### Snapshot Processing
```cpp
void processSnapshot(const uint8_t* data, size_t size) {
    // Fast path for irrelevant snapshots
    if (!isTrackedInstrument(extractInstrumentId(data)))
        return;
        
    // Parse directly from memory without copies
    // Use placement new to build Orderbook in-place in the unordered_map
    
    // Critical: Track changeNo for synchronization with incremental updates
}
```

#### Update Processing
```cpp
void processUpdate(const uint8_t* data, size_t size) {
    // Extract instrument ID first to check if tracked
    int32_t instrumentId = extractInstrumentId(data);
    if (!isTrackedInstrument(instrumentId))
        return;
        
    // Extract changeNo
    int32_t changeNo = extractChangeNo(data);
    
    auto& orderbook = orderbooks[instrumentId];
    
    // Synchronization logic
    if (!orderbook.isValid || changeNo != orderbook.changeNo + 1) {
        // Cache update - use pre-allocated memory
        cacheUpdate(instrumentId, data, size);
        return;
    }
    
    // Apply updates sequentially
    bool vwapModified = false;
    for (const auto& event : parseEvents(data, size)) {
        switch (event.eventType) {
            case '1': // Add
                vwapModified |= addPriceLevel(orderbook, event);
                break;
            case '2': // Modify
                vwapModified |= modifyPriceLevel(orderbook, event);
                break;
            case '3': // Delete
                vwapModified |= deletePriceLevel(orderbook, event);
                break;
        }
    }
    
    orderbook.changeNo = changeNo;
    
    // Only recalculate VWAP if levels changed
    if (vwapModified) {
        recalculateVWAP(orderbook);
    }
}
```

#### VWAP Calculation
```cpp
void recalculateVWAP(Orderbook& orderbook) {
    // Store old values for change detection
    orderbook.lastVwapNumerator = orderbook.vwapNumerator;
    orderbook.lastVwapDenominator = orderbook.vwapDenominator;
    
    // Reset calculation
    orderbook.vwapNumerator = 0;
    orderbook.vwapDenominator = 0;
    
    // Only consider first 5 non-zero levels for each side
    int askCount = std::min(orderbook.askCount, 5);
    int bidCount = std::min(orderbook.bidCount, 5);
    
    // Normalize prices by tickSize (converts to integer)
    for (int i = 0; i < askCount; i++) {
        uint32_t normalizedPrice = static_cast<uint32_t>(orderbook.asks[i].price / orderbook.tickSize);
        int32_t volume = orderbook.asks[i].volume;
        if (volume == 0) continue;
        
        orderbook.vwapNumerator += normalizedPrice * volume;
        orderbook.vwapDenominator += volume;
    }
    
    for (int i = 0; i < bidCount; i++) {
        uint32_t normalizedPrice = static_cast<uint32_t>(orderbook.bids[i].price / orderbook.tickSize);
        int32_t volume = orderbook.bids[i].volume;
        if (volume == 0) continue;
        
        orderbook.vwapNumerator += normalizedPrice * volume;
        orderbook.vwapDenominator += volume;
    }
    
    // Check if VWAP changed
    orderbook.vwapChanged = 
        (orderbook.vwapNumerator != orderbook.lastVwapNumerator) || 
        (orderbook.vwapDenominator != orderbook.lastVwapDenominator);
}
```

### Parsing Strategies

#### VInt Decoding
```cpp
// Optimized ZigZag + Varint decoder for sint64
inline int64_t decodeVInt(const uint8_t* data, size_t& offset) {
    uint64_t value = 0;
    int shift = 0;
    uint8_t byte;
    
    do {
        byte = data[offset++];
        value |= static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    // ZigZag decode
    return (value >> 1) ^ -static_cast<int64_t>(value & 1);
}
```

#### Zero-Copy Parsing
```cpp
// Parse field directly from memory without intermediate copies
inline void parseField(const uint8_t* data, size_t size, uint16_t expectedFieldId, 
                      void* output, size_t outputSize) {
    size_t offset = 0;
    
    while (offset < size) {
        const FieldHeader* header = reinterpret_cast<const FieldHeader*>(data + offset);
        offset += sizeof(FieldHeader);
        
        if (header->fieldId == expectedFieldId) {
            // Direct copy with size check
            size_t copySize = std::min(static_cast<size_t>(header->fieldLen), outputSize);
            std::memcpy(output, data + offset, copySize);
            return;
        }
        
        // Skip this field
        offset += header->fieldLen;
    }
}
```

## 4. Performance Optimizations

### Memory Management
- **Custom Allocator**: Implement a simple arena allocator for all temporary allocations
- **Pre-sized Hash Maps**: Pre-allocate hash maps to maximum expected size
- **Stack Allocation**: Use alloca for short-lived variable-sized arrays
- **String Handling**: Use string_view instead of string; avoid string copies
- **Zero-Copy**: Parse directly from input buffer without intermediate copies

### Algorithm Optimizations
- **Branch Prediction**: Help compiler with `__builtin_expect` for common paths
- **Lookup Tables**: Use lookup tables for common conversions (e.g., char event types to enum)
- **Sorting**: Keep sorted arrays for price levels, use insertion sort for small arrays
- **VWAP Calculation**: Track running sum to avoid full recalculation when possible

### SIMD Optimizations
- **VWAP Calculation**: Use AVX/SSE to process multiple price levels in parallel
- **Parallel Processing**: Process independent instruments in parallel using SIMD
- **Memory Operations**: Use SIMD for fast memcpy and zeroing operations

### I/O and Parsing
- **Buffer Management**: Use power-of-two sizes for modulo optimization (bitwise AND)
- **Offset Calculations**: Optimize shared memory queue operations
```cpp
// Optimized queue operations (power-of-two size N)
inline uint32_t getReadPos(uint32_t consumerOffset, uint32_t bufferSize) {
    return consumerOffset & (bufferSize - 1); // Faster than modulo
}

inline uint32_t getWritePos(uint32_t producerOffset, uint32_t bufferSize) {
    return producerOffset & (bufferSize - 1);
}

inline uint32_t getAvailableBytes(uint32_t producerOffset, uint32_t consumerOffset) {
    return producerOffset - consumerOffset;
}
```

## 5. Critical Edge Cases

1. **Sequence Gap Detection**: When `update.changeNo != orderbook.changeNo + 1`, cache update until next snapshot
2. **Orderbook Initialization**: Handle case when update arrives before snapshot
3. **Zero Volume Levels**: Skip zero volume levels in VWAP calculation
4. **Incorrect Frame Alignment**: Verify 8-byte alignment in queue
5. **Buffer Wraparound**: Handle buffer wraparound in shared memory queue correctly
6. **Empty Orderbook**: Handle case when orderbook has no valid levels
7. **Invalid Increments**: Detect and handle corrupt protocol data
8. **Output Formatting**: Ensure output is properly formatted according to specs (4-byte values)

## 6. Shared Memory Queue Implementation

```cpp
// SPSC Queue with memory-mapped files
class SPSCQueue {
private:
    // Memory-mapped pointers
    char* buffer;
    spsc_header_t* header;
    size_t bufferSize;
    
public:
    SPSCQueue(const char* headerPath, const char* bufferPath, size_t size) {
        // Memory-map the header file
        int headerFd = open(headerPath, O_RDWR);
        header = static_cast<spsc_header_t*>(mmap(
            nullptr, sizeof(spsc_header_t), 
            PROT_READ | PROT_WRITE, MAP_SHARED, headerFd, 0));
        close(headerFd);
        
        // Memory-map the buffer file (size is 2N for wraparound)
        int bufferFd = open(bufferPath, O_RDWR);
        buffer = static_cast<char*>(mmap(
            nullptr, size * 2, 
            PROT_READ | PROT_WRITE, MAP_SHARED, bufferFd, 0));
        close(bufferFd);
        
        bufferSize = size;
    }
    
    // Producer interface
    char* getWritePtr() {
        return buffer + (header->producer_offset & (bufferSize - 1));
    }
    
    void advanceProducer(uint32_t bytes) {
        // Align to 8-byte boundary
        bytes = (bytes + 7) & ~7;
        std::atomic_fetch_add_explicit(
            &header->producer_offset, bytes, std::memory_order_release);
    }
    
    // Consumer interface
    size_t getReadableBytes() {
        uint32_t producer = header->producer_offset.load(std::memory_order_acquire);
        uint32_t consumer = header->consumer_offset.load(std::memory_order_relaxed);
        return producer - consumer;
    }
    
    const char* getReadPtr() {
        return buffer + (header->consumer_offset & (bufferSize - 1));
    }
    
    void advanceConsumer(uint32_t bytes) {
        // Align to 8-byte boundary
        bytes = (bytes + 7) & ~7;
        std::atomic_fetch_add_explicit(
            &header->consumer_offset, bytes, std::memory_order_release);
    }
};
```

## 7. Metadata Processing

```cpp
void loadMetadata(const char* metaPath) {
    std::ifstream file(metaPath);
    std::string line;
    
    // Read IP addresses
    std::getline(file, line);
    std::istringstream iss(line);
    std::string ip1, ip2;
    iss >> ip1 >> ip2;
    
    tracker.snapshotIP = ipToInt(ip1);
    tracker.updateIP = ipToInt(ip2);
    
    // Read tracked instruments
    while (std::getline(file, line)) {
        tracker.trackedInstruments.insert(line);
    }
    
    // Pre-allocate maps based on number of tracked instruments
    size_t numInstruments = tracker.trackedInstruments.size();
    tracker.orderbooks.reserve(numInstruments);
    tracker.idToName.reserve(numInstruments);
    tracker.cachedUpdates.reserve(numInstruments);
}
```

## 8. Output Formatting

```cpp
void writeOutput(SPSCQueue& outputQueue) {
    // Count instruments with VWAP changes
    uint32_t changedCount = 0;
    std::vector<std::pair<int32_t, Orderbook*>> changedInstruments;
    
    for (auto& [id, orderbook] : tracker.orderbooks) {
        if (orderbook.isValid && orderbook.vwapChanged) {
            changedCount++;
            changedInstruments.emplace_back(id, &orderbook);
        }
    }
    
    if (changedCount == 0) {
        // Write single zero for snapshots or no changes
        *reinterpret_cast<uint32_t*>(outputQueue.getWritePtr()) = 0;
        outputQueue.advanceProducer(sizeof(uint32_t));
        return;
    }
    
    // Write count and then instrument data
    char* writePtr = outputQueue.getWritePtr();
    *reinterpret_cast<uint32_t*>(writePtr) = changedCount;
    writePtr += sizeof(uint32_t);
    
    for (const auto& [id, orderbook] : changedInstruments) {
        *reinterpret_cast<uint32_t*>(writePtr) = id;
        writePtr += sizeof(uint32_t);
        
        *reinterpret_cast<uint32_t*>(writePtr) = orderbook->vwapNumerator;
        writePtr += sizeof(uint32_t);
        
        *reinterpret_cast<uint32_t*>(writePtr) = orderbook->vwapDenominator;
        writePtr += sizeof(uint32_t);
    }
    
    // Advance producer with total bytes written
    outputQueue.advanceProducer(sizeof(uint32_t) + changedCount * 3 * sizeof(uint32_t));
}

## 9. Key Implementation Challenges

1. **Low-latency processing**: Minimize processing time for each frame
2. **Memory efficiency**: Avoid excessive allocations during parsing
3. **Synchronization**: Correctly handle out-of-order snapshots and updates
4. **Correctness**: Ensure accurate orderbook state and VWAP calculations
5. **Error handling**: Gracefully handle malformed packets or protocol errors

## 10. Technology Choices

- **Language**: C++ for performance and low-level control
- **Build system**: CMake for cross-platform compatibility
- **Libraries**:
  - Consider using 
LightPcapNg (https://github.com/rvelea/LightPcapNg and usage example in tests https://github.com/rvelea/LightPcapNg/blob/master/src/tests/test_read_packets.c) for PCAP parsing during development/testing
  - Minimalist approach for production with few external dependencies
  - Possible use of Boost for specific optimized containers

## 11. Testing Strategy

1. **Unit testing**: Test individual components (parsers, orderbook updates, VWAP)
2. **Integration testing**: Test end-to-end flow with sample data
3. **Performance testing**: Measure latency on sample workloads
4. **Correctness validation**: Compare results against reference implementation

## 12. Extensions and Future Improvements

1. Add runtime metrics collection
2. Implement more sophisticated caching strategies
3. Explore memory-mapped I/O for improved performance
4. Add diagnostic logging for debugging 