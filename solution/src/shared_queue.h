#pragma once

#include <atomic>
#include <cstdint>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>

// SPSC (Single Producer Single Consumer) queue header
struct alignas(64) SPSCHeader {
  alignas(64) std::atomic<uint32_t> producer_offset;
  alignas(64) std::atomic<uint32_t> consumer_offset;
};

class SharedQueue {
  friend class FrameProcessor;

public:
  // Constructor for input queue (consumer)
  SharedQueue(const std::string &headerPath, const std::string &bufferPath,
              size_t bufferSize, bool isProducer);

  // Destructor
  ~SharedQueue();

  // Consumer interface
  bool canRead(size_t bytes) const;
  const uint8_t *getReadPtr() const;
  void advanceConsumer(uint32_t bytes);
  size_t getReadableBytes() const;

  // Producer interface
  bool canWrite(size_t bytes) const;
  uint8_t *getWritePtr();
  void advanceProducer(uint32_t bytes);
  size_t getWritableBytes() const;

  // Get total buffer size
  size_t getBufferSize() const { return bufferSize; }

private:
  int headerFd;
  int bufferFd;
  SPSCHeader *header;
  uint8_t *buffer;
  size_t bufferSize;
  bool isProducer;

  // Align bytes to 8-byte boundary
  uint32_t align8(uint32_t bytes) const { return (bytes + 7) & ~7; }

  // Get read position in the buffer
  uint32_t getReadPos() const {
    return header->consumer_offset.load(std::memory_order_relaxed) &
           (bufferSize - 1);
  }

  // Get write position in the buffer
  uint32_t getWritePos() const {
    return header->producer_offset.load(std::memory_order_relaxed) &
           (bufferSize - 1);
  }
};