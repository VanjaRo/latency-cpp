#include "shared_queue.h"
#include <cstring>
#include <stdexcept>
#include <sys/stat.h> // Include for stat

SharedQueue::SharedQueue(const std::string &headerPath,
                         const std::string &bufferPath, size_t bufferSize,
                         bool isProducer)
    : bufferSize(bufferSize), isProducer(isProducer), buffer(nullptr) {

  // Open header file
  headerFd = open(headerPath.c_str(), O_RDWR);
  if (headerFd == -1) {
    throw std::runtime_error("Failed to open header file: " + headerPath +
                             " (" + strerror(errno) + ")");
  }

  // Open buffer file
  bufferFd = open(bufferPath.c_str(), O_RDWR);
  if (bufferFd == -1) {
    close(headerFd);
    throw std::runtime_error("Failed to open buffer file: " + bufferPath +
                             " (" + strerror(errno) + ")");
  }

  // Memory map the header
  header = static_cast<SPSCHeader *>(mmap(nullptr, sizeof(SPSCHeader),
                                          PROT_READ | PROT_WRITE, MAP_SHARED,
                                          headerFd, 0));

  if (header == MAP_FAILED) {
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to mmap header file (" +
                             std::string(strerror(errno)) + ")");
  }

  // Check if hugepages are being used
  int mmap_flags = MAP_SHARED | MAP_FIXED;
  if (bufferPath.rfind("/dev/hugepages/", 0) == 0) {
#ifdef MAP_HUGETLB // Check if MAP_HUGETLB is defined
    mmap_flags |= MAP_HUGETLB;
#else
    // Handle case where MAP_HUGETLB is not available if necessary
    // For now, we might just proceed without it or throw an error
    // Let's proceed without it for now, maybe log a warning later if needed.
#endif
  }

  // Create anonymous mapping for double buffer size
  uint8_t *base_ptr = static_cast<uint8_t *>(mmap(
      nullptr, bufferSize * 2, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (base_ptr == MAP_FAILED) {
    munmap(header, sizeof(SPSCHeader));
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to create anonymous mmap (" +
                             std::string(strerror(errno)) + ")");
  }

  // Map the buffer file into the first half
  buffer = static_cast<uint8_t *>(mmap(
      base_ptr, bufferSize, PROT_READ | PROT_WRITE, mmap_flags, bufferFd, 0));
  if (buffer != base_ptr) {           // Check if MAP_FIXED worked
    munmap(base_ptr, bufferSize * 2); // Clean up anonymous mapping
    munmap(header, sizeof(SPSCHeader));
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to mmap buffer file into first half (" +
                             std::string(strerror(errno)) + ")");
  }

  // Map the buffer file into the second half
  uint8_t *second_half_ptr = static_cast<uint8_t *>(
      mmap(base_ptr + bufferSize, bufferSize, PROT_READ | PROT_WRITE,
           mmap_flags, bufferFd, 0));

  if (second_half_ptr != base_ptr + bufferSize) { // Check if MAP_FIXED worked
    munmap(buffer, bufferSize);                   // Clean up first half mapping
    munmap(base_ptr, bufferSize * 2);             // Clean up anonymous mapping
    munmap(header, sizeof(SPSCHeader));
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to mmap buffer file into second half (" +
                             std::string(strerror(errno)) + ")");
  }
}

SharedQueue::~SharedQueue() {
  munmap(header, sizeof(SPSCHeader));
  // The two mappings share the same underlying anonymous region started at
  // 'buffer'. Unmapping the entire region is sufficient.
  if (buffer != nullptr) { // Check buffer is not null before unmapping
    munmap(buffer, bufferSize * 2);
  }
  close(headerFd);
  close(bufferFd);
}

bool SharedQueue::canRead(size_t bytes) const {
  return getReadableBytes() >= bytes;
}

const uint8_t *SharedQueue::getReadPtr() const { return buffer + getReadPos(); }

void SharedQueue::advanceConsumer(uint32_t bytes) {
  bytes = align8(bytes);
  std::atomic_fetch_add_explicit(&header->consumer_offset, bytes,
                                 std::memory_order_release);
}

size_t SharedQueue::getReadableBytes() const {
  uint32_t producer = header->producer_offset.load(std::memory_order_acquire);
  uint32_t consumer = header->consumer_offset.load(std::memory_order_relaxed);
  return producer - consumer;
}

bool SharedQueue::canWrite(size_t bytes) const {
  return getWritableBytes() >= bytes;
}

uint8_t *SharedQueue::getWritePtr() { return buffer + getWritePos(); }

void SharedQueue::advanceProducer(uint32_t bytes) {
  bytes = align8(bytes);
  std::atomic_fetch_add_explicit(&header->producer_offset, bytes,
                                 std::memory_order_release);
}

size_t SharedQueue::getWritableBytes() const {
  uint32_t producer = header->producer_offset.load(std::memory_order_relaxed);
  uint32_t consumer = header->consumer_offset.load(std::memory_order_acquire);
  return bufferSize - (producer - consumer);
}