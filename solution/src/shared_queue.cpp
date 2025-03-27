#include "shared_queue.h"
#include <cstring>
#include <iostream>
#include <stdexcept>

SharedQueue::SharedQueue(const std::string &headerPath,
                         const std::string &bufferPath, size_t bufferSize,
                         bool isProducer)
    : bufferSize(bufferSize), isProducer(isProducer) {

  // Open header file
  headerFd = open(headerPath.c_str(), O_RDWR);
  if (headerFd == -1) {
    throw std::runtime_error("Failed to open header file: " + headerPath);
  }

  // Open buffer file
  bufferFd = open(bufferPath.c_str(), O_RDWR);
  if (bufferFd == -1) {
    close(headerFd);
    throw std::runtime_error("Failed to open buffer file: " + bufferPath);
  }

  // Memory map the header
  header = static_cast<SPSCHeader *>(mmap(nullptr, sizeof(SPSCHeader),
                                          PROT_READ | PROT_WRITE, MAP_SHARED,
                                          headerFd, 0));

  if (header == MAP_FAILED) {
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to mmap header file");
  }

  // Memory map the buffer (double-sized for wraparound)
  buffer = static_cast<uint8_t *>(mmap(nullptr, bufferSize * 2,
                                       PROT_READ | PROT_WRITE, MAP_SHARED,
                                       bufferFd, 0));

  if (buffer == MAP_FAILED) {
    munmap(header, sizeof(SPSCHeader));
    close(headerFd);
    close(bufferFd);
    throw std::runtime_error("Failed to mmap buffer file");
  }

  // Copy second half of the buffer for wrap-around
  // This isn't needed as the runner does this already
}

SharedQueue::~SharedQueue() {
  munmap(header, sizeof(SPSCHeader));
  munmap(buffer, bufferSize * 2);
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