#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Basic Ethernet header structure
#pragma pack(push, 1)
struct EthernetHeader {
  uint8_t destMac[6];
  uint8_t srcMac[6];
  uint16_t etherType;
};

// IPv4 header structure
struct IPv4Header {
  uint8_t versionAndIHL;
  uint8_t typeOfService;
  uint16_t totalLength;
  uint16_t identification;
  uint16_t flagsAndFragmentOffset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t headerChecksum;
  uint32_t sourceIP;
  uint32_t destIP;
};

// UDP header structure
struct UDPHeader {
  uint16_t sourcePort;
  uint16_t destPort;
  uint16_t length;
  uint16_t checksum;
};
#pragma pack(pop)

// Callback function type for frame processing
using FrameCallback =
    std::function<void(const uint8_t *, size_t, uint32_t, uint32_t)>;

class PcapReader {
public:
  explicit PcapReader(const std::string &filename);
  ~PcapReader();

  // Process all Ethernet frames in the PCAP file
  void processAllFrames(const FrameCallback &callback);

  // Process only frames with specified source and destination IPs
  void processFilteredFrames(uint32_t sourceIP, uint32_t destIP,
                             const FrameCallback &callback);

private:
  struct Implementation;
  std::unique_ptr<Implementation> impl;
};

// Utility function to convert string IP to uint32_t
uint32_t ipStringToUint32(const std::string &ipStr);