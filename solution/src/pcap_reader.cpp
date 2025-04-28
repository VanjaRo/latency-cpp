#include "pcap_reader.h"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

// Include LightPcapNg headers only if the feature is enabled (value is 1)
#if USE_LIGHTPCAPNG == 1
#include "../lib/LightPcapNg/include/light_pcapng.h"
#include "../lib/LightPcapNg/include/light_pcapng_ext.h"
#include "../lib/LightPcapNg/include/light_types.h"
#endif

// Define Implementation struct regardless of USE_LIGHTPCAPNG setting
struct PcapReader::Implementation {
#if USE_LIGHTPCAPNG == 1
  // LightPcapNg implementation fields
  std::string filePath;
  std::vector<uint8_t> buffer;

  explicit Implementation(const std::string &filename)
      : filePath(filename), buffer(1024 * 1024) {
    // Verify file exists
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
      throw std::runtime_error("Failed to open PCAP file: " + filename);
    }
    file.close();
  }
#else
  // Empty implementation when LightPcapNg is disabled
  explicit Implementation(const std::string &) {}
#endif
};

// Constructor - always implemented
PcapReader::PcapReader(const std::string &filename)
    : impl(std::make_unique<Implementation>(filename)) {
#if USE_LIGHTPCAPNG != 1
  throw std::runtime_error(
      "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled.");
#endif
}

// Destructor - always implemented
PcapReader::~PcapReader() = default;

// Implementation of processAllFrames
void PcapReader::processAllFrames(const FrameCallback &callback) {
#if USE_LIGHTPCAPNG == 1
  light_pcapng_t *pcapng =
      light_pcapng_open_read(impl->filePath.c_str(), LIGHT_TRUE);
  if (!pcapng) {
    throw std::runtime_error("Failed to open PCAP file with LightPcapNg: " +
                             impl->filePath);
  }

  light_packet_header frame_header;
  const uint8_t *frame_data;

  while (light_get_next_packet(pcapng, &frame_header, &frame_data) ==
         LIGHT_SUCCESS) {
    processFrameCallback(&frame_header, frame_data, callback, 0, 0, false);
  }

  light_pcapng_close(pcapng);
#else
  throw std::runtime_error(
      "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled.");
#endif
}

// Implementation of processFilteredFrames
void PcapReader::processFilteredFrames(uint32_t snapshotIP, uint32_t updateIP,
                                       const FrameCallback &callback) {
#if USE_LIGHTPCAPNG == 1
  std::cout << "Opening PCAP file: " << impl->filePath << std::endl;

  light_pcapng_t *pcapng =
      light_pcapng_open_read(impl->filePath.c_str(), LIGHT_TRUE);
  if (!pcapng) {
    throw std::runtime_error("Failed to open PCAP file with LightPcapNg: " +
                             impl->filePath);
  }

  std::cout << "Successfully opened PCAP file" << std::endl;

  light_packet_header frame_header;
  const uint8_t *frame_data = nullptr;
  int frameCount = 0;

  std::cout << "Starting to read frames..." << std::endl;

  while (true) {
    int res = light_get_next_packet(pcapng, &frame_header, &frame_data);
    if (!res) {
      break;
    }

    if (frame_data != nullptr) {
      frameCount++;
      std::cout << "\nFrame #" << frameCount
                << ": orig_len=" << frame_header.original_length
                << ", cap_len=" << frame_header.captured_length
                << ", iface_id=" << frame_header.interface_id
                << ", data_link=" << frame_header.data_link
                << ", timestamp=" << frame_header.timestamp.tv_sec << "."
                << std::setfill('0') << std::setw(6)
                << frame_header.timestamp.tv_usec << std::endl;

      if (processFrameCallback(&frame_header, frame_data, callback, snapshotIP,
                               updateIP, true) == 0) {
        std::cout << "Frame skipped due to filtering or invalid format"
                  << std::endl;
      }
    }
  }

  std::cout << "Finished reading frames. Total frames processed: " << frameCount
            << std::endl;

  light_pcapng_close(pcapng);
#else
  throw std::runtime_error(
      "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled.");
#endif
}

#if USE_LIGHTPCAPNG == 1
// Helper function to process frame using LightPcapNg - only defined when
// LightPcapNg is enabled
static int processFrameCallback(const light_packet_header *frame_header,
                                const uint8_t *frame_data,
                                const FrameCallback &callback,
                                uint32_t snapshotIP, uint32_t updateIP,
                                bool filterByIP) {
  if (frame_header->captured_length <
      sizeof(EthernetHeader) + sizeof(IPv4Header)) {
    return 0; // Too small for IP header, skip
  }

  const EthernetHeader *ethHeader =
      reinterpret_cast<const EthernetHeader *>(frame_data);

  if (ntohs(ethHeader->etherType) != 0x0800) {
    return 0; // Skip non-IPv4
  }

  const IPv4Header *ipHeader =
      reinterpret_cast<const IPv4Header *>(frame_data + sizeof(EthernetHeader));
  uint8_t ipVersion = ipHeader->versionAndIHL >> 4;
  uint8_t ipHeaderLength = (ipHeader->versionAndIHL & 0x0F) * 4;
  if (ipVersion != 4 || ipHeaderLength < sizeof(IPv4Header)) {
    return 0; // Invalid IP header
  }
  if (sizeof(EthernetHeader) + ipHeaderLength > frame_header->captured_length) {
    return 0; // Truncated IP header
  }

  uint32_t srcIPNBO = ipHeader->sourceIP;
  uint32_t dstIPNBO = ipHeader->destIP;

  if (filterByIP) {
    bool matchFound = (srcIPNBO == snapshotIP || srcIPNBO == updateIP ||
                       dstIPNBO == snapshotIP || dstIPNBO == updateIP);
    if (!matchFound) {
      return 0; // Skip based on IP filter
    }
  }

  if (ipHeader->protocol != 17) {
    return 0; // Skip non-UDP packet
  }

  if (sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader) >
      frame_header->captured_length) {
    return 0; // UDP header truncated
  }

  const UDPHeader *udpHeader = reinterpret_cast<const UDPHeader *>(
      frame_data + sizeof(EthernetHeader) + ipHeaderLength);

  size_t headerOffset =
      sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader);

  uint16_t udpTotalLength = ntohs(udpHeader->length);
  size_t udpDeclaredPayloadLength = 0;
  if (udpTotalLength >= sizeof(UDPHeader)) {
    udpDeclaredPayloadLength = udpTotalLength - sizeof(UDPHeader);
  } else {
    return 0;
  }

  size_t maxPossiblePayloadLength = 0;
  if (frame_header->captured_length >= headerOffset) {
    maxPossiblePayloadLength = frame_header->captured_length - headerOffset;
  } else {
    return 0;
  }

  size_t finalPayloadLength =
      std::min(udpDeclaredPayloadLength, maxPossiblePayloadLength);

  callback(frame_data + headerOffset, finalPayloadLength, srcIPNBO, dstIPNBO);
  return 1;
}
#endif

// Convert string IP to uint32_t (used by both implementations)
// Define regardless of USE_LIGHTPCAPNG setting to avoid undefined reference
uint32_t ipStringToUint32(const std::string &ipStr) {
#if USE_LIGHTPCAPNG == 1
  // Original LightPcapNg implementation
  uint32_t a, b, c, d;
  sscanf(ipStr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
  return (a << 24) | (b << 16) | (c << 8) | d;
#else
  // Use inet_pton implementation when LightPcapNg is disabled
  struct in_addr addr;
  if (inet_pton(AF_INET, ipStr.c_str(), &addr) != 1) {
    throw std::runtime_error("Invalid IP address format: " + ipStr);
  }
  return addr.s_addr;
#endif
}