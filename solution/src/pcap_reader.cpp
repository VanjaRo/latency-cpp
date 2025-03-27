#include "pcap_reader.h"
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>

#define USE_LIGHTPCAPNG

#ifdef USE_LIGHTPCAPNG
#include "../lib/LightPcapNg/include/light_pcapng.h"
#include "../lib/LightPcapNg/include/light_pcapng_ext.h"
#include "../lib/LightPcapNg/include/light_types.h"
#endif

#ifndef USE_LIGHTPCAPNG
// Custom PCAPNG parsing implementation - only used if LightPcapNg is not
// available

// LightPcapNg structures for parsing PCAPNG
struct BlockHeader {
  uint32_t blockType;
  uint32_t blockTotalLength;
};

// Enhanced Frame Block type
constexpr uint32_t EPB_TYPE = 0x00000006;

// Section Header Block type
constexpr uint32_t SHB_TYPE = 0x0A0D0D0A;

// Interface Description Block type
constexpr uint32_t IDB_TYPE = 0x00000001;

// Enhanced Frame Block structure
#pragma pack(push, 1)
struct EPBHeader {
  uint32_t interfaceId;
  uint32_t timestampHigh;
  uint32_t timestampLow;
  uint32_t capturedLen;
  uint32_t frameLen;
};
#pragma pack(pop)

// Implementation of PcapReader with custom parsing
struct PcapReader::Implementation {
  std::ifstream file;
  std::vector<uint8_t> buffer;

  explicit Implementation(const std::string &filename)
      : file(filename, std::ios::binary), buffer(1024 * 1024) {
    if (!file.is_open()) {
      throw std::runtime_error("Failed to open PCAP file: " + filename);
    }
  }
};

// Extract frame data from Enhanced Frame Block
void extractFrameFromEPB(std::ifstream &file, const BlockHeader &blockHeader,
                         const EPBHeader &epbHeader,
                         std::vector<uint8_t> &buffer,
                         const FrameCallback &callback) {
  // Read the frame data
  if (epbHeader.capturedLen > buffer.size()) {
    buffer.resize(epbHeader.capturedLen);
  }

  file.read(reinterpret_cast<char *>(buffer.data()), epbHeader.capturedLen);

  // Process Ethernet, IP, and UDP headers
  if (epbHeader.capturedLen <
      sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(UDPHeader)) {
    // Skip padding bytes and block trailer
    size_t remainingBytes =
        blockHeader.blockTotalLength -
        (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
    file.seekg(remainingBytes, std::ios::cur);
    return;
  }

  const EthernetHeader *ethHeader =
      reinterpret_cast<const EthernetHeader *>(buffer.data());

  // Check for IPv4 (etherType = 0x0800 in network byte order)
  if (ntohs(ethHeader->etherType) != 0x0800) {
    // Skip padding bytes and block trailer
    size_t remainingBytes =
        blockHeader.blockTotalLength -
        (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
    file.seekg(remainingBytes, std::ios::cur);
    return;
  }

  const IPv4Header *ipHeader = reinterpret_cast<const IPv4Header *>(
      buffer.data() + sizeof(EthernetHeader));

  // Check for UDP (protocol = 17)
  if (ipHeader->protocol != 17) {
    // Skip padding bytes and block trailer
    size_t remainingBytes =
        blockHeader.blockTotalLength -
        (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
    file.seekg(remainingBytes, std::ios::cur);
    return;
  }

  const UDPHeader *udpHeader = reinterpret_cast<const UDPHeader *>(
      buffer.data() + sizeof(EthernetHeader) +
      (ipHeader->versionAndIHL & 0x0F) * 4);

  // Calculate payload offset and length
  size_t headerOffset = sizeof(EthernetHeader) +
                        (ipHeader->versionAndIHL & 0x0F) * 4 +
                        sizeof(UDPHeader);
  size_t payloadLength = ntohs(udpHeader->length) - sizeof(UDPHeader);

  // Ensure we have a valid payload
  if (headerOffset + payloadLength > epbHeader.capturedLen) {
    // Skip padding bytes and block trailer
    size_t remainingBytes =
        blockHeader.blockTotalLength -
        (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
    file.seekg(remainingBytes, std::ios::cur);
    return;
  }

  // Call the callback with payload data and IP addresses
  callback(buffer.data() + headerOffset, payloadLength,
           ntohl(ipHeader->sourceIP), ntohl(ipHeader->destIP));

  // Skip padding bytes and block trailer
  size_t remainingBytes =
      blockHeader.blockTotalLength -
      (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
  if (remainingBytes > 0) {
    file.seekg(remainingBytes, std::ios::cur);
  }
}

// Constructor
PcapReader::PcapReader(const std::string &filename)
    : impl(std::make_unique<Implementation>(filename)) {}

// Destructor
PcapReader::~PcapReader() = default;

// Process all frames in the PCAP file - custom implementation
void PcapReader::processAllFrames(const FrameCallback &callback) {
  impl->file.seekg(0, std::ios::beg);
  BlockHeader blockHeader;

  while (impl->file.read(reinterpret_cast<char *>(&blockHeader),
                         sizeof(BlockHeader))) {
    if (blockHeader.blockType == EPB_TYPE) {
      // Enhanced Frame Block
      EPBHeader epbHeader;
      impl->file.read(reinterpret_cast<char *>(&epbHeader), sizeof(EPBHeader));

      // Process the frame
      extractFrameFromEPB(impl->file, blockHeader, epbHeader, impl->buffer,
                          callback);
    } else {
      // Skip other block types
      impl->file.seekg(blockHeader.blockTotalLength - sizeof(BlockHeader),
                       std::ios::cur);
    }
  }
}

// Process filtered frames by IP - custom implementation
void PcapReader::processFilteredFrames(uint32_t sourceIP, uint32_t destIP,
                                       const FrameCallback &callback) {
  impl->file.seekg(0, std::ios::beg);
  BlockHeader blockHeader;

  while (impl->file.read(reinterpret_cast<char *>(&blockHeader),
                         sizeof(BlockHeader))) {
    if (blockHeader.blockType == EPB_TYPE) {
      // Enhanced Frame Block
      EPBHeader epbHeader;
      impl->file.read(reinterpret_cast<char *>(&epbHeader), sizeof(EPBHeader));

      // Read the frame data
      if (epbHeader.capturedLen > impl->buffer.size()) {
        impl->buffer.resize(epbHeader.capturedLen);
      }

      impl->file.read(reinterpret_cast<char *>(impl->buffer.data()),
                      epbHeader.capturedLen);

      // Process Ethernet, IP, and UDP headers
      if (epbHeader.capturedLen >=
          sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(UDPHeader)) {
        const EthernetHeader *ethHeader =
            reinterpret_cast<const EthernetHeader *>(impl->buffer.data());

        // Check for IPv4 (etherType = 0x0800 in network byte order)
        if (ntohs(ethHeader->etherType) == 0x0800) {
          const IPv4Header *ipHeader = reinterpret_cast<const IPv4Header *>(
              impl->buffer.data() + sizeof(EthernetHeader));

          // Check for UDP (protocol = 17)
          if (ipHeader->protocol == 17) {
            // Check if source IP matches
            uint32_t srcIP = ntohl(ipHeader->sourceIP);
            uint32_t dstIP = ntohl(ipHeader->destIP);

            // If the source IP is one of our target IPs
            if (srcIP == sourceIP || srcIP == destIP) {
              const UDPHeader *udpHeader = reinterpret_cast<const UDPHeader *>(
                  impl->buffer.data() + sizeof(EthernetHeader) +
                  (ipHeader->versionAndIHL & 0x0F) * 4);

              // Calculate payload offset and length
              size_t headerOffset = sizeof(EthernetHeader) +
                                    (ipHeader->versionAndIHL & 0x0F) * 4 +
                                    sizeof(UDPHeader);
              size_t payloadLength =
                  ntohs(udpHeader->length) - sizeof(UDPHeader);

              // Ensure we have a valid payload
              if (headerOffset + payloadLength <= epbHeader.capturedLen) {
                // Call the callback with payload data
                callback(impl->buffer.data() + headerOffset, payloadLength,
                         srcIP, dstIP);
              }
            }
          }
        }
      }

      // Skip padding bytes and block trailer
      size_t remainingBytes =
          blockHeader.blockTotalLength -
          (sizeof(BlockHeader) + sizeof(EPBHeader) + epbHeader.capturedLen);
      if (remainingBytes > 0) {
        impl->file.seekg(remainingBytes, std::ios::cur);
      }
    } else {
      // Skip other block types
      impl->file.seekg(blockHeader.blockTotalLength - sizeof(BlockHeader),
                       std::ios::cur);
    }
  }
}

#else
// LightPcapNg implementation - used when LightPcapNg library is available

// Implementation of PcapReader using LightPcapNg library
struct PcapReader::Implementation {
  // File path
  std::string filePath;

  // Buffer for frame data
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
};

// Helper function to process frame using LightPcapNg
static int processFrameCallback(const light_packet_header *frame_header,
                                const uint8_t *frame_data,
                                const FrameCallback &callback,
                                uint32_t snapshotIP, uint32_t updateIP,
                                bool filterByIP) {
  std::cout << "Processing frame: captured_length="
            << frame_header->captured_length
            << ", original_length=" << frame_header->original_length
            << std::endl;

  // Process Ethernet, IP, and UDP headers
  if (frame_header->captured_length <
      sizeof(EthernetHeader) + sizeof(IPv4Header) + sizeof(UDPHeader)) {
    std::cout << "Frame too small, skipping (size="
              << frame_header->captured_length << ", required="
              << (sizeof(EthernetHeader) + sizeof(IPv4Header) +
                  sizeof(UDPHeader))
              << ")" << std::endl;
    return 0; // Too small, skip
  }

  const EthernetHeader *ethHeader =
      reinterpret_cast<const EthernetHeader *>(frame_data);

  const IPv4Header *ipHeader =
      reinterpret_cast<const IPv4Header *>(frame_data + sizeof(EthernetHeader));

  // Print IP header information
  uint32_t srcIP = ntohl(ipHeader->sourceIP);
  uint32_t dstIP = ntohl(ipHeader->destIP);

  // If filtering by IP, check if this frame matches our target IPs
  if (filterByIP) {
    std::cout << "Checking IPs: src=0x" << std::hex << srcIP << ", dst=0x"
              << dstIP << ", target1=0x" << snapshotIP << ", target2=0x"
              << updateIP << std::dec << std::endl;

    // Check both source and destination IPs against both target IPs
    bool matchFound = (srcIP == snapshotIP || srcIP == updateIP ||
                       dstIP == snapshotIP || dstIP == updateIP);

    if (!matchFound) {
      std::cout << "No IP match found, skipping" << std::endl;
      return 0;
    }
  }

  const UDPHeader *udpHeader =
      reinterpret_cast<const UDPHeader *>(frame_data + sizeof(EthernetHeader) +
                                          (ipHeader->versionAndIHL & 0x0F) * 4);

  // Calculate payload offset and length
  size_t headerOffset = sizeof(EthernetHeader) +
                        (ipHeader->versionAndIHL & 0x0F) * 4 +
                        sizeof(UDPHeader);
  size_t payloadLength = ntohs(udpHeader->length) - sizeof(UDPHeader);

  std::cout << "Header offset: " << headerOffset << std::endl;
  std::cout << "Payload length: " << payloadLength << std::endl;

  // Call the callback with payload data and IP addresses
  callback(frame_data + headerOffset, payloadLength, srcIP, dstIP);
  std::cout << "Successfully processed frame with payload length "
            << payloadLength << std::endl;

  return 1;
}

// Constructor
PcapReader::PcapReader(const std::string &filename)
    : impl(std::make_unique<Implementation>(filename)) {}

// Destructor
PcapReader::~PcapReader() = default;

// Process all frames in the PCAP file - LightPcapNg implementation
void PcapReader::processAllFrames(const FrameCallback &callback) {
  // Create a light_pcapng reader
  light_pcapng_t *pcapng =
      light_pcapng_open_read(impl->filePath.c_str(), LIGHT_TRUE);
  if (!pcapng) {
    throw std::runtime_error("Failed to open PCAP file with LightPcapNg: " +
                             impl->filePath);
  }

  // Read frames
  light_packet_header frame_header;
  const uint8_t *frame_data;

  while (light_get_next_packet(pcapng, &frame_header, &frame_data) ==
         LIGHT_SUCCESS) {
    processFrameCallback(&frame_header, frame_data, callback, 0, 0, false);
  }

  // Cleanup
  light_pcapng_close(pcapng);
}

// Process filtered frames by IP - LightPcapNg implementation
void PcapReader::processFilteredFrames(uint32_t snapshotIP, uint32_t updateIP,
                                       const FrameCallback &callback) {
  std::cout << "Opening PCAP file: " << impl->filePath << std::endl;

  // Create a light_pcapng reader
  light_pcapng_t *pcapng =
      light_pcapng_open_read(impl->filePath.c_str(), LIGHT_TRUE);
  if (!pcapng) {
    throw std::runtime_error("Failed to open PCAP file with LightPcapNg: " +
                             impl->filePath);
  }

  std::cout << "Successfully opened PCAP file" << std::endl;

  // Read frames
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

  // Cleanup
  light_pcapng_close(pcapng);
}

#endif

// Convert string IP to uint32_t (used by both implementations)
uint32_t ipStringToUint32(const std::string &ipStr) {
  uint32_t a, b, c, d;
  sscanf(ipStr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
  return (a << 24) | (b << 16) | (c << 8) | d;
}