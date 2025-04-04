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
  // std::cout << "Processing frame: captured_length=" // Debug
  //           << frame_header->captured_length       // Debug
  //           << ", original_length=" << frame_header->original_length // Debug
  //           << std::endl;                          // Debug

  // Process Ethernet, IP, and UDP headers
  if (frame_header->captured_length <
      sizeof(EthernetHeader) +
          sizeof(IPv4Header)) { // Check only Eth+IP header initially
    // std::cout << "Frame too small for Eth+IP, skipping (size=" // Debug
    //           << frame_header->captured_length << ", required=" // Debug
    //           << (sizeof(EthernetHeader) + sizeof(IPv4Header)) // Debug
    //           << ")" << std::endl;                             // Debug

    return 0; // Too small for IP header, skip
  }

  const EthernetHeader *ethHeader =
      reinterpret_cast<const EthernetHeader *>(frame_data);

  // Check for IPv4 (etherType = 0x0800 in network byte order)
  if (ntohs(ethHeader->etherType) != 0x0800 /* ETHERTYPE_IP */) {
    // std::cout << "Not an IPv4 frame (EtherType: 0x" << std::hex // Debug
    //           << ntohs(ethHeader->etherType) << std::dec << "), skipping" //
    //           Debug
    //           << std::endl;                                // Debug

    return 0; // Skip non-IPv4
  }

  const IPv4Header *ipHeader =
      reinterpret_cast<const IPv4Header *>(frame_data + sizeof(EthernetHeader));

  // Check IP version and header length validity
  uint8_t ipVersion = ipHeader->versionAndIHL >> 4;
  uint8_t ipHeaderLength = (ipHeader->versionAndIHL & 0x0F) * 4;
  if (ipVersion != 4 || ipHeaderLength < sizeof(IPv4Header)) {
    // std::cout << "Invalid IPv4 header (Version: " << (int)ipVersion // Debug
    //           << ", IHL: " << (int)ipHeaderLength << "), skipping" <<
    //           std::endl; // Debug
    return 0; // Invalid IP header
  }
  // Ensure entire IP header is captured
  if (sizeof(EthernetHeader) + ipHeaderLength > frame_header->captured_length) {
    // std::cout << "Truncated IP header, skipping" << std::endl; // Debug
    return 0; // Truncated IP header
  }

  // Get IPs in Network Byte Order (NBO) for filtering
  uint32_t srcIPNBO = ipHeader->sourceIP;
  uint32_t dstIPNBO = ipHeader->destIP;

  // If filtering by IP, check if this frame matches our target IPs (using NBO)
  if (filterByIP) {
    // Note: snapshotIP and updateIP are already NBO from FrameProcessor
    // std::cout << "Checking IPs (NBO): src=0x" << std::hex << srcIPNBO << ",
    // dst=0x" // Debug
    //           << dstIPNBO << ", snapshot=0x" << snapshotIP << ", update=0x"
    //           // Debug
    //           << updateIP << std::dec << std::endl; // Debug

    bool matchFound = (srcIPNBO == snapshotIP || srcIPNBO == updateIP ||
                       dstIPNBO == snapshotIP || dstIPNBO == updateIP);

    if (!matchFound) {
      // std::cout << "No IP match found, skipping" << std::endl; // Debug
      return 0; // Skip based on IP filter
    }
  }

  // Check for UDP protocol (17)
  if (ipHeader->protocol != 17 /* IPPROTO_UDP */) {
    // std::cout << "Not a UDP packet (Proto: " << (int)ipHeader->protocol <<
    // "), skipping" << std::endl; // Debug
    return 0; // Skip non-UDP packet
  }

  // Ensure UDP header is fully captured
  if (sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader) >
      frame_header->captured_length) {
    // std::cout << "Truncated UDP header, skipping" << std::endl; // Debug
    return 0; // UDP header truncated
  }

  const UDPHeader *udpHeader = reinterpret_cast<const UDPHeader *>(
      frame_data + sizeof(EthernetHeader) + ipHeaderLength);

  // Calculate payload offset
  size_t headerOffset =
      sizeof(EthernetHeader) + ipHeaderLength + sizeof(UDPHeader);

  // Calculate payload length declared in UDP header
  uint16_t udpTotalLength = ntohs(udpHeader->length);
  size_t udpDeclaredPayloadLength = 0;
  if (udpTotalLength >= sizeof(UDPHeader)) {
    udpDeclaredPayloadLength = udpTotalLength - sizeof(UDPHeader);
  } else {
    // std::cout << "Invalid UDP header length (" << udpTotalLength << "),
    // skipping" << std::endl; // Debug
    return 0; // Invalid UDP length field
  }

  // Calculate actual available payload length based on captured frame size
  size_t maxPossiblePayloadLength = 0;
  if (frame_header->captured_length >=
      headerOffset) { // Use >= to allow zero-length payload
    maxPossiblePayloadLength = frame_header->captured_length - headerOffset;
  } else {
    // This case should be caught by the header checks above, but included for
    // safety std::cout << "Header offset exceeds captured length (" <<
    // headerOffset << " > " // Debug
    //           << frame_header->captured_length << "), skipping" << std::endl;
    //           // Debug

    return 0;
  }

  // Use the smaller of the declared UDP payload length and the actual available
  // length
  size_t finalPayloadLength =
      std::min(udpDeclaredPayloadLength, maxPossiblePayloadLength);

  // std::cout << "Header offset: " << headerOffset << std::endl; // Debug
  // std::cout << "UDP Declared Payload length: " << udpDeclaredPayloadLength <<
  // std::endl; // Debug std::cout << "Max Possible Payload length: " <<
  // maxPossiblePayloadLength << std::endl; // Debug std::cout << "Final Payload
  // length: " << finalPayloadLength << std::endl; // Debug

  // Call the callback with payload data pointer, calculated payload length, and
  // NBO IPs The callback lambda in FrameProcessor uses NBO IPs for its
  // isSnapshot check.
  callback(frame_data + headerOffset, finalPayloadLength, srcIPNBO, dstIPNBO);
  // std::cout << "Successfully processed frame with payload length " // Debug
  //           << finalPayloadLength << std::endl;                    // Debug

  return 1; // Indicate success
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