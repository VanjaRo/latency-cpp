#include "frame_processor.h"
#include "protocol_logger.h"
#include "shared_queue.h"
#include <cstdint>
#include <emmintrin.h>
#include <iostream> // For PCAP direct mode output

#include <arpa/inet.h> // For ntohs, ntohl, inet_pton
#include <cstring>     // For memset
#include <fstream>
#include <netinet/if_ether.h> // Include for ETHERTYPE_IP
#include <sstream>
#include <stdexcept>

// Ethernet constants
constexpr size_t ETHERNET_FCS_LENGTH =
    4; // Standard Ethernet Frame Check Sequence length.

// Define constants for minimum Ethernet frame size calculation when skipping
// non-IP frames. An Ethernet frame must be at least 60 bytes before the FCS, or
// 64 bytes with the FCS. Minimum payload to achieve 60 bytes (before FCS) = 60
// bytes - sizeof(EthernetHeader) sizeof(EthernetHeader) is 14 bytes (6 DstMAC +
// 6 SrcMAC + 2 EtherType). So, MINIMUM_ETHERNET_PAYLOAD_FOR_PADDING = 60 - 14 =
// 46 bytes.
constexpr size_t MINIMUM_ETHERNET_PAYLOAD_FOR_PADDING = 46;
constexpr size_t MINIMUM_ALIGNED_ETH_FRAME_SIZE_FOR_SKIP =
    sizeof(EthernetHeader) + MINIMUM_ETHERNET_PAYLOAD_FOR_PADDING +
    ETHERNET_FCS_LENGTH;
// This evaluates to 14 (Eth Header) + 46 (Min Payload) + 4 (FCS) = 64 bytes.
// This value is already 8-byte aligned.

// Constant for minimal advancement of the queue consumer on critical parsing
// errors.
constexpr size_t MINIMAL_ALIGNED_ADVANCE_ON_ERROR =
    SharedQueue::align8(sizeof(EthernetHeader)); // 16 bytes

// Helper to apply unified spin/yield/sleep backoff
static inline void backoffDelay(int &counter) {
  _mm_pause();
  ++counter;
}

// The global ipStringToUint32 function is now always defined in pcap_reader.cpp

// Helper function to convert IP string to uint32_t (Network Byte Order)
uint32_t FrameProcessor::ipStringToUint32(const std::string &ip_str) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
    throw std::runtime_error("Invalid IP address format: " + ip_str);
  }
  // inet_pton stores the address in network byte order, which is what we need
  // for comparison with packet headers.
  return addr.s_addr;
}

// Load metadata (implementation moved here)
bool FrameProcessor::loadMetadata() {
  std::ifstream metaFile(metadataPath_);
  if (!metaFile) {
    LOG_ERROR("Failed to open metadata file: ", metadataPath_);
    return false;
  }

  std::string line;
  // Read IPs
  if (std::getline(metaFile, line)) {
    std::istringstream iss(line);
    std::string ip1_str, ip2_str;
    if (iss >> ip1_str >> ip2_str) {
      try {
        snapshotIP_ = ipStringToUint32(ip1_str);
        updateIP_ = ipStringToUint32(ip2_str);
        LOG_INFO("Target IPs loaded: Snapshot=", ip1_str, ", Update=", ip2_str);
      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to parse IPs from metadata: ", e.what());
        return false;
      }
    } else {
      LOG_ERROR("Failed to read IPs from first line of metadata.");
      return false;
    }
  } else {
    LOG_ERROR("Metadata file is empty or failed to read first line.");
    return false;
  }

  // Read instrument names
  targetInstruments_.clear();
  while (std::getline(metaFile, line)) {
    if (!line.empty()) {
      targetInstruments_.insert(line);
    }
  }
  LOG_INFO("Loaded ", targetInstruments_.size(), " target instruments.");
  orderbookManager_.loadInstruments(
      targetInstruments_); // Pass instruments to manager
  return true;
}

// Constructor for Queue Mode
FrameProcessor::FrameProcessor(SharedQueue &inputQueue,
                               SharedQueue &outputQueue,
                               const std::string &metadataPath)
    : usePcap_(false), inputQueue_(&inputQueue), outputQueue_(&outputQueue),
      metadataPath_(metadataPath), orderbookManager_(),
      protocolParser_(orderbookManager_) {
  if (!loadMetadata()) {
    throw std::runtime_error("Failed to load metadata for Queue mode.");
  }
}

// Constructor for PCAP Mode
FrameProcessor::FrameProcessor(const std::string &pcapFilename,
                               const std::string &metadataPath)
    : usePcap_(true), pcapFilename_(pcapFilename), metadataPath_(metadataPath),
      orderbookManager_(), protocolParser_(orderbookManager_) {
  if (!loadMetadata()) {
    throw std::runtime_error("Failed to load metadata for PCAP mode.");
  }
  // PcapReader is initialized later in runPcap()
}

void FrameProcessor::run() {
  if (usePcap_) {
    runPcap();
  } else {
    runQueue();
  }
}

void FrameProcessor::runPcap() {
  LOG_INFO("Running in PCAP mode from file: ", pcapFilename_);
#if USE_LIGHTPCAPNG == 1
  try {
    pcapReader_ = std::make_unique<PcapReader>(pcapFilename_);

    // Process filtered frames
    pcapReader_->processFilteredFrames(
        snapshotIP_, updateIP_,
        [&](const uint8_t *data, size_t size, uint32_t srcIPNBO,
            uint32_t dstIPNBO) {
          // Skip tiny payloads (likely heartbeats, etc.)
          if (size < 10) {
            LOG_DEBUG("Skipping small packet of size ", size);
            return;
          }

          // Check if this is from one of our target IPs
          const bool fromTargetIP =
              (srcIPNBO == snapshotIP_ || srcIPNBO == updateIP_);

          if (!fromTargetIP) {
            LOG_DEBUG("Skipping packet from non-target IP");
            return;
          }

          LOG_DEBUG("Processing packet of size ", size, " from target IP");

          // Determine message type
          bool isSnapshotOrError = true; // Default to true (write 0)

          try {
            // Detect message type to determine output behavior
            if (size >= sizeof(FrameHeader)) {
              MessageType msgType =
                  ProtocolParser::detectMessageType(data, size);
              // Only set to false if it's definitely an UPDATE message
              if (msgType == MessageType::UPDATE) {
                isSnapshotOrError = false;
              }
            }

            // Process the payload (will throw on any parse error)
            protocolParser_.parsePayload(data, size);

            // Even after successful parsing, we still write 0 for snapshot
            // messages
          } catch (const std::exception &e) {
            LOG_ERROR("Error processing PCAP payload: ", e.what());
            isSnapshotOrError = true; // Treat errors as snapshot (write 0)
          } catch (...) {
            LOG_ERROR("Unknown error processing PCAP payload");
            isSnapshotOrError = true; // Treat errors as snapshot (write 0)
          }

          // Use the existing writeOutput method for consistent behavior
          writeOutput(isSnapshotOrError,
                      0); // Use frame counter 0 for PCAP mode
        });
  } catch (const std::runtime_error &e) {
    // Handle PcapReader-specific errors
    LOG_ERROR("PcapReader error: ", e.what());
    throw; // Re-throw to let main handle it
  } catch (const std::exception &e) {
    LOG_ERROR("Unexpected error during PCAP processing: ", e.what());
    throw;
  }
#else
  // When LightPcapNg support is disabled, provide a clear error message
  LOG_ERROR(
      "PCAP mode is not available because USE_LIGHTPCAPNG is not enabled.");
  LOG_ERROR("Please rebuild with ./build.sh --with-lightpcapng to enable PCAP "
            "support.");
  throw std::runtime_error("PCAP mode requires LightPcapNg support. Rebuild "
                           "with --with-lightpcapng.");
#endif
}

// Helper function to wait for a minimum number of bytes in the queue
bool FrameProcessor::waitForBytes(size_t requiredBytes,
                                  uint64_t /*frameCounter*/,
                                  const char * /*waitReason*/) {
  // Tight user-space spin until the buffer has at least requiredBytes
  int max_retries = 1000000000;
  int retry_count = 0;
  while (inputQueue_->getReadableBytes() < requiredBytes) {
    backoffDelay(retry_count);
    if (retry_count >= max_retries) {
      return false;
    }
  }
  return true;
}

// --- Implementation of new private helper methods for parsing ---

bool FrameProcessor::parseEthernetHeader(PacketInfo &info,
                                         uint64_t frameCounter) {
  const size_t MINIMAL_ALIGNED_ADVANCE_ON_ERROR =
      SharedQueue::align8(sizeof(EthernetHeader)); // 16 bytes
  int retry_count = 0;
  const int max_retries = 15;

  // 1. Wait for minimum Ethernet alignment data
  while (!waitForBytes(sizeof(EthernetHeader), frameCounter, "ETH_ALIGN")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for ETH_ALIGN. Will keep waiting.");
    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for ETH_ALIGN. Returning "
                "invalid packet.");
      info.valid = false;
      info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
      return false;
    }
    backoffDelay(retry_count);
  }

  info.bytesAvailableWhenParsed = inputQueue_->getReadableBytes();

  // 2. Peek at Ethernet Header
  info.rawDataStart = inputQueue_->getReadPtr();
  if (!info.rawDataStart) {
    LOG_ERROR("[Frame ", frameCounter,
              "] getReadPtr() returned nullptr after ETH_ALIGN wait! Returning "
              "invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }
  info.ethHeader = reinterpret_cast<const EthernetHeader *>(info.rawDataStart);

  LOG_DEBUG("[Frame ", frameCounter,
            "] Ethernet header: ", "Source MAC: ", info.ethHeader->srcMac,
            "Destination MAC: ", info.ethHeader->destMac,
            "EtherType: ", info.ethHeader->etherType);

  try {
    info.etherType = ntohs(info.ethHeader->etherType);
    LOG_TRACE("[Frame ", frameCounter, "] EtherType = 0x", std::hex,
              info.etherType, std::dec);
  } catch (const std::exception &e) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Exception accessing etherType: ", e.what(),
              " Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing etherType. Possible corrupted "
              "buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }

  // 3. Handle non-IP frames (this is a valid skip, not an error)
  if (info.etherType != ETHERTYPE_IP) {
    LOG_WARN("[Frame ", frameCounter, "] Skipping non-IP frame (EtherType: 0x",
             std::hex, info.etherType, std::dec, ")");
    info.valid = false; // Mark as invalid/skip
    info.alignedFrameSize = MINIMUM_ALIGNED_ETH_FRAME_SIZE_FOR_SKIP;
    return false; // Indicates packet should be skipped
  }
  return true; // Successfully parsed Ethernet header for an IP packet
}

bool FrameProcessor::parseIpHeader(PacketInfo &info, uint64_t frameCounter) {
  const size_t MINIMAL_ALIGNED_ADVANCE_ON_ERROR =
      SharedQueue::align8(sizeof(EthernetHeader)); // 16 bytes
  const size_t min_ip_header_and_eth_size =
      sizeof(EthernetHeader) + sizeof(IPv4Header);
  int retry_count = 0;
  const int max_retries = 15;

  // 1. Wait for full Ethernet + minimum IP header
  while (!waitForBytes(min_ip_header_and_eth_size, frameCounter, "IP_HEADER")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for IP_HEADER. Will keep waiting.");
    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for IP_HEADER. Returning "
                "invalid packet.");
      info.valid = false;
      info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
      return false;
    }
    backoffDelay(retry_count);
  }

  info.bytesAvailableWhenParsed = inputQueue_->getReadableBytes();

  // Re-get pointer as buffer might have wrapped
  info.rawDataStart = inputQueue_->getReadPtr();
  if (!info.rawDataStart) {
    LOG_ERROR("[Frame ", frameCounter,
              "] getReadPtr() returned nullptr after IP_HEADER wait! Returning "
              "invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }
  // info.ethHeader is already set by parseEthernetHeader
  info.ipHeader = reinterpret_cast<const IPv4Header *>(info.rawDataStart +
                                                       sizeof(EthernetHeader));

  // 2. Extract and Validate IP Header fields
  try {
    uint8_t ipVersion = info.ipHeader->versionAndIHL >> 4;
    info.ipHeaderLength = (info.ipHeader->versionAndIHL & 0x0F) * 4;
    info.ipTotalLength = ntohs(info.ipHeader->totalLength);
    info.ipProtocol = info.ipHeader->protocol;
    info.sourceIP = info.ipHeader->sourceIP; // Keep in NBO for comparison

    LOG_TRACE("[Frame ", frameCounter, "] IP Version=", (int)ipVersion,
              ", HdrLen=", (int)info.ipHeaderLength,
              ", TotalLen=", info.ipTotalLength,
              ", Proto=", (int)info.ipProtocol);

    // Basic validation
    if (ipVersion != 4) {
      LOG_WARN("[Frame ", frameCounter,
               "] Skipping non-IPv4 packet (Version: ", ipVersion, ")");
      info.valid = false;
      info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
      return false;
    }
    if (info.ipHeaderLength < 20) { // Minimum IPv4 header size
      LOG_WARN("[Frame ", frameCounter,
               "] Skipping packet with invalid IP header length: ",
               info.ipHeaderLength);
      info.valid = false;
      info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
      return false;
    }
    if (info.ipTotalLength < info.ipHeaderLength) {
      LOG_WARN("[Frame ", frameCounter,
               "] Skipping packet with IP total length (", info.ipTotalLength,
               ") < IP header length (", info.ipHeaderLength, ").");
      info.valid = false;
      info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
      return false;
    }
  } catch (const std::exception &e) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Exception accessing IP Header fields: ", e.what(),
              " Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing IP Header fields. Possible "
              "corrupted buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }

  // 3. Calculate required frame size for IP packet and wait for it
  info.frameSize =
      sizeof(EthernetHeader) + info.ipTotalLength + ETHERNET_FCS_LENGTH;
  info.alignedFrameSize = SharedQueue::align8(info.frameSize);
  LOG_TRACE("[Frame ", frameCounter, "] Calculated frameSize=", info.frameSize,
            ", alignedFrameSize=", info.alignedFrameSize);

  retry_count = 0;
  while (!waitForBytes(info.alignedFrameSize, frameCounter, "FRAME_DATA")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for FRAME_DATA (",
             info.alignedFrameSize, ") bytes). Will keep waiting.");
    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for FRAME_DATA (expected ",
                info.alignedFrameSize,
                " bytes). Returning invalid packet but preserving expected "
                "alignedFrameSize for queue advancement.");
      info.valid = false;
      // DO NOT change info.alignedFrameSize here. It was calculated based on
      // ipTotalLength and should be used to advance the queue to skip this
      // problematic frame.
      return false;
    }
    backoffDelay(retry_count);
  }

  info.bytesAvailableWhenParsed = inputQueue_->getReadableBytes();

  // Re-get pointers as buffer might have wrapped or more data arrived
  info.rawDataStart = inputQueue_->getReadPtr();
  if (!info.rawDataStart) {
    LOG_ERROR("[Frame ", frameCounter,
              "] getReadPtr() returned nullptr after frame data wait! "
              "Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }
  // info.ethHeader and info.ipHeader pointers need to be re-established based
  // on the new rawDataStart
  info.ethHeader = reinterpret_cast<const EthernetHeader *>(info.rawDataStart);
  info.ipHeader = reinterpret_cast<const IPv4Header *>(info.rawDataStart +
                                                       sizeof(EthernetHeader));

  // 4. Check if this is from one of our target IPs
  info.isTargetIP =
      (info.sourceIP == snapshotIP_ || info.sourceIP == updateIP_);

  if (!info.isTargetIP) {
    LOG_TRACE("[Frame ", frameCounter, "] Skipping frame from non-target IP.");
    info.valid = false; // Mark as skip, but use the calculated alignedFrameSize
    return false;       // Indicates packet should be skipped based on IP
  }

  if (info.ipProtocol != IPPROTO_UDP) {
    LOG_WARN("[Frame ", frameCounter,
             "] Skipping non-UDP packet from target IP (Proto: ",
             info.ipProtocol, ")");
    info.valid = false; // Mark as skip, use calculated alignedFrameSize
    return false;       // Indicates packet should be skipped
  }

  return true; // Successfully parsed IP header for a target UDP packet
}

bool FrameProcessor::parseUdpHeaderAndPayload(PacketInfo &info,
                                              uint64_t frameCounter) {
  const size_t MINIMAL_ALIGNED_ADVANCE_ON_ERROR =
      SharedQueue::align8(sizeof(EthernetHeader)); // 16 bytes

  // Assumes rawDataStart, ethHeader, ipHeader, ipHeaderLength are correctly set
  // and validated by previous parsing steps.

  info.udpHeader = reinterpret_cast<const UDPHeader *>(
      info.rawDataStart + sizeof(EthernetHeader) + info.ipHeaderLength);
  uint16_t udpTotalLength = 0;
  try {
    udpTotalLength = ntohs(info.udpHeader->length);
    LOG_TRACE("[Frame ", frameCounter, "] UDP Length=", udpTotalLength);

    if (udpTotalLength < sizeof(UDPHeader)) {
      LOG_WARN("[Frame ", frameCounter,
               "] Invalid UDP header length: ", udpTotalLength,
               ". Treating as empty payload.");
      info.payloadLength = 0;
    } else {
      info.payload =
          reinterpret_cast<const uint8_t *>(info.udpHeader) + sizeof(UDPHeader);
      info.payloadLength = udpTotalLength - sizeof(UDPHeader);

      // Sanity check payload length against IP total length
      size_t expectedUdpPayloadLength =
          info.ipTotalLength - info.ipHeaderLength - sizeof(UDPHeader);
      if (info.payloadLength != expectedUdpPayloadLength) {
        LOG_WARN(
            "[Frame ", frameCounter,
            "] UDP payload length mismatch. UDP header: ", info.payloadLength,
            ", IP header implies: ", expectedUdpPayloadLength,
            ". Using UDP header length.");
      }

      // Boundary check: Ensure payload doesn't read past the received frame
      // data
      const uint8_t *frameEndBasedOnIp =
          info.rawDataStart + info.frameSize - ETHERNET_FCS_LENGTH;
      const uint8_t *payloadEnd = info.payload + info.payloadLength;

      if (payloadEnd > frameEndBasedOnIp) {
        LOG_ERROR("[Frame ", frameCounter, "] Calculated UDP payload (offset ",
                  (payloadEnd - info.rawDataStart),
                  ") exceeds IP frame boundary (size ", info.frameSize,
                  "). Clamping payload length.");
        ptrdiff_t rawMaxPayload = frameEndBasedOnIp - info.payload;
        size_t maxPayload =
            rawMaxPayload > 0 ? static_cast<size_t>(rawMaxPayload) : 0;
        info.payloadLength = info.payloadLength > maxPayload ? maxPayload : 0;
        if (info.payloadLength > 0) {
          LOG_WARN("[Frame ", frameCounter, "] Clamped payload length to ",
                   info.payloadLength);
        } else {
          LOG_WARN("[Frame ", frameCounter,
                   "] Payload length becomes 0 after clamping.");
          info.payload = nullptr;
        }
      }
    }
  } catch (const std::exception &e) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Exception accessing UDP Header/Payload: ", e.what(),
              " Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = info.alignedFrameSize > 0
                                ? info.alignedFrameSize
                                : MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing UDP Header/Payload. Possible "
              "corrupted buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = info.alignedFrameSize > 0
                                ? info.alignedFrameSize
                                : MINIMAL_ALIGNED_ADVANCE_ON_ERROR;
    return false;
  }

  // If we reached here with a valid payload, mark the packet as valid
  info.valid = (info.payload != nullptr && info.payloadLength > 0);

  if (!info.valid) {
    LOG_DEBUG("[Frame ", frameCounter,
              "] Packet from target IP has no valid payload");
  }
  return info.valid; // Returns true if payload is valid, false otherwise
}

// Helper function to parse the next packet from the input queue
FrameProcessor::PacketInfo
FrameProcessor::parseNextPacket(uint64_t frameCounter) {
  PacketInfo info;
  // MINIMAL_ALIGNED_ADVANCE_ON_ERROR is defined in each helper where needed.

  // 1. Parse Ethernet Header and check EtherType
  if (!parseEthernetHeader(info, frameCounter)) {
    // info.valid and info.alignedFrameSize are set by parseEthernetHeader
    // This path handles non-IP skips or critical Ethernet header errors.
    return info;
  }

  // At this point, it's an IP packet. Proceed to parse IP header.
  if (!parseIpHeader(info, frameCounter)) {
    // info.valid and info.alignedFrameSize are set by parseIpHeader
    // This path handles IP validation errors, non-target IPs, or non-UDP skips.
    return info;
  }

  // At this point, it's a UDP packet from a target IP. Parse UDP header and get
  // payload.
  if (!parseUdpHeaderAndPayload(info, frameCounter)) {
    // info.valid and info.alignedFrameSize are set by parseUdpHeaderAndPayload
    // This path handles UDP parsing errors or empty/invalid payloads.
    // Note: even if this returns false (payload not valid),
    // info.alignedFrameSize should still be correct for advancing the queue
    // based on IP packet length.
    return info;
  }

  // If all parsing stages passed, info.valid should be true.
  return info;
}

// Helper function to write output to the queue
void FrameProcessor::writeOutput(bool isSnapshotOrError,
                                 uint64_t frameCounter) {
  // Sequence count + initial log
  writesCount_++;
  LOG_DEBUG("[Frame ", frameCounter, "] writeOutput seq=", writesCount_);

  // PCAP mode: print directly
  if (usePcap_) {
    if (isSnapshotOrError) {
      std::cout << 0 << '\n';
    } else {
      auto updates = orderbookManager_.getUpdatedInstruments();
      if (updates.empty()) {
        std::cout << 0 << '\n';
      } else {
        std::cout << updates.size();
        for (auto &u : updates) {
          std::cout << ' ' << u.instrumentId << ' ' << u.numerator << ' '
                    << u.denominator;
        }
        std::cout << '\n';
      }
      orderbookManager_.clearChangedVWAPs();
    }
    return;
  }

  // Prepare payload vector (empty for snapshots/errors)
  std::vector<OrderbookManager::VWAPResult> updates;
  if (!isSnapshotOrError)
    updates = orderbookManager_.getUpdatedInstruments();

  uint32_t count = static_cast<uint32_t>(updates.size());
  size_t headerSz = sizeof(count);
  size_t bodySz = count * 3 * sizeof(uint32_t);
  size_t totalSz = headerSz + bodySz;
  // Pad total size to 8-byte boundary for shared-queue alignment
  size_t paddedSz = SharedQueue::align8(totalSz);

  // Warn every WARN_LOG_INTERVAL backoff loops
  constexpr int WARN_LOG_INTERVAL = 1024;
  int backoff = 0;
  while (!outputQueue_->canWrite(paddedSz)) {
    if ((backoff % WARN_LOG_INTERVAL) == 0) {
      size_t free = outputQueue_->getWritableBytes();
      LOG_WARN("[Frame ", frameCounter, "] backpressure: need ", paddedSz,
               " bytes, free ", free);
    }
    backoffDelay(backoff);
  }

  // Write count and entries
  uint8_t *wptr = outputQueue_->getWritePtr();
  *reinterpret_cast<uint32_t *>(wptr) = count;
  wptr += headerSz;
  LOG_DEBUG("[Frame ", frameCounter, "] writing ", count, " entries (", totalSz,
            " bytes) padded to ", paddedSz);

  // Trace-only detailed logs
  if (COMPILE_TIME_LOG_LEVEL >= static_cast<int>(LogLevel::TRACE)) {
    for (auto &u : updates) {
      if (orderbookManager_.isVWAPChanged(u.instrumentId)) {
        LOG_TRACE("[Frame ", frameCounter, "] VWAP ID=", u.instrumentId,
                  " N=", u.numerator, " D=", u.denominator);
      }
    }
  }

  // Copy payload (ID, numerator, denominator triples)
  for (auto &u : updates) {
    *reinterpret_cast<uint32_t *>(wptr) = u.instrumentId;
    wptr += sizeof(uint32_t);
    *reinterpret_cast<uint32_t *>(wptr) = u.numerator;
    wptr += sizeof(uint32_t);
    *reinterpret_cast<uint32_t *>(wptr) = u.denominator;
    wptr += sizeof(uint32_t);
  }

  // Zero out any padding beyond the real data
  if (paddedSz > totalSz) {
    std::memset(wptr, 0, paddedSz - totalSz);
  }
  // Publish padded size
  outputQueue_->advanceProducer(paddedSz);
  orderbookManager_.clearChangedVWAPs();
  LOG_DEBUG("[Frame ", frameCounter, "] writeOutput done, wrote ", count,
            " entries, totalSz=", totalSz, ", paddedSz=", paddedSz);
}

// Helper function to process a valid packet's payload
bool FrameProcessor::processPacketPayload(const PacketInfo &packetInfo,
                                          uint64_t frameCounter) {
  if (!packetInfo.payload || packetInfo.payloadLength == 0) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Called processPacketPayload with empty payload");
    return true; // Error
  }

  // Additional validation to catch suspicious payload lengths
  const size_t MIN_VALID_PAYLOAD =
      sizeof(FrameHeader); // At minimum, should have a frame header
  const size_t MAX_REASONABLE_PAYLOAD = 65535; // Standard UDP max size

  if (packetInfo.payloadLength < MIN_VALID_PAYLOAD) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Payload too small to contain a valid message: ",
              packetInfo.payloadLength, " < ", MIN_VALID_PAYLOAD);
    return true; // Error
  }

  if (packetInfo.payloadLength > MAX_REASONABLE_PAYLOAD) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Suspiciously large payload: ", packetInfo.payloadLength, " > ",
              MAX_REASONABLE_PAYLOAD);
    return true; // Error
  }

  bool processingError = false;

  try {
    LOG_TRACE("[Frame ", frameCounter, "] Parsing payload (",
              packetInfo.payloadLength, " bytes)...");
    // Let the protocol parser handle the parsing logic (will throw on error)
    protocolParser_.parsePayload(packetInfo.payload, packetInfo.payloadLength);
    LOG_TRACE("[Frame ", frameCounter, "] Payload parsing complete.");
  } catch (const std::exception &e) {
    LOG_ERROR("[Frame ", frameCounter, "] Error parsing payload: ", e.what());
    processingError = true; // Treat any exception as processing error
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown error during payload parsing.");
    processingError = true;
  }

  return processingError;
}

// Helper function to advance the input queue consumer
void FrameProcessor::advanceInputQueue(const PacketInfo &packetInfo,
                                       uint64_t frameCounter) {
  [[maybe_unused]] uint32_t currentOffset =
      inputQueue_->header->consumer_offset.load(std::memory_order_relaxed);

  LOG_DEBUG("[Frame ", frameCounter, "] Advancing consumer by aligned size: ",
            packetInfo.alignedFrameSize,
            " (original frameSize=", packetInfo.frameSize,
            ", current offset=", currentOffset, ")");

  if (packetInfo.alignedFrameSize > 0) {
    inputQueue_->advanceConsumer(packetInfo.alignedFrameSize);
    [[maybe_unused]] uint32_t newOffset =
        inputQueue_->header->consumer_offset.load(std::memory_order_relaxed);
    LOG_DEBUG("[Frame ", frameCounter, "] Consumer advanced from ",
              currentOffset, " to ", newOffset,
              " (delta: ", (newOffset - currentOffset), ")");
  } else {
    LOG_ERROR(
        "[Frame ", frameCounter,
        "] CRITICAL: packetInfo.alignedFrameSize is non-positive (",
        packetInfo.alignedFrameSize,
        "). This indicates a severe parsing logic error in parseNextPacket. "
        "Advancing by MINIMAL_ALIGNED_ADVANCE_ON_ERROR (",
        MINIMAL_ALIGNED_ADVANCE_ON_ERROR,
        " bytes) as a last resort. QUEUE WILL LIKELY MISALIGN.");
    inputQueue_->advanceConsumer(MINIMAL_ALIGNED_ADVANCE_ON_ERROR);
    [[maybe_unused]] uint32_t newOffset =
        inputQueue_->header->consumer_offset.load(std::memory_order_relaxed);
    LOG_DEBUG("[Frame ", frameCounter, "] Consumer advanced from ",
              currentOffset, " to ", newOffset,
              " (delta: ", (newOffset - currentOffset), ")");
  }
}

// Helper function to process a single frame from the input queue
void FrameProcessor::processSingleFrame(uint64_t frameCounter) {
  // Update the current frame counter in the logger
  SET_LOG_FRAME(frameCounter);

  LOG_DEBUG("[Frame ", frameCounter, "] ----- Start Processing -----");

  // 1. Parse the next packet (network level)
  LOG_DEBUG("[Frame ", frameCounter, "] Step 1: Parsing network packet");
  PacketInfo packetInfo = parseNextPacket(frameCounter);
  LOG_DEBUG("[Frame ", frameCounter,
            "] Packet parsed, valid=", packetInfo.valid,
            ", payload=", (packetInfo.payload ? "present" : "null"),
            ", size=", packetInfo.payloadLength);

  // 2. Handle invalid/skipped packets - write 0 to output and advance
  if (!packetInfo.valid) {
    LOG_DEBUG("[Frame ", frameCounter, "] Invalid packet, writing 0 to output");
    LOG_DEBUG("[Frame ", frameCounter,
              "] Advancing input queue before writing 0");
    advanceInputQueue(packetInfo, frameCounter);
    LOG_DEBUG("[Frame ", frameCounter,
              "] Writing 0 to output for invalid packet");
    writeOutput(true, frameCounter); // Write 0 for invalid packets
    LOG_DEBUG("[Frame ", frameCounter,
              "] ----- End Processing (Invalid) -----");
    return;
  }

  // 3. Process payload (application level)
  bool processingError = processPacketPayload(packetInfo, frameCounter);

  // 4. Determine if this is a snapshot message by asking the protocol parser
  MessageType msgType = ProtocolParser::detectMessageType(
      packetInfo.payload, packetInfo.payloadLength);
  bool writeZeroMsgType =
      (msgType == MessageType::SNAPSHOT || msgType == MessageType::UNKNOWN);

  // 5. Write Output
  // Write 0 if it was a snapshot message OR unknown message type OR if a
  // processing error occurred
  // First free input space before blocking on output
  advanceInputQueue(packetInfo, frameCounter);
  writeOutput(writeZeroMsgType || processingError, frameCounter);
}

// Main processing loop for Queue mode
void FrameProcessor::runQueue() {
  LOG_INFO("Starting frame processing loop (Queue mode).");

  SET_LOG_FRAME_THRESHOLD(134050);

  // Check for null queue pointers
  if (!inputQueue_ || !outputQueue_) {
    LOG_ERROR(
        "FATAL: Input or Output queue is NULL in runQueue! Cannot proceed.");
    return; // Return instead of throwing
  }

  uint64_t frameCounter = 1; // Initialize frame counter
  const int MAX_CONSECUTIVE_ERRORS =
      100; // Maximum consecutive errors before giving up
  int consecutiveErrors = 0;
  uint32_t lastConsumerOffset = 0;
  uint32_t lastProducerOffset = 0;
  uint64_t stuckFrameCounter = 0;
  bool potentiallyStuck = false;

  // Diagnostic variables to track progress
  uint64_t lastSuccessfulFrame = 0;
  uint64_t stuckCheckInterval = 50; // Check for being stuck every 50 frames

  while (true) {
    // Diagnostic check - log queue state periodically
    if (frameCounter % stuckCheckInterval == 0) {
      uint32_t currentConsumerOffset =
          inputQueue_->header->consumer_offset.load(std::memory_order_relaxed);
      uint32_t currentProducerOffset =
          outputQueue_->header->producer_offset.load(std::memory_order_relaxed);

      LOG_INFO("PROGRESS: Frame ", frameCounter,
               ", Input queue - consumer: ", currentConsumerOffset,
               ", Output queue - producer: ", currentProducerOffset,
               ", Last successful: ", lastSuccessfulFrame);

      // Check if we're potentially stuck by seeing if offsets haven't changed
      if (currentConsumerOffset == lastConsumerOffset &&
          currentProducerOffset == lastProducerOffset) {
        stuckFrameCounter++;
        if (stuckFrameCounter >= 3) { // Three consecutive stuck checks
          potentiallyStuck = true;
          LOG_ERROR("POTENTIAL HANG DETECTED! Queues haven't advanced in ",
                    (stuckFrameCounter * stuckCheckInterval),
                    " frames. Last successful frame: ", lastSuccessfulFrame,
                    ", Current: ", frameCounter);
        }
      } else {
        stuckFrameCounter = 0;
        potentiallyStuck = false;
      }

      lastConsumerOffset = currentConsumerOffset;
      lastProducerOffset = currentProducerOffset;
    }

    try {
      LOG_DEBUG("BEGIN: Starting to process frame ", frameCounter);

      // Check input queue size before processing
      size_t bytesAvailable = inputQueue_->getReadableBytes();
      LOG_DEBUG("INPUT: Available bytes before processing: ", bytesAvailable);

      // If we're potentially stuck, add extra diagnostics
      if (potentiallyStuck) {
        LOG_ERROR("DIAGNOSTIC: Processing potentially hanging frame ",
                  frameCounter, ", BytesAvailable: ", bytesAvailable,
                  ", InputOffset: ",
                  inputQueue_->header->consumer_offset.load(
                      std::memory_order_relaxed),
                  ", OutputOffset: ",
                  outputQueue_->header->producer_offset.load(
                      std::memory_order_relaxed));
      }

      processSingleFrame(frameCounter);

      LOG_DEBUG("END: Finished processing frame ", frameCounter);

      // Record successful frame
      lastSuccessfulFrame = frameCounter;
      frameCounter++;        // Increment frame counter for the next iteration
      consecutiveErrors = 0; // Reset error counter on success
    } catch (const std::exception &e) {
      consecutiveErrors++;
      LOG_ERROR("Caught exception in frame processing loop: ", e.what(),
                " (frame ", frameCounter, ", error #", consecutiveErrors, ")");

      // Output more debug info when an error occurs
      LOG_ERROR(
          "DIAGNOSTIC: Exception at frame ", frameCounter, ", InputOffset: ",
          inputQueue_->header->consumer_offset.load(std::memory_order_relaxed),
          ", OutputOffset: ",
          outputQueue_->header->producer_offset.load(std::memory_order_relaxed),
          ", BytesAvailable: ", inputQueue_->getReadableBytes());

      // Write a zero to output to unblock runner and advance consumer minimally
      LOG_INFO("Writing emergency 0 to output after exception");
      writeOutput(true, frameCounter);
      inputQueue_->advanceConsumer(MINIMAL_ALIGNED_ADVANCE_ON_ERROR);
      if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
        LOG_ERROR("Too many consecutive errors (", consecutiveErrors,
                  "), halting processing.");
        break;
      }
      // Sleep briefly before retrying
      _mm_pause();
      // Advance frame counter to avoid getting stuck
      frameCounter++;
    } catch (...) {
      consecutiveErrors++;
      LOG_ERROR("Caught unknown exception in frame processing loop ", "(frame ",
                frameCounter, ", error #", consecutiveErrors, ")");

      // Output more debug info when an error occurs
      LOG_ERROR(
          "DIAGNOSTIC: Unknown exception at frame ", frameCounter,
          ", InputOffset: ",
          inputQueue_->header->consumer_offset.load(std::memory_order_relaxed),
          ", OutputOffset: ",
          outputQueue_->header->producer_offset.load(std::memory_order_relaxed),
          ", BytesAvailable: ", inputQueue_->getReadableBytes());

      // Write a zero to output to unblock runner and advance consumer minimally
      LOG_INFO("Writing emergency 0 to output after unknown exception");
      writeOutput(true, frameCounter);
      inputQueue_->advanceConsumer(MINIMAL_ALIGNED_ADVANCE_ON_ERROR);
      if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
        LOG_ERROR("Too many consecutive errors (", consecutiveErrors,
                  "), halting processing.");
        break;
      }
      _mm_pause();
      // Advance frame counter to avoid getting stuck
      frameCounter++;
    }
  }

  LOG_INFO("Exiting frame processing loop (Queue mode) after frame ",
           (frameCounter - 1), ".");
}
