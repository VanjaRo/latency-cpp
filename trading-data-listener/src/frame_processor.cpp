#include "frame_processor.h"
#include "protocol_logger.h"
#include "shared_queue.h"
#include <emmintrin.h>
#include <iostream> // For PCAP direct mode output

#include <arpa/inet.h> // For ntohs, ntohl, inet_pton
#include <chrono>
#include <cstring> // For memcpy
#include <fstream>
#include <immintrin.h>
#include <netinet/if_ether.h> // Include for ETHERTYPE_IP
#include <sstream>
#include <stdexcept>
#include <thread>

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

constexpr uint32_t ETHERNET_FCS_LENGTH = 4;

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
        LOG_INFO("Note: IP-based message type detection is now deprecated, "
                 "using message header instead");
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

// Helper to apply unified spin/yield/sleep backoff
void FrameProcessor::backoffDelay(int &counter) {
  _mm_pause();
  ++counter;
}

// Helper function to parse the next packet from the input queue
FrameProcessor::PacketInfo
FrameProcessor::parseNextPacket(uint64_t frameCounter) {
  PacketInfo info;
  const size_t min_alignment = 8;
  const size_t min_eth_header_alignment =
      SharedQueue::align8(sizeof(EthernetHeader));
  const size_t min_ip_header_size =
      sizeof(EthernetHeader) + sizeof(IPv4Header); // Eth=14, IPv4=20 -> 34
  const int max_retries =
      15; // Maximum number of retry attempts before giving up
  int retry_count = 0;

  // 1. Wait for minimum Ethernet alignment data
  while (!waitForBytes(sizeof(EthernetHeader), frameCounter, "ETH_ALIGN")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for ETH_ALIGN. Will keep waiting.");

    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for ETH_ALIGN. Returning "
                "invalid packet.");
      info.valid = false;
      info.alignedFrameSize =
          min_alignment; // Set size to advance by minimal amount
      return info;
    }

    // unified backoff before retrying
    backoffDelay(retry_count);
  }

  info.bytesAvailableWhenParsed =
      inputQueue_->getReadableBytes(); // Initial read

  // 2. Peek at Ethernet Header
  info.rawDataStart = inputQueue_->getReadPtr();
  if (!info.rawDataStart) {
    LOG_ERROR("[Frame ", frameCounter,
              "] getReadPtr() returned nullptr after ETH_ALIGN wait! Returning "
              "invalid packet.");
    info.valid = false;
    info.alignedFrameSize = min_alignment;
    return info;
  }
  info.ethHeader = reinterpret_cast<const EthernetHeader *>(info.rawDataStart);

  //   Debug ethernet header print
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
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing etherType. Possible corrupted "
              "buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  }

  // 3. Handle non-IP frames
  if (info.etherType != ETHERTYPE_IP) {
    LOG_WARN("[Frame ", frameCounter, "] Skipping non-IP frame (EtherType: 0x",
             std::hex, info.etherType, std::dec, ")");
    info.valid = false; // Mark as invalid/skip
    info.alignedFrameSize =
        min_eth_header_alignment; // Set size to advance by minimal amount
    return info;
  }

  // 4. Wait for full Ethernet + minimum IP header
  retry_count = 0;
  while (!waitForBytes(min_ip_header_size, frameCounter, "IP_HEADER")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for IP_HEADER. Will keep waiting.");

    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for IP_HEADER. Returning "
                "invalid packet.");
      info.valid = false;
      info.alignedFrameSize = min_eth_header_alignment;
      return info;
    }

    // unified backoff before retrying
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
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  }
  info.ethHeader = reinterpret_cast<const EthernetHeader *>(info.rawDataStart);
  info.ipHeader = reinterpret_cast<const IPv4Header *>(info.rawDataStart +
                                                       sizeof(EthernetHeader));

  // 5. Extract and Validate IP Header fields
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
      info.alignedFrameSize = min_eth_header_alignment; // Minimal advance
      return info;
    }
    if (info.ipHeaderLength < 20) { // Minimum IPv4 header size
      LOG_WARN("[Frame ", frameCounter,
               "] Skipping packet with invalid IP header length: ",
               info.ipHeaderLength);
      info.valid = false;
      info.alignedFrameSize = min_eth_header_alignment; // Minimal advance
      return info;
    }
    if (info.ipTotalLength < info.ipHeaderLength) {
      LOG_WARN("[Frame ", frameCounter,
               "] Skipping packet with IP total length (", info.ipTotalLength,
               ") < IP header length (", info.ipHeaderLength, ").");
      info.valid = false;
      info.alignedFrameSize = min_eth_header_alignment; // Minimal advance
      return info;
    }

  } catch (const std::exception &e) { // Catch specific standard exceptions
    LOG_ERROR("[Frame ", frameCounter,
              "] Exception accessing IP Header fields: ", e.what(),
              " Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing IP Header fields. Possible "
              "corrupted buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  }

  // 6. Calculate required frame size and wait for it
  info.frameSize =
      sizeof(EthernetHeader) + info.ipTotalLength + ETHERNET_FCS_LENGTH;
  info.alignedFrameSize = SharedQueue::align8(info.frameSize);
  LOG_TRACE("[Frame ", frameCounter, "] Calculated frameSize=", info.frameSize,
            ", alignedFrameSize=", info.alignedFrameSize);

  retry_count = 0;
  while (!waitForBytes(info.frameSize, frameCounter, "FRAME_DATA")) {
    LOG_WARN("[Frame ", frameCounter, "] waitForBytes failed (attempt ",
             retry_count, ") while waiting for FRAME_DATA (", info.frameSize,
             " bytes). Will keep waiting.");

    if (retry_count >= max_retries) {
      LOG_ERROR("[Frame ", frameCounter,
                "] Multiple waitForBytes failures for FRAME_DATA. Returning "
                "invalid packet.");
      info.valid = false;
      info.alignedFrameSize = min_eth_header_alignment;
      return info;
    }

    // unified backoff before retrying
    backoffDelay(retry_count);
  }

  info.bytesAvailableWhenParsed = inputQueue_->getReadableBytes();

  // 7. Re-get pointers and extract UDP info (if applicable)
  info.rawDataStart = inputQueue_->getReadPtr();
  if (!info.rawDataStart) {
    LOG_ERROR("[Frame ", frameCounter,
              "] getReadPtr() returned nullptr after frame data wait! "
              "Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = min_eth_header_alignment;
    return info;
  }

  // 8. Check if this is from one of our target IPs
  info.isTargetIP =
      (info.sourceIP == snapshotIP_ || info.sourceIP == updateIP_);

  if (!info.isTargetIP) {
    LOG_TRACE("[Frame ", frameCounter, "] Skipping frame from non-target IP.");
    info.valid = false; // Mark as skip
    // Keep alignedFrameSize as calculated, since we waited for it
    return info;
  }

  if (info.ipProtocol != IPPROTO_UDP) {
    LOG_WARN("[Frame ", frameCounter,
             "] Skipping non-UDP packet from target IP (Proto: ",
             info.ipProtocol, ")");
    info.valid = false; // Mark as skip
    // Keep alignedFrameSize
    return info;
  }

  // 9. Process UDP Header and extract payload
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
        // Potentially adjust info.payloadLength here if needed, but sticking to
        // UDP header value
      }

      // Boundary check: Ensure payload doesn't read past the received frame
      // data
      const uint8_t *frameEndBasedOnIp =
          info.rawDataStart + info.frameSize -
          ETHERNET_FCS_LENGTH; // End of IP payload
      const uint8_t *payloadEnd = info.payload + info.payloadLength;

      if (payloadEnd > frameEndBasedOnIp) {
        LOG_ERROR("[Frame ", frameCounter, "] Calculated UDP payload (offset ",
                  (payloadEnd - info.rawDataStart),
                  ") exceeds IP frame boundary (size ", info.frameSize,
                  "). Clamping payload length.");
        // Adjust payload length to prevent reading out of bounds
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
          info.payload = nullptr; // No valid payload
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
                                : min_eth_header_alignment;
    return info;
  } catch (...) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Unknown exception accessing UDP Header/Payload. Possible "
              "corrupted buffer. Returning invalid packet.");
    info.valid = false;
    info.alignedFrameSize = info.alignedFrameSize > 0
                                ? info.alignedFrameSize
                                : min_eth_header_alignment;
    return info;
  }

  // If we reached here with a valid payload, mark the packet as valid
  info.valid = (info.payload != nullptr && info.payloadLength > 0);

  if (!info.valid) {
    LOG_DEBUG("[Frame ", frameCounter,
              "] Packet from target IP has no valid payload");
  }

  return info;
}

// Helper function to write output to the queue
void FrameProcessor::writeOutput(bool isSnapshotOrError,
                                 uint64_t frameCounter) {
  if (usePcap_) [[unlikely]] {
    // PCAP direct mode: print output to stdout
    if (isSnapshotOrError) {
      std::cout << 0 << std::endl;
    } else {
      auto updatedInstruments = orderbookManager_.getUpdatedInstruments();
      if (updatedInstruments.empty()) {
        std::cout << 0 << std::endl;
      } else {
        std::cout << updatedInstruments.size();
        for (const auto &vwap : updatedInstruments) {
          std::cout << " " << vwap.instrumentId << " " << vwap.numerator << " "
                    << vwap.denominator;
        }
        std::cout << std::endl;
      }
      orderbookManager_.clearChangedVWAPs();
    }
    return;
  }
  const size_t output_size_zero = sizeof(uint32_t);
  const size_t output_size_result_triple = 3 * sizeof(uint32_t);

  if (isSnapshotOrError) {
    // Write 0 for snapshot or error cases
    LOG_TRACE("[Frame ", frameCounter,
              "] Preparing to write output: 0 (Snapshot/Error)");
    int wait_cycles = 0;
    while (!outputQueue_->canWrite(output_size_zero)) {
      if (wait_cycles % 10000 == 0) {
        uint32_t prod = outputQueue_->header->producer_offset.load(
            std::memory_order_relaxed);
        uint32_t cons = outputQueue_->header->consumer_offset.load(
            std::memory_order_relaxed);
        LOG_WARN("[Frame ", frameCounter,
                 "] Waiting to write 0 to output queue... (Prod:", prod,
                 " Cons:", cons, ")");
      }
      // unified backoff
      backoffDelay(wait_cycles);
    }
    LOG_DEBUG("[Frame ", frameCounter,
              "] Output queue has space for 0. Writing...");
    uint32_t *writePtr =
        reinterpret_cast<uint32_t *>(outputQueue_->getWritePtr());
    *writePtr = 0;
    outputQueue_->advanceProducer(output_size_zero);
    LOG_TRACE("[Frame ", frameCounter, "] Wrote output: 0 (Snapshot/Error)");
  } else {
    // Get instruments that were updated in this frame and have valid orderbooks
    auto updatedInstruments = orderbookManager_.getUpdatedInstruments();

    if (updatedInstruments.empty()) {
      // Write 0 if no updated instruments with valid orderbooks
      LOG_TRACE("[Frame ", frameCounter,
                "] Preparing to write output: 0 (No updated instruments)");
      int wait_cycles = 0;
      while (!outputQueue_->canWrite(output_size_zero)) {
        if (wait_cycles % 10000 == 0) {
          uint32_t prod = outputQueue_->header->producer_offset.load(
              std::memory_order_relaxed);
          uint32_t cons = outputQueue_->header->consumer_offset.load(
              std::memory_order_relaxed);
          LOG_WARN("[Frame ", frameCounter,
                   "] Waiting to write 0 (no updated instruments) to output "
                   "queue... (Prod:",
                   prod, " Cons:", cons, ")");
        }
        // unified backoff
        backoffDelay(wait_cycles);
      }
      LOG_DEBUG("[Frame ", frameCounter,
                "] Output queue has space for 0 (no updated instruments). "
                "Writing...");
      uint32_t *writePtr =
          reinterpret_cast<uint32_t *>(outputQueue_->getWritePtr());
      *writePtr = 0;
      outputQueue_->advanceProducer(output_size_zero);
      LOG_TRACE("[Frame ", frameCounter,
                "] Wrote output: 0 (No updated instruments)");
    } else {
      // Write all updated instruments' VWAPs
      size_t totalBytesToWrite =
          sizeof(uint32_t) +
          updatedInstruments.size() * output_size_result_triple;
      LOG_TRACE("[Frame ", frameCounter, "] Preparing to write ",
                updatedInstruments.size(), " instrument VWAPs (",
                totalBytesToWrite, " bytes)");
      int wait_cycles = 0;
      while (!outputQueue_->canWrite(totalBytesToWrite)) {
        if (wait_cycles % 10000 == 0) {
          uint32_t prod = outputQueue_->header->producer_offset.load(
              std::memory_order_relaxed);
          uint32_t cons = outputQueue_->header->consumer_offset.load(
              std::memory_order_relaxed);
          LOG_WARN("[Frame ", frameCounter, "] Waiting to write ",
                   updatedInstruments.size(), " VWAPs (", totalBytesToWrite,
                   " bytes) to output queue... (Prod:", prod, " Cons:", cons,
                   ")");
        }
        // unified backoff
        backoffDelay(wait_cycles);
      }
      LOG_TRACE("[Frame ", frameCounter, "] Output queue has space for ",
                updatedInstruments.size(), " VWAPs. Writing...");

      uint8_t *writePtr = outputQueue_->getWritePtr();
      uint32_t count = static_cast<uint32_t>(updatedInstruments.size());
      // Write count directly via pointer for speed
      *reinterpret_cast<uint32_t *>(writePtr) = count;
      writePtr += sizeof(uint32_t);

      // Only log the number of VWAPs being written
      LOG_TRACE("[Frame ", frameCounter, "] Writing ", count, " VWAP values");

      // In detailed trace mode, identify VWAP updates for this frame
      if (COMPILE_TIME_LOG_LEVEL >= static_cast<int>(LogLevel::TRACE)) {
        int updatedCount = 0;

        // Count once to avoid repeating the isVWAPChanged check
        for (const auto &vwap : updatedInstruments) {
          if (orderbookManager_.isVWAPChanged(vwap.instrumentId)) {
            updatedCount++;
            LOG_TRACE("  -> Updated VWAP: ID:", vwap.instrumentId,
                      " N:", vwap.numerator, " D:", vwap.denominator);
          }
        }

        if (updatedCount > 0) {
          LOG_TRACE("[Frame ", frameCounter, "] Of ", count,
                    " updated instruments, ", updatedCount,
                    " had value updates in this frame");
        } else {
          LOG_TRACE(
              "[Frame ", frameCounter, "] All ", count,
              " instruments were updated but none had value changes in this "
              "frame");
        }
      }

      // Write the actual data
      for (const auto &vwap : updatedInstruments) {
        // Write VWAP fields directly via pointer for speed
        *reinterpret_cast<uint32_t *>(writePtr) = vwap.instrumentId;
        writePtr += sizeof(uint32_t);
        *reinterpret_cast<uint32_t *>(writePtr) = vwap.numerator;
        writePtr += sizeof(uint32_t);
        *reinterpret_cast<uint32_t *>(writePtr) = vwap.denominator;
        writePtr += sizeof(uint32_t);
      }

      outputQueue_->advanceProducer(totalBytesToWrite);
      LOG_TRACE("[Frame ", frameCounter, "] Advanced output producer by ",
                totalBytesToWrite);
    }
    // We still clear the VWAP changed flags after writing
    orderbookManager_.clearChangedVWAPs();
  }
}

// Helper function to process a valid packet's payload
bool FrameProcessor::processPacketPayload(const PacketInfo &packetInfo,
                                          uint64_t frameCounter) {
  if (!packetInfo.payload || packetInfo.payloadLength == 0) {
    LOG_ERROR("[Frame ", frameCounter,
              "] Called processPacketPayload with empty payload");
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
    LOG_WARN("[Frame ", frameCounter,
             "] Packet resulted in 0 alignedFrameSize (Likely non-IP or "
             "invalid header). Advancing by minimum 8 bytes.");
    inputQueue_->advanceConsumer(SharedQueue::align8(8));
    [[maybe_unused]] uint32_t newOffset =
        inputQueue_->header->consumer_offset.load(std::memory_order_relaxed);
    LOG_DEBUG("[Frame ", frameCounter, "] Consumer advanced from ",
              currentOffset, " to ", newOffset,
              " (delta: ", (newOffset - currentOffset), ")");
  }
}

// Helper function to process a single frame from the input queue
void FrameProcessor::processSingleFrame(uint64_t frameCounter) {
  LOG_DEBUG("[Frame ", frameCounter, "] ----- Start Processing -----");

  // 1. Parse the next packet (network level)
  PacketInfo packetInfo = parseNextPacket(frameCounter);

  // 2. Handle invalid/skipped packets - write 0 to output and advance
  if (!packetInfo.valid) {
    LOG_DEBUG("[Frame ", frameCounter, "] Invalid packet, writing 0 to output");
    writeOutput(true, frameCounter); // Write 0 for invalid packets
    advanceInputQueue(packetInfo, frameCounter);
    return;
  }

  // 3. Process payload (application level)
  bool processingError = processPacketPayload(packetInfo, frameCounter);

  // 4. Determine if this is a snapshot message by asking the protocol parser
  MessageType msgType = ProtocolParser::detectMessageType(
      packetInfo.payload, packetInfo.payloadLength);
  bool isSnapshotMessage = (msgType == MessageType::SNAPSHOT);

  LOG_DEBUG("[Frame ", frameCounter, "] Processing error: ", processingError,
            " messageType: ", static_cast<int>(msgType),
            " isSnapshot: ", isSnapshotMessage);

  // 5. Write Output
  // Write 0 if it was a snapshot message OR if a processing error occurred
  writeOutput(isSnapshotMessage || processingError, frameCounter);

  // 6. Advance Input Queue Consumer
  advanceInputQueue(packetInfo, frameCounter);

  LOG_TRACE("[Frame ", frameCounter, "] ----- End Processing -----");
}

// Main processing loop for Queue mode
void FrameProcessor::runQueue() {
  LOG_INFO("Starting frame processing loop (Queue mode).");

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

  while (true) {
    try {
      processSingleFrame(frameCounter);
      frameCounter++;        // Increment frame counter for the next iteration
      consecutiveErrors = 0; // Reset error counter on success
    } catch (const std::exception &e) {
      consecutiveErrors++;
      LOG_ERROR("Caught exception in frame processing loop: ", e.what(),
                " (frame ", frameCounter, ", error #", consecutiveErrors, ")");
      // Write a zero to output to unblock runner and advance consumer minimally
      writeOutput(true, frameCounter);
      inputQueue_->advanceConsumer(SharedQueue::align8(8));
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
      // Write a zero to output to unblock runner and advance consumer minimally
      writeOutput(true, frameCounter);
      inputQueue_->advanceConsumer(SharedQueue::align8(8));
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
