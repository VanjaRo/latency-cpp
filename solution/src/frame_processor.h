#pragma once

#include "orderbook.h"
#include "pcap_reader.h"
#include "protocol_parser.h"
#include "shared_queue.h"
#include <cstdint>
#include <memory>
#include <set>
#include <string>

// Forward declare header structs if not already included via pcap_reader.h
// (Good practice if pcap_reader.h isn't strictly necessary for this header)
struct EthernetHeader;
struct IPv4Header;
struct UDPHeader;

class FrameProcessor {
public:
  // Constructor for Shared Queue mode
  FrameProcessor(SharedQueue &inputQueue, SharedQueue &outputQueue,
                 const std::string &metadataPath);

  // Constructor for PCAP Debug mode
  FrameProcessor(const std::string &pcapFilename,
                 const std::string &metadataPath);

  // Runs the main processing loop (either queue or pcap)
  void run();

private:
  // --- Helper Struct for Parsed Packet Data ---
  struct PacketInfo {
    bool valid =
        false; // Was parsing successful and is this a packet we care about?
    const uint8_t *rawDataStart =
        nullptr; // Pointer to the start of raw frame data read
    const EthernetHeader *ethHeader = nullptr;
    const IPv4Header *ipHeader = nullptr;
    const UDPHeader *udpHeader = nullptr;
    const uint8_t *payload = nullptr;
    size_t payloadLength = 0;
    uint16_t etherType = 0;
    uint8_t ipHeaderLength = 0; // In bytes
    uint16_t ipTotalLength = 0; // In bytes
    uint8_t ipProtocol = 0;
    uint32_t sourceIP = 0; // Network byte order
    bool isSnapshot = false;
    bool isUpdate = false;
    size_t frameSize = 0; // Actual size based on IP totalLength + headers + FCS
    size_t alignedFrameSize = 0; // Frame size rounded up to 8-byte alignment
    size_t bytesAvailableWhenParsed = 0; // Debug/diagnostic info
  };

  // Mode flag
  bool usePcap_;

  // Members for Queue mode
  SharedQueue *inputQueue_ = nullptr;
  SharedQueue *outputQueue_ = nullptr;

  // Members for PCAP mode
  std::string pcapFilename_;
  std::unique_ptr<PcapReader> pcapReader_ = nullptr;

  // Common members
  std::string metadataPath_;
  OrderbookManager orderbookManager_;
  ProtocolParser protocolParser_;
  uint32_t snapshotIP_ = 0;
  uint32_t updateIP_ = 0;
  std::set<std::string> targetInstruments_;

  // Helper function to load metadata (IPs and instruments)
  bool loadMetadata();

  // Runs the processing loop for PCAP input
  void runPcap();

  // Runs the processing loop for Queue input (existing logic)
  void runQueue();

  // Helper to parse the next packet from the input queue
  PacketInfo parseNextPacket(uint64_t frameCounter);

  // Helper function to process a single frame from the input queue
  void processSingleFrame(uint64_t frameCounter);

  // Helper function to process the payload of a valid packet
  // Returns true if a processing error occurred, false otherwise.
  bool processPayload(const PacketInfo &packetInfo, uint64_t frameCounter);

  // Helper function to advance the input queue consumer
  void advanceInputQueue(const PacketInfo &packetInfo, uint64_t frameCounter);

  // Helper to wait for a specific number of bytes in the input queue
  bool waitForBytes(size_t requiredBytes, uint64_t frameCounter,
                    const char *waitReason);

  // Helper to write results to the output queue
  void writeOutput(bool isSnapshotOrError, uint64_t frameCounter);

  // Helper to convert IP string to uint32_t
  uint32_t ipStringToUint32(const std::string &ip_str);
};