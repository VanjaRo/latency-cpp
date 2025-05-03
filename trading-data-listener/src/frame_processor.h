#pragma once

#include "orderbook.h"
#include "protocol_parser.h"
#include "shared_queue.h"
#include <cstdint>
#include <memory>
#include <set>
#include <string>

// Always forward declare ipStringToUint32 to ensure it's available regardless
// of USE_LIGHTPCAPNG
uint32_t ipStringToUint32(const std::string &ipStr);

// Define header structures and PcapReader based on whether LightPcapNg is
// enabled
#if USE_LIGHTPCAPNG == 1
// When LightPcapNg is enabled, include pcap_reader.h
#include "pcap_reader.h"
#else
// When LightPcapNg is disabled, define our own structures and a stub PcapReader
#include <functional>
#include <stdexcept>

// Network header structures
#pragma pack(push, 1)
struct EthernetHeader {
  uint8_t destMac[6];
  uint8_t srcMac[6];
  uint16_t etherType;
};

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

struct UDPHeader {
  uint16_t sourcePort;
  uint16_t destPort;
  uint16_t length;
  uint16_t checksum;
};
#pragma pack(pop)

// Define FrameCallback type to match the one in pcap_reader.h
using FrameCallback =
    std::function<void(const uint8_t *, size_t, uint32_t, uint32_t)>;

// Stub implementation of PcapReader
class PcapReader {
public:
  explicit PcapReader(const std::string &) {
    throw std::runtime_error(
        "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled");
  }
  ~PcapReader() = default;

  void processAllFrames(const FrameCallback &) {
    throw std::runtime_error(
        "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled");
  }

  void processFilteredFrames(uint32_t, uint32_t, const FrameCallback &) {
    throw std::runtime_error(
        "PcapReader is disabled because USE_LIGHTPCAPNG is not enabled");
  }
};
#endif // End of USE_LIGHTPCAPNG != 1 block

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
  // Backoff parameters for busy-wait loops
  static constexpr int BACKOFF_SPIN_LIMIT = 50;
  static constexpr int BACKOFF_YIELD_LIMIT = 100;

  // Helper to apply unified spin/yield/sleep backoff
  static void backoffDelay(int &counter);

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
    uint32_t sourceIP = 0;   // Network byte order
    bool isTargetIP = false; // Whether this is from one of our target IPs
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
  uint32_t snapshotIP_ = 0; // Used for filtering packets
  uint32_t updateIP_ = 0;   // Used for filtering packets
  std::set<std::string> targetInstruments_;

  // Helper function to load metadata (IPs and instruments)
  bool loadMetadata();

  // Runs the processing loop for PCAP input
  void runPcap();

  // Runs the processing loop for Queue input (existing logic)
  void runQueue();

  // Network-level packet parsing
  PacketInfo parseNextPacket(uint64_t frameCounter);

  // Process a valid packet's payload by sending to protocol parser
  bool processPacketPayload(const PacketInfo &packetInfo,
                            uint64_t frameCounter);

  // Process a single frame from the input queue (main processing function)
  void processSingleFrame(uint64_t frameCounter);

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