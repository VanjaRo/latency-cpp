#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "orderbook.h"
#include "pcap_reader.h"
#include "protocol_logger.h"
#include "protocol_parser.h"
#include "shared_queue.h"

// For direct PCAPng reading (debugging mode)
#define DEBUG_PCAP_READING 1

// Process packets from input queue
void processPackets(SharedQueue &inputQueue, SharedQueue &outputQueue,
                    const std::string &metadataPath) {
  // Create orderbook manager
  OrderbookManager orderbookManager;
  orderbookManager.loadMetadata(metadataPath);

  // Create protocol parser
  ProtocolParser parser;

  // Process frames from the queue
  while (true) {
    // Check if there's enough data to read frame header
    if (inputQueue.getReadableBytes() < sizeof(FrameHeader)) {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
      continue;
    }

    // Read frame header
    const uint8_t *readPtr = inputQueue.getReadPtr();
    const FrameHeader *header = reinterpret_cast<const FrameHeader *>(readPtr);

    // Check if we have the entire frame
    uint32_t frameSize = sizeof(FrameHeader) + header->length;
    if (inputQueue.getReadableBytes() < frameSize) {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
      continue;
    }

    // Process the frame with callbacks
    bool isSnapshot =
        (header->typeId == static_cast<uint8_t>(MessageType::SNAPSHOT));
    bool vwapChanged = false;

    parser.parsePayload(
        readPtr, frameSize,
        // SnapshotInstrumentCallback
        [&](const InstrumentInfo &info) {
          orderbookManager.processSnapshot(info);
        },
        // SnapshotOrderbookCallback
        [&](int64_t instrumentId, Side side, double price, int64_t volume) {
          orderbookManager.processSnapshotOrderbook(instrumentId, side, price,
                                                    volume);
        },
        // UpdateHeaderCallback
        [&](const UpdateHeader &header) {
          orderbookManager.processUpdateHeader(header);
        },
        // UpdateEventCallback
        [&](const UpdateEvent &event) {
          orderbookManager.processUpdateEvent(event);
        });

    // Finalize update and prepare output
    if (!isSnapshot) {
      orderbookManager.finalizeUpdate();
      auto changedVWAPs = orderbookManager.getChangedVWAPs();

      if (changedVWAPs.empty()) {
        // No changes, write 0
        uint32_t *writePtr =
            reinterpret_cast<uint32_t *>(outputQueue.getWritePtr());
        *writePtr = 0;
        outputQueue.advanceProducer(sizeof(uint32_t));
      } else {
        // Write count and changed VWAPs
        uint8_t *writePtr = outputQueue.getWritePtr();
        uint32_t *countPtr = reinterpret_cast<uint32_t *>(writePtr);
        *countPtr = static_cast<uint32_t>(changedVWAPs.size());
        writePtr += sizeof(uint32_t);

        for (const auto &vwap : changedVWAPs) {
          uint32_t *dataPtr = reinterpret_cast<uint32_t *>(writePtr);
          *dataPtr = vwap.instrumentId;
          writePtr += sizeof(uint32_t);

          dataPtr = reinterpret_cast<uint32_t *>(writePtr);
          *dataPtr = vwap.numerator;
          writePtr += sizeof(uint32_t);

          dataPtr = reinterpret_cast<uint32_t *>(writePtr);
          *dataPtr = vwap.denominator;
          writePtr += sizeof(uint32_t);
        }

        outputQueue.advanceProducer(sizeof(uint32_t) +
                                    changedVWAPs.size() * 3 * sizeof(uint32_t));
      }
    } else {
      // For snapshots, just write 0
      uint32_t *writePtr =
          reinterpret_cast<uint32_t *>(outputQueue.getWritePtr());
      *writePtr = 0;
      outputQueue.advanceProducer(sizeof(uint32_t));
    }

    // Advance the consumer pointer in the input queue
    inputQueue.advanceConsumer(frameSize);
  }
}

#if DEBUG_PCAP_READING
// Read packets directly from pcap file for debugging
int debugPcapReading(const std::string &pcapFilename,
                     const std::string &metadataPath) {
  try {
    OrderbookManager orderbookManager;
    orderbookManager.loadMetadata(metadataPath);

    ProtocolParser parser;
    PcapReader pcapReader(pcapFilename);

    uint32_t snapshotIP = 0, updateIP = 0;

    // Extract IPs from metadata
    {
      std::ifstream metaFile(metadataPath);
      if (!metaFile) {
        throw std::runtime_error("Failed to open metadata file");
      }

      std::string line;
      if (std::getline(metaFile, line)) {
        std::istringstream iss(line);
        std::string ip1, ip2;
        if (iss >> ip1 >> ip2) {
          snapshotIP = ipStringToUint32(ip1);
          updateIP = ipStringToUint32(ip2);
        }
      }
    }

    // Process filtered frames
    pcapReader.processFilteredFrames(
        snapshotIP, updateIP,
        [&](const uint8_t *data, size_t size, uint32_t srcIP, uint32_t dstIP) {
          bool isSnapshot = (srcIP == snapshotIP);

          parser.parsePayload(
              data, size,
              // SnapshotInstrumentCallback
              [&](const InstrumentInfo &info) {
                orderbookManager.processSnapshot(info);
              },
              // SnapshotOrderbookCallback
              [&](int64_t instrumentId, Side side, double price,
                  int64_t volume) {
                orderbookManager.processSnapshotOrderbook(instrumentId, side,
                                                          price, volume);
              },
              // UpdateHeaderCallback
              [&](const UpdateHeader &header) {
                orderbookManager.processUpdateHeader(header);
              },
              // UpdateEventCallback
              [&](const UpdateEvent &event) {
                orderbookManager.processUpdateEvent(event);
              });

          // Finalize update if it's an incremental update
          if (!isSnapshot) {
            orderbookManager.finalizeUpdate();
            auto changedVWAPs = orderbookManager.getChangedVWAPs();

            // Print changed VWAPs for debugging
            if (!changedVWAPs.empty()) {
              std::cout << "VWAP changes: " << changedVWAPs.size() << std::endl;
              for (const auto &vwap : changedVWAPs) {
                std::cout << "  InstrumentID: " << vwap.instrumentId
                          << ", VWAP: " << vwap.numerator << "/"
                          << vwap.denominator << std::endl;
              }
            }
          }
        });

    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}
#endif

int main(int argc, char *argv[]) {
  // Log the compile-time log level
  LOG_INFO("Application started with compile-time log level: ",
           COMPILE_TIME_LOG_LEVEL_STR);

  // --- Argument Parsing (Simplified) ---
  std::vector<std::string> args(argv + 1, argv + argc); // Exclude program name

  // --- Mode Selection based on remaining args ---
#if DEBUG_PCAP_READING
  // If args match debug mode (2 args: pcap, metadata)
  if (args.size() == 2) {
    LOG_INFO("Running in DEBUG_PCAP_READING mode.");
    return debugPcapReading(args[0], args[1]);
  }
#endif

  // Check for normal mode arguments (6 args)
  if (args.size() != 6) {
    std::cerr << "Usage: " << argv[0]
              << " <input_header> <input_buffer> <output_header> "
                 "<output_buffer> <buffer_size> <metadata_path>"
              << std::endl;
#if DEBUG_PCAP_READING
    std::cerr << "   or: " << argv[0] << " <pcap_file> <metadata_path>"
              << std::endl;
#endif
    return 1;
  }

  // Normal mode
  LOG_INFO("Running in normal mode.");
  try {
    std::string inputHeaderPath = args[0];
    std::string inputBufferPath = args[1];
    std::string outputHeaderPath = args[2];
    std::string outputBufferPath = args[3];
    size_t bufferSize = std::stoull(args[4]);
    std::string metadataPath = args[5];

    // Create shared queues
    SharedQueue inputQueue(inputHeaderPath, inputBufferPath, bufferSize, false);
    SharedQueue outputQueue(outputHeaderPath, outputBufferPath, bufferSize,
                            true);

    // Process packets
    processPackets(inputQueue, outputQueue, metadataPath);

    return 0;
  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}