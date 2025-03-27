#include "pcap_reader.h"
#include "protocol_parser.h"
#include <iomanip>
#include <iostream>
#include <string>

void hexDump(const uint8_t *data, size_t size, size_t bytesPerLine = 16) {
  for (size_t i = 0; i < size; i += bytesPerLine) {
    // Print offset
    std::cout << std::setfill('0') << std::setw(8) << std::hex << i << ": ";

    // Print hex values
    for (size_t j = 0; j < bytesPerLine; j++) {
      if (i + j < size) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << static_cast<int>(data[i + j]) << " ";
      } else {
        std::cout << "   ";
      }
    }

    std::cout << " | ";

    // Print ASCII values
    for (size_t j = 0; j < bytesPerLine; j++) {
      if (i + j < size) {
        char c = data[i + j];
        if (c >= 32 && c <= 126) {
          std::cout << c;
        } else {
          std::cout << ".";
        }
      } else {
        std::cout << " ";
      }
    }

    std::cout << std::endl;
  }
  std::cout << std::dec; // Reset to decimal
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <pcap_file> <ip1> <ip2>"
              << std::endl;
    return 1;
  }

  std::string pcapFile = argv[1];
  uint32_t ip1 = ipStringToUint32(argv[2]);
  uint32_t ip2 = ipStringToUint32(argv[3]);

  std::cout << "Reading PCAP file: " << pcapFile << std::endl;
  std::cout << "Filtering for IPs: " << argv[2] << " (" << std::hex << ip1
            << ")"
            << " and " << argv[3] << " (" << ip2 << ")" << std::dec
            << std::endl;

  try {
    PcapReader reader(pcapFile);

    // Counter for frames
    int frameCount = 0;

    // Process frames with filtered IPs
    reader.processFilteredFrames(
        ip1, ip2,
        [&](const uint8_t *data, size_t size, uint32_t srcIP, uint32_t dstIP) {
          frameCount++;

          // Print basic frame info
          std::cout << "\n----------------------------------------"
                    << std::endl;
          std::cout << "Frame #" << frameCount << std::endl;
          std::cout << "Source IP: " << std::hex << srcIP << std::dec
                    << std::endl;
          std::cout << "Dest IP: " << std::hex << dstIP << std::dec
                    << std::endl;
          std::cout << "Payload size: " << size << " bytes" << std::endl;

          // Print frame header if it exists
          if (size >= sizeof(FrameHeader)) {
            const FrameHeader *header =
                reinterpret_cast<const FrameHeader *>(data);
            std::cout << "Frame header: dummy="
                      << static_cast<int>(header->dummy) << ", typeId=0x"
                      << std::hex << static_cast<int>(header->typeId)
                      << std::dec << ", length=" << header->length << std::endl;
          }

          // Dump first 64 bytes of the payload
          std::cout << "First 64 bytes of payload:" << std::endl;
          hexDump(data, std::min(size, size_t(64)));

          // Limit to first 5 frames for brevity
          if (frameCount >= 5) {
            return;
          }
        });

    std::cout << "\nTotal frames processed: " << frameCount << std::endl;

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}