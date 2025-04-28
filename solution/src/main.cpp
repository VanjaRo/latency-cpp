#include <iostream>
#include <memory>    // For std::unique_ptr
#include <stdexcept> // For std::runtime_error, std::stoull
#include <string>
#include <vector>

#include "frame_processor.h" // Include the new processor
#include "protocol_logger.h" // Keep for logging
#include "shared_queue.h"
// pcap_reader.h is included via frame_processor.h if needed

int main(int argc, char *argv[]) {
  std::ios_base::sync_with_stdio(false);
  LOG_INFO("Application started with compile-time log level: ",
           COMPILE_TIME_LOG_LEVEL_STR);

  // Declare pointers outside the if block
  std::unique_ptr<SharedQueue> inputQueuePtr = nullptr;
  std::unique_ptr<SharedQueue> outputQueuePtr = nullptr;
  std::unique_ptr<FrameProcessor> processor = nullptr;

  try {
    if (argc == 3) {
      // PCAP Debug Mode
      std::string pcapFilename = argv[1];
      std::string metadataPath = argv[2];

      // Check if LightPcapNg support is enabled
#if USE_LIGHTPCAPNG != 1
      LOG_ERROR(
          "PCAP mode is not available because USE_LIGHTPCAPNG is not enabled.");
      LOG_ERROR("Please rebuild with ./build.sh --with-lightpcapng to enable "
                "PCAP support.");
      std::cerr << "Error: PCAP mode requires LightPcapNg support. Rebuild "
                   "with --with-lightpcapng."
                << std::endl;
      return 1;
#endif

      LOG_INFO("Running in PCAP mode.");
      LOG_INFO("PCAP File: ", pcapFilename);
      LOG_INFO("Metadata Path: ", metadataPath);
      LOG_DEBUG("Creating FrameProcessor for PCAP...");
      // Queues are not needed for PCAP mode processor
      processor = std::make_unique<FrameProcessor>(pcapFilename, metadataPath);
      LOG_DEBUG("FrameProcessor for PCAP created.");

    } else if (argc == 7) {
      // Shared Queue Mode
      std::string inputHeaderPath = argv[1];
      std::string inputBufferPath = argv[2];
      std::string outputHeaderPath = argv[3];
      std::string outputBufferPath = argv[4];
      size_t bufferSize = std::stoull(argv[5]);
      std::string metadataPath = argv[6];

      LOG_INFO("Running in Shared Queue mode.");
      LOG_INFO("Input Header: ", inputHeaderPath);
      LOG_INFO("Input Buffer: ", inputBufferPath);
      LOG_INFO("Output Header: ", outputHeaderPath);
      LOG_INFO("Output Buffer: ", outputBufferPath);
      LOG_INFO("Buffer Size: ", bufferSize);
      LOG_INFO("Metadata Path: ", metadataPath);

      LOG_DEBUG("Creating Input SharedQueue...");
      // Allocate queues on the heap, manage with unique_ptr
      inputQueuePtr = std::make_unique<SharedQueue>(
          inputHeaderPath, inputBufferPath, bufferSize, false); // Consumer
      LOG_DEBUG("Input SharedQueue created.");

      LOG_DEBUG("Creating Output SharedQueue...");
      outputQueuePtr = std::make_unique<SharedQueue>(
          outputHeaderPath, outputBufferPath, bufferSize, true); // Producer
      LOG_DEBUG("Output SharedQueue created.");

      // Ensure queues were created successfully before proceeding
      if (!inputQueuePtr || !outputQueuePtr) {
        throw std::runtime_error("Failed to allocate SharedQueue objects.");
      }

      LOG_DEBUG("Creating FrameProcessor for Queues...");
      // Pass the actual queue objects by reference (dereference the pointers)
      processor = std::make_unique<FrameProcessor>(
          *inputQueuePtr, *outputQueuePtr, metadataPath);
      LOG_DEBUG("FrameProcessor for Queues created.");

    } else {
      std::cerr << "Usage: " << argv[0] << " <pcap_file> <metadata_path>"
                << std::endl;
      std::cerr << "   or: " << argv[0]
                << " <input_header> <input_buffer> <output_header> "
                   "<output_buffer> <buffer_size> <metadata_path>"
                << std::endl;
      return 1;
    }

    // Ensure processor was created
    if (!processor) {
      throw std::runtime_error("FrameProcessor was not initialized.");
    }

    // Run the processor (either mode)
    LOG_DEBUG("Calling processor->run()...");
    processor->run();
    // Queues managed by unique_ptr will be automatically cleaned up
    // when main exits or if an exception occurs after their creation.
    LOG_DEBUG("processor->run() returned (only expected in PCAP mode).");

    // If PCAP mode, run() finishes. If Queue mode, it loops indefinitely.
    if (argc == 3) {
      LOG_INFO("PCAP processing finished successfully.");
    }

    return 0;

  } catch (const std::exception &e) {
    LOG_ERROR("Critical Error: ", e.what());
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
  }
}