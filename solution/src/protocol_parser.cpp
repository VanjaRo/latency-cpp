#include "protocol_parser.h"
#include "orderbook.h"
#include "protocol_logger.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory_resource>
#include <sstream>
#include <stdexcept>

// Decode ZigZag encoded vint
int64_t ProtocolParser::decodeVInt(const uint8_t *data, size_t &offset,
                                   size_t available_bytes) {
  uint64_t unsigned_result = 0;
  int shift = 0;

  while (true) {
    if (offset >= available_bytes) {
      throw std::runtime_error(
          "Variable-length integer read past end of buffer");
    }
    uint8_t byte = data[offset++];
    unsigned_result |= static_cast<uint64_t>(byte & 0x7F) << shift;
    if (!(byte & 0x80)) {
      break;
    }
    shift += 7;
    if (shift >= 64) { // Varint too long or malformed
      throw std::runtime_error(
          "Variable-length integer is too long or malformed");
    }
  }
  // ZigZag decode: (unsigned_result >> 1) ^ -(unsigned_result & 1)
  return (unsigned_result >> 1) ^ (-(int64_t)(unsigned_result & 1));
}

// Constants for header skips
constexpr size_t SNAPSHOT_HEADER_SKIP = 4;
constexpr size_t UPDATE_HEADER_SKIP = 20;

// Constants for INSTRUMENT_INFO field layout
constexpr size_t INSTRUMENT_NAME_LEN = 31;
constexpr size_t INSTRUMENT_UNUSED_LEN = 61;
constexpr size_t INSTRUMENT_TICK_SIZE_LEN = sizeof(double);
constexpr size_t INSTRUMENT_REFERENCE_PRICE_LEN = sizeof(double);
constexpr size_t INSTRUMENT_ID_LEN = sizeof(int32_t);
constexpr size_t INSTRUMENT_INFO_TOTAL_LEN =
    INSTRUMENT_NAME_LEN + INSTRUMENT_UNUSED_LEN + INSTRUMENT_TICK_SIZE_LEN +
    INSTRUMENT_REFERENCE_PRICE_LEN + INSTRUMENT_ID_LEN; // Should be 112

#ifndef NDEBUG
// Helper function to dump hex bytes for debugging
void ProtocolParser::dumpHexBytes(const uint8_t *data, size_t size,
                                  const char *prefix) {
  constexpr size_t MAX_DUMP = 64; // Maximum bytes to dump
  size_t dumpSize = std::min(size, MAX_DUMP);

  std::ostringstream oss;
  oss << prefix << " (" << size << " bytes): ";

  for (size_t i = 0; i < dumpSize; ++i) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%02x ", data[i]);
    oss << buf;
    if ((i + 1) % 16 == 0 && i < dumpSize - 1) {
      oss << "\n                    ";
    }
  }

  if (size > MAX_DUMP) {
    oss << "... (" << (size - MAX_DUMP) << " more bytes)";
  }

  LOG_DEBUG(oss.str());
}
#endif

void ProtocolParser::parsePayload(const uint8_t *data, size_t size) {
  size_t current_offset = 0; // Need an offset to track position
  LOG_DEBUG("Starting to parse UDP payload of size ", size, " bytes");
  dumpHexBytes(data, std::min(size, static_cast<size_t>(32)),
               "Payload starts with");

  // Make sure we can at least read a header
  if (size < sizeof(FrameHeader)) {
    LOG_ERROR("UDP payload too small to contain even a single frame header: ",
              size, " bytes < ", sizeof(FrameHeader), " bytes");
    return;
  }

  while (current_offset + sizeof(FrameHeader) <= size) { // Check if header fits
    // Important sanity check - ensure we haven't advanced too far
    if (current_offset >= size) {
      LOG_ERROR("Parsing error: current_offset (", current_offset,
                ") exceeds payload size (", size, ")");
      break;
    }

    // Extract header
    const FrameHeader *header = nullptr;
    try {
      header = getFieldPtr<FrameHeader>(data, current_offset, size);
    } catch (const std::runtime_error &e) {
      LOG_ERROR("Error accessing frame header at offset ", current_offset, ": ",
                e.what());
      break;
    }

    // Validate header data
    if (header->length == 0) [[unlikely]] {
      LOG_WARN("Found message with zero length at offset ", current_offset,
               ", typeId=", std::hex, static_cast<int>(header->typeId),
               std::dec);
      current_offset += sizeof(FrameHeader);
      continue;
    }

    size_t header_and_message_size = sizeof(FrameHeader) + header->length;

    // Check if the entire message fits within the available data
    if (current_offset + header_and_message_size > size) {
      LOG_ERROR("Incomplete message: offset=", current_offset,
                " needed=", header_and_message_size, " available=", size);
      break; // Stop processing this payload
    }

    const uint8_t *messageData = data + current_offset + sizeof(FrameHeader);
    size_t messageSize = header->length;

    // Get message type from the header
    MessageType msgType = static_cast<MessageType>(header->typeId);

    LOG_DEBUG("Processing message type=", std::hex, static_cast<int>(msgType),
              " size=", std::dec, messageSize, " at offset ", current_offset,
              " (FrameHeader size=", sizeof(FrameHeader), ")");
    dumpHexBytes(data + current_offset,
                 std::min(sizeof(FrameHeader) + 16, size - current_offset),
                 "Header and message start");

    switch (msgType) {
    case MessageType::SNAPSHOT: {
      if (messageSize < SNAPSHOT_HEADER_SKIP) {
        LOG_ERROR("Snapshot message too short after header skip: ", messageSize,
                  " bytes < ", SNAPSHOT_HEADER_SKIP, " bytes");
        break;
      }
      LOG_DEBUG("Snapshot message: skipping additional ", SNAPSHOT_HEADER_SKIP,
                " bytes of header");
      dumpHexBytes(messageData,
                   std::min(SNAPSHOT_HEADER_SKIP + 16, messageSize),
                   "Snapshot header and content start");

      // Skip the additional message header bytes as described in README
      messageData += SNAPSHOT_HEADER_SKIP;

      // Important: per README, we're not adjusting messageSize since the length
      // field already accounts only for the content after the common 3-byte
      // header
      try {
        LOG_DEBUG("Passing messageSize of ", messageSize,
                  " bytes to parseSnapshotMessage");
        parseSnapshotMessage(messageData, messageSize);
      } catch (const std::exception &e) {
        LOG_ERROR("Exception in parseSnapshotMessage: ", e.what());
      } catch (...) {
        LOG_ERROR("Unknown exception in parseSnapshotMessage");
      }
      break;
    }
    case MessageType::UPDATE: {
      if (messageSize < UPDATE_HEADER_SKIP) {
        LOG_ERROR("Update message too short after header skip: ", messageSize,
                  " bytes < ", UPDATE_HEADER_SKIP, " bytes");
        break;
      }
      LOG_DEBUG("Update message: skipping additional ", UPDATE_HEADER_SKIP,
                " bytes of header");
      dumpHexBytes(messageData, std::min(UPDATE_HEADER_SKIP + 16, messageSize),
                   "Update header and content start");

      // Skip the additional message header bytes as described in README
      messageData += UPDATE_HEADER_SKIP;

      // Important: per README, we're not adjusting messageSize since the length
      // field already accounts only for the content after the common 3-byte
      // header
      try {
        LOG_DEBUG("Passing messageSize of ", messageSize,
                  " bytes to parseUpdateMessage");
        parseUpdateMessage(messageData, messageSize);
      } catch (const std::exception &e) {
        LOG_ERROR("Exception in parseUpdateMessage: ", e.what());
      } catch (...) {
        LOG_ERROR("Unknown exception in parseUpdateMessage");
      }
      break;
    }
    default:
      LOG_DEBUG("Ignoring unknown message type: ", std::hex,
                static_cast<int>(msgType), std::dec);
      break;
    }

    // Advance to the next message
    LOG_DEBUG("Advanced to next message, from offset ", current_offset, " to ",
              (current_offset + header_and_message_size), " of ", size,
              " bytes total");
    current_offset += header_and_message_size;
  }

  if (current_offset < size) {
    LOG_WARN("Extra data remaining at the end of UDP payload: ",
             (size - current_offset), " bytes.");
    dumpHexBytes(data + current_offset,
                 std::min(size - current_offset, static_cast<size_t>(32)),
                 "Remaining unprocessed data");
  } else if (current_offset == size) {
    LOG_DEBUG("Successfully parsed entire UDP payload of ", size, " bytes");
  } else if (current_offset > size) {
    LOG_ERROR("Parsing error detected: advanced past end of payload (",
              current_offset, " > ", size, ")");
  }
}

// Private helper methods (add these to the implementation)

void ProtocolParser::parseSnapshotMessage(const uint8_t *data, size_t size) {
  LOG_DEBUG("--- Started parsing snapshot message, data size=", size,
            " bytes ---");
  LOG_DEBUG("Note: 'data' pointer has already been advanced past "
            "SNAPSHOT_HEADER_SKIP bytes");

  dumpHexBytes(data, std::min(size, static_cast<size_t>(32)),
               "Beginning of snapshot content");

  size_t offset = 0;
  int32_t currentInstrumentId = -1;

  while (offset + sizeof(FieldHeader) <= size) {
    // Read FieldHeader directly via pointer for speed (no memcpy)
    const FieldHeader *localHeader =
        getFieldPtr<FieldHeader>(data, offset, size);
    // Check for complete field availability
    if (offset + sizeof(FieldHeader) + localHeader->fieldLen > size) {
      LOG_ERROR("Incomplete field data at offset ", offset,
                ". Field id=", std::hex, localHeader->fieldId, std::dec,
                " Declared Length=", localHeader->fieldLen,
                " Remaining Size=", (size - offset - sizeof(FieldHeader)));
      return; // Stop processing this message
    }
    // Proceed with parsed header
    const uint8_t *fieldData = data + offset + sizeof(FieldHeader);
    const size_t fieldSize = localHeader->fieldLen;
    SnapshotFieldId fieldId =
        static_cast<SnapshotFieldId>(localHeader->fieldId);

    LOG_TRACE("Processing snapshot field ", std::hex,
              static_cast<int>(localHeader->fieldId), " size=", std::dec,
              localHeader->fieldLen);

    bool processNext = true;
    switch (fieldId) {
    case SnapshotFieldId::INSTRUMENT_INFO: {
      if (fieldSize < sizeof(InstrumentInfoFieldLayout)) {
        LOG_ERROR("INSTRUMENT_INFO field too short: ", fieldSize);
        processNext = false; // Stop processing this message
        break;
      }

      // Access InstrumentInfoFieldLayout directly via pointer for speed (no
      // memcpy)
      const InstrumentInfoFieldLayout *layout =
          reinterpret_cast<const InstrumentInfoFieldLayout *>(fieldData);

      InstrumentInfo parsedInstrument = {};
      std::memcpy(parsedInstrument.name, layout->instrument_name,
                  sizeof(parsedInstrument.name));
      parsedInstrument.name[sizeof(parsedInstrument.name) - 1] = '\0';
      parsedInstrument.tickSize = layout->tick_size;
      parsedInstrument.referencePrice = layout->reference_price;
      parsedInstrument.instrumentId = layout->instrument_id;

      int32_t newInstrumentId = parsedInstrument.instrumentId;

      // Finalize previous instrument *before* processing the new one
      if (currentInstrumentId != -1 && currentInstrumentId != newInstrumentId &&
          manager_.isTrackedInstrumentId(currentInstrumentId)) {
        LOG_DEBUG("Instrument ID changed from ", currentInstrumentId, " to ",
                  newInstrumentId, ". Finalizing snapshot for ",
                  currentInstrumentId);
        manager_.finalizeSnapshot(currentInstrumentId);
      }

      currentInstrumentId = newInstrumentId; // Update the current ID

      LOG_DEBUG("Processing instrument info field for id=",
                currentInstrumentId);
      manager_.processSnapshotInfo(parsedInstrument); // Process the new one

      break; // Continue to next field
    }

    case SnapshotFieldId::TRADING_SESSION_INFO: {
      if (currentInstrumentId == -1) {
        LOG_WARN("Received trading session info (0x0102) without preceding "
                 "instrument info (0x0101). Skipping field.");
        break;
      }
      if (!manager_.isTrackedInstrumentId(currentInstrumentId)) {
        LOG_TRACE("Skipping trading session info for untracked id=",
                  currentInstrumentId);
        break;
      }

      if (fieldSize < sizeof(int32_t)) {
        LOG_ERROR("TRADING_SESSION_INFO field too short: ", fieldSize);
        processNext = false;
        break;
      }
      if (fieldSize > sizeof(int32_t)) {
        LOG_TRACE("TRADING_SESSION_INFO field has extra data (size=", fieldSize,
                  "), only reading last 4 bytes.");
      }

      // Read change number directly via pointer for speed (no memcpy)
      int32_t changeNo = *reinterpret_cast<const int32_t *>(
          fieldData + fieldSize - sizeof(int32_t));

      LOG_DEBUG("Parsed trading session info for ID ", currentInstrumentId,
                ": changeNo=", changeNo);

      manager_.updateSnapshotChangeNo(currentInstrumentId, changeNo);

      break;
    }

    case SnapshotFieldId::ORDERBOOK: {
      if (currentInstrumentId == -1) {
        LOG_WARN("Received orderbook field (0x0103) without preceding "
                 "instrument info (0x0101). Skipping field.");
        break;
      }
      if (!manager_.isTrackedInstrumentId(currentInstrumentId)) {
        LOG_TRACE("Skipping orderbook field for untracked id=",
                  currentInstrumentId);
        break; // Skip if the current instrument isn't tracked
      }

      if (!parseOrderbookField(fieldData, fieldSize, currentInstrumentId)) {
        LOG_ERROR("Failed to parse orderbook field for id=",
                  currentInstrumentId);
        // Don't necessarily stop the whole message, maybe other fields are ok
        // processNext = false; // Decide if fatal
      }
      break;
    }

    default:
      LOG_TRACE("Skipping unknown snapshot field: ", std::hex,
                static_cast<int>(fieldId), std::dec);
      // Continue processing other fields
      break;
    }

    if (!processNext) {
      LOG_ERROR("Stopping snapshot message processing due to error in field ",
                std::hex, static_cast<int>(fieldId), std::dec);
      return; // Stop processing this message entirely
    }

    // Advance offset to the next field
    offset += sizeof(FieldHeader) + fieldSize;
  }

  if (offset != size) {
    LOG_WARN("Extra data remaining at the end of snapshot message: ",
             (size - offset), " bytes.");
  }

  // Finalize the *last* instrument seen in the message
  if (currentInstrumentId != -1 &&
      manager_.isTrackedInstrumentId(currentInstrumentId)) {
    LOG_DEBUG(
        "End of snapshot message. Finalizing snapshot for last instrument id=",
        currentInstrumentId);
    manager_.finalizeSnapshot(currentInstrumentId);
  } else if (currentInstrumentId != -1) {
    LOG_TRACE("End of snapshot message. Last instrument ID ",
              currentInstrumentId, " was not tracked. No finalization needed.");
  } else {
    LOG_DEBUG("End of snapshot message. No active instrument to finalize.");
  }
  LOG_DEBUG("--- Finished parsing snapshot message, processed ", offset, " of ",
            size, " bytes ---");
}

void ProtocolParser::parseUpdateMessage(const uint8_t *data, size_t size) {
  LOG_DEBUG("--- Started parsing update message, data size=", size,
            " bytes ---");
  LOG_DEBUG("Note: 'data' pointer has already been advanced past "
            "UPDATE_HEADER_SKIP bytes");

  dumpHexBytes(data, std::min(size, static_cast<size_t>(32)),
               "Beginning of update content");

  size_t offset = 0;
  UpdateHeader currentHeader = {}; // Header for the current group
  // Use PMR vector for update events to allocate in the manager's arena
  std::pmr::vector<CachedParsedUpdateEvent> currentEvents(
      manager_.getUpdateResource());
  bool headerParsedForCurrentGroup =
      false; // Flag: have we seen 0x0003 for the current group?

  while (offset + sizeof(FieldHeader) <= size) {
    // Read FieldHeader directly via pointer for speed (no memcpy)
    const FieldHeader *localHeader =
        getFieldPtr<FieldHeader>(data, offset, size);
    // Validate field length against available data
    if (offset + sizeof(FieldHeader) + localHeader->fieldLen > size) {
      LOG_ERROR("Incomplete field data at offset ", offset,
                ". Field id=", std::hex, localHeader->fieldId, std::dec,
                " Declared Length=", localHeader->fieldLen,
                " Remaining Size=", (size - offset - sizeof(FieldHeader)));
      return; // Stop processing this message
    }
    // Extract field payload pointer and size
    const uint8_t *fieldData = data + offset + sizeof(FieldHeader);
    size_t fieldSize = localHeader->fieldLen;
    UpdateFieldId fieldId = static_cast<UpdateFieldId>(localHeader->fieldId);
    LOG_TRACE("Processing update field ", std::hex,
              static_cast<int>(localHeader->fieldId), " size=", std::dec,
              localHeader->fieldLen);

    bool processNext = true;
    switch (fieldId) {
    case UpdateFieldId::UPDATE_HEADER: { // 0x0003
      // Handle previous group *before* parsing the new header
      if (headerParsedForCurrentGroup) {
        LOG_DEBUG("New update header found. Handling previous group for id=",
                  currentHeader.instrumentId);
        if (manager_.isTrackedInstrumentId(currentHeader.instrumentId)) {
          manager_.handleUpdateMessage(currentHeader, currentEvents);
        } else {
          LOG_TRACE(
              "Skipping handling of previous update group for untracked id=",
              currentHeader.instrumentId);
        }
        currentEvents.clear(); // Reset for the new group regardless
      }

      // Parse the new header
      size_t headerFieldOffset = 0;
      try {
        currentHeader.instrumentId =
            decodeVInt(fieldData, headerFieldOffset, fieldSize);
        currentHeader.changeNo =
            decodeVInt(fieldData, headerFieldOffset, fieldSize);
      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to decode update header: ", e.what(),
                  ". Field Size: ", fieldSize);
        headerParsedForCurrentGroup = false;
        processNext = false;
      }

      LOG_DEBUG(
          "Parsed update header: instrumentId=", currentHeader.instrumentId,
          " changeNo=", currentHeader.changeNo);

      // Mark that we have a header for the *next* set of events
      headerParsedForCurrentGroup = true;

      // Check if VInt decoding consumed exactly fieldSize (optional, for
      // sanity)
      if (headerFieldOffset != fieldSize) {
        LOG_TRACE("VInt decoding for update header consumed ",
                  headerFieldOffset, " bytes, but fieldLen was ", fieldSize,
                  ". Header likely valid.");
      }
      break; // Continue parsing fields
    }

    case UpdateFieldId::UPDATE_ENTRY: { // 0x1001
      if (!headerParsedForCurrentGroup) {
        LOG_WARN("Skipping update entry field (0x1001) without a preceding "
                 "valid header (0x0003)");
        break; // Skip this field, maybe the next one is a header
      }
      // Only parse/cache events for tracked instruments
      if (!manager_.isTrackedInstrumentId(currentHeader.instrumentId)) {
        LOG_TRACE("Skipping update entry field for untracked instrument id=",
                  currentHeader.instrumentId);
        break; // Skip this field
      }

      if (fieldSize < 2) { // Need at least type and side
        LOG_ERROR("Update entry field (0x1001) too short: ", fieldSize);
        processNext = false; // Stop processing this message
        break;
      }

      size_t eventOffset = 0;
      // Parse event fields, using error flags for bounds checking
      CachedParsedUpdateEvent event = {};

      // Read event type and side
      event.eventType = static_cast<EventType>(fieldData[eventOffset++]);
      event.side = static_cast<Side>(fieldData[eventOffset++]);

      // Validate event type and side
      if (event.eventType != EventType::ADD &&
          event.eventType != EventType::MODIFY &&
          event.eventType != EventType::DELETE) {
        LOG_ERROR("Invalid event type in update entry: ",
                  static_cast<char>(event.eventType));
        processNext = false; // Stop processing this message
        break;
      }
      if (event.side != Side::BID && event.side != Side::ASK) {
        LOG_ERROR("Invalid side in update entry: ",
                  static_cast<char>(event.side));
        processNext = false; // Stop processing this message
        break;
      }

      // Read VInts for the rest of the event data
      try {
        event.priceLevel = decodeVInt(fieldData, eventOffset, fieldSize);
        event.priceOffset = decodeVInt(fieldData, eventOffset, fieldSize);
        event.volume = decodeVInt(fieldData, eventOffset, fieldSize);
      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to decode update entry field (0x1001): ", e.what(),
                  ". Field Size: ", fieldSize,
                  " Initial Offset: ", offset + sizeof(FieldHeader),
                  " Event Offset: ", eventOffset);
        processNext = false;
        break;
      }

      // Check if we consumed exactly the field length
      if (eventOffset != fieldSize) {
        LOG_TRACE("Consumed ", eventOffset,
                  " bytes for update entry, but fieldLen was ", fieldSize,
                  ". Ignoring extra bytes as per README.");
      }

      LOG_TRACE("Parsed update entry: type=",
                (event.eventType == EventType::ADD      ? "ADD"
                 : event.eventType == EventType::MODIFY ? "MODIFY"
                                                        : "DELETE"),
                " side=", (event.side == Side::BID ? "BID" : "ASK"),
                " level=", event.priceLevel, " offset=", event.priceOffset,
                " volume=", event.volume);

      // Add the successfully parsed event to the current group's list
      currentEvents.push_back(event);
      break; // Continue parsing fields
    }

    // Handle summary fields (ignore them)
    case UpdateFieldId::SUMMARY_1002:
    case UpdateFieldId::SUMMARY_1011:
    case UpdateFieldId::SUMMARY_1012:
    case UpdateFieldId::SUMMARY_1013:
    case UpdateFieldId::SUMMARY_1014:
    case UpdateFieldId::SUMMARY_1015:
    case UpdateFieldId::SUMMARY_1016:
      LOG_TRACE("Skipping summary update field: ", std::hex,
                static_cast<int>(fieldId), std::dec);
      // Successfully skipped
      break;

    default:
      LOG_TRACE("Skipping unknown update field id=", std::hex,
                static_cast<int>(fieldId), std::dec);
      // Continue processing other fields
      break;
    }

    if (!processNext) {
      LOG_ERROR("Stopping update message processing due to error in field ",
                std::hex, static_cast<int>(fieldId), std::dec);
      return; // Stop processing this message entirely
    }

    // Advance offset to the next field
    offset += sizeof(FieldHeader) + fieldSize;
  }

  if (offset != size) {
    LOG_WARN("Extra data remaining at the end of update message: ",
             (size - offset), " bytes.");
  }

  // After processing all fields, handle the *last* group if one was parsed
  // and is for a tracked instrument
  if (headerParsedForCurrentGroup &&
      manager_.isTrackedInstrumentId(currentHeader.instrumentId)) {
    LOG_DEBUG("Handling final update group for id=",
              currentHeader.instrumentId);
    manager_.handleUpdateMessage(currentHeader, currentEvents);
  } else if (headerParsedForCurrentGroup) {
    LOG_TRACE("Skipping handling of final update group for untracked id=",
              currentHeader.instrumentId);
  }
  LOG_DEBUG("--- Finished parsing update message, processed ", offset, " of ",
            size, " bytes ---");
}

bool ProtocolParser::parseOrderbookField(const uint8_t *data, size_t size,
                                         int32_t expectedInstrId) {
  size_t offset = 0;
  const size_t ENTRY_SIZE = sizeof(SnapshotOrderbookEntryLayout);
  int32_t fieldInstrumentId = -1; // Use expectedInstrId directly
  bool firstEntry = true;

  // This check is now redundant as the caller (parseSnapshotMessage) checks
  // first if (!manager_.isTrackedInstrumentId(expectedInstrId)) { ... }

  while (offset + ENTRY_SIZE <= size) {
    // Access entry directly via pointer for speed (no memcpy)
    const SnapshotOrderbookEntryLayout *entry =
        reinterpret_cast<const SnapshotOrderbookEntryLayout *>(data + offset);

    if (firstEntry) {
      fieldInstrumentId = entry->instrument_id;
      if (fieldInstrumentId != expectedInstrId) {
        LOG_ERROR("Mismatched instrument ID between 0x0101 field (",
                  expectedInstrId, ") and first entry in 0x0103 field (",
                  fieldInstrumentId, "). Skipping field.");
        return false; // Error parsing this field
      }
      // Check again here in case tracking status changed between 0x0101 and
      // 0x0103? Unlikely but safe.
      if (!manager_.isTrackedInstrumentId(fieldInstrumentId)) {
        LOG_WARN("Orderbook field ID ", fieldInstrumentId,
                 " matches expected ID ", expectedInstrId,
                 " but became untracked? Skipping field.");
        return true; // Skip the rest of the field, but don't signal message
                     // error
      }
      firstEntry = false;
    } else if (entry->instrument_id != fieldInstrumentId) {
      // fieldInstrumentId here is the one validated from the first entry
      LOG_ERROR(
          "Inconsistent instrument ID within orderbook field 0x0103: expected ",
          fieldInstrumentId, ", got ", entry->instrument_id,
          ". Stopping processing of this field.");
      return false; // Error parsing this field
    }

    Side side;
    if (entry->direction == static_cast<char>(Side::BID)) {
      side = Side::BID;
    } else if (entry->direction == static_cast<char>(Side::ASK)) {
      side = Side::ASK;
    } else {
      LOG_ERROR("Invalid side character '", entry->direction, "' (",
                static_cast<int>(entry->direction),
                ") in orderbook field for instrument ID ", fieldInstrumentId);
      return false; // Error parsing this field
    }

    LOG_TRACE("Parsed snapshot orderbook entry: id=", fieldInstrumentId,
              " Side=", (side == Side::BID ? "BID" : "ASK"),
              " Price=", entry->price, " Volume=", entry->volume);

    manager_.processSnapshotOrderbook(fieldInstrumentId, side, entry->price,
                                      entry->volume);
    offset += ENTRY_SIZE;
  }

  if (offset < size) {
    LOG_WARN("Partial entry data remaining in orderbook field: ",
             (size - offset), " bytes for instrument ID ",
             expectedInstrId, // Use expectedInstrId for logging if firstEntry
                              // was false
             ". Expected multiple of ", ENTRY_SIZE, " bytes.");
    // This isn't necessarily a fatal error for the message.
  }

  // Return true if we processed at least one entry, false if the field was
  // empty or only had errors
  return !firstEntry;
}

// getFieldPtr remains the same (needed by the loops now)
template <typename T>
const T *ProtocolParser::getFieldPtr(const uint8_t *data, size_t offset,
                                     size_t size) {
  if (offset + sizeof(T) > size) {
    // Add more context to the error message
    throw std::runtime_error("Field access beyond buffer: trying to read " +
                             std::to_string(sizeof(T)) + " bytes at offset " +
                             std::to_string(offset) + " with total size " +
                             std::to_string(size));
  }
  return reinterpret_cast<const T *>(data + offset);
}

// Detect message type from header without processing the full payload
MessageType ProtocolParser::detectMessageType(const uint8_t *data,
                                              size_t size) {
  if (!data || size < sizeof(FrameHeader)) {
    LOG_TRACE("Cannot detect message type: data is null or size is too small");
    return MessageType::UNKNOWN;
  }

  const FrameHeader *frameHeader = reinterpret_cast<const FrameHeader *>(data);
  uint8_t typeId = frameHeader->typeId;

  if (typeId == static_cast<uint8_t>(MessageType::SNAPSHOT)) {
    return MessageType::SNAPSHOT;
  } else if (typeId == static_cast<uint8_t>(MessageType::UPDATE)) {
    return MessageType::UPDATE;
  } else {
    LOG_TRACE("Unknown message type ID: 0x", std::hex, static_cast<int>(typeId),
              std::dec);
    return MessageType::UNKNOWN;
  }
}