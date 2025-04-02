#include "protocol_parser.h"
#include "protocol_logger.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

// Decode ZigZag encoded vint
int64_t ProtocolParser::decodeVInt(const uint8_t *data, size_t &offset,
                                   size_t available_bytes) {
  uint64_t unsigned_result = 0; // Use unsigned for varint decoding
  int shift = 0;
  size_t start_offset = offset;

  while (true) {
    if (offset >= available_bytes) {
      throw std::runtime_error(
          "Variable-length integer read past end of buffer");
    }
    uint8_t byte = data[offset++];
    unsigned_result |= static_cast<uint64_t>(byte & 0x7F) << shift;
    // If the most significant bit is not set, this is the last byte.
    if (!(byte & 0x80)) {
      break;
    }
    shift += 7;
    // Check for overflow: 10 bytes * 7 bits/byte = 70 bits, max is 64.
    // If shift reaches 63 (meaning we are processing the 10th byte),
    // the last byte must not have the MSB set and must contribute <= 1 bit.
    if (shift >= 64) { // Varint technically uses max 10 bytes for 64 bits
      throw std::runtime_error("Variable-length integer is too long");
    }
  }
  // ZigZag decode: (unsigned_result >> 1) ^ -(unsigned_result & 1)
  int64_t result = (unsigned_result >> 1) ^ (-(int64_t)(unsigned_result & 1));
  return result;
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

void ProtocolParser::parsePayload(const uint8_t *data, size_t size) {

  if (size < sizeof(FrameHeader)) {
    LOG_ERROR("Message too small for header: size=", size);
    return;
  }

  const FrameHeader *header = getFieldPtr<FrameHeader>(data, 0, size);
  if (size < sizeof(FrameHeader) + header->length) {
    LOG_ERROR("Incomplete message: expected ",
              sizeof(FrameHeader) + header->length, " bytes, got ", size);
    return;
  }

  const uint8_t *messageData = data + sizeof(FrameHeader);
  size_t messageSize = header->length;
  MessageType msgType = static_cast<MessageType>(header->typeId);

  LOG_DEBUG("Processing message type=", std::hex,
            static_cast<int>(header->typeId), " size=", std::dec, messageSize);

  switch (msgType) {
  case MessageType::SNAPSHOT: {
    if (messageSize < SNAPSHOT_HEADER_SKIP) {
      LOG_ERROR("Snapshot message too short after header skip");
      return;
    }
    messageData += SNAPSHOT_HEADER_SKIP;
    messageSize -= SNAPSHOT_HEADER_SKIP;
    parseSnapshotMessage(messageData, messageSize);
    break;
  }
  case MessageType::UPDATE: {
    if (messageSize < UPDATE_HEADER_SKIP) {
      LOG_ERROR("Update message too short after header skip");
      return;
    }
    messageData += UPDATE_HEADER_SKIP;
    messageSize -= UPDATE_HEADER_SKIP;
    parseUpdateMessage(messageData, messageSize);
    break;
  }
  default:
    LOG_DEBUG("Ignoring unknown message type: ", std::hex,
              static_cast<int>(header->typeId));
    break;
  }
}

// Private helper methods (add these to the implementation)

void ProtocolParser::parseSnapshotMessage(const uint8_t *data, size_t size) {

  FieldContext ctx(data, size);
  InstrumentInfo currentInstrument = {};
  int32_t currentInstrumentId = -1;
  bool instrumentInfoProcessed = false;

  auto fieldHandler = [&](SnapshotFieldId fieldId, const uint8_t *fieldData,
                          size_t fieldSize) -> bool {
    switch (fieldId) {
    case SnapshotFieldId::INSTRUMENT_INFO: {
      if (fieldSize < sizeof(InstrumentInfoFieldLayout)) {
        LOG_ERROR("INSTRUMENT_INFO field too short: ", fieldSize);
        return false;
      }

      const auto *layout =
          reinterpret_cast<const InstrumentInfoFieldLayout *>(fieldData);
      std::memcpy(currentInstrument.name, layout->instrument_name,
                  sizeof(currentInstrument.name));
      currentInstrument.name[sizeof(currentInstrument.name) - 1] = '\0';
      currentInstrument.tickSize = layout->tick_size;
      currentInstrument.referencePrice = layout->reference_price;
      currentInstrument.instrumentId = layout->instrument_id;
      currentInstrument.changeNo = -1;

      currentInstrumentId = currentInstrument.instrumentId;
      instrumentInfoProcessed = true;

      LOG_DEBUG("Parsed instrument info: name='", currentInstrument.name,
                "' id=", currentInstrument.instrumentId);
      return true;
    }

    case SnapshotFieldId::TRADING_SESSION_INFO: {
      if (!instrumentInfoProcessed) {
        LOG_WARN(
            "Received trading session info without preceding instrument info");
        return false;
      }

      if (fieldSize < sizeof(int32_t)) {
        LOG_ERROR("TRADING_SESSION_INFO field too short");
        return false;
      }

      currentInstrument.changeNo = *reinterpret_cast<const int32_t *>(
          fieldData + fieldSize - sizeof(int32_t));
      LOG_DEBUG("Parsed trading session info: changeNo=",
                currentInstrument.changeNo);

      manager_.processSnapshotInfo(currentInstrument);
      return true;
    }

    case SnapshotFieldId::ORDERBOOK: {
      if (currentInstrumentId == -1 || currentInstrument.changeNo == -1) {
        LOG_WARN("Received orderbook without complete instrument/session info "
                 "preceding it.");
        return false;
      }

      bool success =
          parseOrderbookField(fieldData, fieldSize, currentInstrumentId);
      if (success) {
        LOG_DEBUG("Finalizing snapshot for instrument ID: ",
                  currentInstrumentId);
        manager_.finalizeSnapshot(currentInstrumentId);
      }
      return success;
    }

    default:
      LOG_TRACE("Skipping unknown snapshot field: ", std::hex,
                static_cast<int>(fieldId));
      return true;
    }
  };

  processFields<SnapshotFieldId>(ctx, fieldHandler);
}

void ProtocolParser::parseUpdateMessage(const uint8_t *data, size_t size) {

  FieldContext ctx(data, size);
  UpdateHeader currentHeader = {}; // Header for the current group
  std::vector<CachedParsedUpdateEvent>
      currentEvents; // Events for the current group
  bool headerParsedForCurrentGroup =
      false; // Flag: have we seen 0x0003 for the current group?

  auto fieldHandler = [&](UpdateFieldId fieldId, const uint8_t *fieldData,
                          size_t fieldSize) -> bool {
    switch (fieldId) {
    case UpdateFieldId::UPDATE_HEADER: { // 0x0003
      // If we were accumulating events for a *previous* header, handle that
      // group now.
      if (headerParsedForCurrentGroup) {
        LOG_DEBUG("New update header found. Handling previous group for ID: ",
                  currentHeader.instrumentId);
        manager_.handleUpdateMessage(currentHeader, currentEvents);
        // Reset for the new group
        currentEvents.clear();
        headerParsedForCurrentGroup = false;
      }

      // Parse the new header
      size_t headerFieldOffset = 0;
      try {
        currentHeader.instrumentId =
            decodeVInt(fieldData, headerFieldOffset, fieldSize);
        if (headerFieldOffset >= fieldSize) {
          LOG_ERROR("Update header field too short for change_no");
          return false; // Stop processing this message
        }
        currentHeader.changeNo =
            decodeVInt(fieldData, headerFieldOffset, fieldSize);

        LOG_DEBUG(
            "Parsed update header: instrumentId=", currentHeader.instrumentId,
            " changeNo=", currentHeader.changeNo);
        headerParsedForCurrentGroup =
            true; // Mark that we have a header for the *next* set of events
        return true;

      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to decode update header: ", e.what());
        headerParsedForCurrentGroup =
            false;    // Ensure we don't process subsequent events
        return false; // Stop processing this message on header decode error
      }
    }

    case UpdateFieldId::UPDATE_ENTRY: { // 0x1001
      if (!headerParsedForCurrentGroup) {
        LOG_WARN("Skipping update entry field (0x1001) without a preceding "
                 "valid header (0x0003)");
        return true; // Skip this field, maybe the next one is a header
      }

      // Parse the update event directly here
      if (fieldSize < 2) { // Need at least type and side
        LOG_ERROR("Update entry field (0x1001) too short: ", fieldSize);
        return false; // Stop processing this message
      }

      size_t eventOffset = 0;
      try {
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
          return false; // Stop processing this message
        }
        if (event.side != Side::BID && event.side != Side::ASK) {
          LOG_ERROR("Invalid side in update entry: ",
                    static_cast<char>(event.side));
          return false; // Stop processing this message
        }

        // Read VInts for the rest of the event data
        event.priceLevel = decodeVInt(fieldData, eventOffset, fieldSize);

        event.priceOffset = decodeVInt(fieldData, eventOffset, fieldSize);

        event.volume = decodeVInt(fieldData, eventOffset, fieldSize);

        // Check if we consumed exactly the field length (adjusted for vint
        // decoding advancing offset)
        if (eventOffset != fieldSize) {
          // This can happen if fieldLen in the header is larger than the actual
          // varint data consumed. The README mentions this: "пропустить
          // ненужные байты вплоть до конца поля согласно field_len"
          LOG_TRACE("Consumed ", eventOffset, " bytes, but fieldLen was ",
                    fieldSize, ". Ignoring extra bytes as per README.");
          // We don't return false here, just note the discrepancy. The
          // important data was parsed.
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
        return true;

      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to decode update entry field (0x1001): ", e.what(),
                  ". Field Size: ", fieldSize, " Offset: ", eventOffset);
        return false; // Stop processing this message on event decode error
      }
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
                static_cast<int>(fieldId));
      return true; // Successfully skipped

    default:
      LOG_TRACE("Skipping unknown update field ID: ", std::hex,
                static_cast<int>(fieldId));
      return true; // Continue processing other fields
    }
  };

  // Process all fields in the message using the handler
  processFields<UpdateFieldId>(ctx, fieldHandler);

  // After processing all fields, handle the *last* group if one was parsed
  if (headerParsedForCurrentGroup) {
    LOG_DEBUG("Handling final update group for ID: ",
              currentHeader.instrumentId);
    manager_.handleUpdateMessage(currentHeader, currentEvents);
  }
}

bool ProtocolParser::parseOrderbookField(const uint8_t *data, size_t size,
                                         int32_t expectedInstrId) {
  size_t offset = 0;
  const size_t ENTRY_SIZE =
      sizeof(SnapshotOrderbookEntryLayout); // Use the correct struct size (17)
  int32_t fieldInstrumentId = -1; // To store the ID found within this field

  while (offset + ENTRY_SIZE <= size) {
    const auto *entry =
        reinterpret_cast<const SnapshotOrderbookEntryLayout *>(data + offset);

    if (offset == 0) {
      fieldInstrumentId = entry->instrument_id; // Store ID from the first entry
      // Validate against the ID from the preceding INSTRUMENT_INFO field
      if (fieldInstrumentId != expectedInstrId) {
        LOG_ERROR("Mismatched instrument ID between 0x0101 field (",
                  expectedInstrId, ") and first entry in 0x0103 field (",
                  fieldInstrumentId, ")");
        // Depending on strictness, consider returning false
      }
    } else if (entry->instrument_id != fieldInstrumentId) {
      // Check consistency *within* the orderbook field if needed
      LOG_WARN(
          "Inconsistent instrument ID within orderbook field 0x0103: expected ",
          fieldInstrumentId, ", got ", entry->instrument_id,
          ". Processing continues with first ID.");
      // Continue processing using fieldInstrumentId
    }

    Side side;
    if (entry->direction == static_cast<char>(Side::BID)) {
      side = Side::BID;
    } else if (entry->direction == static_cast<char>(Side::ASK)) {
      side = Side::ASK;
    } else {
      LOG_ERROR("Invalid side character '", entry->direction, "' (",
                static_cast<int>(entry->direction),
                ") in orderbook field for instrument ID ",
                fieldInstrumentId); // Use ID from field
      return false; // Treat invalid side as critical error for this field
    }

    LOG_TRACE("Parsed snapshot orderbook entry: ID=",
              entry->instrument_id, // Log the actual entry ID
              " Side=", (side == Side::BID ? "BID" : "ASK"),
              " Price=", entry->price, " Volume=", entry->volume);

    // Use the instrument ID found *within this field* when processing
    manager_.processSnapshotOrderbook(fieldInstrumentId, side, entry->price,
                                      entry->volume);
    offset += ENTRY_SIZE;
  }

  if (offset < size) {
    LOG_WARN(
        "Partial entry data remaining in orderbook field: ", (size - offset),
        " bytes for instrument ID ", fieldInstrumentId, // Use ID from field
        ". Expected multiple of ", ENTRY_SIZE, " bytes.");
  }

  // Ensure we actually processed at least one entry before returning true
  return (fieldInstrumentId != -1);
}