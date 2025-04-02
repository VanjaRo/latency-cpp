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

void ProtocolParser::parsePayload(
    const uint8_t *data, size_t size,
    const SnapshotInstrumentCallback &instrCallback,
    const SnapshotOrderbookCallback &orderbookCallback,
    const UpdateHeaderCallback &updateHeaderCallback,
    const UpdateEventCallback &updateEventCallback) {

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
    parseSnapshotMessage(messageData, messageSize, instrCallback,
                         orderbookCallback);
    break;
  }
  case MessageType::UPDATE: {
    if (messageSize < UPDATE_HEADER_SKIP) {
      LOG_ERROR("Update message too short after header skip");
      return;
    }
    messageData += UPDATE_HEADER_SKIP;
    messageSize -= UPDATE_HEADER_SKIP;
    parseUpdateMessage(messageData, messageSize, updateHeaderCallback,
                       updateEventCallback);
    break;
  }
  default:
    LOG_DEBUG("Ignoring unknown message type: ", std::hex,
              static_cast<int>(header->typeId));
    break;
  }
}

// Private helper methods (add these to the implementation)

void ProtocolParser::parseSnapshotMessage(
    const uint8_t *data, size_t size,
    const SnapshotInstrumentCallback &instrCallback,
    const SnapshotOrderbookCallback &orderbookCallback) {

  FieldContext ctx(data, size);
  InstrumentInfo currentInstrument = {};
  bool haveInstrument = false;
  bool haveTradingSession = false;

  auto fieldHandler = [&](SnapshotFieldId fieldId, const uint8_t *fieldData,
                          size_t fieldSize) {
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
      currentInstrument.tickSize = layout->tick_size;
      currentInstrument.referencePrice = layout->reference_price;
      currentInstrument.instrumentId = layout->instrument_id;

      haveInstrument = true;
      haveTradingSession = false;

      LOG_DEBUG("Parsed instrument info: name='", currentInstrument.name,
                "' id=", currentInstrument.instrumentId);
      return true;
    }

    case SnapshotFieldId::TRADING_SESSION_INFO: {
      if (!haveInstrument) {
        LOG_WARN("Received trading session info without instrument info");
        return false;
      }

      if (fieldSize < sizeof(int32_t)) {
        LOG_ERROR("TRADING_SESSION_INFO field too short");
        return false;
      }

      currentInstrument.changeNo = *reinterpret_cast<const int32_t *>(
          fieldData + fieldSize - sizeof(int32_t));
      haveTradingSession = true;

      LOG_DEBUG("Parsed trading session info: changeNo=",
                currentInstrument.changeNo);

      instrCallback(currentInstrument);
      return true;
    }

    case SnapshotFieldId::ORDERBOOK: {
      if (!haveInstrument || !haveTradingSession) {
        LOG_WARN("Received orderbook without complete instrument info");
        return false;
      }

      return parseOrderbookField(fieldData, fieldSize,
                                 currentInstrument.instrumentId,
                                 orderbookCallback);
    }

    default:
      LOG_TRACE("Skipping unknown snapshot field: ", std::hex,
                static_cast<int>(fieldId));
      return true;
    }
  };

  processFields<SnapshotFieldId>(ctx, fieldHandler);
}

void ProtocolParser::parseUpdateMessage(
    const uint8_t *data, size_t size,
    const UpdateHeaderCallback &updateHeaderCallback,
    const UpdateEventCallback &updateEventCallback) {

  FieldContext ctx(data, size);
  UpdateHeader currentHeader = {};
  bool currentUpdateHeaderValid = false;

  auto fieldHandler = [&](UpdateFieldId fieldId, const uint8_t *fieldData,
                          size_t fieldSize) {
    switch (fieldId) {
    case UpdateFieldId::UPDATE_HEADER: {
      currentUpdateHeaderValid = false;
      currentHeader = {};
      size_t headerFieldOffset = 0;

      try {
        // Parse instrument_id and change_no as VInts
        currentHeader.instrumentId =
            decodeVInt(fieldData, headerFieldOffset, fieldSize);

        if (headerFieldOffset >= fieldSize) {
          LOG_ERROR("Update header field too short for change_no");
          return false;
        }

        currentHeader.changeNo = decodeVInt(fieldData, headerFieldOffset,
                                            fieldSize - headerFieldOffset);

        LOG_DEBUG(
            "Parsed update header: instrumentId=", currentHeader.instrumentId,
            " changeNo=", currentHeader.changeNo);

        currentUpdateHeaderValid = true;
        updateHeaderCallback(currentHeader);
        return true;

      } catch (const std::runtime_error &e) {
        LOG_ERROR("Failed to decode update header: ", e.what());
        return false;
      }
    }

    case UpdateFieldId::UPDATE_ENTRY: {
      if (!currentUpdateHeaderValid) {
        LOG_WARN("Skipping update entry without valid header");
        return false;
      }

      return parseUpdateEntryField(fieldData, fieldSize,
                                   currentHeader.instrumentId,
                                   updateEventCallback);
    }

    default:
      LOG_TRACE("Skipping unknown update field: ", std::hex,
                static_cast<int>(fieldId));
      return true;
    }
  };

  processFields<UpdateFieldId>(ctx, fieldHandler);
}

bool ProtocolParser::parseOrderbookField(
    const uint8_t *data, size_t size,
    int32_t expectedInstrId, // ID from INSTRUMENT_INFO field
    const SnapshotOrderbookCallback &callback) {

  if (size < sizeof(int32_t)) {
    LOG_ERROR("Orderbook field too short for instrument ID");
    return false;
  }

  // Read instrument ID *ONCE* at the beginning of the field data
  int32_t instrumentId = *reinterpret_cast<const int32_t *>(data);
  if (instrumentId !=
      expectedInstrId) { // Check against the one from INSTRUMENT_INFO
    LOG_WARN("Mismatched instrument ID in orderbook: expected ",
             expectedInstrId, " got ", instrumentId);
    return false;
  }

  // Start offset *AFTER* the instrument ID
  size_t offset = sizeof(int32_t);
  const size_t LEVEL_SIZE = sizeof(OrderbookLevelLayout); // 13 bytes

  while (offset + LEVEL_SIZE <= size) {
    // Interpret remaining data as 13-byte layouts (Side, Price, Volume)
    const auto *level =
        reinterpret_cast<const OrderbookLevelLayout *>(data + offset);

    Side side;
    if (level->side == static_cast<char>(Side::BID)) {
      side = Side::BID;
    } else if (level->side == static_cast<char>(Side::ASK)) {
      side = Side::ASK;
    } else {
      LOG_ERROR("Invalid side character in orderbook: ", level->side);
      return false;
    }

    // Use the instrumentId read ONCE at the start for the callback
    callback(instrumentId, side, level->price, level->volume);
    offset += LEVEL_SIZE;
  }

  if (offset < size) {
    LOG_WARN("Partial level data remaining in orderbook: ", (size - offset),
             " bytes");
  }

  return true;
}

bool ProtocolParser::parseUpdateEntryField(
    const uint8_t *data, size_t size, int64_t instrumentId,
    const UpdateEventCallback &callback) {

  if (size < 2) {
    LOG_ERROR("Update entry field too short: ", size);
    return false;
  }

  size_t offset = 0;
  uint32_t processedEntries = 0;

  while (offset + 2 <= size) {
    try {
      UpdateEvent event = {};
      event.instrumentId = instrumentId;

      // Read event type and side
      event.eventType = static_cast<EventType>(data[offset++]);
      event.side = static_cast<Side>(data[offset++]);

      // Validate event type and side
      if (event.eventType != EventType::ADD &&
          event.eventType != EventType::MODIFY &&
          event.eventType != EventType::DELETE) {
        LOG_ERROR("Invalid event type: ", static_cast<char>(event.eventType));
        return false;
      }

      if (event.side != Side::BID && event.side != Side::ASK) {
        LOG_ERROR("Invalid side: ", static_cast<char>(event.side));
        return false;
      }

      // Read VInts
      event.priceLevel = decodeVInt(data, offset, size - offset);
      event.priceOffset = decodeVInt(data, offset, size - offset);
      event.volume = decodeVInt(data, offset, size - offset);

      LOG_TRACE("Parsed update entry: type=",
                (event.eventType == EventType::ADD      ? "ADD"
                 : event.eventType == EventType::MODIFY ? "MODIFY"
                                                        : "DELETE"),
                " side=", (event.side == Side::BID ? "BID" : "ASK"),
                " level=", event.priceLevel, " offset=", event.priceOffset,
                " volume=", event.volume);

      callback(event);
      processedEntries++;

    } catch (const std::runtime_error &e) {
      LOG_ERROR("Failed to decode update entry: ", e.what());
      return false;
    }
  }

  if (offset < size) {
    LOG_WARN("Partial data remaining in update entry: ", (size - offset),
             " bytes");
  }

  return processedEntries > 0;
}