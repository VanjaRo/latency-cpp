#include "protocol_parser.h"
#include <cstdint>
#include <cstring>
#include <iostream>

// Decode ZigZag encoded vint
int64_t ProtocolParser::decodeVInt(const uint8_t *data, size_t &offset) {
  int64_t result = 0;
  int shift = 0;
  while (true) {
    uint8_t byte = data[offset++];
    result |= static_cast<int64_t>(byte & 0x7F) << shift;
    // If the most significant bit is not set, this is the last byte.
    if (!(byte & 0x80)) {
      break;
    }
    shift += 7;
    if (shift >= 64) {
      throw std::runtime_error("Variable-length integer is too long");
    }
  }
  return result;
}

void ProtocolParser::parsePayload(
    const uint8_t *data, size_t size,
    const SnapshotInstrumentCallback &instrCallback,
    const SnapshotOrderbookCallback &orderbookCallback,
    const UpdateHeaderCallback &updateHeaderCallback,
    const UpdateEventCallback &updateEventCallback) {

  // Basic validation
  if (size < sizeof(FrameHeader)) {
    return;
  }

  // Parse frame header
  const FrameHeader *frameHeader = reinterpret_cast<const FrameHeader *>(data);

  // Check if we have a complete message
  if (size < sizeof(FrameHeader) + frameHeader->length) {
    return;
  }

  // Skip header and process the message based on type
  const uint8_t *messageData = data + sizeof(FrameHeader);
  size_t messageSize = frameHeader->length;

  // Process based on message type
  MessageType msgType = static_cast<MessageType>(frameHeader->typeId);

  if (msgType == MessageType::SNAPSHOT) {
    // Parse snapshot message
    // add unuzed 4 bytes
    messageData += 4;
    parseSnapshotMessage(messageData, messageSize, instrCallback,
                         orderbookCallback);
  } else if (msgType == MessageType::UPDATE) {
    // Parse update message
    // add unuzed 20 bytes
    messageData += 20;
    parseUpdateMessage(messageData, messageSize, updateHeaderCallback,
                       updateEventCallback);
  }
}

// Private helper methods (add these to the implementation)

void ProtocolParser::parseSnapshotMessage(
    const uint8_t *data, size_t size,
    const SnapshotInstrumentCallback &instrCallback,
    const SnapshotOrderbookCallback &orderbookCallback) {

  size_t offset = 0;
  InstrumentInfo instrumentInfo = {};
  bool hasInstrument = false;
  int32_t instrumentId = 0;
  int32_t changeNo = 0;

  std::cout << "Parsing snapshot message of size " << size << std::endl;

  // Process fields until we reach the end of the message
  while (offset + sizeof(FieldHeader) <= size) {
    const FieldHeader *fieldHeader =
        reinterpret_cast<const FieldHeader *>(data + offset);
    offset += sizeof(FieldHeader);

    // Ensure we have enough data for the field
    if (offset + fieldHeader->fieldLen > size) {
      std::cout << "Not enough data for field ID " << fieldHeader->fieldId
                << ", need " << fieldHeader->fieldLen << " bytes, have "
                << (size - offset) << std::endl;
      break;
    }

    // Process field based on ID
    SnapshotFieldId fieldId =
        static_cast<SnapshotFieldId>(fieldHeader->fieldId);
    std::cout << "Processing field ID " << std::hex
              << static_cast<int16_t>(fieldId) << std::dec << " with length "
              << fieldHeader->fieldLen << std::endl;

    switch (fieldId) {
    case SnapshotFieldId::INSTRUMENT_INFO: {
      const uint8_t *fieldData = data + offset;
      size_t fieldOffset = 0;

      // Validate field length (should be 112 bytes)
      if (fieldHeader->fieldLen < 112) {
        // std::cout << "Warning: INSTRUMENT_INFO field too short, expected 112
        // "
        //              "bytes but got "
        //           << fieldHeader->fieldLen << std::endl;
        break;
      }

      // Extract instrument name (31 bytes)
      std::memcpy(instrumentInfo.name, fieldData + fieldOffset, 31);
      //   instrumentInfo.name[30] = '\0'; // Ensure null termination
      fieldOffset += 31;

      // Skip 61 bytes of unused data
      fieldOffset += 61;

      // Extract tick_size (double, 8 bytes)
      instrumentInfo.tickSize =
          *reinterpret_cast<const double *>(fieldData + fieldOffset);
      fieldOffset += sizeof(double);

      // Extract reference_price (double, 8 bytes)
      instrumentInfo.referencePrice =
          *reinterpret_cast<const double *>(fieldData + fieldOffset);
      fieldOffset += sizeof(double);

      // Extract instrument_id (int32, 4 bytes)
      instrumentInfo.instrumentId =
          *reinterpret_cast<const int32_t *>(fieldData + fieldOffset);
      fieldOffset += sizeof(int32_t);

      instrumentId = instrumentInfo.instrumentId;
      hasInstrument = true;

      std::cout << "Found instrument info: name='" << instrumentInfo.name
                << "', id=" << instrumentInfo.instrumentId
                << ", tickSize=" << instrumentInfo.tickSize
                << ", refPrice=" << instrumentInfo.referencePrice << std::endl;
      break;
    }

    case SnapshotFieldId::TRADING_SESSION_INFO: {
      const uint8_t *fieldData = data + offset;

      if (hasInstrument) {
        // we are interested in the last 4 bytes of the 154 bytes field
        const int32_t changeNo = *reinterpret_cast<const int32_t *>(
            fieldData + fieldHeader->fieldLen - 4);
        instrumentInfo.changeNo = changeNo;

        // Call instrument callback
        std::cout << "Calling instrument callback for '" << instrumentInfo.name
                  << "' with changeNo " << changeNo << std::endl;
        instrCallback(instrumentInfo);
      }
      break;
    }

    case SnapshotFieldId::ORDERBOOK: {
      if (!hasInstrument) {
        // std::cout << "Warning: Received orderbook data without instrument
        // info"
        //           << std::endl;
        break;
      }

      const uint8_t *fieldData = data + offset;
      size_t fieldOffset = 0;

      int32_t orderbookInstrumentId =
          *reinterpret_cast<const int32_t *>(fieldData + fieldOffset);
      fieldOffset += sizeof(int32_t);

      if (orderbookInstrumentId != instrumentId) {
        std::cout << "Warning: Received orderbook data for different instrument"
                  << std::endl;
        break;
      }

      // Process orderbook entries
      int processedEntries = 0;
      while (fieldOffset + 9 <= fieldHeader->fieldLen) {
        Side side = static_cast<Side>(fieldData[fieldOffset++]);

        double price =
            *reinterpret_cast<const double *>(fieldData + fieldOffset);
        fieldOffset += sizeof(double);

        int32_t volume =
            *reinterpret_cast<const int32_t *>(fieldData + fieldOffset);
        fieldOffset += sizeof(int32_t);

        std::cout << "  Entry " << processedEntries
                  << ": side=" << (side == Side::BID ? "BID" : "ASK")
                  << ", price=" << price << ", volume=" << volume << std::endl;

        // Call orderbook callback with correct instrument ID
        orderbookCallback(orderbookInstrumentId, side, price, volume);
        processedEntries++;
      }

      break;
    }
    default:
      std::cout << "Skipping unknown snapshot field ID 0x" << std::hex
                << static_cast<uint16_t>(fieldId) << std::dec << std::endl;
      break;
    }

    // Move to next field
    offset += fieldHeader->fieldLen;
  }

  if (offset < size) {
    std::cout << "Warning: " << (size - offset)
              << " bytes remaining after processing all fields" << std::endl;
  }
}

void ProtocolParser::parseUpdateMessage(
    const uint8_t *data, size_t size,
    const UpdateHeaderCallback &updateHeaderCallback,
    const UpdateEventCallback &updateEventCallback) {

  size_t offset = 0;
  bool hasHeader = false;
  UpdateHeader currentHeader;

  std::cout << "Parsing update message of size " << size << std::endl;

  while (offset + sizeof(FieldHeader) <= size) {
    const FieldHeader *fieldHeader =
        reinterpret_cast<const FieldHeader *>(data + offset);
    offset += sizeof(FieldHeader);

    // if (offset + fieldLen > size) {
    //   std::cout << "Not enough data for field ID " << std::hex << fieldId
    //             << ", need " << fieldLen << " bytes, have " << (size -
    //             offset)
    //             << std::endl;
    //   break;
    // }

    const uint8_t *fieldData = data + offset;

    UpdateFieldId fieldId = static_cast<UpdateFieldId>(fieldHeader->fieldId);
    switch (fieldId) {
    case UpdateFieldId::UPDATE_HEADER: {
      size_t headerOffset = 0;
      try {
        // Parse instrument_id and change_no as VInts
        currentHeader.instrumentId = decodeVInt(fieldData, headerOffset);

        if (headerOffset >= fieldHeader->fieldLen) {
          std::cout << "Update header truncated after instrument_id"
                    << std::endl;
          break;
        }

        currentHeader.changeNo =
            decodeVInt(fieldData + headerOffset, headerOffset);

        std::cout << "Update header: instrumentId="
                  << currentHeader.instrumentId
                  << ", changeNo=" << currentHeader.changeNo << std::endl;

        if (headerOffset > fieldHeader->fieldLen) {
          std::cout << "Update header truncated after change_no" << std::endl;
          break;
        }

        hasHeader = true;
        updateHeaderCallback(currentHeader);
        std::cout << "Found update header: instrumentId="
                  << currentHeader.instrumentId
                  << ", changeNo=" << currentHeader.changeNo << std::endl;
      } catch (const std::runtime_error &e) {
        std::cout << "Error decoding update header: " << e.what() << std::endl;
      }
      break;
    }
    case UpdateFieldId::UPDATE_ENTRY: {
      if (!hasHeader) {
        std::cout << "Warning: Received update entry without header"
                  << std::endl;
        offset += fieldHeader->fieldLen;
        continue;
      }

      if (fieldHeader->fieldLen < 4) {
        std::cout << "Update entry field too short: " << fieldHeader->fieldLen
                  << " bytes" << std::endl;
        offset += fieldHeader->fieldLen;
        continue;
      }

      size_t entryOffset = 0;

      uint32_t processedEntries = 0;
      while (entryOffset + 2 <= fieldHeader->fieldLen) {
        try {
          UpdateEvent event;
          event.instrumentId = currentHeader.instrumentId;

          // Read event type and side
          event.eventType = static_cast<EventType>(fieldData[entryOffset++]);
          std::cout << "Event type huhla: " << std::hex
                    << static_cast<uint16_t>(event.eventType) << std::dec
                    << std::endl;
          event.side = static_cast<Side>(fieldData[entryOffset++]);

          // Read price level, price offset, and volume as VInts
          //   if (entryOffset >= fieldLen) {
          //     std::cout << "Update entry truncated before price level"
          //               << std::endl;
          //     break;
          //   }
          event.priceLevel = decodeVInt(fieldData + entryOffset, entryOffset);

          //   if (entryOffset >= fieldLen) {
          //     std::cout << "Update entry truncated before price offset"
          //               << std::endl;
          //     break;
          //   }
          event.priceOffset = decodeVInt(fieldData + entryOffset, entryOffset);

          //   if (entryOffset >= fieldLen) {
          //     std::cout << "Update entry truncated before volume" <<
          //     std::endl; break;
          //   }
          event.volume = decodeVInt(fieldData + entryOffset, entryOffset);

          std::cout << "  Entry " << processedEntries << ": type="
                    << (event.eventType == EventType::ADD      ? "ADD"
                        : event.eventType == EventType::MODIFY ? "MODIFY"
                                                               : "DELETE")
                    << ", side=" << (event.side == Side::BID ? "BID" : "ASK")
                    << ", level=" << event.priceLevel
                    << ", offset=" << event.priceOffset
                    << ", volume=" << event.volume << std::endl;

          updateEventCallback(event);
          processedEntries++;
        } catch (const std::runtime_error &e) {
          std::cout << "Error decoding update entry: " << e.what() << std::endl;
          break;
        }
      }
      break;
    }
    default: {
      std::cout << "Skipping unknown update field ID 0x" << std::hex
                << static_cast<uint16_t>(fieldId) << std::dec << std::endl;
    }
    }
    offset += fieldHeader->fieldLen;
  }

  if (offset < size) {
    std::cout << "Warning: " << (size - offset)
              << " bytes remaining after processing all fields" << std::endl;
  }
}