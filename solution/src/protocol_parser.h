#pragma once

#include "protocol_logger.h"
#include <cstdint>
#include <functional>
#include <stdexcept> // For runtime_error in decodeVInt
#include <string>
#include <vector>

// Protocol message types
enum class MessageType : uint8_t {
  SNAPSHOT = 0x32,
  UPDATE = 0x01,
  UNKNOWN = 0xFF
};

// Field IDs
enum class SnapshotFieldId : uint16_t {
  INSTRUMENT_INFO = 0x0101,
  TRADING_SESSION_INFO = 0x0102,
  ORDERBOOK = 0x0103,
};

enum class UpdateFieldId : uint16_t {
  UPDATE_HEADER = 0x0003,
  UPDATE_ENTRY = 0x1001,
};

// Event types in updates
enum class EventType : char { ADD = '1', MODIFY = '2', DELETE = '3' };

// Side types (bid/ask)
enum class Side : char { BID = '0', ASK = '1' };

#pragma pack(push, 1)
// Frame header structure
struct FrameHeader {
  uint8_t dummy;
  uint8_t typeId;
  uint16_t length;
};

// Field header structure
struct FieldHeader {
  uint16_t fieldId;
  uint16_t fieldLen;
};

// Structure representing the layout of the Instrument Information field
// (0x0101)
struct InstrumentInfoFieldLayout {
  char instrument_name[31];
  uint8_t unused_data[61]; // Skip these bytes
  double tick_size;
  double reference_price;
  int32_t instrument_id;
  // Total size should be 31 + 61 + 8 + 8 + 4 = 112 bytes
};
static_assert(sizeof(InstrumentInfoFieldLayout) == 112,
              "InstrumentInfoFieldLayout size mismatch");

// Structure representing only the relevant part (last 4 bytes) of the Trading
// Session Info field (0x0102) We access this by calculating the offset:
// field_len - sizeof(int32_t) struct TradingSessionInfoTail {
//     int32_t change_no;
// };

// Structure representing an entry within the Orderbook field (0x0103)
// struct OrderbookEntryLayout { // <-- Original thought based on README?
//   int32_t instrument_id;
//   char direction;
//   double price;
//   int32_t volume;
// The impl loop has `fieldOffset + 9 <= fieldHeader->fieldLen` and reads
// Side(1), price(8), volume(4). That's 13. Ah, the `instrument_id` is
// *outside* the loop in the impl, read once.
// };

// Let's adjust the OrderbookEntryLayout based on implementation: Side, Price,
// Volume
struct OrderbookLevelLayout { // <-- Current struct based on implementation
  char side;                  // '0' or '1'
  double price;
  int32_t volume;
  // Size = 1 + 8 + 4 = 13 bytes
};
static_assert(sizeof(OrderbookLevelLayout) == 13,
              "OrderbookLevelLayout size mismatch");

#pragma pack(pop)

// Update event structure (after parsing vint)
struct UpdateEvent {
  EventType eventType;
  Side side;
  int64_t priceLevel;  // Index (1-based from protocol)
  int64_t priceOffset; // Offset from reference price
  int64_t volume;
  int64_t instrumentId; // Added from header
};

// Instrument information structure (used by OrderbookManager)
struct InstrumentInfo {
  char name[31];
  double tickSize;
  double referencePrice;
  int32_t instrumentId; // Changed from int64_t to match binary layout of
                        // snapshot field
  int32_t changeNo;     // From trading session info field
};

// Update message header (after parsing vint)
struct UpdateHeader {
  int64_t instrumentId;
  int64_t changeNo;
};

// Callbacks for different message types
using SnapshotInstrumentCallback = std::function<void(const InstrumentInfo &)>;
using SnapshotOrderbookCallback = std::function<void(
    int32_t /*instrId*/, Side, double /*price*/, int32_t /*volume*/)>;
using UpdateHeaderCallback = std::function<void(const UpdateHeader &)>;
using UpdateEventCallback = std::function<void(const UpdateEvent &)>;

class ProtocolParser {
public:
  // Constructor no longer takes a log level
  explicit ProtocolParser() = default; // Use default constructor

  // Parse a frame and call appropriate callbacks
  void parsePayload(const uint8_t *data, size_t size,
                    const SnapshotInstrumentCallback &instrCallback,
                    const SnapshotOrderbookCallback &orderbookCallback,
                    const UpdateHeaderCallback &updateHeaderCallback,
                    const UpdateEventCallback &updateEventCallback);

  // Helper to decode vint (variable length integer)
  // Made static as it doesn't depend on parser state
  static int64_t decodeVInt(const uint8_t *data, size_t &offset,
                            size_t available_bytes); // Added available_bytes

private:
  // Structure to track field parsing state
  struct FieldContext {
    const uint8_t *data;      // Base pointer to message data
    size_t size;              // Total message size
    size_t offset;            // Current offset in message
    size_t fieldSize;         // Size of current field
    const uint8_t *fieldData; // Pointer to current field data

    FieldContext(const uint8_t *d, size_t s)
        : data(d), size(s), offset(0), fieldSize(0), fieldData(nullptr) {}

    bool canReadField() const { return offset + sizeof(FieldHeader) <= size; }

    bool advanceField(const FieldHeader *header) {
      if (offset + sizeof(FieldHeader) + header->fieldLen > size) {
        return false;
      }
      offset += sizeof(FieldHeader);
      fieldSize = header->fieldLen;
      fieldData = data + offset;
      return true;
    }

    void nextField() { offset += fieldSize; }
  };

  // Template declarations
  template <typename T>
  static T *getFieldPtr(const uint8_t *data, size_t offset, size_t size);

  template <typename FieldIdType>
  bool processFields(
      FieldContext &ctx,
      const std::function<bool(FieldIdType, const uint8_t *, size_t)> &handler);

  // Non-template method declarations
  void parseSnapshotMessage(const uint8_t *data, size_t size,
                            const SnapshotInstrumentCallback &instrCallback,
                            const SnapshotOrderbookCallback &orderbookCallback);

  void parseUpdateMessage(const uint8_t *data, size_t size,
                          const UpdateHeaderCallback &updateHeaderCallback,
                          const UpdateEventCallback &updateEventCallback);

  bool parseOrderbookField(const uint8_t *data, size_t size,
                           int32_t expectedInstrId,
                           const SnapshotOrderbookCallback &callback);

  bool parseUpdateEntryField(const uint8_t *data, size_t size,
                             int64_t instrumentId,
                             const UpdateEventCallback &callback);
};

// Template implementations
template <typename T>
T *ProtocolParser::getFieldPtr(const uint8_t *data, size_t offset,
                               size_t size) {
  if (offset + sizeof(T) > size) {
    throw std::runtime_error("Field access beyond buffer");
  }
  return reinterpret_cast<const T *>(data + offset);
}

template <typename FieldIdType>
bool ProtocolParser::processFields(
    FieldContext &ctx,
    const std::function<bool(FieldIdType, const uint8_t *, size_t)> &handler) {
  while (ctx.canReadField()) {
    const FieldHeader *header =
        getFieldPtr<FieldHeader>(ctx.data, ctx.offset, ctx.size);

    if (!ctx.advanceField(header)) {
      LOG_ERROR("Incomplete field data at offset ", ctx.offset);
      return false;
    }

    FieldIdType fieldId = static_cast<FieldIdType>(header->fieldId);
    LOG_TRACE("Processing field ", std::hex, static_cast<int>(header->fieldId),
              " size=", std::dec, header->fieldLen);

    if (!handler(fieldId, ctx.fieldData, ctx.fieldSize)) {
      LOG_WARN("Field handler failed for field ", std::hex,
               static_cast<int>(header->fieldId));
      // Continue processing other fields
    }

    ctx.nextField();
  }
  return true;
}