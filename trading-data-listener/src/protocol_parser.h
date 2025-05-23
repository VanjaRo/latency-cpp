#pragma once

#include "protocol_logger.h"
// Forward declare OrderbookManager to avoid circular dependency
class OrderbookManager;

#include <cstdint>
#include <stdexcept> // For runtime_error
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
  // Summary fields (to be skipped)
  SUMMARY_1002 = 0x1002,
  SUMMARY_1011 = 0x1011,
  SUMMARY_1012 = 0x1012,
  SUMMARY_1013 = 0x1013,
  SUMMARY_1014 = 0x1014,
  SUMMARY_1015 = 0x1015,
  SUMMARY_1016 = 0x1016,
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

// Structure representing an entry within the Snapshot Orderbook field (0x0103)
// based on README.md
struct SnapshotOrderbookEntryLayout {
  int32_t instrument_id;
  char direction; // '0' or '1'
  double price;
  int32_t volume;
  // Size = 4 + 1 + 8 + 4 = 17 bytes
};
static_assert(sizeof(SnapshotOrderbookEntryLayout) == 17,
              "SnapshotOrderbookEntryLayout size mismatch");

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

class ProtocolParser {
public:
  // Constructor no longer takes or uses runtime log level
  explicit ProtocolParser(OrderbookManager &manager) : manager_(manager) {
    LOG_INFO("ProtocolParser created, linked with OrderbookManager.");
  }

  // Parse a frame and call manager methods directly
  void parsePayload(const uint8_t *data, size_t size);

  // Detect message type from header without processing the full payload
  static MessageType detectMessageType(const uint8_t *data, size_t size);

  // Helper to decode vint (variable length integer)
  static int64_t decodeVInt(const uint8_t *data, size_t &offset,
                            size_t available_bytes);

private:
  OrderbookManager &manager_; // Reference to the manager

#ifndef NDEBUG
  // Helper function to dump hex bytes for debugging
  void dumpHexBytes(const uint8_t *data, size_t size, const char *prefix);
#else
  inline void dumpHexBytes(const uint8_t *, size_t, const char *) {}
#endif

  template <typename T>
  static const T *getFieldPtr(const uint8_t *data, size_t offset, size_t size);

  // Non-template method declarations
  void parseSnapshotMessage(const uint8_t *data, size_t size);
  void parseUpdateMessage(const uint8_t *data, size_t size);

  bool parseOrderbookField(const uint8_t *data, size_t size,
                           int32_t expectedInstrId);
  // parseUpdateEntryField removed - logic moved inline
};