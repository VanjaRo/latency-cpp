#pragma once

#include <cstdint>
#include <functional>
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
#pragma pack(pop)

// Update event structure (after parsing vint)
struct UpdateEvent {
  EventType eventType;
  Side side;
  int64_t priceLevel;
  int64_t priceOffset;
  int64_t volume;
  int64_t instrumentId;
};

// Instrument information structure
struct InstrumentInfo {
  char name[31];
  double tickSize;
  double referencePrice;
  int64_t instrumentId;
  int64_t changeNo; // From trading session info field
};

// Update message header
struct UpdateHeader {
  int64_t instrumentId;
  int64_t changeNo;
};

// Callbacks for different message types
using SnapshotInstrumentCallback = std::function<void(const InstrumentInfo &)>;
using SnapshotOrderbookCallback =
    std::function<void(int32_t, Side, double, int32_t)>;
using UpdateHeaderCallback = std::function<void(const UpdateHeader &)>;
using UpdateEventCallback = std::function<void(const UpdateEvent &)>;

class ProtocolParser {
public:
  // Parse a frame and call appropriate callbacks
  void parsePayload(const uint8_t *data, size_t size,
                    const SnapshotInstrumentCallback &instrCallback,
                    const SnapshotOrderbookCallback &orderbookCallback,
                    const UpdateHeaderCallback &updateHeaderCallback,
                    const UpdateEventCallback &updateEventCallback);

  // Helper to decode vint (variable length integer)
  static int64_t decodeVInt(const uint8_t *data, size_t &offset);

private:
  // Helper method to parse snapshot messages
  void parseSnapshotMessage(const uint8_t *data, size_t size,
                            const SnapshotInstrumentCallback &instrCallback,
                            const SnapshotOrderbookCallback &orderbookCallback);

  // Helper method to parse update messages
  void parseUpdateMessage(const uint8_t *data, size_t size,
                          const UpdateHeaderCallback &updateHeaderCallback,
                          const UpdateEventCallback &updateEventCallback);
};