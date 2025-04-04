#pragma once

#include "protocol_parser.h"
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Maximum number of price levels to track
constexpr size_t MAX_PRICE_LEVELS = 5;

// Price level structure
struct alignas(64) PriceLevel {
  double price;
  int64_t volume;
};

// Orderbook structure
struct Orderbook {
  int32_t instrumentId;
  double tickSize;
  double referencePrice;
  int32_t changeNo;

  // Pre-allocated fixed arrays for bids and asks
  std::array<PriceLevel, MAX_PRICE_LEVELS> asks;
  std::array<PriceLevel, MAX_PRICE_LEVELS> bids;
  int askCount;
  int bidCount;

  // Pre-computed VWAP components
  uint32_t vwapNumerator;
  uint32_t vwapDenominator;
  uint32_t lastVwapNumerator;
  uint32_t lastVwapDenominator;

  // State flags
  bool isValid;
  bool vwapChanged;

  // Constructor
  Orderbook();
};

// Structure to hold parsed update events for caching
struct CachedParsedUpdateEvent {
  EventType eventType;
  Side side;
  int priceLevel;      // 1-based from protocol
  int64_t priceOffset; // vint from protocol
  int64_t volume;      // vint from protocol
};

// Structure to hold a complete cached update message (header info + events)
struct CachedParsedUpdate {
  int64_t changeNo;
  std::vector<CachedParsedUpdateEvent> events;
  // No need for instrumentId, refPrice, tickSize here; retrieved from Orderbook
  // when applying.

  // Add a comparison operator for sorting
  bool operator<(const CachedParsedUpdate &other) const {
    return changeNo < other.changeNo;
  }
};

class OrderbookManager {
public:
  OrderbookManager();

  // Check if an instrument is tracked
  bool isTrackedInstrument(const std::string &name) const;
  bool isTrackedInstrumentId(int32_t id) const;

  // Check if an IP is relevant
  bool isRelevantIP(uint32_t ip) const;

  // Process snapshot
  void processSnapshotInfo(const InstrumentInfo &info);
  void processSnapshotOrderbook(int32_t instrumentId, Side side, double price,
                                int32_t volume);

  // Finalize the current update and calculate VWAP
  void finalizeSnapshot(int32_t instrumentId);

  // Update change number from snapshot's trading session info
  void updateSnapshotChangeNo(int32_t instrumentId, int32_t changeNo);

  // Process update
  void handleUpdateMessage(const UpdateHeader &header,
                           const std::vector<CachedParsedUpdateEvent> &events);

  // Get changed VWAPs for output
  struct VWAPResult {
    int32_t instrumentId;
    uint32_t numerator;
    uint32_t denominator;
  };
  std::vector<VWAPResult> getChangedVWAPs() const;

  // Clear the list of changed VWAPs
  void clearChangedVWAPs();

  // Load target instruments directly
  void loadInstruments(const std::set<std::string> &instruments);

private:
  // Maps and sets for tracking
  std::unordered_map<int32_t, Orderbook> orderbooks;
  std::unordered_set<std::string> trackedInstruments;
  std::unordered_map<int32_t, std::string> idToName;

  // Cache for out-of-sequence or pre-snapshot updates
  std::unordered_map<int32_t, std::vector<CachedParsedUpdate>>
      cachedParsedUpdates;

  // Filtered IPs
  uint32_t snapshotIP;
  uint32_t updateIP;

  // Calculate VWAP for an orderbook
  void calculateVWAP(Orderbook &orderbook);

  // Add, modify, or delete price level (using 0-based index)
  void addPriceLevel(Orderbook &orderbook, Side side, int priceLevelIndex,
                     double price, int64_t volume);
  void modifyPriceLevel(Orderbook &orderbook, Side side, int priceLevelIndex,
                        double price, int64_t volume);
  void deletePriceLevel(Orderbook &orderbook, Side side, int priceLevelIndex);

  // Applies cached updates after a snapshot
  void applyCachedUpdates(Orderbook &orderbook);
};