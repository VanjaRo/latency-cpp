#pragma once

#include "protocol_parser.h"
#include <array>
#include <cstdint>
#include <memory>
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

// Structure to hold cached updates when sync is needed
struct CachedUpdate {
  std::vector<uint8_t> data;
};

class OrderbookManager {
public:
  OrderbookManager();

  // Load metadata with tracked instruments and IPs
  void loadMetadata(const std::string &metadataPath);

  // Check if an instrument is tracked
  bool isTrackedInstrument(const std::string &name) const;
  bool isTrackedInstrumentId(int32_t id) const;

  // Check if an IP is relevant
  bool isRelevantIP(uint32_t ip) const;

  // Process snapshot
  void processSnapshot(const InstrumentInfo &info);
  void processSnapshotOrderbook(int32_t instrumentId, Side side, double price,
                                int32_t volume);

  // Process update
  void processUpdateHeader(const UpdateHeader &header);
  void processUpdateEvent(const UpdateEvent &event);

  // Finalize the current update and calculate VWAP
  void finalizeUpdate();

  // Get changed VWAPs for output
  struct VWAPResult {
    int32_t instrumentId;
    uint32_t numerator;
    uint32_t denominator;
  };
  std::vector<VWAPResult> getChangedVWAPs() const;

private:
  // Maps and sets for tracking
  std::unordered_map<int32_t, Orderbook> orderbooks;
  std::unordered_set<std::string> trackedInstruments;
  std::unordered_map<int32_t, std::string> idToName;
  std::unordered_map<int32_t, std::vector<CachedUpdate>> cachedUpdates;

  // Currently processing instrument ID
  int32_t currentInstrumentId;

  // Filtered IPs
  uint32_t snapshotIP;
  uint32_t updateIP;

  // Calculate VWAP for an orderbook
  void calculateVWAP(Orderbook &orderbook);

  // Add, modify, or delete price level
  void addPriceLevel(Orderbook &orderbook, Side side, int priceLevel,
                     double price, int32_t volume);
  void modifyPriceLevel(Orderbook &orderbook, Side side, int priceLevel,
                        double price, int32_t volume);
  void deletePriceLevel(Orderbook &orderbook, Side side, int priceLevel);
};