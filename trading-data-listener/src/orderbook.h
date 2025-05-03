#pragma once

#include "protocol_parser.h"
#include <array>
#include <cstdint>
#include <cstring> // for std::memcpy, std::memmove
#include <map>
#include <memory>
#include <memory_resource>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Maximum number of price levels to track
constexpr size_t MAX_PRICE_LEVELS = 5;

// Inline capacity margin: allow up to DEPTH_MARGIN extra levels before heap
// fallback
static constexpr size_t DEPTH_MARGIN = 20;
static constexpr size_t MAX_DEPTH_STORAGE =
    MAX_PRICE_LEVELS + DEPTH_MARGIN; // Inline buffer up to 20 levels

static constexpr size_t ARENA_SIZE_MULTIPLIER = 20;

// Price level structure
struct alignas(64) PriceLevel {
  double price;
  int64_t volume;
};

// Dedicated PMR arena for PriceBuf heap fallbacks (persistent for program
// lifetime)
inline std::pmr::monotonic_buffer_resource priceBufResource(
    MAX_DEPTH_STORAGE * sizeof(PriceLevel) * ARENA_SIZE_MULTIPLIER,
    std::pmr::get_default_resource());

// Small-buffer container for PriceLevel: inline capacity up to
// MAX_DEPTH_STORAGE, heap-fallback beyond
struct PriceBuf {
  static constexpr size_t InlineCap = MAX_DEPTH_STORAGE;
  PriceLevel inline_buf[InlineCap];
  PriceLevel *heap_buf = nullptr;
  size_t sz = 0;
  size_t cap = InlineCap;
  // Memory resource for fallback allocations
  std::pmr::memory_resource *mr = &priceBufResource;
  PriceBuf() = default;
  ~PriceBuf() {
    if (heap_buf) {
      // Deallocate fallback buffer
      mr->deallocate(heap_buf, cap * sizeof(PriceLevel), alignof(PriceLevel));
    }
  }
  size_t size() const { return sz; }
  size_t capacity() const { return cap; }
  bool empty() const { return sz == 0; }
  PriceLevel *data() { return heap_buf ? heap_buf : inline_buf; }
  const PriceLevel *data() const { return heap_buf ? heap_buf : inline_buf; }
  PriceLevel &operator[](size_t idx) { return data()[idx]; }
  const PriceLevel &operator[](size_t idx) const { return data()[idx]; }
  void clear() {
    sz = 0;
    if (heap_buf) {
      mr->deallocate(heap_buf, cap * sizeof(PriceLevel), alignof(PriceLevel));
      heap_buf = nullptr;
      cap = InlineCap;
    }
  }
  void grow() {
    size_t oldCap = cap;
    size_t newCap = cap * 2;
    // Allocate fallback from PMR arena
    void *raw = mr->allocate(newCap * sizeof(PriceLevel), alignof(PriceLevel));
    PriceLevel *newBuf = static_cast<PriceLevel *>(raw);
    std::memcpy(newBuf, data(), sz * sizeof(PriceLevel));
    // Deallocate previous heap buffer if any
    if (heap_buf) {
      mr->deallocate(heap_buf, oldCap * sizeof(PriceLevel),
                     alignof(PriceLevel));
    }
    heap_buf = newBuf;
    cap = newCap;
  }
  void insert(size_t idx, const PriceLevel &v) {
    if (sz + 1 > cap)
      grow();
    size_t numToMove = sz - idx;
    if (numToMove > 0)
      std::memmove(&data()[idx + 1], &data()[idx],
                   numToMove * sizeof(PriceLevel));
    data()[idx] = v;
    ++sz;
  }
  void push_back(const PriceLevel &v) { insert(sz, v); }
  void erase(size_t idx) {
    if (idx < sz) {
      size_t numToMove = sz - idx - 1;
      if (numToMove > 0)
        std::memmove(&data()[idx], &data()[idx + 1],
                     numToMove * sizeof(PriceLevel));
      --sz;
    }
  }
};

// Orderbook structure
struct Orderbook {
  int32_t instrumentId;
  double tickSize;
  double invTickSize; // 1/tickSize precomputed
  double referencePrice;
  int32_t changeNo;

  // Price levels container with inline buffer and heap fallback
  PriceBuf asks;
  PriceBuf bids;

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
  std::pmr::vector<CachedParsedUpdateEvent> events;
  // Construct from any container of events into the arena
  template <typename Container>
  CachedParsedUpdate(int64_t changeNo_, const Container &evts,
                     std::pmr::memory_resource *mr)
      : changeNo(changeNo_), events(evts.begin(), evts.end(), mr) {}
  // Comparison operator for sorting
  bool operator<(const CachedParsedUpdate &other) const {
    return changeNo < other.changeNo;
  }
};

class OrderbookManager {
public:
  OrderbookManager();

  // Access the memory resource used for cached updates
  std::pmr::memory_resource *getUpdateResource() { return &updateResource; }

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
  void
  handleUpdateMessage(const UpdateHeader &header,
                      const std::pmr::vector<CachedParsedUpdateEvent> &events);

  // Check if a specific instrument's VWAP has changed
  bool isVWAPChanged(int32_t instrumentId) const;

  // Get valid orderbooks for output
  struct VWAPResult {
    int32_t instrumentId;
    uint32_t numerator;
    uint32_t denominator;
  };
  std::vector<VWAPResult> getValidOrderbooks() const;

  // Get instruments that were updated in the current frame
  std::vector<VWAPResult> getUpdatedInstruments() const;

  // Clear the list of changed VWAPs
  void clearChangedVWAPs();

  // Load target instruments directly
  void loadInstruments(const std::set<std::string> &instruments);

private:
  // Maps and sets for tracking
  std::unordered_map<int32_t, Orderbook> orderbooks;
  std::unordered_set<std::string> trackedInstruments;
  std::unordered_map<int32_t, std::string> idToName;

  // Track instruments that were updated in the current frame
  std::unordered_set<int32_t> updatedInstruments;

  // Memory pool for cached updates
  std::pmr::monotonic_buffer_resource updateResource;
  std::pmr::unordered_map<int32_t, std::pmr::vector<CachedParsedUpdate>>
      cachedParsedUpdates{&updateResource};

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

  // Helper function to infer missing levels in deletePriceLevel
  PriceLevel inferMissingLevel(const Orderbook &orderbook, Side side);

  // Helper method to normalize price consistently
  int64_t normalizePrice(double price, double tickSize);
};