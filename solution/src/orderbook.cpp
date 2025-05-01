#include "orderbook.h"
#include "pcap_reader.h" // For ipStringToUint32 if used
#include "protocol_logger.h"
#include <algorithm> // For std::sort, std::find_if
#include <cmath>     // Include for std::round
#include <cstdint>
#include <cstring>
#include <fstream> // For std::ifstream in loadMetadata
#include <limits>
#include <memory_resource> // For pmr::vector
#include <sstream>         // For std::istringstream in loadMetadata
#include <vector> // For std::vector in cachedParsedUpdates and getChangedVWAPs

// Orderbook constructor
Orderbook::Orderbook()
    : instrumentId(0), tickSize(0.0), referencePrice(0.0), changeNo(0),
      vwapNumerator(0), vwapDenominator(0), lastVwapNumerator(0),
      lastVwapDenominator(0), isValid(false), vwapChanged(false) {
  // Initialize inline buffers empty
  asks.clear();
  bids.clear();
}

// OrderbookManager constructor
OrderbookManager::OrderbookManager() : snapshotIP(0), updateIP(0) {
  LOG_INFO("OrderbookManager created.");
  updatedInstruments.reserve(100); // Reserve some initial capacity
}

// Check if an instrument name is tracked
bool OrderbookManager::isTrackedInstrument(const std::string &name) const {
  return trackedInstruments.count(name) > 0;
}

// Check if an instrument ID is tracked
bool OrderbookManager::isTrackedInstrumentId(int32_t id) const {
  auto it = idToName.find(id);
  if (it == idToName.end()) {
    return false;
  }
  return isTrackedInstrument(it->second);
}

// Check if an IP is relevant
bool OrderbookManager::isRelevantIP(uint32_t ip) const {
  return ip == snapshotIP || ip == updateIP;
}

// Process instrument info part of a snapshot
void OrderbookManager::processSnapshotInfo(const InstrumentInfo &info) {
  // Get instrument name and trim any trailing spaces
  std::string instrName(info.name);
  instrName.erase(
      std::find_if(instrName.rbegin(), instrName.rend(),
                   [](unsigned char ch) { return !std::isspace(ch); })
          .base(),
      instrName.end());

  LOG_DEBUG("Processing snapshot info for instrument '", instrName,
            "' (id=", info.instrumentId, ")");

  // Skip if not tracked
  if (!isTrackedInstrument(instrName)) {
    LOG_TRACE("Skipping untracked instrument: '", instrName, "'");
    // Clear any potentially cached updates for this untracked ID
    cachedParsedUpdates.erase(info.instrumentId);
    idToName.erase(
        info.instrumentId); // Also remove ID->name mapping if untracked
    orderbooks.erase(
        info.instrumentId); // Remove any potentially existing invalid book
    return;
  }

  LOG_INFO("Applying snapshot info for tracked instrument '", instrName,
           "' (id=", info.instrumentId, ")");

  // Create or get orderbook entry
  auto &orderbook = orderbooks[info.instrumentId]; // Creates if not exists

  // Reset orderbook state based on snapshot info
  orderbook.instrumentId = info.instrumentId;
  orderbook.tickSize = info.tickSize;
  orderbook.referencePrice = info.referencePrice;
  orderbook.changeNo = -1;
  orderbook.isValid = true;
  orderbook.asks.clear();
  orderbook.bids.clear();
  orderbook.vwapChanged = false;

  // Track ID to name mapping
  idToName[info.instrumentId] = instrName;

  LOG_DEBUG(
      "Initialized/Reset orderbook from snapshot info: id=", info.instrumentId,
      " TickSize=", info.tickSize, " RefPrice=", info.referencePrice);

  // VWAP calculation and cached update application happen in finalizeSnapshot
}

// Process orderbook entry from snapshot
void OrderbookManager::processSnapshotOrderbook(int32_t instrumentId, Side side,
                                                double price, int32_t volume) {
  // Find the orderbook - it must exist if processSnapshotInfo was called for a
  // tracked instrument
  auto it = orderbooks.find(instrumentId);
  if (it == orderbooks.end() || !isTrackedInstrumentId(instrumentId)) {
    LOG_WARN("Received snapshot OB entry for unknown/untracked id=",
             instrumentId);
    return;
  }

  Orderbook &orderbook = it->second;
  const char *sideStr = (side == Side::BID) ? "BID" : "ASK";
  LOG_TRACE("Processing snapshot OB entry: id=", instrumentId,
            " Side=", sideStr, " Price=", price, " Volume=", volume);

  // Snapshot provides only top levels, directly add to vector
  if (side == Side::BID) {
    if (orderbook.bids.size() < MAX_PRICE_LEVELS) {
      orderbook.bids.push_back({price, static_cast<int64_t>(volume)});
    } else {
      LOG_WARN("Snapshot provides more than MAX_PRICE_LEVELS BIDs for id=",
               instrumentId);
    }
  } else { // ASK
    if (orderbook.asks.size() < MAX_PRICE_LEVELS) {
      orderbook.asks.push_back({price, static_cast<int64_t>(volume)});
    } else {
      LOG_WARN("Snapshot provides more than MAX_PRICE_LEVELS ASKs for id=",
               instrumentId);
    }
  }
}

// Finalize snapshot processing for a given instrument
void OrderbookManager::finalizeSnapshot(int32_t instrumentId) {
  // Skip untracked instruments
  if (!isTrackedInstrumentId(instrumentId)) {
    LOG_TRACE("Skipping finalizeSnapshot for untracked id=", instrumentId);
    return;
  }

  auto it = orderbooks.find(instrumentId);
  // Verify orderbook exists and is valid
  if (it == orderbooks.end()) {
    LOG_ERROR("Finalize snapshot called for unknown instrument id=",
              instrumentId);
    return;
  }

  Orderbook &orderbook = it->second;

  if (!orderbook.isValid) {
    LOG_ERROR("Finalize snapshot called for invalid orderbook id=",
              instrumentId);
    return;
  }

  // Check if changeNo was set properly
  if (orderbook.changeNo == -1) {
    LOG_WARN(
        "Finalizing snapshot for ID ", instrumentId,
        " but changeNo was never set (missing TRADING_SESSION_INFO). Using 0.");
    orderbook.changeNo = 0; // Default to 0 if missing
  }

  LOG_DEBUG("Finalizing snapshot application for id=", instrumentId,
            " ChangeNo: ", orderbook.changeNo,
            " Bid Levels=", orderbook.bids.size(),
            " Ask Levels=", orderbook.asks.size());

  // Calculate initial VWAP based on the snapshot levels
  //   calculateVWAP(orderbook);

  // Store this initial VWAP state as the baseline
  //   orderbook.lastVwapNumerator = orderbook.vwapNumerator;
  //   orderbook.lastVwapDenominator = orderbook.vwapDenominator;
  //   orderbook.vwapChanged = false; // Reset flag, as this is the baseline

  // Verify orderbook is in a consistent state
  if (orderbook.tickSize <= 0) {
    LOG_WARN("Orderbook has invalid tick size (", orderbook.tickSize,
             ") after snapshot for ID ", instrumentId,
             ". This may cause problems with updates.");
  }

  if (orderbook.bids.empty() && orderbook.asks.empty()) {
    LOG_WARN("Empty orderbook (no bids or asks) after snapshot for ID ",
             instrumentId);
  }

  LOG_DEBUG("Initial VWAP calculated post-snapshot for ID ", instrumentId, ": ",
            orderbook.vwapNumerator, "/", orderbook.vwapDenominator);

  // Apply any relevant cached updates
  applyCachedUpdates(orderbook);
}

// Applies cached updates after a snapshot or potentially during recovery
void OrderbookManager::applyCachedUpdates(Orderbook &orderbook) {
  // Check if we have any cached updates for this instrument
  auto cacheIt = cachedParsedUpdates.find(orderbook.instrumentId);
  if (cacheIt == cachedParsedUpdates.end() || cacheIt->second.empty()) {
    LOG_TRACE("No cached updates found for ID ", orderbook.instrumentId);
    return;
  }

  LOG_INFO("Applying cached updates for id=", orderbook.instrumentId,
           " Current ChangeNo: ", orderbook.changeNo,
           " Cached Count: ", cacheIt->second.size());

  // Add to updated instruments when applying cached updates
  updatedInstruments.insert(orderbook.instrumentId);

  auto &cachedQueue = cacheIt->second;
  // Sort updates by changeNo to ensure we apply them in the correct order
  std::sort(cachedQueue.begin(), cachedQueue.end());

  size_t appliedCount = 0;
  auto queue_it = cachedQueue.begin();

  // Process all applicable updates
  while (queue_it != cachedQueue.end()) {
    // Stop processing if the orderbook becomes invalid
    if (!orderbook.isValid) {
      LOG_WARN("Orderbook ID ", orderbook.instrumentId,
               " became invalid during cached update application. Stopping.");
      break;
    }

    // Check if this is the next expected update
    if (queue_it->changeNo == orderbook.changeNo + 1) {
      LOG_INFO("Applying cached update id=", orderbook.instrumentId,
               " ChangeNo: ", queue_it->changeNo);

      // Store state before applying this update
      orderbook.lastVwapNumerator = orderbook.vwapNumerator;
      orderbook.lastVwapDenominator = orderbook.vwapDenominator;
      orderbook.vwapChanged = false;

      // Validate tick size before processing events
      if (orderbook.tickSize <= 0) {
        LOG_WARN("Invalid tick size (", orderbook.tickSize,
                 ") in cached update for ID ", orderbook.instrumentId,
                 ". Skipping update events.");
        orderbook.isValid = false;
        break;
      }

      // Process all events in this update
      for (const auto &event : queue_it->events) {
        double price =
            orderbook.referencePrice + (event.priceOffset * orderbook.tickSize);
        int priceLevelIndex =
            event.priceLevel - 1; // Convert 1-based to 0-based

        if (priceLevelIndex < 0) {
          LOG_ERROR("Invalid cached price level index (negative): ",
                    event.priceLevel, " for ID ", orderbook.instrumentId);
          continue;
        }

        try {
          switch (event.eventType) {
          case EventType::ADD:
            addPriceLevel(orderbook, event.side, priceLevelIndex, price,
                          event.volume);
            break;
          case EventType::MODIFY:
            modifyPriceLevel(orderbook, event.side, priceLevelIndex, price,
                             event.volume);
            break;
          case EventType::DELETE:
            deletePriceLevel(orderbook, event.side, priceLevelIndex);
            break;
          default:
            LOG_ERROR("Unknown event type in cached update: ",
                      static_cast<char>(event.eventType), " for ID ",
                      orderbook.instrumentId);
            break;
          }
        } catch (const std::out_of_range &e) {
          LOG_ERROR("Error processing cached price level index: ",
                    priceLevelIndex + 1, " for ID ", orderbook.instrumentId,
                    ": ", e.what());
        }
      }

      // Update change number and recalculate VWAP
      orderbook.changeNo = queue_it->changeNo;
      calculateVWAP(orderbook);

      // Process successful, remove from cache and advance iterator
      queue_it = cachedQueue.erase(queue_it);
      appliedCount++;
    }
    // Handle old or duplicate updates
    else if (queue_it->changeNo <= orderbook.changeNo) {
      LOG_WARN("Discarding old/duplicate cached update for id=",
               orderbook.instrumentId, " Cached ChangeNo: ", queue_it->changeNo,
               " Book ChangeNo: ", orderbook.changeNo);
      queue_it = cachedQueue.erase(queue_it);
    }
    // Sequence gap detected - can't apply further updates until we get a new
    // snapshot
    else {
      LOG_INFO(
          "Stopping cached update application for id=", orderbook.instrumentId,
          " Gap detected. Expected: ", orderbook.changeNo + 1,
          " Found: ", queue_it->changeNo);
      break; // Since updates are sorted, no more can apply
    }
  }

  // Log summary of applied updates
  LOG_INFO("Finished applying cached updates for id=", orderbook.instrumentId,
           ". Applied ", appliedCount,
           " updates. Remaining cached: ", cachedQueue.size());

  // Clean up empty cache entries
  if (cachedQueue.empty()) {
    cachedParsedUpdates.erase(cacheIt);
  }
  // Recycle PMR memory for cached updates after application
  updateResource.release();
}

// Process a fully parsed update message (header + events)
void OrderbookManager::handleUpdateMessage(
    const UpdateHeader &header,
    const std::pmr::vector<CachedParsedUpdateEvent> &events) {

  // Skip processing for untracked instruments
  if (!isTrackedInstrumentId(header.instrumentId)) {
    LOG_TRACE("Skipping update message for untracked instrument: ",
              header.instrumentId);
    return;
  }

  // Add this instrument to the list of updated instruments regardless of
  // whether we process it now or cache it for later
  updatedInstruments.insert(header.instrumentId);

  auto ob_it = orderbooks.find(header.instrumentId);
  bool bookExists = (ob_it != orderbooks.end());
  bool bookIsValid = bookExists && ob_it->second.isValid;
  int64_t currentChangeNo = bookExists ? ob_it->second.changeNo : -1;
  int64_t expectedChangeNo = bookExists ? currentChangeNo + 1 : -1;

  // --- Check for out-of-sequence or duplicate updates ---
  // Handle duplicate/old updates
  if (bookIsValid && header.changeNo <= currentChangeNo) {
    LOG_WARN("Received old update message for id=", header.instrumentId,
             " Received ChangeNo: ", header.changeNo,
             " Book ChangeNo: ", currentChangeNo, ". Discarding.");
    return; // Discard old messages
  }

  // --- Determine if caching is needed ---
  bool needsCaching = !bookExists || !bookIsValid ||
                      (bookIsValid && header.changeNo != expectedChangeNo);

  if (needsCaching) {
    LOG_INFO("Caching update message for id=", header.instrumentId,
             " ChangeNo: ", header.changeNo, " Reason: bookExists=", bookExists,
             " bookIsValid=", bookIsValid,
             " expectedChangeNo=", expectedChangeNo);

    // If book exists but update is out-of-sequence, invalidate the book
    if (bookIsValid && header.changeNo != expectedChangeNo) {
      LOG_WARN("Out-of-sequence update for id=", header.instrumentId,
               " Received=", header.changeNo, " Expected=", expectedChangeNo,
               ". Invalidating book.");
      ob_it->second.isValid = false; // Invalidate book
    }

    // Cache the update for later processing (use PMR-based CachedParsedUpdate)
    cachedParsedUpdates[header.instrumentId].emplace_back(
        header.changeNo, events, &updateResource);
    return;
  }

  // --- Direct Processing Logic ---
  Orderbook &orderbook = ob_it->second;
  LOG_TRACE("Processing update message directly for id=", header.instrumentId,
            " ChangeNo: ", header.changeNo);

  // Add log for update header and event count
  LOG_DEBUG("Processing update for ID ", header.instrumentId, " ChangeNo ",
            header.changeNo, " with ", events.size(), " events.");

  // Store previous VWAP state before applying events
  orderbook.lastVwapNumerator = orderbook.vwapNumerator;
  orderbook.lastVwapDenominator = orderbook.vwapDenominator;
  orderbook.vwapChanged = false;

  // Validate tick size before processing events
  if (orderbook.tickSize <= 0) {
    LOG_WARN("Invalid tick size (", orderbook.tickSize, ") for ID ",
             orderbook.instrumentId, ". Skipping update events.");
    return;
  }

  // Process all events in this update
  for (const auto &event : events) {
    double price =
        orderbook.referencePrice + (event.priceOffset * orderbook.tickSize);
    int priceLevelIndex = event.priceLevel - 1; // Convert 1-based to 0-based

    if (priceLevelIndex < 0) {
      LOG_ERROR("Invalid price level index (0 or negative): ", event.priceLevel,
                " for ID ", orderbook.instrumentId);
      continue;
    }

    try {
      switch (event.eventType) {
      case EventType::ADD:
        addPriceLevel(orderbook, event.side, priceLevelIndex, price,
                      event.volume);
        break;
      case EventType::MODIFY:
        modifyPriceLevel(orderbook, event.side, priceLevelIndex, price,
                         event.volume);
        break;
      case EventType::DELETE:
        deletePriceLevel(orderbook, event.side, priceLevelIndex);
        break;
      default:
        LOG_ERROR("Unknown event type in handleUpdateMessage: ",
                  static_cast<char>(event.eventType));
        break;
      }
    } catch (const std::out_of_range &e) {
      LOG_ERROR("Error processing price level index: ", priceLevelIndex + 1,
                " for ID ", orderbook.instrumentId, ": ", e.what());
    }
  }

  // Update the change number after successfully processing all events
  orderbook.changeNo = header.changeNo;

  // Add log for orderbook state after applying events
  LOG_DEBUG("Orderbook state for ID ", orderbook.instrumentId,
            " after applying update ", orderbook.changeNo, ":");
  LOG_DEBUG("  BidCount: ", orderbook.bids.size(),
            ", AskCount: ", orderbook.asks.size());
  LOG_DEBUG("  Bids:");
  for (size_t i = 0; i < orderbook.bids.size(); ++i) {
    LOG_DEBUG("    [", i, "] Price=", orderbook.bids[i].price,
              ", Volume=", orderbook.bids[i].volume);
  }
  LOG_DEBUG("  Asks:");
  for (size_t i = 0; i < orderbook.asks.size(); ++i) {
    LOG_DEBUG("    [", i, "] Price=", orderbook.asks[i].price,
              ", Volume=", orderbook.asks[i].volume);
  }

  // Calculate VWAP once after all events are applied
  calculateVWAP(orderbook);
}

// --- Internal Orderbook Manipulation ---

// Add a price level
void OrderbookManager::addPriceLevel(Orderbook &orderbook, Side side,
                                     int priceLevelIndex, double price,
                                     int64_t volume) {
  LOG_TRACE("Add Level: id=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " Price=", price, " Vol=", volume);

  PriceBuf &buf = (side == Side::BID) ? orderbook.bids : orderbook.asks;

  // Validate price level index
  if (priceLevelIndex < 0) {
    LOG_WARN("Negative price level index: ", priceLevelIndex, " for ID ",
             orderbook.instrumentId, ". Skipping.");
    return;
  }

  // Determine insert position (clamp to [0..size])
  size_t idx = (priceLevelIndex < 0) ? 0 : static_cast<size_t>(priceLevelIndex);
  if (idx > buf.size())
    idx = buf.size();
  buf.insert(idx, PriceLevel{price, volume});

  if (orderbook.instrumentId == 2882) {
    LOG_DEBUG("ID 2882 Add Final state after adding level at index ",
              priceLevelIndex, " (Price=", price, ", Volume=", volume, ") for ",
              (side == Side::BID ? "BID" : "ASK"), ". New count: ", buf.size(),
              ", Vector size: ", buf.size());
    // Log only top levels relevant for VWAP if vector is large
    int log_limit = std::min((size_t)buf.size(), MAX_PRICE_LEVELS + 2);
    for (int i = 0; i < log_limit; ++i) {
      if (i < buf.size()) { // Boundary check
        LOG_DEBUG("  Level[", i, "]: Price=", buf[i].price,
                  ", Volume=", buf[i].volume);
      } else {
        LOG_DEBUG("  Level[", i, "]: Index out of bounds (size=", buf.size(),
                  ")");
      }
    }
  }
}

// Modify a price level
void OrderbookManager::modifyPriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevelIndex, double price,
                                        int64_t volume) {
  LOG_TRACE("Modify Level: id=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " Price=", price, " Vol=", volume);

  PriceBuf &buf = (side == Side::BID) ? orderbook.bids : orderbook.asks;

  // Validate price level index
  if (priceLevelIndex < 0) {
    LOG_WARN("Negative price level index: ", priceLevelIndex, " for ID ",
             orderbook.instrumentId, ". Skipping.");
    return;
  }

  // If index beyond end, treat as add
  if (static_cast<size_t>(priceLevelIndex) >= buf.size()) {
    addPriceLevel(orderbook, side, priceLevelIndex, price, volume);
  } else {
    buf[priceLevelIndex] = {price, volume};
  }

  if (orderbook.instrumentId == 2882) {
    LOG_DEBUG("ID 2882 Modify Final state after modifying level at index ",
              priceLevelIndex, " (Price=", price, ", Volume=", volume, ") for ",
              (side == Side::BID ? "BID" : "ASK"), ". New count: ", buf.size(),
              ", Vector size: ", buf.size());
    int log_limit = std::min((size_t)buf.size(), MAX_PRICE_LEVELS + 2);
    for (int i = 0; i < log_limit; ++i) {
      if (i < buf.size()) { // Boundary check
        LOG_DEBUG("  Level[", i, "]: Price=", buf[i].price,
                  ", Volume=", buf[i].volume);
      } else {
        LOG_DEBUG("  Level[", i, "]: Index out of bounds (size=", buf.size(),
                  ")");
      }
    }
  }
}

// Helper function to infer a missing level based on existing patterns
PriceLevel OrderbookManager::inferMissingLevel(const Orderbook &orderbook,
                                               Side side) {
  const auto &levels = (side == Side::BID) ? orderbook.bids : orderbook.asks;
  int count =
      (side == Side::BID) ? orderbook.bids.size() : orderbook.asks.size();

  // Default in case we can't infer
  PriceLevel result = {0.0, 0};

  if (count < 2) {
    LOG_WARN("Not enough levels to infer missing level for ID ",
             orderbook.instrumentId);
    return result;
  }

  // Try to infer the pattern from the last two levels
  double priceDiff = 0.0;

  // For BID, prices typically decrease
  // For ASK, prices typically increase
  if (side == Side::BID) {
    // Check if the bid price sequence is decreasing
    if (levels[count - 2].price > levels[count - 1].price) {
      priceDiff = levels[count - 2].price - levels[count - 1].price;
      result.price = levels[count - 1].price - priceDiff;
    }
  } else { // ASK
    // Check if the ask price sequence is increasing
    if (levels[count - 2].price < levels[count - 1].price) {
      priceDiff = levels[count - 1].price - levels[count - 2].price;
      result.price = levels[count - 1].price + priceDiff;
    }
  }

  // If we found a reasonable pattern, use the average volume of existing levels
  if (priceDiff > 0) {
    int64_t totalVolume = 0;
    for (int i = 0; i < count; i++) {
      totalVolume += levels[i].volume;
    }
    result.volume = (count > 0) ? (totalVolume / count) : 1;

    // If the calculated volume is 0, default to 1
    if (result.volume <= 0) {
      result.volume = 1;
    }

    LOG_DEBUG("Inferred missing level for ID ", orderbook.instrumentId,
              " Side=", (side == Side::BID ? "BID" : "ASK"),
              " Price=", result.price, " Volume=", result.volume,
              " using price difference of ", priceDiff);
  } else {
    LOG_WARN("Could not infer price pattern for ID ", orderbook.instrumentId,
             " Side=", (side == Side::BID ? "BID" : "ASK"));

    // As a fallback for ASK side, try to use the tick size and last price
    if (side == Side::ASK && orderbook.tickSize > 0) {
      result.price = levels[count - 1].price + orderbook.tickSize;
      result.volume = 1; // Default volume
      LOG_DEBUG("Using fallback method for ID ", orderbook.instrumentId,
                " Added Price=", result.price, " at tick size ",
                orderbook.tickSize);
    }
  }

  return result;
}

// Delete a price level
void OrderbookManager::deletePriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevelIndex) {
  LOG_TRACE("Delete Level: id=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex);

  PriceBuf &buf = (side == Side::BID) ? orderbook.bids : orderbook.asks;

  // Validate index boundaries
  if (priceLevelIndex < 0 ||
      static_cast<size_t>(priceLevelIndex) >= buf.size()) {
    LOG_WARN("Delete level index out of bounds: Index=", priceLevelIndex,
             " for ID ", orderbook.instrumentId, ". Skipping.");
    return;
  }

  buf.erase(priceLevelIndex);

  // Add extra debug logging to understand the state right after the delete
  // operation
  LOG_TRACE("After deletion for ID ", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " New Count=", buf.size());

  if (orderbook.instrumentId == 2882) {
    LOG_DEBUG("ID 2882 Delete Final state for ",
              (side == Side::BID ? "BID" : "ASK"), ". New count: ", buf.size(),
              ", Vector size: ", buf.size());
    int log_limit = std::min((size_t)buf.size(), MAX_PRICE_LEVELS + 2);
    for (int i = 0; i < log_limit; ++i) {
      if (i < buf.size()) { // Boundary check
        LOG_DEBUG("  Level[", i, "]: Price=", buf[i].price,
                  ", Volume=", buf[i].volume);
      } else {
        LOG_DEBUG("  Level[", i, "]: Index out of bounds (size=", buf.size(),
                  ")");
      }
    }
  }
}

// Helper method to normalize price with consistent rounding
int64_t OrderbookManager::normalizePrice(double price, double tickSize) {
  // To ensure consistent normalization regardless of compiler/platform:
  // 1. Use a high-precision calculation first
  // 2. Apply proper rounding to nearest integer
  // The key is to handle potential floating-point imprecision

  // Calculate the precise tick count (price / tickSize)
  double exactTicks = price / tickSize;

  // Round to the nearest integer
  // Adding 0.5 and truncating is equivalent to rounding for positive numbers
  int64_t normalizedPrice = static_cast<int64_t>(exactTicks + 0.5);

  // In some edge cases with floating point math, values that should round up
  // might not due to representation error (e.g., 3134.999999 instead of 3135.0)
  // Check if we're extremely close to the next integer (within epsilon)
  constexpr double EPSILON = 1e-10;
  double fraction = exactTicks - floor(exactTicks);
  if (fraction > 0.5 - EPSILON && fraction < 0.5) {
    // We're just barely below 0.5, which might be due to floating-point error
    LOG_TRACE("Price normalization: Adjusting borderline case ", exactTicks,
              " (fraction=", fraction, ") from ", normalizedPrice, " to ",
              static_cast<int64_t>(floor(exactTicks) + 1));
    normalizedPrice = static_cast<int64_t>(floor(exactTicks) + 1);
  }

  return normalizedPrice;
}

// Calculate VWAP for an orderbook
void OrderbookManager::calculateVWAP(Orderbook &orderbook) {
  if (!orderbook.isValid) {
    LOG_TRACE("Skipping VWAP calculation for invalid orderbook id=",
              orderbook.instrumentId);
    orderbook.vwapChanged = false;
    return;
  }

  if (orderbook.tickSize <= 0) {
    LOG_WARN("Invalid tick size (", orderbook.tickSize, ") for ID ",
             orderbook.instrumentId, ". VWAP calculation skipped.");
    orderbook.vwapChanged = false;
    return;
  }

  LOG_TRACE("Calculating VWAP for id=", orderbook.instrumentId);
  uint64_t numeratorSum = 0;
  uint64_t denominatorSum = 0;

  // Log the current state of the orderbook
  LOG_TRACE("Current orderbook state for ID ", orderbook.instrumentId,
            " - BidCount: ", orderbook.bids.size(),
            ", AskCount: ", orderbook.asks.size(),
            ", TickSize: ", orderbook.tickSize,
            ", Bid vector size: ", orderbook.bids.size(),
            ", Ask vector size: ", orderbook.asks.size());

  // Determine number of levels to consider for VWAP (top MAX_PRICE_LEVELS)
  size_t bidLevelsToConsider =
      std::min((size_t)orderbook.bids.size(), MAX_PRICE_LEVELS);
  size_t askLevelsToConsider =
      std::min((size_t)orderbook.asks.size(), MAX_PRICE_LEVELS);

  // Detailed check for zero or negative volume/price entries within considered
  // levels
  bool hasZeroOrNegativeEntries = false;

  // Log bids (only those considered for VWAP)
  LOG_TRACE("Bid levels considered for VWAP (up to ", bidLevelsToConsider,
            ") for ID ", orderbook.instrumentId, ":");
  for (size_t i = 0; i < bidLevelsToConsider; ++i) {
    const auto &level = orderbook.bids[i];
    LOG_TRACE("  Bid[", i, "]: Price=", level.price, " Volume=", level.volume);
    if (level.volume <= 0 || level.price <= 0) {
      LOG_WARN("Zero or negative entry found in Bid[", i,
               "]: Price=", level.price, " Volume=", level.volume, " for ID ",
               orderbook.instrumentId);
      hasZeroOrNegativeEntries = true;
    }
  }

  // Log asks (only those considered for VWAP)
  LOG_TRACE("Ask levels considered for VWAP (up to ", askLevelsToConsider,
            ") for ID ", orderbook.instrumentId, ":");
  for (size_t i = 0; i < askLevelsToConsider; ++i) {
    const auto &level = orderbook.asks[i];
    LOG_TRACE("  Ask[", i, "]: Price=", level.price, " Volume=", level.volume);
    if (level.volume <= 0 || level.price <= 0) {
      LOG_WARN("Zero or negative entry found in Ask[", i,
               "]: Price=", level.price, " Volume=", level.volume, " for ID ",
               orderbook.instrumentId);
      hasZeroOrNegativeEntries = true;
    }
  }

  if (hasZeroOrNegativeEntries) {
    LOG_WARN("Zero or negative entries found in orderbook ID ",
             orderbook.instrumentId,
             ". These will be skipped in VWAP calculation.");
  }

  int bidsContributing = 0;
  // Bids - Iterate only up to bidLevelsToConsider
  for (size_t i = 0; i < bidLevelsToConsider; ++i) {
    const auto &level = orderbook.bids[i];
    if (level.volume > 0 && level.price > 0) {
      // Use the consistent normalization helper
      int64_t normalizedPrice = normalizePrice(level.price, orderbook.tickSize);

      // Log the contribution from this level
      LOG_TRACE("Bid[", i, "] contributes: Price=", level.price,
                " NormalizedPrice=", normalizedPrice, " Volume=", level.volume,
                " To numerator: +",
                (normalizedPrice * static_cast<uint64_t>(level.volume)),
                " To denominator: +", static_cast<uint64_t>(level.volume));

      // Safety check to avoid overflow
      if (normalizedPrice > 0 &&
          static_cast<uint64_t>(normalizedPrice) >
              UINT64_MAX / static_cast<uint64_t>(level.volume)) {
        LOG_WARN("Potential overflow in VWAP calculation for ID ",
                 orderbook.instrumentId, ". Skipping level.");
        continue;
      }

      numeratorSum += normalizedPrice * static_cast<uint64_t>(level.volume);
      denominatorSum += static_cast<uint64_t>(level.volume);
      bidsContributing++;
    }
  }

  int asksContributing = 0;
  // Asks - Iterate only up to askLevelsToConsider
  for (size_t i = 0; i < askLevelsToConsider; ++i) {
    const auto &level = orderbook.asks[i];
    if (level.volume > 0 && level.price > 0) {
      // Use the same consistent normalization helper for asks
      double exactTicks = level.price / orderbook.tickSize;
      int64_t normalizedPrice = normalizePrice(level.price, orderbook.tickSize);

      // Log extra details for debugging
      LOG_TRACE("Ask[", i, "] price division: ", level.price, " / ",
                orderbook.tickSize, " = ", exactTicks, " normalized to ",
                normalizedPrice);

      // Log the contribution from this level
      LOG_TRACE("Ask[", i, "] contributes: Price=", level.price,
                " NormalizedPrice=", normalizedPrice, " Volume=", level.volume,
                " To numerator: +",
                (normalizedPrice * static_cast<uint64_t>(level.volume)),
                " To denominator: +", static_cast<uint64_t>(level.volume));

      // Safety check to avoid overflow
      if (normalizedPrice > 0 &&
          static_cast<uint64_t>(normalizedPrice) >
              UINT64_MAX / static_cast<uint64_t>(level.volume)) {
        LOG_WARN("Potential overflow in VWAP calculation for ID ",
                 orderbook.instrumentId, ". Skipping level.");
        continue;
      }

      numeratorSum += normalizedPrice * static_cast<uint64_t>(level.volume);
      denominatorSum += static_cast<uint64_t>(level.volume);
      asksContributing++;
    }
  }

  LOG_TRACE("VWAP contribution summary - Bids contributing: ", bidsContributing,
            " Asks contributing: ", asksContributing);

  // Log raw totals before truncation
  LOG_TRACE("Raw VWAP calculation for ID ", orderbook.instrumentId,
            " - Total numerator: ", numeratorSum,
            " Total denominator: ", denominatorSum);

  // Expected values comparison (for debugging)
  if (orderbook.instrumentId == 2882) {
    LOG_DEBUG("ID 2882 result comparison - Got: numerator=", numeratorSum,
              " denominator=", denominatorSum,
              " Expected: numerator=58355 denominator=19");
  }

  // Safely truncate to uint32_t - VWAP components are defined as uint32_t in
  // the struct
  uint32_t finalNumerator = (numeratorSum > UINT32_MAX)
                                ? UINT32_MAX
                                : static_cast<uint32_t>(numeratorSum);
  uint32_t finalDenominator = (denominatorSum > UINT32_MAX)
                                  ? UINT32_MAX
                                  : static_cast<uint32_t>(denominatorSum);

  // While we now report all valid orderbooks, we still track VWAP changes for
  // debugging
  // The VWAP changes if either the numerator or denominator is different from
  // the last recorded values.
  orderbook.vwapChanged = (finalNumerator != orderbook.lastVwapNumerator ||
                           finalDenominator != orderbook.lastVwapDenominator);

  orderbook.vwapNumerator = finalNumerator;
  orderbook.vwapDenominator = finalDenominator;

  LOG_TRACE("Final VWAP: N=", orderbook.vwapNumerator,
            " D=", orderbook.vwapDenominator,
            " Changed=", (orderbook.vwapChanged ? "yes" : "no"));
}

// Get valid orderbooks for output
std::vector<OrderbookManager::VWAPResult>
OrderbookManager::getValidOrderbooks() const {
  LOG_TRACE("Getting valid orderbooks for VWAP reporting...");
  std::vector<VWAPResult> results;
  results.reserve(orderbooks.size()); // Pre-allocate to avoid reallocations

  for (const auto &pair : orderbooks) {
    const auto &orderbook = pair.second;

    // Report all valid orderbooks with both bids and asks
    if (orderbook.isValid && !orderbook.asks.empty() &&
        !orderbook.bids.empty() &&
        orderbook.vwapDenominator >
            0) { // Ensure we don't report zero-denominator VWAPs

      LOG_DEBUG("Reporting VWAP for id=", orderbook.instrumentId,
                " VWAP: ", orderbook.vwapNumerator, "/",
                orderbook.vwapDenominator,
                " Changed: ", (orderbook.vwapChanged ? "yes" : "no"));

      results.push_back({orderbook.instrumentId, orderbook.vwapNumerator,
                         orderbook.vwapDenominator});
    } else {
      // Log skipped orderbooks for debugging
      LOG_TRACE("Orderbook for ID ", orderbook.instrumentId,
                " not reported: isValid=", orderbook.isValid,
                ", askCount=", orderbook.asks.size(),
                ", bidCount=", orderbook.bids.size(),
                ", denominator=", orderbook.vwapDenominator);
    }
  }

  LOG_TRACE("Found ", results.size(), " valid orderbooks to report out of ",
            orderbooks.size(), " total orderbooks.");
  return results;
}

// This method may not be needed anymore since we now report all valid
// orderbooks But keeping it for potential future use to track changes between
// updates
void OrderbookManager::clearChangedVWAPs() {
  // Clear the vwapChanged flag for all orderbooks
  for (auto &pair : orderbooks) {
    pair.second.vwapChanged = false;
  }

  // Clear the list of updated instruments
  updatedInstruments.clear();

  LOG_TRACE("Cleared changed VWAP flags and updated instruments list.");
}

void OrderbookManager::loadInstruments(
    const std::set<std::string> &instruments) {
  trackedInstruments.clear(); // Clear any previous state
  trackedInstruments.reserve(
      instruments.size()); // Optional: Reserve for efficiency
  for (const auto &instrument : instruments) {
    trackedInstruments.insert(instrument);
  }
  LOG_INFO("OrderbookManager loaded ", trackedInstruments.size(),
           " instruments for tracking.");
  // Reset and reserve the PMR pool for cached updates
  updateResource.release();
  cachedParsedUpdates.clear();
  cachedParsedUpdates.reserve(trackedInstruments.size());
}

// Update change number from snapshot's trading session info
void OrderbookManager::updateSnapshotChangeNo(int32_t instrumentId,
                                              int32_t changeNo) {
  if (!isTrackedInstrumentId(instrumentId)) {
    LOG_TRACE("Ignoring change number update for untracked id=", instrumentId);
    return;
  }
  auto it = orderbooks.find(instrumentId);
  // Check if book exists AND was marked valid by a preceding
  // processSnapshotInfo call
  if (it != orderbooks.end() && it->second.isValid) {
    LOG_DEBUG("Updating snapshot change number for ID ", instrumentId, " from ",
              it->second.changeNo, " to ", changeNo);
    it->second.changeNo = changeNo;
  } else {
    // This might happen if trading session info comes before instrument info,
    // which is a protocol violation
    LOG_WARN(
        "Attempted to update change number for unknown or invalid snapshot "
        "id=",
        instrumentId, ". Book found: ", (it != orderbooks.end()), " IsValid: ",
        (it != orderbooks.end() ? std::to_string(it->second.isValid) : "N/A"));
  }
}

// Check if a specific instrument's VWAP has changed
bool OrderbookManager::isVWAPChanged(int32_t instrumentId) const {
  auto it = orderbooks.find(instrumentId);
  if (it != orderbooks.end()) {
    return it->second.vwapChanged;
  }
  return false;
}

// Get instruments that were updated in the current frame
std::vector<OrderbookManager::VWAPResult>
OrderbookManager::getUpdatedInstruments() const {
  LOG_TRACE("Getting updated instruments for VWAP reporting...");
  std::vector<VWAPResult> results;
  results.reserve(
      updatedInstruments.size()); // Pre-allocate to avoid reallocations

  for (int32_t instrumentId : updatedInstruments) {
    auto it = orderbooks.find(instrumentId);
    if (it != orderbooks.end()) {
      const auto &orderbook = it->second;

      // Only report instruments that have valid orderbooks with both bids and
      // asks AND whose VWAP has changed
      if (orderbook.isValid && !orderbook.asks.empty() &&
          !orderbook.bids.empty() && orderbook.vwapDenominator > 0 &&
          orderbook.vwapChanged) {

        LOG_DEBUG("Reporting VWAP for updated ID ", orderbook.instrumentId,
                  " VWAP: ", orderbook.vwapNumerator, "/",
                  orderbook.vwapDenominator,
                  " Changed: ", (orderbook.vwapChanged ? "yes" : "no"));

        results.push_back({orderbook.instrumentId, orderbook.vwapNumerator,
                           orderbook.vwapDenominator});
      } else {
        // Log skipped orderbooks for debugging
        LOG_TRACE("Updated orderbook for ID ", orderbook.instrumentId,
                  " not reported: isValid=", orderbook.isValid,
                  ", askCount=", orderbook.asks.size(),
                  ", bidCount=", orderbook.bids.size(),
                  ", denominator=", orderbook.vwapDenominator);
      }
    }
  }

  LOG_TRACE("Found ", results.size(),
            " valid updated orderbooks to report out of ",
            updatedInstruments.size(), " total updated instruments.");
  return results;
}
