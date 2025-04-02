#include "orderbook.h"
#include "pcap_reader.h" // For ipStringToUint32 if used
#include "protocol_logger.h"
#include <algorithm> // For std::sort, std::find_if
#include <cstdint>
#include <fstream> // For std::ifstream in loadMetadata
#include <sstream> // For std::istringstream in loadMetadata
#include <vector>  // For std::vector in cachedParsedUpdates and getChangedVWAPs

// Orderbook constructor
Orderbook::Orderbook()
    : instrumentId(0), tickSize(0.0), referencePrice(0.0), changeNo(0),
      askCount(0), bidCount(0), vwapNumerator(0), vwapDenominator(0),
      lastVwapNumerator(0), lastVwapDenominator(0), isValid(false),
      vwapChanged(false) {

  // Initialize arrays with zeros
  for (auto &ask : asks) {
    ask.price = 0.0;
    ask.volume = 0;
  }
  for (auto &bid : bids) {
    bid.price = 0.0;
    bid.volume = 0;
  }
}

// OrderbookManager constructor
OrderbookManager::OrderbookManager() : snapshotIP(0), updateIP(0) {
  LOG_INFO("OrderbookManager created.");
}

// Load metadata (IPs and instrument names)
void OrderbookManager::loadMetadata(const std::string &metadataPath) {
  LOG_INFO("Loading metadata from: ", metadataPath);
  std::ifstream file(metadataPath);
  if (!file.is_open()) {
    LOG_ERROR("Failed to open metadata file: ", metadataPath);
    throw std::runtime_error("Failed to open metadata file: " + metadataPath);
  }

  std::string line;

  // Read IPs from the first line
  if (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string ip1, ip2;
    if (iss >> ip1 >> ip2) {
      snapshotIP =
          ipStringToUint32(ip1); // Assumes ipStringToUint32 is available
      updateIP = ipStringToUint32(ip2);
      LOG_INFO("Loaded IPs: snapshot=", ip1, " update=", ip2);
    } else {
      LOG_ERROR("Failed to parse IPs from metadata");
      throw std::runtime_error("Failed to parse IPs from metadata");
    }
  } else {
    LOG_ERROR("Metadata file is empty or missing IP line");
    throw std::runtime_error("Metadata file is empty or missing IP line");
  }

  // Read tracked instruments
  int instrumentCount = 0;
  while (std::getline(file, line)) {
    if (!line.empty()) {
      // Remove any trailing whitespace
      line.erase(
          std::find_if(line.rbegin(), line.rend(),
                       [](unsigned char ch) { return !std::isspace(ch); })
              .base(),
          line.end());

      if (!line.empty()) {
        trackedInstruments.insert(line);
        LOG_DEBUG("Tracking instrument: '", line, "'");
        instrumentCount++;
      }
    }
  }
  LOG_INFO("Total tracked instruments: ", instrumentCount);
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
            "' (ID: ", info.instrumentId, ")");

  // Skip if not tracked
  if (!isTrackedInstrument(instrName)) {
    LOG_TRACE("Skipping untracked instrument: '", instrName, "'");
    // Clear any potentially cached updates for this untracked ID
    cachedParsedUpdates.erase(info.instrumentId);
    return;
  }

  LOG_INFO("Applying snapshot for tracked instrument '", instrName,
           "' (ID: ", info.instrumentId, ")");

  // Create or get orderbook entry
  auto &orderbook = orderbooks[info.instrumentId]; // Creates if not exists

  // Reset orderbook state based on snapshot info
  orderbook.instrumentId = info.instrumentId;
  orderbook.tickSize = info.tickSize;
  orderbook.referencePrice = info.referencePrice;
  orderbook.changeNo = info.changeNo;
  orderbook.isValid = true; // Mark as valid *after* applying snapshot base info
  orderbook.askCount = 0;   // Clear existing levels
  orderbook.bidCount = 0;
  for (auto &level : orderbook.asks)
    level = {0.0, 0}; // Reset array elements
  for (auto &level : orderbook.bids)
    level = {0.0, 0};          // Reset array elements
  orderbook.vwapNumerator = 0; // Reset VWAP components
  orderbook.vwapDenominator = 0;
  orderbook.lastVwapNumerator = 0; // Reset history
  orderbook.lastVwapDenominator = 0;
  orderbook.vwapChanged = false; // Reset flag

  // Track ID to name mapping
  idToName[info.instrumentId] = instrName;

  LOG_DEBUG("Initialized/Reset orderbook from snapshot info: ID=",
            info.instrumentId, " ChangeNo=", info.changeNo,
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
    LOG_WARN("Received snapshot OB entry for unknown/untracked ID: ",
             instrumentId);
    return;
  }

  Orderbook &orderbook = it->second;
  const char *sideStr = (side == Side::BID) ? "BID" : "ASK";
  LOG_TRACE("Processing snapshot OB entry: ID=", instrumentId,
            " Side=", sideStr, " Price=", price, " Volume=", volume);

  if (side == Side::BID) {
    if (orderbook.bidCount < MAX_PRICE_LEVELS) {
      orderbook.bids[orderbook.bidCount++] = {
          price, static_cast<int64_t>(volume)}; // Cast volume
    } else {
      LOG_WARN("Snapshot provides more than MAX_PRICE_LEVELS BIDs for ID: ",
               instrumentId);
    }
  } else { // ASK
    if (orderbook.askCount < MAX_PRICE_LEVELS) {
      orderbook.asks[orderbook.askCount++] = {
          price, static_cast<int64_t>(volume)}; // Cast volume
    } else {
      LOG_WARN("Snapshot provides more than MAX_PRICE_LEVELS ASKs for ID: ",
               instrumentId);
    }
  }
}

// Finalize snapshot processing for a given instrument
void OrderbookManager::finalizeSnapshot(int32_t instrumentId) {
  auto it = orderbooks.find(instrumentId);
  if (it == orderbooks.end() || !it->second.isValid) {
    LOG_ERROR("Finalize snapshot called for unknown or invalid ID: ",
              instrumentId);
    return;
  }
  Orderbook &orderbook = it->second;

  LOG_DEBUG("Finalizing snapshot application for ID: ", instrumentId,
            " Bid Levels=", orderbook.bidCount,
            " Ask Levels=", orderbook.askCount);

  // 1. Calculate initial VWAP based on the now populated snapshot levels
  calculateVWAP(orderbook);

  // 2. Store this initial VWAP state as the baseline "last" state
  orderbook.lastVwapNumerator = orderbook.vwapNumerator;
  orderbook.lastVwapDenominator = orderbook.vwapDenominator;
  orderbook.vwapChanged = false;

  LOG_DEBUG("Initial VWAP calculated post-snapshot for ID ", instrumentId, ": ",
            orderbook.vwapNumerator, "/", orderbook.vwapDenominator);

  // 3. Attempt to apply any relevant cached updates
  applyCachedUpdates(orderbook);
}

// Applies cached updates after a snapshot or potentially during recovery
void OrderbookManager::applyCachedUpdates(Orderbook &orderbook) {
  auto cacheIt = cachedParsedUpdates.find(orderbook.instrumentId);
  if (cacheIt == cachedParsedUpdates.end() || cacheIt->second.empty()) {
    return; // No cached updates
  }

  LOG_INFO("Applying cached updates for ID: ", orderbook.instrumentId,
           " Current ChangeNo: ", orderbook.changeNo,
           " Cached Count: ", cacheIt->second.size());

  auto &cachedQueue = cacheIt->second;
  std::sort(cachedQueue.begin(), cachedQueue.end()); // Sort by changeNo

  size_t appliedCount = 0;
  auto queue_it = cachedQueue.begin(); // Use different iterator name

  while (queue_it != cachedQueue.end()) {
    if (!orderbook.isValid) {
      LOG_WARN("Orderbook ID ", orderbook.instrumentId,
               " became invalid during cached update application. Stopping.");
      break;
    }

    if (queue_it->changeNo == orderbook.changeNo + 1) {
      LOG_INFO("Applying cached update ID: ", orderbook.instrumentId,
               " ChangeNo: ", queue_it->changeNo);

      // Store state *before* applying this cached update
      orderbook.lastVwapNumerator = orderbook.vwapNumerator;
      orderbook.lastVwapDenominator = orderbook.vwapDenominator;
      orderbook.vwapChanged = false;

      for (const auto &event : queue_it->events) {
        if (orderbook.tickSize <= 0) {
          LOG_WARN("Invalid tick size while applying cached update for ID ",
                   orderbook.instrumentId, ". Skipping event.");
          continue;
        }
        double price =
            orderbook.referencePrice + (event.priceOffset * orderbook.tickSize);
        int priceLevelIndex =
            event.priceLevel - 1; // Convert 1-based to 0-based

        if (priceLevelIndex < 0) {
          LOG_ERROR("Invalid cached price level index: ", event.priceLevel);
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
                      static_cast<char>(event.eventType));
            break;
          }
        } catch (const std::out_of_range &e) {
          LOG_ERROR("Error processing cached price level index: ",
                    priceLevelIndex + 1, " for ID ", orderbook.instrumentId);
        }
      }

      orderbook.changeNo = queue_it->changeNo;
      calculateVWAP(
          orderbook); // Recalculate VWAP and set vwapChanged if needed

      // Remove from cache (iterator invalidation - erase and advance)
      queue_it = cachedQueue.erase(queue_it);
      appliedCount++;

    } else if (queue_it->changeNo <= orderbook.changeNo) {
      LOG_WARN("Discarding old/duplicate cached update for ID: ",
               orderbook.instrumentId, " Cached ChangeNo: ", queue_it->changeNo,
               " Book ChangeNo: ", orderbook.changeNo);
      queue_it = cachedQueue.erase(queue_it);
    } else { // Gap detected
      LOG_INFO(
          "Stopping cached update application for ID: ", orderbook.instrumentId,
          " Gap detected. Expected: ", orderbook.changeNo + 1,
          " Found: ", queue_it->changeNo);
      break; // Since sorted, no more can apply
    }
  }

  LOG_INFO("Finished applying cached updates for ID: ", orderbook.instrumentId,
           ". Applied ", appliedCount,
           " updates. Remaining cached: ", cachedQueue.size());
  if (cachedQueue.empty()) {
    cachedParsedUpdates.erase(cacheIt);
  }
}

// Process a fully parsed update message (header + events)
void OrderbookManager::handleUpdateMessage(
    const UpdateHeader &header,
    const std::vector<CachedParsedUpdateEvent> &events) {

  if (!isTrackedInstrumentId(header.instrumentId)) {
    LOG_TRACE("Skipping update message for untracked instrument: ",
              header.instrumentId);
    return;
  }

  auto ob_it =
      orderbooks.find(header.instrumentId); // Use different iterator name
  bool bookExists = (ob_it != orderbooks.end());
  bool bookIsValid = bookExists && ob_it->second.isValid;
  int64_t currentChangeNo = bookExists ? ob_it->second.changeNo : -1;
  int64_t expectedChangeNo = bookExists ? currentChangeNo + 1 : -1;

  // --- Caching Logic ---
  bool needsCaching = !bookExists || !bookIsValid ||
                      (bookIsValid && header.changeNo != expectedChangeNo);

  if (bookIsValid && header.changeNo <= currentChangeNo) {
    LOG_WARN("Received old update message for ID: ", header.instrumentId,
             " Received ChangeNo: ", header.changeNo,
             " Book ChangeNo: ", currentChangeNo, ". Discarding.");
    return; // Discard old messages
  }

  if (needsCaching) {
    LOG_INFO("Caching update message for ID: ", header.instrumentId,
             " ChangeNo: ", header.changeNo, " Reason: bookExists=", bookExists,
             " bookIsValid=", bookIsValid,
             " expectedChangeNo=", expectedChangeNo);

    if (bookIsValid && header.changeNo != expectedChangeNo) {
      LOG_WARN("Out-of-sequence update for ID: ", header.instrumentId,
               " Received=", header.changeNo, " Expected=", expectedChangeNo,
               ". Invalidating book.");
      ob_it->second.isValid = false; // Invalidate book
    }
    cachedParsedUpdates[header.instrumentId].push_back(
        {header.changeNo, events});
    return;
  }

  // --- Direct Processing Logic ---
  Orderbook &orderbook = ob_it->second;
  LOG_TRACE("Processing update message directly for ID: ", header.instrumentId,
            " ChangeNo: ", header.changeNo);

  // Store previous VWAP state before applying events
  orderbook.lastVwapNumerator = orderbook.vwapNumerator;
  orderbook.lastVwapDenominator = orderbook.vwapDenominator;
  orderbook.vwapChanged = false;

  for (const auto &event : events) {
    if (orderbook.tickSize <= 0) {
      LOG_WARN("Invalid tick size for ID ", header.instrumentId,
               ". Skipping event.");
      continue;
    }
    double price =
        orderbook.referencePrice + (event.priceOffset * orderbook.tickSize);
    int priceLevelIndex = event.priceLevel - 1; // Convert 1-based to 0-based

    if (priceLevelIndex < 0) {
      LOG_ERROR("Invalid price level index (0 or negative): ",
                event.priceLevel);
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
                " for ID ", header.instrumentId);
    }
  }

  orderbook.changeNo = header.changeNo;
  calculateVWAP(orderbook); // Calculate VWAP once after all events are applied
}

// --- Internal Orderbook Manipulation ---

// Add a price level
void OrderbookManager::addPriceLevel(Orderbook &orderbook, Side side,
                                     int priceLevelIndex, double price,
                                     int64_t volume) {
  LOG_TRACE("Add Level: ID=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " Price=", price, " Vol=", volume);

  auto &levels = (side == Side::BID) ? orderbook.bids : orderbook.asks;
  int &count = (side == Side::BID) ? orderbook.bidCount : orderbook.askCount;

  if (priceLevelIndex < 0 || priceLevelIndex > count ||
      priceLevelIndex >= MAX_PRICE_LEVELS) {
    LOG_WARN("Add level index out of bounds: Index=", priceLevelIndex,
             " CurrentCount=", count, " MaxLevels=", MAX_PRICE_LEVELS);
    return;
  }

  if (priceLevelIndex <
      count) { // Inserting within existing or replacing last element if full
    if (count == MAX_PRICE_LEVELS) { // Shift and overwrite last if full
      for (int i = count - 1; i > priceLevelIndex; --i) {
        levels[i] = levels[i - 1];
      }
    } else { // Shift and increment count if not full
      for (int i = count; i > priceLevelIndex; --i) {
        levels[i] = levels[i - 1];
      }
      count++;
    }
  } else if (priceLevelIndex == count &&
             count < MAX_PRICE_LEVELS) { // Appending
    count++;
  }
  // Insert/Update the level data
  levels[priceLevelIndex] = {price, volume};
}

// Modify a price level
void OrderbookManager::modifyPriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevelIndex, double price,
                                        int64_t volume) {
  LOG_TRACE("Modify Level: ID=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " Price=", price, " Vol=", volume);

  auto &levels = (side == Side::BID) ? orderbook.bids : orderbook.asks;
  int count = (side == Side::BID) ? orderbook.bidCount : orderbook.askCount;

  if (priceLevelIndex < 0 || priceLevelIndex >= count) {
    LOG_WARN("Modify level index out of bounds: Index=", priceLevelIndex,
             " Count=", count);
    return;
  }
  levels[priceLevelIndex] = {price, volume};
}

// Delete a price level
void OrderbookManager::deletePriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevelIndex) {
  LOG_TRACE("Delete Level: ID=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex);

  auto &levels = (side == Side::BID) ? orderbook.bids : orderbook.asks;
  int &count = (side == Side::BID) ? orderbook.bidCount : orderbook.askCount;

  if (priceLevelIndex < 0 || priceLevelIndex >= count) {
    LOG_WARN("Delete level index out of bounds: Index=", priceLevelIndex,
             " Count=", count);
    return;
  }

  for (int i = priceLevelIndex; i < count - 1; ++i) {
    levels[i] = levels[i + 1];
  }

  if (count > 0) {
    count--;
    levels[count] = {0.0, 0}; // Clear the element at the new end
  }
}

// Calculate VWAP for an orderbook
void OrderbookManager::calculateVWAP(Orderbook &orderbook) {
  if (!orderbook.isValid) {
    LOG_TRACE("Skipping VWAP calculation for invalid orderbook ID: ",
              orderbook.instrumentId);
    orderbook.vwapChanged = false;
    return;
  }
  if (orderbook.tickSize <= 0) {
    LOG_WARN("Invalid tick size (", orderbook.tickSize, ") for ID ",
             orderbook.instrumentId, ". VWAP calculation skipped.");
    orderbook.vwapChanged =
        (orderbook.vwapNumerator != orderbook.lastVwapNumerator ||
         orderbook.vwapDenominator != orderbook.lastVwapDenominator);
    return;
  }

  LOG_TRACE("Calculating VWAP for ID: ", orderbook.instrumentId);
  uint64_t numeratorSum = 0;
  uint64_t denominatorSum = 0;

  // Bids
  for (int i = 0; i < orderbook.bidCount; ++i) {
    const auto &level = orderbook.bids[i];
    if (level.volume > 0 && level.price > 0) {
      uint32_t normalizedPrice = static_cast<uint32_t>(
          level.price / orderbook.tickSize + 0.5); // Rounding
      numeratorSum += static_cast<uint64_t>(normalizedPrice) * level.volume;
      denominatorSum += level.volume;
    }
  }

  // Asks
  for (int i = 0; i < orderbook.askCount; ++i) {
    const auto &level = orderbook.asks[i];
    if (level.volume > 0 && level.price > 0) {
      uint32_t normalizedPrice = static_cast<uint32_t>(
          level.price / orderbook.tickSize + 0.5); // Rounding
      numeratorSum += static_cast<uint64_t>(normalizedPrice) * level.volume;
      denominatorSum += level.volume;
    }
  }

  uint32_t finalNumerator = static_cast<uint32_t>(numeratorSum);
  uint32_t finalDenominator = static_cast<uint32_t>(denominatorSum);

  if (finalNumerator != orderbook.lastVwapNumerator ||
      finalDenominator != orderbook.lastVwapDenominator) {
    LOG_DEBUG("VWAP changed for ID: ", orderbook.instrumentId,
              " New: ", finalNumerator, "/", finalDenominator,
              " Old: ", orderbook.lastVwapNumerator, "/",
              orderbook.lastVwapDenominator);
    orderbook.vwapChanged = true;
  } else {
    orderbook.vwapChanged = false;
  }

  orderbook.vwapNumerator = finalNumerator;
  orderbook.vwapDenominator = finalDenominator;

  LOG_TRACE("  Final VWAP: N=", orderbook.vwapNumerator,
            " D=", orderbook.vwapDenominator,
            " Changed=", (orderbook.vwapChanged ? "yes" : "no"));
}

// Get changed VWAPs
std::vector<OrderbookManager::VWAPResult>
OrderbookManager::getChangedVWAPs() const {
  LOG_TRACE("Getting changed VWAPs...");
  std::vector<VWAPResult> results;
  for (const auto &pair : orderbooks) {
    const auto &orderbook = pair.second;
    if (orderbook.vwapChanged && orderbook.isValid && orderbook.askCount > 0 &&
        orderbook.bidCount > 0) {
      LOG_DEBUG("Reporting changed VWAP for ID: ", orderbook.instrumentId,
                " VWAP: ", orderbook.vwapNumerator, "/",
                orderbook.vwapDenominator);
      results.push_back({orderbook.instrumentId, orderbook.vwapNumerator,
                         orderbook.vwapDenominator});
    } else if (orderbook.vwapChanged) {
      LOG_TRACE("VWAP changed for ID ", orderbook.instrumentId,
                " but not reported (isValid=", orderbook.isValid,
                ", askCount=", orderbook.askCount,
                ", bidCount=", orderbook.bidCount, ")");
    }
  }
  LOG_TRACE("Found ", results.size(), " changed VWAPs to report.");
  return results;
}
