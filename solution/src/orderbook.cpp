#include "orderbook.h"
#include "pcap_reader.h"
#include "protocol_logger.h"
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

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
OrderbookManager::OrderbookManager()
    : currentInstrumentId(0), snapshotIP(0), updateIP(0) {
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
      snapshotIP = ipStringToUint32(ip1);
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

// Process instrument snapshot
void OrderbookManager::processSnapshot(const InstrumentInfo &info) {
  // Get instrument name and trim any trailing spaces
  std::string instrName(info.name);
  instrName.erase(
      std::find_if(instrName.rbegin(), instrName.rend(),
                   [](unsigned char ch) { return !std::isspace(ch); })
          .base(),
      instrName.end());

  LOG_DEBUG("Processing snapshot for instrument '", instrName,
            "' (ID: ", info.instrumentId, ")");

  // Skip if not tracked
  if (!isTrackedInstrument(instrName)) {
    LOG_TRACE("Skipping untracked instrument: '", instrName, "'");
    return;
  }

  LOG_INFO("Creating/updating orderbook for tracked instrument '", instrName,
           "' (ID: ", info.instrumentId, ")");

  // Create or update orderbook entry
  auto &orderbook = orderbooks[info.instrumentId];
  orderbook.instrumentId = info.instrumentId;
  orderbook.tickSize = info.tickSize;
  orderbook.referencePrice = info.referencePrice;
  orderbook.changeNo = info.changeNo;
  orderbook.isValid = true;
  orderbook.askCount = 0;
  orderbook.bidCount = 0;
  orderbook.vwapNumerator = 0;
  orderbook.vwapDenominator = 0;
  orderbook.lastVwapNumerator = 0;
  orderbook.lastVwapDenominator = 0;
  orderbook.vwapChanged = false;

  // Track ID to name mapping
  idToName[info.instrumentId] = instrName;

  // Set current instrument ID for orderbook updates
  currentInstrumentId = info.instrumentId;

  LOG_DEBUG("Initialized orderbook: ID=", info.instrumentId,
            " ChangeNo=", info.changeNo, " TickSize=", info.tickSize,
            " RefPrice=", info.referencePrice);
}

// Process orderbook entry from snapshot
void OrderbookManager::processSnapshotOrderbook(int32_t instrumentId, Side side,
                                                double price, int32_t volume) {
  // Find the orderbook
  auto it = orderbooks.find(instrumentId);
  if (it == orderbooks.end()) {
    LOG_WARN("Received snapshot orderbook entry for unknown instrument ID: ",
             instrumentId);
    return;
  }
  if (!it->second.isValid) {
    LOG_WARN(
        "Received snapshot orderbook entry for invalid/uninitialized orderbook "
        "ID: ",
        instrumentId);
    return;
  }

  Orderbook &orderbook = it->second;
  const char *sideStr = (side == Side::BID) ? "BID" : "ASK";
  LOG_TRACE("Processing snapshot OB entry: ID=", instrumentId,
            " Side=", sideStr, " Price=", price, " Volume=", volume);

  if (side == Side::BID) {
    // Add to bids if there's space
    if (orderbook.bidCount < MAX_PRICE_LEVELS) {
      orderbook.bids[orderbook.bidCount].price = price;
      orderbook.bids[orderbook.bidCount].volume = volume;
      orderbook.bidCount++;
      LOG_TRACE("Added BID level ", orderbook.bidCount, " Price=", price,
                " Vol=", volume);
    } else {
      LOG_WARN("Max BID levels reached for ID: ", instrumentId);
    }
  } else if (side == Side::ASK) {
    // Add to asks if there's space
    if (orderbook.askCount < MAX_PRICE_LEVELS) {
      orderbook.asks[orderbook.askCount].price = price;
      orderbook.asks[orderbook.askCount].volume = volume;
      orderbook.askCount++;
      LOG_TRACE("Added ASK level ", orderbook.askCount, " Price=", price,
                " Vol=", volume);
    } else {
      LOG_WARN("Max ASK levels reached for ID: ", instrumentId);
    }
  }

  // Calculate VWAP after each update
  calculateVWAP(orderbook);
}

// Process update header
void OrderbookManager::processUpdateHeader(const UpdateHeader &header) {
  LOG_TRACE("Processing update header: ID=", header.instrumentId,
            " ChangeNo=", header.changeNo);

  // Find the orderbook
  auto it = orderbooks.find(header.instrumentId);
  if (it == orderbooks.end()) {
    LOG_DEBUG("Skipping update header for unknown instrument ID: ",
              header.instrumentId);
    currentInstrumentId = -1; // Invalidate context
    return;
  }

  Orderbook &orderbook = it->second;

  // Check if this update is in sequence
  if (!orderbook.isValid || header.changeNo != orderbook.changeNo + 1) {
    LOG_WARN("Out-of-sequence update for ID: ", header.instrumentId,
             " Received=", header.changeNo,
             " Expected=", orderbook.changeNo + 1);
    // Here, we might need logic to invalidate the book or wait for a snapshot.
    // For now, just skip processing events related to this header.
    currentInstrumentId = -1; // Invalidate context
    return;
  }

  // Update the orderbook change number
  orderbook.changeNo = header.changeNo;

  // Set current instrument ID for update events
  currentInstrumentId = header.instrumentId;

  // Store current VWAP values
  orderbook.lastVwapNumerator = orderbook.vwapNumerator;
  orderbook.lastVwapDenominator = orderbook.vwapDenominator;
  orderbook.vwapChanged = false;

  LOG_DEBUG("Update header accepted for ID: ", header.instrumentId,
            " New ChangeNo=", orderbook.changeNo);
}

// Process update event
void OrderbookManager::processUpdateEvent(const UpdateEvent &event) {
  if (event.instrumentId != currentInstrumentId) {
    LOG_WARN("Skipping update event for mismatched instrument ID. Expected=",
             currentInstrumentId, " Got=", event.instrumentId);
    return;
  }

  // Find the orderbook using the event's instrument ID
  auto it = orderbooks.find(event.instrumentId);
  if (it == orderbooks.end() || !it->second.isValid) {
    std::cout << "Skipping update for unknown/invalid instrument ID: "
              << event.instrumentId << std::endl;
    return;
  }

  Orderbook &orderbook = it->second;
  auto nameIt = idToName.find(event.instrumentId);
  std::string instrName =
      (nameIt != idToName.end()) ? nameIt->second : "unknown";

  // Calculate the actual price using reference price and tick size
  double price =
      orderbook.referencePrice + (event.priceOffset * orderbook.tickSize);

  const char *eventTypeStr =
      (event.eventType == EventType::ADD      ? "ADD"
       : event.eventType == EventType::MODIFY ? "MODIFY"
                                              : "DELETE");
  const char *sideStr = (event.side == Side::BID) ? "BID" : "ASK";

  LOG_TRACE("Processing update event: ID=", event.instrumentId,
            " Type=", eventTypeStr, " Side=", sideStr,
            " Level=", event.priceLevel, " Price=", price,
            " (Ref=", orderbook.referencePrice, " + Offset=", event.priceOffset,
            " * Tick=", orderbook.tickSize, ")", " Vol=", event.volume);

  // Validate price level index (protocol uses 1-based)
  int priceLevelIndex = event.priceLevel - 1;
  if (priceLevelIndex < 0) {
    LOG_ERROR("Invalid price level index (0 or negative): ", event.priceLevel);
    return; // Skip invalid event
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
      // Should not happen if parser validation is correct
      LOG_ERROR("Unknown event type received: ",
                static_cast<char>(event.eventType));
      return;
    }
  } catch (const std::out_of_range &e) {
    LOG_ERROR("Error processing price level index: ", priceLevelIndex + 1,
              " - ", e.what());
    // Depending on severity, might invalidate orderbook or just skip event
    return;
  }

  // Calculate VWAP after each event
  calculateVWAP(orderbook);
}

// Add a price level
void OrderbookManager::addPriceLevel(Orderbook &orderbook, Side side,
                                     int priceLevelIndex, double price,
                                     int64_t volume) {
  LOG_TRACE("Add Level: ID=", orderbook.instrumentId,
            " Side=", (side == Side::BID ? "BID" : "ASK"),
            " Index=", priceLevelIndex, " Price=", price, " Vol=", volume);

  auto &levels = (side == Side::BID) ? orderbook.bids : orderbook.asks;
  int &count = (side == Side::BID) ? orderbook.bidCount : orderbook.askCount;

  if (priceLevelIndex > count || priceLevelIndex >= MAX_PRICE_LEVELS) {
    LOG_WARN("Add level index out of bounds: Index=", priceLevelIndex,
             " Count=", count, " Max=", MAX_PRICE_LEVELS);
    // Optionally clamp or handle error based on spec interpretation
    return; // Skip invalid add
  }

  // Shift elements if inserting within existing levels or at the end but below
  // max
  if (priceLevelIndex < count && count < MAX_PRICE_LEVELS) {
    for (int i = count; i > priceLevelIndex; --i) {
      levels[i] = levels[i - 1];
    }
  } else if (priceLevelIndex < MAX_PRICE_LEVELS) {
    // Inserting at the end, just make sure count doesn't exceed max
  } else {
    // Should have been caught by the bounds check above
    return;
  }

  levels[priceLevelIndex].price = price;
  levels[priceLevelIndex].volume = volume;

  // Increment count only if we are adding within the max limit
  if (count < MAX_PRICE_LEVELS) {
    count++;
  }
  // If inserting at an index that was already the max, we effectively replace
  // No else needed here as the replacement happens above.
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
  levels.at(priceLevelIndex).price = price; // Use .at() for bounds check
  levels.at(priceLevelIndex).volume = volume;
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

  // Shift elements left to fill the gap
  for (int i = priceLevelIndex; i < count - 1; ++i) {
    levels[i] = levels[i + 1];
  }

  // Decrement count and clear the last (now unused) element
  if (count > 0) {
    levels[count - 1].price = 0.0; // Optional: Clear old data
    levels[count - 1].volume = 0;
    count--;
  }
}

// Calculate VWAP for an orderbook
void OrderbookManager::calculateVWAP(Orderbook &orderbook) {
  LOG_TRACE("Calculating VWAP for ID: ", orderbook.instrumentId);
  uint64_t numeratorSum = 0;
  uint64_t denominatorSum = 0;

  auto nameIt = idToName.find(orderbook.instrumentId);
  std::string instrName =
      (nameIt != idToName.end()) ? nameIt->second : "unknown";

  // Ensure tickSize is positive to avoid division by zero or unexpected
  // behavior
  if (orderbook.tickSize <= 0) {
    LOG_WARN("Invalid tick size (", orderbook.tickSize, ") for ID ",
             orderbook.instrumentId, ". VWAP calculation skipped.");
    // Keep VWAP unchanged or set to zero? Let's keep it unchanged for now.
    orderbook.vwapChanged =
        (orderbook.vwapNumerator != orderbook.lastVwapNumerator ||
         orderbook.vwapDenominator != orderbook.lastVwapDenominator);
    return;
  }

  // Process bids
  LOG_TRACE("  Bids (Count=", orderbook.bidCount, ")");
  for (int i = 0; i < orderbook.bidCount; ++i) {
    const auto &level = orderbook.bids[i];
    if (level.volume > 0 && level.price > 0) {
      // Normalize price by tickSize before calculation, cast to integer
      uint32_t normalizedPrice = static_cast<uint32_t>(
          level.price / orderbook.tickSize + 0.5); // Add 0.5 for rounding
      numeratorSum += static_cast<uint64_t>(normalizedPrice) * level.volume;
      denominatorSum += level.volume;
      LOG_TRACE("    Level ", i, ": Price=", level.price,
                " (Norm=", normalizedPrice, ")", " Vol=", level.volume,
                " | Running Sums: N=", numeratorSum, " D=", denominatorSum);
    }
  }

  // Process asks
  LOG_TRACE("  Asks (Count=", orderbook.askCount, ")");
  for (int i = 0; i < orderbook.askCount; ++i) {
    const auto &level = orderbook.asks[i];
    if (level.volume > 0 && level.price > 0) {
      // Normalize price by tickSize before calculation, cast to integer
      uint32_t normalizedPrice = static_cast<uint32_t>(
          level.price / orderbook.tickSize + 0.5); // Add 0.5 for rounding
      numeratorSum += static_cast<uint64_t>(normalizedPrice) * level.volume;
      denominatorSum += level.volume;
      LOG_TRACE("    Level ", i, ": Price=", level.price,
                " (Norm=", normalizedPrice, ")", " Vol=", level.volume,
                " | Running Sums: N=", numeratorSum, " D=", denominatorSum);
    }
  }

  // Update VWAP components
  uint32_t finalNumerator = static_cast<uint32_t>(numeratorSum);
  uint32_t finalDenominator = static_cast<uint32_t>(denominatorSum);

  // Check if VWAP has changed *before* updating the values
  if (finalNumerator != orderbook.vwapNumerator ||
      finalDenominator != orderbook.vwapDenominator) {
    LOG_DEBUG("VWAP changed for ID: ", orderbook.instrumentId,
              " New: ", finalNumerator, "/", finalDenominator,
              " Old: ", orderbook.vwapNumerator, "/",
              orderbook.vwapDenominator);
    orderbook.vwapChanged = true;
  } else {
    orderbook.vwapChanged = false; // Explicitly set to false if no change
  }

  // Store the new VWAP values
  orderbook.vwapNumerator = finalNumerator;
  orderbook.vwapDenominator = finalDenominator;

  LOG_TRACE("  Final VWAP: N=", orderbook.vwapNumerator,
            " D=", orderbook.vwapDenominator,
            " Changed=", (orderbook.vwapChanged ? "yes" : "no"));
}

// TODO: FinalizeUpdate might need adjustment based on when VWAP is calculated
void OrderbookManager::finalizeUpdate() {
  // If VWAP is calculated after each event, this might just be a placeholder.
  // If VWAP is calculated once per update message (after all events),
  // the calculation would happen here or just before getChangedVWAPs.
  // For now, assuming calculateVWAP is called after each event or after
  // processing all events for an instrument in the message.
  LOG_TRACE("Finalizing update for instrument ID: ", currentInstrumentId);
  // Resetting the context is important if processing moves to another
  // instrument currentInstrumentId = -1; // Or handle context differently
}

// Get changed VWAPs
std::vector<OrderbookManager::VWAPResult>
OrderbookManager::getChangedVWAPs() const {
  LOG_TRACE("Getting changed VWAPs...");
  std::vector<VWAPResult> results;
  for (const auto &pair : orderbooks) {
    const auto &orderbook = pair.second;
    // Check validity and non-empty conditions as per README
    if (orderbook.vwapChanged && orderbook.isValid && orderbook.askCount > 0 &&
        orderbook.bidCount > 0) {
      LOG_DEBUG("Reporting changed VWAP for ID: ", orderbook.instrumentId,
                " VWAP: ", orderbook.vwapNumerator, "/",
                orderbook.vwapDenominator);
      results.push_back({orderbook.instrumentId, orderbook.vwapNumerator,
                         orderbook.vwapDenominator});
    } else if (orderbook.vwapChanged) {
      // Log why a changed VWAP wasn't reported
      LOG_TRACE("VWAP changed for ID ", orderbook.instrumentId,
                " but not reported (isValid=", orderbook.isValid,
                ", askCount=", orderbook.askCount,
                ", bidCount=", orderbook.bidCount, ")");
    }
  }
  LOG_TRACE("Found ", results.size(), " changed VWAPs to report.");
  return results;
}