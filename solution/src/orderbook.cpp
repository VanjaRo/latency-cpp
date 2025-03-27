#include "orderbook.h"
#include "pcap_reader.h"
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
    : currentInstrumentId(0), snapshotIP(0), updateIP(0) {}

// Load metadata (IPs and instrument names)
void OrderbookManager::loadMetadata(const std::string &metadataPath) {
  std::ifstream file(metadataPath);
  if (!file.is_open()) {
    std::cerr << "Failed to open metadata file: " << metadataPath << std::endl;
    return;
  }

  std::string line;

  // Read IPs from the first line
  if (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string ip1, ip2;
    if (iss >> ip1 >> ip2) {
      snapshotIP = ipStringToUint32(ip1);
      updateIP = ipStringToUint32(ip2);
      std::cout << "Loaded IPs: " << ip1 << " and " << ip2 << std::endl;
    }
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
        std::cout << "Tracking instrument: '" << line << "'" << std::endl;
        instrumentCount++;
      }
    }
  }
  std::cout << "Total tracked instruments: " << instrumentCount << std::endl;
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

  std::cout << "Processing snapshot for instrument '" << instrName
            << "' (ID: " << info.instrumentId << ")" << std::endl;

  // Skip if not tracked
  if (!isTrackedInstrument(instrName)) {
    std::cout << "Skipping untracked instrument: '" << instrName << "'"
              << std::endl;
    return;
  }

  std::cout << "Creating/updating orderbook for tracked instrument '"
            << instrName << "' (ID: " << info.instrumentId << ")" << std::endl;

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

  std::cout << "Successfully initialized orderbook for '" << instrName
            << "' (ID: " << info.instrumentId << ", ChangeNo: " << info.changeNo
            << ", TickSize: " << info.tickSize
            << ", ReferencePrice: " << info.referencePrice << ")" << std::endl;
}

// Process orderbook entry from snapshot
void OrderbookManager::processSnapshotOrderbook(int32_t instrumentId, Side side,
                                                double price, int32_t volume) {
  // Find the orderbook
  auto it = orderbooks.find(instrumentId);
  if (it == orderbooks.end() || !it->second.isValid) {
    // Orderbook not found or not initialized
    return;
  }

  Orderbook &orderbook = it->second;

  if (side == Side::BID) {
    // Add to bids if there's space
    if (orderbook.bidCount < MAX_PRICE_LEVELS) {
      orderbook.bids[orderbook.bidCount].price = price;
      orderbook.bids[orderbook.bidCount].volume = volume;
      orderbook.bidCount++;
    }
  } else if (side == Side::ASK) {
    // Add to asks if there's space
    if (orderbook.askCount < MAX_PRICE_LEVELS) {
      orderbook.asks[orderbook.askCount].price = price;
      orderbook.asks[orderbook.askCount].volume = volume;
      orderbook.askCount++;
    }
  }

  // Calculate VWAP after each update
  calculateVWAP(orderbook);
}

// Process update header
void OrderbookManager::processUpdateHeader(const UpdateHeader &header) {
  // Find the orderbook
  auto it = orderbooks.find(header.instrumentId);
  if (it == orderbooks.end()) {
    // Orderbook not found, can't process update
    return;
  }

  Orderbook &orderbook = it->second;

  // Check if this update is in sequence
  if (!orderbook.isValid || header.changeNo != orderbook.changeNo + 1) {
    // Out of sequence, can't process
    std::cout << "Skipping out-of-sequence update for instrument "
              << header.instrumentId << " (received: " << header.changeNo
              << ", expected: " << (orderbook.changeNo + 1) << ")" << std::endl;
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
}

// Process update event
void OrderbookManager::processUpdateEvent(const UpdateEvent &event) {
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

  std::cout << "Processing update for '" << instrName
            << "' (ID: " << event.instrumentId
            << "), Event: " << static_cast<int>(event.eventType)
            << ", Side: " << static_cast<int>(event.side)
            << ", Level: " << event.priceLevel << ", Price: " << price
            << " (Ref: " << orderbook.referencePrice
            << " + Offset: " << event.priceOffset
            << " * TickSize: " << orderbook.tickSize << ")"
            << ", Volume: " << event.volume << std::endl;

  // Handle the event based on its type
  switch (event.eventType) {
  case EventType::ADD:
    addPriceLevel(orderbook, event.side, event.priceLevel, price, event.volume);
    break;

  case EventType::MODIFY:
    modifyPriceLevel(orderbook, event.side, event.priceLevel, price,
                     event.volume);
    break;

  case EventType::DELETE:
    deletePriceLevel(orderbook, event.side, event.priceLevel);
    break;

  default:
    std::cout << "Unknown event type for instrument " << event.instrumentId
              << " (Event: " << std::hex << static_cast<char>(event.eventType)
              << std::dec << ")" << std::endl;
    return;
  }

  // Calculate VWAP after each event
  calculateVWAP(orderbook);
}

// Add a price level
void OrderbookManager::addPriceLevel(Orderbook &orderbook, Side side,
                                     int priceLevel, double price,
                                     int32_t volume) {
  if (side == Side::BID) {
    // Insert at the specified price level, shifting other levels if needed
    if (priceLevel < MAX_PRICE_LEVELS) {
      // Shift elements after the insertion point
      for (int i = std::min<int>(MAX_PRICE_LEVELS - 1, orderbook.bidCount);
           i > priceLevel; --i) {
        orderbook.bids[i] = orderbook.bids[i - 1];
      }

      // Insert the new element
      orderbook.bids[priceLevel].price = price;
      orderbook.bids[priceLevel].volume = volume;

      // Update count (but don't exceed max)
      orderbook.bidCount =
          std::min<int>(MAX_PRICE_LEVELS, orderbook.bidCount + 1);
    }
  } else if (side == Side::ASK) {
    // Insert at the specified price level, shifting other levels if needed
    if (priceLevel < MAX_PRICE_LEVELS) {
      // Shift elements after the insertion point
      for (int i = std::min<int>(MAX_PRICE_LEVELS - 1, orderbook.askCount);
           i > priceLevel; --i) {
        orderbook.asks[i] = orderbook.asks[i - 1];
      }

      // Insert the new element
      orderbook.asks[priceLevel].price = price;
      orderbook.asks[priceLevel].volume = volume;

      // Update count (but don't exceed max)
      orderbook.askCount =
          std::min<int>(MAX_PRICE_LEVELS, orderbook.askCount + 1);
    }
  }
}

// Modify a price level
void OrderbookManager::modifyPriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevel, double price,
                                        int32_t volume) {
  if (side == Side::BID) {
    if (priceLevel < orderbook.bidCount) {
      orderbook.bids[priceLevel].price = price;
      orderbook.bids[priceLevel].volume = volume;
    }
  } else if (side == Side::ASK) {
    if (priceLevel < orderbook.askCount) {
      orderbook.asks[priceLevel].price = price;
      orderbook.asks[priceLevel].volume = volume;
    }
  }
}

// Delete a price level
void OrderbookManager::deletePriceLevel(Orderbook &orderbook, Side side,
                                        int priceLevel) {
  if (side == Side::BID) {
    if (priceLevel < orderbook.bidCount) {
      // Shift elements to fill the gap
      for (int i = priceLevel; i < orderbook.bidCount - 1; ++i) {
        orderbook.bids[i] = orderbook.bids[i + 1];
      }
      orderbook.bidCount--;
    }
  } else if (side == Side::ASK) {
    if (priceLevel < orderbook.askCount) {
      // Shift elements to fill the gap
      for (int i = priceLevel; i < orderbook.askCount - 1; ++i) {
        orderbook.asks[i] = orderbook.asks[i + 1];
      }
      orderbook.askCount--;
    }
  }
}

// Calculate VWAP for an orderbook
void OrderbookManager::calculateVWAP(Orderbook &orderbook) {
  uint32_t numerator = 0;
  uint32_t denominator = 0;

  auto nameIt = idToName.find(orderbook.instrumentId);
  std::string instrName =
      (nameIt != idToName.end()) ? nameIt->second : "unknown";

  // Process bids
  for (int i = 0; i < MAX_PRICE_LEVELS; ++i) {
    const auto &bidLevel = orderbook.bids[i];
    if (bidLevel.volume > 0 && bidLevel.price > 0) {
      numerator += bidLevel.price * bidLevel.volume;
      denominator += bidLevel.volume;
    }
  }

  // Process asks
  for (int i = 0; i < MAX_PRICE_LEVELS; ++i) {
    const auto &askLevel = orderbook.asks[i];
    if (askLevel.volume > 0 && askLevel.price > 0) {
      numerator += askLevel.price * askLevel.volume;
      denominator += askLevel.volume;
    }
  }

  // Update VWAP components
  orderbook.vwapNumerator = numerator / orderbook.tickSize;
  orderbook.vwapDenominator = denominator / orderbook.tickSize;

  // Check if VWAP has changed
  if (numerator != orderbook.lastVwapNumerator ||
      denominator != orderbook.lastVwapDenominator) {
    orderbook.vwapChanged = true;
  }

  // Debug output
  std::cout << "VWAP calculation for '" << instrName
            << "' (ID: " << orderbook.instrumentId << "):"
            << "\n  Raw Numerator: " << numerator
            << "\n  Raw Denominator: " << denominator
            << "\n  Changed: " << (orderbook.vwapChanged ? "yes" : "no")
            << std::endl;
}

// TODO: Doesn't make anys scence
void OrderbookManager::finalizeUpdate() {
  // Store current VWAPs as last VWAPs for all orderbooks
  for (auto &pair : orderbooks) {
    auto &orderbook = pair.second;
    if (orderbook.vwapChanged) {
      std::cout << "VWAP changes: 1" << std::endl;
      std::cout << "  InstrumentID: " << orderbook.instrumentId
                << ", VWAP: " << orderbook.vwapNumerator << "/"
                << orderbook.vwapDenominator << std::endl;
    }
    orderbook.lastVwapNumerator = orderbook.vwapNumerator;
    orderbook.lastVwapDenominator = orderbook.vwapDenominator;
    orderbook.vwapChanged = false;
  }
}

// Get changed VWAPs
std::vector<OrderbookManager::VWAPResult>
OrderbookManager::getChangedVWAPs() const {
  std::vector<VWAPResult> results;
  for (const auto &pair : orderbooks) {
    const auto &orderbook = pair.second;
    if (orderbook.vwapChanged) {
      results.push_back({orderbook.instrumentId, orderbook.vwapNumerator,
                         orderbook.vwapDenominator});
    }
  }
  return results;
}