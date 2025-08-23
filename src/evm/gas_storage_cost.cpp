// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "evm/gas_storage_cost.h"

namespace zen {
namespace evm {
/// The gas cost specification for storage instructions.
struct StorageCostSpec {
  bool NetCost;       ///< Is this net gas cost metering schedule?
  int16_t WarmAccess; ///< Storage warm access cost, YP: G_{warmaccess}
  int16_t Set;        ///< Storage addition cost, YP: G_{sSet}
  int16_t ReSet;      ///< Storage modification cost, YP: G_{sReSet}
  int16_t Clear;      ///< Storage deletion refund, YP: R_{sClear}
};

/// Table of gas cost specification for storage instructions per EVM revision.
/// TODO: This can be moved to instruction traits and be used in other places:
/// e.g.
///       SLOAD cost, replacement for warm_storage_read_cost.
const auto STORAGE_COST_SPEC_TABLE = []() noexcept {
  std::array<StorageCostSpec, EVMC_MAX_REVISION + 1> Tbl{};

  // Legacy cost schedule.
  for (auto Rev : {EVMC_FRONTIER, EVMC_HOMESTEAD, EVMC_TANGERINE_WHISTLE,
                   EVMC_SPURIOUS_DRAGON, EVMC_BYZANTIUM, EVMC_PETERSBURG})
    Tbl[Rev] = {false, 200, 20000, 5000, 15000};

  // Net cost schedule.
  Tbl[EVMC_CONSTANTINOPLE] = {true, 200, 20000, 5000, 15000};
  Tbl[EVMC_ISTANBUL] = {true, 800, 20000, 5000, 15000};
  Tbl[EVMC_BERLIN] = {true, WARM_STORAGE_READ_COST, 20000,
                      5000 - COLD_SLOAD_COST, 15000};
  Tbl[EVMC_LONDON] = {true, WARM_STORAGE_READ_COST, 20000,
                      5000 - COLD_SLOAD_COST, 4800};
  Tbl[EVMC_PARIS] = Tbl[EVMC_LONDON];
  Tbl[EVMC_SHANGHAI] = Tbl[EVMC_LONDON];
  Tbl[EVMC_CANCUN] = Tbl[EVMC_LONDON];
  Tbl[EVMC_PRAGUE] = Tbl[EVMC_LONDON];
  Tbl[EVMC_OSAKA] = Tbl[EVMC_LONDON];
  Tbl[EVMC_EXPERIMENTAL] = Tbl[EVMC_LONDON];
  return Tbl;
}();

// The lookup table of SSTORE costs by the storage update status.
extern const std::array<
    std::array<StorageStoreCost, EVMC_STORAGE_MODIFIED_RESTORED + 1>,
    EVMC_MAX_REVISION + 1>
    SSTORE_COSTS = []() noexcept {
      std::array<
          std::array<StorageStoreCost, EVMC_STORAGE_MODIFIED_RESTORED + 1>,
          EVMC_MAX_REVISION + 1>
          Tbl{};

      for (size_t Rev = EVMC_FRONTIER; Rev <= EVMC_MAX_REVISION; ++Rev) {
        auto &E = Tbl[Rev];
        if (const auto C = STORAGE_COST_SPEC_TABLE[Rev]; !C.NetCost) // legacy
        {
          E[EVMC_STORAGE_ADDED] = {C.Set, 0};
          E[EVMC_STORAGE_DELETED] = {C.ReSet, C.Clear};
          E[EVMC_STORAGE_MODIFIED] = {C.ReSet, 0};
          E[EVMC_STORAGE_ASSIGNED] = E[EVMC_STORAGE_MODIFIED];
          E[EVMC_STORAGE_DELETED_ADDED] = E[EVMC_STORAGE_ADDED];
          E[EVMC_STORAGE_MODIFIED_DELETED] = E[EVMC_STORAGE_DELETED];
          E[EVMC_STORAGE_DELETED_RESTORED] = E[EVMC_STORAGE_ADDED];
          E[EVMC_STORAGE_ADDED_DELETED] = E[EVMC_STORAGE_DELETED];
          E[EVMC_STORAGE_MODIFIED_RESTORED] = E[EVMC_STORAGE_MODIFIED];
        } else // net cost
        {
          E[EVMC_STORAGE_ASSIGNED] = {C.WarmAccess, 0};
          E[EVMC_STORAGE_ADDED] = {C.Set, 0};
          E[EVMC_STORAGE_DELETED] = {C.ReSet, C.Clear};
          E[EVMC_STORAGE_MODIFIED] = {C.ReSet, 0};
          E[EVMC_STORAGE_DELETED_ADDED] = {C.WarmAccess,
                                           static_cast<int16_t>(-C.Clear)};
          E[EVMC_STORAGE_MODIFIED_DELETED] = {C.WarmAccess, C.Clear};
          E[EVMC_STORAGE_DELETED_RESTORED] = {
              C.WarmAccess,
              static_cast<int16_t>(C.ReSet - C.WarmAccess - C.Clear)};
          E[EVMC_STORAGE_ADDED_DELETED] = {
              C.WarmAccess, static_cast<int16_t>(C.Set - C.WarmAccess)};
          E[EVMC_STORAGE_MODIFIED_RESTORED] = {
              C.WarmAccess, static_cast<int16_t>(C.ReSet - C.WarmAccess)};
        }
      }

      return Tbl;
    }();
} // namespace evm
} // namespace zen
