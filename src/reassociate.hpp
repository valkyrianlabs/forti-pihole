//
// Reassociation: a device that comes back under a new (usually randomized) MAC. The companion only
// proposes; it never moves an identity on its own, because a hostname or vendor is trivially spoofed
// and the old identity may be privileged. The new MAC is classified on its own merits meanwhile.
//
// Evidence, scored: a distinctive hostname match (3), the same hardware family (1), OS (1), OS
// version (1) and vendor (1). Generic names (iPhone, Watch, MacBook-Air, ... and any name that more
// than one current device carries) are not evidence. A candidate needs a hostname match and a score
// of at least 4, and the old MAC must be offline.
//

#ifndef FORTI_VLAN_MAC_REASSOCIATE_HPP
#define FORTI_VLAN_MAC_REASSOCIATE_HPP

#include "classify.hpp"
#include "inventory.hpp"
#include "state.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace fvm {

    inline constexpr int candidate_threshold = 4;

    bool generic_hostname(std::string_view hostname);

    // New candidates from this snapshot (ids already in state or dismissed are skipped). Only old
    // identities the companion knows (state records) and that it placed or the operator pinned are
    // considered: a reassociation transfers a segment, so there must be one to transfer.
    std::vector<Candidate> find_candidates(const Snapshot& snapshot, const State& state, const Classification& classification,
                                           std::int64_t now);

    // Stable id for a pair: 8 hex digits.
    std::string candidate_id(std::string_view old_mac, std::string_view new_mac);

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_REASSOCIATE_HPP
