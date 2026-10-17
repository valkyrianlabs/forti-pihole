//
// DHCP address slicing: from classification to address actions on slice networks.
//
// For a network in slices/hybrid mode, every member of a group with a slice there should hold a
// DHCP reservation inside that slice. Three outcomes per device:
//
//   in place      its address is in its slice and reserved: nothing to do
//   reserve       its address is already in its slice but not reserved: add a reservation at that
//                 same address (no address change, no lease touched)
//   move          its address is elsewhere: a migration (operation.hpp) picks an address in the slice
//                 and moves it safely; never a bare reservation edit
//
// Devices with an address inside a slice that is not theirs (a static address, a stale lease) are
// reported, never moved automatically: their group has no slice there, so there is no target.
//
// The planner input (occupancy, pools, existing slices) is built from the snapshot here, so
// `forti-pihole slices` and the migration planner see exactly the same picture.
//

#ifndef FORTI_PIHOLE_SLICING_HPP
#define FORTI_PIHOLE_SLICING_HPP

#include "alloc/plan.hpp"
#include "classify.hpp"
#include "config.hpp"
#include "inventory.hpp"

#include <optional>
#include <string>
#include <vector>

namespace fph {

    struct SliceAction {
        std::string kind;   // in-place | reserve | move
        std::string mac, label, group, interface;
        std::string from_ip, to_ip;   // to_ip: chosen in the slice (move), or the current address (reserve)
        std::string slice;            // the group's slice the address belongs to
        std::optional<std::uint64_t> reservation_id;   // the device's current reservation, if any
        bool reservation_managed = false;
        std::uint64_t dhcp_server = 0;
        std::string why;
    };

    struct SliceFinding {
        std::string kind;   // foreign-in-slice | no-address | no-network | no-dhcp | slice-full | conflict | unmanaged-reservations
        std::string interface, mac, label, detail;
    };

    struct SlicingPlan {
        std::vector<SliceAction> actions;
        std::vector<SliceFinding> findings;
    };

    // The allocation planner's input for one network, from the snapshot. Requests: one per group
    // with members detected on the network (excluding the network's own group), sized from the
    // member count; existing slices from the configuration.
    std::optional<alloc::PlanInput> plan_input(const Config& config, const Network& network, const Snapshot& snapshot,
                                               const Classification& classification);

    SlicingPlan plan_slicing(const Config& config, const Snapshot& snapshot, const Classification& classification);

    // alloc::complement over CIDR strings (Pi-hole hybrid mapping).
    std::vector<std::string> complement_strings(const std::string& network, const std::vector<std::string>& slices);

}  // namespace fph

#endif  // FORTI_PIHOLE_SLICING_HPP
