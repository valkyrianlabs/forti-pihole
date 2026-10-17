//
// The CIDR allocation planner for DHCP address slicing.
//
// On one FortiGate interface subnet (the "parent", e.g. 192.168.1.0/24 with gateway .1) each
// logical device group gets one or more CIDR-aligned address *slices* (192.168.1.224/28 for the
// TVs); every member gets a DHCP reservation inside its group's slices, and Pi-hole maps each
// slice to a DNS filtering group. A slice is a classification unit, not a routed subnet: members
// keep the parent's mask and gateway. The parent may itself be a VLAN's subnet (hybrid mode).
//
// A slice is only exclusive when the DHCP server can never hand one of its addresses to some other
// device, so it must lie outside every dynamic ip-range (or inside an exclude-range): a reservation
// inside a pool protects that one address, not the rest of the slice.
//
// Everything here is a pure function of its inputs. The planner *proposes*; it never applies
// anything, and a pool change in a proposal is a suggestion for the operator (or a later,
// explicitly enabled step) to carry out.
//
// Sizing rule. A group expecting N devices with headroom h needs ceil(N * max(h, 1)) addresses
// (at least 1). A new slice is the smallest block of 2^k >= max(4, need) addresses, so never smaller
// than a /30: a slice of one or two addresses would leave no room for the next device and multiply
// the Pi-hole client entries. A request's prefix bounds narrow this further (min_prefix: largest
// block allowed; max_prefix: smallest block allowed, at most 30). A block containing the parent's
// network or broadcast address loses that address, so the planner only accepts such a block when
// what is left still covers the need.
//

#ifndef FORTI_PIHOLE_ALLOC_PLAN_HPP
#define FORTI_PIHOLE_ALLOC_PLAN_HPP

#include "cidr.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace fph::alloc {

    // Why an address is taken.
    enum class Use {
        interface_ip,     // the interface address (gateway) or a secondary IP
        reservation,      // DHCP reserved-address entry
        lease,            // current DHCP lease
        vip,              // VIP mapped IP
        address_object,   // host (/32 or single-address range) firewall address object
        static_device,    // inventory device with an IP but no lease (statically configured)
    };

    struct Occupant {
        Ipv4 ip = 0;
        Use use = Use::lease;
        std::string label;   // what the operator recognizes: hostname, object name, "port1"
        std::string mac;     // normalized MAC when known (reservations, leases, devices)
        // The device group this occupant belongs to, when it is a member of one: inside that group's
        // slices it is at home, everywhere else in a slice it is foreign. Empty: no group.
        std::string group;
    };

    struct Occupancy {
        std::vector<Occupant> entries;

        void add(Occupant occupant) { entries.push_back(std::move(occupant)); }
        // Everything at `ip`, in insertion order.
        [[nodiscard]] std::vector<const Occupant*> at(Ipv4 ip) const;
        [[nodiscard]] std::vector<const Occupant*> within(const Range& range) const;
    };

    // A FortiGate DHCP server ip-range entry: the server hands its addresses to unknown devices.
    struct Pool {
        int id = 0;
        Range range;
    };

    struct Request {
        std::string group;
        std::uint64_t expected = 0;        // devices the group is expected to hold
        double headroom = 1.5;             // growth factor, >= 1
        std::optional<int> min_prefix;     // largest block allowed (e.g. 26: never bigger than a /26)
        std::optional<int> max_prefix;     // smallest block allowed (e.g. 28: never smaller than a /28)
    };

    struct Policy {
        // When true the planner may take space inside a dynamic pool for a new slice, together with
        // a proposed pool change (shrink or exclude-range) that disturbs no current dynamic lease.
        // When false, pool changes only ever appear as alternatives for a shortfall.
        bool allow_pool_changes = false;
    };

    struct PlanInput {
        Cidr network;                                        // the interface subnet (the parent)
        std::vector<Ipv4> interface_ips;                     // gateway and secondary IPs
        std::vector<Pool> pools;                             // dynamic ip-ranges
        std::vector<Range> excludes;                         // exclude-ranges
        Occupancy occupancy;
        std::map<std::string, std::vector<Cidr>> existing;   // group -> slices it holds today
        std::vector<Request> requests;
        Policy policy;

        // The occupancy plus interface_ips as Use::interface_ip entries: what pick_address needs.
        [[nodiscard]] Occupancy effective_occupancy() const;
    };

    struct Slice {
        std::string group;
        Cidr cidr;
        bool retained = true;   // held before this plan (false: proposed by it)

        bool operator==(const Slice&) const = default;
    };

    enum class ConflictKind {
        outside_network,    // the slice is not inside the parent network
        dynamic_pool,       // overlaps a dynamic pool, not covered by exclude-ranges
        slice_overlap,      // overlaps another slice
        interface_ip,       // contains the gateway or another interface address
        foreign_occupant,   // a reservation, lease, VIP, address object or device of another group
    };

    struct Conflict {
        ConflictKind kind = ConflictKind::outside_network;
        Slice slice;
        std::optional<Range> range;    // the overlapping addresses (pool, other slice)
        std::optional<Ipv4> ip;        // the occupant's or interface's address
        std::optional<Use> use;        // for foreign_occupant
        std::string label;             // occupant label, "pool <id>", or the other slice's group
        std::string mac;
        std::optional<Cidr> other;     // slice_overlap: the other slice
        std::string detail;            // one line for humans

        bool operator==(const Conflict&) const = default;
    };

    // Every conflict of `slices` against the input's network, pools, exclude-ranges, interface IPs and
    // occupancy (input.existing and input.requests are ignored). Ordered by slice address, then kind
    // (in declaration order), then address, so the same input reports the same list. An overlap is
    // reported once, on the lower slice.
    std::vector<Conflict> check(const PlanInput& input, std::span<const Slice> slices);

    struct PoolChange {
        enum class Kind { shrink, exclude };
        Kind kind = Kind::shrink;
        int pool_id = 0;
        Range pool;       // the ip-range as it is
        Range result;     // shrink: the ip-range after; exclude: the exclude-range to add
        Cidr frees;       // the slice this change makes room for
        std::string detail;

        bool operator==(const PoolChange&) const = default;
    };

    // The input with `changes` carried out, for validating a proposal that includes them; nothing
    // outside the returned value changes.
    PlanInput with_pool_changes(PlanInput input, std::span<const PoolChange> changes);

    struct Alternative {
        enum class Kind { reduce_headroom, split, shrink_pool, exclude_range };
        Kind kind = Kind::reduce_headroom;
        std::string detail;
        std::vector<Cidr> slices;                 // what the group would get in addition
        std::optional<PoolChange> pool_change;
        // Current dynamic leases (without a reservation) that would have to move: the ranking key.
        std::vector<std::string> disturbed;
    };

    // Alternatives are ranked by how many current dynamic leases they displace (fewest first), then
    // by kind in declaration order (less headroom and splitting change nothing on the FortiGate; a
    // shrink keeps the pool contiguous, an exclude-range punches a hole), then by how many addresses
    // they take from the pool. None ever moves a reservation, VIP, address object or static device.
    struct GroupPlan {
        std::string group;
        std::uint64_t expected = 0;
        std::uint64_t needed = 0;       // ceil(expected * headroom)
        std::uint64_t capacity = 0;     // addresses its slices offer after the plan
        std::uint64_t missing = 0;      // needed - capacity when short, else 0
        std::vector<Alternative> alternatives;   // when missing > 0: fewest disturbed first
    };

    struct Usage {
        std::uint64_t used = 0;    // distinct occupied addresses
        std::uint64_t total = 0;   // assignable addresses
        std::uint64_t free = 0;
    };

    struct SliceUsage {
        Slice slice;
        Usage usage;
    };

    struct Utilization {
        std::vector<SliceUsage> slices;
        Usage overall;
    };

    // Per slice: total = its usable addresses less interface IPs; used = distinct occupied addresses
    // among them, whoever holds them. Overall: the sums.
    Utilization utilization(const PlanInput& input, std::span<const Slice> slices);

    struct Proposal {
        Cidr network;
        std::vector<Slice> slices;               // retained and new, by address
        std::vector<Slice> dropped;              // existing slices outside the network
        std::vector<PoolChange> pool_changes;    // needed by new slices (Policy::allow_pool_changes)
        std::vector<GroupPlan> groups;           // one per request, by group
        std::vector<Conflict> conflicts;         // of retained and dropped slices
        Utilization utilization;

        [[nodiscard]] bool complete() const;     // every request met
    };

    // Retains every existing slice inside the network (a retained slice with conflicts is reported,
    // not moved: moving it would renumber its devices), then gives each request that its slices do
    // not cover another best-fit slice. Requests are served largest block first, then by group name,
    // so the result depends only on the input. Throws std::invalid_argument on a malformed request
    // (duplicate group, headroom < 1, prefix bounds outside network prefix..30 or crossed).
    Proposal propose(const PlanInput& input);

    // An address for a device of `slice`: `preferred` when it is a usable address of the slice that
    // no one else holds, else the lowest such address; nullopt when the slice is full. Occupants with
    // `mac` are the device itself and do not count as taken; interface IPs (Use::interface_ip, so pass
    // PlanInput::effective_occupancy()) and the parent's network and broadcast addresses never qualify.
    std::optional<Ipv4> pick_address(const Cidr& parent, const Cidr& slice, const Occupancy& occupancy,
                                     std::optional<Ipv4> preferred, std::string_view mac = {});

    std::string_view use_name(Use use);
    std::string_view conflict_kind_name(ConflictKind kind);
    std::string_view alternative_kind_name(Alternative::Kind kind);

}  // namespace fph::alloc

#endif  // FORTI_PIHOLE_ALLOC_PLAN_HPP
