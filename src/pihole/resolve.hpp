//
// Which client entry, and so which groups, Pi-hole applies to a query: a model of FTL's
// get_client_groupids() (src/database/gravity-db.c, FTL v6.7.1; unchanged in precedence in v6.8).
// No API endpoint reports this (no /api path takes a client and answers its groups; /api/search
// takes only a domain), so forti-pihole computes it from GET /api/clients the way FTL does.
//
// FTL resolves per client IP (each source address is its own FTL client), in this order, and stops
// at the first step that finds an entry:
//
//   1. IP and subnet entries, longest prefix first. Every client row is scored with the SQL function
//      subnet_match(row, ip) (src/database/sqlite3-ext.c): the row's prefix length when the address
//      falls inside it (a bare address counts as /32 or /128), else 0. The query keeps rows with a
//      score > 0, groups them by score and takes the highest score; among rows with that same score
//      it takes max(id), the most recently added row, and logs a "subnet" warning to Pi-hole's
//      diagnosis messages (logg_subnet_warning()). So an exact address beats any subnet, a /28 beats
//      the /24 around it, and two entries of the same length that both match are an ambiguity Pi-hole
//      resolves by row id.
//      Address families never mix: a row and the address are IPv6 when they contain ':', IPv4
//      otherwise. An IPv4-mapped IPv6 address ("::ffff:10.0.0.5") is IPv6 to FTL and matches only
//      IPv6 rows; FTL does not unmap it. dnsmasq opens its IPv6 sockets IPV6_V6ONLY (network.c), so
//      IPv4 clients arrive as IPv4 and a mapped address does not occur in practice.
//      A /0 row scores 0 and never matches; a MAC-shaped row (17 characters, five ':' and no "::",
//      isMAC() in network-table.c) and anything that is not an address score 0 too.
//   2. The MAC address FTL knows for the IP (in-memory neighbor data, else its network table), only
//      when the setting resolver.macNames is true (the default). Rows are compared as text,
//      case-insensitively (SQL "ip = ? COLLATE NOCASE"), against "AA:BB:CC:DD:EE:FF": a row written
//      "aa-bb-cc-dd-ee-ff" never matches a MAC. Of several rows that compare equal the first in table
//      order (the lowest id) wins.
//   3. The hostname FTL resolved for the IP, compared the same way (exact text, case-insensitive; no
//      suffix or wildcard matching).
//   4. The interface the query arrived on, as a row ":<interface>", compared the same way.
//   5. No entry: the client is in the Default group (id 0) only.
//
// The entry found is used with exactly its groups (client_by_group); the Default group is not added.
// Groups that are disabled stay in the set, but the gravity and domain views filter on
// group.enabled = 1, so their lists do not apply (see enabled_groups()).
//
// The address is the query's source as FTL sees it: with dns.EDNS0ECS (default true) an ECS client
// subnet in the query replaces it (dnsmasq_interface.c _FTL_new_query()); when clients query a
// forwarder (the FortiGate's DNS proxy, a router) instead of Pi-hole, Pi-hole sees the forwarder.
//
// Consequences for what forti-pihole writes:
//   - Overlapping subnets of different lengths are well defined (longest prefix wins), so a VLAN
//     subnet entry plus narrower slice or per-device address entries inside it is a valid design.
//   - Two matching rows of the same length are not: canonical_client() writes one spelling per
//     network (no "10.0.0.7/24" next to "10.0.0.0/24", no "10.0.0.5/32" next to "10.0.0.5"), and
//     find_ambiguities() reports such rows when someone else created them.
//   - Any address or subnet row that covers a device shadows that device's MAC, hostname and
//     interface rows entirely. Inside a managed subnet, per-device exceptions must be address rows.
//   - IPv4 rows say nothing about the same device's IPv6 queries.
//

#ifndef FORTI_PIHOLE_PIHOLE_RESOLVE_HPP
#define FORTI_PIHOLE_PIHOLE_RESOLVE_HPP

#include "pihole/model.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fph::pihole {

    // subnet_match(entry, ip) exactly as FTL computes it: the matching prefix length, 0 for no match.
    [[nodiscard]] int subnet_match(std::string_view entry, std::string_view ip);

    // What FTL knows about the client that sent a query; empty strings are unknown.
    struct Observed {
        std::string ip;          // the source address, as FTL prints it (inet_ntop form)
        std::string mac;         // any spelling normalize_mac() reads
        std::string hostname;    // the name FTL resolved for the address
        std::string interface;   // the interface the query arrived on, without ':'
    };

    struct ResolveOptions {
        bool mac_names = true;   // FTL's resolver.macNames: when false, step 2 is skipped
    };

    enum class Match { address, mac, hostname, interface, none };

    [[nodiscard]] std::string_view to_string(Match match);

    struct Resolution {
        Match match = Match::none;
        std::optional<int> entry_id;   // the chosen client row
        std::string entry;             // its client text
        int prefix = 0;                // matching bits, for Match::address
        std::vector<int> tied;         // other rows FTL weighed equally (same prefix), ascending ids
        std::vector<int> groups;       // the group ids FTL uses: the row's, or {0} when none matched
    };

    [[nodiscard]] Resolution resolve_client(std::span<const ClientEntry> clients, const Observed& seen,
                                            const ResolveOptions& options = {});

    // resolve_client(...).groups.
    [[nodiscard]] std::vector<int> effective_groups(std::span<const ClientEntry> clients, std::string_view ip,
                                                    std::string_view mac = {}, std::string_view hostname = {},
                                                    std::string_view interface = {});

    // The ids among `ids` whose group exists and is enabled: the groups whose lists actually apply.
    [[nodiscard]] std::vector<int> enabled_groups(std::span<const int> ids, std::span<const Group> groups);

    // Pairs of client rows that Pi-hole cannot order: two address/subnet rows of the same prefix
    // length and family that cover the same network (FTL picks the higher id and warns), or two rows
    // that differ only in letter case (MAC, hostname or interface rows; the lowest id wins).
    struct Ambiguity {
        int first_id, second_id;
        std::string first, second;
    };

    [[nodiscard]] std::vector<Ambiguity> find_ambiguities(std::span<const ClientEntry> clients);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_RESOLVE_HPP
