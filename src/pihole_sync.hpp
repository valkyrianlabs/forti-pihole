//
// Pi-hole side of a sync: which client entries (CIDR -> Pi-hole groups) the configured networks
// imply, and how to get there from what Pi-hole has. forti-pihole owns only the client entries it
// created (comment marker `managed by forti-pihole`); groups, their blocklists and settings, and
// every other client entry belong to the operator and are only read.
//
//   subnet  one entry per interface subnet (primary and secondary) -> the network group's Pi-hole group
//   slices  one entry per slice -> the slice group's Pi-hole group; the rest stays Default
//   hybrid  slices, plus the rest of the subnet -> the network group's Pi-hole group: either as one
//           subnet entry under the more specific slice entries (when Pi-hole resolves the most
//           specific match) or as the CIDR complement of the slices (when it does not)
//
// Groups map by name to groups that already exist; forti-pihole never creates a filtering group on
// its own during sync (setup can, when the operator asks).
//

#ifndef FORTI_PIHOLE_PIHOLE_SYNC_HPP
#define FORTI_PIHOLE_PIHOLE_SYNC_HPP

#include "config.hpp"
#include "inventory.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace fph {

    struct PiholeGroupInfo {
        int id = 0;
        std::string name;
        bool enabled = true;
    };

    struct PiholeClientInfo {
        int id = 0;
        std::string client;    // IP, CIDR, MAC, hostname or interface, as Pi-hole stores it
        std::string comment;
        std::vector<int> groups;
        [[nodiscard]] bool managed() const;
    };

    struct PiholeView {
        std::vector<PiholeGroupInfo> groups;
        std::vector<PiholeClientInfo> clients;
        [[nodiscard]] const PiholeGroupInfo* group(std::string_view name) const;   // case-sensitive, as Pi-hole
        [[nodiscard]] const PiholeGroupInfo* group(int id) const;
    };

    struct DesiredClient {
        std::string cidr;          // canonical "a.b.c.d/n"
        std::string pihole_group;  // by name
        std::string interface, why;   // "slice tvs", "subnet", "complement of slices"
    };

    struct PiholeChange {
        std::string kind;   // create | update | delete
        std::string cidr, pihole_group, comment, why;
        int client_id = 0;              // update/delete
        std::vector<int> group_ids;     // create/update: the entry's groups
    };

    struct PiholeFinding {
        std::string kind;   // missing-group | unmanaged-overlap | unmanaged-shadow | stale-managed | mac-client | hostname-client
        std::string client, detail;
        int client_id = 0;
    };

    struct PiholePlan {
        std::vector<DesiredClient> desired;
        std::vector<PiholeChange> changes;
        std::vector<PiholeFinding> findings;
        [[nodiscard]] bool empty() const { return changes.empty(); }
    };

    // "a.b.c.d m.m.m.m" -> "a.b.c.d/n" (network address, host bits cleared); empty when invalid.
    std::string to_cidr(std::string_view ip_and_mask);

    struct PiholeSyncOptions {
        // From the Pi-hole client-resolution study: does Pi-hole pick the most specific CIDR when
        // several client entries contain an address? If not, hybrid uses the complement.
        bool most_specific_wins = false;
        bool prune = false;   // delete managed entries no network implies any more (else: reported)
        // The minimal CIDR cover of network minus slices (alloc::complement).
        std::function<std::vector<std::string>(const std::string& network, const std::vector<std::string>& slices)> complement;
    };

    std::vector<DesiredClient> desired_clients(const Config& config, const Snapshot& snapshot, const PiholeSyncOptions& options);

    PiholePlan plan_pihole(const Config& config, const Snapshot& snapshot, const PiholeView& view, const PiholeSyncOptions& options);

    std::string managed_comment(const DesiredClient& desired);

}  // namespace fph

#endif  // FORTI_PIHOLE_PIHOLE_SYNC_HPP
