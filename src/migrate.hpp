//
// Address migration: moving one device to a new reserved address inside its group's slice, as a
// journaled operation (operation.hpp). Built from a SliceAction "move" and the current snapshot.
//
// Refused (no operation is created) unless all of these hold:
//   - the target address is free (no lease, reservation, VIP, host object or static device)
//   - no VIP maps the old address (a port forward follows the address, not the device)
//   - the device's reservation, if it has one, carries forti-pihole's marker or is adopted
//   - every host object on the old address that enabled policies use as a source is adopted
//     (it then follows the device: updated to the new address)
//
// Steps, in order:
//   pihole       the slice's managed CIDR client entry exists and maps to the group's Pi-hole group
//   reservation  create or update the reservation (single child-table entry, never the whole list)
//   objects      adopted host objects: old address -> new address, BEFORE the lease is released, so
//                the old address never stays privileged while it is free
//   revoke       revoke only the device's old lease
//   observe      wait for the device to take the new address (bounded; then "waiting": reconnect it)
//   verify       lease and inventory show the new address; firewall reach is unchanged; Pi-hole
//                resolves the new address to the intended group
//
// Rollback (reverse): objects back to the old address; the reservation restored (engine rollback
// plan) and the new lease revoked so the device renews into its old address; the Pi-hole entry the
// operation created removed if nothing else uses it.
//

#ifndef FORTI_PIHOLE_MIGRATE_HPP
#define FORTI_PIHOLE_MIGRATE_HPP

#include "config.hpp"
#include "connectivity.hpp"
#include "inventory.hpp"
#include "operation.hpp"
#include "references.hpp"
#include "slicing.hpp"

#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <vector>

namespace fph {

    struct Adoptions {
        std::set<std::string> address_objects;   // host objects that may follow the device
        bool reservation = false;                // the device's own administrator reservation may be changed
    };

    struct MigrationRefusal {
        std::string reason;
        std::vector<std::string> needs;   // what would make it possible ("adopt object X", ...)
    };

    struct MigrationPlan {
        std::string mac, label;
        std::optional<Operation> operation;   // nullopt: refused
        MigrationRefusal refusal;
        std::vector<IpReference> old_references, new_references;
        Reach before;                         // firewall reach at the old address (verified after)
        std::vector<std::string> notes;       // what stays behind (Pi-hole per-IP entries, ranges)
    };

    MigrationPlan plan_migration(const Config& config, const Snapshot& snapshot, const SliceAction& action, const Adoptions& adoptions,
                                 std::int64_t now);

    // Engine operations used by the steps (exposed for tests and for `plan --json`).
    nlohmann::json reservation_operations(const SliceAction& action, const std::string& description);
    nlohmann::json object_operations(const std::vector<std::string>& objects, const std::string& ip);
    nlohmann::json revoke_operation(const std::string& ip);

    std::string reservation_description(const SliceAction& action);

}  // namespace fph

#endif  // FORTI_PIHOLE_MIGRATE_HPP
