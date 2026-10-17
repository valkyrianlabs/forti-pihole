//
// Reconciliation: from classification to the smallest set of engine operations that makes the
// segment groups say what the decisions say.
//
//   - Desired membership starts from the groups as they are, so an administrator's own members stay.
//   - A device moves by removing its single-device members from the other segment groups and adding
//     its member to its segment group (unless something there already covers it).
//   - Missing segment groups and device objects are created, with the ownership marker.
//   - Devices the companion has not seen for retire_after_days (or that a confirmed reassociation
//     replaced) lose their managed object, unless something outside the segment groups uses it.
//   - Every device's internet and DNS reach is simulated before and after; a device whose reach
//     would shrink keeps its current placement (reported as blocked).
//   - Nothing destructive happens when the inventory is empty (a failed or partial read).
//   - At most max_changes devices change per run; the rest wait for the next one.
//
// Segment groups whose segment left the configuration are reported, never deleted.
//

#ifndef FORTI_PIHOLE_RECONCILE_HPP
#define FORTI_PIHOLE_RECONCILE_HPP

#include "classify.hpp"
#include "connectivity.hpp"
#include "config.hpp"
#include "inventory.hpp"
#include "state.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <string>
#include <vector>

namespace fph {

    struct Change {
        std::string kind;   // create-group | create-object | move | place | retire | comment
        std::string mac, label, object, segment, from;
        std::string reason;
    };

    struct Written {
        std::string object, segment;
    };

    struct Changeset {
        nlohmann::json operations = nlohmann::json::array();   // engine plan operations, in order
        std::vector<Change> changes;
        std::vector<Loss> blocked;                 // refused by the connectivity check
        std::vector<std::string> deferred;         // MACs over max_changes
        std::vector<std::string> notes;            // orphan groups, skipped retirements, ...
        std::map<std::string, Written> written;    // mac -> what the groups hold for it after apply
        std::vector<std::string> retired;          // MACs whose records go after apply

        [[nodiscard]] bool empty() const { return operations.empty(); }
    };

    Changeset reconcile(const Snapshot& snapshot, const Classification& classification, const Config& config, const State& state,
                        std::int64_t now, int max_changes);

    // The managed object's comment: marker, then a readable description from untrusted device data
    // (printable ASCII only, bounded so FortiOS's 255-character limit holds).
    std::string object_comment(const Device& device);
    std::string group_comment(const Segment& segment);

}  // namespace fph

#endif  // FORTI_PIHOLE_RECONCILE_HPP
