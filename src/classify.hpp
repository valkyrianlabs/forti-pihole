//
// Classification: which segment each managed device belongs in, and why.
//
// Precedence (first that applies wins):
//   1. protected   the device is never classified or moved by the companion
//   2. assignment  config.json "assignments" (explicit, file)
//   3. pin         explicit operator decisions: `assign`, `confirm`, or a move made in the FortiGate GUI
//                  (detected as a placement the companion did not write)
//   4. rule        presumptive: config rules and GUI-made mvlan-rule-<segment>-<label> dynamic objects;
//                  the highest priority wins, a tie between segments is ambiguous
//   5. default     unknown and ambiguous devices
//
// Privileged segments are reachable only through 2 and 3: config validation refuses rules that target
// them, and native rule objects naming one are ignored with a warning.
//

#ifndef FORTI_VLAN_MAC_CLASSIFY_HPP
#define FORTI_VLAN_MAC_CLASSIFY_HPP

#include "config.hpp"
#include "inventory.hpp"
#include "state.hpp"

#include <nlohmann/json.hpp>

#include <map>
#include <set>
#include <string>
#include <vector>

namespace fvm {

    struct RuleMatch {
        std::string segment, rule;   // rule: config rule name or the native object's name
        int priority = 0;
        bool native = false;
    };

    // Where a device currently is: one (segment, member object) pair per placement found in the groups.
    struct Placement {
        std::string segment, member;
        bool by_companion = false;   // exactly what the companion last wrote for this device
    };

    struct Decision {
        Device device;
        std::string segment;   // effective; empty for a protected device nobody placed
        std::string source;    // protected | assignment | pin | rule | default | ambiguous
        std::string detail;    // rule name, pin source, ...
        std::vector<std::string> reasons;
        std::vector<RuleMatch> matches;     // every rule that matched (for the report)
        std::vector<Placement> placements;  // observed
        std::string member;                 // the object to place in the segment group
        bool create_member = false;         // member does not exist yet (a managed object will be created)
        bool adopted = false;               // member is an administrator's object, referenced as-is
        bool keep = false;                  // protected: no change of any kind
    };

    struct Overlap {
        std::string mac, label;
        std::vector<std::string> segments;   // observed, in config order
        std::string winner, why;
    };

    struct Classification {
        std::vector<Decision> decisions;   // by MAC
        std::vector<Overlap> overlaps;
        std::vector<std::string> warnings;
        std::map<std::string, Pin> new_pins;           // GUI moves detected this run (to record in state)
        std::set<std::string> cleared_pins;            // GUI pins dropped because the operator deleted the object
        std::set<std::string> unusable_segments;       // segment group name taken by an object without the marker

        [[nodiscard]] const Decision* decision(std::string_view mac) const;
    };

    // Case-insensitive glob ('*', '?').
    bool glob_match(std::string_view pattern, std::string_view text);

    bool rule_matches(const Match& match, const Device& device);

    // True when address `name` (address or group, recursively) covers the device (MAC or IP).
    bool covers(const Snapshot& snapshot, std::string_view name, const Device& device);

    Classification classify(const Snapshot& snapshot, const Config& config, const State& state, std::int64_t now);

    // FortiOS object name for a new managed device object: <prefix>dev-<slug>-<last 6 hex digits>,
    // unique in the snapshot, at most 79 characters.
    std::string device_object_name(const Config& config, const Device& device, const Snapshot& snapshot);

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_CLASSIFY_HPP
