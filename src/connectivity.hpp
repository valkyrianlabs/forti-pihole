//
// The "no device loses its route" check. For every online managed device it simulates FortiOS's
// first-match policy lookup towards two probes, before and after a proposed change:
//
//   internet  TCP/443 to 1.1.1.1 out of a WAN-role interface
//   dns       UDP/53 to the DNS server the device's DHCP server hands out (skipped when that is the
//             FortiGate itself, which local-in, not a policy, governs)
//
// A change that turns a device's accept into a deny or no match is refused for that device. The
// simulation ignores schedules, and treats policies it cannot evaluate offline (users/groups, ISDB,
// FQDN or tag addresses) as non-matching. The same blind spots apply before and after, so a group
// change still shows up; a precise verdict for every policy is not the goal.
//

#ifndef FORTI_PIHOLE_CONNECTIVITY_HPP
#define FORTI_PIHOLE_CONNECTIVITY_HPP

#include "inventory.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace fph {

    struct Verdict {
        std::string action = "none";   // accept | deny | none (implicit deny) | n/a (probe does not apply)
        std::uint64_t policy = 0;
        std::string policy_name;

        [[nodiscard]] bool reaches() const { return action == "accept" || action == "n/a"; }
        [[nodiscard]] std::string describe() const;
    };

    struct Reach {
        Verdict internet, dns;
    };

    struct Loss {
        std::string mac, label, probe;
        Verdict before, after;
    };

    Reach evaluate(const Snapshot& snapshot, const Device& device);

    // Devices whose reach shrinks from `before` to `after` (online devices only).
    std::vector<Loss> compare(const Snapshot& before, const Snapshot& after);

    // Port and service matching, exposed for tests.
    bool portrange_covers(std::string_view range, unsigned port);
    bool service_covers(const Snapshot& snapshot, std::string_view name, std::string_view protocol, unsigned port);

}  // namespace fph

#endif  // FORTI_PIHOLE_CONNECTIVITY_HPP
