//
// Everything on the FortiGate that refers to one IPv4 address. A device's address can only move
// safely when nothing still grants that address something the device had: a host address object
// in a policy keeps working for whoever gets the old address next (policies OR their source
// objects, so a MAC object next to it does not help), a VIP keeps forwarding to it, and a
// reservation or lease keeps it occupied.
//
// Kinds:
//   host       ipmask /32 (or an iprange of exactly that address): the object stands for this device
//   range      an iprange that contains it (also covers others)
//   subnet     an ipmask/interface-subnet with a shorter mask that contains it (also covers others)
//   vip        a VIP whose mapped address is it (port forwards follow the address, not the device)
//   reservation, lease   DHCP
//
// For address objects, `policies` lists every policy that reaches the object directly or through
// (nested) address groups, as source or destination, so the report can say what moving the address
// would take away or leave behind.
//

#ifndef FORTI_PIHOLE_REFERENCES_HPP
#define FORTI_PIHOLE_REFERENCES_HPP

#include "inventory.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace fph {

    struct PolicyUse {
        std::uint64_t id = 0;
        std::string name;
        bool source = false;          // srcaddr (else dstaddr)
        bool enabled = true;
        std::vector<std::string> via;   // groups between the policy and the object, outermost first
    };

    struct IpReference {
        std::string kind;     // host | range | subnet | vip | reservation | lease
        std::string name;     // object / VIP name, "dhcp <server id> reservation <id>", "lease"
        std::string detail;   // subnet text, MAC of a reservation or lease, ...
        bool managed = false; // carries forti-pihole's marker
        std::vector<PolicyUse> policies;
    };

    std::vector<IpReference> references_to(const Snapshot& snapshot, std::string_view ip);

    // Host objects among the references whose policies make the address privileged: enabled
    // policies that use them as a source. These must follow the device (or be cleared) before the
    // old address can be handed to anyone else.
    std::vector<const IpReference*> privileged_hosts(const std::vector<IpReference>& references);

}  // namespace fph

#endif  // FORTI_PIHOLE_REFERENCES_HPP
