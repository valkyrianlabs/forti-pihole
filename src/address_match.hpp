//
// Does a FortiOS address (or address group) cover an endpoint? Used both to see where a device
// currently sits and to simulate policy matching for the connectivity check. Deliberately
// conservative: types the companion cannot evaluate offline (FQDN, geography, wildcard, ISDB, EMS
// and other dynamic tags) never match, so they behave the same before and after a change and cannot
// hide a lost route.
//

#ifndef FORTI_PIHOLE_ADDRESS_MATCH_HPP
#define FORTI_PIHOLE_ADDRESS_MATCH_HPP

#include "inventory.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace fph {

    struct Endpoint {
        std::string mac;   // empty for a destination
        std::string ip;
    };

    std::optional<std::uint32_t> parse_ipv4(std::string_view text);

    // "a.b.c.d m.m.m.m" or "a.b.c.d/len".
    bool in_subnet(std::string_view ip, std::string_view subnet);

    bool address_covers(const Snapshot& snapshot, std::string_view name, const Endpoint& endpoint);

}  // namespace fph

#endif  // FORTI_PIHOLE_ADDRESS_MATCH_HPP
