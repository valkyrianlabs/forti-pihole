//
// MAC addresses as FortiOS shows them: six lowercase hex pairs joined by ':'. Everything the
// companion compares (inventory, DHCP leases, address objects, state) goes through normalize()
// first, because FortiOS accepts and echoes several spellings (upper case, '-' separators).
//

#ifndef FORTI_VLAN_MAC_MAC_HPP
#define FORTI_VLAN_MAC_MAC_HPP

#include <optional>
#include <string>
#include <string_view>

namespace fvm {

    // "AA-BB-cc:dd:EE:ff" -> "aa:bb:cc:dd:ee:ff"; nullopt when it is not a MAC address.
    std::optional<std::string> normalize_mac(std::string_view text);

    // The locally administered bit: set on randomized ("private Wi-Fi") addresses, which can rotate,
    // so a device seen with one can come back under another.
    bool locally_administered(std::string_view mac);

    // "aa:bb:cc:dd:ee:ff" -> "ddeeff": the part that tells siblings from one vendor apart.
    std::string mac_suffix(std::string_view mac);

    // The first three octets ("aa:bb:cc"), compared against rule mac_prefix values.
    std::string mac_oui(std::string_view mac);

    // True when `mac` falls in a FortiOS macaddr entry: one address, or a range "lo-hi".
    bool mac_in_entry(std::string_view mac, std::string_view entry);

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_MAC_HPP
