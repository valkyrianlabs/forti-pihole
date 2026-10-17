//
// The companion's configuration: which groups exist, how devices are presumed into them, and
// which devices are never touched. It holds policy about classification only. Membership itself
// lives on the FortiGate (address groups), so the GUI stays the source of truth.
//
//   $FORTI_HOME/pihole/config.json   (default ~/.forti/pihole/config.json)
//
// Groups are listed in priority order: when an operator puts one device in two group groups,
// the earlier group wins (and the overlap is reported).
//

#ifndef FORTI_PIHOLE_CONFIG_HPP
#define FORTI_PIHOLE_CONFIG_HPP

#include "pihole/marker.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace fph {

    class ConfigError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // A logical device group: a FortiGate address group <prefix>grp-<name> holding one MAC object per
    // member, mapped to a Pi-hole filtering group. Groups are network-independent: where a member
    // gets its address (a slice, a VLAN subnet) depends on the network it is detected on.
    struct DeviceGroup {
        std::string name;          // [a-z0-9_]{1,32}
        std::string description;
        // A privileged group (trusted users, work machines) is only ever entered by an explicit
        // assignment: no rule, no vendor match and no reassociation can put a device there.
        bool privileged = false;
        // The Pi-hole group (by name) its addresses resolve to. Empty: not mapped, so Pi-hole applies
        // its Default group, as it does for any client it has no entry for.
        std::string pihole_group;
    };

    struct SliceSpec {
        std::string group;   // a listed device group
        std::string cidr;    // "192.168.1.224/28", inside the network's subnet, host bits zero
    };

    // How one FortiGate interface's addresses map to Pi-hole groups (the allocation strategy).
    //   subnet  the whole interface subnet (and secondary subnets) -> the network group's Pi-hole group.
    //           Native VLANs: nothing on the FortiGate changes.
    //   slices  DHCP address slicing: members of a group with a slice here get a reservation inside
    //           it; each slice CIDR -> its group's Pi-hole group; the rest of the subnet stays with
    //           Pi-hole's Default group.
    //   hybrid  slices, and the rest of the subnet -> the network group's Pi-hole group.
    //   observe inventory and reports only.
    struct Network {
        enum class Mode { subnet, slices, hybrid, observe };
        std::string interface;
        Mode mode = Mode::observe;
        std::string group;   // the network's group: unclassified members' group, and the subnet's Pi-hole mapping
        std::vector<SliceSpec> slices;
        // Slices only: may forti-pihole create, move and delete DHCP reservations here? Off until the
        // operator turns it on; a plan is still shown.
        bool manage_reservations = false;
    };

    std::string_view to_string(Network::Mode mode);

    struct PiholeConfig {
        std::string url;          // "https://pihole.example.net"; empty: Pi-hole sync disabled
        std::string ca_bundle;    // PEM for a private CA; empty: the system trust store
        std::string name = "default";   // names the credential in forti's secret store: pihole/<name>/password
        int timeout_ms = 10000;
    };

    // All set fields must match (AND). String fields compare case-insensitively and accept the glob
    // wildcards '*' and '?'. Empty fields are not checked.
    struct Match {
        std::string vendor;       // inventory hardware_vendor ("TP-Link")
        std::string family;       // hardware_family ("Plug", "Fire TV")
        std::string type;         // hardware_type ("IoT", "Television")
        std::string os;           // os_name ("Fire OS")
        std::string hostname;     // inventory or DHCP hostname ("HS103", "amazon-*")
        std::string vci;          // DHCP vendor class identifier ("udhcp*")
        std::string mac_prefix;   // OUI or longer prefix ("5c:e9:31")

        [[nodiscard]] bool empty() const;
    };

    struct Rule {
        std::string name;      // shown in reports; defaults to "<group>#<index>"
        std::string group;
        int priority = 100;    // higher wins; equal-priority matches in different groups are ambiguous
        Match match;
    };

    struct Config {
        // Off after install: sync plans and reports, and writes nothing to the FortiGate or Pi-hole
        // until the operator sets it (forti-pihole setup asks).
        bool enabled = false;
        std::string profile;                          // forti profile; empty: the default profile
        std::string vdom;                             // empty: the profile's
        std::string prefix = "fp-";                // every managed object's name starts with it
        std::vector<std::string> interfaces;          // devices detected here are classified; default: every network's interface
        std::vector<Network> networks;
        PiholeConfig pihole;
        nlohmann::json daemon = nlohmann::json::object();   // forti-piholed's section (validated by the daemon)
        std::string default_group = "default";
        std::vector<DeviceGroup> groups;
        std::vector<Rule> rules;
        std::vector<std::string> protected_macs;      // never classified or moved automatically
        std::map<std::string, std::string> assignments;   // mac -> group, explicit (config-file pins)
        int retire_after_days = 30;
        int native_rule_priority = 50;                // priority of GUI-made fp-rule-* objects
        bool adopt_existing = true;                   // reuse an admin's single-MAC address object as the member
        int max_changes = 50;                         // per apply; more waits for the next run

        // Validates everything; throws ConfigError with the offending key.
        static Config from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;

        [[nodiscard]] const DeviceGroup* group(std::string_view name) const;
        [[nodiscard]] const Network* network(std::string_view interface) const;
        [[nodiscard]] bool is_protected(std::string_view mac) const;
        [[nodiscard]] std::size_t group_rank(std::string_view name) const;   // index; npos when unknown

        // Object names (the ownership marker is the comment; names alone are not trusted).
        [[nodiscard]] std::string addrgrp_name(std::string_view group) const { return prefix + "grp-" + std::string(group); }
        [[nodiscard]] std::string rule_prefix() const { return prefix + "rule-"; }
        [[nodiscard]] std::string device_prefix() const { return prefix + "dev-"; }
        [[nodiscard]] std::string slice_name(std::string_view cidr) const;   // <prefix>slice-a.b.c.d-n
    };

    // The comment every managed object carries; objects without it are an administrator's and are
    // never modified or deleted.
    inline constexpr std::string_view marker = ownership_marker;

    // Loads and validates; a missing file is ConfigError with a hint to run `forti-pihole init`.
    Config load_config(const std::filesystem::path& path);

    // A starting configuration: the groups and presumptive rules from the example, all disabled
    // from privileged inference. Written by `init`.
    nlohmann::json example_config();

}  // namespace fph

#endif  // FORTI_PIHOLE_CONFIG_HPP
