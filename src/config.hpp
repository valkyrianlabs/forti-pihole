//
// The companion's configuration: which segments exist, how devices are presumed into them, and
// which devices are never touched. It holds policy about classification only. Membership itself
// lives on the FortiGate (address groups), so the GUI stays the source of truth.
//
//   $FORTI_HOME/vlan-mac/config.json   (default ~/.forti/vlan-mac/config.json)
//
// Segments are listed in priority order: when an operator puts one device in two segment groups,
// the earlier segment wins (and the overlap is reported).
//

#ifndef FORTI_VLAN_MAC_CONFIG_HPP
#define FORTI_VLAN_MAC_CONFIG_HPP

#include <nlohmann/json.hpp>

#include <filesystem>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace fvm {

    class ConfigError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    struct Segment {
        std::string name;          // [a-z0-9_]{1,32}
        std::string description;
        // A privileged segment (trusted users, work machines) is only ever entered by an explicit
        // assignment: no rule, no vendor match and no reassociation can put a device there.
        bool privileged = false;
        // Documentation of the intended DHCP subnet ("192.168.30.0/24"). Not acted on: subnet
        // assignment is not available until FortiOS behaviour for it is proven (docs, safety).
        std::string subnet;
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
        std::string name;      // shown in reports; defaults to "<segment>#<index>"
        std::string segment;
        int priority = 100;    // higher wins; equal-priority matches in different segments are ambiguous
        Match match;
    };

    struct Config {
        std::string profile;                          // forti profile; empty: the default profile
        std::string vdom;                             // empty: the profile's
        std::string prefix = "mvlan-";                // every managed object's name starts with it
        std::vector<std::string> interfaces = {"internal"};   // only devices detected here are managed
        std::string default_segment = "default";
        std::vector<Segment> segments;
        std::vector<Rule> rules;
        std::vector<std::string> protected_macs;      // never classified or moved automatically
        std::map<std::string, std::string> assignments;   // mac -> segment, explicit (config-file pins)
        int retire_after_days = 30;
        int native_rule_priority = 50;                // priority of GUI-made mvlan-rule-* objects
        bool adopt_existing = true;                   // reuse an admin's single-MAC address object as the member
        int max_changes = 50;                         // per apply; more waits for the next run

        // Validates everything; throws ConfigError with the offending key.
        static Config from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;

        [[nodiscard]] const Segment* segment(std::string_view name) const;
        [[nodiscard]] bool is_protected(std::string_view mac) const;
        [[nodiscard]] std::size_t segment_rank(std::string_view name) const;   // index; npos when unknown

        // Object names (the ownership marker is the comment; names alone are not trusted).
        [[nodiscard]] std::string group_name(std::string_view segment) const { return prefix + "seg-" + std::string(segment); }
        [[nodiscard]] std::string rule_prefix() const { return prefix + "rule-"; }
        [[nodiscard]] std::string device_prefix() const { return prefix + "dev-"; }
    };

    // The comment every managed object carries; objects without it are an administrator's and are
    // never modified or deleted.
    inline constexpr std::string_view marker = "managed by forti-vlan-mac";

    // Loads and validates; a missing file is ConfigError with a hint to run `forti-vlan-mac init`.
    Config load_config(const std::filesystem::path& path);

    // A starting configuration: the segments and presumptive rules from the example, all disabled
    // from privileged inference. Written by `init`.
    nlohmann::json example_config();

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_CONFIG_HPP
