#include "config.hpp"

#include "mac.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>

namespace fph {

    using json = nlohmann::json;

    namespace {

        void allow_keys(const json& object, std::initializer_list<std::string_view> keys, std::string_view where) {
            if (!object.is_object()) throw ConfigError(std::format("{}: must be an object", where));
            for (auto it = object.begin(); it != object.end(); ++it)
                if (std::ranges::find(keys, std::string_view(it.key())) == keys.end())
                    throw ConfigError(std::format("{}: unknown key \"{}\"", where, it.key()));
        }

        std::string text(const json& object, const char* key, std::string_view where, std::string fallback = {}) {
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return fallback;
            if (!it->is_string()) throw ConfigError(std::format("{}.{}: must be a string", where, key));
            return it->get<std::string>();
        }

        int integer(const json& object, const char* key, std::string_view where, int fallback, int lo, int hi) {
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return fallback;
            if (!it->is_number_integer()) throw ConfigError(std::format("{}.{}: must be an integer", where, key));
            auto value = it->get<long long>();
            if (value < lo || value > hi) throw ConfigError(std::format("{}.{}: must be {}..{}", where, key, lo, hi));
            return static_cast<int>(value);
        }

        bool boolean(const json& object, const char* key, std::string_view where, bool fallback) {
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return fallback;
            if (!it->is_boolean()) throw ConfigError(std::format("{}.{}: must be true or false", where, key));
            return it->get<bool>();
        }

        std::vector<std::string> strings(const json& object, const char* key, std::string_view where,
                                         std::vector<std::string> fallback) {
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return fallback;
            if (!it->is_array()) throw ConfigError(std::format("{}.{}: must be an array of strings", where, key));
            std::vector<std::string> out;
            for (const auto& item: *it) {
                if (!item.is_string()) throw ConfigError(std::format("{}.{}: must be an array of strings", where, key));
                out.push_back(item.get<std::string>());
            }
            return out;
        }

        // DeviceGroup names become part of FortiOS object names (79 characters max for addresses).
        bool valid_group_name(std::string_view name) {
            static const std::regex pattern("^[a-z0-9_]{1,32}$");
            return std::regex_match(name.begin(), name.end(), pattern);
        }

        bool valid_prefix(std::string_view prefix) {
            static const std::regex pattern("^[A-Za-z0-9_-]{2,24}$");
            return std::regex_match(prefix.begin(), prefix.end(), pattern);
        }

        bool valid_cidr(std::string_view text) {
            static const std::regex pattern(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$)");
            std::match_results<std::string_view::const_iterator> m;
            if (!std::regex_match(text.begin(), text.end(), m, pattern)) return false;
            for (int i = 1; i <= 4; ++i)
                if (std::stoi(m[i].str()) > 255) return false;
            return std::stoi(m[5].str()) <= 32;
        }

        Match parse_match(const json& object, const std::string& where) {
            allow_keys(object, {"vendor", "family", "type", "os", "hostname", "vci", "mac_prefix"}, where);
            Match match;
            match.vendor = text(object, "vendor", where);
            match.family = text(object, "family", where);
            match.type = text(object, "type", where);
            match.os = text(object, "os", where);
            match.hostname = text(object, "hostname", where);
            match.vci = text(object, "vci", where);
            match.mac_prefix = text(object, "mac_prefix", where);
            if (!match.mac_prefix.empty()) {
                std::string lowered;
                for (char c: match.mac_prefix) lowered += static_cast<char>(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c == '-' ? ':' : c);
                static const std::regex pattern("^[0-9a-f]{2}(:[0-9a-f]{2}){0,5}$");
                if (!std::regex_match(lowered, pattern)) throw ConfigError(std::format("{}.mac_prefix: not a MAC prefix", where));
                match.mac_prefix = lowered;
            }
            if (match.empty()) throw ConfigError(std::format("{}: matches nothing (set at least one field)", where));
            return match;
        }

        std::optional<std::pair<std::uint32_t, int>> parse_cidr(std::string_view text) {
            if (!valid_cidr(text)) return std::nullopt;
            auto slash = text.find('/');
            std::uint32_t value = 0;
            std::string_view ip = text.substr(0, slash);
            for (int i = 0; i < 4; ++i) {
                auto dot = ip.find('.');
                value = (value << 8) | static_cast<std::uint32_t>(std::stoi(std::string(ip.substr(0, dot))));
                ip = dot == std::string_view::npos ? std::string_view() : ip.substr(dot + 1);
            }
            int prefix = std::stoi(std::string(text.substr(slash + 1)));
            return std::pair{value, prefix};
        }

        bool host_bits_clear(std::uint32_t value, int prefix) {
            std::uint32_t mask = prefix == 0 ? 0 : ~std::uint32_t(0) << (32 - prefix);
            return (value & ~mask) == 0;
        }

        Network::Mode parse_mode(const std::string& text, const std::string& where) {
            if (text == "subnet") return Network::Mode::subnet;
            if (text == "slices") return Network::Mode::slices;
            if (text == "hybrid") return Network::Mode::hybrid;
            if (text == "observe" || text.empty()) return Network::Mode::observe;
            throw ConfigError(where + ".mode: subnet, slices, hybrid or observe");
        }

        void parse_networks(Config& config, const json& root) {
            auto networks = root.find("networks");
            if (networks == root.end() || networks->is_null()) return;
            if (!networks->is_array()) throw ConfigError("config.networks: must be an array");
            std::set<std::string> seen;
            for (std::size_t i = 0; i < networks->size(); ++i) {
                auto where = std::format("config.networks[{}]", i);
                const auto& item = (*networks)[i];
                allow_keys(item, {"interface", "mode", "group", "slices", "manage_reservations"}, where);
                Network network;
                network.interface = text(item, "interface", where);
                if (network.interface.empty()) throw ConfigError(where + ".interface: required");
                if (!seen.insert(network.interface).second) throw ConfigError(where + ".interface: listed twice");
                network.mode = parse_mode(text(item, "mode", where, "observe"), where);
                network.group = text(item, "group", where, config.default_group);
                const DeviceGroup* base = config.group(network.group);
                if (!base) throw ConfigError(where + ".group: \"" + network.group + "\" is not a listed group");
                network.manage_reservations = boolean(item, "manage_reservations", where, false);
                if (auto slices = item.find("slices"); slices != item.end() && !slices->is_null()) {
                    if (!slices->is_array()) throw ConfigError(where + ".slices: must be an array");
                    std::vector<std::pair<std::uint32_t, int>> parsed;
                    for (std::size_t j = 0; j < slices->size(); ++j) {
                        auto at = std::format("{}.slices[{}]", where, j);
                        allow_keys((*slices)[j], {"group", "cidr"}, at);
                        SliceSpec slice{text((*slices)[j], "group", at), text((*slices)[j], "cidr", at)};
                        if (!config.group(slice.group)) throw ConfigError(at + ".group: \"" + slice.group + "\" is not a listed group");
                        auto cidr = parse_cidr(slice.cidr);
                        if (!cidr) throw ConfigError(at + ".cidr: not an IPv4 CIDR");
                        if (!host_bits_clear(cidr->first, cidr->second))
                            throw ConfigError(at + ".cidr: " + slice.cidr + " has host bits set");
                        for (const auto& other: parsed) {
                            int shorter = std::min(other.second, cidr->second);
                            std::uint32_t mask = shorter == 0 ? 0 : ~std::uint32_t(0) << (32 - shorter);
                            if ((other.first & mask) == (cidr->first & mask))
                                throw ConfigError(at + ".cidr: " + slice.cidr + " overlaps another slice of this network");
                        }
                        parsed.push_back(*cidr);
                        network.slices.push_back(std::move(slice));
                    }
                }
                if (network.mode == Network::Mode::subnet && !network.slices.empty())
                    throw ConfigError(where + ": subnet mode has no slices (use hybrid)");
                if (network.mode == Network::Mode::slices && !base->pihole_group.empty())
                    throw ConfigError(where + ": in slices mode the rest of the subnet stays with Pi-hole's Default group, but group \"" +
                                      network.group + "\" maps to Pi-hole group \"" + base->pihole_group + "\" (use hybrid)");
                config.networks.push_back(std::move(network));
            }
        }

        void parse_pihole(Config& config, const json& root) {
            auto pihole = root.find("pihole");
            if (pihole == root.end() || pihole->is_null()) return;
            allow_keys(*pihole, {"url", "ca_bundle", "name", "timeout_ms"}, "config.pihole");
            config.pihole.url = text(*pihole, "url", "config.pihole");
            auto& url = config.pihole.url;
            bool loopback_http = url.starts_with("http://127.") || url.starts_with("http://localhost") || url.starts_with("http://[::1]");
            if (!url.empty() && !url.starts_with("https://") && !loopback_http)
                throw ConfigError("config.pihole.url: must start with https:// (plain http only to a Pi-hole on this host)");
            while (config.pihole.url.ends_with("/")) config.pihole.url.pop_back();
            config.pihole.ca_bundle = text(*pihole, "ca_bundle", "config.pihole");
            config.pihole.name = text(*pihole, "name", "config.pihole", config.pihole.name);
            if (!valid_prefix(config.pihole.name)) throw ConfigError("config.pihole.name: 2-24 characters of [A-Za-z0-9_-]");
            config.pihole.timeout_ms = integer(*pihole, "timeout_ms", "config.pihole", config.pihole.timeout_ms, 1000, 120000);
        }

    }  // namespace

    std::string_view to_string(Network::Mode mode) {
        switch (mode) {
            case Network::Mode::subnet: return "subnet";
            case Network::Mode::slices: return "slices";
            case Network::Mode::hybrid: return "hybrid";
            case Network::Mode::observe: return "observe";
        }
        return "observe";
    }

    bool Match::empty() const {
        return vendor.empty() && family.empty() && type.empty() && os.empty() && hostname.empty() && vci.empty() &&
               mac_prefix.empty();
    }

    Config Config::from_json(const json& root) {
        allow_keys(root, {"enabled", "profile", "vdom", "prefix", "interfaces", "networks", "pihole", "daemon", "default_group",
                          "groups", "rules", "protected", "assignments", "retire_after_days", "native_rule_priority",
                          "adopt_existing", "max_changes", "$comment"},
                   "config");
        Config config;
        config.enabled = boolean(root, "enabled", "config", false);
        config.profile = text(root, "profile", "config");
        config.vdom = text(root, "vdom", "config");
        config.prefix = text(root, "prefix", "config", config.prefix);
        if (!valid_prefix(config.prefix)) throw ConfigError("config.prefix: 2-24 characters of [A-Za-z0-9_-]");
        config.interfaces = strings(root, "interfaces", "config", {});
        config.default_group = text(root, "default_group", "config", config.default_group);
        config.retire_after_days = integer(root, "retire_after_days", "config", config.retire_after_days, 1, 3650);
        config.native_rule_priority = integer(root, "native_rule_priority", "config", config.native_rule_priority, 0, 10000);
        config.adopt_existing = boolean(root, "adopt_existing", "config", config.adopt_existing);
        config.max_changes = integer(root, "max_changes", "config", config.max_changes, 1, 1000);

        auto groups = root.find("groups");
        if (groups == root.end() || !groups->is_array() || groups->empty())
            throw ConfigError("config.groups: list at least one group");
        std::set<std::string> names;
        for (std::size_t i = 0; i < groups->size(); ++i) {
            auto where = std::format("config.groups[{}]", i);
            const auto& item = (*groups)[i];
            allow_keys(item, {"name", "description", "privileged", "pihole_group"}, where);
            DeviceGroup group;
            group.name = text(item, "name", where);
            if (!valid_group_name(group.name)) throw ConfigError(where + ".name: 1-32 characters of [a-z0-9_]");
            if (!names.insert(group.name).second) throw ConfigError(where + ".name: duplicate group \"" + group.name + "\"");
            group.description = text(item, "description", where);
            group.privileged = boolean(item, "privileged", where, false);
            group.pihole_group = text(item, "pihole_group", where);
            config.groups.push_back(std::move(group));
        }
        const DeviceGroup* fallback = config.group(config.default_group);
        if (!fallback) throw ConfigError("config.default_group: \"" + config.default_group + "\" is not a listed group");
        // Unknown devices land in the default group, so it must never grant privileged access.
        if (fallback->privileged) throw ConfigError("config.default_group: the default group cannot be privileged");

        if (auto rules = root.find("rules"); rules != root.end() && !rules->is_null()) {
            if (!rules->is_array()) throw ConfigError("config.rules: must be an array");
            for (std::size_t i = 0; i < rules->size(); ++i) {
                auto where = std::format("config.rules[{}]", i);
                const auto& item = (*rules)[i];
                allow_keys(item, {"name", "group", "priority", "match"}, where);
                Rule rule;
                rule.group = text(item, "group", where);
                const DeviceGroup* target = config.group(rule.group);
                if (!target) throw ConfigError(where + ".group: \"" + rule.group + "\" is not a listed group");
                if (target->privileged)
                    throw ConfigError(where + ".group: \"" + rule.group +
                                      "\" is privileged; privileged groups are only entered by explicit assignment");
                rule.name = text(item, "name", where, std::format("{}#{}", rule.group, i));
                rule.priority = integer(item, "priority", where, rule.priority, 0, 10000);
                auto match = item.find("match");
                if (match == item.end()) throw ConfigError(where + ".match: required");
                rule.match = parse_match(*match, where + ".match");
                config.rules.push_back(std::move(rule));
            }
        }

        parse_networks(config, root);
        parse_pihole(config, root);
        if (auto daemon = root.find("daemon"); daemon != root.end() && !daemon->is_null()) {
            if (!daemon->is_object()) throw ConfigError("config.daemon: must be an object");
            config.daemon = *daemon;
        }

        if (config.interfaces.empty())
            for (const auto& n: config.networks) config.interfaces.push_back(n.interface);
        if (config.interfaces.empty()) throw ConfigError("config: list at least one network (or interface)");

        for (const auto& mac: strings(root, "protected", "config", {})) {
            auto normalized = normalize_mac(mac);
            if (!normalized) throw ConfigError("config.protected: \"" + mac + "\" is not a MAC address");
            config.protected_macs.push_back(*normalized);
        }

        if (auto assignments = root.find("assignments"); assignments != root.end() && !assignments->is_null()) {
            if (!assignments->is_object()) throw ConfigError("config.assignments: must be an object of mac -> group");
            for (auto it = assignments->begin(); it != assignments->end(); ++it) {
                auto normalized = normalize_mac(it.key());
                if (!normalized) throw ConfigError("config.assignments: \"" + it.key() + "\" is not a MAC address");
                if (!it->is_string() || !config.group(it->get<std::string>()))
                    throw ConfigError("config.assignments." + it.key() + ": must name a listed group");
                config.assignments[*normalized] = it->get<std::string>();
            }
        }
        return config;
    }

    json Config::to_json() const {
        json groups_json = json::array();
        for (const auto& s: groups) {
            json item = {{"name", s.name}, {"privileged", s.privileged}};
            if (!s.description.empty()) item["description"] = s.description;
            if (!s.pihole_group.empty()) item["pihole_group"] = s.pihole_group;
            groups_json.push_back(std::move(item));
        }
        json rules_json = json::array();
        for (const auto& r: rules) {
            json match;
            auto put = [&](const char* key, const std::string& value) { if (!value.empty()) match[key] = value; };
            put("vendor", r.match.vendor);
            put("family", r.match.family);
            put("type", r.match.type);
            put("os", r.match.os);
            put("hostname", r.match.hostname);
            put("vci", r.match.vci);
            put("mac_prefix", r.match.mac_prefix);
            rules_json.push_back({{"name", r.name}, {"group", r.group}, {"priority", r.priority}, {"match", match}});
        }
        json networks_json = json::array();
        for (const auto& n: networks) {
            json slices = json::array();
            for (const auto& sl: n.slices) slices.push_back({{"group", sl.group}, {"cidr", sl.cidr}});
            networks_json.push_back({{"interface", n.interface}, {"mode", std::string(fph::to_string(n.mode))}, {"group", n.group},
                                     {"slices", slices}, {"manage_reservations", n.manage_reservations}});
        }
        json pihole_json = {{"url", pihole.url}, {"name", pihole.name}, {"timeout_ms", pihole.timeout_ms}};
        if (!pihole.ca_bundle.empty()) pihole_json["ca_bundle"] = pihole.ca_bundle;
        return {{"enabled", enabled}, {"profile", profile}, {"vdom", vdom}, {"prefix", prefix}, {"interfaces", interfaces},
                {"networks", networks_json}, {"pihole", pihole_json}, {"daemon", daemon},
                {"default_group", default_group}, {"groups", groups_json}, {"rules", rules_json},
                {"protected", protected_macs}, {"assignments", assignments}, {"retire_after_days", retire_after_days},
                {"native_rule_priority", native_rule_priority}, {"adopt_existing", adopt_existing},
                {"max_changes", max_changes}};
    }

    const DeviceGroup* Config::group(std::string_view name) const {
        for (const auto& s: groups)
            if (s.name == name) return &s;
        return nullptr;
    }

    const Network* Config::network(std::string_view interface) const {
        for (const auto& n: networks)
            if (n.interface == interface) return &n;
        return nullptr;
    }

    bool Config::is_protected(std::string_view mac) const {
        return std::ranges::find(protected_macs, mac) != protected_macs.end();
    }

    std::size_t Config::group_rank(std::string_view name) const {
        for (std::size_t i = 0; i < groups.size(); ++i)
            if (groups[i].name == name) return i;
        return std::string::npos;
    }

    Config load_config(const std::filesystem::path& path) {
        std::ifstream in(path);
        if (!in)
            throw ConfigError(std::format("no configuration at {} (run `forti-pihole init` to write a starting one)",
                                          path.string()));
        std::stringstream buffer;
        buffer << in.rdbuf();
        json parsed = json::parse(buffer.str(), nullptr, false);
        if (parsed.is_discarded()) throw ConfigError(std::format("{}: not valid JSON", path.string()));
        return Config::from_json(parsed);
    }

    json example_config() {
        // The groups mirror the operator's planning table; subnets are documentation until subnet
        // assignment is proven. Rules only target non-privileged groups (enforced by from_json).
        return json::parse(R"json({
  "$comment": "forti-pihole configuration. Groups are FortiGate address groups <prefix>grp-<name> (edit membership in the FortiGate GUI) mapped to Pi-hole groups. Nothing is written until enabled is true.",
  "enabled": false,
  "profile": "",
  "prefix": "fp-",
  "pihole": {"url": "", "name": "default"},
  "networks": [
    {"interface": "internal", "mode": "observe", "group": "default", "slices": [], "manage_reservations": false}
  ],
  "default_group": "default",
  "groups": [
    {"name": "trusted", "description": "The operator's own devices", "privileged": true},
    {"name": "work", "description": "Work computers", "privileged": true},
    {"name": "tvs", "description": "TVs and streaming sticks"},
    {"name": "iot_trusted", "description": "IoT devices with a known, needed cloud"},
    {"name": "iot_untrusted", "description": "Commodity IoT (plugs, bulbs)"},
    {"name": "default", "description": "Everything not yet classified"}
  ],
  "rules": [
    {"name": "kasa-plugs", "group": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}},
    {"name": "hue", "group": "iot_untrusted", "match": {"vendor": "Philips", "family": "Hue"}},
    {"name": "fire-tv", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}},
    {"name": "smart-tvs", "group": "tvs", "match": {"type": "Television"}},
    {"name": "ring", "group": "iot_trusted", "match": {"vendor": "Ring"}},
    {"name": "rain-bird", "group": "iot_trusted", "match": {"vendor": "Rain Bird"}},
    {"name": "myq", "group": "iot_trusted", "match": {"vendor": "Chamberlain"}}
  ],
  "protected": [],
  "assignments": {},
  "retire_after_days": 30,
  "adopt_existing": true,
  "max_changes": 50
})json");
    }

}  // namespace fph
