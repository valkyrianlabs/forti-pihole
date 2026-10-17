#include "config.hpp"

#include "mac.hpp"

#include <algorithm>
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

        // Segment names become part of FortiOS object names (79 characters max for addresses).
        bool valid_segment_name(std::string_view name) {
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

    }  // namespace

    bool Match::empty() const {
        return vendor.empty() && family.empty() && type.empty() && os.empty() && hostname.empty() && vci.empty() &&
               mac_prefix.empty();
    }

    Config Config::from_json(const json& root) {
        allow_keys(root, {"profile", "vdom", "prefix", "interfaces", "default_segment", "segments", "rules", "protected",
                          "assignments", "retire_after_days", "native_rule_priority", "adopt_existing", "max_changes",
                          "$comment"},
                   "config");
        Config config;
        config.profile = text(root, "profile", "config");
        config.vdom = text(root, "vdom", "config");
        config.prefix = text(root, "prefix", "config", config.prefix);
        if (!valid_prefix(config.prefix)) throw ConfigError("config.prefix: 2-24 characters of [A-Za-z0-9_-]");
        config.interfaces = strings(root, "interfaces", "config", config.interfaces);
        if (config.interfaces.empty()) throw ConfigError("config.interfaces: list at least one interface");
        config.default_segment = text(root, "default_segment", "config", config.default_segment);
        config.retire_after_days = integer(root, "retire_after_days", "config", config.retire_after_days, 1, 3650);
        config.native_rule_priority = integer(root, "native_rule_priority", "config", config.native_rule_priority, 0, 10000);
        config.adopt_existing = boolean(root, "adopt_existing", "config", config.adopt_existing);
        config.max_changes = integer(root, "max_changes", "config", config.max_changes, 1, 1000);

        auto segments = root.find("segments");
        if (segments == root.end() || !segments->is_array() || segments->empty())
            throw ConfigError("config.segments: list at least one segment");
        std::set<std::string> names;
        for (std::size_t i = 0; i < segments->size(); ++i) {
            auto where = std::format("config.segments[{}]", i);
            const auto& item = (*segments)[i];
            allow_keys(item, {"name", "description", "privileged", "subnet"}, where);
            Segment segment;
            segment.name = text(item, "name", where);
            if (!valid_segment_name(segment.name)) throw ConfigError(where + ".name: 1-32 characters of [a-z0-9_]");
            if (!names.insert(segment.name).second) throw ConfigError(where + ".name: duplicate segment \"" + segment.name + "\"");
            segment.description = text(item, "description", where);
            segment.privileged = boolean(item, "privileged", where, false);
            segment.subnet = text(item, "subnet", where);
            if (!segment.subnet.empty() && !valid_cidr(segment.subnet)) throw ConfigError(where + ".subnet: not an IPv4 CIDR");
            config.segments.push_back(std::move(segment));
        }
        const Segment* fallback = config.segment(config.default_segment);
        if (!fallback) throw ConfigError("config.default_segment: \"" + config.default_segment + "\" is not a listed segment");
        // Unknown devices land in the default segment, so it must never grant privileged access.
        if (fallback->privileged) throw ConfigError("config.default_segment: the default segment cannot be privileged");

        if (auto rules = root.find("rules"); rules != root.end() && !rules->is_null()) {
            if (!rules->is_array()) throw ConfigError("config.rules: must be an array");
            for (std::size_t i = 0; i < rules->size(); ++i) {
                auto where = std::format("config.rules[{}]", i);
                const auto& item = (*rules)[i];
                allow_keys(item, {"name", "segment", "priority", "match"}, where);
                Rule rule;
                rule.segment = text(item, "segment", where);
                const Segment* target = config.segment(rule.segment);
                if (!target) throw ConfigError(where + ".segment: \"" + rule.segment + "\" is not a listed segment");
                if (target->privileged)
                    throw ConfigError(where + ".segment: \"" + rule.segment +
                                      "\" is privileged; privileged segments are only entered by explicit assignment");
                rule.name = text(item, "name", where, std::format("{}#{}", rule.segment, i));
                rule.priority = integer(item, "priority", where, rule.priority, 0, 10000);
                auto match = item.find("match");
                if (match == item.end()) throw ConfigError(where + ".match: required");
                rule.match = parse_match(*match, where + ".match");
                config.rules.push_back(std::move(rule));
            }
        }

        for (const auto& mac: strings(root, "protected", "config", {})) {
            auto normalized = normalize_mac(mac);
            if (!normalized) throw ConfigError("config.protected: \"" + mac + "\" is not a MAC address");
            config.protected_macs.push_back(*normalized);
        }

        if (auto assignments = root.find("assignments"); assignments != root.end() && !assignments->is_null()) {
            if (!assignments->is_object()) throw ConfigError("config.assignments: must be an object of mac -> segment");
            for (auto it = assignments->begin(); it != assignments->end(); ++it) {
                auto normalized = normalize_mac(it.key());
                if (!normalized) throw ConfigError("config.assignments: \"" + it.key() + "\" is not a MAC address");
                if (!it->is_string() || !config.segment(it->get<std::string>()))
                    throw ConfigError("config.assignments." + it.key() + ": must name a listed segment");
                config.assignments[*normalized] = it->get<std::string>();
            }
        }
        return config;
    }

    json Config::to_json() const {
        json segments_json = json::array();
        for (const auto& s: segments) {
            json item = {{"name", s.name}, {"privileged", s.privileged}};
            if (!s.description.empty()) item["description"] = s.description;
            if (!s.subnet.empty()) item["subnet"] = s.subnet;
            segments_json.push_back(std::move(item));
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
            rules_json.push_back({{"name", r.name}, {"segment", r.segment}, {"priority", r.priority}, {"match", match}});
        }
        return {{"profile", profile}, {"vdom", vdom}, {"prefix", prefix}, {"interfaces", interfaces},
                {"default_segment", default_segment}, {"segments", segments_json}, {"rules", rules_json},
                {"protected", protected_macs}, {"assignments", assignments}, {"retire_after_days", retire_after_days},
                {"native_rule_priority", native_rule_priority}, {"adopt_existing", adopt_existing},
                {"max_changes", max_changes}};
    }

    const Segment* Config::segment(std::string_view name) const {
        for (const auto& s: segments)
            if (s.name == name) return &s;
        return nullptr;
    }

    bool Config::is_protected(std::string_view mac) const {
        return std::ranges::find(protected_macs, mac) != protected_macs.end();
    }

    std::size_t Config::segment_rank(std::string_view name) const {
        for (std::size_t i = 0; i < segments.size(); ++i)
            if (segments[i].name == name) return i;
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
        // The segments mirror the operator's planning table; subnets are documentation until subnet
        // assignment is proven. Rules only target non-privileged segments (enforced by from_json).
        return json::parse(R"json({
  "$comment": "forti-pihole configuration. Segments are FortiGate address groups <prefix>seg-<name>; edit membership in the FortiGate GUI.",
  "profile": "",
  "prefix": "fp-",
  "interfaces": ["internal"],
  "default_segment": "default",
  "segments": [
    {"name": "owner", "description": "Owner's own devices", "privileged": true, "subnet": "192.168.60.0/24"},
    {"name": "work", "description": "Work computers", "privileged": true, "subnet": "192.168.50.0/24"},
    {"name": "tvs", "description": "TVs and streaming sticks", "subnet": "192.168.40.0/24"},
    {"name": "iot_trusted", "description": "IoT devices with a known, needed cloud", "subnet": "192.168.31.0/24"},
    {"name": "iot_untrusted", "description": "Commodity IoT (plugs, bulbs)", "subnet": "192.168.30.0/24"},
    {"name": "default", "description": "Everything not yet classified (the existing 192.168.1.0/24)"}
  ],
  "rules": [
    {"name": "kasa-plugs", "segment": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}},
    {"name": "hue", "segment": "iot_untrusted", "match": {"vendor": "Philips", "family": "Hue"}},
    {"name": "fire-tv", "segment": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}},
    {"name": "smart-tvs", "segment": "tvs", "match": {"type": "Television"}},
    {"name": "ring", "segment": "iot_trusted", "match": {"vendor": "Ring"}},
    {"name": "rain-bird", "segment": "iot_trusted", "match": {"vendor": "Rain Bird"}},
    {"name": "myq", "segment": "iot_trusted", "match": {"vendor": "Chamberlain"}}
  ],
  "protected": [],
  "assignments": {},
  "retire_after_days": 30,
  "adopt_existing": true,
  "max_changes": 50
})json");
    }

}  // namespace fph
