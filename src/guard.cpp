#include "guard.hpp"

#include <array>
#include <format>

namespace fph {

    using json = nlohmann::json;

    namespace {

        constexpr std::array writable = {std::string_view("firewall/address"), std::string_view("firewall/addrgrp")};

        bool is_writable(std::string_view resource) {
            if (resource.starts_with("cmdb/")) resource.remove_prefix(5);
            for (auto w: writable)
                if (resource == w) return true;
            return false;
        }

        std::string percent_decode(std::string_view text) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            std::string out;
            for (std::size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 && hex(text[i + 2]) >= 0) {
                    out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2]));
                    i += 2;
                } else out += text[i];
            }
            return out;
        }

        bool has_marker(const json& object) {
            auto it = object.find("comment");
            return it != object.end() && it->is_string() && it->get<std::string>().find(marker) != std::string::npos;
        }

        bool has_marker_in(const json& object, const char* key) {
            auto it = object.find(key);
            return it != object.end() && it->is_string() && it->get<std::string>().find(marker) != std::string::npos;
        }

        bool parse_id(std::string_view text, std::uint64_t& value) {
            if (text.empty() || text.size() > 10) return false;
            value = 0;
            for (char c: text) {
                if (c < '0' || c > '9') return false;
                value = value * 10 + static_cast<std::uint64_t>(c - '0');
            }
            return true;
        }

        // Single reservation entries on permitted servers (engine child operations).
        void check_reservation_op(const json& op, const std::string& where, const Snapshot& snapshot, const WritePermits& permits) {
            auto kind = op.value("op", std::string());
            if (op.value("child", std::string()) != "reserved-address")
                throw GuardViolation(where + ": only single reserved-address entries of a DHCP server may be written");
            std::uint64_t server = 0;
            auto parent = op.contains("parent") ? (op["parent"].is_string() ? op["parent"].get<std::string>() : op["parent"].dump()) : std::string();
            if (!parse_id(parent, server) || !permits.dhcp_servers.contains(server))
                throw GuardViolation(std::format("{}: reservations on DHCP server {} are not permitted now", where, parent));
            if (kind == "create") {
                if (!has_marker_in(op.value("object", json::object()), "description"))
                    throw GuardViolation(where + ": a new reservation must carry the ownership marker");
                return;
            }
            if (kind != "update" && kind != "delete") throw GuardViolation(std::format("{}: operation \"{}\" is not allowed", where, kind));
            std::uint64_t entry = 0;
            auto key = op.contains("key") ? (op["key"].is_string() ? op["key"].get<std::string>() : op["key"].dump()) : std::string();
            if (!parse_id(key, entry) || !permits.reservations.contains({server, entry}))
                throw GuardViolation(std::format("{}: reservation {} on server {} is not permitted", where, key, server));
            if (kind == "update") {
                const auto& set = op.value("set", json::object());
                if (set.contains("description") && !has_marker_in(set, "description"))
                    throw GuardViolation(where + ": an update must keep the ownership marker in the description");
                if (set.contains("mac")) throw GuardViolation(where + ": a reservation's MAC never changes (that would hand it to another device)");
            }
            (void) snapshot;
        }

    }  // namespace

    void check_operations(const json& operations, const Snapshot& snapshot, const Config& config, const WritePermits& permits) {
        if (!operations.is_array()) throw GuardViolation("operations must be an array");
        for (std::size_t i = 0; i < operations.size(); ++i) {
            const auto& op = operations[i];
            auto where = std::format("operation {}", i);
            auto kind = op.value("op", std::string());
            auto resource = op.value("resource", std::string());
            if (resource == "system.dhcp/server" || resource == "cmdb/system.dhcp/server") {
                check_reservation_op(op, where, snapshot, permits);
                continue;
            }
            if (resource.starts_with("system/automation-")) {
                if (!permits.automation) throw GuardViolation(where + ": automation objects only inside forti-pihole events install|remove");
                if (resource != "system/automation-trigger" && resource != "system/automation-action" && resource != "system/automation-stitch")
                    throw GuardViolation(where + ": " + resource + " is not writable");
                auto name = kind == "create" ? op.value("object", json::object()).value("name", std::string()) : op.value("key", std::string());
                if (!name.starts_with(config.prefix)) throw GuardViolation(std::format("{}: {} lacks the prefix {}", where, name, config.prefix));
                if (kind == "create" && !has_marker_in(op.value("object", json::object()), "description"))
                    throw GuardViolation(where + ": automation objects must carry the ownership marker");
                if (kind != "create" && kind != "delete") throw GuardViolation(where + ": only create and delete of automation objects");
                continue;
            }
            if (resource == "monitor/system/dhcp/revoke") {
                if (kind != "action") throw GuardViolation(where + ": revoke is an action");
                const auto& ips = op.value("body", json::object()).value("ip", json::array());
                if (!ips.is_array() || ips.empty()) throw GuardViolation(where + ": revoke must list the addresses");
                for (const auto& ip: ips)
                    if (!ip.is_string() || !permits.revoke_ips.contains(ip.get<std::string>()))
                        throw GuardViolation(std::format("{}: revoking {} is not permitted", where, ip.dump()));
                continue;
            }
            if ((resource == "firewall/address" || resource == "cmdb/firewall/address") && kind == "update" &&
                permits.address_objects.contains(op.value("key", std::string()))) {
                // An adopted host object following its device: only its address changes.
                const auto& set = op.value("set", json::object());
                if (set.size() != 1 || !set.contains("subnet") || op.contains("clear"))
                    throw GuardViolation(std::format("{}: an adopted object may only have its subnet changed", where));
                continue;
            }
            if (!is_writable(resource)) throw GuardViolation(std::format("{}: {} is not a resource forti-pihole may write", where, resource));
            bool group = resource.ends_with("addrgrp");
            if (kind == "create") {
                const auto& object = op.value("object", json::object());
                auto name = object.value("name", std::string());
                if (!name.starts_with(config.prefix)) throw GuardViolation(std::format("{}: {} lacks the prefix {}", where, name, config.prefix));
                if (!has_marker(object)) throw GuardViolation(std::format("{}: {} is created without the ownership marker", where, name));
                if (group ? snapshot.addrgrp(name) != nullptr : snapshot.address(name) != nullptr)
                    throw GuardViolation(std::format("{}: {} already exists", where, name));
            } else if (kind == "update" || kind == "delete") {
                auto key = op.value("key", std::string());
                if (!key.starts_with(config.prefix)) throw GuardViolation(std::format("{}: {} lacks the prefix {}", where, key, config.prefix));
                bool managed = group ? (snapshot.addrgrp(key) && snapshot.addrgrp(key)->managed())
                                     : (snapshot.address(key) && snapshot.address(key)->managed());
                if (!managed) throw GuardViolation(std::format("{}: {} does not carry the ownership marker", where, key));
                if (kind == "update") {
                    // The marker must survive: a comment change has to keep it, and nothing may clear it.
                    const auto& set = op.value("set", json::object());
                    if (set.contains("comment") && !has_marker(set))
                        throw GuardViolation(std::format("{}: update would remove the ownership marker from {}", where, key));
                    for (const auto& cleared: op.value("clear", json::array()))
                        if (cleared == "comment" || cleared == "name")
                            throw GuardViolation(std::format("{}: may not clear {} on {}", where, cleared.get<std::string>(), key));
                    if (set.contains("name")) throw GuardViolation(std::format("{}: renames are not allowed ({})", where, key));
                }
            } else throw GuardViolation(std::format("{}: operation \"{}\" is not allowed", where, kind));
        }
    }

    std::string refuse_write(fortiapi::Method method, std::string_view url, std::string_view body, std::string_view prefix,
                             const WritePermits& permits) {
        if (method == fortiapi::Method::Get) return {};
        auto api = url.find("/api/v2/");
        if (api == std::string_view::npos) return "not a FortiOS API URL";
        auto path = url.substr(api + 8);
        path = path.substr(0, path.find('?'));

        // Permitted DHCP reservation entries: cmdb/system.dhcp/server/<id>/reserved-address[/<entry>].
        if (path.starts_with("cmdb/system.dhcp/server/")) {
            auto rest = path.substr(24);
            auto slash = rest.find('/');
            if (slash == std::string_view::npos) return std::format("{} of a whole DHCP server", fortiapi::to_string(method));
            std::uint64_t server = 0;
            if (!parse_id(rest.substr(0, slash), server)) return "DHCP server key is not a number";
            rest = rest.substr(slash + 1);
            constexpr std::string_view child = "reserved-address";
            if (!rest.starts_with(child)) return std::format("DHCP server attribute other than {}", child);
            rest = rest.substr(child.size());
            if (!permits.dhcp_servers.contains(server)) return std::format("reservations on DHCP server {} are not permitted now", server);
            if (rest.empty()) {
                if (method != fortiapi::Method::Post) return "only single reservation entries may be written";
                auto parsed = json::parse(body, nullptr, false);
                if (!parsed.is_object() || !has_marker_in(parsed, "description")) return "a new reservation must carry the ownership marker";
                return {};
            }
            if (rest.front() != '/' || rest.find('/', 1) != std::string_view::npos) return std::format("nested path {}", path);
            std::uint64_t entry = 0;
            if (!parse_id(rest.substr(1), entry)) return "reservation key is not a number";
            if (method == fortiapi::Method::Post) return "POST to a reservation entry path";
            if (!permits.reservations.contains({server, entry})) return std::format("reservation {} on server {} is not permitted", entry, server);
            return {};
        }
        for (std::string_view table: {"cmdb/system/automation-trigger", "cmdb/system/automation-action", "cmdb/system/automation-stitch"}) {
            if (path != table && !path.starts_with(std::string(table) + "/")) continue;
            if (!permits.automation) return "automation objects are written only by forti-pihole events install|remove";
            if (path == table) {
                if (method != fortiapi::Method::Post) return "only creates on an automation table";
                auto parsed = json::parse(body, nullptr, false);
                auto name = parsed.is_object() ? parsed.value("name", std::string()) : std::string();
                if (!name.starts_with(prefix) || !has_marker_in(parsed, "description")) return "automation object without the prefix or marker";
                return {};
            }
            auto rest = path.substr(table.size() + 1);
            if (rest.find('/') != std::string_view::npos || method != fortiapi::Method::Delete || !percent_decode(rest).starts_with(prefix))
                return "only deletes of forti-pihole's own automation objects";
            return {};
        }
        if (path == "monitor/system/dhcp/revoke") {
            if (method != fortiapi::Method::Post) return "revoke is a POST";
            auto parsed = json::parse(body, nullptr, false);
            const auto ips = parsed.is_object() ? parsed.value("ip", json::array()) : json::array();
            if (!ips.is_array() || ips.empty()) return "revoke without addresses";
            for (const auto& ip: ips)
                if (!ip.is_string() || !permits.revoke_ips.contains(ip.get<std::string>())) return "revoke of an address that is not permitted";
            return {};
        }
        if (path.starts_with("cmdb/firewall/address/") && method == fortiapi::Method::Put) {
            auto rest = path.substr(22);
            if (rest.find('/') == std::string_view::npos && permits.address_objects.contains(percent_decode(rest))) {
                auto parsed = json::parse(body, nullptr, false);
                if (!parsed.is_object() || parsed.size() != 1 || !parsed.contains("subnet")) return "an adopted object may only have its subnet changed";
                return {};
            }
        }
        for (auto w: writable) {
            std::string collection = "cmdb/" + std::string(w);
            if (path == collection) {
                // A create names the object in its body.
                if (method != fortiapi::Method::Post) return std::format("{} on the whole collection {}", fortiapi::to_string(method), collection);
                auto parsed = json::parse(body, nullptr, false);
                auto name = parsed.is_object() ? parsed.value("name", std::string()) : std::string();
                if (!name.starts_with(prefix)) return std::format("create of \"{}\" in {} (not {}*)", name, collection, prefix);
                return {};
            }
            if (path.starts_with(collection + "/")) {
                auto rest = path.substr(collection.size() + 1);
                // Exactly one more path segment: the object. Child-table paths are not allowed here.
                if (rest.find('/') != std::string_view::npos) return std::format("nested path {}", path);
                auto name = percent_decode(rest);
                if (!name.starts_with(prefix)) return std::format("{} of \"{}\" (not {}*)", fortiapi::to_string(method), name, prefix);
                if (method == fortiapi::Method::Post) return std::format("POST to an object path {}", path);
                return {};
            }
        }
        return std::format("{} {} is outside forti-pihole's write allowlist", fortiapi::to_string(method), path);
    }

    fortiapi::HttpResponse GuardTransport::perform(const fortiapi::HttpRequest& request) {
        if (auto why = refuse_write(request.method, request.url, request.body, prefix_, *permits_); !why.empty())
            // Thrown before the inner transport sees the request: nothing reaches the device.
            throw GuardViolation("write guard refused a request: " + why);
        return inner_->perform(request);
    }

}  // namespace fph
