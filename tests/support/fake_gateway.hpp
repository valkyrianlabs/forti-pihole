//
// An in-memory FortiGate behind the Gateway interface: the engine's request/result contract, a
// device inventory, address objects and groups, policies, and plan/apply with the three profile
// modes. Fixture MACs come from the IANA documentation range (00:00:5e:00:53:xx) or are randomized
// (02:...), addresses from RFC 5737; nothing here resembles a real network.
//

#ifndef FORTI_PIHOLE_TESTS_FAKE_GATEWAY_HPP
#define FORTI_PIHOLE_TESTS_FAKE_GATEWAY_HPP

#include <gateway.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <format>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fph::test {

    using json = nlohmann::json;

    inline json device(const std::string& mac, const std::string& ip, json extra = json::object()) {
        json d = {{"mac", mac}, {"ipv4_address", ip}, {"detected_interface", "internal"}, {"is_online", true},
                  {"last_seen", 1'800'000'000}, {"online_interfaces", json::array({"internal"})}};
        for (auto it = extra.begin(); it != extra.end(); ++it) d[it.key()] = it.value();
        return d;
    }

    inline json mac_address(const std::string& name, const std::string& mac, const std::string& comment = "") {
        return {{"name", name}, {"type", "mac"}, {"sub-type", "sdn"}, {"comment", comment}, {"macaddr", json::array({{{"macaddr", mac}}})}};
    }

    inline json addrgrp(const std::string& name, std::vector<std::string> members, const std::string& comment = "") {
        json m = json::array();
        for (const auto& n: members) m.push_back({{"name", n}});
        return {{"name", name}, {"member", m}, {"comment", comment}, {"exclude", "disable"}, {"exclude-member", json::array()}};
    }

    class FakeGateway final : public Gateway {
    public:
        std::string mode = "autonomous";   // read-only | guarded | autonomous
        json devices = json::array();
        json leases = json::array();
        std::map<std::string, json> addresses;
        std::map<std::string, json> addrgrps;
        json policies = json::array();
        json services = json::parse(R"([
            {"name": "ALL", "protocol": "IP"},
            {"name": "DNS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"},
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443", "udp-portrange": ""},
            {"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80", "udp-portrange": ""}])");
        json service_groups = json::parse(R"([{"name": "Web Access", "member": [{"name": "DNS"}, {"name": "HTTP"}, {"name": "HTTPS"}]}])");
        json interfaces = json::parse(R"([
            {"name": "internal", "role": "lan", "ip": "192.0.2.1 255.255.255.0", "secondaryip": []},
            {"name": "internal1", "role": "lan", "ip": "198.51.100.1 255.255.255.0", "secondaryip": []},
            {"name": "wan1", "role": "wan", "ip": "203.0.113.2 255.255.255.0", "secondaryip": []}])");
        json dhcp = json::parse(R"([{"id": 1, "interface": "internal", "default-gateway": "192.0.2.1", "netmask": "255.255.255.0",
                                     "dns-service": "specify", "dns-server1": "198.51.100.2"}])");

        json vips = json::array();

        // Recorded traffic.
        std::vector<json> plans;            // every plan request's operations
        std::vector<std::string> applied;   // plan ids executed
        std::set<std::string> approved;     // guarded: plan ids a person approved
        bool fail_reads = false;
        int next_plan = 1;
        std::map<std::string, json> stored;   // plan id -> operations

        json read(const json& request) override {
            if (fail_reads) return {{"ok", false}, {"error", {{"code", "connection"}, {"message", "scripted read failure"}}}};
            auto resource = request.value("resource", std::string());
            auto list = [](const json& items) { return json{{"ok", true}, {"data", items}, {"meta", json::object()}}; };
            auto values = [](const std::map<std::string, json>& map) {
                json out = json::array();
                for (const auto& [k, v]: map) out.push_back(v);
                return out;
            };
            if (resource == "monitor/user/device/query") return list(devices);
            if (resource == "monitor/system/dhcp") return list(leases);
            if (resource == "firewall/address") return list(values(addresses));
            if (resource == "firewall/addrgrp") return list(values(addrgrps));
            if (resource == "firewall/policy") return list(policies);
            if (resource == "firewall.service/custom") return list(services);
            if (resource == "firewall.service/group") return list(service_groups);
            if (resource == "system/interface") return list(interfaces);
            if (resource == "system.dhcp/server") return list(dhcp);
            if (resource == "firewall/vip") return list(vips);
            if (resource == "monitor/firewall/address-dynamic") {
                auto name = request["params"].value("mkey", std::string());
                json addrs = json::array();
                if (auto it = addresses.find(name); it != addresses.end()) {
                    auto vendor = it->second.value("hw-vendor", std::string());
                    for (const auto& d: devices)
                        if (!vendor.empty() && d.value("hardware_vendor", std::string()) == vendor) addrs.push_back(d["mac"]);
                }
                return {{"ok", true}, {"data", {{name, {{"addrs", addrs}, {"addrs_count", addrs.size()}}}}}};
            }
            return {{"ok", false}, {"error", {{"code", "unknown_resource"}, {"message", "fake: " + resource}}}};
        }

        // Called after a lease revoke with the revoked IP: tests simulate the device renewing.
        std::function<void(const std::string& ip)> on_revoke;
        bool approve_everything = false;

        json plan(const json& request) override {
            plans.push_back(request["operations"]);
            auto id = std::format("20370101-000000-{:06x}", next_plan++);
            stored[id] = request["operations"];
            return {{"ok", true}, {"data", {{"id", id}, {"summary", std::format("{} operation(s)", request["operations"].size())}, {"risk", "low"}}}};
        }

        json apply(const json& request) override {
            auto id = request.value("plan_id", std::string());
            auto it = stored.find(id);
            if (it == stored.end()) return {{"ok", false}, {"error", {{"code", "not_found"}, {"message", "no such plan"}}}};
            if (mode == "read-only") return {{"ok", false}, {"error", {{"code", "policy_denied"}, {"message", "read-only"}}}};
            if (mode == "guarded" && !approved.contains(id))
                return {{"ok", false}, {"error", {{"code", "approval_required"}, {"message", "approve it"}}}};
            if (std::ranges::find(applied, id) != applied.end())
                return {{"ok", false}, {"error", {{"code", "usage"}, {"message", "already applied"}}}};
            json record = json::array();
            json inverse = json::array();
            for (const auto& op: it->second) {
                auto [rec, undo] = execute(op);
                record.push_back(rec);
                if (!undo.is_null()) inverse.insert(inverse.begin(), undo);
            }
            applied.push_back(id);
            json data = {{"status", "applied"}, {"operations", record}};
            if (!inverse.empty()) {
                stored[id + "-rb"] = inverse;
                data["rollback"] = {{"plan_id", id + "-rb"}};
            }
            return {{"ok", true}, {"data", data}};
        }

        json discover(const json&) override {
            return {{"ok", true}, {"data", {{"profile", "lab"}, {"mode", mode}}}};
        }

        // GUI-style edits by the "operator".
        void move_member(const std::string& from, const std::string& to, const std::string& member) {
            auto& f = addrgrps.at(from)["member"];
            for (auto i = f.begin(); i != f.end(); ++i)
                if ((*i)["name"] == member) {
                    f.erase(i);
                    break;
                }
            addrgrps.at(to)["member"].push_back({{"name", member}});
        }

        [[nodiscard]] std::vector<std::string> members(const std::string& name) const {
            std::vector<std::string> out;
            if (auto it = addrgrps.find(name); it != addrgrps.end())
                for (const auto& m: it->second["member"]) out.push_back(m["name"]);
            std::ranges::sort(out);
            return out;
        }

        json& reservations(std::uint64_t server) {
            for (auto& d: dhcp)
                if (d["id"] == server) {
                    if (!d.contains("reserved-address")) d["reserved-address"] = json::array();
                    return d["reserved-address"];
                }
            throw std::runtime_error("fake: no DHCP server");
        }

    private:
        static std::string text(const json& j) { return j.is_string() ? j.get<std::string>() : j.dump(); }

        // Executes one engine operation; returns the record entry and the inverse operation (or null).
        std::pair<json, json> execute(const json& op) {
            auto kind = op["op"].get<std::string>();
            auto resource = op["resource"].get<std::string>();
            json rec = {{"op", kind}, {"resource", resource}, {"status", "verified"}};
            if (resource == "monitor/system/dhcp/revoke") {
                for (const auto& ip: op["body"]["ip"]) {
                    json kept = json::array();
                    for (const auto& l: leases)
                        if (l["ip"] != ip) kept.push_back(l);
                    leases = kept;
                    if (on_revoke) on_revoke(ip.get<std::string>());
                }
                rec["status"] = "applied_unverified";
                return {rec, json()};
            }
            if (resource == "system.dhcp/server") {
                auto server = static_cast<std::uint64_t>(std::stoull(text(op["parent"])));
                auto& list = reservations(server);
                rec["parent"] = text(op["parent"]);
                rec["child"] = "reserved-address";
                if (kind == "create") {
                    auto entry = op["object"];
                    std::uint64_t next = 1;
                    for (const auto& r: list) next = std::max<std::uint64_t>(next, r["id"].get<std::uint64_t>() + 1);
                    if (!entry.contains("id") || entry["id"] == 0) entry["id"] = next;
                    if (!entry.contains("type")) entry["type"] = "mac";
                    list.push_back(entry);
                    rec["key"] = std::to_string(entry["id"].get<std::uint64_t>());
                    return {rec, json{{"op", "delete"}, {"resource", resource}, {"parent", rec["parent"]}, {"child", "reserved-address"}, {"key", rec["key"]}}};
                }
                auto key = static_cast<std::uint64_t>(std::stoull(text(op["key"])));
                rec["key"] = std::to_string(key);
                for (auto it = list.begin(); it != list.end(); ++it) {
                    if ((*it)["id"] != key) continue;
                    if (kind == "update") {
                        json before = json::object();
                        for (auto s = op["set"].begin(); s != op["set"].end(); ++s) {
                            before[s.key()] = it->contains(s.key()) ? (*it)[s.key()] : json("");
                            (*it)[s.key()] = s.value();
                        }
                        return {rec, json{{"op", "update"}, {"resource", resource}, {"parent", rec["parent"]}, {"child", "reserved-address"},
                                          {"key", rec["key"]}, {"set", before}}};
                    }
                    json removed = *it;
                    list.erase(it);
                    return {rec, json{{"op", "create"}, {"resource", resource}, {"parent", rec["parent"]}, {"child", "reserved-address"}, {"object", removed}}};
                }
                throw std::runtime_error("fake: no such reservation");
            }
            auto& table = resource == "firewall/addrgrp" ? addrgrps : addresses;
            if (kind == "create") {
                auto object = op["object"];
                table[object["name"]] = object;
                rec["key"] = object["name"];
                return {rec, json{{"op", "delete"}, {"resource", resource}, {"key", object["name"]}}};
            }
            if (kind == "update") {
                auto& object = table.at(op["key"]);
                json before = json::object();
                for (auto s = op["set"].begin(); s != op["set"].end(); ++s) {
                    before[s.key()] = object.contains(s.key()) ? object[s.key()] : json("");
                    object[s.key()] = s.value();
                }
                rec["key"] = op["key"];
                return {rec, json{{"op", "update"}, {"resource", resource}, {"key", op["key"]}, {"set", before}}};
            }
            json removed = table.at(op["key"]);
            table.erase(op["key"]);
            rec["key"] = op["key"];
            return {rec, json{{"op", "create"}, {"resource", resource}, {"object", removed}}};
        }
    };

}  // namespace fph::test

#endif  // FORTI_PIHOLE_TESTS_FAKE_GATEWAY_HPP
