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

#include <format>
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
            for (const auto& op: it->second) execute(op);
            applied.push_back(id);
            return {{"ok", true}, {"data", {{"status", "applied"}, {"rollback", {{"plan_id", id + "-rb"}}}}}};
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

    private:
        void execute(const json& op) {
            auto kind = op["op"].get<std::string>();
            auto resource = op["resource"].get<std::string>();
            auto& table = resource == "firewall/addrgrp" ? addrgrps : addresses;
            if (kind == "create") {
                auto object = op["object"];
                table[object["name"]] = object;
            } else if (kind == "update") {
                auto& object = table.at(op["key"]);
                for (auto s = op["set"].begin(); s != op["set"].end(); ++s) object[s.key()] = s.value();
            } else if (kind == "delete") {
                table.erase(op["key"]);
            }
        }
    };

}  // namespace fph::test

#endif  // FORTI_PIHOLE_TESTS_FAKE_GATEWAY_HPP
