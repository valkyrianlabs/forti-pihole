#include "connectivity.hpp"

#include "address_match.hpp"

#include <algorithm>
#include <charconv>
#include <format>

namespace fvm {

    namespace {

        constexpr std::string_view internet_probe = "1.1.1.1";

        bool listed(const std::vector<std::string>& list, std::string_view name) {
            return std::ranges::find(list, name) != list.end() || std::ranges::find(list, "any") != list.end();
        }

        bool any_covers(const Snapshot& snapshot, const std::vector<std::string>& names, const Endpoint& endpoint, bool negate) {
            bool hit = std::ranges::any_of(names, [&](const auto& n) { return address_covers(snapshot, n, endpoint); });
            return negate ? !hit : hit;
        }

        bool parse_port(std::string_view text, unsigned& value) {
            auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
            return error == std::errc() && end == text.data() + text.size();
        }

        bool service_covers_depth(const Snapshot& snapshot, std::string_view name, std::string_view protocol, unsigned port, int depth) {
            if (depth > 16) return false;
            if (name == "ALL") return true;
            auto it = snapshot.services.find(std::string(name));
            if (it == snapshot.services.end()) return false;
            const auto& service = it->second;
            if (service.group)
                return std::ranges::any_of(service.members, [&](const auto& m) {
                    return service_covers_depth(snapshot, m, protocol, port, depth + 1);
                });
            if (service.protocol == "IP") return service.name == "ALL";
            if (service.protocol != "TCP/UDP/SCTP" && !service.protocol.empty()) return false;
            return portrange_covers(protocol == "tcp" ? service.tcp : service.udp, port);
        }

        // The interface whose connected subnet holds `ip`; WAN-role interfaces when none does.
        std::vector<std::string> egress_for(const Snapshot& snapshot, std::string_view ip) {
            for (const auto& [name, interface]: snapshot.interfaces) {
                if (!interface.ip.empty() && interface.ip != "0.0.0.0 0.0.0.0" && in_subnet(ip, interface.ip)) return {name};
                for (const auto& secondary: interface.secondary)
                    if (in_subnet(ip, secondary)) return {name};
            }
            std::vector<std::string> wan;
            for (const auto& [name, interface]: snapshot.interfaces)
                if (interface.role == "wan") wan.push_back(name);
            return wan;
        }

        Verdict lookup(const Snapshot& snapshot, const Device& device, std::string_view dst_ip, std::string_view protocol,
                       unsigned port) {
            Endpoint source{device.mac, device.ip};
            Endpoint destination{{}, std::string(dst_ip)};
            auto egress = egress_for(snapshot, dst_ip);
            for (const auto& policy: snapshot.policies) {
                if (!policy.enabled || policy.needs_auth || policy.internet_service) continue;
                if (!listed(policy.srcintf, device.interface)) continue;
                if (!std::ranges::any_of(egress, [&](const auto& e) { return listed(policy.dstintf, e); })) continue;
                if (!any_covers(snapshot, policy.srcaddr, source, policy.srcaddr_negate)) continue;
                if (!any_covers(snapshot, policy.dstaddr, destination, policy.dstaddr_negate)) continue;
                bool service = std::ranges::any_of(policy.service, [&](const auto& s) { return service_covers(snapshot, s, protocol, port); });
                if (policy.service_negate) service = !service;
                if (!service) continue;
                return {policy.action == "accept" ? "accept" : "deny", policy.id, policy.name};
            }
            return {};
        }

    }  // namespace

    std::string Verdict::describe() const {
        if (action == "n/a") return "n/a";
        if (action == "none") return "no matching policy (implicit deny)";
        return std::format("{} by policy {}{}", action, policy, policy_name.empty() ? "" : " \"" + policy_name + "\"");
    }

    bool portrange_covers(std::string_view range, unsigned port) {
        // "53", "1-65535", "80 443", "443:1024-65535" (destination[:source]), space separated.
        while (!range.empty()) {
            auto space = range.find(' ');
            auto item = range.substr(0, space);
            range = space == std::string_view::npos ? std::string_view() : range.substr(space + 1);
            if (item.empty()) continue;
            auto destination = item.substr(0, item.find(':'));
            unsigned lo = 0, hi = 0;
            if (auto dash = destination.find('-'); dash != std::string_view::npos) {
                if (!parse_port(destination.substr(0, dash), lo) || !parse_port(destination.substr(dash + 1), hi)) continue;
            } else {
                if (!parse_port(destination, lo)) continue;
                hi = lo;
            }
            if (lo <= port && port <= hi) return true;
        }
        return false;
    }

    bool service_covers(const Snapshot& snapshot, std::string_view name, std::string_view protocol, unsigned port) {
        return service_covers_depth(snapshot, name, protocol, port, 0);
    }

    Reach evaluate(const Snapshot& snapshot, const Device& device) {
        Reach reach;
        reach.internet = lookup(snapshot, device, internet_probe, "tcp", 443);
        std::string dns;
        for (const auto& server: snapshot.dhcp)
            if (server.interface == device.interface) dns = server.dns1;
        if (dns.empty() || dns == "0.0.0.0") reach.dns.action = "n/a";
        else reach.dns = lookup(snapshot, device, dns, "udp", 53);
        return reach;
    }

    std::vector<Loss> compare(const Snapshot& before, const Snapshot& after) {
        std::vector<Loss> losses;
        for (const auto& device: before.devices) {
            if (!device.online) continue;
            auto a = evaluate(before, device), b = evaluate(after, device);
            if (a.internet.reaches() && !b.internet.reaches()) losses.push_back({device.mac, device.label(), "internet", a.internet, b.internet});
            if (a.dns.reaches() && !b.dns.reaches()) losses.push_back({device.mac, device.label(), "dns", a.dns, b.dns});
        }
        return losses;
    }

}  // namespace fvm
