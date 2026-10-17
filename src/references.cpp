#include "references.hpp"

#include "address_match.hpp"

#include <algorithm>
#include <format>
#include <functional>
#include <map>

namespace fph {

    namespace {

        // Every policy that reaches `object`, walking group membership outwards. Groups FortiOS
        // refuses to make cyclic; the depth bound only protects against a corrupt read.
        std::vector<PolicyUse> policies_reaching(const Snapshot& snapshot, const std::string& object) {
            std::vector<PolicyUse> out;
            std::function<void(const std::string&, std::vector<std::string>, int)> walk =
                    [&](const std::string& name, std::vector<std::string> via, int depth) {
                        if (depth > 16) return;
                        for (const auto& policy: snapshot.policies) {
                            bool src = std::ranges::find(policy.srcaddr, name) != policy.srcaddr.end();
                            bool dst = std::ranges::find(policy.dstaddr, name) != policy.dstaddr.end();
                            if (src) out.push_back({policy.id, policy.name, true, policy.enabled, via});
                            if (dst) out.push_back({policy.id, policy.name, false, policy.enabled, via});
                        }
                        for (const auto& [group_name, group]: snapshot.addrgrps)
                            if (std::ranges::find(group.members, name) != group.members.end()) {
                                auto next = via;
                                next.insert(next.begin(), group_name);
                                walk(group_name, next, depth + 1);
                            }
                    };
            walk(object, {}, 0);
            return out;
        }

        bool host_mask(std::string_view subnet) { return subnet.ends_with(" 255.255.255.255") || subnet.ends_with("/32"); }

        bool in_mapped(std::string_view ip, std::string_view mapped) {
            auto dash = mapped.find('-');
            if (dash == std::string_view::npos) return ip == mapped;
            auto value = parse_ipv4(ip), lo = parse_ipv4(mapped.substr(0, dash)), hi = parse_ipv4(mapped.substr(dash + 1));
            return value && lo && hi && *lo <= *value && *value <= *hi;
        }

    }  // namespace

    std::vector<IpReference> references_to(const Snapshot& snapshot, std::string_view ip) {
        std::vector<IpReference> out;
        if (!parse_ipv4(ip)) return out;
        std::string address(ip);

        for (const auto& [name, object]: snapshot.addresses) {
            IpReference ref;
            ref.name = name;
            ref.managed = object.managed();
            if (object.type == "ipmask" || object.type == "interface-subnet") {
                if (object.subnet.empty() || object.subnet == "0.0.0.0 0.0.0.0" || !in_subnet(address, object.subnet)) continue;
                ref.kind = host_mask(object.subnet) && object.type == "ipmask" ? "host" : "subnet";
                ref.detail = object.subnet;
            } else if (object.type == "iprange") {
                auto value = parse_ipv4(address), lo = parse_ipv4(object.start_ip), hi = parse_ipv4(object.end_ip);
                if (!value || !lo || !hi || *value < *lo || *value > *hi) continue;
                ref.kind = *lo == *hi ? "host" : "range";
                ref.detail = object.start_ip + "-" + object.end_ip;
            } else continue;
            ref.policies = policies_reaching(snapshot, name);
            out.push_back(std::move(ref));
        }

        for (const auto& vip: snapshot.vips)
            for (const auto& mapped: vip.mapped)
                if (in_mapped(address, mapped)) {
                    IpReference ref{"vip", vip.name, std::format("{} -> {}", vip.extintf, mapped), false, {}};
                    for (const auto& policy: snapshot.policies)
                        if (std::ranges::find(policy.dstaddr, vip.name) != policy.dstaddr.end())
                            ref.policies.push_back({policy.id, policy.name, false, policy.enabled, {}});
                    out.push_back(std::move(ref));
                }

        for (const auto& server: snapshot.dhcp)
            for (const auto& r: server.reservations)
                if (r.ip == address)
                    out.push_back({"reservation", std::format("dhcp {} reservation {}", server.id, r.id), r.mac, r.managed(), {}});

        for (const auto& lease: snapshot.leases)
            if (lease.ip == address) out.push_back({"lease", "lease", lease.mac, false, {}});

        // Hosts first: they are what a migration has to act on.
        std::ranges::stable_sort(out, [](const auto& a, const auto& b) { return a.kind == "host" && b.kind != "host"; });
        return out;
    }

    std::vector<const IpReference*> privileged_hosts(const std::vector<IpReference>& references) {
        std::vector<const IpReference*> out;
        for (const auto& ref: references)
            if (ref.kind == "host" && std::ranges::any_of(ref.policies, [](const PolicyUse& p) { return p.enabled && p.source; }))
                out.push_back(&ref);
        return out;
    }

}  // namespace fph
