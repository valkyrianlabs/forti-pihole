#include "slicing.hpp"

#include "alloc/cidr.hpp"
#include "mac.hpp"
#include "pihole_sync.hpp"

#include <algorithm>
#include <format>
#include <map>

namespace fph {

    namespace {

        using alloc::Cidr;
        using alloc::Ipv4;

        // The device group a MAC is classified into (for occupancy: at home in its own slices).
        std::map<std::string, std::string> groups_by_mac(const Classification& classification) {
            std::map<std::string, std::string> out;
            for (const auto& d: classification.decisions)
                if (!d.group.empty()) out[d.device.mac] = d.group;
            return out;
        }

        std::optional<Cidr> subnet_of(const Interface& interface) {
            auto text = to_cidr(interface.ip);
            return text.empty() ? std::nullopt : Cidr::parse(text);
        }

        std::optional<Ipv4> ip_of(std::string_view text) { return alloc::parse_ipv4(text); }

    }  // namespace

    std::vector<std::string> complement_strings(const std::string& network, const std::vector<std::string>& slices) {
        auto parent = Cidr::parse(network);
        if (!parent) return {};
        std::vector<Cidr> cut;
        for (const auto& s: slices)
            if (auto c = Cidr::parse(s)) cut.push_back(*c);
        std::vector<std::string> out;
        for (const auto& c: alloc::complement(*parent, cut)) out.push_back(c.str());
        return out;
    }

    std::optional<alloc::PlanInput> plan_input(const Config& config, const Network& network, const Snapshot& snapshot,
                                               const Classification& classification) {
        const Interface* interface = snapshot.interface(network.interface);
        if (!interface) return std::nullopt;
        auto subnet = subnet_of(*interface);
        if (!subnet) return std::nullopt;

        alloc::PlanInput input;
        input.network = *subnet;
        auto by_mac = groups_by_mac(classification);
        auto group_of = [&](const std::string& mac) {
            auto it = by_mac.find(mac);
            return it == by_mac.end() ? std::string() : it->second;
        };

        if (auto gw = ip_of(interface->ip.substr(0, interface->ip.find(' ')))) input.interface_ips.push_back(*gw);
        for (const auto& secondary: interface->secondary)
            if (auto ip = ip_of(secondary.substr(0, secondary.find(' '))); ip && subnet->contains(*ip)) input.interface_ips.push_back(*ip);

        if (const DhcpServer* server = snapshot.dhcp_for(network.interface)) {
            int pool_id = 0;
            for (const auto& r: server->ranges) {
                ++pool_id;
                if (auto lo = ip_of(r.start), hi = ip_of(r.end); lo && hi && *lo <= *hi) input.pools.push_back({pool_id, {*lo, *hi}});
            }
            for (const auto& r: server->excludes)
                if (auto lo = ip_of(r.start), hi = ip_of(r.end); lo && hi && *lo <= *hi) input.excludes.push_back({*lo, *hi});
            for (const auto& r: server->reservations) {
                auto ip = ip_of(r.ip);
                if (!ip || !subnet->contains(*ip)) continue;
                // The label the operator knows: the address object for that MAC, else the reservation id.
                std::string label = std::format("reservation {}", r.id);
                for (const auto& [name, a]: snapshot.addresses)
                    if (a.type == "mac" && a.macs.size() == 1 && normalize_mac(a.macs.front()) == r.mac) label = name;
                input.occupancy.add({*ip, alloc::Use::reservation, label, r.mac, group_of(r.mac)});
            }
        }
        for (const auto& lease: snapshot.leases) {
            auto ip = ip_of(lease.ip);
            if (!ip || !subnet->contains(*ip)) continue;
            input.occupancy.add({*ip, alloc::Use::lease, lease.hostname.empty() ? lease.mac : lease.hostname, lease.mac, group_of(lease.mac)});
        }
        for (const auto& vip: snapshot.vips)
            for (const auto& mapped: vip.mapped) {
                auto range = alloc::Range::parse(mapped);
                if (!range) continue;
                for (Ipv4 ip = range->lo; subnet->contains(ip) && ip <= range->hi; ++ip) {
                    input.occupancy.add({ip, alloc::Use::vip, vip.name, {}, {}});
                    if (ip == range->hi) break;
                }
            }
        for (const auto& [name, a]: snapshot.addresses)
            if (a.type == "ipmask" && a.subnet.ends_with(" 255.255.255.255"))
                if (auto ip = ip_of(a.subnet.substr(0, a.subnet.find(' '))); ip && subnet->contains(*ip))
                    input.occupancy.add({*ip, alloc::Use::address_object, name, {}, {}});
        // Devices the inventory sees at an address no lease explains: statically configured.
        for (const auto& d: snapshot.devices) {
            if (d.interface != network.interface || d.ip.empty()) continue;
            bool leased = std::ranges::any_of(snapshot.leases, [&](const Lease& l) { return l.mac == d.mac && l.ip == d.ip; });
            if (leased) continue;
            if (auto ip = ip_of(d.ip); ip && subnet->contains(*ip))
                input.occupancy.add({*ip, alloc::Use::static_device, d.label(), d.mac, group_of(d.mac)});
        }

        for (const auto& s: network.slices)
            if (auto c = Cidr::parse(s.cidr)) input.existing[s.group].push_back(*c);

        // One request per group with members on this network (the network's own group needs no slice).
        std::map<std::string, std::uint64_t> members;
        for (const auto& d: classification.decisions)
            if (d.device.interface == network.interface && !d.group.empty() && d.group != network.group) ++members[d.group];
        for (const auto& [group, count]: members) {
            const DeviceGroup* g = config.group(group);
            if (!g || g->pihole_group.empty()) continue;   // nothing for Pi-hole to tell apart: no slice needed
            input.requests.push_back({group, count, 1.5, std::nullopt, std::nullopt});
        }
        return input;
    }

    SlicingPlan plan_slicing(const Config& config, const Snapshot& snapshot, const Classification& classification) {
        SlicingPlan plan;
        for (const auto& network: config.networks) {
            if (network.mode != Network::Mode::slices && network.mode != Network::Mode::hybrid) continue;
            const Interface* interface = snapshot.interface(network.interface);
            if (!interface) {
                plan.findings.push_back({"no-network", network.interface, {}, {}, "the FortiGate has no interface " + network.interface});
                continue;
            }
            const DhcpServer* server = snapshot.dhcp_for(network.interface);
            if (!server) {
                plan.findings.push_back({"no-dhcp", network.interface, {}, {}, "no enabled DHCP server on " + network.interface});
                continue;
            }
            auto input = plan_input(config, network, snapshot, classification);
            if (!input) continue;

            std::vector<alloc::Slice> slices;
            for (const auto& [group, cidrs]: input->existing)
                for (const auto& c: cidrs) slices.push_back({group, c, true});
            for (const auto& conflict: alloc::check(*input, slices))
                plan.findings.push_back({"conflict", network.interface, conflict.mac, conflict.label,
                                         std::format("{} {}: {}", alloc::conflict_kind_name(conflict.kind), conflict.slice.cidr.str(), conflict.detail)});

            auto occupancy = input->effective_occupancy();
            // Addresses handed out during this plan: two moves must not pick the same address.
            std::vector<Ipv4> taken;

            for (const auto& decision: classification.decisions) {
                const auto& d = decision.device;
                if (d.interface != network.interface || decision.keep) continue;
                std::vector<Cidr> own;
                if (auto it = input->existing.find(decision.group); it != input->existing.end()) own = it->second;

                const Reservation* reservation = nullptr;
                for (const auto& r: server->reservations)
                    if (r.mac == d.mac) reservation = &r;
                std::string current = reservation ? reservation->ip : d.ip;
                auto current_ip = ip_of(current);

                if (own.empty()) {
                    // No slice for its group here: it belongs in the shared range. Report it when it
                    // sits inside someone else's slice.
                    if (current_ip)
                        for (const auto& s: slices)
                            if (s.cidr.contains(*current_ip))
                                plan.findings.push_back({"foreign-in-slice", network.interface, d.mac, d.label(),
                                                         std::format("{} holds {} inside {}'s slice {}", d.label(), current, s.group, s.cidr.str())});
                    continue;
                }
                if (!current_ip) {
                    plan.findings.push_back({"no-address", network.interface, d.mac, d.label(), "no current address known; waits for a lease"});
                    continue;
                }

                SliceAction action;
                action.mac = d.mac;
                action.label = d.label();
                action.group = decision.group;
                action.interface = network.interface;
                action.from_ip = current;
                action.dhcp_server = server->id;
                if (reservation) {
                    action.reservation_id = reservation->id;
                    action.reservation_managed = reservation->managed();
                }
                const Cidr* home = nullptr;
                for (const auto& c: own)
                    if (c.contains(*current_ip)) home = &c;
                if (home) {
                    action.slice = home->str();
                    action.to_ip = current;
                    if (reservation && reservation->ip == current && reservation->action == "reserved") {
                        action.kind = "in-place";
                        action.why = "already reserved inside its slice";
                    } else {
                        action.kind = "reserve";
                        action.why = "inside its slice without a reservation: reserve the address it has";
                    }
                    plan.actions.push_back(std::move(action));
                    continue;
                }
                // A move: the first slice of its group with a free address.
                std::optional<Ipv4> target;
                for (const auto& c: own) {
                    auto occ = occupancy;
                    for (Ipv4 t: taken) occ.add({t, alloc::Use::reservation, "planned", "planned", {}});
                    target = alloc::pick_address(input->network, c, occ, std::nullopt, d.mac);
                    if (target) {
                        action.slice = c.str();
                        break;
                    }
                }
                if (!target) {
                    plan.findings.push_back({"slice-full", network.interface, d.mac, d.label(),
                                             std::format("no free address in {}'s slices for {}", decision.group, d.label())});
                    continue;
                }
                taken.push_back(*target);
                action.kind = "move";
                action.to_ip = alloc::format_ipv4(*target);
                action.why = std::format("{} -> {} (slice {} of {})", current, action.to_ip, action.slice, decision.group);
                plan.actions.push_back(std::move(action));
            }
        }
        return plan;
    }

}  // namespace fph
