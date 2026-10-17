#include "pihole_sync.hpp"

#include "address_match.hpp"
#include "mac.hpp"

#include <algorithm>
#include <bit>
#include <format>
#include <set>

namespace fph {

    namespace {

        std::string format_ip(std::uint32_t v) {
            return std::format("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
        }

        // "a.b.c.d/n" -> (network, prefix); nullopt when not a canonical IPv4 CIDR or a bare IPv4.
        std::optional<std::pair<std::uint32_t, int>> cidr_of(std::string_view text) {
            auto slash = text.find('/');
            auto ip = parse_ipv4(text.substr(0, slash));
            if (!ip) return std::nullopt;
            int prefix = 32;
            if (slash != std::string_view::npos) {
                auto tail = text.substr(slash + 1);
                if (tail.empty() || tail.size() > 2 || !std::ranges::all_of(tail, [](char c) { return c >= '0' && c <= '9'; })) return std::nullopt;
                prefix = std::stoi(std::string(tail));
                if (prefix > 32) return std::nullopt;
            }
            return std::pair{*ip, prefix};
        }

        std::uint32_t mask_of(int prefix) { return prefix == 0 ? 0 : ~std::uint32_t(0) << (32 - prefix); }

        bool overlaps(std::pair<std::uint32_t, int> a, std::pair<std::uint32_t, int> b) {
            auto m = mask_of(std::min(a.second, b.second));
            return (a.first & m) == (b.first & m);
        }

        bool inside(std::pair<std::uint32_t, int> inner, std::pair<std::uint32_t, int> outer) {
            return inner.second >= outer.second && (inner.first & mask_of(outer.second)) == (outer.first & mask_of(outer.second));
        }

        std::string normalized_cidr(std::string_view text) {
            auto c = cidr_of(text);
            if (!c) return {};
            return std::format("{}/{}", format_ip(c->first & mask_of(c->second)), c->second);
        }

    }  // namespace

    bool PiholeClientInfo::managed() const { return comment.find(marker) != std::string::npos; }

    const PiholeGroupInfo* PiholeView::group(std::string_view name) const {
        for (const auto& g: groups)
            if (g.name == name) return &g;
        return nullptr;
    }

    const PiholeGroupInfo* PiholeView::group(int id) const {
        for (const auto& g: groups)
            if (g.id == id) return &g;
        return nullptr;
    }

    std::string to_cidr(std::string_view ip_and_mask) {
        auto space = ip_and_mask.find(' ');
        if (space == std::string_view::npos) return normalized_cidr(ip_and_mask);
        auto ip = parse_ipv4(ip_and_mask.substr(0, space));
        auto mask = parse_ipv4(ip_and_mask.substr(space + 1));
        if (!ip || !mask || *ip == 0) return {};
        // Only contiguous masks describe a subnet.
        int prefix = std::popcount(*mask);
        if (mask_of(prefix) != *mask) return {};
        return std::format("{}/{}", format_ip(*ip & *mask), prefix);
    }

    std::string managed_comment(const DesiredClient& desired) {
        return std::format("{}: {} {}", marker, desired.interface, desired.why);
    }

    std::vector<DesiredClient> desired_clients(const Config& config, const Snapshot& snapshot, const PiholeSyncOptions& options) {
        std::vector<DesiredClient> out;
        for (const auto& network: config.networks) {
            if (network.mode == Network::Mode::observe) continue;
            const Interface* interface = snapshot.interface(network.interface);
            if (!interface) continue;   // reported elsewhere: a configured interface the FortiGate does not have
            std::vector<std::string> subnets;
            if (auto primary = to_cidr(interface->ip); !primary.empty()) subnets.push_back(primary);
            for (const auto& secondary: interface->secondary)
                if (auto s = to_cidr(secondary); !s.empty()) subnets.push_back(s);
            const DeviceGroup* base = config.group(network.group);
            std::string base_pihole = base ? base->pihole_group : std::string();

            std::vector<std::string> slices;
            for (const auto& slice: network.slices) {
                const DeviceGroup* group = config.group(slice.group);
                slices.push_back(normalized_cidr(slice.cidr));
                if (group && !group->pihole_group.empty())
                    out.push_back({normalized_cidr(slice.cidr), group->pihole_group, network.interface, "slice " + slice.group});
            }

            if (network.mode == Network::Mode::subnet || (network.mode == Network::Mode::hybrid && options.most_specific_wins)) {
                if (!base_pihole.empty())
                    for (const auto& subnet: subnets) out.push_back({subnet, base_pihole, network.interface, "subnet"});
            } else if (network.mode == Network::Mode::hybrid && !base_pihole.empty() && options.complement) {
                for (const auto& subnet: subnets) {
                    std::vector<std::string> within;
                    auto s = cidr_of(subnet);
                    for (const auto& slice: slices)
                        if (auto c = cidr_of(slice); c && s && inside(*c, *s)) within.push_back(slice);
                    for (const auto& piece: options.complement(subnet, within))
                        out.push_back({piece, base_pihole, network.interface, "rest of " + subnet});
                }
            }
        }
        return out;
    }

    PiholePlan plan_pihole(const Config& config, const Snapshot& snapshot, const PiholeView& view, const PiholeSyncOptions& options) {
        PiholePlan plan;
        plan.desired = desired_clients(config, snapshot, options);

        std::set<std::string> wanted;
        for (const auto& desired: plan.desired) {
            wanted.insert(desired.cidr);
            const PiholeGroupInfo* group = view.group(desired.pihole_group);
            if (!group) {
                plan.findings.push_back({"missing-group", desired.cidr,
                                         std::format("Pi-hole has no group \"{}\" ({} {}); create it in Pi-hole or map another",
                                                     desired.pihole_group, desired.interface, desired.why)});
                continue;
            }
            std::string comment = managed_comment(desired);
            // Match an existing entry by the CIDR itself, however Pi-hole spells it.
            const PiholeClientInfo* existing = nullptr;
            for (const auto& client: view.clients)
                if (normalized_cidr(client.client) == desired.cidr && client.client.find('/') != std::string::npos) existing = &client;
            if (!existing) {
                plan.changes.push_back({"create", desired.cidr, desired.pihole_group, comment, desired.why, 0, {group->id}});
                continue;
            }
            if (!existing->managed()) {
                // The operator already maps this CIDR: theirs wins, and the difference is reported.
                bool same = existing->groups == std::vector<int>{group->id};
                if (!same)
                    plan.findings.push_back({"unmanaged-overlap", existing->client,
                                             std::format("an operator entry for {} maps to other groups than \"{}\"; left as it is",
                                                         existing->client, desired.pihole_group),
                                             existing->id});
                continue;
            }
            if (existing->groups != std::vector<int>{group->id} || existing->comment != comment)
                plan.changes.push_back({"update", desired.cidr, desired.pihole_group, comment, desired.why, existing->id, {group->id}});
        }

        for (const auto& client: view.clients) {
            auto c = cidr_of(client.client);
            if (client.managed()) {
                auto cidr = normalized_cidr(client.client);
                if (wanted.contains(cidr)) continue;
                if (options.prune) plan.changes.push_back({"delete", cidr, {}, client.comment, "no network implies it", client.id, {}});
                else
                    plan.findings.push_back({"stale-managed", client.client,
                                             "managed entry no configured network implies any more; `sync --prune` removes it", client.id});
                continue;
            }
            if (!c) {
                if (normalize_mac(client.client))
                    plan.findings.push_back({"mac-client", client.client,
                                             "Pi-hole identifies this client by MAC; for clients routed through the FortiGate Pi-hole cannot "
                                             "see their MAC, so the entry may never match",
                                             client.id});
                continue;
            }
            // Operator entries inside managed CIDRs: an exact-IP entry takes precedence over the CIDR in
            // Pi-hole, so the device keeps those groups whatever slice it is in.
            for (const auto& desired: plan.desired) {
                auto d = cidr_of(desired.cidr);
                if (!d || !overlaps(*c, *d)) continue;
                if (normalized_cidr(client.client) == desired.cidr) break;   // handled above
                std::string groups;
                for (int id: client.groups) {
                    const PiholeGroupInfo* g = view.group(id);
                    groups += (groups.empty() ? "" : ", ") + (g ? g->name : std::to_string(id));
                }
                plan.findings.push_back({"unmanaged-shadow", client.client,
                                         std::format("operator entry {} ({}; groups {}) lies in {} ({} -> {}): it decides that address, not the "
                                                     "managed CIDR; remove it once the device's new address is verified",
                                                     client.client, client.comment.empty() ? "no comment" : client.comment,
                                                     groups.empty() ? "none" : groups, desired.cidr, desired.why, desired.pihole_group),
                                         client.id});
                break;
            }
        }
        (void) snapshot;
        return plan;
    }

}  // namespace fph
