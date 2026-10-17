#include "address_match.hpp"

#include "mac.hpp"

#include <algorithm>
#include <charconv>

namespace fph {

    namespace {

        bool covers(const Snapshot& snapshot, std::string_view name, const Endpoint& endpoint, int depth) {
            // FortiOS rejects group loops; the depth limit only protects against a corrupt read.
            if (depth > 16) return false;
            if (const AddrGroup* ag = snapshot.addrgrp(name)) {
                bool in = std::ranges::any_of(ag->members, [&](const auto& m) { return covers(snapshot, m, endpoint, depth + 1); });
                if (in && ag->exclude)
                    in = !std::ranges::any_of(ag->exclude_members,
                                              [&](const auto& m) { return covers(snapshot, m, endpoint, depth + 1); });
                return in;
            }
            const Address* address = snapshot.address(name);
            if (!address) return false;
            const auto& type = address->type;
            if (type == "ipmask" || type == "interface-subnet")
                return !endpoint.ip.empty() && in_subnet(endpoint.ip, address->subnet);
            if (type == "iprange") {
                auto ip = parse_ipv4(endpoint.ip), lo = parse_ipv4(address->start_ip), hi = parse_ipv4(address->end_ip);
                return ip && lo && hi && *lo <= *ip && *ip <= *hi;
            }
            if (type == "mac")
                return !endpoint.mac.empty() &&
                       std::ranges::any_of(address->macs, [&](const auto& entry) { return mac_in_entry(endpoint.mac, entry); });
            if (type == "dynamic" && address->sub_type == "device-identification")
                return std::ranges::any_of(address->resolved, [&](const auto& value) {
                    return (!endpoint.mac.empty() && value == endpoint.mac) || (!endpoint.ip.empty() && value == endpoint.ip);
                });
            return false;
        }

    }  // namespace

    std::optional<std::uint32_t> parse_ipv4(std::string_view text) {
        std::uint32_t value = 0;
        int parts = 0;
        while (!text.empty()) {
            unsigned octet = 0;
            auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), octet);
            if (error != std::errc() || octet > 255 || end == text.data()) return std::nullopt;
            value = (value << 8) | octet;
            ++parts;
            text.remove_prefix(static_cast<std::size_t>(end - text.data()));
            if (text.empty()) break;
            if (text.front() != '.' || parts == 4) return std::nullopt;
            text.remove_prefix(1);
        }
        if (parts != 4) return std::nullopt;
        return value;
    }

    bool in_subnet(std::string_view ip, std::string_view subnet) {
        auto address = parse_ipv4(ip);
        if (!address) return false;
        std::uint32_t network = 0, mask = 0;
        if (auto slash = subnet.find('/'); slash != std::string_view::npos) {
            auto net = parse_ipv4(subnet.substr(0, slash));
            unsigned length = 0;
            auto tail = subnet.substr(slash + 1);
            auto [end, error] = std::from_chars(tail.data(), tail.data() + tail.size(), length);
            if (!net || error != std::errc() || length > 32) return false;
            network = *net;
            mask = length == 0 ? 0 : ~std::uint32_t(0) << (32 - length);
        } else {
            auto space = subnet.find(' ');
            if (space == std::string_view::npos) return false;
            auto net = parse_ipv4(subnet.substr(0, space));
            auto m = parse_ipv4(subnet.substr(space + 1));
            if (!net || !m) return false;
            network = *net;
            mask = *m;
        }
        return (*address & mask) == (network & mask);
    }

    bool address_covers(const Snapshot& snapshot, std::string_view name, const Endpoint& endpoint) {
        return covers(snapshot, name, endpoint, 0);
    }

}  // namespace fph
