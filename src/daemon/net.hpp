//
// IP addresses and CIDR blocks for the receiver's source allowlist. Only literals are parsed here:
// the allowlist is a security boundary, so it never depends on DNS at match time (the FortiGate's
// own address is resolved once, at start and on SIGHUP, by resolve_host()).
//

#ifndef FORTI_PIHOLED_NET_HPP
#define FORTI_PIHOLED_NET_HPP

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

struct sockaddr;

namespace fph::daemon {

    struct IpAddress {
        bool v6 = false;
        std::array<std::uint8_t, 16> bytes{};   // IPv4 uses the first 4

        // "192.0.2.1", "2001:db8::1". An IPv4-mapped IPv6 address (::ffff:192.0.2.1, what a dual-stack
        // listener reports for IPv4 peers) is returned as the IPv4 address, so one rule covers both.
        static std::optional<IpAddress> parse(std::string_view text);
        static std::optional<IpAddress> from_sockaddr(const sockaddr* address);
        [[nodiscard]] std::string to_string() const;
        [[nodiscard]] bool loopback() const;
        bool operator==(const IpAddress&) const = default;
    };

    struct Cidr {
        IpAddress base;
        int prefix = 0;

        // "192.0.2.0/24", "2001:db8::/32", or a bare address (a host route: /32 or /128). Host bits
        // set below the prefix are refused: "192.0.2.1/24" is almost always a typo for a host.
        static std::optional<Cidr> parse(std::string_view text);
        static Cidr host(const IpAddress& address) { return {address, address.v6 ? 128 : 32}; }
        [[nodiscard]] bool contains(const IpAddress& address) const;
        [[nodiscard]] std::string to_string() const;
    };

    class Allowlist {
        std::vector<Cidr> blocks_;

    public:
        Allowlist() = default;
        explicit Allowlist(std::vector<Cidr> blocks) : blocks_(std::move(blocks)) {}
        [[nodiscard]] bool allows(const IpAddress& address) const;
        [[nodiscard]] bool empty() const { return blocks_.empty(); }
        [[nodiscard]] const std::vector<Cidr>& blocks() const { return blocks_; }
        // True when a block covers every address (0.0.0.0/0, ::/0): worth a warning at start.
        [[nodiscard]] bool allows_any() const;
    };

    // The addresses `host` (an IP literal or a DNS name, e.g. a forti profile's host) resolves to, as
    // host routes. Empty when it does not resolve.
    std::vector<Cidr> resolve_host(const std::string& host);

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_NET_HPP
