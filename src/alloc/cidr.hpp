//
// IPv4 addresses, inclusive ranges and CIDR blocks for the allocation planner (plan.hpp).
//
// Parsing is strict on purpose: the planner's inputs come from FortiOS and from operator
// configuration, and a block written "192.168.1.5/28" almost always means the operator got the
// alignment wrong, so it is refused instead of being silently rounded down to .0/28.
//
// Arithmetic that can step past 255.255.255.255 is done in 64 bits; the types themselves store
// 32-bit values.
//

#ifndef FORTI_PIHOLE_ALLOC_CIDR_HPP
#define FORTI_PIHOLE_ALLOC_CIDR_HPP

#include <compare>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace fph::alloc {

    using Ipv4 = std::uint32_t;

    // "a.b.c.d": four decimal octets 0..255, no leading zeros ("010" is octal to some tools and
    // decimal to others), no whitespace or signs.
    std::optional<Ipv4> parse_ipv4(std::string_view text);
    std::string format_ipv4(Ipv4 ip);

    // An inclusive address range [lo, hi], the shape of FortiOS DHCP ip-range / exclude-range.
    struct Range {
        Ipv4 lo = 0;
        Ipv4 hi = 0;

        // "a.b.c.d-e.f.g.h" (or a single address); nullopt when malformed or lo > hi.
        static std::optional<Range> parse(std::string_view text);
        static Range single(Ipv4 ip) { return {ip, ip}; }

        [[nodiscard]] std::uint64_t size() const { return std::uint64_t{hi} - lo + 1; }
        [[nodiscard]] bool contains(Ipv4 ip) const { return ip >= lo && ip <= hi; }
        [[nodiscard]] bool contains(const Range& other) const { return other.lo >= lo && other.hi <= hi; }
        [[nodiscard]] bool overlaps(const Range& other) const { return other.lo <= hi && lo <= other.hi; }
        [[nodiscard]] std::string str() const;

        auto operator<=>(const Range&) const = default;
    };

    // Overlap of two ranges, nullopt when they are disjoint.
    std::optional<Range> intersect(const Range& a, const Range& b);

    // Sorted, overlapping and adjacent ranges merged: the canonical form of an address set.
    std::vector<Range> normalize(std::vector<Range> ranges);

    // `from` minus `minus`, normalized. Neither input needs to be normalized.
    std::vector<Range> subtract(std::vector<Range> from, std::vector<Range> minus);

    struct Cidr {
        Ipv4 network = 0;
        int prefix = 32;

        // "a.b.c.d/n", n in 0..32, host bits zero. The "/n" is required.
        static std::optional<Cidr> parse(std::string_view text);
        // The block of `prefix` containing `ip` (host bits cleared). prefix must be 0..32.
        static Cidr containing(Ipv4 ip, int prefix);

        [[nodiscard]] Ipv4 first() const { return network; }
        [[nodiscard]] Ipv4 last() const { return static_cast<Ipv4>(std::uint64_t{network} + size() - 1); }
        [[nodiscard]] std::uint64_t size() const { return std::uint64_t{1} << (32 - prefix); }
        [[nodiscard]] Range range() const { return {first(), last()}; }
        [[nodiscard]] bool contains(Ipv4 ip) const { return range().contains(ip); }
        [[nodiscard]] bool contains(const Cidr& other) const { return range().contains(other.range()); }
        [[nodiscard]] bool overlaps(const Cidr& other) const { return range().overlaps(other.range()); }
        [[nodiscard]] std::string str() const;

        // The addresses of this block a device may hold when the block is a slice of `parent`: all of
        // them except the parent subnet's own network and broadcast addresses. A slice is not a
        // routed subnet (its members keep the parent's mask and gateway), so the slice's first and
        // last addresses are ordinary hosts. A /31 or /32 parent has no network or broadcast address
        // to lose (RFC 3021). nullopt when nothing is left or the block is not inside `parent`.
        [[nodiscard]] std::optional<Range> usable(const Cidr& parent) const;
        [[nodiscard]] std::uint64_t usable_count(const Cidr& parent) const;

        auto operator<=>(const Cidr&) const = default;
    };

    // The fewest CIDR blocks that exactly cover `range`, in address order.
    std::vector<Cidr> cover(const Range& range);

    // The fewest CIDR blocks that, together with `slices`, cover `network` exactly once: the network
    // minus the slices. Pi-hole matches a client against every CIDR entry it holds, so in hybrid
    // mode the "rest of the subnet" group must be spelled as this cover rather than as the subnet
    // itself, which would overlap every slice. Parts of slices outside `network` are ignored.
    std::vector<Cidr> complement(const Cidr& network, std::span<const Cidr> slices);

}  // namespace fph::alloc

#endif  // FORTI_PIHOLE_ALLOC_CIDR_HPP
