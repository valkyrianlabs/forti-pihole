#include "cidr.hpp"

#include <algorithm>

namespace fph::alloc {

    namespace {

        // A decimal number without sign, whitespace or leading zeros, at most `max`.
        std::optional<std::uint32_t> parse_decimal(std::string_view text, std::uint32_t max) {
            if (text.empty() || text.size() > 10) return std::nullopt;
            if (text.size() > 1 && text.front() == '0') return std::nullopt;
            std::uint64_t value = 0;
            for (char c: text) {
                if (c < '0' || c > '9') return std::nullopt;
                value = value * 10 + static_cast<std::uint64_t>(c - '0');
                if (value > max) return std::nullopt;
            }
            return static_cast<std::uint32_t>(value);
        }

        std::uint64_t mask_of(int prefix) {
            return prefix == 0 ? 0 : (~std::uint64_t{0} << (32 - prefix)) & 0xffffffffu;
        }

    }  // namespace

    std::optional<Ipv4> parse_ipv4(std::string_view text) {
        Ipv4 ip = 0;
        for (int octet = 0; octet < 4; ++octet) {
            std::size_t dot = octet < 3 ? text.find('.') : text.size();
            if (dot == std::string_view::npos) return std::nullopt;
            auto value = parse_decimal(text.substr(0, dot), 255);
            if (!value) return std::nullopt;
            ip = (ip << 8) | *value;
            text.remove_prefix(octet < 3 ? dot + 1 : dot);
        }
        return text.empty() ? std::optional<Ipv4>(ip) : std::nullopt;
    }

    std::string format_ipv4(Ipv4 ip) {
        return std::to_string(ip >> 24) + '.' + std::to_string((ip >> 16) & 0xff) + '.' + std::to_string((ip >> 8) & 0xff) + '.' +
               std::to_string(ip & 0xff);
    }

    std::optional<Range> Range::parse(std::string_view text) {
        auto dash = text.find('-');
        if (dash == std::string_view::npos) {
            auto ip = parse_ipv4(text);
            return ip ? std::optional<Range>(Range::single(*ip)) : std::nullopt;
        }
        auto lo = parse_ipv4(text.substr(0, dash));
        auto hi = parse_ipv4(text.substr(dash + 1));
        if (!lo || !hi || *lo > *hi) return std::nullopt;
        return Range{*lo, *hi};
    }

    std::string Range::str() const {
        return lo == hi ? format_ipv4(lo) : format_ipv4(lo) + '-' + format_ipv4(hi);
    }

    std::optional<Range> intersect(const Range& a, const Range& b) {
        if (!a.overlaps(b)) return std::nullopt;
        return Range{std::max(a.lo, b.lo), std::min(a.hi, b.hi)};
    }

    std::vector<Range> normalize(std::vector<Range> ranges) {
        std::sort(ranges.begin(), ranges.end());
        std::vector<Range> out;
        for (const auto& range: ranges) {
            // Adjacent ranges merge too (hi + 1 == lo), so equal sets have one spelling.
            if (!out.empty() && std::uint64_t{range.lo} <= std::uint64_t{out.back().hi} + 1)
                out.back().hi = std::max(out.back().hi, range.hi);
            else
                out.push_back(range);
        }
        return out;
    }

    std::vector<Range> subtract(std::vector<Range> from, std::vector<Range> minus) {
        from = normalize(std::move(from));
        minus = normalize(std::move(minus));
        std::vector<Range> out;
        std::size_t m = 0;
        for (auto range: from) {
            std::uint64_t lo = range.lo;
            std::uint64_t hi = range.hi;
            while (m < minus.size() && minus[m].hi < lo) ++m;
            // Walk the holes inside this range; `m` stays on the first hole that may reach the next
            // range, since a hole can span two of them.
            std::size_t k = m;
            while (lo <= hi && k < minus.size() && minus[k].lo <= hi) {
                if (minus[k].lo > lo) out.push_back({static_cast<Ipv4>(lo), static_cast<Ipv4>(minus[k].lo - 1)});
                lo = std::max<std::uint64_t>(lo, std::uint64_t{minus[k].hi} + 1);
                ++k;
            }
            if (lo <= hi) out.push_back({static_cast<Ipv4>(lo), static_cast<Ipv4>(hi)});
        }
        return out;
    }

    std::optional<Cidr> Cidr::parse(std::string_view text) {
        auto slash = text.find('/');
        if (slash == std::string_view::npos) return std::nullopt;
        auto ip = parse_ipv4(text.substr(0, slash));
        auto prefix = parse_decimal(text.substr(slash + 1), 32);
        if (!ip || !prefix) return std::nullopt;
        if ((std::uint64_t{*ip} & ~mask_of(static_cast<int>(*prefix)) & 0xffffffffu) != 0) return std::nullopt;
        return Cidr{*ip, static_cast<int>(*prefix)};
    }

    Cidr Cidr::containing(Ipv4 ip, int prefix) {
        return Cidr{static_cast<Ipv4>(ip & mask_of(prefix)), prefix};
    }

    std::string Cidr::str() const {
        return format_ipv4(network) + '/' + std::to_string(prefix);
    }

    std::optional<Range> Cidr::usable(const Cidr& parent) const {
        if (!parent.contains(*this)) return std::nullopt;
        std::uint64_t lo = first();
        std::uint64_t hi = last();
        if (parent.prefix < 31) {
            if (lo == parent.first()) ++lo;
            if (hi == parent.last()) --hi;
        }
        if (lo > hi) return std::nullopt;
        return Range{static_cast<Ipv4>(lo), static_cast<Ipv4>(hi)};
    }

    std::uint64_t Cidr::usable_count(const Cidr& parent) const {
        auto range = usable(parent);
        return range ? range->size() : 0;
    }

    std::vector<Cidr> cover(const Range& range) {
        std::vector<Cidr> out;
        std::uint64_t at = range.lo;
        const std::uint64_t end = std::uint64_t{range.hi} + 1;
        while (at < end) {
            // The largest block that starts aligned at `at` and does not run past the range.
            int prefix = 0;
            while (prefix < 32) {
                std::uint64_t size = std::uint64_t{1} << (32 - prefix);
                if (at % size == 0 && at + size <= end) break;
                ++prefix;
            }
            out.push_back({static_cast<Ipv4>(at), prefix});
            at += std::uint64_t{1} << (32 - prefix);
        }
        return out;
    }

    std::vector<Cidr> complement(const Cidr& network, std::span<const Cidr> slices) {
        std::vector<Range> holes;
        for (const auto& slice: slices) holes.push_back(slice.range());
        // Each remaining maximal range is covered on its own: no block of a minimal cover can span
        // a slice, so the per-range greedy covers together are minimal for the whole set.
        std::vector<Cidr> out;
        for (const auto& range: subtract({network.range()}, std::move(holes))) {
            auto blocks = cover(range);
            out.insert(out.end(), blocks.begin(), blocks.end());
        }
        return out;
    }

}  // namespace fph::alloc
