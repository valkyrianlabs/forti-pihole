#include "net.hpp"

#include <algorithm>
#include <charconv>
#include <cstring>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace fph::daemon {

    namespace {

        constexpr std::array<std::uint8_t, 12> v4_mapped_prefix = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

        IpAddress unmap(IpAddress address) {
            if (address.v6 && std::equal(v4_mapped_prefix.begin(), v4_mapped_prefix.end(), address.bytes.begin())) {
                IpAddress v4;
                std::copy_n(address.bytes.begin() + 12, 4, v4.bytes.begin());
                return v4;
            }
            return address;
        }

    }  // namespace

    std::optional<IpAddress> IpAddress::parse(std::string_view text) {
        // inet_pton needs a terminated string and accepts nothing but plain literals (no zone ids,
        // no shortened IPv4 such as "10.1"), which is what an allowlist wants.
        if (text.empty() || text.size() > 45) return std::nullopt;
        // Zone ids ("fe80::1%en0") name a local interface, not an address a rule can match.
        if (text.find('%') != std::string_view::npos) return std::nullopt;
        std::string buffer(text);
        IpAddress address;
        if (::inet_pton(AF_INET, buffer.c_str(), address.bytes.data()) == 1) return address;
        address.v6 = true;
        if (::inet_pton(AF_INET6, buffer.c_str(), address.bytes.data()) == 1) return unmap(address);
        return std::nullopt;
    }

    std::optional<IpAddress> IpAddress::from_sockaddr(const sockaddr* address) {
        if (!address) return std::nullopt;
        IpAddress out;
        if (address->sa_family == AF_INET) {
            sockaddr_in in{};
            std::memcpy(&in, address, sizeof in);
            std::memcpy(out.bytes.data(), &in.sin_addr, 4);
            return out;
        }
        if (address->sa_family == AF_INET6) {
            sockaddr_in6 in6{};
            std::memcpy(&in6, address, sizeof in6);
            out.v6 = true;
            std::memcpy(out.bytes.data(), &in6.sin6_addr, 16);
            return unmap(out);
        }
        return std::nullopt;
    }

    std::string IpAddress::to_string() const {
        char buffer[INET6_ADDRSTRLEN] = {};
        ::inet_ntop(v6 ? AF_INET6 : AF_INET, bytes.data(), buffer, sizeof buffer);
        return buffer;
    }

    bool IpAddress::loopback() const {
        if (!v6) return bytes[0] == 127;
        for (std::size_t i = 0; i < 15; ++i)
            if (bytes[i] != 0) return false;
        return bytes[15] == 1;
    }

    std::optional<Cidr> Cidr::parse(std::string_view text) {
        auto slash = text.find('/');
        auto address = IpAddress::parse(text.substr(0, slash));
        if (!address) return std::nullopt;
        if (slash == std::string_view::npos) return host(*address);
        auto digits = text.substr(slash + 1);
        int prefix = -1;
        auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), prefix);
        int max = address->v6 ? 128 : 32;
        if (digits.empty() || error != std::errc() || end != digits.data() + digits.size() || prefix < 0 || prefix > max)
            return std::nullopt;
        Cidr cidr{*address, prefix};
        // The base must be the network address itself.
        for (int bit = prefix; bit < max; ++bit)
            if (address->bytes[static_cast<std::size_t>(bit / 8)] & (0x80 >> (bit % 8))) return std::nullopt;
        return cidr;
    }

    bool Cidr::contains(const IpAddress& address) const {
        if (address.v6 != base.v6) return false;
        int full = prefix / 8, rest = prefix % 8;
        for (int i = 0; i < full; ++i)
            if (address.bytes[static_cast<std::size_t>(i)] != base.bytes[static_cast<std::size_t>(i)]) return false;
        if (rest == 0) return true;
        auto mask = static_cast<std::uint8_t>(0xff << (8 - rest));
        return (address.bytes[static_cast<std::size_t>(full)] & mask) == (base.bytes[static_cast<std::size_t>(full)] & mask);
    }

    std::string Cidr::to_string() const { return base.to_string() + "/" + std::to_string(prefix); }

    bool Allowlist::allows(const IpAddress& address) const {
        for (const auto& block: blocks_)
            if (block.contains(address)) return true;
        return false;
    }

    bool Allowlist::allows_any() const {
        for (const auto& block: blocks_)
            if (block.prefix == 0) return true;
        return false;
    }

    std::vector<Cidr> resolve_host(const std::string& host) {
        if (auto literal = IpAddress::parse(host)) return {Cidr::host(*literal)};
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* result = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) return {};
        std::vector<Cidr> out;
        for (auto* entry = result; entry; entry = entry->ai_next) {
            auto address = IpAddress::from_sockaddr(entry->ai_addr);
            if (!address) continue;
            auto cidr = Cidr::host(*address);
            bool seen = false;
            for (const auto& existing: out) seen = seen || (existing.base == cidr.base);
            if (!seen) out.push_back(cidr);
        }
        ::freeaddrinfo(result);
        return out;
    }

}  // namespace fph::daemon
