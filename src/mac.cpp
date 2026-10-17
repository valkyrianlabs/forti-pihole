#include "mac.hpp"

#include <cstdint>

namespace fph {

    namespace {

        int hex_value(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        // 48-bit value of a normalized address, for range comparisons.
        std::optional<std::uint64_t> value_of(std::string_view text) {
            auto mac = normalize_mac(text);
            if (!mac) return std::nullopt;
            std::uint64_t value = 0;
            for (char c: *mac)
                if (c != ':') value = value * 16 + static_cast<std::uint64_t>(hex_value(c));
            return value;
        }

        std::string_view trim(std::string_view text) {
            while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
            while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
            return text;
        }

    }  // namespace

    std::optional<std::string> normalize_mac(std::string_view text) {
        text = trim(text);
        std::string digits;
        for (char c: text) {
            if (c == ':' || c == '-') continue;
            if (hex_value(c) < 0) return std::nullopt;
            digits += static_cast<char>(c >= 'A' && c <= 'F' ? c - 'A' + 'a' : c);
        }
        if (digits.size() != 12) return std::nullopt;
        // Separators, when present, must sit between every pair: "aabb:ccdd:eeff" is not a MAC.
        std::size_t separators = text.size() - digits.size();
        if (separators != 0 && separators != 5) return std::nullopt;
        if (separators == 5)
            for (std::size_t i = 2; i < text.size(); i += 3)
                if (text[i] != ':' && text[i] != '-') return std::nullopt;
        std::string out;
        for (std::size_t i = 0; i < 12; i += 2) {
            if (!out.empty()) out += ':';
            out += digits.substr(i, 2);
        }
        return out;
    }

    bool locally_administered(std::string_view mac) {
        auto normalized = normalize_mac(mac);
        if (!normalized) return false;
        return (hex_value((*normalized)[1]) & 0x2) != 0;
    }

    std::string mac_suffix(std::string_view mac) {
        auto normalized = normalize_mac(mac);
        if (!normalized) return {};
        std::string out;
        for (char c: normalized->substr(9))
            if (c != ':') out += c;
        return out;
    }

    std::string mac_oui(std::string_view mac) {
        auto normalized = normalize_mac(mac);
        return normalized ? normalized->substr(0, 8) : std::string();
    }

    bool mac_in_entry(std::string_view mac, std::string_view entry) {
        auto value = value_of(mac);
        if (!value) return false;
        entry = trim(entry);
        // A range is "lo-hi"; a single address may itself use '-' separators, so split only where
        // both halves parse.
        for (std::size_t dash = entry.find('-'); dash != std::string_view::npos; dash = entry.find('-', dash + 1)) {
            auto lo = value_of(entry.substr(0, dash));
            auto hi = value_of(entry.substr(dash + 1));
            if (lo && hi) return *lo <= *value && *value <= *hi;
        }
        auto single = value_of(entry);
        return single && *single == *value;
    }

}  // namespace fph
