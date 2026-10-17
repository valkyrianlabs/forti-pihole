#include "pihole/text.hpp"

#include <arpa/inet.h>

#include <algorithm>

namespace fph::pihole {

    namespace {

        char fold(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

    }  // namespace

    std::string printable(std::string_view text, std::size_t limit) {
        std::string out;
        out.reserve(std::min(text.size(), limit));
        for (char c: text) {
            if (out.size() >= limit) {
                out += "...";
                break;
            }
            auto byte = static_cast<unsigned char>(c);
            out += byte < 0x20 || byte == 0x7f ? '?' : c;
        }
        return out;
    }

    bool equals_nocase(std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i)
            if (fold(a[i]) != fold(b[i])) return false;
        return true;
    }

    std::string ascii_lower(std::string_view text) {
        std::string out(text);
        for (char& c: out) c = fold(c);
        return out;
    }

    namespace {

        // glibc's inet_pton4() (and musl's): exactly four decimal parts of 1 to 3 digits, each at most
        // 255, no leading zeros. Hand-written because BSD libcs (macOS) accept "010.1.2.3".
        bool parse_dotted_quad(std::string_view text, unsigned char* out) {
            int part = 0;
            std::size_t digits = 0;
            unsigned value = 0;
            for (std::size_t i = 0; i <= text.size(); ++i) {
                char c = i < text.size() ? text[i] : '.';
                if (c >= '0' && c <= '9') {
                    if (digits == 1 && value == 0) return false;   // leading zero
                    value = value * 10 + static_cast<unsigned>(c - '0');
                    if (++digits > 3 || value > 255) return false;
                } else if (c == '.') {
                    if (digits == 0 || part == 4) return false;
                    out[part++] = static_cast<unsigned char>(value);
                    digits = 0;
                    value = 0;
                } else {
                    return false;
                }
            }
            return part == 4;
        }

    }  // namespace

    bool parse_inet(std::string_view text, bool v6, unsigned char (&out)[16]) {
        std::fill(std::begin(out), std::end(out), static_cast<unsigned char>(0));
        if (!v6) return parse_dotted_quad(text, out);
        if (text.find('%') != std::string_view::npos) return false;
        // An embedded IPv4 tail ("::ffff:10.0.0.5") follows the IPv4 rules (glibc parses it with inet_pton4()).
        if (auto colon = text.rfind(':'); colon != std::string_view::npos && text.find('.', colon) != std::string_view::npos) {
            unsigned char tail[4];
            if (!parse_dotted_quad(text.substr(colon + 1), tail)) return false;
        }
        std::string copy(text);
        return inet_pton(AF_INET6, copy.c_str(), out) == 1;
    }

}  // namespace fph::pihole
