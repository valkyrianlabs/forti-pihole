//
// Small text helpers for untrusted strings (Pi-hole hints, comments, hostnames) that end up in
// messages, and for the case-insensitive comparisons Pi-hole's database makes (SQLite COLLATE NOCASE
// folds ASCII only).
//

#ifndef FORTI_PIHOLE_PIHOLE_TEXT_HPP
#define FORTI_PIHOLE_PIHOLE_TEXT_HPP

#include <string>
#include <string_view>

namespace fph::pihole {

    // Control characters become '?', and the result is cut at `limit` bytes with "...".
    [[nodiscard]] std::string printable(std::string_view text, std::size_t limit);

    // SQLite's NOCASE: ASCII letters compare equal regardless of case, every other byte exactly.
    [[nodiscard]] bool equals_nocase(std::string_view a, std::string_view b);

    [[nodiscard]] std::string ascii_lower(std::string_view text);

    // inet_pton() as Pi-hole's libc (glibc or musl) does it, into 16 zeroed bytes. FTL runs on Linux;
    // macOS's inet_pton() also accepts IPv4 parts with leading zeros and IPv6 zones ("fe80::1%eth0"),
    // which Linux refuses, so this refuses them too.
    [[nodiscard]] bool parse_inet(std::string_view text, bool v6, unsigned char (&out)[16]);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_TEXT_HPP
