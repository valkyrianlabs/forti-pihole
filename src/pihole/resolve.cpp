#include "pihole/resolve.hpp"
#include "pihole/text.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace fph::pihole {

    namespace {

        // isMAC() in FTL's network-table.c: 17 characters, five ':' and no "::". Deliberately loose,
        // and it runs before anything else in subnet_match().
        bool ftl_is_mac(std::string_view text) {
            return text.size() == 17 && std::ranges::count(text, ':') == 5 && text.find("::") == std::string_view::npos;
        }

        // What subnet_match() makes of a client row, the database side: the family, prefix length and
        // masked network; nullopt where it returns 0 before comparing anything.
        struct Row {
            bool v6 = false;
            int bits = 0;
            unsigned char network[16] = {};
        };

        // sscanf("%i") on what follows the '/': strtol with base 0 (leading whitespace, a sign, 0x hex,
        // a leading 0 for octal). When no number is there the conversion fails and FTL keeps the
        // default length (32 or 128), exactly like a row without '/'.
        std::optional<long> scan_i(std::string_view text) {
            std::string copy(text);
            const char* begin = copy.c_str();
            char* end = nullptr;
            errno = 0;
            long value = std::strtol(begin, &end, 0);
            if (end == begin) return std::nullopt;
            if (errno == ERANGE) return value < 0 ? -1L : 1000L;   // out of range either way
            return value;
        }

        std::optional<Row> ftl_row(std::string_view entry) {
            if (ftl_is_mac(entry)) return std::nullopt;
            Row row;
            row.v6 = entry.find(':') != std::string_view::npos;   // strchr() over the whole row
            long bits = row.v6 ? 128 : 32;
            // "%m[^/]/%i": at least one character before any '/'; a row starting with '/' fails (rt < 1).
            auto slash = entry.find('/');
            std::string_view address = entry.substr(0, slash);
            if (address.empty()) return std::nullopt;
            if (slash != std::string_view::npos)
                if (auto scanned = scan_i(entry.substr(slash + 1))) bits = *scanned;
            if (bits < 0 || bits > (row.v6 ? 128 : 32)) return std::nullopt;
            row.bits = static_cast<int>(bits);
            if (!parse_inet(address, row.v6, row.network)) return std::nullopt;
            for (int i = row.bits; i < 128; ++i)
                row.network[i / 8] &= static_cast<unsigned char>(~(1u << (7 - i % 8)));
            return row;
        }

        std::optional<int> first_nocase(std::span<const ClientEntry> clients, std::string_view text) {
            // "SELECT id FROM client WHERE ip = ? COLLATE NOCASE": the UNIQUE index on ip is BINARY, so
            // SQLite scans the table in rowid (= id) order and the lowest id comes first.
            std::optional<int> best;
            for (const auto& entry: clients)
                if (equals_nocase(entry.client, text) && (!best || entry.id < *best)) best = entry.id;
            return best;
        }

        const ClientEntry* by_id(std::span<const ClientEntry> clients, int id) {
            for (const auto& entry: clients)
                if (entry.id == id) return &entry;
            return nullptr;
        }

    }  // namespace

    int subnet_match(std::string_view entry, std::string_view ip) {
        auto row = ftl_row(entry);
        if (!row) return 0;
        bool v6 = ip.find(':') != std::string_view::npos;
        if (row->v6 != v6) return 0;
        unsigned char address[16];
        if (!parse_inet(ip, v6, address)) return 0;
        for (int i = 0; i < row->bits; ++i) {
            unsigned char bit = static_cast<unsigned char>(1u << (7 - i % 8));
            if ((address[i / 8] & bit) != (row->network[i / 8] & bit)) return 0;
        }
        // The length itself, so /0 scores 0 and never survives "WHERE matching_bits > 0".
        return row->bits;
    }

    std::string_view to_string(Match match) {
        switch (match) {
            case Match::address: return "address";
            case Match::mac: return "MAC address";
            case Match::hostname: return "hostname";
            case Match::interface: return "interface";
            case Match::none: return "none (Default group)";
        }
        return "none";
    }

    Resolution resolve_client(std::span<const ClientEntry> clients, const Observed& seen, const ResolveOptions& options) {
        Resolution out;
        auto chosen = [&](int id, Match match) {
            const ClientEntry* entry = by_id(clients, id);
            out.match = match;
            out.entry_id = id;
            out.entry = entry->client;
            out.groups = entry->groups;
            std::ranges::sort(out.groups);
            return out;
        };

        // 1. Longest prefix; ties go to max(id).
        int best_bits = 0;
        std::vector<int> best_ids;
        if (!seen.ip.empty()) {
            for (const auto& entry: clients) {
                int bits = subnet_match(entry.client, seen.ip);
                if (bits <= 0 || bits < best_bits) continue;
                if (bits > best_bits) {
                    best_bits = bits;
                    best_ids.clear();
                }
                best_ids.push_back(entry.id);
            }
        }
        if (!best_ids.empty()) {
            std::ranges::sort(best_ids);
            int id = best_ids.back();
            best_ids.pop_back();
            chosen(id, Match::address);
            out.prefix = best_bits;
            out.tied = std::move(best_ids);
            return out;
        }

        // 2. MAC, as FTL prints it.
        if (options.mac_names && !seen.mac.empty())
            if (auto mac = normalize_mac(seen.mac))
                if (auto id = first_nocase(clients, *mac)) return chosen(*id, Match::mac);

        // 3. Hostname.
        if (!seen.hostname.empty())
            if (auto id = first_nocase(clients, seen.hostname)) return chosen(*id, Match::hostname);

        // 4. Interface, as ":<name>".
        if (!seen.interface.empty())
            if (auto id = first_nocase(clients, ":" + seen.interface)) return chosen(*id, Match::interface);

        // 5. Default group.
        out.groups = {default_group_id};
        return out;
    }

    std::vector<int> effective_groups(std::span<const ClientEntry> clients, std::string_view ip, std::string_view mac,
                                      std::string_view hostname, std::string_view interface) {
        Observed seen{std::string(ip), std::string(mac), std::string(hostname), std::string(interface)};
        return resolve_client(clients, seen).groups;
    }

    std::vector<int> enabled_groups(std::span<const int> ids, std::span<const Group> groups) {
        std::vector<int> out;
        for (int id: ids)
            for (const auto& group: groups)
                if (group.id == id && group.enabled) {
                    out.push_back(id);
                    break;
                }
        return out;
    }

    std::vector<Ambiguity> find_ambiguities(std::span<const ClientEntry> clients) {
        std::vector<Ambiguity> out;
        for (std::size_t i = 0; i < clients.size(); ++i) {
            auto a = ftl_row(clients[i].client);
            for (std::size_t j = i + 1; j < clients.size(); ++j) {
                auto b = ftl_row(clients[j].client);
                bool tie = false;
                if (a && b)
                    tie = a->bits > 0 && a->v6 == b->v6 && a->bits == b->bits &&
                          std::memcmp(a->network, b->network, sizeof a->network) == 0;
                else
                    tie = equals_nocase(clients[i].client, clients[j].client);
                if (!tie) continue;
                const auto& [first, second] = clients[i].id < clients[j].id ? std::pair(&clients[i], &clients[j])
                                                                          : std::pair(&clients[j], &clients[i]);
                out.push_back({first->id, second->id, first->client, second->client});
            }
        }
        return out;
    }

}  // namespace fph::pihole
