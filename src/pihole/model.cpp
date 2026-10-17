#include "pihole/model.hpp"
#include "pihole/error.hpp"
#include "pihole/marker.hpp"
#include "pihole/text.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <charconv>
#include <format>

namespace fph::pihole {

    using nlohmann::json;

    namespace {

        [[noreturn]] void bad(std::string_view what, std::string_view field) {
            throw DecodeError(std::format("Pi-hole: unexpected {} in the reply: field \"{}\" is missing or has the "
                                          "wrong type", what, field));
        }

        const json& object_field(const json& object, const char* name, std::string_view what) {
            auto it = object.find(name);
            if (it == object.end() || !it->is_object()) bad(what, name);
            return *it;
        }

        const json& array_field(const json& object, const char* name, std::string_view what) {
            if (!object.is_object()) bad(what, name);
            auto it = object.find(name);
            if (it == object.end() || !it->is_array()) bad(what, name);
            return *it;
        }

        int int_field(const json& object, const char* name, std::string_view what) {
            auto it = object.find(name);
            if (it == object.end() || !it->is_number_integer()) bad(what, name);
            return it->get<int>();
        }

        std::int64_t timestamp(const json& object, const char* name) {
            auto it = object.find(name);
            return it != object.end() && it->is_number_integer() ? it->get<std::int64_t>() : 0;
        }

        std::string string_field(const json& object, const char* name, std::string_view what) {
            auto it = object.find(name);
            if (it == object.end() || !it->is_string()) bad(what, name);
            return it->get<std::string>();
        }

        // A nullable string; FTL also writes "" for "none" in a few places (a client's name).
        std::optional<std::string> nullable(const json& object, const char* name, std::string_view what) {
            auto it = object.find(name);
            if (it == object.end() || it->is_null()) return std::nullopt;
            if (!it->is_string()) bad(what, name);
            auto text = it->get<std::string>();
            if (text.empty()) return std::nullopt;
            return text;
        }

        ComponentVersion component(const json& version, const char* name) {
            ComponentVersion out;
            auto it = version.find(name);
            if (it == version.end() || !it->is_object()) return out;
            auto local = it->find("local");
            if (local == it->end() || !local->is_object()) return out;
            out.version = nullable(*local, "version", "version object");
            out.branch = nullable(*local, "branch", "version object");
            out.hash = nullable(*local, "hash", "version object");
            return out;
        }

        bool parse_ip(std::string_view text, bool v6, unsigned char (&out)[16]) { return parse_inet(text, v6, out); }

        std::string format_ip(const unsigned char (&bytes)[16], bool v6) {
            char text[INET6_ADDRSTRLEN] = {};
            inet_ntop(v6 ? AF_INET6 : AF_INET, bytes, text, sizeof text);
            return text;
        }

        bool hostname_char(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                   c == '.';
        }

        bool interface_char(char c) { return hostname_char(c) || c == '@'; }

        struct Parsed {
            ClientKind kind;
            std::string canonical;
        };

        std::optional<Parsed> parse_client(std::string_view client) {
            if (client.empty() || client.size() > 253) return std::nullopt;
            // FTL refuses spaces and tabs ("Spaces and tabs are not allowed") and CR/LF in any item.
            if (std::ranges::any_of(client, [](char c) { return static_cast<unsigned char>(c) <= 0x20 || c == 0x7f; }))
                return std::nullopt;

            unsigned char bytes[16];
            if (auto slash = client.find('/'); slash != std::string_view::npos) {
                std::string_view address = client.substr(0, slash), length = client.substr(slash + 1);
                bool v6 = address.find(':') != std::string_view::npos;
                if (!parse_ip(address, v6, bytes)) return std::nullopt;
                // Plain decimal only: FTL reads the length with sscanf("%i"), which would take "010" as
                // octal 8, and a reader of the entry would not.
                if (length.empty() || length.size() > 3 || length.starts_with('0') ||
                    !std::ranges::all_of(length, [](char c) { return c >= '0' && c <= '9'; }))
                    return std::nullopt;
                int bits = 0;
                std::from_chars(length.data(), length.data() + length.size(), bits);
                int max = v6 ? 128 : 32;
                if (bits < 1 || bits > max) return std::nullopt;   // /0 never matches in FTL
                if (bits == max) return Parsed{v6 ? ClientKind::ipv6 : ClientKind::ipv4, format_ip(bytes, v6)};
                for (int i = bits; i < 128; ++i) bytes[i / 8] &= static_cast<unsigned char>(~(1u << (7 - i % 8)));
                return Parsed{v6 ? ClientKind::subnet6 : ClientKind::subnet4, std::format("{}/{}", format_ip(bytes, v6), bits)};
            }
            if (parse_ip(client, false, bytes)) return Parsed{ClientKind::ipv4, format_ip(bytes, false)};
            if (parse_ip(client, true, bytes)) return Parsed{ClientKind::ipv6, format_ip(bytes, true)};
            if (auto mac = normalize_mac(client)) return Parsed{ClientKind::mac, *mac};
            if (client.starts_with(':')) {
                std::string_view name = client.substr(1);
                if (name.empty() || name.size() > 15 || !std::ranges::all_of(name, interface_char)) return std::nullopt;
                return Parsed{ClientKind::interface, std::string(client)};
            }
            if (!std::ranges::all_of(client, hostname_char) || client.starts_with('.') || client.find("..") != std::string_view::npos)
                return std::nullopt;
            return Parsed{ClientKind::hostname, ascii_lower(client)};
        }

    }  // namespace

    bool ClientEntry::managed() const { return comment && carries_marker(*comment); }

    std::optional<Version> Version::parse(std::string_view text) {
        if (text.starts_with('v')) text.remove_prefix(1);
        // A suffix such as "-12-gabcdef" (a build past a tag) does not change the release.
        text = text.substr(0, text.find('-'));
        Version out;
        int* parts[] = {&out.major, &out.minor, &out.patch};
        std::size_t count = 0;
        while (!text.empty() && count < 3) {
            auto dot = text.find('.');
            std::string_view part = text.substr(0, dot);
            if (part.empty() || part.size() > 6 || !std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; }))
                return std::nullopt;
            std::from_chars(part.data(), part.data() + part.size(), *parts[count++]);
            if (dot == std::string_view::npos) {
                text = {};
            } else {
                text.remove_prefix(dot + 1);
                if (text.empty()) return std::nullopt;
            }
        }
        if (!text.empty() || count < 2) return std::nullopt;
        return out;
    }

    std::string Version::to_string() const { return std::format("v{}.{}.{}", major, minor, patch); }

    void check_supported(const VersionInfo& info) {
        if (!info.ftl.version)
            throw VersionError(std::format("Pi-hole: cannot tell the FTL version (none reported); forti-pihole needs "
                                           "Pi-hole FTL {} or later", minimum_ftl_version.to_string()));
        auto version = Version::parse(*info.ftl.version);
        if (!version)
            throw VersionError(std::format("Pi-hole: cannot tell the FTL version from \"{}\" (a development build?); "
                                           "forti-pihole needs a Pi-hole FTL release {} or later",
                                           printable(*info.ftl.version, 40), minimum_ftl_version.to_string()));
        if (*version < minimum_ftl_version)
            throw VersionError(std::format("Pi-hole: FTL {} is older than {}, the oldest forti-pihole supports; update "
                                           "Pi-hole (pihole -up) first",
                                           printable(*info.ftl.version, 40), minimum_ftl_version.to_string()));
    }

    Group decode_group(const json& item) {
        constexpr std::string_view what = "group";
        if (!item.is_object()) bad(what, "groups[]");
        Group group;
        group.id = int_field(item, "id", what);
        group.name = string_field(item, "name", what);
        group.comment = nullable(item, "comment", what);
        auto enabled = item.find("enabled");
        if (enabled != item.end()) {
            if (!enabled->is_boolean()) bad(what, "enabled");
            group.enabled = enabled->get<bool>();
        }
        group.date_added = timestamp(item, "date_added");
        group.date_modified = timestamp(item, "date_modified");
        return group;
    }

    ClientEntry decode_client(const json& item) {
        constexpr std::string_view what = "client";
        if (!item.is_object()) bad(what, "clients[]");
        ClientEntry entry;
        entry.id = int_field(item, "id", what);
        entry.client = string_field(item, "client", what);
        entry.comment = nullable(item, "comment", what);
        entry.name = nullable(item, "name", what);
        // Required: FTL always sends it (an empty array for no group, list.c api_list_read()). A missing
        // set is not "no groups" and not "Default"; guessing either would misreport what applies.
        for (const auto& id: array_field(item, "groups", what)) {
            if (!id.is_number_integer()) bad(what, "groups[]");
            entry.groups.push_back(id.get<int>());
        }
        std::ranges::sort(entry.groups);
        entry.date_added = timestamp(item, "date_added");
        entry.date_modified = timestamp(item, "date_modified");
        return entry;
    }

    std::vector<Group> decode_groups(const json& reply) {
        std::vector<Group> out;
        for (const auto& item: array_field(reply, "groups", "groups reply")) out.push_back(decode_group(item));
        return out;
    }

    std::vector<ClientEntry> decode_clients(const json& reply) {
        std::vector<ClientEntry> out;
        for (const auto& item: array_field(reply, "clients", "clients reply")) out.push_back(decode_client(item));
        return out;
    }

    VersionInfo decode_version(const json& reply) {
        if (!reply.is_object()) bad("version reply", "version");
        const json& version = object_field(reply, "version", "version reply");
        VersionInfo info;
        info.core = component(version, "core");
        info.web = component(version, "web");
        info.ftl = component(version, "ftl");
        if (auto docker = version.find("docker"); docker != version.end() && docker->is_object())
            info.docker = nullable(*docker, "local", "version object");
        return info;
    }

    std::vector<std::string> processed_errors(const json& reply) {
        std::vector<std::string> out;
        if (!reply.is_object()) return out;
        auto processed = reply.find("processed");
        if (processed == reply.end() || !processed->is_object()) return out;
        auto errors = processed->find("errors");
        if (errors == processed->end() || !errors->is_array()) return out;
        for (const auto& error: *errors) {
            std::string text = error.is_object() && error.contains("error") && error["error"].is_string()
                                       ? error["error"].get<std::string>()
                                       : std::string("unknown error");
            out.push_back(std::move(text));
        }
        return out;
    }

    std::string_view to_string(ClientKind kind) {
        switch (kind) {
            case ClientKind::ipv4: return "IPv4 address";
            case ClientKind::ipv6: return "IPv6 address";
            case ClientKind::subnet4: return "IPv4 subnet";
            case ClientKind::subnet6: return "IPv6 subnet";
            case ClientKind::mac: return "MAC address";
            case ClientKind::interface: return "interface";
            case ClientKind::hostname: return "hostname";
        }
        return "client";
    }

    std::optional<ClientKind> classify_client(std::string_view client) {
        auto parsed = parse_client(client);
        if (!parsed) return std::nullopt;
        return parsed->kind;
    }

    std::optional<std::string> canonical_client(std::string_view client) {
        auto parsed = parse_client(client);
        if (!parsed) return std::nullopt;
        return std::move(parsed->canonical);
    }

    std::optional<std::string> normalize_mac(std::string_view text) {
        // Six hex pairs separated by ':' or '-' (one separator throughout). Bare or dotted spellings
        // are not taken: as Pi-hole client strings they are hostnames, and guessing would change meaning.
        if (text.size() != 17) return std::nullopt;
        char separator = text[2];
        if (separator != ':' && separator != '-') return std::nullopt;
        std::string out;
        for (std::size_t i = 0; i < 17; ++i) {
            char c = text[i];
            if (i % 3 == 2) {
                if (c != separator) return std::nullopt;
                out += ':';
                continue;
            }
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return std::nullopt;
            out += c >= 'a' && c <= 'f' ? static_cast<char>(c - 'a' + 'A') : c;
        }
        return out;
    }

}  // namespace fph::pihole
