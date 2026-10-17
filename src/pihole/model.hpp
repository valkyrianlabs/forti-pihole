//
// What the Pi-hole v6 API returns, decoded. Shapes follow FTL's OpenAPI specification
// (src/api/docs/content/specs/*.yaml in pi-hole/FTL, also served by Pi-hole at /api/docs) and, where
// the specification is loose, what FTL's src/api/list.c actually emits.
//
// The Default group: group id 0, named "Default", always exists (gravity.db.sql inserts it and
// trigger tr_group_zero recreates it when deleted). A client that matches no client entry uses
// group 0 only. A client entry is in exactly the groups listed for it: the Default group is not
// implied (FTL's get_client_groupids() reads client_by_group and nothing else). A new entry starts in
// group 0 (trigger tr_client_add); sending "groups" replaces that set, and "groups": [] is accepted
// and leaves the entry in no group at all, which means no adlist and no domain entry applies to it:
// nothing is blocked for that device (the gravity lookups filter `group_id IN carray(<client's
// groups>)`, gravity-db.c). The client refuses an empty set unless the caller asks for it.
//

#ifndef FORTI_PIHOLE_PIHOLE_MODEL_HPP
#define FORTI_PIHOLE_PIHOLE_MODEL_HPP

#include <nlohmann/json.hpp>

#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fph::pihole {

    inline constexpr int default_group_id = 0;

    struct Group {
        int id = 0;
        std::string name;
        std::optional<std::string> comment;
        bool enabled = true;
        std::int64_t date_added = 0;
        std::int64_t date_modified = 0;
    };

    // One row of Pi-hole's client table: `client` is an IP address, a CIDR subnet, a MAC address,
    // a hostname, or an interface written ":eth0" (clients.yaml, add_client).
    struct ClientEntry {
        int id = 0;
        std::string client;
        std::optional<std::string> comment;
        std::vector<int> groups;               // group ids, ascending
        std::optional<std::string> name;       // hostname FTL knows for it (read-only), when any
        std::int64_t date_added = 0;
        std::int64_t date_modified = 0;

        // Carries the ownership marker: forti-pihole created it and may change or remove it.
        [[nodiscard]] bool managed() const;
    };

    struct Version {
        int major = 0, minor = 0, patch = 0;

        // "v6.7.1", "6.7", "v6.4.3"; nullopt for anything else (development builds report e.g.
        // "vDev-1a2b3c4", custom branches null).
        [[nodiscard]] static std::optional<Version> parse(std::string_view text);
        [[nodiscard]] std::string to_string() const;
        auto operator<=>(const Version&) const = default;
    };

    struct ComponentVersion {
        std::optional<std::string> version;   // local version, e.g. "v6.7.1"; null on custom builds
        std::optional<std::string> branch;
        std::optional<std::string> hash;
    };

    // GET /api/info/version (info.yaml, components/schemas/version): the local versions.
    struct VersionInfo {
        ComponentVersion core, web, ftl;
        std::optional<std::string> docker;    // image tag when running in Docker
    };

    // The oldest FTL forti-pihole talks to. FTL serves the API, so its version is the one that counts.
    //
    // v6.7 (2026-07-06), from the FTL history:
    //   - duplicate items are reported as "The item is already present" (0c16b793); earlier releases
    //     leaked "UNIQUE constraint failed: ..." (handled too, but not relied on);
    //   - list items with CR/LF are rejected for every list type, including clients and groups
    //     (4c99a3a2, 5742884b; an item is echoed into the Location header), and so are non-string
    //     array items (03b940e7);
    //   - session hardening (a153cc09): FTL stops writing a wrong password to its debug log in plain
    //     text, compares SIDs in constant time, and can no longer hand out an empty SID;
    //   - group resolution uses the in-memory MAC when the network table lags (5c78a6aa, #2912):
    //     before it a MAC-based client entry silently fell back to the Default group for a while,
    //     which is not what resolve.hpp models;
    //   - since v6.6.1 a POST whose every item failed answers 400 instead of 201 (0fc7c8a8).
    // The maintainer's Pi-hole runs FTL v6.7.1; v6.8 changes nothing this module relies on.
    inline constexpr Version minimum_ftl_version{6, 7, 0};

    // Throws VersionError unless the FTL version is known and at least minimum_ftl_version.
    void check_supported(const VersionInfo& info);

    // Decoders: DecodeError when a required field is missing or has the wrong type.
    [[nodiscard]] Group decode_group(const nlohmann::json& json);
    [[nodiscard]] ClientEntry decode_client(const nlohmann::json& json);
    [[nodiscard]] std::vector<Group> decode_groups(const nlohmann::json& reply);         // {"groups": [...]}
    [[nodiscard]] std::vector<ClientEntry> decode_clients(const nlohmann::json& reply);  // {"clients": [...]}
    [[nodiscard]] VersionInfo decode_version(const nlohmann::json& reply);               // {"version": {...}}

    // POST/PUT replies carry {"processed": {"success": [{"item"}], "errors": [{"item", "error"}]}}
    // (clients.yaml, lists_processed). The error texts, empty when every item succeeded.
    [[nodiscard]] std::vector<std::string> processed_errors(const nlohmann::json& reply);

    // ---- client strings ----

    enum class ClientKind { ipv4, ipv6, subnet4, subnet6, mac, interface, hostname };

    [[nodiscard]] std::string_view to_string(ClientKind kind);

    // What a client string is, the way forti-pihole writes them; nullopt for strings Pi-hole would
    // reject or that cannot match anything (spaces, control characters, empty, ":" alone, an
    // out-of-range prefix length, a /0 subnet, which FTL never matches because subnet_match()
    // returns the prefix length and the lookup requires it to be > 0).
    [[nodiscard]] std::optional<ClientKind> classify_client(std::string_view client);

    // The one spelling forti-pihole writes for a client, so that its own comparisons are exact even
    // though Pi-hole's UNIQUE(ip) column is case-sensitive while its lookups are not:
    // addresses as inet_ntop prints them, subnets as network/prefix ("10.0.0.0/24", never
    // "10.0.0.7/24"), MACs as FTL prints them ("AA:BB:CC:DD:EE:FF", from any common spelling),
    // hostnames in lower case, interfaces unchanged. nullopt when classify_client() rejects it.
    [[nodiscard]] std::optional<std::string> canonical_client(std::string_view client);

    // "aa-bb-cc-dd-ee-ff", "AABB.CCDD.EEFF", "aabbccddeeff" -> "AA:BB:CC:DD:EE:FF"; nullopt otherwise.
    [[nodiscard]] std::optional<std::string> normalize_mac(std::string_view text);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_MODEL_HPP
