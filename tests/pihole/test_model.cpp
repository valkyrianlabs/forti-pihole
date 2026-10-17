// Decoding Pi-hole replies, the version gate and client strings.

#include "pihole/error.hpp"
#include "pihole/marker.hpp"
#include "pihole/model.hpp"

#include <gtest/gtest.h>

using namespace fph::pihole;
using nlohmann::json;

TEST(PiholeModel, DecodesGroupsAsTheSpecificationShowsThem) {
    // groups.yaml, components/examples/groups
    auto reply = json::parse(R"({"groups": [
        {"name": "Default", "comment": "The default group", "enabled": true, "id": 0,
         "date_added": 1594670974, "date_modified": 1611157897},
        {"name": "a", "comment": null, "enabled": true, "id": 5, "date_added": 1604871899, "date_modified": 1604871899}],
        "took": 0.003, "processed": null})");
    auto groups = decode_groups(reply);
    ASSERT_EQ(groups.size(), 2u);
    EXPECT_EQ(groups[0].id, default_group_id);
    EXPECT_EQ(groups[0].name, "Default");
    EXPECT_EQ(groups[0].comment, "The default group");
    EXPECT_TRUE(groups[0].enabled);
    EXPECT_EQ(groups[1].id, 5);
    EXPECT_FALSE(groups[1].comment.has_value());
    EXPECT_EQ(groups[1].date_added, 1604871899);
}

TEST(PiholeModel, DecodesClientsTheWayFtlEmitsThem) {
    // As list.c api_list_read() writes a row: "name" is "" when FTL knows none, "groups" is always
    // there (the specification's example omits it), possibly empty, ascending by group id.
    auto reply = json::parse(R"({"clients": [
        {"client": "10.0.0.0/24", "name": "", "comment": "managed by forti-pihole: segment iot",
         "groups": [3, 1], "id": 7, "date_added": 1700000000, "date_modified": 1700000001},
        {"client": "AA:BB:CC:DD:EE:FF", "name": "tv.lan", "comment": null, "groups": [], "id": 8,
         "date_added": 1, "date_modified": 2}], "took": 0.01})");
    auto clients = decode_clients(reply);
    ASSERT_EQ(clients.size(), 2u);
    EXPECT_EQ(clients[0].client, "10.0.0.0/24");
    EXPECT_FALSE(clients[0].name.has_value());
    EXPECT_EQ(clients[0].groups, (std::vector<int>{1, 3}));
    EXPECT_TRUE(clients[0].managed());
    EXPECT_EQ(clients[1].name, "tv.lan");
    EXPECT_TRUE(clients[1].groups.empty());
    EXPECT_FALSE(clients[1].managed());
}

TEST(PiholeModel, RefusesClientsWithoutAGroupSet) {
    // A missing set is neither "no group" nor "Default": guessing would misreport what applies.
    auto reply = json::parse(R"({"clients": [{"client": "10.0.0.1", "comment": null, "id": 1}]})");
    EXPECT_THROW((void) decode_clients(reply), DecodeError);
    EXPECT_THROW((void) decode_clients(json::parse(R"({"clients": [{"client": "x", "id": 1, "groups": ["0"]}]})")),
                 DecodeError);
    EXPECT_THROW((void) decode_clients(json::parse(R"({"clients": {}})")), DecodeError);
    EXPECT_THROW((void) decode_groups(json::parse(R"({"groups": [{"name": "x"}]})")), DecodeError);
    EXPECT_THROW((void) decode_groups(json::parse(R"([])")), DecodeError);
}

TEST(PiholeModel, ManagedMeansTheCommentCarriesTheMarker) {
    ClientEntry entry;
    EXPECT_FALSE(entry.managed());
    entry.comment = "kids' tablet";
    EXPECT_FALSE(entry.managed());
    entry.comment = std::string(fph::ownership_marker);
    EXPECT_TRUE(entry.managed());
    entry.comment = "managed by forti-pihole: segment kids";
    EXPECT_TRUE(entry.managed());
    entry.comment = "Managed By Forti-Pihole";   // the marker is exact text
    EXPECT_FALSE(entry.managed());
}

TEST(PiholeModel, DecodesVersions) {
    auto reply = json::parse(R"({"version": {
        "core": {"local": {"branch": "master", "version": "v6.4.3", "hash": "a1b2"}, "remote": {"version": "v6.4.3"}},
        "web": {"local": {"branch": "master", "version": "v6.6", "hash": null}},
        "ftl": {"local": {"branch": "master", "version": "v6.7.1", "hash": "c9d0", "date": "2026-09-19"}},
        "docker": {"local": null, "remote": null}}, "took": 0.001})");
    auto info = decode_version(reply);
    EXPECT_EQ(info.core.version, "v6.4.3");
    EXPECT_EQ(info.web.version, "v6.6");
    EXPECT_FALSE(info.web.hash.has_value());
    EXPECT_EQ(info.ftl.version, "v6.7.1");
    EXPECT_EQ(info.ftl.branch, "master");
    EXPECT_FALSE(info.docker.has_value());
    EXPECT_NO_THROW(check_supported(info));
    EXPECT_THROW((void) decode_version(json::parse(R"({"took": 1})")), DecodeError);
}

TEST(PiholeModel, ParsesVersions) {
    EXPECT_EQ(Version::parse("v6.7.1"), (Version{6, 7, 1}));
    EXPECT_EQ(Version::parse("6.7"), (Version{6, 7, 0}));
    EXPECT_EQ(Version::parse("v6.8"), (Version{6, 8, 0}));
    EXPECT_EQ(Version::parse("v6.7.1-12-gabcdef"), (Version{6, 7, 1}));
    EXPECT_FALSE(Version::parse("vDev-1a2b3c4").has_value());
    EXPECT_FALSE(Version::parse("").has_value());
    EXPECT_FALSE(Version::parse("v6").has_value());
    EXPECT_FALSE(Version::parse("v6.").has_value());
    EXPECT_FALSE(Version::parse("v6.7.1.2").has_value());
    EXPECT_FALSE(Version::parse("six").has_value());
    EXPECT_LT((Version{6, 6, 2}), minimum_ftl_version);
    EXPECT_EQ(minimum_ftl_version.to_string(), "v6.7.0");
}

TEST(PiholeModel, TheVersionGateRefusesOldAndUnknownFtl) {
    auto with = [](std::optional<std::string> ftl) {
        VersionInfo info;
        info.ftl.version = std::move(ftl);
        return info;
    };
    EXPECT_NO_THROW(check_supported(with("v6.7")));
    EXPECT_NO_THROW(check_supported(with("v6.7.1")));
    EXPECT_NO_THROW(check_supported(with("v6.8")));
    EXPECT_NO_THROW(check_supported(with("v7.0")));
    EXPECT_THROW(check_supported(with("v6.6.2")), VersionError);
    EXPECT_THROW(check_supported(with("v6.0")), VersionError);
    EXPECT_THROW(check_supported(with("v5.25.2")), VersionError);
    EXPECT_THROW(check_supported(with("vDev-1a2b3c4")), VersionError);
    EXPECT_THROW(check_supported(with(std::nullopt)), VersionError);
    try {
        check_supported(with("v6.4.3"));
        FAIL();
    } catch (const VersionError& error) {
        EXPECT_NE(std::string(error.what()).find("older than v6.7.0"), std::string::npos) << error.what();
    }
}

TEST(PiholeModel, ProcessedErrors) {
    EXPECT_TRUE(processed_errors(json::parse(R"({"processed": null})")).empty());
    EXPECT_TRUE(processed_errors(json::parse(R"({"processed": {"errors": [], "success": [{"item": "a"}]}})")).empty());
    auto errors = processed_errors(json::parse(
            R"({"processed": {"errors": [{"item": "10.0.0.1", "error": "The item is already present"}], "success": []}})"));
    ASSERT_EQ(errors.size(), 1u);
    EXPECT_TRUE(is_duplicate_message(errors[0]));
    EXPECT_TRUE(is_duplicate_message("UNIQUE constraint failed: client.ip"));   // before FTL v6.7
    EXPECT_FALSE(is_duplicate_message("FOREIGN KEY constraint failed"));
}

TEST(PiholeModel, ClassifiesClientStrings) {
    EXPECT_EQ(classify_client("192.168.2.5"), ClientKind::ipv4);
    EXPECT_EQ(classify_client("::1"), ClientKind::ipv6);
    EXPECT_EQ(classify_client("fd00::5"), ClientKind::ipv6);
    EXPECT_EQ(classify_client("192.168.2.0/24"), ClientKind::subnet4);
    EXPECT_EQ(classify_client("fd00:1::/64"), ClientKind::subnet6);
    EXPECT_EQ(classify_client("12:34:56:78:9A:BC"), ClientKind::mac);
    EXPECT_EQ(classify_client(":eth0"), ClientKind::interface);
    EXPECT_EQ(classify_client(":eth0.20"), ClientKind::interface);
    EXPECT_EQ(classify_client("localhost"), ClientKind::hostname);
    EXPECT_EQ(classify_client("tv.lan"), ClientKind::hostname);

    EXPECT_FALSE(classify_client("").has_value());
    EXPECT_FALSE(classify_client("10.0.0.1 ").has_value());        // FTL: no spaces or tabs
    EXPECT_FALSE(classify_client("a\tb").has_value());
    EXPECT_FALSE(classify_client("host\r\nX-Injected: 1").has_value());
    EXPECT_FALSE(classify_client("0.0.0.0/0").has_value());        // never matches in FTL
    EXPECT_FALSE(classify_client("10.0.0.0/33").has_value());
    EXPECT_FALSE(classify_client("10.0.0.0/010").has_value());     // FTL would read octal 8
    EXPECT_FALSE(classify_client("10.0.0.0/").has_value());
    EXPECT_FALSE(classify_client("/24").has_value());
    EXPECT_FALSE(classify_client("fe80::1%eth0").has_value());
    EXPECT_FALSE(classify_client(":").has_value());
    EXPECT_FALSE(classify_client("a..b").has_value());
}

TEST(PiholeModel, CanonicalClientStrings) {
    EXPECT_EQ(canonical_client("10.0.0.7/24"), "10.0.0.0/24");
    EXPECT_EQ(canonical_client("10.0.0.5/32"), "10.0.0.5");      // a full-length prefix is the address
    EXPECT_EQ(canonical_client("FD00:0:0::1"), "fd00::1");
    EXPECT_EQ(canonical_client("fd00:1:2:3:4::/64"), "fd00:1:2:3::/64");
    EXPECT_EQ(canonical_client("fd00::1/128"), "fd00::1");
    EXPECT_EQ(canonical_client("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(canonical_client("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(canonical_client("TV.Lan"), "tv.lan");
    EXPECT_EQ(canonical_client(":eth0"), ":eth0");
    EXPECT_FALSE(canonical_client("aa:bb-cc:dd:ee:ff").has_value());
}

TEST(PiholeModel, NormalizesMacs) {
    EXPECT_EQ(normalize_mac("12:34:56:78:9a:bc"), "12:34:56:78:9A:BC");
    EXPECT_EQ(normalize_mac("12-34-56-78-9A-BC"), "12:34:56:78:9A:BC");
    EXPECT_FALSE(normalize_mac("12:34-56:78:9a:bc").has_value());   // mixed separators
    EXPECT_FALSE(normalize_mac("123456789abc").has_value());        // a hostname to Pi-hole
    EXPECT_FALSE(normalize_mac("1234.5678.9abc").has_value());
    EXPECT_FALSE(normalize_mac("12:34:56:78:9a:bg").has_value());
    EXPECT_FALSE(normalize_mac("").has_value());
}
