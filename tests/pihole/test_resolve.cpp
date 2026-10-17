// Client resolution: FTL's subnet_match() and get_client_groupids() precedence (resolve.hpp).

#include "pihole/resolve.hpp"

#include <gtest/gtest.h>

using namespace fph::pihole;

namespace {

    ClientEntry row(int id, std::string client, std::vector<int> groups) {
        ClientEntry entry;
        entry.id = id;
        entry.client = std::move(client);
        entry.groups = std::move(groups);
        entry.comment = "managed by forti-pihole";
        return entry;
    }

}  // namespace

TEST(PiholeSubnetMatch, ScoresThePrefixLength) {
    EXPECT_EQ(subnet_match("10.0.0.0/8", "10.1.2.3"), 8);
    EXPECT_EQ(subnet_match("10.1.0.0/16", "10.1.2.3"), 16);
    EXPECT_EQ(subnet_match("10.1.2.3", "10.1.2.3"), 32);          // a bare address is /32
    EXPECT_EQ(subnet_match("10.1.2.3/32", "10.1.2.3"), 32);
    EXPECT_EQ(subnet_match("10.1.2.4", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("10.2.0.0/16", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("10.0.0.7/24", "10.0.0.200"), 24);      // host bits of the row are masked off
    EXPECT_EQ(subnet_match("fd00::/64", "fd00::1"), 64);
    EXPECT_EQ(subnet_match("FD00::1", "fd00::1"), 128);
    EXPECT_EQ(subnet_match("fd00::/64", "fd00:0:0:1::1"), 0);
}

TEST(PiholeSubnetMatch, ZeroWhereFtlReturnsZero) {
    EXPECT_EQ(subnet_match("0.0.0.0/0", "10.1.2.3"), 0);           // the score is the length: /0 never wins
    EXPECT_EQ(subnet_match("::/0", "fd00::1"), 0);
    EXPECT_EQ(subnet_match("10.0.0.0/33", "10.1.2.3"), 0);         // out of range
    EXPECT_EQ(subnet_match("10.0.0.0/-1", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("/24", "10.1.2.3"), 0);                 // no address before '/'
    EXPECT_EQ(subnet_match("12:34:56:78:9A:BC", "10.1.2.3"), 0);   // isMAC() first
    EXPECT_EQ(subnet_match("tv.lan", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match(":eth0", "fd00::1"), 0);
    EXPECT_EQ(subnet_match(" 10.1.2.3", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("fe80::1%eth0", "fe80::1"), 0);       // glibc's inet_pton() takes no zone
    EXPECT_EQ(subnet_match("010.1.2.3", "10.1.2.3"), 0);         // nor leading zeros
    EXPECT_EQ(subnet_match("10.1.2.3", "not-an-ip"), 0);
    EXPECT_EQ(subnet_match("10.1.2.3", ""), 0);
}

TEST(PiholeSubnetMatch, FamiliesNeverMix) {
    // FTL decides the family by ':' in each string; it does not unmap IPv4-mapped IPv6 addresses.
    EXPECT_EQ(subnet_match("10.0.0.0/8", "::ffff:10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("::ffff:10.0.0.0/104", "::ffff:10.1.2.3"), 104);
    EXPECT_EQ(subnet_match("::ffff:10.1.2.3", "10.1.2.3"), 0);
    EXPECT_EQ(subnet_match("fd00::/8", "10.1.2.3"), 0);
}

TEST(PiholeSubnetMatch, ReadsTheLengthLikeSscanfPercentI) {
    // "%m[^/]/%i": octal and hex lengths, and a length that does not parse keeps the default (/32).
    EXPECT_EQ(subnet_match("10.0.0.0/010", "10.1.2.3"), 8);
    EXPECT_EQ(subnet_match("10.0.0.0/0x10", "10.0.2.3"), 16);
    EXPECT_EQ(subnet_match("10.0.0.0/abc", "10.0.0.0"), 32);
    EXPECT_EQ(subnet_match("10.0.0.0/abc", "10.0.0.1"), 0);
    EXPECT_EQ(subnet_match("10.0.0.0/ 24", "10.0.0.9"), 24);       // %i skips leading whitespace
}

TEST(PiholeResolve, LongestPrefixWinsAndAnExactAddressBeatsAnySubnet) {
    std::vector<ClientEntry> clients = {row(1, "10.0.0.0/8", {1}), row(2, "10.1.0.0/16", {2}),
                                        row(3, "10.1.2.0/28", {3}), row(4, "10.1.2.3", {4})};
    EXPECT_EQ(effective_groups(clients, "10.1.2.3"), (std::vector<int>{4}));
    EXPECT_EQ(effective_groups(clients, "10.1.2.4"), (std::vector<int>{3}));
    EXPECT_EQ(effective_groups(clients, "10.1.9.9"), (std::vector<int>{2}));
    EXPECT_EQ(effective_groups(clients, "10.9.9.9"), (std::vector<int>{1}));
    EXPECT_EQ(effective_groups(clients, "192.168.1.1"), (std::vector<int>{0}));   // no row: Default only

    // Order in the table does not matter, only the length.
    std::vector<ClientEntry> reversed(clients.rbegin(), clients.rend());
    EXPECT_EQ(effective_groups(reversed, "10.1.2.4"), (std::vector<int>{3}));

    auto resolution = resolve_client(clients, Observed{"10.1.2.4", "", "", ""});
    EXPECT_EQ(resolution.match, Match::address);
    EXPECT_EQ(resolution.entry_id, 3);
    EXPECT_EQ(resolution.entry, "10.1.2.0/28");
    EXPECT_EQ(resolution.prefix, 28);
    EXPECT_TRUE(resolution.tied.empty());
}

TEST(PiholeResolve, EqualLengthTiesGoToTheHighestId) {
    // "max(id) chosen_match_id ... GROUP BY matching_bits ORDER BY matching_bits DESC LIMIT 1".
    std::vector<ClientEntry> clients = {row(5, "10.0.0.0/24", {1}), row(9, "10.0.0.7/24", {2}),
                                        row(7, "10.0.0.128/24", {3}), row(2, "10.0.0.5/32", {4}), row(3, "10.0.0.5", {5})};
    auto resolution = resolve_client(clients, Observed{"10.0.0.9", "", "", ""});
    EXPECT_EQ(resolution.entry_id, 9);
    EXPECT_EQ(resolution.groups, (std::vector<int>{2}));
    EXPECT_EQ(resolution.tied, (std::vector<int>{5, 7}));
    // Two spellings of one address tie at /32 as well.
    auto exact = resolve_client(clients, Observed{"10.0.0.5", "", "", ""});
    EXPECT_EQ(exact.entry_id, 3);
    EXPECT_EQ(exact.tied, (std::vector<int>{2}));

    auto ambiguities = find_ambiguities(clients);
    ASSERT_EQ(ambiguities.size(), 4u);   // 5-9, 5-7, 9-7 and 2-3
    for (const auto& a: ambiguities) EXPECT_LT(a.first_id, a.second_id);
}

TEST(PiholeResolve, AddressRowsShadowMacHostnameAndInterfaceRows) {
    std::vector<ClientEntry> clients = {row(1, "10.0.0.0/24", {1}), row(2, "AA:BB:CC:DD:EE:FF", {2}),
                                        row(3, "tv.lan", {3}), row(4, ":eth0", {4})};
    Observed seen{"10.0.0.5", "aa:bb:cc:dd:ee:ff", "tv.lan", "eth0"};
    auto resolution = resolve_client(clients, seen);
    EXPECT_EQ(resolution.match, Match::address);
    EXPECT_EQ(resolution.groups, (std::vector<int>{1}));

    // Outside the subnet the MAC row applies, then the hostname, then the interface.
    seen.ip = "192.168.1.5";
    EXPECT_EQ(resolve_client(clients, seen).match, Match::mac);
    EXPECT_EQ(resolve_client(clients, seen).groups, (std::vector<int>{2}));
    seen.mac.clear();
    EXPECT_EQ(resolve_client(clients, seen).match, Match::hostname);
    seen.hostname.clear();
    EXPECT_EQ(resolve_client(clients, seen).match, Match::interface);
    EXPECT_EQ(resolve_client(clients, seen).groups, (std::vector<int>{4}));
    seen.interface.clear();
    EXPECT_EQ(resolve_client(clients, seen).match, Match::none);
}

TEST(PiholeResolve, MacRowsCompareAsTextIgnoringCase) {
    std::vector<ClientEntry> clients = {row(4, "aa:bb:cc:dd:ee:ff", {2}), row(6, "AA:BB:CC:DD:EE:FF", {3}),
                                        row(1, "11-22-33-44-55-66", {4})};
    // Both spellings match ("COLLATE NOCASE"); the table scan meets the lowest id first.
    EXPECT_EQ(effective_groups(clients, "192.168.1.5", "AA-BB-CC-DD-EE-FF"), (std::vector<int>{2}));
    // A dash-written row is not a MAC to FTL: it is compared to "11:22:33:44:55:66" and differs.
    EXPECT_EQ(effective_groups(clients, "192.168.1.5", "11:22:33:44:55:66"), (std::vector<int>{0}));
    // resolver.macNames = false skips the MAC step.
    auto resolution = resolve_client(clients, Observed{"192.168.1.5", "aa:bb:cc:dd:ee:ff", "", ""},
                                     ResolveOptions{.mac_names = false});
    EXPECT_EQ(resolution.match, Match::none);

    auto ambiguities = find_ambiguities(clients);
    ASSERT_EQ(ambiguities.size(), 1u);
    EXPECT_EQ(ambiguities[0].first_id, 4);
    EXPECT_EQ(ambiguities[0].second_id, 6);
}

TEST(PiholeResolve, HostnamesAreExactButCaseInsensitive) {
    std::vector<ClientEntry> clients = {row(1, "TV.lan", {2})};
    EXPECT_EQ(effective_groups(clients, "192.168.1.5", "", "tv.LAN"), (std::vector<int>{2}));
    EXPECT_EQ(effective_groups(clients, "192.168.1.5", "", "tv"), (std::vector<int>{0}));
    EXPECT_EQ(effective_groups(clients, "192.168.1.5", "", "tv.lan.home"), (std::vector<int>{0}));
}

TEST(PiholeResolve, AnEntryIsInExactlyItsGroups) {
    // The Default group is not implied for a matched entry; an empty set means no group at all.
    std::vector<ClientEntry> clients = {row(1, "10.0.0.1", {}), row(2, "10.0.0.2", {3, 1}), row(3, "10.0.0.3", {0, 2})};
    EXPECT_TRUE(effective_groups(clients, "10.0.0.1").empty());
    EXPECT_EQ(effective_groups(clients, "10.0.0.2"), (std::vector<int>{1, 3}));
    EXPECT_EQ(effective_groups(clients, "10.0.0.3"), (std::vector<int>{0, 2}));
    EXPECT_EQ(effective_groups(clients, "10.0.0.4"), (std::vector<int>{0}));
}

TEST(PiholeResolve, Ipv6QueriesIgnoreIpv4Rows) {
    std::vector<ClientEntry> clients = {row(1, "10.0.0.0/24", {1}), row(2, "fd00:10::/64", {2}),
                                        row(3, "AA:BB:CC:DD:EE:FF", {3})};
    EXPECT_EQ(effective_groups(clients, "fd00:10::5", "aa:bb:cc:dd:ee:ff"), (std::vector<int>{2}));
    EXPECT_EQ(effective_groups(clients, "fd00:99::5", "aa:bb:cc:dd:ee:ff"), (std::vector<int>{3}));
    EXPECT_EQ(effective_groups(clients, "::ffff:10.0.0.5"), (std::vector<int>{0}));
}

TEST(PiholeResolve, EnabledGroups) {
    std::vector<Group> groups = {{0, "Default", {}, true, 0, 0}, {1, "kids", {}, false, 0, 0}, {2, "iot", {}, true, 0, 0}};
    std::vector<int> ids = {0, 1, 2, 7};
    EXPECT_EQ(enabled_groups(ids, groups), (std::vector<int>{0, 2}));
}
