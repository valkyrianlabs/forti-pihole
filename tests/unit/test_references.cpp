// What refers to an address: host objects through nested groups into policies, ranges, subnets,
// VIPs, reservations and leases.

#include "fixture.hpp"

#include <references.hpp>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;
}

TEST(References, HostObjectThroughNestedGroupsIntoAPolicy) {
    FakeGateway fake;
    populate(fake);
    // Like a household's "Important Devices": a TV's IP object inside "TVs", used by an ALL policy.
    fake.addresses["Stick IP"] = {{"name", "Stick IP"}, {"type", "ipmask"}, {"subnet", "192.0.2.13 255.255.255.255"}, {"comment", ""}};
    fake.addresses["Stick MAC"] = mac_address("Stick MAC", stick);
    fake.addrgrps["TVs"] = addrgrp("TVs", {"Stick IP"});
    fake.addrgrps["Important"] = addrgrp("Important", {"TVs", "Stick MAC"});
    fake.policies.push_back({{"policyid", 17}, {"name", "Important Devices"}, {"status", "enable"}, {"action", "accept"},
                             {"srcintf", json::array({{{"name", "internal"}}})}, {"dstintf", json::array({{{"name", "wan1"}}})},
                             {"srcaddr", json::array({{{"name", "Important"}}})}, {"dstaddr", json::array({{{"name", "all"}}})},
                             {"service", json::array({{{"name", "ALL"}}})}, {"users", json::array()}, {"groups", json::array()}});
    fake.vips = json::parse(R"([{"name": "game-forward", "extintf": "wan1", "mappedip": [{"range": "192.0.2.13"}]}])");
    fake.dhcp[0]["reserved-address"] = json::parse(R"([{"id": 12, "type": "mac", "ip": "192.0.2.13", "mac": "00:00:5e:00:53:03",
                                                       "action": "reserved", "description": ""}])");
    fake.leases = json::parse(R"([{"ip": "192.0.2.13", "mac": "00:00:5e:00:53:03", "interface": "internal", "type": "ipv4"}])");
    auto snapshot = collect(fake, test_config(), now);
    auto refs = references_to(snapshot, "192.0.2.13");

    ASSERT_FALSE(refs.empty());
    EXPECT_EQ(refs.front().kind, "host");
    EXPECT_EQ(refs.front().name, "Stick IP");
    ASSERT_EQ(refs.front().policies.size(), 1u);
    EXPECT_EQ(refs.front().policies[0].id, 17u);
    EXPECT_TRUE(refs.front().policies[0].source);
    EXPECT_EQ(refs.front().policies[0].via, (std::vector<std::string>{"Important", "TVs"}));

    auto kinds = [&](const std::string& kind) { return std::ranges::count_if(refs, [&](const auto& r) { return r.kind == kind; }); };
    EXPECT_EQ(kinds("subnet"), 1);        // LAN, used by the DNS and LAN-out policies
    EXPECT_EQ(kinds("vip"), 1);
    EXPECT_EQ(kinds("reservation"), 1);
    EXPECT_EQ(kinds("lease"), 1);

    auto privileged = privileged_hosts(refs);
    ASSERT_EQ(privileged.size(), 1u);
    EXPECT_EQ(privileged[0]->name, "Stick IP");
}

TEST(References, NothingForAFreeAddress) {
    FakeGateway fake;
    populate(fake);
    auto snapshot = collect(fake, test_config(), now);
    auto refs = references_to(snapshot, "192.0.2.226");
    EXPECT_TRUE(privileged_hosts(refs).empty());
    EXPECT_EQ(std::ranges::count_if(refs, [](const auto& r) { return r.kind != "subnet"; }), 0);
    EXPECT_TRUE(references_to(snapshot, "not-an-ip").empty());
}
