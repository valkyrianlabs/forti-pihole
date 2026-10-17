// The Pi-hole side of a sync: desired CIDR client entries per network strategy, and the plan from
// what Pi-hole has, without touching operator entries.

#include "fixture.hpp"

#include <pihole_sync.hpp>

#include <algorithm>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;

    Config config_with(json networks) {
        auto j = json::parse(R"({"groups": [
            {"name": "trusted", "privileged": true, "pihole_group": "Owner"},
            {"name": "tvs", "pihole_group": "TV"},
            {"name": "iot", "pihole_group": "IOT"},
            {"name": "default"}]})");
        j["networks"] = std::move(networks);
        return Config::from_json(j);
    }

    PiholeView household() {
        PiholeView view;
        view.groups = {{0, "Default", true}, {1, "Work", true}, {2, "TV", true}, {4, "Owner", true}, {5, "IOT", true}};
        view.clients = {{4, "192.0.2.13", "living room tv", {2}}, {11, "00:00:5E:00:53:66", "Mac Studio", {4}}};
        return view;
    }

    Snapshot snapshot_with_vlan() {
        FakeGateway fake;
        populate(fake);
        fake.interfaces.push_back({{"name", "vlan30"}, {"type", "vlan"}, {"role", "lan"}, {"ip", "198.51.100.129 255.255.255.128"},
                                   {"interface", "internal"}, {"vlanid", 30}, {"secondaryip", json::array()}});
        return collect(fake, Config::from_json(json::parse(R"({"networks": [{"interface": "internal"}], "groups": [{"name": "default"}]})")), now);
    }
}  // namespace

TEST(PiholeSync, CidrNormalization) {
    EXPECT_EQ(to_cidr("192.168.1.1 255.255.255.0"), "192.168.1.0/24");
    EXPECT_EQ(to_cidr("192.168.1.208/28"), "192.168.1.208/28");
    EXPECT_EQ(to_cidr("10.0.0.1 255.0.255.0"), "");   // not a contiguous mask
    EXPECT_EQ(to_cidr("0.0.0.0 0.0.0.0"), "");        // an interface without an address
}

TEST(PiholeSync, SlicesCreateManagedEntriesAndReportShadows) {
    auto config = config_with(json::parse(R"([{"interface": "internal", "mode": "slices",
        "slices": [{"group": "tvs", "cidr": "192.0.2.0/28"}, {"group": "trusted", "cidr": "192.0.2.224/28"}]}])"));
    auto plan = plan_pihole(config, snapshot_with_vlan(), household(), {});
    ASSERT_EQ(plan.changes.size(), 2u);
    EXPECT_EQ(plan.changes[0].kind, "create");
    EXPECT_EQ(plan.changes[0].cidr, "192.0.2.0/28");
    EXPECT_EQ(plan.changes[0].group_ids, std::vector<int>{2});
    EXPECT_NE(plan.changes[0].comment.find(marker), std::string::npos);
    EXPECT_EQ(plan.changes[1].group_ids, std::vector<int>{4});
    auto has = [&](const std::string& kind) {
        return std::ranges::any_of(plan.findings, [&](const auto& f) { return f.kind == kind; });
    };
    EXPECT_TRUE(has("unmanaged-shadow"));   // the per-device 192.0.2.13 entry overrides the tvs slice
    EXPECT_TRUE(has("mac-client"));         // MAC entries never match routed clients
}

TEST(PiholeSync, IdempotentWhenInPlace) {
    auto config = config_with(json::parse(R"([{"interface": "internal", "mode": "slices", "slices": [{"group": "tvs", "cidr": "192.0.2.0/28"}]}])"));
    auto view = household();
    view.clients.push_back({20, "192.0.2.0/28", std::string(marker) + ": internal slice tvs", {2}});
    auto plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    EXPECT_TRUE(plan.empty());
    // Someone re-pointed the managed entry: put back.
    view.clients.back().groups = {5};
    plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    ASSERT_EQ(plan.changes.size(), 1u);
    EXPECT_EQ(plan.changes[0].kind, "update");
    EXPECT_EQ(plan.changes[0].client_id, 20);
}

TEST(PiholeSync, OperatorEntriesForTheSameCidrWin) {
    auto config = config_with(json::parse(R"([{"interface": "internal", "mode": "slices", "slices": [{"group": "tvs", "cidr": "192.0.2.0/28"}]}])"));
    auto view = household();
    view.clients.push_back({30, "192.0.2.0/28", "my own", {5}});
    auto plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    EXPECT_TRUE(plan.empty());
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) { return f.kind == "unmanaged-overlap" && f.client_id == 30; }));
}

TEST(PiholeSync, StaleManagedEntriesNeedPrune) {
    auto config = config_with(json::parse(R"([{"interface": "internal", "mode": "observe"}])"));
    auto view = household();
    view.clients.push_back({20, "192.0.2.0/28", std::string(marker) + ": internal slice tvs", {2}});
    auto plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    EXPECT_TRUE(plan.empty());
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) { return f.kind == "stale-managed"; }));
    PiholeSyncOptions prune;
    prune.prune = true;
    plan = plan_pihole(config, snapshot_with_vlan(), view, prune);
    ASSERT_EQ(plan.changes.size(), 1u);
    EXPECT_EQ(plan.changes[0].kind, "delete");
}

TEST(PiholeSync, SubnetModeAndMissingGroups) {
    auto config = config_with(json::parse(R"([{"interface": "vlan30", "mode": "subnet", "group": "iot"}])"));
    auto plan = plan_pihole(config, snapshot_with_vlan(), household(), {});
    ASSERT_EQ(plan.changes.size(), 1u);
    EXPECT_EQ(plan.changes[0].cidr, "198.51.100.128/25");
    EXPECT_EQ(plan.changes[0].group_ids, std::vector<int>{5});

    auto view = household();
    std::erase_if(view.groups, [](const auto& g) { return g.name == "IOT"; });
    plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    EXPECT_TRUE(plan.empty());   // never invents a filtering group
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) { return f.kind == "missing-group"; }));
}

TEST(PiholeSync, HybridUsesTheComplementUnlessMostSpecificWins) {
    auto config = config_with(json::parse(R"([{"interface": "vlan30", "mode": "hybrid", "group": "iot",
        "slices": [{"group": "tvs", "cidr": "198.51.100.128/26"}]}])"));
    PiholeSyncOptions options;
    options.complement = [](const std::string& network, const std::vector<std::string>& slices) {
        EXPECT_EQ(network, "198.51.100.128/25");
        EXPECT_EQ(slices, std::vector<std::string>{"198.51.100.128/26"});
        return std::vector<std::string>{"198.51.100.192/26"};
    };
    auto plan = plan_pihole(config, snapshot_with_vlan(), household(), options);
    std::vector<std::string> cidrs;
    for (const auto& c: plan.changes) cidrs.push_back(c.cidr + "->" + c.pihole_group);
    EXPECT_EQ(cidrs, (std::vector<std::string>{"198.51.100.128/26->TV", "198.51.100.192/26->IOT"}));

    options.most_specific_wins = true;
    plan = plan_pihole(config, snapshot_with_vlan(), household(), options);
    cidrs.clear();
    for (const auto& c: plan.changes) cidrs.push_back(c.cidr + "->" + c.pihole_group);
    EXPECT_EQ(cidrs, (std::vector<std::string>{"198.51.100.128/26->TV", "198.51.100.128/25->IOT"}));
}

TEST(PiholeSync, ChangedSubnetReplacesItsOwnEntry) {
    // vlan30 moved from 198.51.100.0/25 to 198.51.100.128/25: the managed entry follows.
    auto config = config_with(json::parse(R"([{"interface": "vlan30", "mode": "subnet", "group": "iot"}])"));
    auto view = household();
    view.clients.push_back({40, "198.51.100.0/25", std::string(marker) + ": vlan30 subnet", {5}});
    auto plan = plan_pihole(config, snapshot_with_vlan(), view, {});
    std::vector<std::string> kinds;
    for (const auto& c: plan.changes) kinds.push_back(c.kind + " " + c.cidr);
    EXPECT_EQ(kinds, (std::vector<std::string>{"create 198.51.100.128/25", "delete 198.51.100.0/25"}));
}

TEST(PiholeSync, SuggestsUnconfiguredNetworks) {
    FakeGateway fake;
    populate(fake);
    fake.interfaces.push_back({{"name", "vlan40"}, {"type", "vlan"}, {"role", "lan"}, {"ip", "203.0.113.1 255.255.255.0"},
                               {"interface", "internal"}, {"vlanid", 40}, {"secondaryip", json::array()}});
    fake.dhcp.push_back({{"id", 4}, {"interface", "vlan40"}, {"dns-service", "specify"}, {"dns-server1", "198.51.100.2"}});
    auto config = config_with(json::parse(R"([{"interface": "internal", "mode": "observe"}])"));
    auto plan = plan_pihole(config, collect(fake, config, now), household(), {});
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) {
        return f.kind == "new-network" && f.client == "vlan40" && f.detail.find("subnet") != std::string::npos;
    }));
}
