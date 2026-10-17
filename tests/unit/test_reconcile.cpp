// Reconciliation: first run, idempotence, moves, the change budget, retirement, fail-static
// behaviour on an empty inventory, and the connectivity check.

#include "fixture.hpp"

#include <classify.hpp>
#include <reconcile.hpp>

#include <algorithm>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;

    Changeset plan_for(FakeGateway& fake, const Config& config, const State& state = {}, int max_changes = 50) {
        auto snapshot = collect(fake, config, now);
        auto c = classify(snapshot, config, state, now);
        return reconcile(snapshot, c, config, state, now, max_changes);
    }

    // Applies the operations to the fake the way the engine would, and records what was written.
    void apply_to(FakeGateway& fake, const Changeset& changes, State& state) {
        auto id = fake.plan({{"operations", changes.operations}})["data"]["id"].get<std::string>();
        ASSERT_TRUE(fake.apply({{"plan_id", id}}).value("ok", false));
        for (const auto& [mac, w]: changes.written) {
            state.devices[mac].object = w.object;
            state.devices[mac].written_group = w.group;
        }
        for (const auto& mac: changes.retired) state.devices.erase(mac);
    }

    std::size_t count_ops(const Changeset& c, const std::string& op, const std::string& resource) {
        return std::ranges::count_if(c.operations, [&](const json& o) { return o["op"] == op && o["resource"] == resource; });
    }
}  // namespace

TEST(Reconcile, FirstRunCreatesGroupsAndObjects) {
    FakeGateway fake;
    populate(fake);
    auto changes = plan_for(fake, test_config());
    EXPECT_EQ(count_ops(changes, "create", "firewall/addrgrp"), 4u);   // every configured group
    EXPECT_EQ(count_ops(changes, "create", "firewall/address"), 6u);   // one object per device
    // Objects come first, then the groups that reference them.
    EXPECT_EQ(changes.operations.front()["resource"], "firewall/address");
    for (const auto& op: changes.operations) {
        if (op["op"] != "create") continue;
        EXPECT_TRUE(op["object"]["name"].get<std::string>().starts_with("fp-"));
        EXPECT_NE(op["object"]["comment"].get<std::string>().find(marker), std::string::npos);
    }
    State state;
    apply_to(fake, changes, state);
    auto iot = fake.members("fp-grp-iot_untrusted");
    EXPECT_EQ(iot.size(), 2u);
    EXPECT_EQ(fake.members("fp-grp-tvs").size(), 1u);
    EXPECT_EQ(fake.members("fp-grp-owner").size(), 0u);   // privileged: nothing inferred
    EXPECT_EQ(fake.members("fp-grp-default").size(), 3u);
}

TEST(Reconcile, IsIdempotent) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    auto again = plan_for(fake, config, state);
    EXPECT_TRUE(again.empty()) << again.operations.dump(2);
    EXPECT_TRUE(again.changes.empty());
}

TEST(Reconcile, PinMovesADeviceAndKeepsAdministratorMembers) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    // The operator also put an object of their own into the tvs group.
    fake.addresses["Projector"] = {{"name", "Projector"}, {"type", "ipmask"}, {"subnet", "192.0.2.99 255.255.255.255"}, {"comment", ""}};
    fake.addrgrps["fp-grp-tvs"]["member"].push_back({{"name", "Projector"}});
    state.devices[plug1].written_group = "iot_untrusted";
    state.pins[plug1] = {"tvs", "assign", now};
    auto changes = plan_for(fake, config, state);
    apply_to(fake, changes, state);
    auto tvs = fake.members("fp-grp-tvs");
    EXPECT_NE(std::ranges::find(tvs, "Projector"), tvs.end());
    EXPECT_EQ(fake.members("fp-grp-iot_untrusted").size(), 1u);
    EXPECT_EQ(tvs.size(), 3u);
    EXPECT_TRUE(plan_for(fake, config, state).empty());
}

TEST(Reconcile, ChangeBudgetDefersTheRest) {
    FakeGateway fake;
    populate(fake);
    auto changes = plan_for(fake, test_config(), {}, 2);
    EXPECT_EQ(changes.deferred.size(), 4u);
    EXPECT_EQ(count_ops(changes, "create", "firewall/address"), 2u);
    std::size_t placed = std::ranges::count_if(changes.changes, [](const Change& c) { return c.kind == "place"; });
    EXPECT_EQ(placed, 2u);
}

TEST(Reconcile, RetiresOnlyLongGoneManagedObjects) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    // The unknown device leaves; 31 days later its object goes.
    auto gone = mystery;
    remove_device(fake, gone);
    state.devices[gone].last_seen = now - 31 * 86400;
    auto changes = plan_for(fake, config, state);
    ASSERT_EQ(count_ops(changes, "delete", "firewall/address"), 1u);
    EXPECT_EQ(changes.retired, std::vector<std::string>{gone});
    apply_to(fake, changes, state);
    EXPECT_EQ(fake.members("fp-grp-default").size(), 2u);

    // Within the grace period nothing is retired.
    FakeGateway fresh;
    populate(fresh);
    State s2;
    apply_to(fresh, plan_for(fresh, config), s2);
    remove_device(fresh, gone);
    s2.devices[gone].last_seen = now - 5 * 86400;
    EXPECT_TRUE(plan_for(fresh, config, s2).empty());
}

TEST(Reconcile, EmptyInventoryChangesNothing) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    for (auto& [mac, r]: state.devices) r.last_seen = now - 400 * 86400;
    fake.devices = json::array();   // a failed or partial read, not a mass departure
    auto changes = plan_for(fake, config, state);
    EXPECT_EQ(count_ops(changes, "delete", "firewall/address"), 0u);
    EXPECT_TRUE(changes.empty());
}

TEST(Reconcile, RetirementKeepsObjectsUsedElsewhere) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    auto object = state.devices[mystery].object;
    // An administrator's policy references the managed object directly.
    fake.policies.push_back({{"policyid", 40}, {"name", "special"}, {"status", "enable"}, {"action", "accept"},
                             {"srcintf", json::array({{{"name", "internal"}}})}, {"dstintf", json::array({{{"name", "wan1"}}})},
                             {"srcaddr", json::array({{{"name", object}}})}, {"dstaddr", json::array({{{"name", "all"}}})},
                             {"service", json::array({{{"name", "ALL"}}})}, {"users", json::array()}, {"groups", json::array()}});
    remove_device(fake, mystery);
    state.devices[mystery].last_seen = now - 31 * 86400;
    auto changes = plan_for(fake, config, state);
    EXPECT_EQ(count_ops(changes, "delete", "firewall/address"), 0u);
    EXPECT_FALSE(changes.notes.empty());
}

TEST(Reconcile, ConnectivityCheckBlocksARouteLoss) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    apply_to(fake, plan_for(fake, config), state);
    // The operator has started using groups: only iot_untrusted may browse now.
    fake.policies = json::parse(R"([
        {"policyid": 12, "name": "DNS", "status": "enable", "action": "accept", "srcintf": [{"name": "internal"}],
         "dstintf": [{"name": "internal1"}], "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "DNS Server"}],
         "service": [{"name": "DNS"}], "users": [], "groups": []},
        {"policyid": 30, "name": "iot out", "status": "enable", "action": "accept", "srcintf": [{"name": "internal"}],
         "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "fp-grp-iot_untrusted"}], "dstaddr": [{"name": "all"}],
         "service": [{"name": "HTTPS"}], "users": [], "groups": []}
    ])");
    // Moving a plug to tvs would cut its internet: refused, it stays where it is.
    state.pins[plug1] = {"tvs", "assign", now};
    auto changes = plan_for(fake, config, state);
    ASSERT_EQ(changes.blocked.size(), 1u);
    EXPECT_EQ(changes.blocked[0].mac, plug1);
    EXPECT_EQ(changes.blocked[0].probe, "internet");
    EXPECT_TRUE(changes.empty()) << changes.operations.dump(2);
}

TEST(Reconcile, ObjectCommentsAreSanitized) {
    Device d;
    d.mac = plug1;
    d.hostname = "evil\"\nname\x1b[2J";
    d.vendor = "TP-Link";
    auto comment = object_comment(d);
    EXPECT_EQ(comment.find('\n'), std::string::npos);
    EXPECT_EQ(comment.find('\x1b'), std::string::npos);
    EXPECT_EQ(comment.find('"'), std::string::npos);
    EXPECT_LE(comment.size(), 255u);
    EXPECT_TRUE(comment.starts_with(marker));
}
