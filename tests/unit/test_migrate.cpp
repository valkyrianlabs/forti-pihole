// Address migrations: what is refused and why, the step order, and the engine operations.

#include "fixture.hpp"

#include <classify.hpp>
#include <migrate.hpp>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;

    struct Scene {
        FakeGateway fake;
        Config config = Config::from_json(json::parse(R"({"groups": [{"name": "tvs", "pihole_group": "TV"}, {"name": "default"}],
            "rules": [{"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}],
            "networks": [{"interface": "internal", "mode": "slices", "slices": [{"group": "tvs", "cidr": "192.0.2.208/28"}]}]})"));

        Scene() {
            populate(fake);
            fake.dhcp[0]["ip-range"] = json::parse(R"([{"id": 1, "start-ip": "192.0.2.2", "end-ip": "192.0.2.200"}])");
            fake.dhcp[0]["reserved-address"] = json::parse(R"([{"id": 12, "type": "mac", "ip": "192.0.2.13", "mac": "00:00:5e:00:53:03",
                                                               "action": "reserved", "description": ""}])");
            for (const auto& d: fake.devices)
                fake.leases.push_back({{"ip", d["ipv4_address"]}, {"mac", d["mac"]}, {"interface", "internal"}, {"type", "ipv4"}});
            // The household shape: the stick's IP object in "TVs", the group in an ALL policy.
            fake.addresses["Stick IP"] = {{"name", "Stick IP"}, {"type", "ipmask"}, {"subnet", "192.0.2.13 255.255.255.255"}, {"comment", ""}};
            fake.addrgrps["TVs"] = addrgrp("TVs", {"Stick IP"});
            fake.policies.insert(fake.policies.begin(),
                                 json{{"policyid", 17}, {"name", "Important Devices"}, {"status", "enable"}, {"action", "accept"},
                                      {"srcintf", json::array({{{"name", "internal"}}})}, {"dstintf", json::array({{{"name", "wan1"}}})},
                                      {"srcaddr", json::array({{{"name", "TVs"}}})}, {"dstaddr", json::array({{{"name", "all"}}})},
                                      {"service", json::array({{{"name", "ALL"}}})}, {"users", json::array()}, {"groups", json::array()}});
        }

        SliceAction stick_move() {
            auto snapshot = collect(fake, config, now);
            auto c = classify(snapshot, config, {}, now);
            auto plan = plan_slicing(config, snapshot, c);
            for (const auto& a: plan.actions)
                if (a.mac == stick) return a;
            throw std::runtime_error("no action for the stick");
        }

        MigrationPlan migrate(const Adoptions& adoptions) {
            auto action = stick_move();
            return plan_migration(config, collect(fake, config, now), action, adoptions, now);
        }
    };
}  // namespace

TEST(Migrate, RefusesWithoutAdoptingTheReservationAndPrivilegedObjects) {
    Scene s;
    auto action = s.stick_move();
    EXPECT_EQ(action.kind, "move");
    EXPECT_EQ(action.reservation_id, 12u);

    auto plan = s.migrate({});
    EXPECT_FALSE(plan.operation);
    EXPECT_NE(plan.refusal.reason.find("reservation 12"), std::string::npos);

    Adoptions reservation_only;
    reservation_only.reservation = true;
    plan = s.migrate(reservation_only);
    EXPECT_FALSE(plan.operation);
    ASSERT_EQ(plan.refusal.needs.size(), 1u);
    EXPECT_NE(plan.refusal.needs[0].find("Stick IP"), std::string::npos);
    EXPECT_NE(plan.refusal.needs[0].find("17"), std::string::npos);
}

TEST(Migrate, StepsInSafeOrder) {
    Scene s;
    Adoptions adopt;
    adopt.reservation = true;
    adopt.address_objects = {"Stick IP"};
    auto plan = s.migrate(adopt);
    ASSERT_TRUE(plan.operation) << plan.refusal.reason;
    std::vector<std::string> ids;
    for (const auto& step: plan.operation->steps) ids.push_back(step.id);
    // Objects follow the device BEFORE the old lease is released.
    EXPECT_EQ(ids, (std::vector<std::string>{"pihole", "reservation", "objects", "revoke", "observe", "verify"}));
    EXPECT_EQ(plan.before.internet.policy, 17u);

    const auto& reservation = plan.operation->step("reservation")->forward["operations"][0];
    EXPECT_EQ(reservation["op"], "update");
    EXPECT_EQ(reservation["child"], "reserved-address");
    EXPECT_EQ(reservation["parent"], "1");
    EXPECT_EQ(reservation["key"], "12");
    EXPECT_EQ(reservation["set"]["ip"], "192.0.2.208");
    EXPECT_NE(reservation["set"]["description"].get<std::string>().find(marker), std::string::npos);

    const auto& objects = plan.operation->step("objects")->forward["operations"][0];
    EXPECT_EQ(objects["key"], "Stick IP");
    EXPECT_EQ(objects["set"]["subnet"], "192.0.2.208 255.255.255.255");

    const auto& revoke = plan.operation->step("revoke")->forward["operation"];
    EXPECT_EQ(revoke["resource"], "monitor/system/dhcp/revoke");
    EXPECT_EQ(revoke["body"]["ip"][0], "192.0.2.13");
}

TEST(Migrate, NewReservationWhenTheDeviceHasNone) {
    Scene s;
    s.fake.dhcp[0]["reserved-address"] = json::array();
    s.fake.addrgrps.erase("TVs");
    auto plan = s.migrate({});
    ASSERT_TRUE(plan.operation) << plan.refusal.reason;
    const auto& op = plan.operation->step("reservation")->forward["operations"][0];
    EXPECT_EQ(op["op"], "create");
    EXPECT_EQ(op["object"]["mac"], stick);
    EXPECT_EQ(op["object"]["id"], 0);
    EXPECT_FALSE(plan.operation->step("objects"));   // nothing privileged by address
    EXPECT_FALSE(plan.notes.empty());                // but the leftover host object is reported
}

TEST(Migrate, VipsAndOccupiedTargetsRefuse) {
    Scene s;
    Adoptions adopt;
    adopt.reservation = true;
    adopt.address_objects = {"Stick IP"};
    s.fake.vips = json::parse(R"([{"name": "stream-forward", "extintf": "wan1", "mappedip": [{"range": "192.0.2.13"}]}])");
    auto plan = s.migrate(adopt);
    EXPECT_FALSE(plan.operation);
    EXPECT_NE(plan.refusal.reason.find("VIP"), std::string::npos);

    Scene t;
    auto action = t.stick_move();
    action.to_ip = "192.0.2.11";   // a plug's address
    plan = plan_migration(t.config, collect(t.fake, t.config, now), action, adopt, now);
    EXPECT_FALSE(plan.operation);
    EXPECT_NE(plan.refusal.reason.find("in use"), std::string::npos);
}
