// DHCP address slicing: in place, reserve-without-moving, moves into a slice, foreign devices in a
// slice, and distinct targets for concurrent moves.

#include "fixture.hpp"

#include <classify.hpp>
#include <slicing.hpp>

#include <algorithm>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;

    Config slicing_config(json slices) {
        auto j = json::parse(R"({"groups": [
            {"name": "tvs", "pihole_group": "TV"}, {"name": "iot_untrusted", "pihole_group": "IOT"}, {"name": "default"}],
            "rules": [{"name": "plugs", "group": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}},
                      {"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}]})");
        j["networks"] = json::array({{{"interface", "internal"}, {"mode", "slices"}, {"slices", std::move(slices)}}});
        return Config::from_json(j);
    }

    void pool_and_leases(FakeGateway& fake) {
        fake.dhcp[0]["ip-range"] = json::parse(R"([{"id": 1, "start-ip": "192.0.2.2", "end-ip": "192.0.2.200"}])");
        fake.leases = json::array();
        for (const auto& d: fake.devices)
            fake.leases.push_back({{"ip", d["ipv4_address"]}, {"mac", d["mac"]}, {"interface", "internal"}, {"type", "ipv4"}});
    }

    SlicingPlan run_plan(FakeGateway& fake, const Config& config) {
        auto snapshot = collect(fake, config, now);
        auto c = classify(snapshot, config, {}, now);
        return plan_slicing(config, snapshot, c);
    }

    const SliceAction* action_for(const SlicingPlan& plan, std::string_view mac) {
        for (const auto& a: plan.actions)
            if (a.mac == mac) return &a;
        return nullptr;
    }
}  // namespace

TEST(Slicing, MovesMembersIntoTheirSlice) {
    FakeGateway fake;
    populate(fake);
    pool_and_leases(fake);
    auto plan = run_plan(fake, slicing_config(json::parse(R"([{"group": "tvs", "cidr": "192.0.2.208/28"},
                                                               {"group": "iot_untrusted", "cidr": "192.0.2.224/28"}])")));
    const SliceAction* s = action_for(plan, stick);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->kind, "move");
    EXPECT_EQ(s->from_ip, "192.0.2.13");
    EXPECT_EQ(s->to_ip, "192.0.2.208");
    EXPECT_EQ(s->slice, "192.0.2.208/28");
    // The two plugs move too, to distinct addresses.
    const SliceAction* p1 = action_for(plan, plug1);
    const SliceAction* p2 = action_for(plan, plug2);
    ASSERT_TRUE(p1 && p2);
    EXPECT_NE(p1->to_ip, p2->to_ip);
    // Devices of groups without a slice get no action.
    EXPECT_FALSE(action_for(plan, mystery));
}

TEST(Slicing, ReservesInPlaceWithoutMoving) {
    FakeGateway fake;
    populate(fake);
    for (auto& d: fake.devices)
        if (d["mac"] == stick) d["ipv4_address"] = "192.0.2.210";
    pool_and_leases(fake);
    auto config = slicing_config(json::parse(R"([{"group": "tvs", "cidr": "192.0.2.208/28"}])"));
    auto plan = run_plan(fake, config);
    const SliceAction* s = action_for(plan, stick);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->kind, "reserve");
    EXPECT_EQ(s->to_ip, "192.0.2.210");

    fake.dhcp[0]["reserved-address"] = json::parse(R"([{"id": 7, "type": "mac", "ip": "192.0.2.210", "mac": "00:00:5e:00:53:03",
                                                       "action": "reserved", "description": ""}])");
    plan = run_plan(fake, config);
    s = action_for(plan, stick);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->kind, "in-place");
    EXPECT_EQ(s->reservation_id, 7u);
    EXPECT_FALSE(s->reservation_managed);
}

TEST(Slicing, ForeignDevicesInASliceAreReportedNotMoved) {
    FakeGateway fake;
    populate(fake);
    for (auto& d: fake.devices)
        if (d["mac"] == mystery) d["ipv4_address"] = "192.0.2.212";   // statically configured, no lease
    pool_and_leases(fake);
    json kept = json::array();
    for (const auto& l: fake.leases)
        if (l["mac"] != mystery) kept.push_back(l);
    fake.leases = kept;
    auto plan = run_plan(fake, slicing_config(json::parse(R"([{"group": "tvs", "cidr": "192.0.2.208/28"}])")));
    EXPECT_FALSE(action_for(plan, mystery));
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) { return f.kind == "foreign-in-slice"; }));
    EXPECT_TRUE(std::ranges::any_of(plan.findings, [](const auto& f) { return f.kind == "conflict"; }));
    // The stick does not get the foreign device's address.
    const SliceAction* s = action_for(plan, stick);
    ASSERT_TRUE(s);
    EXPECT_NE(s->to_ip, "192.0.2.212");
}

TEST(Slicing, PlanInputReflectsTheNetwork) {
    FakeGateway fake;
    populate(fake);
    pool_and_leases(fake);
    fake.vips = json::parse(R"([{"name": "forward", "extintf": "wan1", "mappedip": [{"range": "192.0.2.240"}]}])");
    auto config = slicing_config(json::parse(R"([{"group": "tvs", "cidr": "192.0.2.208/28"}])"));
    auto snapshot = collect(fake, config, now);
    auto c = classify(snapshot, config, {}, now);
    auto input = plan_input(config, config.networks[0], snapshot, c);
    ASSERT_TRUE(input);
    EXPECT_EQ(input->network.str(), "192.0.2.0/24");
    EXPECT_EQ(input->pools.size(), 1u);
    EXPECT_EQ(input->existing.at("tvs").size(), 1u);
    // Requests for groups with members and a Pi-hole mapping: tvs (1) and iot_untrusted (2).
    ASSERT_EQ(input->requests.size(), 2u);
    auto proposal = alloc::propose(*input);
    EXPECT_TRUE(proposal.complete());
    for (const auto& s: proposal.slices) EXPECT_FALSE(s.cidr.contains(*alloc::parse_ipv4("192.0.2.240")));
}

TEST(Slicing, ComplementStrings) {
    auto rest = complement_strings("192.168.30.0/24", {"192.168.30.0/26"});
    EXPECT_EQ(rest, (std::vector<std::string>{"192.168.30.64/26", "192.168.30.128/25"}));
}
