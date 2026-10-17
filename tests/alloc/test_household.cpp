// The planner on a realistic household: one flat 192.168.1.0/24 on the FortiGate's LAN interface,
// gateway .1, one dynamic pool .2-.200, about twenty reservations scattered over .2-.54 and leases
// over .2-.55. Device names and MACs are made up (MACs from the RFC 7042 documentation block).

#include <alloc/cidr.hpp>
#include <alloc/plan.hpp>
#include <alloc/render.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <stdexcept>

using namespace fph::alloc;

namespace {

    Ipv4 lan(int host) {
        return 0xc0a80100u + static_cast<Ipv4>(host);   // 192.168.1.<host>
    }

    std::string mac(int n) {
        static const char* hex = "0123456789abcdef";
        return std::string("00:00:5e:00:53:") + hex[(n >> 4) & 0xf] + hex[n & 0xf];
    }

    struct Device {
        int host;
        const char* label;
        const char* group;   // "" when in no group
    };

    // Reserved devices: the TVs and IoT gear are group members, but today they all sit inside the
    // dynamic pool, so their slices have to be found elsewhere and the devices moved by the caller
    // (pick_address), one reservation at a time.
    constexpr Device reserved[] = {
        {2, "ap-upstairs", ""},   {3, "ap-downstairs", ""},  {5, "nas", ""},          {7, "printer", ""},
        {10, "tv-living", "tv"},  {11, "tv-bedroom", "tv"},  {12, "tv-office", "tv"}, {14, "apple-tv", "tv"},
        {17, "thermostat", "iot"}, {19, "doorbell", "iot"},  {21, "cam-front", "iot"}, {22, "cam-back", "iot"},
        {25, "plug-1", "iot"},    {26, "plug-2", "iot"},     {30, "hue-bridge", "iot"}, {33, "sonos-1", ""},
        {34, "sonos-2", ""},      {40, "xbox", ""},          {45, "laptop-work", ""},  {48, "desktop", ""},
        {54, "homepod", ""},
    };

    // Dynamic clients holding a lease right now.
    constexpr Device dynamic[] = {
        {4, "iphone-a", ""}, {6, "iphone-b", ""}, {8, "ipad", ""}, {9, "guest-android", ""},
        {13, "watch", ""},   {15, "kindle", ""},  {16, "macbook", ""}, {55, "guest-laptop", ""},
    };

    PlanInput household() {
        PlanInput input;
        input.network = *Cidr::parse("192.168.1.0/24");
        input.interface_ips = {lan(1)};
        input.pools = {{1, {lan(2), lan(200)}}};
        int n = 0;
        for (const auto& d: reserved) {
            input.occupancy.add({lan(d.host), Use::reservation, d.label, mac(++n), d.group});
            input.occupancy.add({lan(d.host), Use::lease, d.label, mac(n), d.group});
        }
        for (const auto& d: dynamic) input.occupancy.add({lan(d.host), Use::lease, d.label, mac(++n), d.group});
        // The NAS is published through a VIP and named by a host address object.
        input.occupancy.add({lan(5), Use::vip, "vip-nas-https", {}, {}});
        input.occupancy.add({lan(5), Use::address_object, "h-nas", {}, {}});
        Request tv;
        tv.group = "tv";
        tv.expected = 6;   // 9 addresses -> /28
        Request iot;
        iot.group = "iot";
        iot.expected = 8;   // 12 addresses -> /28
        input.requests = {tv, iot};
        return input;
    }

    std::vector<std::string> strs(const std::vector<Slice>& slices) {
        std::vector<std::string> out;
        for (const auto& s: slices) out.push_back(s.group + " " + s.cidr.str());
        return out;
    }

    const GroupPlan& plan_of(const Proposal& p, std::string_view group) {
        for (const auto& g: p.groups)
            if (g.group == group) return g;
        throw std::runtime_error("no group " + std::string(group));
    }

}  // namespace

TEST(Household, SlicesOnlyAboveThePool) {
    auto input = household();
    auto p = propose(input);
    EXPECT_TRUE(p.complete());
    EXPECT_TRUE(p.pool_changes.empty());
    EXPECT_TRUE(p.conflicts.empty());
    EXPECT_EQ(strs(p.slices), (std::vector<std::string>{"iot 192.168.1.208/28", "tv 192.168.1.224/28"}));
    for (const auto& s: p.slices) {
        EXPECT_FALSE(s.retained);
        EXPECT_GE(s.cidr.first(), lan(201)) << s.cidr.str();
        EXPECT_LE(s.cidr.last(), lan(254)) << s.cidr.str();
    }
    EXPECT_TRUE(check(input, p.slices).empty());
    EXPECT_EQ(plan_of(p, "tv").capacity, 16u);
    EXPECT_EQ(plan_of(p, "iot").capacity, 16u);
    EXPECT_EQ(p.utilization.overall.total, 32u);
    EXPECT_EQ(p.utilization.overall.used, 0u);   // nobody has moved in yet
}

TEST(Household, MovingDevicesIntoTheirSlices) {
    auto input = household();
    auto p = propose(input);
    auto occupancy = input.effective_occupancy();
    // Each TV gets the next free address of its slice; its old address in the pool is not inside
    // the slice, so it is not kept.
    const Cidr tv = *Cidr::parse("192.168.1.224/28");
    std::vector<Ipv4> given;
    int n = 0;
    for (const auto& d: reserved) {
        ++n;
        if (std::string_view(d.group) != "tv") continue;
        auto address = pick_address(input.network, tv, occupancy, lan(d.host), mac(n));
        ASSERT_TRUE(address);
        given.push_back(*address);
        occupancy.add({*address, Use::reservation, d.label, mac(n), "tv"});
    }
    EXPECT_EQ(given, (std::vector<Ipv4>{lan(224), lan(225), lan(226), lan(227)}));
    // Planning again with the slices in place and the members moved keeps everything.
    input.existing["tv"] = {tv};
    input.existing["iot"] = {*Cidr::parse("192.168.1.208/28")};
    input.occupancy = occupancy;
    auto again = propose(input);
    for (const auto& s: again.slices) EXPECT_TRUE(s.retained);
    EXPECT_EQ(strs(again.slices), strs(p.slices));
    EXPECT_TRUE(again.conflicts.empty());
    EXPECT_EQ(again.utilization.overall.used, 4u);
}

TEST(Household, MoreThanFitsProposesShrinkingThePool) {
    auto input = household();
    Request kids;
    kids.group = "kids";
    kids.expected = 30;   // 45 addresses -> /26: .201-.254 has no /26
    input.requests.push_back(kids);
    auto p = propose(input);
    EXPECT_FALSE(p.complete());
    EXPECT_TRUE(p.pool_changes.empty());   // not allowed: alternatives only
    EXPECT_EQ(strs(p.slices), (std::vector<std::string>{"iot 192.168.1.208/28", "tv 192.168.1.224/28"}));
    const auto& g = plan_of(p, "kids");
    EXPECT_EQ(g.missing, 45u);
    ASSERT_FALSE(g.alternatives.empty());
    // Nothing smaller fits either (only .240/28 and scraps are left), so the best ways are pool
    // changes that disturb nobody: shrinking the pool to .2-.127 (the top of the pool is unused).
    const auto& best = g.alternatives.front();
    EXPECT_EQ(best.kind, Alternative::Kind::shrink_pool);
    EXPECT_TRUE(best.disturbed.empty());
    ASSERT_TRUE(best.pool_change);
    EXPECT_EQ(best.pool_change->pool_id, 1);
    EXPECT_EQ(best.pool_change->result, (Range{lan(2), lan(127)}));
    EXPECT_EQ(best.slices, std::vector<Cidr>{*Cidr::parse("192.168.1.128/26")});
    EXPECT_EQ(best.detail, "shrink pool 1 from 192.168.1.2-192.168.1.200 to 192.168.1.2-192.168.1.127 to free 192.168.1.128/26");
    // Shrinking from the bottom would hit reservations and every lease: never proposed as free.
    for (const auto& alt: g.alternatives) {
        if (alt.pool_change && alt.pool_change->kind == PoolChange::Kind::shrink && alt.pool_change->result.lo != lan(2)) {
            EXPECT_FALSE(alt.disturbed.empty()) << alt.detail;
        }
    }

    // Allowed to propose pool changes, the planner takes that shrink itself.
    input.policy.allow_pool_changes = true;
    auto allowed = propose(input);
    EXPECT_TRUE(allowed.complete());
    ASSERT_EQ(allowed.pool_changes.size(), 1u);
    EXPECT_EQ(allowed.pool_changes[0].result, (Range{lan(2), lan(127)}));
    EXPECT_EQ(strs(allowed.slices),
              (std::vector<std::string>{"kids 192.168.1.128/26", "iot 192.168.1.208/28", "tv 192.168.1.224/28"}));
    EXPECT_TRUE(check(with_pool_changes(input, allowed.pool_changes), allowed.slices).empty());
    EXPECT_FALSE(check(input, allowed.slices).empty());   // without the change the kids slice is in the pool
}

TEST(Household, SmallerHeadroomIsTheCheapestFix) {
    // Later, with the TV and IoT slices in place, a guest group arrives.
    auto input = household();
    input.existing["iot"] = {*Cidr::parse("192.168.1.208/28")};
    input.existing["tv"] = {*Cidr::parse("192.168.1.224/28")};
    Request guests;
    guests.group = "guests";
    guests.expected = 12;   // 18 addresses -> /27, which no longer fits; 12 fit .240/28 (15 usable)
    input.requests.push_back(guests);
    auto p = propose(input);
    const auto& g = plan_of(p, "guests");
    ASSERT_GT(g.missing, 0u);
    ASSERT_FALSE(g.alternatives.empty());
    EXPECT_EQ(g.alternatives.front().kind, Alternative::Kind::reduce_headroom);
    EXPECT_EQ(g.alternatives.front().slices, std::vector<Cidr>{*Cidr::parse("192.168.1.240/28")});
    EXPECT_TRUE(g.alternatives.front().disturbed.empty());
    for (const auto& s: p.slices) EXPECT_TRUE(s.retained);   // the TV and IoT slices did not move
}

TEST(Household, PiHoleComplementCoversTheRest) {
    auto input = household();
    auto p = propose(input);
    std::vector<Cidr> slices;
    for (const auto& s: p.slices) slices.push_back(s.cidr);
    auto rest = complement(input.network, slices);
    std::vector<std::string> blocks;
    for (const auto& b: rest) blocks.push_back(b.str());
    EXPECT_EQ(blocks, (std::vector<std::string>{"192.168.1.0/25", "192.168.1.128/26", "192.168.1.192/28", "192.168.1.240/28"}));
    for (int host = 0; host < 256; ++host) {
        int hits = 0;
        for (const auto& c: slices) hits += c.contains(lan(host));
        for (const auto& c: rest) hits += c.contains(lan(host));
        EXPECT_EQ(hits, 1) << host;
    }
}

TEST(Household, JsonForTheCli) {
    auto j = to_json(propose(household()));
    EXPECT_EQ(j["network"], "192.168.1.0/24");
    EXPECT_EQ(j["complete"], true);
    ASSERT_EQ(j["slices"].size(), 2u);
    EXPECT_EQ(j["slices"][0]["group"], "iot");
    EXPECT_EQ(j["slices"][0]["cidr"], "192.168.1.208/28");
    EXPECT_EQ(j["slices"][0]["origin"], "new");
    EXPECT_EQ(j["slices"][0]["first"], "192.168.1.208");
    EXPECT_EQ(j["slices"][0]["last"], "192.168.1.223");
    EXPECT_EQ(j["slices"][1]["cidr"], "192.168.1.224/28");
    EXPECT_EQ(j["groups"][1]["group"], "tv");
    EXPECT_EQ(j["groups"][1]["needed"], 9);
    EXPECT_EQ(j["groups"][1]["capacity"], 16);
}
