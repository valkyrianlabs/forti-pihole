// The allocation planner (src/alloc/plan.hpp) on small made-up networks: sizing, alignment, best fit,
// retention, growth, shortfalls and their alternatives, validation, address selection, utilization,
// rendering and determinism.

#include <alloc/plan.hpp>
#include <alloc/render.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <random>
#include <stdexcept>

using namespace fph::alloc;

namespace {

    Ipv4 ip(std::string_view text) {
        auto parsed = parse_ipv4(text);
        EXPECT_TRUE(parsed) << text;
        return parsed.value_or(0);
    }

    Cidr cidr(std::string_view text) {
        auto parsed = Cidr::parse(text);
        EXPECT_TRUE(parsed) << text;
        return parsed.value_or(Cidr{});
    }

    Range range(std::string_view text) {
        auto parsed = Range::parse(text);
        EXPECT_TRUE(parsed) << text;
        return parsed.value_or(Range{});
    }

    // 10.0.0.0/24, gateway .1, one dynamic pool .1xx as given.
    PlanInput lan(std::string_view pool = "10.0.0.2-10.0.0.127") {
        PlanInput input;
        input.network = cidr("10.0.0.0/24");
        input.interface_ips = {ip("10.0.0.1")};
        input.pools = {{1, range(pool)}};
        return input;
    }

    Request request(std::string group, std::uint64_t expected, double headroom = 1.5) {
        Request r;
        r.group = std::move(group);
        r.expected = expected;
        r.headroom = headroom;
        return r;
    }

    std::vector<std::string> slices_of(const Proposal& p, const std::string& group) {
        std::vector<std::string> out;
        for (const auto& s: p.slices)
            if (s.group == group) out.push_back(s.cidr.str());
        return out;
    }

    const GroupPlan& plan_of(const Proposal& p, std::string_view group) {
        for (const auto& g: p.groups)
            if (g.group == group) return g;
        throw std::runtime_error("no group " + std::string(group));
    }

    std::vector<ConflictKind> kinds(const std::vector<Conflict>& conflicts) {
        std::vector<ConflictKind> out;
        for (const auto& c: conflicts) out.push_back(c.kind);
        return out;
    }

    Occupant occupant(std::string_view at, Use use, std::string label, std::string group = {}, std::string mac = {}) {
        return {ip(at), use, std::move(label), std::move(mac), std::move(group)};
    }

    // New slices must be clean against the input (with any proposed pool changes made).
    void expect_new_slices_clean(const PlanInput& input, const Proposal& p) {
        auto changed = with_pool_changes(input, p.pool_changes);
        std::vector<Slice> fresh;
        for (const auto& s: p.slices)
            if (!s.retained) fresh.push_back(s);
        std::vector<Slice> all = p.slices;
        for (const auto& c: check(changed, all))
            EXPECT_TRUE(c.slice.retained) << "new slice conflict: " << c.detail;
        for (const auto& s: fresh) EXPECT_EQ(Cidr::parse(s.cidr.str()), s.cidr) << "unaligned " << s.cidr.str();
    }

}  // namespace

TEST(Sizing, SmallestBlockForExpectedTimesHeadroom) {
    struct Case {
        std::uint64_t expected;
        double headroom;
        int prefix;
    };
    for (auto c: {Case{6, 1.5, 28}, Case{10, 1.5, 28}, Case{11, 1.5, 27}, Case{1, 1.5, 30}, Case{0, 1.5, 30}, Case{2, 1.0, 30},
                  Case{3, 1.5, 29}, Case{8, 1.0, 29}, Case{9, 1.0, 28}, Case{10, 1.1, 28}, Case{40, 1.5, 26}}) {
        auto input = lan();
        input.requests = {request("g", c.expected, c.headroom)};
        auto p = propose(input);
        ASSERT_EQ(p.slices.size(), 1u) << c.expected;
        EXPECT_EQ(p.slices[0].cidr.prefix, c.prefix) << c.expected << " x " << c.headroom;
        EXPECT_FALSE(p.slices[0].retained);
        EXPECT_TRUE(p.complete());
        EXPECT_EQ(plan_of(p, "g").needed, std::max<std::uint64_t>({c.expected, 1, static_cast<std::uint64_t>(std::ceil(c.expected * c.headroom - 1e-9))}));
        expect_new_slices_clean(input, p);
    }
}

TEST(Sizing, PrefixBounds) {
    auto input = lan();
    auto r = request("g", 1);
    r.max_prefix = 28;   // never smaller than a /28
    input.requests = {r};
    EXPECT_EQ(slices_of(propose(input), "g"), std::vector<std::string>{"10.0.0.128/28"});

    // Never larger than a /29: 20 devices x 1.5 = 30 addresses become four /29s.
    r = request("g", 20);
    r.min_prefix = 29;
    input.requests = {r};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "g"), (std::vector<std::string>{"10.0.0.128/29", "10.0.0.136/29", "10.0.0.144/29", "10.0.0.152/29"}));
    EXPECT_EQ(plan_of(p, "g").capacity, 32u);
    expect_new_slices_clean(input, p);
}

TEST(Sizing, RefusesMalformedRequests) {
    auto input = lan();
    input.requests = {request("g", 1), request("g", 2)};
    EXPECT_THROW(propose(input), std::invalid_argument);
    input.requests = {request("g", 1, 0.5)};
    EXPECT_THROW(propose(input), std::invalid_argument);
    input.requests = {request("g", 1, std::nan(""))};
    EXPECT_THROW(propose(input), std::invalid_argument);
    input.requests = {request("", 1)};
    EXPECT_THROW(propose(input), std::invalid_argument);
    auto r = request("g", 1);
    r.max_prefix = 31;
    input.requests = {r};
    EXPECT_THROW(propose(input), std::invalid_argument);
    r = request("g", 1);
    r.min_prefix = 23;   // larger than the network
    input.requests = {r};
    EXPECT_THROW(propose(input), std::invalid_argument);
    r = request("g", 1);
    r.min_prefix = 29;
    r.max_prefix = 28;
    input.requests = {r};
    EXPECT_THROW(propose(input), std::invalid_argument);
}

TEST(Allocation, StaysOutOfPoolsInterfaceAndForeignAddresses) {
    // Pool .2-.127; foreign addresses scattered over the top half.
    auto input = lan();
    input.interface_ips.push_back(ip("10.0.0.129"));   // a secondary IP
    input.occupancy.add(occupant("10.0.0.140", Use::vip, "vip-nas"));
    input.occupancy.add(occupant("10.0.0.150", Use::address_object, "h-printer"));
    input.occupancy.add(occupant("10.0.0.170", Use::static_device, "nas"));
    input.occupancy.add(occupant("10.0.0.200", Use::reservation, "laptop", {}, "00:00:5e:00:53:10"));
    input.requests = {request("g", 6)};
    auto p = propose(input);
    // .128/28 holds .129, .140; .144/28 holds .150; .160/28 is the first clean /28, .176/28 lies in
    // a snugger free block (.171-.191 covers .176/28 exactly), so best fit takes that.
    EXPECT_EQ(slices_of(p, "g"), std::vector<std::string>{"10.0.0.176/28"});
    expect_new_slices_clean(input, p);
}

TEST(Allocation, BestFitKeepsLargeBlocksWhole) {
    // Free: .192/28 (a snug hole) and .128/26 (a big one), everything else taken by the pool.
    auto input = lan("10.0.0.2-10.0.0.127");
    input.pools.push_back({2, range("10.0.0.208-10.0.0.254")});
    input.requests = {request("small", 6)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "small"), std::vector<std::string>{"10.0.0.192/28"});

    // And a later /26 request still has its block.
    input.requests = {request("small", 6), request("big", 40)};
    p = propose(input);
    EXPECT_EQ(slices_of(p, "small"), std::vector<std::string>{"10.0.0.192/28"});
    EXPECT_EQ(slices_of(p, "big"), std::vector<std::string>{"10.0.0.128/26"});
    EXPECT_TRUE(p.complete());
}

TEST(Allocation, LargestRequestFirstWhateverTheOrder) {
    // Free: .128/26 and .192/27. A /27 and a /26 request fit only if the /26 goes first.
    auto input = lan("10.0.0.2-10.0.0.127");
    input.pools.push_back({2, range("10.0.0.224-10.0.0.254")});
    input.requests = {request("mid", 15), request("big", 40)};
    auto a = propose(input);
    std::reverse(input.requests.begin(), input.requests.end());
    auto b = propose(input);
    EXPECT_EQ(to_json(a), to_json(b));
    EXPECT_EQ(slices_of(a, "big"), std::vector<std::string>{"10.0.0.128/26"});
    EXPECT_EQ(slices_of(a, "mid"), std::vector<std::string>{"10.0.0.192/27"});
    EXPECT_TRUE(a.complete());
}

TEST(Allocation, ExcludeRangesMakePoolSpaceUsable) {
    auto input = lan("10.0.0.2-10.0.0.254");
    input.excludes = {range("10.0.0.240-10.0.0.254")};
    input.requests = {request("g", 4)};   // 6 -> /29
    auto p = propose(input);
    // .240/29 and .248/29 are excluded; .248/29 holds the broadcast but 7 >= 6 usable. Best fit
    // inside the .240/28 container: .240/29 first.
    EXPECT_EQ(slices_of(p, "g"), std::vector<std::string>{"10.0.0.240/29"});
    expect_new_slices_clean(input, p);
}

TEST(Allocation, EdgeBlockMustStillCoverTheNeed) {
    // Only .240/28 is free, and it loses the broadcast: 15 usable. A need of 16 does not fit there.
    auto input = lan("10.0.0.2-10.0.0.239");
    input.requests = {request("g", 16, 1.0)};
    auto p = propose(input);
    EXPECT_TRUE(p.slices.empty());
    EXPECT_EQ(plan_of(p, "g").missing, 16u);
    input.requests = {request("g", 15, 1.0)};
    EXPECT_EQ(slices_of(propose(input), "g"), std::vector<std::string>{"10.0.0.240/28"});
}

TEST(Allocation, GroupMembersDoNotBlockTheirOwnSlice) {
    // A TV already reserved at .130 (outside the pool) may end up inside the TV slice; the
    // printer's reservation keeps the TV slice away from .144/28.
    auto input = lan();
    input.occupancy.add(occupant("10.0.0.130", Use::reservation, "tv-living", "tv", "00:00:5e:00:53:20"));
    input.occupancy.add(occupant("10.0.0.150", Use::reservation, "printer", {}, "00:00:5e:00:53:21"));
    input.requests = {request("tv", 6)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "tv"), std::vector<std::string>{"10.0.0.128/28"});
    EXPECT_TRUE(check(input, p.slices).empty());

    input.requests = {request("iot", 6)};
    EXPECT_EQ(slices_of(propose(input), "iot"), std::vector<std::string>{"10.0.0.160/28"});
}

TEST(Retention, KeepsValidExistingSlicesAsTheyAre) {
    auto input = lan();
    // A layout an optimizer would not choose (a /28 in the middle of the free space).
    input.existing["tv"] = {cidr("10.0.0.176/28")};
    input.occupancy.add(occupant("10.0.0.177", Use::reservation, "tv-1", "tv", "00:00:5e:00:53:30"));
    input.requests = {request("tv", 6), request("iot", 6)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "tv"), std::vector<std::string>{"10.0.0.176/28"});
    EXPECT_TRUE(p.slices[0].retained || p.slices[1].retained);
    for (const auto& s: p.slices) EXPECT_EQ(s.retained, s.group == "tv");
    // Best fit around the retained slice: .160/28 is a free block of exactly the right size.
    EXPECT_EQ(slices_of(p, "iot"), std::vector<std::string>{"10.0.0.160/28"});
    EXPECT_TRUE(p.conflicts.empty());
    EXPECT_EQ(plan_of(p, "tv").capacity, 16u);
    // Existing groups without a request are retained too.
    input.requests = {};
    EXPECT_EQ(slices_of(propose(input), "tv"), std::vector<std::string>{"10.0.0.176/28"});
}

TEST(Retention, ConflictedSlicesStayAndAreReported) {
    auto input = lan();
    // Overlaps the pool (.120-.127) and holds someone else's lease: reported, not moved, since its
    // devices hold reservations there.
    input.existing["cam"] = {cidr("10.0.0.120/29")};
    input.occupancy.add(occupant("10.0.0.121", Use::lease, "phone-guest", {}, "02:00:5e:00:53:40"));
    input.requests = {request("cam", 2)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "cam"), std::vector<std::string>{"10.0.0.120/29"});
    EXPECT_EQ(kinds(p.conflicts), (std::vector<ConflictKind>{ConflictKind::dynamic_pool, ConflictKind::foreign_occupant}));
    EXPECT_EQ(p.conflicts[0].label, "pool 1");
    EXPECT_EQ(p.conflicts[0].range, range("10.0.0.120-10.0.0.127"));
    EXPECT_EQ(p.conflicts[1].label, "phone-guest");
    // Capacity is 8 less the foreign lease: 7 >= 3, nothing new.
    EXPECT_EQ(plan_of(p, "cam").capacity, 7u);
    EXPECT_TRUE(p.complete());
}

TEST(Retention, OverlappingExistingSlicesAreBothKept) {
    auto input = lan();
    input.existing["tv"] = {cidr("10.0.0.128/28")};
    input.existing["cam"] = {cidr("10.0.0.136/29")};
    // A camera reserved in the overlap is foreign to the tv slice, at home in its own.
    input.occupancy.add(occupant("10.0.0.137", Use::reservation, "cam-1", "cam"));
    input.requests = {request("tv", 4), request("cam", 2)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "tv"), std::vector<std::string>{"10.0.0.128/28"});
    EXPECT_EQ(kinds(p.conflicts), (std::vector<ConflictKind>{ConflictKind::slice_overlap, ConflictKind::foreign_occupant}));
    EXPECT_EQ(p.conflicts[1].detail, "10.0.0.128/28 (tv) contains reservation cam-1 (10.0.0.137) of group cam");
    // Contested addresses count for neither group. The tv keeps 16 - 8 = 8 >= 6, so nothing new;
    // the cam slice lies wholly inside the tv slice, so the cameras get a clean /30 besides it
    // (the existing one stays: its camera holds a reservation there).
    EXPECT_EQ(plan_of(p, "tv").capacity, 8u);
    EXPECT_EQ(slices_of(p, "cam"), (std::vector<std::string>{"10.0.0.136/29", "10.0.0.144/30"}));
    EXPECT_EQ(plan_of(p, "cam").capacity, 4u);
    EXPECT_TRUE(p.complete());
}

TEST(Retention, DropsSlicesOutsideTheNetwork) {
    auto input = lan();
    input.existing["old"] = {cidr("10.0.1.0/28"), cidr("10.0.0.128/28"), cidr("10.0.0.128/28")};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "old"), std::vector<std::string>{"10.0.0.128/28"});   // duplicates collapse
    ASSERT_EQ(p.dropped.size(), 1u);
    EXPECT_EQ(p.dropped[0].cidr.str(), "10.0.1.0/28");
    EXPECT_EQ(kinds(p.conflicts), std::vector<ConflictKind>{ConflictKind::outside_network});
}

TEST(Growth, AddsASliceInsteadOfMovingEveryone) {
    auto input = lan();
    input.existing["tv"] = {cidr("10.0.0.136/29")};
    for (int i = 0; i < 6; ++i)
        input.occupancy.add(occupant("10.0.0." + std::to_string(136 + i), Use::reservation, "tv-" + std::to_string(i), "tv"));
    // 8 TVs x 1.5 = 12 > 8: four more addresses -> one /30 next to the rest, best fit.
    input.requests = {request("tv", 8)};
    auto p = propose(input);
    EXPECT_EQ(slices_of(p, "tv"), (std::vector<std::string>{"10.0.0.128/30", "10.0.0.136/29"}));
    EXPECT_EQ(plan_of(p, "tv").capacity, 12u);
    EXPECT_TRUE(p.complete());
    expect_new_slices_clean(input, p);

    // Growing further adds another slice; the existing two stay.
    input.existing["tv"] = {cidr("10.0.0.136/29"), cidr("10.0.0.128/30")};
    input.requests = {request("tv", 20)};   // 30 needed, 12 held: 18 more -> /27
    p = propose(input);
    EXPECT_EQ(slices_of(p, "tv"), (std::vector<std::string>{"10.0.0.128/30", "10.0.0.136/29", "10.0.0.160/27"}));
    EXPECT_EQ(plan_of(p, "tv").capacity, 44u);
}

TEST(Shortfall, ReportsAndRanksAlternatives) {
    // Pool .2-.223, free .224-.255 (.224/27 with the broadcast). Reservation at .60, leases low in
    // the pool.
    auto input = lan("10.0.0.2-10.0.0.223");
    input.occupancy.add(occupant("10.0.0.60", Use::reservation, "nas", {}, "00:00:5e:00:53:50"));
    input.occupancy.add(occupant("10.0.0.60", Use::lease, "nas", {}, "00:00:5e:00:53:50"));
    input.occupancy.add(occupant("10.0.0.10", Use::lease, "phone-a", {}, "02:00:5e:00:53:51"));
    input.occupancy.add(occupant("10.0.0.11", Use::lease, "phone-b", {}, "02:00:5e:00:53:52"));
    input.requests = {request("guests", 30)};   // 45 -> /26
    auto p = propose(input);
    EXPECT_FALSE(p.complete());
    const auto& g = plan_of(p, "guests");
    EXPECT_EQ(g.needed, 45u);
    EXPECT_EQ(g.capacity, 0u);
    EXPECT_EQ(g.missing, 45u);
    EXPECT_TRUE(p.slices.empty());
    ASSERT_FALSE(g.alternatives.empty());

    std::vector<std::string> details;
    for (const auto& alt: g.alternatives) details.push_back(alt.detail);
    // Headroom 1: 30 addresses fit the /27 at .224 (31 usable). Shrinking from the top frees .192/26
    // and disturbs nobody; an exclude-range does the same. Shrinking from the bottom would have
    // to cross the NAS reservation's neighbourhood and move the phones' leases: ranked last.
    ASSERT_GE(g.alternatives.size(), 4u);
    EXPECT_EQ(g.alternatives[0].kind, Alternative::Kind::reduce_headroom);
    EXPECT_EQ(g.alternatives[0].slices, std::vector<Cidr>{cidr("10.0.0.224/27")});
    EXPECT_EQ(g.alternatives[1].kind, Alternative::Kind::shrink_pool);
    EXPECT_EQ(g.alternatives[1].detail, "shrink pool 1 from 10.0.0.2-10.0.0.223 to 10.0.0.2-10.0.0.191 to free 10.0.0.192/26");
    ASSERT_TRUE(g.alternatives[1].pool_change);
    EXPECT_EQ(g.alternatives[1].pool_change->result, range("10.0.0.2-10.0.0.191"));
    EXPECT_TRUE(g.alternatives[1].disturbed.empty());
    EXPECT_EQ(g.alternatives[2].kind, Alternative::Kind::exclude_range);
    EXPECT_EQ(g.alternatives[2].detail, "add exclude-range 10.0.0.192-10.0.0.223 to pool 1 to free 10.0.0.192/26");
    const auto& last = g.alternatives.back();
    EXPECT_EQ(last.kind, Alternative::Kind::shrink_pool);
    EXPECT_EQ(last.disturbed, (std::vector<std::string>{"phone-a", "phone-b"}));   // the NAS is reserved: not disturbed
    EXPECT_NE(last.detail.find("moving 2 dynamic leases"), std::string::npos) << last.detail;
    for (std::size_t i = 1; i < g.alternatives.size(); ++i)
        EXPECT_LE(g.alternatives[i - 1].disturbed.size(), g.alternatives[i].disturbed.size()) << details[i];

    // Each pool alternative, carried out, gives a clean slice.
    for (const auto& alt: g.alternatives) {
        if (!alt.pool_change) continue;
        auto changed = with_pool_changes(input, std::vector<PoolChange>{*alt.pool_change});
        std::vector<Slice> slices;
        for (const auto& c: alt.slices) slices.push_back({"guests", c, false});
        for (const auto& c: check(changed, slices)) EXPECT_EQ(c.kind, ConflictKind::foreign_occupant) << alt.detail << ": " << c.detail;
    }
}

TEST(Shortfall, SplitOverFragmentedSpace) {
    // Free: .128/29 and .192/28, both outside the pools. A need of 20 has no /27, but the /28 plus
    // a best-fit /30 for the remaining 4 cover it.
    auto input = lan("10.0.0.2-10.0.0.127");
    input.pools.push_back({2, range("10.0.0.136-10.0.0.191")});
    input.pools.push_back({3, range("10.0.0.208-10.0.0.254")});
    input.requests = {request("g", 20, 1.0)};
    auto p = propose(input);
    const auto& g = plan_of(p, "g");
    ASSERT_EQ(g.missing, 20u);
    auto split = std::find_if(g.alternatives.begin(), g.alternatives.end(), [](const Alternative& a) { return a.kind == Alternative::Kind::split; });
    ASSERT_NE(split, g.alternatives.end());
    EXPECT_EQ(split->slices, (std::vector<Cidr>{cidr("10.0.0.128/30"), cidr("10.0.0.192/28")}));
    EXPECT_TRUE(split->disturbed.empty());
    EXPECT_EQ(g.alternatives.front().kind, Alternative::Kind::split);   // nothing to disturb, no pool change
}

TEST(Policy, PoolChangesInThePlanWhenAllowed) {
    auto input = lan("10.0.0.2-10.0.0.223");
    input.occupancy.add(occupant("10.0.0.10", Use::lease, "phone-a"));
    input.requests = {request("guests", 30)};
    input.policy.allow_pool_changes = true;
    auto p = propose(input);
    EXPECT_TRUE(p.complete());
    EXPECT_EQ(slices_of(p, "guests"), std::vector<std::string>{"10.0.0.192/26"});
    ASSERT_EQ(p.pool_changes.size(), 1u);
    EXPECT_EQ(p.pool_changes[0].kind, PoolChange::Kind::shrink);
    EXPECT_EQ(p.pool_changes[0].result, range("10.0.0.2-10.0.0.191"));
    // The input is untouched (nothing is applied), and the plan is clean once the change is made.
    EXPECT_EQ(input.pools[0].range, range("10.0.0.2-10.0.0.223"));
    EXPECT_FALSE(check(input, p.slices).empty());
    expect_new_slices_clean(input, p);
}

TEST(Policy, NeverDisplacesLeasesOnItsOwn) {
    // Every way to free a /26 moves a dynamic lease: stays an alternative even when allowed.
    auto input = lan("10.0.0.2-10.0.0.254");
    for (int i = 0; i < 4; ++i) input.occupancy.add(occupant("10.0.0." + std::to_string(40 + 64 * i), Use::lease, "l" + std::to_string(i)));
    input.requests = {request("g", 30)};
    input.policy.allow_pool_changes = true;
    auto p = propose(input);
    EXPECT_TRUE(p.slices.empty());
    EXPECT_TRUE(p.pool_changes.empty());
    const auto& g = plan_of(p, "g");
    ASSERT_FALSE(g.alternatives.empty());
    for (const auto& alt: g.alternatives) EXPECT_FALSE(alt.disturbed.empty()) << alt.detail;
}

TEST(Check, ReportsEveryKindWithLabels) {
    auto input = lan();
    input.excludes = {range("10.0.0.100-10.0.0.111")};
    input.occupancy.add(occupant("10.0.0.130", Use::reservation, "printer", {}, "00:00:5e:00:53:60"));
    input.occupancy.add(occupant("10.0.0.131", Use::lease, "guest-phone", {}, "02:00:5e:00:53:61"));
    input.occupancy.add(occupant("10.0.0.132", Use::vip, "vip-web"));
    input.occupancy.add(occupant("10.0.0.133", Use::address_object, "h-nas"));
    input.occupancy.add(occupant("10.0.0.134", Use::static_device, "switch"));
    input.occupancy.add(occupant("10.0.0.135", Use::reservation, "tv-1", "tv", "00:00:5e:00:53:62"));   // at home
    std::vector<Slice> slices{{"tv", cidr("10.0.0.128/28"), false},
                              {"cam", cidr("10.0.0.136/29"), false},       // overlaps tv
                              {"iot", cidr("10.0.0.96/28"), false},        // .96-.99 in the pool, .100-.111 excluded
                              {"lab", cidr("10.0.1.0/28"), false},         // outside
                              {"mgmt", cidr("10.0.0.0/30"), false}};       // the gateway
    auto conflicts = check(input, slices);
    std::vector<std::string> lines;
    for (const auto& c: conflicts) lines.push_back(std::string(conflict_kind_name(c.kind)) + " " + c.slice.cidr.str() + " " + c.label);
    EXPECT_EQ(lines, (std::vector<std::string>{
                         "dynamic-pool 10.0.0.0/30 pool 1",
                         "interface-ip 10.0.0.0/30 interface",
                         "dynamic-pool 10.0.0.96/28 pool 1",
                         "slice-overlap 10.0.0.128/28 cam",
                         "foreign-occupant 10.0.0.128/28 printer",
                         "foreign-occupant 10.0.0.128/28 guest-phone",
                         "foreign-occupant 10.0.0.128/28 vip-web",
                         "foreign-occupant 10.0.0.128/28 h-nas",
                         "foreign-occupant 10.0.0.128/28 switch",
                         "outside-network 10.0.1.0/28 ",
                     }));
    auto pool = std::find_if(conflicts.begin(), conflicts.end(), [](const Conflict& c) { return c.slice.group == "iot"; });
    ASSERT_NE(pool, conflicts.end());
    EXPECT_EQ(pool->range, range("10.0.0.96-10.0.0.99"));
    auto overlap = std::find_if(conflicts.begin(), conflicts.end(), [](const Conflict& c) { return c.kind == ConflictKind::slice_overlap; });
    EXPECT_EQ(overlap->other, cidr("10.0.0.136/29"));
    EXPECT_EQ(overlap->range, range("10.0.0.136-10.0.0.143"));
    auto printer = std::find_if(conflicts.begin(), conflicts.end(), [](const Conflict& c) { return c.label == "printer"; });
    EXPECT_EQ(printer->mac, "00:00:5e:00:53:60");
    EXPECT_EQ(printer->use, Use::reservation);
    EXPECT_EQ(printer->detail, "10.0.0.128/28 (tv) contains reservation printer (10.0.0.130) of no group");
    // The overlap is reported once, on the lower slice; the cam slice has nothing else wrong.
    EXPECT_EQ(std::count_if(conflicts.begin(), conflicts.end(), [](const Conflict& c) { return c.slice.group == "cam"; }), 0);
    EXPECT_TRUE(check(input, std::vector<Slice>{{"tv", cidr("10.0.0.144/28"), false}}).empty());
}

TEST(PickAddress, PrefersTheCurrentAddress) {
    auto parent = cidr("10.0.0.0/24");
    auto slice = cidr("10.0.0.128/28");
    Occupancy occupancy;
    occupancy.add(occupant("10.0.0.128", Use::reservation, "tv-1", "tv", "00:00:5e:00:53:70"));
    occupancy.add(occupant("10.0.0.130", Use::lease, "tv-2", "tv", "00:00:5e:00:53:71"));
    occupancy.add(occupant("10.0.0.129", Use::interface_ip, "port1"));
    // Its own lease does not count against it.
    EXPECT_EQ(pick_address(parent, slice, occupancy, ip("10.0.0.130"), "00:00:5e:00:53:71"), ip("10.0.0.130"));
    // Someone else's: the lowest free one.
    EXPECT_EQ(pick_address(parent, slice, occupancy, ip("10.0.0.130"), "00:00:5e:00:53:72"), ip("10.0.0.131"));
    EXPECT_EQ(pick_address(parent, slice, occupancy, std::nullopt), ip("10.0.0.131"));
    // Outside the slice: ignored.
    EXPECT_EQ(pick_address(parent, slice, occupancy, ip("10.0.0.20")), ip("10.0.0.131"));
    EXPECT_EQ(pick_address(parent, slice, occupancy, ip("10.0.0.140")), ip("10.0.0.140"));
    // An interface IP never qualifies, even "for" its own MAC.
    EXPECT_EQ(pick_address(parent, slice, occupancy, ip("10.0.0.129"), ""), ip("10.0.0.131"));
}

TEST(PickAddress, NeverTheParentsNetworkOrBroadcast) {
    auto parent = cidr("10.0.0.0/24");
    Occupancy empty;
    EXPECT_EQ(pick_address(parent, cidr("10.0.0.0/30"), empty, ip("10.0.0.0")), ip("10.0.0.1"));
    EXPECT_EQ(pick_address(parent, cidr("10.0.0.252/30"), empty, ip("10.0.0.255")), ip("10.0.0.252"));
    EXPECT_FALSE(pick_address(parent, cidr("10.0.0.255/32"), empty, std::nullopt));
    EXPECT_FALSE(pick_address(parent, cidr("10.0.1.0/30"), empty, std::nullopt));
    Occupancy full;
    for (int i = 252; i < 255; ++i) full.add(occupant("10.0.0." + std::to_string(i), Use::reservation, "r"));
    EXPECT_FALSE(pick_address(parent, cidr("10.0.0.252/30"), full, std::nullopt));
    // Through PlanInput the interface IPs count too.
    auto input = lan();
    EXPECT_EQ(pick_address(input.network, cidr("10.0.0.0/30"), input.effective_occupancy(), std::nullopt), ip("10.0.0.2"));
}

TEST(Utilization, PerSliceAndOverall) {
    auto input = lan();
    input.occupancy.add(occupant("10.0.0.240", Use::reservation, "a", "g"));
    input.occupancy.add(occupant("10.0.0.240", Use::lease, "a", "g"));   // same address counts once
    input.occupancy.add(occupant("10.0.0.241", Use::lease, "b", "g"));
    input.interface_ips.push_back(ip("10.0.0.130"));
    std::vector<Slice> slices{{"g", cidr("10.0.0.240/28"), true}, {"h", cidr("10.0.0.128/29"), true}};
    auto u = utilization(input, slices);
    ASSERT_EQ(u.slices.size(), 2u);
    EXPECT_EQ(u.slices[0].usage.total, 15u);   // the broadcast is not usable
    EXPECT_EQ(u.slices[0].usage.used, 2u);
    EXPECT_EQ(u.slices[0].usage.free, 13u);
    EXPECT_EQ(u.slices[1].usage.total, 7u);    // the secondary IP is not usable
    EXPECT_EQ(u.slices[1].usage.used, 0u);
    EXPECT_EQ(u.overall.total, 22u);
    EXPECT_EQ(u.overall.used, 2u);
    EXPECT_EQ(u.overall.free, 20u);
}

TEST(Render, ProposalJson) {
    auto input = lan("10.0.0.2-10.0.0.223");
    input.existing["tv"] = {cidr("10.0.0.224/29")};
    input.occupancy.add(occupant("10.0.0.225", Use::reservation, "tv-1", "tv"));
    input.requests = {request("tv", 3), request("guests", 30)};
    auto j = to_json(propose(input));
    EXPECT_EQ(j["network"], "10.0.0.0/24");
    EXPECT_EQ(j["complete"], false);
    ASSERT_EQ(j["slices"].size(), 1u);
    EXPECT_EQ(j["slices"][0]["cidr"], "10.0.0.224/29");
    EXPECT_EQ(j["slices"][0]["origin"], "retained");
    EXPECT_EQ(j["slices"][0]["usage"]["used"], 1);
    EXPECT_EQ(j["slices"][0]["usage"]["total"], 8);
    EXPECT_EQ(j["groups"][0]["group"], "guests");
    EXPECT_EQ(j["groups"][0]["missing"], 45);
    EXPECT_EQ(j["groups"][0]["alternatives"][0]["kind"], "shrink-pool");
    // .192/26 holds the tv slice, so the smallest top shrink frees .128/26.
    EXPECT_EQ(j["groups"][0]["alternatives"][0]["pool_change"]["new_range"], "10.0.0.2-10.0.0.127");
    EXPECT_EQ(j["groups"][0]["alternatives"][0]["slices"][0], "10.0.0.128/26");
    EXPECT_EQ(j["groups"][1]["group"], "tv");
    EXPECT_EQ(j["groups"][1]["missing"], 0);
    EXPECT_TRUE(j["conflicts"].is_array());
    EXPECT_EQ(j["utilization"]["total"], 8);

    std::vector<Slice> bad{{"x", cidr("10.0.0.0/30"), false}};
    auto c = to_json(check(input, bad));
    ASSERT_EQ(c.size(), 2u);
    EXPECT_EQ(c[0]["kind"], "dynamic-pool");
    EXPECT_EQ(c[0]["range"], "10.0.0.2-10.0.0.3");
    EXPECT_EQ(c[0]["label"], "pool 1");
    EXPECT_EQ(c[1]["kind"], "interface-ip");
    EXPECT_EQ(c[1]["ip"], "10.0.0.1");
}

// AddressSanitizer slows the planner about eightfold: the Linux CI build (-O0, ASan/UBSan) takes 4-5 s
// on this test, an unsanitized -O0 build about 0.5 s and -O2 about 30 ms.
#if defined(__SANITIZE_ADDRESS__)
#define FPH_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define FPH_TEST_ASAN 1
#endif
#endif
#ifdef FPH_TEST_ASAN
constexpr auto large_network_bound = std::chrono::seconds(30);
#else
constexpr auto large_network_bound = std::chrono::seconds(5);
#endif

TEST(Scale, LargeNetworkStaysFast) {
    // A /16 with a pool over nearly all of it, a few thousand leases and twenty groups: the
    // enumeration of pool changes must stay cheap.
    PlanInput input;
    input.network = cidr("10.20.0.0/16");
    input.interface_ips = {ip("10.20.0.1")};
    input.pools = {{1, range("10.20.0.2-10.20.250.255")}};
    for (int i = 0; i < 3000; ++i)
        input.occupancy.add({input.network.first() + 2 + static_cast<Ipv4>(i) * 7, Use::lease, "d" + std::to_string(i), {}, {}});
    for (int g = 0; g < 20; ++g) input.requests.push_back(request("g" + std::to_string(g), 10 + static_cast<std::uint64_t>(g) * 25));
    input.policy.allow_pool_changes = true;
    auto start = std::chrono::steady_clock::now();
    auto p = propose(input);
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, large_network_bound);
    EXPECT_TRUE(p.complete());
    expect_new_slices_clean(input, p);
}

TEST(Determinism, SameInputSameProposal) {
    auto input = lan("10.0.0.2-10.0.0.150");
    input.pools.push_back({2, range("10.0.0.200-10.0.0.210")});
    for (int i = 0; i < 20; ++i)
        input.occupancy.add(occupant("10.0.0." + std::to_string(3 + i * 12), i % 2 ? Use::lease : Use::reservation, "d" + std::to_string(i),
                                     i % 3 ? "" : "tv"));
    input.existing["tv"] = {cidr("10.0.0.152/30")};
    input.requests = {request("tv", 5), request("iot", 7), request("cam", 3), request("guests", 30), request("kids", 2)};
    const auto reference = to_json(propose(input)).dump();
    EXPECT_EQ(to_json(propose(input)).dump(), reference);
    std::mt19937 random(7);
    for (int round = 0; round < 20; ++round) {
        auto shuffled = input;
        std::shuffle(shuffled.requests.begin(), shuffled.requests.end(), random);
        std::shuffle(shuffled.pools.begin(), shuffled.pools.end(), random);
        // Occupants at distinct addresses: their order cannot matter.
        std::shuffle(shuffled.occupancy.entries.begin(), shuffled.occupancy.entries.end(), random);
        EXPECT_EQ(to_json(propose(shuffled)).dump(), reference) << "round " << round;
    }
}
