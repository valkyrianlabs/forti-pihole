// Addresses, ranges, CIDR blocks, covers and complements (src/alloc/cidr.hpp).

#include <alloc/cidr.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <random>

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

    std::vector<std::string> strs(const std::vector<Cidr>& blocks) {
        std::vector<std::string> out;
        for (const auto& block: blocks) out.push_back(block.str());
        return out;
    }

}  // namespace

TEST(Ipv4, ParsesAndFormats) {
    EXPECT_EQ(parse_ipv4("192.168.1.1"), 0xc0a80101u);
    EXPECT_EQ(parse_ipv4("0.0.0.0"), 0u);
    EXPECT_EQ(parse_ipv4("255.255.255.255"), 0xffffffffu);
    EXPECT_EQ(format_ipv4(0xc0a801ffu), "192.168.1.255");
    EXPECT_EQ(format_ipv4(0), "0.0.0.0");
}

TEST(Ipv4, RefusesMalformed) {
    for (auto text: {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.-1", "01.2.3.4", "1.2.3.04", " 1.2.3.4", "1.2.3.4 ", "1..3.4",
                     "1.2.3.", ".1.2.3", "a.b.c.d", "+1.2.3.4", "1.2.3.4/24", "4294967296", "1.2.3.99999999999"})
        EXPECT_FALSE(parse_ipv4(text)) << text;
}

TEST(Cidr, ParsesStrictly) {
    auto c = Cidr::parse("192.168.1.224/28");
    ASSERT_TRUE(c);
    EXPECT_EQ(c->network, ip("192.168.1.224"));
    EXPECT_EQ(c->prefix, 28);
    EXPECT_EQ(c->str(), "192.168.1.224/28");
    EXPECT_TRUE(Cidr::parse("0.0.0.0/0"));
    EXPECT_TRUE(Cidr::parse("10.0.0.7/32"));
    EXPECT_TRUE(Cidr::parse("192.0.2.0/24"));
    // Host bits set, missing or bad prefix, leading zeros, junk.
    for (auto text: {"192.168.1.5/28", "192.168.1.1/24", "11.0.0.0/7", "1.0.0.0/0", "192.168.1.0", "192.168.1.0/", "192.168.1.0/33",
                     "192.168.1.0/024", "192.168.1.0/-1", "192.168.1.0/ 24", "192.168.1.0/24 ", "192.168.1.0/2a", "192.168.01.0/24",
                     "/24", "192.168.1.0//24"})
        EXPECT_FALSE(Cidr::parse(text)) << text;
}

TEST(Cidr, Geometry) {
    auto c = cidr("192.168.1.224/28");
    EXPECT_EQ(c.first(), ip("192.168.1.224"));
    EXPECT_EQ(c.last(), ip("192.168.1.239"));
    EXPECT_EQ(c.size(), 16u);
    EXPECT_TRUE(c.contains(ip("192.168.1.224")));
    EXPECT_TRUE(c.contains(ip("192.168.1.239")));
    EXPECT_FALSE(c.contains(ip("192.168.1.240")));
    EXPECT_FALSE(c.contains(ip("192.168.1.223")));
    EXPECT_TRUE(cidr("192.168.1.0/24").contains(c));
    EXPECT_FALSE(c.contains(cidr("192.168.1.0/24")));
    EXPECT_TRUE(c.contains(c));
    EXPECT_TRUE(c.overlaps(cidr("192.168.1.0/24")));
    EXPECT_TRUE(c.overlaps(cidr("192.168.1.232/29")));
    EXPECT_FALSE(c.overlaps(cidr("192.168.1.240/28")));
    EXPECT_FALSE(c.overlaps(cidr("192.168.1.208/28")));

    auto all = cidr("0.0.0.0/0");
    EXPECT_EQ(all.size(), 4294967296u);
    EXPECT_EQ(all.last(), 0xffffffffu);
    EXPECT_TRUE(all.contains(ip("255.255.255.255")));
    auto top = cidr("255.255.255.252/30");
    EXPECT_EQ(top.last(), 0xffffffffu);
    EXPECT_EQ(Cidr::containing(ip("192.168.1.230"), 28), c);
    EXPECT_EQ(Cidr::containing(ip("192.168.1.230"), 0), all);
}

TEST(Cidr, UsableExcludesOnlyTheParentsNetworkAndBroadcast) {
    auto parent = cidr("192.168.1.0/24");
    // A slice inside the parent keeps its own first and last addresses: it is not a subnet.
    auto mid = cidr("192.168.1.224/28");
    EXPECT_EQ(mid.usable(parent), (Range{ip("192.168.1.224"), ip("192.168.1.239")}));
    EXPECT_EQ(mid.usable_count(parent), 16u);
    // At the parent's edges it loses the parent's network or broadcast address.
    EXPECT_EQ(cidr("192.168.1.240/28").usable(parent), (Range{ip("192.168.1.240"), ip("192.168.1.254")}));
    EXPECT_EQ(cidr("192.168.1.0/28").usable(parent), (Range{ip("192.168.1.1"), ip("192.168.1.15")}));
    EXPECT_EQ(parent.usable(parent), (Range{ip("192.168.1.1"), ip("192.168.1.254")}));
    EXPECT_EQ(parent.usable_count(parent), 254u);
    EXPECT_FALSE(cidr("192.168.1.0/32").usable(parent));
    EXPECT_FALSE(cidr("192.168.1.255/32").usable(parent));
    EXPECT_EQ(cidr("192.168.1.0/31").usable_count(parent), 1u);
    // Not inside the parent: nothing.
    EXPECT_FALSE(cidr("192.168.2.0/28").usable(parent));
    EXPECT_FALSE(cidr("192.168.0.0/23").usable(parent));
    // /31 and /32 parents have no network or broadcast address (RFC 3021).
    EXPECT_EQ(cidr("192.0.2.0/31").usable_count(cidr("192.0.2.0/31")), 2u);
    EXPECT_EQ(cidr("192.0.2.1/32").usable_count(cidr("192.0.2.1/32")), 1u);
}

TEST(Range, ParseAndSetOperations) {
    auto r = Range::parse("192.168.1.2-192.168.1.200");
    ASSERT_TRUE(r);
    EXPECT_EQ(r->size(), 199u);
    EXPECT_EQ(r->str(), "192.168.1.2-192.168.1.200");
    EXPECT_EQ(Range::parse("192.168.1.9"), Range::single(ip("192.168.1.9")));
    EXPECT_EQ(Range::single(ip("192.168.1.9")).str(), "192.168.1.9");
    EXPECT_FALSE(Range::parse("192.168.1.9-192.168.1.8"));
    EXPECT_FALSE(Range::parse("192.168.1.9-"));
    EXPECT_FALSE(Range::parse("x-192.168.1.8"));

    EXPECT_EQ(intersect({10, 20}, {15, 30}), (Range{15, 20}));
    EXPECT_FALSE(intersect({10, 20}, {21, 30}));
    EXPECT_EQ(normalize({{30, 40}, {10, 20}, {21, 25}, {35, 50}, {60, 60}}), (std::vector<Range>{{10, 25}, {30, 50}, {60, 60}}));
    EXPECT_EQ(subtract({{0, 100}}, {{10, 20}, {50, 50}, {90, 200}}), (std::vector<Range>{{0, 9}, {21, 49}, {51, 89}}));
    EXPECT_EQ(subtract({{0, 10}, {20, 30}}, {{5, 25}}), (std::vector<Range>{{0, 4}, {26, 30}}));
    EXPECT_EQ(subtract({{0, 10}}, {{0, 10}}), std::vector<Range>{});
    EXPECT_EQ(subtract({{0, 0xffffffffu}}, {{0xfffffff0u, 0xffffffffu}}), (std::vector<Range>{{0, 0xffffffefu}}));
    EXPECT_EQ(normalize({{0xfffffff0u, 0xffffffffu}, {0, 0xffffffefu}}), (std::vector<Range>{{0, 0xffffffffu}}));
}

TEST(Cover, IsMinimalAndAligned) {
    EXPECT_EQ(strs(cover({ip("192.168.1.201"), ip("192.168.1.255")})),
              (std::vector<std::string>{"192.168.1.201/32", "192.168.1.202/31", "192.168.1.204/30", "192.168.1.208/28",
                                        "192.168.1.224/27"}));
    EXPECT_EQ(strs(cover(cidr("192.168.1.0/24").range())), std::vector<std::string>{"192.168.1.0/24"});
    EXPECT_EQ(strs(cover({0, 0xffffffffu})), std::vector<std::string>{"0.0.0.0/0"});
    EXPECT_EQ(strs(cover({0xffffffffu, 0xffffffffu})), std::vector<std::string>{"255.255.255.255/32"});
    EXPECT_EQ(strs(cover({ip("10.0.0.1"), ip("10.0.0.6")})),
              (std::vector<std::string>{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}));
}

TEST(Complement, HybridExample) {
    auto network = cidr("192.168.1.0/24");
    std::vector<Cidr> slices{cidr("192.168.1.208/28"), cidr("192.168.1.224/28")};
    EXPECT_EQ(strs(complement(network, slices)),
              (std::vector<std::string>{"192.168.1.0/25", "192.168.1.128/26", "192.168.1.192/28", "192.168.1.240/28"}));
    EXPECT_EQ(strs(complement(network, {})), std::vector<std::string>{"192.168.1.0/24"});
    std::vector<Cidr> whole{network};
    EXPECT_TRUE(complement(network, whole).empty());
    // Slices partly or wholly outside the network only remove what is inside it.
    std::vector<Cidr> wide{cidr("192.168.0.0/23")};
    EXPECT_TRUE(complement(network, wide).empty());
    std::vector<Cidr> elsewhere{cidr("198.51.100.0/24")};
    EXPECT_EQ(strs(complement(network, elsewhere)), std::vector<std::string>{"192.168.1.0/24"});
    // Overlapping slices are fine.
    std::vector<Cidr> overlapping{cidr("192.168.1.0/25"), cidr("192.168.1.64/26")};
    EXPECT_EQ(strs(complement(network, overlapping)), std::vector<std::string>{"192.168.1.128/25"});
}

// Property: for random slice sets, every address of the network is in exactly one of
// slices ∪ complement, the complement blocks are disjoint, aligned and inside the network, and no two
// complement blocks could merge into one (minimality of the greedy cover per gap).
TEST(Complement, PartitionsTheNetwork) {
    std::mt19937 random(20261017);
    for (int round = 0; round < 300; ++round) {
        int parent_prefix = 20 + static_cast<int>(random() % 9);   // /20../28
        Cidr network = Cidr::containing(0x0a140000u + static_cast<Ipv4>(random() % 4096) * 16, parent_prefix);
        std::vector<Cidr> slices;
        int count = static_cast<int>(random() % 6);
        for (int i = 0; i < count; ++i) {
            int prefix = parent_prefix + static_cast<int>(random() % static_cast<unsigned>(33 - parent_prefix));
            Ipv4 at = network.first() + static_cast<Ipv4>(random() % network.size());
            Cidr slice = Cidr::containing(at, prefix);
            // Disjoint slices, as a valid plan has.
            if (std::none_of(slices.begin(), slices.end(), [&](const Cidr& s) { return s.overlaps(slice); })) slices.push_back(slice);
        }
        auto rest = complement(network, slices);
        for (const auto& block: rest) {
            EXPECT_TRUE(network.contains(block));
            EXPECT_EQ(Cidr::parse(block.str()), block);   // aligned
        }
        for (std::uint64_t a = network.first(); a <= network.last(); ++a) {
            auto addr = static_cast<Ipv4>(a);
            int hits = 0;
            for (const auto& s: slices) hits += s.contains(addr);
            for (const auto& b: rest) hits += b.contains(addr);
            ASSERT_EQ(hits, 1) << "round " << round << " address " << format_ipv4(addr);
        }
        for (std::size_t i = 0; i + 1 < rest.size(); ++i) {
            const auto& a = rest[i];
            const auto& b = rest[i + 1];
            EXPECT_LT(a.last(), b.first());
            bool buddies = a.prefix == b.prefix && a.prefix > 0 && Cidr::containing(a.network, a.prefix - 1).network == a.network &&
                           std::uint64_t{a.last()} + 1 == b.first();
            EXPECT_FALSE(buddies) << a.str() << " and " << b.str() << " should be one block";
        }
    }
}
