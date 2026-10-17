// Authentication pieces: the constant-time compare, Bearer parsing, token generation and the secret
// store round trip (an in-memory store: never the user's Keychain or credentials directory). Also
// the source allowlist and the per-source rate limiter.

#include "support.hpp"

#include <net.hpp>
#include <rate_limit.hpp>
#include <token.hpp>

#include <set>

namespace fph::daemon::test {

    TEST(ConstantTimeEqual, ComparesContentAndLength) {
        EXPECT_TRUE(constant_time_equal("", ""));
        EXPECT_TRUE(constant_time_equal(token, token));
        EXPECT_FALSE(constant_time_equal(token, std::string(token).substr(0, 63)));
        EXPECT_FALSE(constant_time_equal(std::string(token) + "0", token));
        std::string last = token;
        last.back() = 'x';
        EXPECT_FALSE(constant_time_equal(token, last));
        std::string first = token;
        first.front() = 'x';
        EXPECT_FALSE(constant_time_equal(token, first));
        EXPECT_FALSE(constant_time_equal("a", ""));
        // A prefix is not a match (a NUL-padding bug would make it one).
        EXPECT_FALSE(constant_time_equal("abc", std::string("abc\0", 4)));
    }

    TEST(BearerToken, ParsesTheScheme) {
        EXPECT_EQ(bearer_token("Bearer abc"), "abc");
        EXPECT_EQ(bearer_token("bearer abc"), "abc");
        EXPECT_EQ(bearer_token("BEARER   abc"), "abc");
        EXPECT_FALSE(bearer_token("Bearer"));
        EXPECT_FALSE(bearer_token("Bearer "));
        EXPECT_FALSE(bearer_token("Bearerabc"));
        EXPECT_FALSE(bearer_token("Basic YWxhZGRpbjpvcGVu"));
        EXPECT_FALSE(bearer_token("Bearer abc def"));
        EXPECT_FALSE(bearer_token(""));
    }

    TEST(Token, GeneratesDistinct256BitHexTokens) {
        std::set<std::string> seen;
        for (int i = 0; i < 64; ++i) {
            auto t = generate_token();
            EXPECT_EQ(t.size(), 64u);
            EXPECT_EQ(t.find_first_not_of("0123456789abcdef"), std::string::npos);
            EXPECT_TRUE(valid_token(t));
            seen.insert(t);
        }
        EXPECT_EQ(seen.size(), 64u);
    }

    TEST(Token, Validation) {
        EXPECT_TRUE(valid_token(token));
        EXPECT_FALSE(valid_token("short"));
        EXPECT_FALSE(valid_token(std::string(31, 'a')));
        EXPECT_TRUE(valid_token(std::string(32, 'a')));
        EXPECT_FALSE(valid_token(std::string(513, 'a')));
        EXPECT_FALSE(valid_token(std::string(40, 'a') + " b"));
        EXPECT_FALSE(valid_token(std::string(40, 'a') + "\r\nX: y"));
    }

    TEST(Token, StoreRoundTripAndBinding) {
        auto store = forti::engine::memory_secret_store();
        auto account = token_account("fw01");
        EXPECT_EQ(account, "pihole/fw01/webhook-token");
        EXPECT_FALSE(load_token(*store, account, "fw.example:443"));

        auto created = ensure_token(*store, account, "fw.example:443");
        EXPECT_TRUE(valid_token(created));
        EXPECT_EQ(ensure_token(*store, account, "fw.example:443"), created);   // stable once stored
        EXPECT_EQ(load_token(*store, account, "fw.example:443"), created);

        // Bound to its FortiGate: another device's profile does not get it, and the error never
        // contains the token.
        try {
            (void) load_token(*store, account, "other.example:443");
            ADD_FAILURE() << "a token bound to another device was released";
        } catch (const TokenError& e) {
            EXPECT_EQ(std::string(e.what()).find(created), std::string::npos);
            EXPECT_NE(std::string(e.what()).find(account), std::string::npos);
        }

        auto rotated = rotate_token(*store, account, "fw.example:443");
        EXPECT_NE(rotated, created);
        EXPECT_EQ(load_token(*store, account, "fw.example:443"), rotated);

        store->put(account, "weak", "fw.example:443");
        EXPECT_THROW((void) load_token(*store, account, "fw.example:443"), TokenError);
    }

    TEST(Net, ParsesAddresses) {
        EXPECT_EQ(IpAddress::parse("192.0.2.1")->to_string(), "192.0.2.1");
        EXPECT_EQ(IpAddress::parse("2001:db8::1")->to_string(), "2001:db8::1");
        // A dual-stack listener's view of an IPv4 peer is the IPv4 address.
        auto mapped = IpAddress::parse("::ffff:192.0.2.1");
        ASSERT_TRUE(mapped);
        EXPECT_FALSE(mapped->v6);
        EXPECT_EQ(mapped->to_string(), "192.0.2.1");
        for (const char* bad: {"", "192.0.2", "192.0.2.256", "10.1", "host.example", "192.0.2.1 ", "fe80::1%en0", "::g"})
            EXPECT_FALSE(IpAddress::parse(bad)) << bad;
        EXPECT_TRUE(IpAddress::parse("127.0.0.5")->loopback());
        EXPECT_TRUE(IpAddress::parse("::1")->loopback());
        EXPECT_FALSE(IpAddress::parse("192.0.2.1")->loopback());
    }

    TEST(Net, CidrMatching) {
        auto lan = Cidr::parse("192.0.2.0/24");
        ASSERT_TRUE(lan);
        EXPECT_TRUE(lan->contains(*IpAddress::parse("192.0.2.200")));
        EXPECT_FALSE(lan->contains(*IpAddress::parse("192.0.3.1")));
        EXPECT_FALSE(lan->contains(*IpAddress::parse("2001:db8::1")));
        auto odd = Cidr::parse("10.0.0.0/9");
        EXPECT_TRUE(odd->contains(*IpAddress::parse("10.127.255.255")));
        EXPECT_FALSE(odd->contains(*IpAddress::parse("10.128.0.0")));
        auto host = Cidr::parse("192.0.2.1");
        EXPECT_EQ(host->to_string(), "192.0.2.1/32");
        EXPECT_FALSE(host->contains(*IpAddress::parse("192.0.2.2")));
        auto v6 = Cidr::parse("2001:db8::/32");
        EXPECT_TRUE(v6->contains(*IpAddress::parse("2001:db8:ffff::1")));
        EXPECT_FALSE(v6->contains(*IpAddress::parse("2001:db9::1")));
        EXPECT_TRUE(Cidr::parse("0.0.0.0/0")->contains(*IpAddress::parse("203.0.113.9")));
        // Host bits below the prefix: almost always a typo for a host, so refused.
        for (const char* bad: {"192.0.2.1/24", "192.0.2.0/33", "192.0.2.0/", "192.0.2.0/-1", "192.0.2.0/2a", "2001:db8::1/32", "x/8"})
            EXPECT_FALSE(Cidr::parse(bad)) << bad;
    }

    TEST(Net, Allowlist) {
        Allowlist empty;
        EXPECT_FALSE(empty.allows(*IpAddress::parse("192.0.2.1")));
        Allowlist list({*Cidr::parse("192.0.2.1"), *Cidr::parse("198.51.100.0/24")});
        EXPECT_TRUE(list.allows(*IpAddress::parse("192.0.2.1")));
        EXPECT_TRUE(list.allows(*IpAddress::parse("::ffff:198.51.100.7")));
        EXPECT_FALSE(list.allows(*IpAddress::parse("192.0.2.2")));
        EXPECT_FALSE(list.allows_any());
        EXPECT_TRUE(Allowlist({*Cidr::parse("::/0")}).allows_any());
        // A literal resolves without DNS (the tests never touch the network).
        EXPECT_EQ(resolve_host("192.0.2.9").at(0).to_string(), "192.0.2.9/32");
    }

    TEST(RateLimiter, BurstThenRefill) {
        RateLimiter limiter(3, 60);   // 3 at once, one per second after that
        std::int64_t t = 1000;
        EXPECT_TRUE(limiter.allow("a", t));
        EXPECT_TRUE(limiter.allow("a", t));
        EXPECT_TRUE(limiter.allow("a", t));
        EXPECT_FALSE(limiter.allow("a", t));
        EXPECT_EQ(limiter.retry_after_s("a", t), 1);
        EXPECT_TRUE(limiter.allow("b", t));   // per source
        EXPECT_FALSE(limiter.allow("a", t + 500));
        EXPECT_TRUE(limiter.allow("a", t + 1000));
        EXPECT_FALSE(limiter.allow("a", t + 1000));
        // Never more than the burst, however long the quiet.
        t += 1'000'000;
        for (int i = 0; i < 3; ++i) EXPECT_TRUE(limiter.allow("a", t));
        EXPECT_FALSE(limiter.allow("a", t));
        // A clock that goes backwards refills nothing.
        EXPECT_FALSE(limiter.allow("a", t - 5000));
    }

    TEST(RateLimiter, BoundedSources) {
        RateLimiter limiter(1, 1, 4);
        for (int i = 0; i < 100; ++i) EXPECT_TRUE(limiter.allow("source-" + std::to_string(i), i));
        EXPECT_LE(limiter.sources(), 4u);
    }

}  // namespace fph::daemon::test
