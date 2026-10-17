// MAC handling, configuration validation, the write guard and the connectivity primitives.

#include "fixture.hpp"

#include <address_match.hpp>
#include <connectivity.hpp>
#include <guard.hpp>
#include <mac.hpp>

using namespace fph;
using namespace fph::test;

TEST(Mac, NormalizesSpellings) {
    EXPECT_EQ(normalize_mac("AA-BB-cc:DD:ee:FF"), "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(normalize_mac("aabbccddeeff"), "aa:bb:cc:dd:ee:ff");
    EXPECT_FALSE(normalize_mac("aabb:ccdd:eeff"));
    EXPECT_FALSE(normalize_mac("aa:bb:cc:dd:ee"));
    EXPECT_FALSE(normalize_mac("zz:bb:cc:dd:ee:ff"));
}

TEST(Mac, LocallyAdministeredBit) {
    EXPECT_TRUE(locally_administered("82:00:5e:00:53:c5"));
    EXPECT_TRUE(locally_administered(phone));
    EXPECT_FALSE(locally_administered(plug1));
}

TEST(Mac, EntriesAndRanges) {
    EXPECT_TRUE(mac_in_entry(plug1, "00:00:5E:00:53:01"));
    EXPECT_TRUE(mac_in_entry(plug2, "00:00:5e:00:53:00-00:00:5e:00:53:0f"));
    EXPECT_FALSE(mac_in_entry(laptop, "00:00:5e:00:53:00-00:00:5e:00:53:04"));
    EXPECT_EQ(mac_suffix(plug1), "005301");
    EXPECT_EQ(mac_oui(plug1), "00:00:5e");
}

TEST(Config, ExampleIsValid) {
    auto config = Config::from_json(example_config());
    EXPECT_EQ(config.default_group, "default");
    ASSERT_TRUE(config.group("trusted"));
    EXPECT_TRUE(config.group("trusted")->privileged);
    EXPECT_FALSE(config.rules.empty());
}

TEST(Config, RefusesRulesIntoPrivilegedSegments) {
    auto j = json::parse(R"({"groups": [{"name": "owner", "privileged": true}, {"name": "default"}],
                             "rules": [{"group": "owner", "match": {"hostname": "Alexs-*"}}]})");
    EXPECT_THROW(Config::from_json(j), ConfigError);
}

TEST(Config, RefusesPrivilegedDefault) {
    auto j = json::parse(R"({"default_group": "owner", "groups": [{"name": "owner", "privileged": true}]})");
    EXPECT_THROW(Config::from_json(j), ConfigError);
}

TEST(Config, RefusesUnknownKeysAndBadValues) {
    EXPECT_THROW(Config::from_json(json::parse(R"({"groups": [{"name": "default"}], "colour": 1})")), ConfigError);
    EXPECT_THROW(Config::from_json(json::parse(R"({"groups": [{"name": "Default"}]})")), ConfigError);
    EXPECT_THROW(Config::from_json(json::parse(R"({"groups": [{"name": "default", "subnet": "10.0.0.0/33"}]})")), ConfigError);
    EXPECT_THROW(Config::from_json(json::parse(R"({"groups": [{"name": "default"}], "prefix": "x"})")), ConfigError);
    EXPECT_THROW(Config::from_json(json::parse(R"({"groups": [{"name": "default"}], "rules": [{"group": "default", "match": {}}]})")),
                 ConfigError);
}

TEST(Guard, OperationsOutsideTheAllowlistAreRefused) {
    auto config = test_config();
    Snapshot snapshot;
    auto policy = json::array({{{"op", "update"}, {"resource", "firewall/policy"}, {"key", "2"}, {"set", {{"status", "disable"}}}}});
    EXPECT_THROW(check_operations(policy, snapshot, config), GuardViolation);

    auto unprefixed = json::array({{{"op", "create"}, {"resource", "firewall/address"},
                                    {"object", {{"name", "Thermostat"}, {"comment", std::string(marker)}}}}});
    EXPECT_THROW(check_operations(unprefixed, snapshot, config), GuardViolation);

    auto unmarked = json::array({{{"op", "create"}, {"resource", "firewall/address"}, {"object", {{"name", "fp-dev-x"}}}}});
    EXPECT_THROW(check_operations(unmarked, snapshot, config), GuardViolation);

    // An administrator's object that happens to carry the prefix: still not ours.
    Address theirs;
    theirs.name = "fp-rule-iot_untrusted-kasa";
    theirs.type = "dynamic";
    snapshot.addresses[theirs.name] = theirs;
    auto delete_theirs = json::array({{{"op", "delete"}, {"resource", "firewall/address"}, {"key", theirs.name}}});
    EXPECT_THROW(check_operations(delete_theirs, snapshot, config), GuardViolation);

    Address ours;
    ours.name = "fp-dev-plug-005301";
    ours.comment = std::string(marker) + ": plug";
    snapshot.addresses[ours.name] = ours;
    auto strip_marker = json::array({{{"op", "update"}, {"resource", "firewall/address"}, {"key", ours.name}, {"set", {{"comment", "mine now"}}}}});
    EXPECT_THROW(check_operations(strip_marker, snapshot, config), GuardViolation);
    auto ok = json::array({{{"op", "delete"}, {"resource", "firewall/address"}, {"key", ours.name}}});
    EXPECT_NO_THROW(check_operations(ok, snapshot, config));
}

TEST(Guard, TransportRefusesBeforeSending) {
    using fortiapi::Method;
    const std::string base = "https://fortigate.test:8443/api/v2/";
    EXPECT_EQ(refuse_write(Method::Get, base + "cmdb/system/interface", "", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Put, base + "cmdb/system/interface/internal", "{}", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Put, base + "cmdb/firewall/policy/2", "{}", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Post, base + "cmdb/system.dhcp/server/1/reserved-address", "{}", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Post, base + "monitor/system/os/reboot", "{}", "fp-"), "");
    EXPECT_EQ(refuse_write(Method::Post, base + "cmdb/firewall/address?vdom=root", R"({"name":"fp-dev-a"})", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Post, base + "cmdb/firewall/address", R"({"name":"Thermostat"})", "fp-"), "");
    EXPECT_EQ(refuse_write(Method::Put, base + "cmdb/firewall/addrgrp/fp-grp-tvs?vdom=root", "{}", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Delete, base + "cmdb/firewall/addrgrp/TVs", "", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Delete, base + "cmdb/firewall/address", "", "fp-"), "");
    // Encoded names are decoded before the prefix check; nested child paths are refused.
    EXPECT_EQ(refuse_write(Method::Delete, base + "cmdb/firewall/address/fp-dev-a%20b", "", "fp-"), "");
    EXPECT_NE(refuse_write(Method::Delete, base + "cmdb/firewall/address/%6Dvlan%2Fx", "", "nope-"), "");
    EXPECT_NE(refuse_write(Method::Put, base + "cmdb/firewall/addrgrp/fp-grp-tvs/member", "{}", "fp-"), "");
}

namespace {
    class RecordingTransport final : public fortiapi::Transport {
    public:
        int calls = 0;
        fortiapi::HttpResponse perform(const fortiapi::HttpRequest&) override {
            ++calls;
            return {200, "{}"};
        }
    };
}  // namespace

TEST(Guard, RefusedRequestsNeverReachTheInnerTransport) {
    auto inner = std::make_shared<RecordingTransport>();
    GuardTransport guard(inner, "fp-");
    fortiapi::HttpRequest request;
    request.method = fortiapi::Method::Put;
    request.url = "https://fortigate.test:8443/api/v2/cmdb/system/interface/internal";
    EXPECT_THROW(guard.perform(request), GuardViolation);
    EXPECT_EQ(inner->calls, 0);
    request.method = fortiapi::Method::Get;
    EXPECT_NO_THROW(guard.perform(request));
    EXPECT_EQ(inner->calls, 1);
}

TEST(Connectivity, PortRanges) {
    EXPECT_TRUE(portrange_covers("53", 53));
    EXPECT_TRUE(portrange_covers("80 443", 443));
    EXPECT_TRUE(portrange_covers("1-65535", 443));
    EXPECT_TRUE(portrange_covers("443:1024-65535", 443));
    EXPECT_FALSE(portrange_covers("", 443));
    EXPECT_FALSE(portrange_covers("8443", 443));
}

TEST(Connectivity, EvaluatesFirstMatch) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    auto snapshot = collect(fake, config, 1'800'000'100);
    const Device* d = snapshot.device(plug1);
    ASSERT_TRUE(d);
    auto reach = evaluate(snapshot, *d);
    EXPECT_EQ(reach.internet.action, "accept");
    EXPECT_EQ(reach.internet.policy, 2u);
    EXPECT_EQ(reach.dns.action, "accept");
    EXPECT_EQ(reach.dns.policy, 12u);
}

TEST(AddressMatch, Subnets) {
    EXPECT_TRUE(in_subnet("192.0.2.14", "192.0.2.0 255.255.255.0"));
    EXPECT_TRUE(in_subnet("192.0.2.14", "192.0.2.0/24"));
    EXPECT_FALSE(in_subnet("192.0.3.14", "192.0.2.0/24"));
    EXPECT_TRUE(in_subnet("8.8.8.8", "0.0.0.0 0.0.0.0"));
    EXPECT_FALSE(parse_ipv4("1.2.3"));
    EXPECT_FALSE(parse_ipv4("1.2.3.256"));
}

TEST(Inventory, StaleIsOnlineEntriesAreOffline) {
    FakeGateway fake;
    populate(fake);
    // FortiOS still says is_online for an entry it last saw two days ago.
    fake.devices[0]["last_seen"] = 1'800'000'000 - 2 * 86400;
    auto snapshot = collect(fake, test_config(), 1'800'000'100);
    EXPECT_FALSE(snapshot.device(plug1)->online);
    EXPECT_TRUE(snapshot.device(plug2)->online);
}

TEST(Inventory, PlaceholderHostnamesAreDropped) {
    FakeGateway fake;
    populate(fake);
    fake.devices[0]["hostname"] = "none";
    fake.devices[1]["hostname"] = "192-168-1-36";
    auto snapshot = collect(fake, test_config(), 1'800'000'100);
    EXPECT_EQ(snapshot.device(plug1)->hostname, "");
    EXPECT_EQ(snapshot.device(plug2)->hostname, "");
}

TEST(Config, NetworksAndStrategies) {
    auto base = json::parse(R"({"groups": [{"name": "tvs", "pihole_group": "TV"}, {"name": "iot", "pihole_group": "IOT"}, {"name": "default"}]})");
    auto with = [&](json networks) {
        auto j = base;
        j["networks"] = std::move(networks);
        return j;
    };
    auto config = Config::from_json(with(json::parse(R"([
        {"interface": "internal", "mode": "slices", "slices": [{"group": "tvs", "cidr": "192.168.1.208/28"}]},
        {"interface": "vlan30", "mode": "subnet", "group": "iot"},
        {"interface": "vlan40", "mode": "hybrid", "group": "iot", "slices": [{"group": "tvs", "cidr": "192.168.40.0/26"}]}])")));
    EXPECT_EQ(config.networks.size(), 3u);
    EXPECT_EQ(config.network("vlan30")->mode, Network::Mode::subnet);
    EXPECT_FALSE(config.enabled);                      // nothing is written until the operator says so
    EXPECT_EQ(config.interfaces.size(), 3u);           // defaults to the networks' interfaces
    EXPECT_EQ(config.slice_name("192.168.1.208/28"), "fp-slice-192.168.1.208-28");

    // Host bits, overlaps, subnet mode with slices, slices mode with a mapped base group.
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i", "mode": "slices", "slices": [{"group": "tvs", "cidr": "192.168.1.209/28"}]}])"))), ConfigError);
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i", "mode": "slices", "slices": [
        {"group": "tvs", "cidr": "192.168.1.192/26"}, {"group": "iot", "cidr": "192.168.1.208/28"}]}])"))), ConfigError);
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i", "mode": "subnet", "slices": [{"group": "tvs", "cidr": "10.0.0.0/28"}]}])"))), ConfigError);
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i", "mode": "slices", "group": "iot"}])"))), ConfigError);
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i", "mode": "vlan"}])"))), ConfigError);
    EXPECT_THROW(Config::from_json(with(json::parse(R"([{"interface": "i"}, {"interface": "i"}])"))), ConfigError);
}

TEST(Config, PiholeSection) {
    auto j = json::parse(R"({"networks": [{"interface": "internal"}], "groups": [{"name": "default"}],
                             "pihole": {"url": "https://pihole.example.net/", "name": "home"}})");
    auto config = Config::from_json(j);
    EXPECT_EQ(config.pihole.url, "https://pihole.example.net");
    j["pihole"]["url"] = "ftp://x";
    EXPECT_THROW(Config::from_json(j), ConfigError);
    j["pihole"] = {{"url", "https://x"}, {"password", "nope"}};   // secrets never live in the config file
    EXPECT_THROW(Config::from_json(j), ConfigError);
}
