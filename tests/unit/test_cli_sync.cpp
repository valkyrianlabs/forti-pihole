// The full CLI against an in-memory FortiGate and Pi-hole: sync, migrate with adoptions, operations,
// pause, disabled configurations and the inspection commands.

#include "fake_pihole.hpp"
#include "fixture.hpp"

#include <operation.hpp>
#include <state.hpp>

using namespace fph;
using namespace fph::test;

namespace {
    class PiholeForwarder final : public PiholeApi {
        FakePihole& p_;

    public:
        explicit PiholeForwarder(FakePihole& p) : p_(p) {}
        std::string version() override { return p_.version(); }
        PiholeView view() override { return p_.view(); }
        std::vector<PiholeApplied> apply(const std::vector<PiholeChange>& c) override { return p_.apply(c); }
        std::vector<int> effective_groups(const std::string& ip) override { return p_.effective_groups(ip); }
    };

    struct World {
        TempHome home;
        FakeGateway fake;
        FakePihole pihole;
        std::int64_t now = 1'800'000'100;
        std::ostringstream out, err;
        std::istringstream in;
        json config = json::parse(R"({"enabled": true, "pihole": {"url": "https://pihole.example.net"},
            "groups": [{"name": "tvs", "pihole_group": "TV"}, {"name": "iot_untrusted", "pihole_group": "IOT"}, {"name": "default"}],
            "rules": [{"name": "plugs", "group": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}},
                      {"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}],
            "networks": [{"interface": "internal", "mode": "slices", "manage_reservations": false,
                          "slices": [{"group": "tvs", "cidr": "192.0.2.208/28"}, {"group": "iot_untrusted", "cidr": "192.0.2.224/28"}]}]})");

        World() {
            populate(fake);
            fake.dhcp[0]["ip-range"] = json::parse(R"([{"id": 1, "start-ip": "192.0.2.2", "end-ip": "192.0.2.200"}])");
            fake.dhcp[0]["reserved-address"] = json::parse(R"([{"id": 12, "type": "mac", "ip": "192.0.2.13", "mac": "00:00:5e:00:53:03",
                                                               "action": "reserved", "description": ""}])");
            for (const auto& d: fake.devices)
                fake.leases.push_back({{"ip", d["ipv4_address"]}, {"mac", d["mac"]}, {"interface", "internal"}, {"type", "ipv4"}});
            fake.addresses["Stick IP"] = {{"name", "Stick IP"}, {"type", "ipmask"}, {"subnet", "192.0.2.13 255.255.255.255"}, {"comment", ""}};
            fake.addrgrps["TVs"] = addrgrp("TVs", {"Stick IP"});
            fake.policies.insert(fake.policies.begin(),
                                 json{{"policyid", 17}, {"name", "Important Devices"}, {"status", "enable"}, {"action", "accept"},
                                      {"srcintf", json::array({{{"name", "internal"}}})}, {"dstintf", json::array({{{"name", "wan1"}}})},
                                      {"srcaddr", json::array({{{"name", "TVs"}}})}, {"dstaddr", json::array({{{"name", "all"}}})},
                                      {"service", json::array({{{"name", "ALL"}}})}, {"users", json::array()}, {"groups", json::array()}});
            // Whoever's lease is revoked renews into its reservation (the device's own MAC).
            fake.on_revoke = [this](const std::string& revoked) {
                for (auto& d: fake.devices) {
                    if (d["ipv4_address"] != revoked) continue;
                    for (const auto& r: fake.reservations(1))
                        if (r["mac"] == d["mac"]) {
                            fake.leases.push_back({{"ip", r["ip"]}, {"mac", d["mac"]}, {"interface", "internal"}, {"type", "ipv4"}});
                            d["ipv4_address"] = r["ip"];
                        }
                }
            };
            write();
        }

        void write() { write_private(home.path / "pihole" / "config.json", config.dump(2)); }

        int operator()(std::vector<std::string> args) {
            out.str({});
            err.str({});
            Environment env;
            env.home = {home.path / "pihole"};
            env.gateway = [this](const Config&, std::shared_ptr<WritePermits>) { return std::make_unique<Forwarder>(fake); };
            env.pihole = [this](const Config&) -> std::unique_ptr<PiholeApi> { return std::make_unique<PiholeForwarder>(pihole); };
            env.pihole_with_password = [this](const PiholeConfig&, const std::string&) -> std::unique_ptr<PiholeApi> {
                return std::make_unique<PiholeForwarder>(pihole);
            };
            env.clock = [this] { return ++now; };
            env.sleep = [](int) {};
            env.in = &in;
            env.out = &out;
            env.err = &err;
            return run(args, env);
        }

        std::string reserved(const char* mac) {
            for (const auto& r: fake.reservations(1))
                if (r["mac"] == mac) return r["ip"];
            return {};
        }
    };
}  // namespace

TEST(CliSync, SyncMapsSlicesInPihole) {
    World w;
    EXPECT_EQ(w({"sync"}), 0) << w.err.str() << w.out.str();
    std::vector<std::string> clients;
    for (const auto& c: w.pihole.state.clients) clients.push_back(c.client);
    std::ranges::sort(clients);
    EXPECT_EQ(clients, (std::vector<std::string>{"192.0.2.208/28", "192.0.2.224/28"}));
    // manage_reservations is off: no reservation or address changed.
    EXPECT_EQ(w.reserved(stick), "192.0.2.13");
    EXPECT_EQ(w({"sync"}), 0);
    EXPECT_EQ(w.pihole.applied.size(), 2u);   // idempotent
}

TEST(CliSync, DisabledAndPausedWriteNothing) {
    World w;
    w.config["enabled"] = false;
    w.write();
    EXPECT_EQ(w({"sync"}), 7);
    EXPECT_NE(w.out.str().find("not enabled"), std::string::npos);
    EXPECT_TRUE(w.fake.applied.empty());
    EXPECT_TRUE(w.pihole.applied.empty());

    w.config["enabled"] = true;
    w.write();
    EXPECT_EQ(w({"pause"}), 0);
    EXPECT_EQ(w({"sync"}), 0);
    EXPECT_NE(w.out.str().find("paused"), std::string::npos);
    EXPECT_TRUE(w.fake.applied.empty());
    EXPECT_EQ(w({"resume"}), 0);
    EXPECT_EQ(w({"sync"}), 0);
    EXPECT_FALSE(w.fake.applied.empty());
}

TEST(CliSync, MigrateNeedsAdoptionThenMovesAndRollsBack) {
    World w;
    ASSERT_EQ(w({"sync"}), 0);
    EXPECT_EQ(w({"migrate", stick, "--dry-run"}), 7);   // refused: reservation and object need adoption
    EXPECT_NE(w.err.str().find("adopt " + std::string(stick) + " --reservation"), std::string::npos) << w.err.str();
    EXPECT_EQ(w({"migrate", stick}), 7);
    EXPECT_EQ(w({"adopt", stick, "--reservation", "--object", "Stick IP"}), 0);
    EXPECT_EQ(w({"migrate", stick, "--dry-run"}), 0) << w.err.str();
    EXPECT_NE(w.out.str().find("192.0.2.13 -> 192.0.2.208"), std::string::npos) << w.out.str();
    EXPECT_EQ(w.reserved(stick), "192.0.2.13");   // dry run
    EXPECT_EQ(w({"migrate", stick}), 0) << w.out.str() << w.err.str();
    EXPECT_EQ(w.reserved(stick), "192.0.2.208");
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.208 255.255.255.255");

    EXPECT_EQ(w({"operations"}), 0);
    auto id = w.out.str().substr(0, w.out.str().find(' '));
    EXPECT_EQ(w({"operations", "show", id}), 0);
    EXPECT_NE(w.out.str().find("verify"), std::string::npos);
    EXPECT_EQ(w({"operations", "rollback", id}), 0) << w.out.str() << w.err.str();
    EXPECT_EQ(w.reserved(stick), "192.0.2.13");
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.13 255.255.255.255");
}

TEST(CliSync, GuiMoveWithManagedReservationsMigratesOnSync) {
    World w;
    w.config["networks"][0]["manage_reservations"] = true;
    w.write();
    EXPECT_EQ(w({"adopt", stick, "--reservation", "--object", "Stick IP"}), 0);
    // One migration per run by default: the first plug (lowest MAC) moves.
    EXPECT_EQ(w({"sync"}), 0) << w.out.str() << w.err.str();
    EXPECT_EQ(w.reserved(plug1), "192.0.2.224");
    EXPECT_EQ(w.reserved(stick), "192.0.2.13");
    EXPECT_EQ(w({"sync", "--max-migrations", "5"}), 0) << w.err.str();
    EXPECT_EQ(w.reserved(plug2), "192.0.2.225");
    EXPECT_EQ(w.reserved(stick), "192.0.2.208");
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.208 255.255.255.255");
    // Converged: another run changes nothing.
    auto applied = w.fake.applied.size();
    EXPECT_EQ(w({"sync", "--max-migrations", "5"}), 0);
    EXPECT_EQ(w.fake.applied.size(), applied);
}

TEST(CliSync, InspectionCommands) {
    World w;
    EXPECT_EQ(w({"groups"}), 0);
    EXPECT_NE(w.out.str().find("fp-grp-tvs"), std::string::npos);
    EXPECT_NE(w.out.str().find("Pi-hole TV"), std::string::npos);
    EXPECT_EQ(w({"networks"}), 0);
    EXPECT_NE(w.out.str().find("192.0.2.0/24"), std::string::npos);
    EXPECT_NE(w.out.str().find("slices"), std::string::npos);
    EXPECT_EQ(w({"slices"}), 0);
    EXPECT_NE(w.out.str().find("192.0.2.208/28"), std::string::npos);
    EXPECT_EQ(w({"references", "192.0.2.13"}), 0);
    EXPECT_NE(w.out.str().find("Stick IP"), std::string::npos);
    EXPECT_NE(w.out.str().find("policy 17"), std::string::npos);
    EXPECT_EQ(w({"status"}), 0);
    EXPECT_NE(w.out.str().find("pihole"), std::string::npos);
    EXPECT_EQ(w({"plan", "--json"}), 0);
    auto j = json::parse(w.out.str());
    EXPECT_EQ(j["pihole"]["changes"].size(), 2u);
    EXPECT_TRUE(w.fake.applied.empty());
    EXPECT_TRUE(w.pihole.applied.empty());
}
