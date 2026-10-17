// A migration end to end against the in-memory FortiGate and Pi-hole: forward, a device that does not
// renew, resume, rollback, and a crash in the middle.

#include "fake_pihole.hpp"
#include "fixture.hpp"

#include <classify.hpp>
#include <executors.hpp>
#include <migrate.hpp>

#include <algorithm>
#include <memory>

using namespace fph;
using namespace fph::test;

namespace {
    struct World {
        TempHome home;
        FakeGateway fake;
        FakePihole pihole;
        std::int64_t now = 1'800'000'100;
        Config config = Config::from_json(json::parse(R"({"groups": [{"name": "tvs", "pihole_group": "TV"}, {"name": "default"}],
            "rules": [{"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}],
            "networks": [{"interface": "internal", "mode": "slices", "manage_reservations": true,
                          "slices": [{"group": "tvs", "cidr": "192.0.2.208/28"}]}]})"));
        std::shared_ptr<WritePermits> permits = std::make_shared<WritePermits>();
        Journal journal{home.path / "operations"};
        bool device_renews = true;

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
            // A revoked device renews into its reservation, when it renews at all.
            fake.on_revoke = [this](const std::string&) {
                if (!device_renews) return;
                for (const auto& r: fake.reservations(1))
                    if (r["mac"] == stick) {
                        fake.leases.push_back({{"ip", r["ip"]}, {"mac", stick}, {"interface", "internal"}, {"type", "ipv4"}});
                        for (auto& d: fake.devices)
                            if (d["mac"] == stick) d["ipv4_address"] = r["ip"];
                    }
            };
        }

        Operation plan() {
            auto snapshot = collect(fake, config, now);
            auto c = classify(snapshot, config, {}, now);
            SliceAction move;
            for (const auto& a: plan_slicing(config, snapshot, c).actions)
                if (a.mac == stick) move = a;
            Adoptions adopt;
            adopt.reservation = true;
            adopt.address_objects = {"Stick IP"};
            auto m = plan_migration(config, snapshot, move, adopt, now);
            if (!m.operation) throw std::runtime_error(m.refusal.reason);
            journal.save(*m.operation, now);
            return *m.operation;
        }

        Runtime runtime() { return Runtime{fake, permits, &pihole, config, [this] { return ++now; }, [](int) {}}; }

        std::string run(Operation& op) {
            auto rt = runtime();
            MigrationExecutors executors(rt);
            return run_operation(op, journal, [&](const Step& s) { return executors(s); }, rt.clock);
        }

        std::string rollback(Operation& op) {
            auto rt = runtime();
            MigrationExecutors executors(rt);
            return rollback_operation(op, journal, [&](const Step& s) { return executors(s); }, rt.clock);
        }

        std::string reserved_ip() {
            for (const auto& r: fake.reservations(1))
                if (r["mac"] == stick) return r["ip"];
            return {};
        }
        std::string lease_ip() {
            for (const auto& l: fake.leases)
                if (l["mac"] == stick) return l["ip"];
            return {};
        }
    };
}  // namespace

TEST(MigrationRun, MovesTheDeviceAndItsPrivileges) {
    World w;
    auto op = w.plan();
    EXPECT_EQ(w.run(op), "done") << op.to_json().dump(2);
    EXPECT_EQ(w.reserved_ip(), "192.0.2.208");
    EXPECT_EQ(w.lease_ip(), "192.0.2.208");
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.208 255.255.255.255");   // privileges followed the device
    ASSERT_EQ(w.pihole.state.clients.size(), 1u);
    EXPECT_EQ(w.pihole.state.clients[0].client, "192.0.2.208/28");
    EXPECT_EQ(w.pihole.effective_groups("192.0.2.208"), std::vector<int>{2});
    EXPECT_EQ(op.step("verify")->result["reach"]["internet"].get<std::string>().find("17") != std::string::npos, true);
    // Only the permitted writes went out, and the permits were withdrawn afterwards.
    EXPECT_TRUE(w.permits->empty());
    // The old reservation entry was updated in place, never the whole list.
    for (const auto& ops: w.fake.plans)
        for (const auto& o: ops) EXPECT_FALSE(o.contains("set") && o["set"].contains("reserved-address"));
}

TEST(MigrationRun, DeviceThatDoesNotRenewWaitsThenResumes) {
    World w;
    w.device_renews = false;
    auto op = w.plan();
    EXPECT_EQ(w.run(op), "waiting");
    EXPECT_EQ(op.step("observe")->status, "waiting");
    EXPECT_NE(op.step("observe")->error.find("reconnect"), std::string::npos);
    // The old address no longer carries the stick's privileges even while it waits.
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.208 255.255.255.255");
    auto revokes = std::ranges::count_if(w.fake.plans, [](const json& ops) { return ops[0]["resource"] == "monitor/system/dhcp/revoke"; });
    // The person reconnects the device; resume continues without revoking again.
    w.fake.leases.push_back({{"ip", "192.0.2.208"}, {"mac", stick}, {"interface", "internal"}, {"type", "ipv4"}});
    for (auto& d: w.fake.devices)
        if (d["mac"] == stick) d["ipv4_address"] = "192.0.2.208";
    auto loaded = *w.journal.load(op.id);
    EXPECT_EQ(w.run(loaded), "done");
    EXPECT_EQ(std::ranges::count_if(w.fake.plans, [](const json& ops) { return ops[0]["resource"] == "monitor/system/dhcp/revoke"; }), revokes);
}

TEST(MigrationRun, RollbackRestoresEverything) {
    World w;
    auto op = w.plan();
    ASSERT_EQ(w.run(op), "done");
    EXPECT_EQ(w.rollback(op), "rolled-back") << op.to_json().dump(2);
    EXPECT_EQ(w.reserved_ip(), "192.0.2.13");
    EXPECT_EQ(w.lease_ip(), "192.0.2.13");   // revoked the new lease; renewed into the old reservation
    EXPECT_EQ(w.fake.addresses["Stick IP"]["subnet"], "192.0.2.13 255.255.255.255");
    EXPECT_TRUE(w.pihole.state.clients.empty());   // the entry this migration created is gone
    EXPECT_TRUE(w.permits->empty());
}

TEST(MigrationRun, CrashAfterTheReservationResumesWithoutRepeating) {
    World w;
    auto op = w.plan();
    // Run the first two steps, then "crash" with the third marked running.
    {
        auto rt = w.runtime();
        MigrationExecutors executors(rt);
        for (auto& s: op.steps) {
            if (s.id == "objects") {
                s.status = "running";
                break;
            }
            auto outcome = executors(s)->forward(s);
            s.status = "done";
            s.result = outcome.result;
            s.compensate = outcome.compensate;
        }
        w.journal.save(op, w.now);
    }
    auto plans_before = w.fake.plans.size();
    auto loaded = *w.journal.load(op.id);
    EXPECT_EQ(w.run(loaded), "done");
    // objects re-ran (nothing recorded it as applied), revoke/observe/verify ran once; the reservation
    // was not planned again.
    EXPECT_EQ(w.fake.plans.size(), plans_before + 2);
    EXPECT_EQ(w.reserved_ip(), "192.0.2.208");
}

TEST(MigrationRun, ApprovalRequiredWaitsAndRetriesTheSamePlan) {
    World w;
    w.fake.mode = "guarded";
    auto op = w.plan();
    EXPECT_EQ(w.run(op), "waiting");
    EXPECT_EQ(op.step("reservation")->status, "waiting");
    auto id = op.step("reservation")->result["plan_id"].get<std::string>();
    EXPECT_NE(op.step("reservation")->error.find("forti approve " + id), std::string::npos);
    w.fake.mode = "autonomous";
    auto loaded = *w.journal.load(op.id);
    EXPECT_EQ(w.run(loaded), "done");
    EXPECT_NE(std::ranges::find(w.fake.applied, id), w.fake.applied.end());   // the approved plan itself
}
