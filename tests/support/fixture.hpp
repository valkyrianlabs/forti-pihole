//
// A small home network for the tests: two smart plugs (TP-Link), a streaming stick, a phone with a
// randomized MAC, a laptop, and an unknown device; policies where the whole LAN may browse and use
// the DNS server. Plus a temporary forti home for the CLI tests.
//

#ifndef FORTI_PIHOLE_TESTS_FIXTURE_HPP
#define FORTI_PIHOLE_TESTS_FIXTURE_HPP

#include "fake_gateway.hpp"

#include <cli.hpp>
#include <config.hpp>
#include <guard.hpp>
#include <inventory.hpp>
#include <pihole_link.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <sstream>

#include <stdlib.h>

namespace fph::test {

    namespace fs = std::filesystem;

    inline constexpr const char* plug1 = "00:00:5e:00:53:01";
    inline constexpr const char* plug2 = "00:00:5e:00:53:02";
    inline constexpr const char* stick = "00:00:5e:00:53:03";
    inline constexpr const char* phone = "02:00:5e:00:53:04";   // locally administered
    inline constexpr const char* laptop = "00:00:5e:00:53:05";
    inline constexpr const char* mystery = "00:00:5e:00:53:06";

    inline Config test_config() {
        return Config::from_json(json::parse(R"({
            "networks": [{"interface": "internal", "mode": "observe"}],
            "groups": [
                {"name": "owner", "privileged": true},
                {"name": "tvs"},
                {"name": "iot_untrusted"},
                {"name": "default"}
            ],
            "rules": [
                {"name": "plugs", "group": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}},
                {"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}
            ]
        })"));
    }

    inline void populate(FakeGateway& fake) {
        fake.devices = json::array({
                device(plug1, "192.0.2.11", {{"hardware_vendor", "TP-Link"}, {"hardware_family", "Plug"}, {"hostname", "HS103"}}),
                device(plug2, "192.0.2.12", {{"hardware_vendor", "TP-Link"}, {"hardware_family", "Plug"}, {"hostname", "HS103"}}),
                device(stick, "192.0.2.13", {{"hardware_vendor", "Amazon"}, {"hardware_family", "Fire TV Stick"}, {"os_name", "Fire OS"}}),
                device(phone, "192.0.2.14", {{"hardware_vendor", "Apple"}, {"hardware_family", "iPhone"}, {"hostname", "Alexs-Phone"},
                                             {"os_name", "iOS"}, {"os_version", "26.6"}}),
                device(laptop, "192.0.2.15", {{"hardware_vendor", "Apple"}, {"hardware_family", "Mac"}, {"hostname", "Studio"}}),
                device(mystery, "192.0.2.16"),
        });
        fake.addresses["all"] = {{"name", "all"}, {"type", "ipmask"}, {"subnet", "0.0.0.0 0.0.0.0"}, {"comment", ""}};
        fake.addresses["LAN"] = {{"name", "LAN"}, {"type", "interface-subnet"}, {"subnet", "192.0.2.0 255.255.255.0"}, {"comment", ""}};
        fake.addresses["DNS Server"] = {{"name", "DNS Server"}, {"type", "ipmask"}, {"subnet", "198.51.100.2 255.255.255.255"}, {"comment", ""}};
        fake.policies = json::parse(R"([
            {"policyid": 12, "name": "DNS", "status": "enable", "action": "accept", "srcintf": [{"name": "internal"}],
             "dstintf": [{"name": "internal1"}], "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "DNS Server"}],
             "service": [{"name": "DNS"}], "users": [], "groups": []},
            {"policyid": 2, "name": "LAN out", "status": "enable", "action": "accept", "srcintf": [{"name": "internal"}],
             "dstintf": [{"name": "wan1"}], "srcaddr": [{"name": "LAN"}], "dstaddr": [{"name": "all"}],
             "service": [{"name": "Web Access"}], "users": [], "groups": []}
        ])");
    }

    inline void remove_device(FakeGateway& fake, const std::string& mac) {
        json kept = json::array();
        for (const auto& d: fake.devices)
            if (d["mac"] != mac) kept.push_back(d);
        fake.devices = kept;
    }

    struct TempHome {
        fs::path path;
        TempHome() {
            std::string pattern = (fs::temp_directory_path() / "forti-pihole-test-XXXXXX").string();
            if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp failed");
            path = pattern;
        }
        ~TempHome() {
            std::error_code ignored;
            fs::remove_all(path, ignored);
        }
        TempHome(const TempHome&) = delete;
        TempHome& operator=(const TempHome&) = delete;
    };

    // Drives the CLI against a FakeGateway the test keeps (the gateway factory hands out a forwarder).
    class Forwarder final : public Gateway {
        FakeGateway& fake_;

    public:
        explicit Forwarder(FakeGateway& fake) : fake_(fake) {}
        json read(const json& r) override { return fake_.read(r); }
        json plan(const json& r) override { return fake_.plan(r); }
        json apply(const json& r) override { return fake_.apply(r); }
        json discover(const json& r) override { return fake_.discover(r); }
    };

    struct Cli {
        TempHome home;
        FakeGateway fake;
        std::int64_t now = 1'800'000'100;
        std::ostringstream out, err;
        std::istringstream in;

        Cli() {
            populate(fake);
            auto config = test_config().to_json();
            config["enabled"] = true;   // these tests exercise sync; the shipped default is off
            write_private(home.path / "pihole" / "config.json", config.dump(2));
        }

        int operator()(std::vector<std::string> args) {
            out.str({});
            err.str({});
            Environment env;
            env.home = {home.path / "pihole"};
            env.gateway = [this](const Config&, std::shared_ptr<WritePermits>) { return std::make_unique<Forwarder>(fake); };
            env.pihole = [](const Config&) -> std::unique_ptr<PiholeApi> { throw PiholeLinkError("no Pi-hole in this test"); };
            env.pihole_with_password = [](const PiholeConfig&, const std::string&) -> std::unique_ptr<PiholeApi> {
                throw PiholeLinkError("no Pi-hole in this test");
            };
            env.sleep = [](int) {};
            env.in = &in;
            env.clock = [this] { return now; };
            env.out = &out;
            env.err = &err;
            return run(args, env);
        }
    };

}  // namespace fph::test

#endif  // FORTI_PIHOLE_TESTS_FIXTURE_HPP
