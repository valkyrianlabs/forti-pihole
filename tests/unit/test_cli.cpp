// The commands end to end against the in-memory FortiGate and a temporary forti home.

#include "fixture.hpp"

#include <state.hpp>

using namespace fph;
using namespace fph::test;

TEST(Cli, HelpVersionAndUsage) {
    Cli cli;
    EXPECT_EQ(cli({"--help"}), 0);
    EXPECT_NE(cli.out.str().find("usage: forti-pihole"), std::string::npos);
    EXPECT_EQ(cli({"--version"}), 0);
    EXPECT_NE(cli.out.str().find("forti-pihole "), std::string::npos);
    EXPECT_EQ(cli({"frobnicate"}), 2);
    EXPECT_EQ(cli({"report", "--bogus"}), 2);
}

TEST(Cli, InitRefusesToOverwrite) {
    Cli cli;
    EXPECT_EQ(cli({"init"}), 3);
    fs::remove(cli.home.path / "pihole" / "config.json");
    EXPECT_EQ(cli({"init"}), 0);
    EXPECT_TRUE(fs::exists(cli.home.path / "pihole" / "config.json"));
    auto perms = fs::status(cli.home.path / "pihole" / "config.json").permissions();
    EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
}

TEST(Cli, ReportIsReadOnly) {
    Cli cli;
    EXPECT_EQ(cli({"report", "-v"}), 0);
    EXPECT_TRUE(cli.fake.plans.empty());
    EXPECT_FALSE(fs::exists(cli.home.path / "pihole" / "state.json"));
    auto text = cli.out.str();
    EXPECT_NE(text.find("iot_untrusted"), std::string::npos);
    EXPECT_NE(text.find("Pending changes"), std::string::npos);
    EXPECT_EQ(cli({"report", "--json"}), 0);
    auto j = json::parse(cli.out.str());
    EXPECT_EQ(j["devices"].size(), 6u);
    EXPECT_FALSE(j["pending"]["operations"].empty());
}

TEST(Cli, ApplyThenInSync) {
    Cli cli;
    EXPECT_EQ(cli({"apply"}), 0) << cli.err.str();
    EXPECT_EQ(cli.fake.applied.size(), 1u);
    EXPECT_EQ(cli.fake.members("fp-seg-iot_untrusted").size(), 2u);
    EXPECT_EQ(cli({"apply", "--quiet"}), 0);
    EXPECT_EQ(cli.out.str(), "");
    EXPECT_EQ(cli.fake.applied.size(), 1u);   // nothing new to plan
    auto history = read_history(cli.home.path / "pihole" / "history.jsonl", 10);
    ASSERT_EQ(history.size(), 1u);
    EXPECT_EQ(history[0]["status"], "applied");
}

TEST(Cli, GuiMoveIsRespected) {
    Cli cli;
    ASSERT_EQ(cli({"apply"}), 0);
    // The operator drags the stick's object from tvs to default in the FortiGate GUI.
    auto object = cli.fake.members("fp-seg-tvs").front();
    cli.fake.move_member("fp-seg-tvs", "fp-seg-default", object);
    ASSERT_EQ(cli({"apply"}), 0) << cli.err.str();
    // Nothing moved back; the decision is now a pin.
    EXPECT_TRUE(cli.fake.members("fp-seg-tvs").empty());
    auto state = load_state(cli.home.path / "pihole" / "state.json");
    ASSERT_TRUE(state.pins.contains(stick));
    EXPECT_EQ(state.pins[stick].segment, "default");
    EXPECT_EQ(state.pins[stick].source, "gui");
    // And it stays that way.
    ASSERT_EQ(cli({"apply"}), 0);
    EXPECT_TRUE(cli.fake.members("fp-seg-tvs").empty());
}

TEST(Cli, AssignAndAuto) {
    Cli cli;
    ASSERT_EQ(cli({"apply"}), 0);
    EXPECT_EQ(cli({"assign", "02-00-5E-00-53-04", "owner"}), 0);
    ASSERT_EQ(cli({"apply"}), 0) << cli.err.str();
    EXPECT_EQ(cli.fake.members("fp-seg-owner").size(), 1u);
    EXPECT_EQ(cli({"assign", phone, "auto"}), 0);
    ASSERT_EQ(cli({"apply"}), 0);
    EXPECT_TRUE(cli.fake.members("fp-seg-owner").empty());
    EXPECT_EQ(cli({"assign", phone, "nowhere"}), 2);
    EXPECT_EQ(cli({"assign", "not-a-mac", "tvs"}), 2);
}

TEST(Cli, GuardedModeWaitsForApproval) {
    Cli cli;
    cli.fake.mode = "guarded";
    EXPECT_EQ(cli({"apply"}), 7);
    EXPECT_NE(cli.err.str().find("forti approve"), std::string::npos);
    EXPECT_TRUE(cli.fake.applied.empty());
    auto state = load_state(cli.home.path / "pihole" / "state.json");
    ASSERT_TRUE(state.pending);
    // Still waiting: no new plan is made on top of it.
    auto plans = cli.fake.plans.size();
    EXPECT_EQ(cli({"apply"}), 7);
    EXPECT_EQ(cli.fake.plans.size(), plans);
    // A person approves it; the next run applies exactly that plan.
    cli.fake.approved.insert(state.pending->plan_id);
    EXPECT_EQ(cli({"apply"}), 0) << cli.err.str();
    EXPECT_EQ(cli.fake.applied.size(), 1u);
    EXPECT_FALSE(load_state(cli.home.path / "pihole" / "state.json").pending);
    EXPECT_EQ(cli.fake.members("fp-seg-iot_untrusted").size(), 2u);
    // And the result is not mistaken for GUI moves.
    EXPECT_TRUE(load_state(cli.home.path / "pihole" / "state.json").pins.empty());
}

TEST(Cli, ReadOnlyProfileAppliesNothing) {
    Cli cli;
    cli.fake.mode = "read-only";
    EXPECT_EQ(cli({"apply"}), 7);
    EXPECT_TRUE(cli.fake.groups.empty());
}

TEST(Cli, FailedReadsChangeNothing) {
    Cli cli;
    cli.fake.fail_reads = true;
    EXPECT_EQ(cli({"apply"}), 4);
    EXPECT_NE(cli.err.str().find("nothing was changed"), std::string::npos);
    EXPECT_TRUE(cli.fake.plans.empty());
}

TEST(Cli, ReassociationNeedsConfirmation) {
    Cli cli;
    ASSERT_EQ(cli({"assign", phone, "owner"}), 0);
    ASSERT_EQ(cli({"apply"}), 0);
    // The phone comes back with a new private address; the old one is offline.
    const std::string fresh = "02:00:5e:00:53:77";
    for (auto& d: cli.fake.devices)
        if (d["mac"] == phone) d["is_online"] = false;
    cli.fake.devices.push_back(device(fresh, "192.0.2.77", {{"hardware_vendor", "Apple"}, {"hardware_family", "iPhone"},
                                                            {"hostname", "Alexs-Phone"}, {"os_name", "iOS"}, {"os_version", "26.6"}}));
    cli.now += 3600;
    ASSERT_EQ(cli({"apply"}), 0) << cli.err.str();
    auto state = load_state(cli.home.path / "pihole" / "state.json");
    ASSERT_EQ(state.candidates.size(), 1u);
    // Not transferred on its own: the new MAC sits in default.
    auto owner = cli.fake.members("fp-seg-owner");
    EXPECT_EQ(owner.size(), 1u);
    auto id = state.candidates[0].id;
    EXPECT_EQ(cli({"confirm", id}), 0) << cli.err.str();
    ASSERT_EQ(cli({"apply"}), 0) << cli.err.str();
    state = load_state(cli.home.path / "pihole" / "state.json");
    EXPECT_EQ(state.pins[fresh].segment, "owner");
    EXPECT_EQ(state.pins[fresh].source, "confirm");
    EXPECT_FALSE(state.devices.contains(phone));   // retired
    owner = cli.fake.members("fp-seg-owner");
    ASSERT_EQ(owner.size(), 1u);
    EXPECT_NE(owner[0].find("005377"), std::string::npos) << owner[0];   // the new MAC's object
}

TEST(Cli, StatusAndHistory) {
    Cli cli;
    ASSERT_EQ(cli({"apply"}), 0);
    EXPECT_EQ(cli({"status"}), 0);
    EXPECT_NE(cli.out.str().find("autonomous"), std::string::npos);
    EXPECT_EQ(cli({"history"}), 0);
    EXPECT_NE(cli.out.str().find("applied"), std::string::npos);
}
