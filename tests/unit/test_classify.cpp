// Classification precedence, ambiguity, privileged groups, GUI overrides, adoption, overlaps and
// reassociation candidates.

#include "fixture.hpp"

#include <classify.hpp>
#include <reassociate.hpp>

#include <algorithm>

using namespace fph;
using namespace fph::test;

namespace {
    constexpr std::int64_t now = 1'800'000'100;

    Classification run_classify(FakeGateway& fake, const Config& config, const State& state = {}) {
        return classify(collect(fake, config, now), config, state, now);
    }
}  // namespace

TEST(Classify, RulesAndDefault) {
    FakeGateway fake;
    populate(fake);
    auto c = run_classify(fake, test_config());
    EXPECT_EQ(c.decision(plug1)->group, "iot_untrusted");
    EXPECT_EQ(c.decision(plug1)->source, "rule");
    EXPECT_EQ(c.decision(plug1)->detail, "plugs");
    EXPECT_EQ(c.decision(stick)->group, "tvs");
    EXPECT_EQ(c.decision(mystery)->group, "default");
    EXPECT_EQ(c.decision(mystery)->source, "default");
    // Nothing matches the phone: it never lands in the privileged group by inference.
    EXPECT_EQ(c.decision(phone)->group, "default");
    EXPECT_TRUE(c.decision(plug1)->create_member);
    EXPECT_TRUE(c.decision(plug1)->member.starts_with("fp-dev-hs103-"));
}

TEST(Classify, TiesBetweenSegmentsAreAmbiguous) {
    FakeGateway fake;
    populate(fake);
    auto j = test_config().to_json();
    j["rules"].push_back({{"name", "amazon-iot"}, {"group", "iot_untrusted"}, {"priority", 100}, {"match", {{"vendor", "Amazon"}}}});
    auto c = run_classify(fake, Config::from_json(j));
    EXPECT_EQ(c.decision(stick)->group, "default");
    EXPECT_EQ(c.decision(stick)->source, "ambiguous");
    EXPECT_EQ(c.decision(stick)->matches.size(), 2u);
}

TEST(Classify, HigherPriorityWins) {
    FakeGateway fake;
    populate(fake);
    auto j = test_config().to_json();
    j["rules"].push_back({{"name", "amazon-iot"}, {"group", "iot_untrusted"}, {"priority", 300}, {"match", {{"vendor", "Amazon"}}}});
    auto c = run_classify(fake, Config::from_json(j));
    EXPECT_EQ(c.decision(stick)->group, "iot_untrusted");
}

TEST(Classify, NativeRuleObjects) {
    FakeGateway fake;
    populate(fake);
    fake.addresses["fp-rule-tvs-amazon"] = {{"name", "fp-rule-tvs-amazon"}, {"type", "dynamic"},
                                               {"sub-type", "device-identification"}, {"hw-vendor", "Amazon"}, {"comment", ""}};
    // A native rule naming a privileged group is ignored with a warning.
    fake.addresses["fp-rule-owner-apple"] = {{"name", "fp-rule-owner-apple"}, {"type", "dynamic"},
                                                 {"sub-type", "device-identification"}, {"hw-vendor", "Apple"}, {"comment", ""}};
    auto j = test_config().to_json();
    j["rules"] = json::array();
    auto c = run_classify(fake, Config::from_json(j));
    EXPECT_EQ(c.decision(stick)->group, "tvs");
    EXPECT_TRUE(c.decision(stick)->matches.front().native);
    EXPECT_EQ(c.decision(phone)->group, "default");
    EXPECT_TRUE(std::ranges::any_of(c.warnings, [](const auto& w) { return w.find("privileged") != std::string::npos; }));
}

TEST(Classify, ExplicitBeatsRules) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    state.pins[plug1] = {"tvs", "assign", now};
    state.pins[phone] = {"owner", "assign", now};
    auto c = run_classify(fake, config, state);
    EXPECT_EQ(c.decision(plug1)->group, "tvs");
    EXPECT_EQ(c.decision(plug1)->source, "pin");
    EXPECT_EQ(c.decision(phone)->group, "owner");   // privileged, but explicit

    auto j = config.to_json();
    j["assignments"] = {{plug1, "default"}};
    c = run_classify(fake, Config::from_json(j), state);
    EXPECT_EQ(c.decision(plug1)->group, "default");
    EXPECT_EQ(c.decision(plug1)->source, "assignment");
}

TEST(Classify, ProtectedDevicesAreKeptAsTheyAre) {
    FakeGateway fake;
    populate(fake);
    auto j = test_config().to_json();
    j["protected"] = {laptop};
    auto c = run_classify(fake, Config::from_json(j));
    EXPECT_TRUE(c.decision(laptop)->keep);
    EXPECT_EQ(c.decision(laptop)->source, "protected");
}

TEST(Classify, AdoptsAnAdministratorsSingleMacObject) {
    FakeGateway fake;
    populate(fake);
    fake.addresses["Living Room Stick"] = mac_address("Living Room Stick", stick);
    // A range is not adopted: it stands for more than this device.
    fake.addresses["Plugs"] = {{"name", "Plugs"}, {"type", "mac"}, {"comment", ""},
                               {"macaddr", json::array({{{"macaddr", "00:00:5e:00:53:00-00:00:5e:00:53:02"}}})}};
    auto c = run_classify(fake, test_config());
    EXPECT_EQ(c.decision(stick)->member, "Living Room Stick");
    EXPECT_TRUE(c.decision(stick)->adopted);
    EXPECT_FALSE(c.decision(stick)->create_member);
    EXPECT_TRUE(c.decision(plug1)->create_member);
}

TEST(Classify, GuiMoveBecomesAPin) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    auto marker_comment = std::string(marker) + ": x";
    fake.addresses["fp-dev-hs103-005301"] = mac_address("fp-dev-hs103-005301", plug1, marker_comment);
    fake.addrgrps["fp-grp-iot_untrusted"] = addrgrp("fp-grp-iot_untrusted", {}, marker_comment);
    fake.addrgrps["fp-grp-tvs"] = addrgrp("fp-grp-tvs", {"fp-dev-hs103-005301"}, marker_comment);
    State state;
    state.devices[plug1].object = "fp-dev-hs103-005301";
    state.devices[plug1].written_group = "iot_untrusted";   // where the companion put it
    auto c = run_classify(fake, config, state);
    EXPECT_EQ(c.decision(plug1)->group, "tvs");
    EXPECT_EQ(c.decision(plug1)->source, "pin");
    ASSERT_TRUE(c.new_pins.contains(plug1));
    EXPECT_EQ(c.new_pins.at(plug1).source, "gui");
}

TEST(Classify, RemovedFromEveryGroupGoesToDefault) {
    FakeGateway fake;
    populate(fake);
    auto marker_comment = std::string(marker) + ": x";
    fake.addresses["fp-dev-hs103-005301"] = mac_address("fp-dev-hs103-005301", plug1, marker_comment);
    fake.addrgrps["fp-grp-iot_untrusted"] = addrgrp("fp-grp-iot_untrusted", {}, marker_comment);
    State state;
    state.devices[plug1].object = "fp-dev-hs103-005301";
    state.devices[plug1].written_group = "iot_untrusted";
    auto c = run_classify(fake, test_config(), state);
    EXPECT_EQ(c.decision(plug1)->group, "default");
}

TEST(Classify, DeletingTheObjectResetsAGuiPin) {
    FakeGateway fake;
    populate(fake);
    State state;
    state.devices[plug1].object = "fp-dev-hs103-005301";   // gone from the device
    state.devices[plug1].written_group = "tvs";
    state.pins[plug1] = {"tvs", "gui", now};
    auto c = run_classify(fake, test_config(), state);
    EXPECT_TRUE(c.cleared_pins.contains(plug1));
    EXPECT_EQ(c.decision(plug1)->group, "iot_untrusted");
}

TEST(Classify, OverlapsAreReportedWithTheWinner) {
    FakeGateway fake;
    populate(fake);
    auto marker_comment = std::string(marker) + ": x";
    fake.addresses["Stick"] = mac_address("Stick", stick);
    fake.addrgrps["fp-grp-tvs"] = addrgrp("fp-grp-tvs", {"Stick"}, marker_comment);
    fake.addrgrps["fp-grp-iot_untrusted"] = addrgrp("fp-grp-iot_untrusted", {"Stick"}, marker_comment);
    auto c = run_classify(fake, test_config());
    ASSERT_EQ(c.overlaps.size(), 1u);
    EXPECT_EQ(c.overlaps[0].mac, stick);
    // Both placements are the operator's; the earlier group in the configuration wins.
    EXPECT_EQ(c.overlaps[0].winner, "tvs");
}

TEST(Classify, ForeignGroupWithOurNameIsNotManaged) {
    FakeGateway fake;
    populate(fake);
    fake.addrgrps["fp-grp-tvs"] = addrgrp("fp-grp-tvs", {}, "someone else's");
    auto c = run_classify(fake, test_config());
    EXPECT_TRUE(c.unusable_groups.contains("tvs"));
    EXPECT_EQ(c.decision(stick)->group, "default");
}

TEST(Classify, GlobMatching) {
    EXPECT_TRUE(glob_match("Fire TV*", "fire tv stick"));
    EXPECT_TRUE(glob_match("HS1??", "HS103"));
    EXPECT_FALSE(glob_match("HS1??", "HS1030"));
    EXPECT_TRUE(glob_match("*", ""));
    EXPECT_TRUE(glob_match("a*b*c", "aXXbYYc"));
    EXPECT_FALSE(glob_match("a*b*c", "aXXbYY"));
}

TEST(Reassociate, DistinctiveHostnameOnly) {
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    // The phone used to be 02:00:5e:00:53:44 (offline now), pinned to the privileged group.
    state.devices["02:00:5e:00:53:44"] = {"Alexs-Phone", "Alexs-Phone", "Apple", "iPhone", "iOS", "26.6", true, 1, 1, "fp-dev-old", "owner"};
    state.pins["02:00:5e:00:53:44"] = {"owner", "assign", 1};
    auto snapshot = collect(fake, config, now);
    auto c = classify(snapshot, config, state, now);
    auto found = find_candidates(snapshot, state, c, now);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].new_mac, phone);
    EXPECT_GE(found[0].score, candidate_threshold);
    // Never applied on its own: the new MAC is still classified by its own merits.
    EXPECT_EQ(c.decision(phone)->group, "default");

    // Rejected once, never proposed again.
    state.dismissed.insert(found[0].id);
    EXPECT_TRUE(find_candidates(snapshot, state, c, now).empty());
}

TEST(Reassociate, GenericNamesAreNotEvidence) {
    EXPECT_TRUE(generic_hostname("iPhone"));
    EXPECT_TRUE(generic_hostname("iPhone-303"));
    EXPECT_TRUE(generic_hostname("Watch"));
    EXPECT_TRUE(generic_hostname("HS103"));
    EXPECT_FALSE(generic_hostname("Alexs-iPhone"));
    FakeGateway fake;
    populate(fake);
    auto config = test_config();
    State state;
    state.devices["00:00:5e:00:53:99"] = {"HS103", "HS103", "TP-Link", "Plug", "", "", false, 1, 1, "fp-dev-x", "iot_untrusted"};
    auto snapshot = collect(fake, config, now);
    auto c = classify(snapshot, config, state, now);
    EXPECT_TRUE(find_candidates(snapshot, state, c, now).empty());
}
