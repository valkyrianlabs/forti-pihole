// Scheduler timing on an injected clock (no sleeping): debounce, max delay, periodic runs,
// coalescing during a run, backoff with jitter and its cap, restore after a restart, postponement;
// and loop prevention (the event parser and the guard).

#include <events.hpp>
#include <scheduler.hpp>

#include <gtest/gtest.h>

namespace fph::daemon::test {

    namespace {

        constexpr std::int64_t s = 1000;
        constexpr std::int64_t minute = 60 * s;

        ConfigEvent change(std::string path, std::string object) {
            ConfigEvent event;
            event.cfgpath = std::move(path);
            event.cfgobj = std::move(object);
            event.structured = true;
            return event;
        }

        // Defaults: debounce 10 s, max delay 60 s, periodic 15 min, backoff 10 s .. 15 min, suppression 60 s.
        // Jitter 1.0: the full (un-halved) delay, so expectations are exact.
        Scheduler make(double jitter = 1.0) { return Scheduler(Timing{}, [jitter] { return jitter; }); }

        // A scheduler past its startup run, idle at time `t`.
        Scheduler idle_at(std::int64_t t, double jitter = 1.0) {
            auto scheduler = make(jitter);
            scheduler.restore(t, 0, 0);
            EXPECT_EQ(scheduler.take_due(t), RunReason::startup);
            scheduler.finish(t, {});
            return scheduler;
        }

    }  // namespace

    TEST(Scheduler, StartupRunsImmediately) {
        auto scheduler = make();
        scheduler.restore(0, 0, 0);
        EXPECT_TRUE(scheduler.pending());
        EXPECT_EQ(scheduler.next_due_in(0), 0);
        EXPECT_EQ(scheduler.take_due(0), RunReason::startup);
        EXPECT_TRUE(scheduler.running());
        EXPECT_EQ(scheduler.next_due_in(0), -1);
        EXPECT_FALSE(scheduler.take_due(0));   // at most one run at a time
        scheduler.finish(5 * s, {});
        EXPECT_FALSE(scheduler.pending());
        EXPECT_EQ(scheduler.next_due_in(5 * s), 15 * minute);
    }

    TEST(Scheduler, DebouncesABurst) {
        auto scheduler = idle_at(0);
        EXPECT_EQ(scheduler.on_event(100 * s, change("firewall.address", "a")), Scheduler::Outcome::scheduled);
        EXPECT_EQ(scheduler.next_due_in(100 * s), 10 * s);
        EXPECT_FALSE(scheduler.take_due(109 * s));
        // Another event restarts the quiet period.
        scheduler.on_event(108 * s, change("firewall.address", "b"));
        EXPECT_FALSE(scheduler.take_due(117 * s));
        EXPECT_EQ(scheduler.take_due(118 * s), RunReason::event);
        scheduler.finish(120 * s, {});
        EXPECT_FALSE(scheduler.pending());
    }

    TEST(Scheduler, MaxDelayBoundsAnEndlessBurst) {
        auto scheduler = idle_at(0);
        // An event every 5 s, forever: the quiet period never comes, the max delay (60 s) does.
        std::int64_t t = 100 * s;
        std::optional<RunReason> reason;
        for (; t < 300 * s && !reason; t += 5 * s) {
            scheduler.on_event(t, change("firewall.policy", "1"));
            reason = scheduler.take_due(t);
        }
        ASSERT_EQ(reason, RunReason::event);
        EXPECT_EQ(t - 5 * s, 160 * s);
    }

    TEST(Scheduler, PeriodicFullReconcile) {
        auto scheduler = idle_at(0);
        EXPECT_FALSE(scheduler.take_due(15 * minute - 1));
        EXPECT_EQ(scheduler.take_due(15 * minute), RunReason::periodic);
        scheduler.finish(15 * minute + 30 * s, {});
        // Measured from when the last run finished.
        EXPECT_EQ(scheduler.next_due_in(15 * minute + 30 * s), 15 * minute);
        // An event-driven run resets it too.
        scheduler.on_event(20 * minute, change("system.interface", "port1"));
        EXPECT_EQ(scheduler.take_due(20 * minute + 10 * s), RunReason::event);
        scheduler.finish(20 * minute + 20 * s, {});
        EXPECT_EQ(scheduler.next_due_in(20 * minute + 20 * s), 15 * minute);
    }

    TEST(Scheduler, CoalescesEventsDuringARunIntoOneFollowUp) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "a"));
        ASSERT_EQ(scheduler.take_due(20 * s), RunReason::event);
        for (int i = 0; i < 50; ++i)
            EXPECT_EQ(scheduler.on_event(21 * s + i, change("firewall.address", "x" + std::to_string(i))), Scheduler::Outcome::held);
        EXPECT_FALSE(scheduler.take_due(40 * s));
        scheduler.finish(45 * s, {});
        // The held events arrived at ~21 s: their quiet period has passed, so exactly one follow-up now.
        EXPECT_TRUE(scheduler.pending());
        EXPECT_EQ(scheduler.take_due(45 * s), RunReason::event);
        scheduler.finish(50 * s, {});
        EXPECT_FALSE(scheduler.pending());
        EXPECT_FALSE(scheduler.take_due(51 * s));
    }

    TEST(Scheduler, HeldEchoesOfTheRunsOwnWritesAreDropped) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "LAN"));
        ASSERT_EQ(scheduler.take_due(20 * s), RunReason::event);
        // The run writes two objects; the FortiGate reports both while the run is still going.
        scheduler.on_event(22 * s, change("firewall.address", "fp-dev-a"));
        scheduler.on_event(23 * s, change("firewall.addrgrp", "fp-seg-iot"));
        RunResult result;
        result.written = {{"firewall/address", "fp-dev-a"}, {"firewall/addrgrp", "fp-seg-iot"}};
        scheduler.finish(25 * s, result);
        EXPECT_FALSE(scheduler.pending());
        EXPECT_FALSE(scheduler.take_due(60 * s));
    }

    TEST(Scheduler, SuppressionWindowAfterARun) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "LAN"));
        ASSERT_EQ(scheduler.take_due(20 * s), RunReason::event);
        RunResult result;
        result.written = {{"firewall/address", "fp-dev-a"}};
        scheduler.finish(30 * s, result);
        // The echo, late: ignored within the 60 s window.
        EXPECT_EQ(scheduler.on_event(80 * s, change("firewall.address", "fp-dev-a")), Scheduler::Outcome::suppressed);
        EXPECT_FALSE(scheduler.pending());
        // Another object, or the same name on another path, is someone else's change.
        EXPECT_EQ(scheduler.on_event(81 * s, change("firewall.address", "fp-dev-b")), Scheduler::Outcome::scheduled);
        EXPECT_EQ(scheduler.on_event(82 * s, change("firewall.addrgrp", "fp-dev-a")), Scheduler::Outcome::scheduled);
        ASSERT_EQ(scheduler.take_due(92 * s), RunReason::event);
        scheduler.finish(95 * s, {});
        // After the window: the same object counts again (no permanent blind spot).
        EXPECT_EQ(scheduler.on_event(91 * s + minute, change("firewall.address", "fp-dev-a")), Scheduler::Outcome::scheduled);
    }

    TEST(Scheduler, UnattributedEventsAreNeverSuppressed) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "x"));
        ASSERT_TRUE(scheduler.take_due(20 * s));
        RunResult result;
        result.written = {{"firewall/address", ""}};
        scheduler.finish(21 * s, result);
        EXPECT_EQ(scheduler.on_event(22 * s, ConfigEvent{}), Scheduler::Outcome::scheduled);
    }

    TEST(Scheduler, ExponentialBackoffWithCap) {
        auto scheduler = idle_at(0);   // jitter 1.0: the full delay
        EXPECT_EQ(scheduler.backoff_ms(1), 10 * s);
        EXPECT_EQ(scheduler.backoff_ms(2), 20 * s);
        EXPECT_EQ(scheduler.backoff_ms(3), 40 * s);
        EXPECT_EQ(scheduler.backoff_ms(7), 640 * s);
        EXPECT_EQ(scheduler.backoff_ms(8), 900 * s);     // capped at 15 min
        EXPECT_EQ(scheduler.backoff_ms(1000), 900 * s);  // no overflow
        auto low = make(0.0);
        EXPECT_EQ(low.backoff_ms(1), 5 * s);             // jitter keeps at least half
        EXPECT_EQ(low.backoff_ms(100), 450 * s);
    }

    TEST(Scheduler, RetriesAfterFailureAndEventsDoNotCutTheBackoffShort) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "x"));
        ASSERT_EQ(scheduler.take_due(20 * s), RunReason::event);
        scheduler.finish(21 * s, {false, "connection refused", {}});
        EXPECT_EQ(scheduler.failures(), 1);
        EXPECT_TRUE(scheduler.pending());
        EXPECT_EQ(scheduler.next_due_in(21 * s), 10 * s);
        scheduler.on_event(22 * s, change("firewall.address", "y"));
        EXPECT_FALSE(scheduler.take_due(30 * s));
        ASSERT_EQ(scheduler.take_due(31 * s), RunReason::retry);
        scheduler.finish(32 * s, {false, "again", {}});
        EXPECT_EQ(scheduler.failures(), 2);
        EXPECT_EQ(scheduler.next_due_in(32 * s), 20 * s);
        ASSERT_EQ(scheduler.take_due(52 * s), RunReason::retry);
        scheduler.finish(53 * s, {});
        // Success clears the failure count and everything the retry covered.
        EXPECT_EQ(scheduler.failures(), 0);
        EXPECT_FALSE(scheduler.pending());
        EXPECT_EQ(scheduler.next_due_in(53 * s), 15 * minute);
    }

    TEST(Scheduler, RestoreResumesARecordedBackoff) {
        auto scheduler = make();
        scheduler.restore(0, 3, 30 * s);
        EXPECT_EQ(scheduler.failures(), 3);
        EXPECT_FALSE(scheduler.take_due(29 * s));   // no startup run while a backoff is recorded
        EXPECT_EQ(scheduler.take_due(30 * s), RunReason::retry);
        scheduler.finish(31 * s, {false, "still down", {}});
        EXPECT_EQ(scheduler.failures(), 4);
        EXPECT_EQ(scheduler.next_due_in(31 * s), 80 * s);

        auto overdue = make();
        overdue.restore(0, 2, -5 * s);   // the retry time passed while the daemon was down
        EXPECT_EQ(overdue.take_due(0), RunReason::retry);
    }

    TEST(Scheduler, PostponeHoldsPendingWork) {
        auto scheduler = idle_at(0);
        scheduler.on_event(10 * s, change("firewall.address", "x"));
        scheduler.postpone(50 * s);
        EXPECT_FALSE(scheduler.take_due(20 * s));
        EXPECT_EQ(scheduler.next_due_in(20 * s), 30 * s);
        EXPECT_TRUE(scheduler.pending());
        EXPECT_EQ(scheduler.take_due(50 * s), RunReason::event);
    }

    TEST(Scheduler, TimingChangesApply) {
        auto scheduler = idle_at(0);
        Timing fast;
        fast.debounce_ms = 1 * s;
        fast.max_delay_ms = 2 * s;
        scheduler.set_timing(fast);
        scheduler.on_event(10 * s, change("a.b", "c"));
        EXPECT_EQ(scheduler.take_due(11 * s), RunReason::event);
    }

    TEST(Events, ParsesTheTemplateBody) {
        auto event = parse_event(R"json({"source":"fortigate","logid":"0100044547","eventtime":"1760000000000000000","vd":"root",
            "user":"admin","ui":"GUI(192.0.2.50)","action":"Edit","cfgtid":"1234","cfgpath":"firewall.address",
            "cfgobj":"fp-dev-a","logdesc":"Object attribute configured"})json");
        EXPECT_TRUE(event.structured);
        EXPECT_EQ(event.logid, "0100044547");
        EXPECT_EQ(event.cfgpath, "firewall.address");
        EXPECT_EQ(event.resource(), "firewall/address");
        EXPECT_EQ(event.cfgobj, "fp-dev-a");
        EXPECT_EQ(event.action, "Edit");
        EXPECT_EQ(event.user, "admin");
        auto summary = event.summary();
        EXPECT_EQ(summary["cfgobj"], "fp-dev-a");
        EXPECT_FALSE(summary.contains("structured"));
    }

    TEST(Events, LenientWhenAValueBreaksTheJson) {
        // An object name with a quote, substituted unescaped.
        auto event = parse_event(R"({"cfgpath":"firewall.address","cfgobj":"my "odd" name","action":"Add"})");
        EXPECT_FALSE(event.structured);
        EXPECT_EQ(event.cfgpath, "firewall.address");
        EXPECT_EQ(event.cfgobj, "my \"odd\" name");
        EXPECT_EQ(event.action, "Add");
        // Doubled quotes (a substitution that adds its own).
        auto doubled = parse_event(R"({"cfgpath":""firewall.addrgrp"","cfgobj":""fp-seg-iot"",)");
        EXPECT_EQ(doubled.cfgpath, "firewall.addrgrp");
        EXPECT_EQ(doubled.cfgobj, "fp-seg-iot");
    }

    TEST(Events, UnsubstitutedVariablesAndJunk) {
        auto event = parse_event(R"({"cfgpath":"system.global","cfgobj":"%%log.cfgobj%%"})");
        EXPECT_EQ(event.cfgpath, "system.global");
        EXPECT_EQ(event.cfgobj, "");
        auto junk = parse_event("not json at all \x01\x02");
        EXPECT_FALSE(junk.structured);
        EXPECT_TRUE(junk.cfgpath.empty());
        auto numbers = parse_event(R"({"logid":100044547,"cfgtid":7})");
        EXPECT_EQ(numbers.logid, "100044547");
        EXPECT_EQ(numbers.cfgtid, "7");
        auto empty = parse_event("");
        EXPECT_TRUE(empty.summary().contains("structured"));
    }

    TEST(Events, SanitizesUntrustedText) {
        auto event = parse_event(std::string(R"({"cfgobj":")") + std::string(1000, 'a') + "\\u001b[31m\"}");
        EXPECT_EQ(event.cfgobj.size(), 256u);
        EXPECT_EQ(sanitize("a\nb\x1b" "c\x7f"), "a?b?c?");
    }

    TEST(Events, WrittenByOperations) {
        auto ops = nlohmann::json::parse(R"([
            {"op":"create","resource":"firewall/address","object":{"name":"fp-dev-a","type":"mac"}},
            {"op":"update","resource":"firewall/addrgrp","key":"fp-seg-iot","set":{"member":[]}},
            {"op":"delete","resource":"firewall/address","key":"fp-dev-old"},
            {"op":"update","resource":"firewall/policy","key":7},
            {"bogus":true}
        ])");
        auto written = written_by(ops);
        ASSERT_EQ(written.size(), 4u);
        EXPECT_EQ(written[0], (WrittenObject{"firewall/address", "fp-dev-a"}));
        EXPECT_EQ(written[1], (WrittenObject{"firewall/addrgrp", "fp-seg-iot"}));
        EXPECT_EQ(written[2], (WrittenObject{"firewall/address", "fp-dev-old"}));
        EXPECT_EQ(written[3], (WrittenObject{"firewall/policy", "7"}));
        EXPECT_TRUE(written_by(nlohmann::json::object()).empty());
    }

    TEST(LoopGuard, MatchesBothPathSpellingsAndExpires) {
        LoopGuard guard(60 * s);
        guard.record(0, {{"firewall/address", "fp-dev-a"}, {"Firewall.AddrGrp", "fp-seg-iot"}});
        EXPECT_TRUE(guard.suppresses(1 * s, change("firewall.address", "fp-dev-a")));
        EXPECT_TRUE(guard.suppresses(1 * s, change("firewall.addrgrp", "fp-seg-iot")));
        EXPECT_FALSE(guard.suppresses(1 * s, change("firewall.address", "FP-DEV-A")));   // names are exact
        EXPECT_FALSE(guard.suppresses(60 * s, change("firewall.address", "fp-dev-a")));
        guard.prune(61 * s);
        EXPECT_EQ(guard.size(), 0u);
        // A later run extends the window for what it rewrote.
        guard.record(100 * s, {{"firewall/address", "fp-dev-a"}});
        guard.record(150 * s, {{"firewall/address", "fp-dev-a"}});
        EXPECT_TRUE(guard.suppresses(200 * s, change("firewall.address", "fp-dev-a")));
        LoopGuard off(0);
        off.record(0, {{"firewall/address", "x"}});
        EXPECT_FALSE(off.suppresses(0, change("firewall.address", "x")));
    }

}  // namespace fph::daemon::test
