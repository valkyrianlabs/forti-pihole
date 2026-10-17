// The durable operation journal: checkpoints, resume after a crash, waiting steps, rollback order
// and failed compensations.

#include "fixture.hpp"

#include <operation.hpp>

#include <map>
#include <set>

using namespace fph;
using namespace fph::test;

namespace {
    struct Harness {
        TempHome home;
        Journal journal{home.path / "operations"};
        std::int64_t now = 1'800'000'000;
        std::vector<std::string> calls;
        std::map<std::string, StepOutcome::Kind> outcome;   // step id -> what forward returns
        std::set<std::string> in_effect;                    // step ids `already` reports as done
        std::set<std::string> failing_compensations;
        StepExecutor executor;

        Harness() {
            executor.forward = [this](const Step& s) {
                calls.push_back("do " + s.id);
                auto kind = outcome.contains(s.id) ? outcome[s.id] : StepOutcome::Kind::done;
                return StepOutcome{kind, json{{"did", s.id}}, json{{"undo", s.id}}, kind == StepOutcome::Kind::done ? "" : "not yet"};
            };
            executor.compensate = [this](const Step& s) {
                calls.push_back("undo " + s.id);
                bool fail = failing_compensations.contains(s.id);
                return StepOutcome{fail ? StepOutcome::Kind::failed : StepOutcome::Kind::done, json::object(), json(), fail ? "boom" : ""};
            };
            executor.already = [this](const Step& s) { return in_effect.contains(s.id); };
        }

        Operation make() {
            Operation op;
            op.id = new_operation_id(now);
            op.kind = "migrate";
            op.created = now;
            for (const char* id: {"pihole", "reservation", "objects", "revoke", "observe"}) {
                Step step;
                step.id = id;
                step.description = id;
                op.steps.push_back(std::move(step));
            }
            return op;
        }

        std::string run(Operation& op) {
            return run_operation(op, journal, [this](const Step&) { return &executor; }, [this] { return ++now; });
        }
        std::string rollback(Operation& op) {
            return rollback_operation(op, journal, [this](const Step&) { return &executor; }, [this] { return ++now; });
        }
    };
}  // namespace

TEST(Operation, RunsInOrderAndPersists) {
    Harness h;
    auto op = h.make();
    EXPECT_EQ(h.run(op), "done");
    EXPECT_EQ(h.calls, (std::vector<std::string>{"do pihole", "do reservation", "do objects", "do revoke", "do observe"}));
    auto stored = h.journal.load(op.id);
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->status, "done");
    EXPECT_EQ(stored->steps[1].result["did"], "reservation");
    EXPECT_EQ(stored->steps[1].compensate["undo"], "reservation");
    auto perms = fs::status(h.journal.path(op.id)).permissions();
    EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
}

TEST(Operation, WaitingStopsAndResumes) {
    Harness h;
    auto op = h.make();
    h.outcome["observe"] = StepOutcome::Kind::waiting;   // the device has not renewed yet
    EXPECT_EQ(h.run(op), "waiting");
    EXPECT_EQ(h.journal.open().size(), 1u);
    h.calls.clear();
    h.outcome.erase("observe");
    auto again = *h.journal.load(op.id);
    EXPECT_EQ(h.run(again), "done");
    EXPECT_EQ(h.calls, (std::vector<std::string>{"do observe"}));   // completed steps are not redone
    EXPECT_TRUE(h.journal.open().empty());
}

TEST(Operation, CrashMidStepIsRecheckedNotRepeated) {
    Harness h;
    auto op = h.make();
    // Simulate a crash: reservation was started and its effect reached the FortiGate.
    op.steps[0].status = "done";
    op.steps[1].status = "running";
    h.journal.save(op, h.now);
    h.in_effect.insert("reservation");
    auto loaded = *h.journal.load(op.id);
    EXPECT_EQ(h.run(loaded), "done");
    EXPECT_EQ(h.calls, (std::vector<std::string>{"do objects", "do revoke", "do observe"}));
}

TEST(Operation, FailureStopsAndRollbackCompensatesInReverse) {
    Harness h;
    auto op = h.make();
    h.outcome["revoke"] = StepOutcome::Kind::failed;
    EXPECT_EQ(h.run(op), "failed");
    h.calls.clear();
    EXPECT_EQ(h.rollback(op), "rolled-back");
    // The failed step may have partly taken effect: it is compensated too; pending ones are not.
    EXPECT_EQ(h.calls, (std::vector<std::string>{"undo revoke", "undo objects", "undo reservation", "undo pihole"}));
}

TEST(Operation, FailedCompensationKeepsTheOperationOpen) {
    Harness h;
    auto op = h.make();
    EXPECT_EQ(h.run(op), "done");
    h.failing_compensations.insert("objects");
    EXPECT_EQ(h.rollback(op), "rollback-failed");
    EXPECT_EQ(op.step("objects")->status, "compensation-failed");
    // Retrying the rollback only retries what is still outstanding.
    h.failing_compensations.clear();
    h.calls.clear();
    EXPECT_EQ(h.rollback(op), "rolled-back");
    EXPECT_EQ(h.calls, (std::vector<std::string>{"undo objects"}));
}

TEST(Operation, RejectsUnsafeIds) {
    Harness h;
    EXPECT_FALSE(h.journal.load("../../etc/passwd"));
    Operation op;
    op.id = "../x";
    EXPECT_THROW(h.journal.save(op, 1), StateError);
}
