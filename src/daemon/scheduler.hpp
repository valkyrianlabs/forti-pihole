//
// When to run the reconcile. A pure state machine over an injected monotonic clock (milliseconds), so
// every timing rule is testable without sleeping:
//
//   event      a config change: wait for `debounce` of quiet, but never more than `max_delay` after
//              the first event of a burst (an operator editing for ten minutes still gets a run)
//   periodic   a full reconcile `periodic` after the last run finished, events or not
//   retry      after a failure: exponential backoff from `backoff_initial`, doubled per consecutive
//              failure, capped at `backoff_max`, with jitter (half fixed, half random) so several
//              companions do not retry against one FortiGate in lockstep. Events during a backoff do
//              not cut it short: the retry is a full reconcile and covers them.
//   startup    once at start, unless a recorded failure's backoff is still running
//
// At most one run at a time. Events that arrive during a run are held and judged when it finishes,
// against the objects that run reported writing: the echoes of its own writes are dropped, anything
// else becomes exactly one follow-up run (however many events there were).
//

#ifndef FORTI_PIHOLED_SCHEDULER_HPP
#define FORTI_PIHOLED_SCHEDULER_HPP

#include "events.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fph::daemon {

    enum class RunReason { startup, event, periodic, retry };
    std::string_view to_string(RunReason reason);

    // What the reconcile callback reports. `written` lists every FortiGate object it created, updated
    // or deleted (also on a partial failure), for loop prevention.
    struct RunResult {
        bool ok = true;
        std::string error;   // shown in logs and state; must never hold a secret
        std::vector<WrittenObject> written;
    };

    struct Timing {
        std::int64_t debounce_ms = 10'000;
        std::int64_t max_delay_ms = 60'000;
        std::int64_t periodic_ms = 15 * 60'000;
        std::int64_t backoff_initial_ms = 10'000;
        std::int64_t backoff_max_ms = 15 * 60'000;
        std::int64_t suppression_ms = 60'000;
    };

    class Scheduler {
    public:
        enum class Outcome {
            scheduled,    // will cause (or join) a run
            held,         // a run is in progress; judged when it finishes
            suppressed,   // the echo of the companion's own recent write
        };

        // `random` returns [0, 1); it only spreads backoff (tests pass a constant).
        Scheduler(Timing timing, std::function<double()> random);

        void set_timing(const Timing& timing);

        // Start-up: `failures` consecutive failures were recorded and the next retry is due in
        // `retry_in_ms` (<= 0: now). With no failures a startup run is due immediately.
        void restore(std::int64_t now_ms, int failures, std::int64_t retry_in_ms);

        Outcome on_event(std::int64_t now_ms, const ConfigEvent& event);

        // The run that is due now, marking it started; nullopt when none is (or one is running).
        std::optional<RunReason> take_due(std::int64_t now_ms);
        void finish(std::int64_t now_ms, const RunResult& result);

        // Nothing starts before `until_ms` (pause: re-check later). Pending work stays pending.
        void postpone(std::int64_t until_ms) { not_before_ = until_ms; }

        // Milliseconds until something is due (0: now), or -1 while a run is in progress.
        [[nodiscard]] std::int64_t next_due_in(std::int64_t now_ms) const;

        [[nodiscard]] bool running() const { return running_.has_value(); }
        [[nodiscard]] std::optional<RunReason> current() const { return running_; }
        // A run is owed beyond the periodic one: events, a held follow-up, the startup run or a retry.
        [[nodiscard]] bool pending() const;
        [[nodiscard]] int failures() const { return failures_; }
        // Milliseconds from now to the scheduled retry; meaningful while failures() > 0.
        [[nodiscard]] std::int64_t retry_in(std::int64_t now_ms) const { return retry_at_ - now_ms; }
        [[nodiscard]] std::int64_t backoff_ms(int failures) const;   // jittered delay after `failures` failures
        [[nodiscard]] const LoopGuard& guard() const { return guard_; }

    private:
        [[nodiscard]] std::optional<std::int64_t> due_at() const;

        Timing timing_;
        std::function<double()> random_;
        LoopGuard guard_;
        std::optional<RunReason> running_;
        bool startup_ = false;
        std::optional<std::int64_t> first_event_, last_event_;
        struct Held {
            std::int64_t at;
            ConfigEvent event;
        };
        std::vector<Held> held_;
        bool held_overflow_ = false;
        int failures_ = 0;
        std::int64_t retry_at_ = 0;
        std::int64_t next_periodic_ = 0;
        std::int64_t not_before_ = 0;
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_SCHEDULER_HPP
