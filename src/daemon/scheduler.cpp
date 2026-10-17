#include "scheduler.hpp"

#include <algorithm>
#include <cmath>

namespace fph::daemon {

    namespace {

        // Held events are kept only to be judged against the running run's writes; past this many the
        // run is assumed to need a follow-up regardless (an operator bulk edit, not a burst of echoes).
        constexpr std::size_t max_held = 1024;

    }  // namespace

    std::string_view to_string(RunReason reason) {
        switch (reason) {
            case RunReason::startup: return "startup";
            case RunReason::event: return "event";
            case RunReason::periodic: return "periodic";
            case RunReason::retry: return "retry";
        }
        return "unknown";
    }

    Scheduler::Scheduler(Timing timing, std::function<double()> random)
            : timing_(timing), random_(std::move(random)), guard_(timing.suppression_ms) {}

    void Scheduler::set_timing(const Timing& timing) {
        timing_ = timing;
        guard_.set_window(timing.suppression_ms);
    }

    void Scheduler::restore(std::int64_t now_ms, int failures, std::int64_t retry_in_ms) {
        failures_ = std::max(0, failures);
        retry_at_ = now_ms + std::max<std::int64_t>(0, retry_in_ms);
        startup_ = failures_ == 0;
        next_periodic_ = now_ms + timing_.periodic_ms;
    }

    Scheduler::Outcome Scheduler::on_event(std::int64_t now_ms, const ConfigEvent& event) {
        if (guard_.suppresses(now_ms, event)) return Outcome::suppressed;
        if (running_) {
            if (held_.size() < max_held) held_.push_back({now_ms, event});
            else held_overflow_ = true;
            return Outcome::held;
        }
        if (!first_event_) first_event_ = now_ms;
        last_event_ = now_ms;
        return Outcome::scheduled;
    }

    std::optional<std::int64_t> Scheduler::due_at() const {
        if (failures_ > 0) return retry_at_;
        if (startup_) return std::int64_t{0};
        std::int64_t at = next_periodic_;
        if (first_event_) at = std::min(at, std::min(*last_event_ + timing_.debounce_ms, *first_event_ + timing_.max_delay_ms));
        return at;
    }

    std::optional<RunReason> Scheduler::take_due(std::int64_t now_ms) {
        if (running_ || now_ms < not_before_) return std::nullopt;
        auto at = due_at();
        if (!at || now_ms < *at) return std::nullopt;
        RunReason reason = failures_ > 0 ? RunReason::retry
                           : startup_    ? RunReason::startup
                           : first_event_ && now_ms >= std::min(*last_event_ + timing_.debounce_ms, *first_event_ + timing_.max_delay_ms)
                                   ? RunReason::event
                                   : RunReason::periodic;
        // Every run is a full reconcile, so it covers whatever was waiting when it started.
        running_ = reason;
        startup_ = false;
        first_event_.reset();
        last_event_.reset();
        return reason;
    }

    void Scheduler::finish(std::int64_t now_ms, const RunResult& result) {
        running_.reset();
        // Recorded on failure too: a run that stopped part-way still wrote what it wrote.
        guard_.record(now_ms, result.written);
        next_periodic_ = now_ms + timing_.periodic_ms;
        if (result.ok) {
            failures_ = 0;
        } else {
            ++failures_;
            retry_at_ = now_ms + backoff_ms(failures_);
        }
        bool follow_up = held_overflow_;
        std::int64_t first = now_ms;
        for (const auto& held: held_) {
            if (guard_.suppresses(now_ms, held.event)) continue;
            follow_up = true;
            first = std::min(first, held.at);
        }
        if (follow_up) {
            // Debounce is measured from when the events arrived: if they did so early in a long run,
            // the quiet period has already passed and the follow-up starts right away.
            first_event_ = first;
            last_event_ = held_.empty() ? now_ms : std::max(first, held_.back().at);
        }
        held_.clear();
        held_overflow_ = false;
    }

    std::int64_t Scheduler::next_due_in(std::int64_t now_ms) const {
        if (running_) return -1;
        auto at = due_at();
        if (!at) return -1;
        return std::max<std::int64_t>(0, std::max(*at, not_before_) - now_ms);
    }

    bool Scheduler::pending() const { return startup_ || first_event_.has_value() || !held_.empty() || held_overflow_ || failures_ > 0; }

    std::int64_t Scheduler::backoff_ms(int failures) const {
        // initial * 2^(failures-1), computed in floating point so a long outage cannot overflow.
        double base = static_cast<double>(timing_.backoff_initial_ms) * std::pow(2.0, std::max(0, failures - 1));
        base = std::min(base, static_cast<double>(timing_.backoff_max_ms));
        double r = std::clamp(random_ ? random_() : 0.5, 0.0, 1.0);
        return static_cast<std::int64_t>(base / 2 + r * base / 2);
    }

}  // namespace fph::daemon
