//
// forti-piholed: the receiver, the scheduler and the durable state around one reconcile callback.
//
// One thread runs everything but the reconcile itself: a poll(2) loop over the control descriptor
// (signals, delivered by main's self-pipe), the run worker's completion pipe and the HTTP sockets. The
// reconcile runs on a worker thread so the receiver keeps answering (and holding events for the
// follow-up decision) while a run is in progress; there is never more than one worker.
//
// The callback is the only interface to the rest of the program:
//
//   RunResult reconcile(RunReason reason);   // ok/failed, error text, the FortiGate objects written
//
// It is a full, idempotent reconcile every time (the reason is informational), so a dropped or
// misattributed event costs at most one redundant run, never divergence.
//
// Stop (SIGTERM/SIGINT): the listener closes at once, a run in progress is finished and recorded,
// then run() returns. Reload (SIGHUP): the `reload` callback provides fresh settings (config, token,
// allowlist); on failure the current ones stay. The pause flag is re-read from the state file before
// every run, so `forti-pihole pause`/`resume` take effect without a restart.
//

#ifndef FORTI_PIHOLED_DAEMON_HPP
#define FORTI_PIHOLED_DAEMON_HPP

#include "daemon_config.hpp"
#include "daemon_state.hpp"
#include "log.hpp"
#include "net.hpp"
#include "rate_limit.hpp"
#include "scheduler.hpp"
#include "server.hpp"
#include "webhook.hpp"

#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>

namespace fph::daemon {

    using Reconcile = std::function<RunResult(RunReason)>;

    // What SIGHUP re-reads.
    struct Settings {
        DaemonConfig config;
        Allowlist allowlist;               // effective: config.allow_sources or the FortiGate's address
        std::optional<std::string> token;  // nullopt: events disabled (503)
    };

    struct DaemonOptions {
        Settings settings;
        StateFiles files;
        Reconcile reconcile;
        std::function<Settings()> reload;   // null: SIGHUP only logs; throws: keep the current settings
        const Logger* log = nullptr;
        // Injected for tests; defaults: steady_clock, system_clock, a seeded PRNG.
        std::function<std::int64_t()> monotonic_ms;
        std::function<std::int64_t()> wall_s;
        std::function<double()> random;
        std::int64_t pause_recheck_ms = 30'000;
    };

    class Daemon {
    public:
        explicit Daemon(DaemonOptions options);
        ~Daemon();
        Daemon(const Daemon&) = delete;
        Daemon& operator=(const Daemon&) = delete;

        // Loads the state and binds the listener. Throws ServerError (bind) or DaemonStateError.
        void start();
        [[nodiscard]] std::uint16_t port() const { return server_.port(); }

        // Until a stop: each byte read from `control_fd` is a signal number (SIGTERM/SIGINT stop,
        // SIGHUP reloads). Returns the exit status.
        int run(int control_fd);

        [[nodiscard]] const Scheduler& scheduler() const { return scheduler_; }
        [[nodiscard]] const DaemonState& state() const { return state_; }

    private:
        void on_event(const ConfigEvent& event, const Peer& peer, std::int64_t now_ms);
        void maybe_start_run(std::int64_t now_ms);
        void finish_run(std::int64_t now_ms);
        void reload();
        void apply(Settings settings);
        void save();
        void log_settings() const;

        DaemonOptions options_;
        Logger silent_;
        const Logger& log_;
        Scheduler scheduler_;
        RateLimiter limiter_;
        WebhookApp app_;
        Server server_;
        EventLog event_log_;
        DaemonState state_;
        int done_pipe_[2] = {-1, -1};
        std::thread worker_;
        std::future<RunResult> result_;
        std::int64_t run_started_ms_ = 0;
        bool paused_logged_ = false;
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_DAEMON_HPP
