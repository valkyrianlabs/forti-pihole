#include "daemon.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <format>
#include <random>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace fph::daemon {

    using json = nlohmann::json;

    namespace {

        std::int64_t steady_ms() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        }

        std::int64_t system_s() {
            return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        }

        std::function<double()> default_random() {
            auto engine = std::make_shared<std::mt19937_64>(std::random_device{}());
            return [engine] { return std::uniform_real_distribution<double>(0.0, 1.0)(*engine); };
        }

        Server::Options server_options(const DaemonConfig& c) {
            return {c.http_limits(), c.read_timeout_ms, c.max_connections};
        }

        std::string_view outcome_name(Scheduler::Outcome outcome) {
            switch (outcome) {
                case Scheduler::Outcome::scheduled: return "scheduled";
                case Scheduler::Outcome::held: return "held";
                case Scheduler::Outcome::suppressed: return "suppressed";
            }
            return "unknown";
        }

        DaemonOptions with_defaults(DaemonOptions options) {
            if (!options.monotonic_ms) options.monotonic_ms = steady_ms;
            if (!options.wall_s) options.wall_s = system_s;
            if (!options.random) options.random = default_random();
            return options;
        }

    }  // namespace

    Daemon::Daemon(DaemonOptions options)
            : options_(with_defaults(std::move(options))),
              log_(options_.log ? *options_.log : silent_),
              scheduler_(options_.settings.config.timing(), options_.random),
              limiter_(options_.settings.config.rate_burst, options_.settings.config.rate_per_minute),
              app_(options_.settings.allowlist, options_.settings.token, limiter_, log_,
                   [this](const ConfigEvent& event, const Peer& peer, std::int64_t now_ms) { on_event(event, peer, now_ms); }),
              server_(app_, server_options(options_.settings.config)),
              event_log_(options_.files.events(), static_cast<std::uintmax_t>(options_.settings.config.event_log_max_mib) * 1024 * 1024) {
        if (::pipe(done_pipe_) != 0) throw ServerError("cannot create the worker pipe");
        for (int fd: done_pipe_) {
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
            ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
        }
    }

    Daemon::~Daemon() {
        if (worker_.joinable()) worker_.join();
        for (int fd: done_pipe_)
            if (fd >= 0) ::close(fd);
    }

    void Daemon::start() {
        auto now = options_.monotonic_ms();
        auto wall = options_.wall_s();
        auto loaded = load_daemon_state(options_.files);
        state_ = loaded.state;
        if (loaded.corrupt)
            log_.error("state.corrupt", {{"file", options_.files.state().string()},
                                         {"action", "moved aside to .corrupt; starting fresh with a full reconcile"}});
        int failures = state_.consecutive_failures;
        std::int64_t retry_in = (state_.next_retry_at - wall) * 1000;
        if (state_.running) {
            // The previous process died mid-run (crash, OOM, SIGKILL): count it as a failure so a
            // crash loop under Restart=on-failure backs off instead of hitting the FortiGate each time.
            ++failures;
            retry_in = scheduler_.backoff_ms(failures);
            log_.warn("state.interrupted_run", {{"reason", state_.last_run_reason}, {"failures", std::to_string(failures)}});
        }
        scheduler_.restore(now, failures, retry_in);
        state_.running = false;
        state_.consecutive_failures = failures;
        state_.pending = state_.pending || scheduler_.pending();
        state_.next_retry_at = failures > 0 ? wall + std::max<std::int64_t>(0, scheduler_.retry_in(now)) / 1000 : 0;

        const auto& c = options_.settings.config;
        server_.listen(c.listen_address, static_cast<std::uint16_t>(c.listen_port));
        save();
        log_settings();
    }

    void Daemon::log_settings() const {
        const auto& s = options_.settings;
        std::string allow;
        for (const auto& block: s.allowlist.blocks()) allow += (allow.empty() ? "" : ",") + block.to_string();
        log_.info("daemon.listening", {{"address", s.config.listen_address},
                                       {"port", std::to_string(server_.port())},
                                       {"allow", allow.empty() ? "none" : allow},
                                       {"events", s.token ? "enabled" : "disabled"}});
        if (!s.token)
            log_.warn("config.no_token", {{"detail", "no webhook token in the secret store: the events endpoint answers 503; "
                                                     "periodic reconciles still run"}});
        if (s.allowlist.empty())
            log_.warn("config.no_sources", {{"detail", "no allowed source (set allow_sources or a profile whose FortiGate "
                                                       "address resolves): every event is refused"}});
        if (s.allowlist.allows_any()) log_.warn("config.any_source", {{"detail", "allow_sources admits every address"}});
        if (auto ip = IpAddress::parse(s.config.listen_address); ip && !ip->loopback())
            log_.warn("config.cleartext", {{"detail", "plain HTTP: the bearer token crosses the network unencrypted; bind to the "
                                                      "management interface only"}});
    }

    void Daemon::save() {
        try {
            save_daemon_state(options_.files, state_);
        } catch (const std::exception& e) {
            log_.error("state.save_failed", {{"error", e.what()}});
        }
    }

    void Daemon::on_event(const ConfigEvent& event, const Peer& peer, std::int64_t now_ms) {
        auto outcome = scheduler_.on_event(now_ms, event);
        auto wall = options_.wall_s();
        auto summary = event.summary();
        log_.info("fortigate.event", {{"source", peer.address.to_string()},
                                      {"outcome", std::string(outcome_name(outcome))},
                                      {"fields", Logger::fields_of(summary)}});
        try {
            event_log_.append({{"type", "event"}, {"at", wall}, {"source", peer.address.to_string()},
                               {"outcome", outcome_name(outcome)}, {"event", summary}});
        } catch (const std::exception& e) {
            log_.error("event_log.append_failed", {{"error", e.what()}});
        }
        state_.last_event_at = wall;
        state_.last_event = summary;
        // Persisted on the transition only: a burst of a hundred events is one write, not a hundred.
        if (outcome != Scheduler::Outcome::suppressed && !state_.pending) {
            state_.pending = true;
            save();
        }
    }

    void Daemon::maybe_start_run(std::int64_t now_ms) {
        if (scheduler_.running() || scheduler_.next_due_in(now_ms) != 0) return;
        if (read_paused(options_.files)) {
            if (!paused_logged_) log_.info("run.paused", {{"detail", "paused by forti-pihole pause; runs wait for resume"}});
            paused_logged_ = true;
            scheduler_.postpone(now_ms + options_.pause_recheck_ms);
            return;
        }
        if (paused_logged_) log_.info("run.resumed");
        paused_logged_ = false;
        auto reason = scheduler_.take_due(now_ms);
        if (!reason) return;

        run_started_ms_ = now_ms;
        state_.running = true;
        state_.last_run_started = options_.wall_s();
        state_.last_run_reason = std::string(to_string(*reason));
        save();
        log_.info("run.started", {{"reason", state_.last_run_reason}});

        std::promise<RunResult> promise;
        result_ = promise.get_future();
        worker_ = std::thread([reconcile = options_.reconcile, reason = *reason, promise = std::move(promise), fd = done_pipe_[1]]() mutable {
            RunResult result;
            try {
                if (reconcile) result = reconcile(reason);
            } catch (const std::exception& e) {
                result = {false, e.what(), {}};
            } catch (...) {
                result = {false, "unknown error", {}};
            }
            promise.set_value(std::move(result));
            char byte = 1;
            while (::write(fd, &byte, 1) < 0 && errno == EINTR) {}
        });
    }

    void Daemon::finish_run(std::int64_t now_ms) {
        if (!worker_.joinable()) return;
        worker_.join();
        RunResult result = result_.get();
        result.error = sanitize(result.error, 512);
        scheduler_.finish(now_ms, result);
        auto wall = options_.wall_s();
        auto duration = now_ms - run_started_ms_;
        state_.running = false;
        state_.last_run_finished = wall;
        state_.last_run_ok = result.ok;
        state_.last_error = result.ok ? std::string() : result.error;
        state_.consecutive_failures = scheduler_.failures();
        state_.next_retry_at = scheduler_.failures() > 0 ? wall + std::max<std::int64_t>(0, scheduler_.retry_in(now_ms)) / 1000 : 0;
        state_.pending = scheduler_.pending();
        save();
        json entry = {{"type", "run"}, {"at", wall}, {"reason", state_.last_run_reason}, {"ok", result.ok},
                      {"duration_ms", duration}, {"written", result.written.size()}};
        if (!result.ok) entry["error"] = result.error;
        try {
            event_log_.append(entry);
        } catch (const std::exception& e) {
            log_.error("event_log.append_failed", {{"error", e.what()}});
        }
        if (result.ok)
            log_.info("run.finished", {{"reason", state_.last_run_reason}, {"ok", "true"}, {"duration_ms", std::to_string(duration)},
                                       {"written", std::to_string(result.written.size())},
                                       {"follow_up", scheduler_.pending() ? "true" : "false"}});
        else
            log_.warn("run.failed", {{"reason", state_.last_run_reason}, {"error", result.error},
                                     {"failures", std::to_string(scheduler_.failures())},
                                     {"retry_in_s", std::to_string(std::max<std::int64_t>(0, scheduler_.retry_in(now_ms)) / 1000)}});
    }

    void Daemon::apply(Settings settings) {
        const auto& old = options_.settings.config;
        const auto& c = settings.config;
        if (c.listen_address != old.listen_address || c.listen_port != old.listen_port) {
            // Bound before the old socket is released, so a failed rebind leaves the old one serving.
            server_.listen(c.listen_address, static_cast<std::uint16_t>(c.listen_port));
        }
        scheduler_.set_timing(c.timing());
        limiter_.configure(c.rate_burst, c.rate_per_minute);
        server_.set_options(server_options(c));
        app_.set_allowlist(settings.allowlist);
        app_.set_token(settings.token);
        event_log_.set_max_bytes(static_cast<std::uintmax_t>(c.event_log_max_mib) * 1024 * 1024);
        options_.settings = std::move(settings);
    }

    void Daemon::reload() {
        if (!options_.reload) {
            log_.info("daemon.reload", {{"detail", "nothing to reload"}});
            return;
        }
        try {
            apply(options_.reload());
            log_.info("daemon.reloaded");
            log_settings();
        } catch (const std::exception& e) {
            log_.error("daemon.reload_failed", {{"error", e.what()}, {"detail", "keeping the current settings"}});
        }
    }

    int Daemon::run(int control_fd) {
        bool stopping = false;
        for (;;) {
            auto now = options_.monotonic_ms();
            if (!stopping) maybe_start_run(now);
            if (stopping && !scheduler_.running()) break;

            std::vector<pollfd> fds;
            fds.push_back({stopping ? -1 : control_fd, POLLIN, 0});   // negative: poll ignores it
            fds.push_back({done_pipe_[0], POLLIN, 0});
            auto offset = server_.collect(fds);

            std::int64_t timeout = stopping ? -1 : scheduler_.next_due_in(now);
            if (int t = server_.timeout_ms(now); t >= 0) timeout = timeout < 0 ? t : std::min<std::int64_t>(timeout, t);
            // Cap the wait so a clock oddity (or a long periodic interval) never means an unbounded sleep.
            if (timeout < 0 || timeout > 60'000) timeout = 60'000;

            int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), static_cast<int>(timeout));
            if (ready < 0 && errno != EINTR) {
                log_.error("daemon.poll_failed", {{"error", std::to_string(errno)}});
                return 1;
            }
            now = options_.monotonic_ms();
            server_.dispatch(fds, offset, now);

            if (fds[1].revents & POLLIN) {
                char drain[64];
                while (::read(done_pipe_[0], drain, sizeof drain) > 0) {}
                finish_run(now);
            }
            if (fds[0].revents & (POLLIN | POLLHUP)) {
                unsigned char signals[16];
                auto n = ::read(control_fd, signals, sizeof signals);
                for (ssize_t i = 0; i < n; ++i) {
                    int signal = signals[i];
                    if (signal == SIGHUP) {
                        reload();
                    } else if (signal == SIGTERM || signal == SIGINT) {
                        if (!stopping) {
                            stopping = true;
                            server_.close_all();
                            log_.info("daemon.stopping", {{"detail", scheduler_.running() ? "finishing the current run" : "idle"}});
                        } else if (scheduler_.running()) {
                            log_.info("daemon.stopping", {{"detail", "still finishing the current run"}});
                        }
                    }
                }
                if (n == 0) {   // the control pipe closed: nobody can stop us any more, so stop now
                    stopping = true;
                    server_.close_all();
                }
            }
        }
        save();
        log_.info("daemon.stopped");
        return 0;
    }

}  // namespace fph::daemon
