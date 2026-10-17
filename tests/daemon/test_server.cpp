// Real sockets on 127.0.0.1:0: the listener and the whole daemon, with clients in the test thread.
// Short limits keep the timeout cases fast. Nothing leaves the loopback interface.

#include "support.hpp"

#include <daemon.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fph::daemon::test {

    using namespace std::chrono_literals;
    using json = nlohmann::json;

    namespace {

        std::int64_t now_ms() {
            return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
        }

        int connect_to(std::uint16_t port) {
            int fd = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof address) != 0) {
                ::close(fd);
                return -1;
            }
#if defined(SO_NOSIGPIPE)
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            return fd;
        }

        void send_all(int fd, std::string_view bytes) {
            while (!bytes.empty()) {
                auto n = ::send(fd, bytes.data(), bytes.size(), 0);
                if (n <= 0) return;
                bytes.remove_prefix(static_cast<std::size_t>(n));
            }
        }

        // Everything until the server closes (or `limit` passes).
        std::string read_all(int fd, std::chrono::milliseconds limit = 3000ms) {
            std::string out;
            auto end = std::chrono::steady_clock::now() + limit;
            while (std::chrono::steady_clock::now() < end) {
                pollfd p{fd, POLLIN, 0};
                if (::poll(&p, 1, 50) <= 0) continue;
                char buffer[4096];
                auto n = ::recv(fd, buffer, sizeof buffer, 0);
                if (n <= 0) break;
                out.append(buffer, static_cast<std::size_t>(n));
            }
            return out;
        }

        std::string http_exchange(std::uint16_t port, std::string_view request) {
            int fd = connect_to(port);
            if (fd < 0) return "connect failed";
            send_all(fd, request);
            auto response = read_all(fd);
            ::close(fd);
            return response;
        }

        int status_of(const std::string& response) {
            if (!response.starts_with("HTTP/1.1 ") || response.size() < 12) return 0;
            return std::stoi(response.substr(9, 3));
        }

        std::string post(std::string_view body, std::string_view authorization = {}) {
            std::string request = "POST /v1/fortigate/events HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n";
            if (!authorization.empty()) request += "Authorization: " + std::string(authorization) + "\r\n";
            request += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + std::string(body);
            return request;
        }

        std::string bearer() { return std::string("Bearer ") + token; }

        std::string event_body(std::string_view path, std::string_view object) {
            return json{{"source", "fortigate"}, {"cfgpath", path}, {"cfgobj", object}, {"action", "Edit"}, {"user", "admin"}}.dump();
        }

        // A Server + WebhookApp driven by a poll loop on a background thread.
        class Harness {
        public:
            explicit Harness(Server::Options options, Allowlist allowlist, int burst = 100)
                    : limiter_(burst, 600),
                      app_(std::move(allowlist), std::string(token), limiter_, log_,
                           [this](const ConfigEvent& event, const Peer&, std::int64_t) {
                               std::lock_guard lock(mutex_);
                               events_.push_back(event);
                           }),
                      server_(app_, options) {
                server_.listen("127.0.0.1", 0);
                if (::pipe(stop_) != 0) throw std::runtime_error("pipe");
                thread_ = std::thread([this] { loop(); });
            }
            ~Harness() {
                char byte = 1;
                [[maybe_unused]] auto n = ::write(stop_[1], &byte, 1);
                thread_.join();
                ::close(stop_[0]);
                ::close(stop_[1]);
            }
            [[nodiscard]] std::uint16_t port() const { return server_.port(); }
            std::vector<ConfigEvent> events() {
                std::lock_guard lock(mutex_);
                return events_;
            }

        private:
            void loop() {
                for (;;) {
                    std::vector<pollfd> fds{{stop_[0], POLLIN, 0}};
                    auto offset = server_.collect(fds);
                    int timeout = server_.timeout_ms(now_ms());
                    ::poll(fds.data(), static_cast<nfds_t>(fds.size()), timeout < 0 ? 100 : std::min(timeout, 100));
                    if (fds[0].revents & POLLIN) return;
                    server_.dispatch(fds, offset, now_ms());
                }
            }

            Logger log_;
            RateLimiter limiter_;
            WebhookApp app_;
            Server server_;
            int stop_[2] = {-1, -1};
            std::thread thread_;
            std::mutex mutex_;
            std::vector<ConfigEvent> events_;
        };

        Server::Options short_limits() {
            Server::Options options;
            options.read_timeout_ms = 300;
            options.limits.max_header_bytes = 1024;
            options.limits.max_body_bytes = 2048;
            return options;
        }

        Allowlist loopback() { return Allowlist({*Cidr::parse("127.0.0.1")}); }

    }  // namespace

    TEST(Server, AcceptsAnAuthenticatedEvent) {
        Harness harness(short_limits(), loopback());
        auto response = http_exchange(harness.port(), post(event_body("firewall.address", "fp-dev-a"), bearer()));
        EXPECT_EQ(status_of(response), 202) << response;
        EXPECT_NE(response.find("Connection: close"), std::string::npos);
        ASSERT_EQ(harness.events().size(), 1u);
        EXPECT_EQ(harness.events()[0].cfgobj, "fp-dev-a");
    }

    TEST(Server, Health) {
        Harness harness(short_limits(), loopback());
        auto response = http_exchange(harness.port(), "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        EXPECT_EQ(status_of(response), 200);
        EXPECT_TRUE(response.ends_with("{\"status\":\"ok\"}\n"));
        auto head = http_exchange(harness.port(), "HEAD /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        EXPECT_EQ(status_of(head), 200);
        EXPECT_TRUE(head.ends_with("\r\n\r\n"));
        EXPECT_EQ(status_of(http_exchange(harness.port(), "POST /v1/health HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")), 405);
    }

    TEST(Server, RefusalStatuses) {
        Harness harness(short_limits(), loopback());
        auto port = harness.port();
        auto missing = http_exchange(port, post("{}"));
        EXPECT_EQ(status_of(missing), 401);
        EXPECT_NE(missing.find("WWW-Authenticate: Bearer"), std::string::npos);
        EXPECT_EQ(status_of(http_exchange(port, post("{}", "Bearer wrong-token-wrong-token-wrong-token"))), 401);
        EXPECT_EQ(status_of(http_exchange(port, post("{}", std::string("Basic ") + token))), 401);
        auto method = http_exchange(port, "GET /v1/fortigate/events HTTP/1.1\r\nHost: x\r\n\r\n");
        EXPECT_EQ(status_of(method), 405);
        EXPECT_NE(method.find("Allow: POST"), std::string::npos);
        EXPECT_EQ(status_of(http_exchange(port, "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")), 404);
        EXPECT_EQ(status_of(http_exchange(port, post(std::string(4096, 'x'), bearer()))), 413);
        EXPECT_EQ(status_of(http_exchange(port, "GET /" + std::string(2000, 'a') + " HTTP/1.1\r\nHost: x\r\n\r\n")), 431);
        EXPECT_EQ(status_of(http_exchange(port, "POST /v1/fortigate/events HTTP/1.1\r\nHost: x\r\nAuthorization: " + bearer() + "\r\n\r\n")), 411);
        EXPECT_EQ(status_of(http_exchange(port, "garbage\r\n\r\n")), 400);
        EXPECT_TRUE(harness.events().empty());
    }

    TEST(Server, SourceAllowlist) {
        // Loopback is not on this allowlist: health still answers (local monitoring), events do not.
        Harness harness(short_limits(), Allowlist({*Cidr::parse("192.0.2.1")}));
        EXPECT_EQ(status_of(http_exchange(harness.port(), post("{}", bearer()))), 403);
        EXPECT_EQ(status_of(http_exchange(harness.port(), "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")), 200);
        EXPECT_TRUE(harness.events().empty());
    }

    TEST(Server, RateLimitPerSource) {
        Harness harness(short_limits(), loopback(), 2);
        EXPECT_EQ(status_of(http_exchange(harness.port(), "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")), 200);
        EXPECT_EQ(status_of(http_exchange(harness.port(), "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n")), 200);
        auto limited = http_exchange(harness.port(), post(event_body("a.b", "c"), bearer()));
        EXPECT_EQ(status_of(limited), 429);
        EXPECT_NE(limited.find("Retry-After: "), std::string::npos);
        EXPECT_TRUE(harness.events().empty());
    }

    TEST(Server, SlowlorisIsCutOffAtTheDeadline) {
        Harness harness(short_limits(), loopback());
        int fd = connect_to(harness.port());
        ASSERT_GE(fd, 0);
        auto start = std::chrono::steady_clock::now();
        // One byte every 40 ms keeps the connection busy but never completes the head.
        std::string head = "POST /v1/fortigate/events HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaa";
        std::string response;
        for (char c: head) {
            send_all(fd, std::string_view(&c, 1));
            pollfd p{fd, POLLIN, 0};
            if (::poll(&p, 1, 40) > 0) {
                response = read_all(fd, 2000ms);
                break;
            }
        }
        auto elapsed = std::chrono::steady_clock::now() - start;
        ::close(fd);
        EXPECT_EQ(status_of(response), 408) << response;
        EXPECT_LT(elapsed, 2000ms);
        EXPECT_GE(elapsed, 250ms);
    }

    TEST(Server, IdleConnectionClosesSilently) {
        Harness harness(short_limits(), loopback());
        int fd = connect_to(harness.port());
        ASSERT_GE(fd, 0);
        auto start = std::chrono::steady_clock::now();
        auto response = read_all(fd, 3000ms);
        auto elapsed = std::chrono::steady_clock::now() - start;
        ::close(fd);
        EXPECT_EQ(response, "");
        EXPECT_LT(elapsed, 2000ms);
    }

    TEST(Server, ExpectContinue) {
        Harness harness(short_limits(), loopback());
        int fd = connect_to(harness.port());
        ASSERT_GE(fd, 0);
        auto body = event_body("firewall.address", "x");
        send_all(fd, "POST /v1/fortigate/events HTTP/1.1\r\nHost: x\r\nAuthorization: " + bearer() +
                             "\r\nExpect: 100-continue\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n");
        char buffer[256];
        pollfd p{fd, POLLIN, 0};
        ASSERT_GT(::poll(&p, 1, 2000), 0);
        auto n = ::recv(fd, buffer, sizeof buffer, 0);
        ASSERT_GT(n, 0);
        EXPECT_EQ(std::string(buffer, static_cast<std::size_t>(n)).substr(0, 25), "HTTP/1.1 100 Continue\r\n\r\n");
        send_all(fd, body);
        auto rest = std::string(buffer, static_cast<std::size_t>(n)).substr(25) + read_all(fd);
        ::close(fd);
        EXPECT_EQ(status_of(rest), 202) << rest;
        EXPECT_EQ(harness.events().size(), 1u);
    }

    TEST(Server, ManyConnectionsBeyondTheLimitWaitTheirTurn) {
        auto options = short_limits();
        options.max_connections = 2;
        Harness harness(options, loopback());
        std::vector<int> idle;
        for (int i = 0; i < 2; ++i) idle.push_back(connect_to(harness.port()));
        // A third client waits in the backlog until an idle slot times out, then is served.
        auto start = std::chrono::steady_clock::now();
        auto response = http_exchange(harness.port(), "GET /v1/health HTTP/1.1\r\nHost: x\r\n\r\n");
        EXPECT_EQ(status_of(response), 200);
        EXPECT_GE(std::chrono::steady_clock::now() - start, 200ms);
        for (int fd: idle) ::close(fd);
    }

    // ---- the whole daemon ----

    namespace {

        struct Runs {
            std::mutex mutex;
            std::condition_variable changed;
            std::vector<RunReason> reasons;
            RunResult next;
            std::chrono::milliseconds duration{0};

            RunResult record(RunReason reason) {
                std::this_thread::sleep_for(duration);
                std::lock_guard lock(mutex);
                reasons.push_back(reason);
                changed.notify_all();
                return next;
            }
            bool wait_for(std::size_t count, std::chrono::milliseconds limit) {
                std::unique_lock lock(mutex);
                return changed.wait_for(lock, limit, [&] { return reasons.size() >= count; });
            }
            std::size_t count() {
                std::lock_guard lock(mutex);
                return reasons.size();
            }
            RunReason at(std::size_t i) {
                std::lock_guard lock(mutex);
                return reasons.at(i);
            }
        };

        class DaemonHarness {
        public:
            DaemonHarness(const fs::path& dir, Runs& runs, std::int64_t pause_recheck_ms = 100) : log_(&log_text_) {
                DaemonOptions options;
                options.settings.config.listen_port = 0;
                options.settings.config.debounce_seconds = 1;
                options.settings.config.max_delay_seconds = 1;
                options.settings.allowlist = loopback();
                options.settings.token = token;
                options.files = {dir};
                options.reconcile = [&runs](RunReason reason) { return runs.record(reason); };
                options.log = &log_;
                options.random = [] { return 1.0; };
                options.pause_recheck_ms = pause_recheck_ms;
                daemon_ = std::make_unique<Daemon>(std::move(options));
                daemon_->start();
                if (::pipe(control_) != 0) throw std::runtime_error("pipe");
                thread_ = std::thread([this] { status_ = daemon_->run(control_[0]); });
            }
            ~DaemonHarness() { stop(); }
            void signal(int number) {
                auto byte = static_cast<unsigned char>(number);
                [[maybe_unused]] auto n = ::write(control_[1], &byte, 1);
            }
            int stop() {
                if (thread_.joinable()) {
                    signal(SIGTERM);
                    thread_.join();
                    ::close(control_[0]);
                    ::close(control_[1]);
                }
                return status_;
            }
            [[nodiscard]] std::uint16_t port() const { return daemon_->port(); }
            Daemon& daemon() { return *daemon_; }
            std::string log() { return log_text_.str(); }   // only after stop()

        private:
            std::ostringstream log_text_;
            Logger log_;
            std::unique_ptr<Daemon> daemon_;
            int control_[2] = {-1, -1};
            std::thread thread_;
            int status_ = -1;
        };

    }  // namespace

    TEST(Daemon, EventRunsAndEchoesAreSuppressed) {
        TempDir dir;
        Runs runs;
        runs.next.written = {{"firewall/address", "fp-dev-a"}};
        DaemonHarness harness(dir.path(), runs);
        ASSERT_TRUE(runs.wait_for(1, 3000ms));   // the startup run
        EXPECT_EQ(runs.at(0), RunReason::startup);

        // The startup run's own write comes back as an event: ignored.
        EXPECT_EQ(status_of(http_exchange(harness.port(), post(event_body("firewall.address", "fp-dev-a"), bearer()))), 202);
        // An operator's change: one debounced run.
        EXPECT_EQ(status_of(http_exchange(harness.port(), post(event_body("firewall.policy", "7"), bearer()))), 202);
        EXPECT_EQ(status_of(http_exchange(harness.port(), post(event_body("firewall.policy", "8"), bearer()))), 202);
        ASSERT_TRUE(runs.wait_for(2, 4000ms));
        EXPECT_EQ(runs.at(1), RunReason::event);
        std::this_thread::sleep_for(1500ms);
        EXPECT_EQ(runs.count(), 2u);   // no loop: the second run's echo (fp-dev-a again) is suppressed

        EXPECT_EQ(harness.stop(), 0);
        auto log = harness.log();
        EXPECT_EQ(log.find(token), std::string::npos);
        EXPECT_NE(log.find("outcome=suppressed"), std::string::npos);
        EXPECT_NE(log.find("event=run.finished reason=event"), std::string::npos);
        auto events = read_file(dir.path() / "events.jsonl");
        EXPECT_EQ(events.find(token), std::string::npos);
        EXPECT_NE(events.find("\"outcome\":\"suppressed\""), std::string::npos);
        EXPECT_NE(events.find("\"type\":\"run\""), std::string::npos);
        auto state = json::parse(read_file(dir.path() / "daemon-state.json"));
        EXPECT_EQ(state["last_run_reason"], "event");
        EXPECT_EQ(state["last_run_ok"], true);
        EXPECT_EQ(state["running"], false);
        EXPECT_EQ(state["pending"], false);
        EXPECT_EQ(state["last_event"]["cfgobj"], "8");
        EXPECT_EQ(read_file(dir.path() / "daemon-state.json").find(token), std::string::npos);
    }

    TEST(Daemon, FailureIsRecordedForTheNextStart) {
        TempDir dir;
        Runs runs;
        runs.next = {false, "FortiGate unreachable", {}};
        {
            DaemonHarness harness(dir.path(), runs);
            ASSERT_TRUE(runs.wait_for(1, 3000ms));
            std::this_thread::sleep_for(100ms);
        }
        auto state = json::parse(read_file(dir.path() / "daemon-state.json"));
        EXPECT_EQ(state["consecutive_failures"], 1);
        EXPECT_EQ(state["last_error"], "FortiGate unreachable");
        EXPECT_GT(state["next_retry_at"].get<std::int64_t>(), 0);
        // A restart resumes the backoff: no immediate startup run.
        Runs again;
        DaemonHarness harness(dir.path(), again);
        EXPECT_EQ(harness.daemon().scheduler().failures(), 1);
        EXPECT_FALSE(again.wait_for(1, 500ms));
    }

    TEST(Daemon, InterruptedRunCountsAsAFailure) {
        TempDir dir;
        StateFiles files{dir.path()};
        DaemonState crashed;
        crashed.running = true;
        crashed.last_run_reason = "periodic";
        save_daemon_state(files, crashed);
        Runs runs;
        DaemonHarness harness(dir.path(), runs);
        EXPECT_EQ(harness.daemon().scheduler().failures(), 1);
        EXPECT_FALSE(runs.wait_for(1, 300ms));
    }

    TEST(Daemon, PauseIsHonouredWithoutRestart) {
        TempDir dir;
        StateFiles files{dir.path()};
        set_paused(files, true, 1);
        Runs runs;
        DaemonHarness harness(dir.path(), runs);
        EXPECT_FALSE(runs.wait_for(1, 400ms));   // the startup run waits
        set_paused(files, false, 2);
        ASSERT_TRUE(runs.wait_for(1, 2000ms));
        EXPECT_EQ(runs.at(0), RunReason::startup);
        harness.stop();
        EXPECT_FALSE(json::parse(read_file(files.state()))["paused"].get<bool>());
    }

    TEST(Daemon, StopFinishesTheCurrentRun) {
        TempDir dir;
        Runs runs;
        runs.duration = 400ms;
        DaemonHarness harness(dir.path(), runs);
        std::this_thread::sleep_for(100ms);   // the startup run is in progress
        auto start = std::chrono::steady_clock::now();
        EXPECT_EQ(harness.stop(), 0);
        EXPECT_GE(std::chrono::steady_clock::now() - start, 200ms);
        EXPECT_EQ(runs.count(), 1u);
        auto state = json::parse(read_file(dir.path() / "daemon-state.json"));
        EXPECT_EQ(state["running"], false);
        EXPECT_EQ(state["last_run_ok"], true);
        // The listener closed at the stop.
        EXPECT_LT(connect_to(harness.port()), 0);
    }

    TEST(Daemon, EventsDuringARunBecomeOneFollowUp) {
        TempDir dir;
        Runs runs;
        runs.duration = 600ms;
        DaemonHarness harness(dir.path(), runs);
        std::this_thread::sleep_for(100ms);   // inside the startup run
        for (int i = 0; i < 5; ++i)
            EXPECT_EQ(status_of(http_exchange(harness.port(), post(event_body("firewall.policy", std::to_string(i)), bearer()))), 202);
        ASSERT_TRUE(runs.wait_for(2, 4000ms));
        std::this_thread::sleep_for(1500ms);
        EXPECT_EQ(runs.count(), 2u);
        EXPECT_EQ(runs.at(1), RunReason::event);
    }

    TEST(Daemon, ReloadAppliesNewSettings) {
        TempDir dir;
        Runs runs;
        DaemonOptions options;
        options.settings.config.listen_port = 0;
        options.settings.allowlist = loopback();
        options.settings.token = std::nullopt;   // events disabled at first
        options.files = {dir.path()};
        options.reconcile = [&runs](RunReason reason) { return runs.record(reason); };
        Settings fresh = options.settings;
        fresh.token = token;
        options.reload = [&fresh] { return fresh; };
        Daemon daemon(std::move(options));
        daemon.start();
        int control[2];
        ASSERT_EQ(::pipe(control), 0);
        std::thread thread([&] { daemon.run(control[0]); });
        EXPECT_EQ(status_of(http_exchange(daemon.port(), post("{}", bearer()))), 503);
        unsigned char hup = SIGHUP;
        [[maybe_unused]] auto n = ::write(control[1], &hup, 1);
        bool reloaded = false;
        for (int i = 0; i < 40 && !reloaded; ++i) {
            reloaded = status_of(http_exchange(daemon.port(), post("{}", bearer()))) == 202;
            if (!reloaded) std::this_thread::sleep_for(25ms);
        }
        EXPECT_TRUE(reloaded);
        unsigned char term = SIGTERM;
        n = ::write(control[1], &term, 1);
        thread.join();
        ::close(control[0]);
        ::close(control[1]);
    }

}  // namespace fph::daemon::test
