//
// forti-piholed: the optional runtime service. Runs in the foreground under a supervisor (systemd
// user unit, launchd via `brew services`); it never daemonizes itself.
//

#include "daemon.hpp"
#include "setup.hpp"

#include <forti_piholed_version.hpp>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <format>
#include <iostream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

namespace {

    constexpr std::string_view usage_text = R"(forti-piholed: receives FortiGate config-change webhooks and schedules forti-pihole reconciles

Usage: forti-piholed [--foreground] [--config PATH] [--profile NAME]
       forti-piholed --check-config [--config PATH] [--profile NAME]
       forti-piholed --version | --help

Options:
  --foreground     run in the foreground (the default and only mode; systemd or launchd supervise it)
  --config PATH    daemon configuration (default: $FORTI_HOME/pihole/daemon.json; absent: defaults)
  --profile NAME   forti profile (default: daemon.json's "profile", else the default profile)
  --check-config   validate the configuration, report the effective settings and exit
  --version        print the version and what it was built from
  -h, --help       this text

Endpoints (one listener, default 127.0.0.1:8735):
  POST /v1/fortigate/events   Authorization: Bearer <token>, from allow_sources only
  GET  /v1/health             liveness, no data

Signals: SIGTERM/SIGINT stop after the current run; SIGHUP reloads the configuration and token.
Plain HTTP only: the token crosses the network in cleartext, so bind to the management interface.
)";

    int control_pipe[2] = {-1, -1};

    extern "C" void on_signal(int signal) {
        int saved = errno;   // the handler must not disturb the interrupted code's errno
        auto byte = static_cast<unsigned char>(signal);
        [[maybe_unused]] auto n = ::write(control_pipe[1], &byte, 1);
        errno = saved;
    }

    void install_signals() {
        if (::pipe(control_pipe) != 0) throw std::runtime_error("cannot create the signal pipe");
        for (int fd: control_pipe) {
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
            ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
        }
        struct sigaction action{};
        action.sa_handler = on_signal;
        sigemptyset(&action.sa_mask);
        for (int signal: {SIGTERM, SIGINT, SIGHUP}) ::sigaction(signal, &action, nullptr);
        // A peer that hangs up mid-response must cost an EPIPE, not the process.
        ::signal(SIGPIPE, SIG_IGN);
    }

    struct Args {
        bool check = false, version = false, help = false;
        std::string config, profile;
    };

    struct UsageError : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    Args parse(const std::vector<std::string>& args) {
        Args out;
        for (std::size_t i = 0; i < args.size(); ++i) {
            const auto& a = args[i];
            auto value = [&](const char* flag) {
                if (i + 1 >= args.size()) throw UsageError(std::format("{} needs a value", flag));
                return args[++i];
            };
            if (a == "--foreground") continue;
            if (a == "--check-config") out.check = true;
            else if (a == "--version") out.version = true;
            else if (a == "-h" || a == "--help") out.help = true;
            else if (a == "--config") out.config = value("--config");
            else if (a == "--profile") out.profile = value("--profile");
            else throw UsageError(std::format("unknown argument {}", a));
        }
        return out;
    }

    // Until the reconcile is wired in: a run that does nothing and writes nothing, so the scheduler,
    // receiver and state can be exercised end to end.
    fph::daemon::RunResult stub_reconcile(fph::daemon::RunReason) { return {}; }

    int check_config(const fph::daemon::Resolved& resolved, const fph::daemon::Environment& environment) {
        const auto& c = resolved.settings.config;
        std::string allow;
        for (const auto& block: resolved.settings.allowlist.blocks()) allow += (allow.empty() ? "" : ", ") + block.to_string();
        auto config_path = environment.config_path.empty() ? fph::daemon::StateFiles{fph::daemon::pihole_dir(environment.paths)}.daemon_config()
                                                           : environment.config_path;
        std::cout << "forti-piholed: configuration ok\n"
                  << std::format("  config:    {}\n", config_path.string())
                  << std::format("  profile:   {}\n", resolved.profile.empty() ? "(none)" : resolved.profile)
                  << std::format("  listen:    {}:{} (plain HTTP)\n", c.listen_address, c.listen_port)
                  << std::format("  allow:     {}\n", allow.empty() ? "(none: every event is refused)" : allow)
                  << std::format("  token:     {}\n", resolved.settings.token ? "stored as " + resolved.token_account : "missing")
                  << std::format("  schedule:  debounce {}s, max delay {}s, full reconcile every {} min, backoff {}s..{}s, "
                                 "suppression {}s\n",
                                 c.debounce_seconds, c.max_delay_seconds, c.full_reconcile_minutes, c.backoff_initial_seconds,
                                 c.backoff_max_seconds, c.suppression_seconds)
                  << std::format("  limits:    header {} B, body {} B, read timeout {} ms, {} connections, rate {}/min (burst {})\n",
                                 c.max_header_bytes, c.max_body_bytes, c.read_timeout_ms, c.max_connections, c.rate_per_minute,
                                 c.rate_burst);
        for (const auto& warning: resolved.warnings) std::cout << "warning: " << warning << "\n";
        return 0;
    }

}  // namespace

int main(int argc, char** argv) {
    // A core dump could hold the webhook token (and the engine's API key once reconciles run here).
    struct rlimit no_core{0, 0};
    ::setrlimit(RLIMIT_CORE, &no_core);

    Args args;
    try {
        args = parse(std::vector<std::string>(argv + 1, argv + argc));
    } catch (const UsageError& e) {
        std::cerr << "forti-piholed: " << e.what() << "\n(see forti-piholed --help)\n";
        return 2;
    }
    if (args.help) {
        std::cout << usage_text;
        return 0;
    }
    if (args.version) {
        std::cout << "forti-piholed " << FORTI_PIHOLED_VERSION << " (" << FORTI_PIHOLED_BUILT_FROM << ")\n";
        return 0;
    }

    fph::daemon::Environment environment{forti::engine::Paths::from_env(), args.config, args.profile, nullptr};
    // journald stamps each line itself; anywhere else (launchd's log file, a terminal) we do.
    fph::daemon::Logger log(&std::cerr, std::getenv("JOURNAL_STREAM") == nullptr);

    fph::daemon::Resolved resolved;
    try {
        resolved = fph::daemon::resolve_settings(environment);
    } catch (const fph::daemon::DaemonConfigError& e) {
        if (args.check) std::cout << "forti-piholed: configuration invalid: " << e.what() << "\n";
        else log.error("config.invalid", {{"error", e.what()}});
        return 3;   // the ecosystem's config status (forti::engine::exit_code(Code::config))
    }
    if (args.check) return check_config(resolved, environment);

    for (const auto& warning: resolved.warnings) log.warn("config.warning", {{"detail", warning}});
    try {
        install_signals();
        fph::daemon::DaemonOptions options;
        options.settings = resolved.settings;
        options.files = {fph::daemon::pihole_dir(environment.paths)};
        options.reconcile = stub_reconcile;
        options.reload = [environment, &log] {
            auto fresh = fph::daemon::resolve_settings(environment);
            for (const auto& warning: fresh.warnings) log.warn("config.warning", {{"detail", warning}});
            return fresh.settings;
        };
        options.log = &log;
        fph::daemon::Daemon daemon(std::move(options));
        daemon.start();
        log.info("daemon.started", {{"version", FORTI_PIHOLED_VERSION}, {"profile", resolved.profile}});
        return daemon.run(control_pipe[0]);
    } catch (const std::exception& e) {
        log.error("daemon.failed", {{"error", e.what()}});
        return 1;
    }
}
