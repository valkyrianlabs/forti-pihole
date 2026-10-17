//
// forti-piholed's configuration: $FORTI_HOME/pihole/daemon.json (absent: every default). It is
// separate from config.json (the classification policy) so the one-shot CLI never needs to know
// about the receiver, and it holds no secret: the webhook token is in forti's secret store
// (token.hpp), never here.
//
//   {
//     "profile": "fw01",                                  // forti profile; empty: the default profile
//     "listen": {"address": "127.0.0.1", "port": 8735},   // IP literal; loopback until configured
//     "allow_sources": ["192.0.2.1"],                     // CIDRs; absent/empty: the profile's FortiGate
//     "limits": {"max_header_bytes": 8192, "max_body_bytes": 65536, "read_timeout_ms": 5000,
//                "max_connections": 16},
//     "rate_limit": {"burst": 30, "per_minute": 120},     // per source address
//     "schedule": {"debounce_seconds": 10, "max_delay_seconds": 60, "full_reconcile_minutes": 15,
//                  "backoff_initial_seconds": 10, "backoff_max_seconds": 900, "suppression_seconds": 60},
//     "event_log": {"max_mib": 4},                        // events.jsonl rotates to events.jsonl.1
//     "token_account": ""                                 // empty: pihole/<profile>/webhook-token
//   }
//
// Plain HTTP only in 0.1: the bearer token crosses the network in cleartext, so bind to the
// management interface (or loopback behind a local TLS proxy) and keep the allowlist to the FortiGate.
//

#ifndef FORTI_PIHOLED_DAEMON_CONFIG_HPP
#define FORTI_PIHOLED_DAEMON_CONFIG_HPP

#include "http.hpp"
#include "net.hpp"
#include "scheduler.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace fph::daemon {

    class DaemonConfigError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    inline constexpr unsigned default_port = 8735;

    struct DaemonConfig {
        std::string profile;
        std::string listen_address = "127.0.0.1";
        unsigned listen_port = default_port;   // 0 (an ephemeral port) only when set in code (tests)
        std::vector<Cidr> allow_sources;       // empty: the FortiGate's address (resolved from the profile)

        std::size_t max_header_bytes = 8 * 1024;
        std::size_t max_body_bytes = 64 * 1024;
        int read_timeout_ms = 5000;
        int max_connections = 16;

        int rate_burst = 30;
        int rate_per_minute = 120;

        int debounce_seconds = 10;
        int max_delay_seconds = 60;
        int full_reconcile_minutes = 15;
        int backoff_initial_seconds = 10;
        int backoff_max_seconds = 900;
        int suppression_seconds = 60;

        int event_log_max_mib = 4;
        std::string token_account;

        // Strict: unknown keys, wrong types and out-of-range values throw DaemonConfigError naming
        // the key ("daemon.schedule.debounce_seconds: must be 1..3600").
        static DaemonConfig from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;

        [[nodiscard]] Timing timing() const;
        [[nodiscard]] http::Limits http_limits() const;
    };

    // Missing file: the defaults. Unreadable or invalid: DaemonConfigError.
    DaemonConfig load_daemon_config(const std::filesystem::path& path);

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_DAEMON_CONFIG_HPP
