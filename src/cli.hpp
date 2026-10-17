//
// Command line: argv -> one of the commands, rendered as text or JSON. The FortiGate is reached only
// through a Gateway, so tests drive the commands against an in-memory FortiGate.
//
// Exit status: 0 success, 1 internal (including a guard refusal: that is a bug), 2 usage, 3 config,
// 4 connection/auth, 6 device/API errors, 7 waiting for approval / read-only profile / stale plan,
// 8 partial or unknown outcome. The engine's codes map the same way (architecture.md).
//

#ifndef FORTI_PIHOLE_CLI_HPP
#define FORTI_PIHOLE_CLI_HPP

#include "gateway.hpp"
#include "state.hpp"

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fph {

    struct Config;

    struct WritePermits;
    struct PiholeConfig;
    class PiholeApi;

    struct Environment {
        Home home = Home::from_env();
        // Builds the gateway once the configuration is known (production: engine_gateway with the
        // guard transport sharing `permits`).
        std::function<std::unique_ptr<Gateway>(const Config&, std::shared_ptr<WritePermits> permits)> gateway;
        // Pi-hole with the stored password (production: pihole_connect), and with a given one (setup).
        std::function<std::unique_ptr<PiholeApi>(const Config&)> pihole;
        std::function<std::unique_ptr<PiholeApi>(const PiholeConfig&, const std::string& password)> pihole_with_password;
        std::function<std::int64_t()> clock;
        std::function<void(int seconds)> sleep;
        std::istream* in = nullptr;
        std::ostream* out = nullptr;
        std::ostream* err = nullptr;
    };

    int run(const std::vector<std::string>& args, Environment& environment);

    std::string usage_text();

}  // namespace fph

#endif  // FORTI_PIHOLE_CLI_HPP
