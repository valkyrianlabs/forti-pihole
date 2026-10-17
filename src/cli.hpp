//
// Command line: argv -> one of the commands, rendered as text or JSON. The FortiGate is reached only
// through a Gateway, so tests drive the commands against an in-memory FortiGate.
//
// Exit status: 0 success, 1 internal (including a guard refusal: that is a bug), 2 usage, 3 config,
// 4 connection/auth, 6 device/API errors, 7 waiting for approval / read-only profile / stale plan,
// 8 partial or unknown outcome. The engine's codes map the same way (architecture.md).
//

#ifndef FORTI_VLAN_MAC_CLI_HPP
#define FORTI_VLAN_MAC_CLI_HPP

#include "gateway.hpp"
#include "state.hpp"

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fvm {

    struct Config;

    struct Environment {
        Home home = Home::from_env();
        // Builds the gateway once the configuration is known (production: engine_gateway).
        std::function<std::unique_ptr<Gateway>(const Config&)> gateway;
        std::function<std::int64_t()> clock;
        std::ostream* out = nullptr;
        std::ostream* err = nullptr;
    };

    int run(const std::vector<std::string>& args, Environment& environment);

    std::string usage_text();

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_CLI_HPP
