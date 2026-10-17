//
// From the environment to the daemon's effective settings: daemon.json, the forti profile (for the
// FortiGate's address, the default allowlist, and the token's binding) and the token from the secret
// store. Used at start, on SIGHUP and by --check-config. Problems that leave the daemon useful
// (no token yet, a profile that does not resolve) are warnings; an invalid daemon.json is an error.
//

#ifndef FORTI_PIHOLED_SETUP_HPP
#define FORTI_PIHOLED_SETUP_HPP

#include "daemon.hpp"

#include <forti/engine/profile.hpp>

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fph::daemon {

    struct Environment {
        forti::engine::Paths paths;
        std::filesystem::path config_path;          // empty: <pihole dir>/daemon.json
        std::string profile;                        // --profile; overrides daemon.json's
        std::shared_ptr<forti::engine::SecretStore> secrets;   // null: the engine's default store
    };

    struct Resolved {
        Settings settings;
        std::string profile;         // the profile actually used (empty: none could be loaded)
        std::string token_account;
        std::vector<std::string> warnings;
    };

    // <forti home>/pihole, the directory forti-pihole's own files live in (state.hpp's Home::from_env).
    std::filesystem::path pihole_dir(const forti::engine::Paths& paths);

    // Throws DaemonConfigError for an unreadable or invalid daemon.json.
    Resolved resolve_settings(const Environment& environment);

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_SETUP_HPP
