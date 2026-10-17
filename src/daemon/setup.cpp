#include "setup.hpp"

#include "token.hpp"

#include <format>

namespace fph::daemon {

    std::filesystem::path pihole_dir(const forti::engine::Paths& paths) {
        // Before `forti home migrate` (legacy XDG layout) there is no home; the companion keeps its
        // files beside the engine's state then, exactly as the CLI does.
        return (paths.home.empty() ? paths.state : paths.home) / "pihole";
    }

    Resolved resolve_settings(const Environment& environment) {
        Resolved out;
        auto config_path = environment.config_path.empty() ? StateFiles{pihole_dir(environment.paths)}.daemon_config()
                                                           : environment.config_path;
        out.settings.config = load_daemon_config(config_path);
        auto& config = out.settings.config;
        if (!environment.profile.empty()) config.profile = environment.profile;

        std::optional<forti::engine::Profile> profile;
        try {
            forti::engine::ProfileStore store(environment.paths);
            profile = store.load().select(config.profile);
            out.profile = profile->name;
        } catch (const std::exception& e) {
            out.warnings.push_back(std::format("no forti profile: {}", e.what()));
        }

        if (!config.allow_sources.empty()) {
            out.settings.allowlist = Allowlist(config.allow_sources);
        } else if (profile) {
            auto resolved = resolve_host(profile->host);
            if (resolved.empty()) out.warnings.push_back(std::format("the FortiGate address ({}) does not resolve; set allow_sources", profile->host));
            out.settings.allowlist = Allowlist(std::move(resolved));
        }

        out.token_account = !config.token_account.empty() ? config.token_account : profile ? token_account(profile->name) : std::string();
        if (out.token_account.empty()) {
            out.warnings.push_back("no token account (no profile and no token_account): events are disabled");
            return out;
        }
        try {
            auto secrets = environment.secrets ? environment.secrets : forti::engine::default_secret_store(environment.paths);
            out.settings.token = load_token(*secrets, out.token_account, profile ? profile->secret_binding() : std::string());
            if (!out.settings.token)
                out.warnings.push_back(std::format("no webhook token stored as {}: events are disabled", out.token_account));
        } catch (const std::exception& e) {
            // Engine and token errors name the account, never the value.
            out.warnings.push_back(std::format("webhook token unavailable: {}", e.what()));
        }
        return out;
    }

}  // namespace fph::daemon
