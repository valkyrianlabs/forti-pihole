//
// The core's door to Pi-hole: what sync needs, behind an interface so tests use an in-memory
// Pi-hole. The production implementation wraps pihole::Client (session login with the app password
// from forti's secret store, the write allowlist and ownership checks in the client itself).
//
// Credential: forti's secret store (macOS Keychain service "forti", else the 0600 file store), account
// `pihole/<name>/password`, bound to the Pi-hole URL's host:port like forti's own API keys, so a
// configuration pointing somewhere else cannot obtain it. `forti-pihole setup` stores it.
//

#ifndef FORTI_PIHOLE_PIHOLE_LINK_HPP
#define FORTI_PIHOLE_PIHOLE_LINK_HPP

#include "config.hpp"
#include "pihole_sync.hpp"

#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace forti::engine {
    class SecretStore;
}

namespace fph {

    class PiholeLinkError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    struct PiholeApplied {
        std::string kind, cidr;
        int client_id = 0;
        bool ok = false;
        std::string error;
    };

    class PiholeApi {
    public:
        virtual ~PiholeApi() = default;
        virtual std::string version() = 0;   // "FTL v6.7.1"; throws when unsupported
        virtual PiholeView view() = 0;
        // Applies managed-entry changes in order; stops at the first failure.
        virtual std::vector<PiholeApplied> apply(const std::vector<PiholeChange>& changes) = 0;
        // Group ids Pi-hole applies to a query from `ip` (FTL's own resolution order).
        virtual std::vector<int> effective_groups(const std::string& ip) = 0;
    };

    std::string pihole_account(const PiholeConfig& pihole);    // "pihole/<name>/password"
    std::string pihole_binding(const PiholeConfig& pihole);    // "host:port" of the URL

    // Connects and logs in. Throws PiholeLinkError (no secret in the message) when Pi-hole is not
    // configured, the password is missing or bound elsewhere, or the version is unsupported.
    std::unique_ptr<PiholeApi> pihole_connect(const Config& config, forti::engine::SecretStore& store);

    // The same, with a password given directly (setup verifies before storing).
    std::unique_ptr<PiholeApi> pihole_connect(const PiholeConfig& pihole, const std::string& password);

}  // namespace fph

#endif  // FORTI_PIHOLE_PIHOLE_LINK_HPP
