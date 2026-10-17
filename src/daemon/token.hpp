//
// The webhook bearer token: a shared secret between the FortiGate's webhook action and the receiver.
// It lives in forti's secret store (macOS: the login Keychain, service "forti"; elsewhere the engine's
// file store under <forti home>/credentials, 0600) under "pihole/<profile>/webhook-token", bound to
// the profile's FortiGate (host:port) like the profile's API key. It is never written to a config
// file, the daemon's state, the event log or stderr.
//

#ifndef FORTI_PIHOLED_TOKEN_HPP
#define FORTI_PIHOLED_TOKEN_HPP

#include <forti/engine/profile.hpp>

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace fph::daemon {

    class TokenError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // Compares without an early exit, so the time taken says nothing about how many leading bytes
    // matched. (The lengths may still differ in timing; a token's length is not a secret.)
    bool constant_time_equal(std::string_view a, std::string_view b);

    // The token of an `Authorization: Bearer <token>` value (scheme case-insensitive), or nullopt.
    std::optional<std::string_view> bearer_token(std::string_view authorization);

    // 256 random bits from the OS (getentropy), as 64 lower-case hex digits: safe in an HTTP header
    // and in FortiOS's http-headers value without any escaping.
    std::string generate_token();

    // 32..512 characters of the RFC 6750 token68 alphabet. Anything shorter is too weak to stand in
    // for authentication on a cleartext management network.
    bool valid_token(std::string_view token);

    // "pihole/<profile>/webhook-token"
    std::string token_account(std::string_view profile);

    // The stored token, or nullopt when there is none. Throws TokenError (naming the account, never
    // the value) when the stored secret is bound to another device or is not a valid token.
    std::optional<std::string> load_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding);

    // The stored token, generating and storing one first when there is none.
    std::string ensure_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding);

    // Replaces the stored token with a new one (the FortiGate's webhook action must be updated too).
    std::string rotate_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding);

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_TOKEN_HPP
