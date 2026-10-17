//
// Errors of the Pi-hole client. Every message names the request (method and path) and what Pi-hole
// said, never a credential: passwords travel only in the body of POST /api/auth and the session ID
// only in the X-FTL-SID header, and neither is ever formatted into an error.
//
//   Error              base; also configuration problems (a bad endpoint)
//   TransportError     nothing usable came back: connect, TLS, timeout, oversized body
//   DecodeError        a reply that is not the JSON the API specification describes
//   ApiError           an HTTP error reply, with Pi-hole's error.key / error.message / error.hint
//     AuthError        401, and login refusals (wrong password, 2FA required)
//     RateLimitError   429: FTL's login rate limit or no free API seat (webserver.api.max_sessions)
//     ConflictError    the item is already present
//     NotFoundError    404
//   VersionError       the Pi-hole is older than forti-pihole supports, or its version is unknown
//   OwnershipError     refused locally: the entry does not carry the ownership marker
//   RequestRefused     refused locally: the request is outside what forti-pihole may send
//

#ifndef FORTI_PIHOLE_PIHOLE_ERROR_HPP
#define FORTI_PIHOLE_PIHOLE_ERROR_HPP

#include <stdexcept>
#include <string>
#include <string_view>

namespace fph::pihole {

    class Error : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    class TransportError : public Error {
    public:
        using Error::Error;
    };

    class DecodeError : public Error {
    public:
        using Error::Error;
    };

    class ApiError : public Error {
        long status_;
        std::string key_, message_, hint_;

    public:
        ApiError(const std::string& what, long status, std::string key, std::string message, std::string hint)
                : Error(what), status_(status), key_(std::move(key)), message_(std::move(message)),
                  hint_(std::move(hint)) {}

        [[nodiscard]] long status() const { return status_; }
        [[nodiscard]] const std::string& key() const { return key_; }        // e.g. "database_error"; "" when none
        [[nodiscard]] const std::string& message() const { return message_; }
        [[nodiscard]] const std::string& hint() const { return hint_; }      // "" when null
    };

    class AuthError : public ApiError {
    public:
        using ApiError::ApiError;
    };

    class RateLimitError : public ApiError {
    public:
        using ApiError::ApiError;
    };

    class ConflictError : public ApiError {
    public:
        using ApiError::ApiError;
    };

    class NotFoundError : public ApiError {
    public:
        using ApiError::ApiError;
    };

    class VersionError : public Error {
    public:
        using Error::Error;
    };

    class OwnershipError : public Error {
    public:
        using Error::Error;
    };

    class RequestRefused : public Error {
    public:
        using Error::Error;
    };

    // Throws the ApiError subclass for an HTTP error reply. `where` is "METHOD /api/path"; `body` is the
    // reply, which may be Pi-hole's error object, a session object (401 from /api/auth carries one), a
    // reverse proxy's HTML page or nothing.
    [[noreturn]] void throw_api_error(std::string_view where, long status, std::string_view body);

    // True for Pi-hole's "already present" database errors. FTL v6.7 says "The item is already present"
    // (FTL commit 0c16b793); older releases passed SQLite's "UNIQUE constraint failed: ..." through.
    [[nodiscard]] bool is_duplicate_message(std::string_view text);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_ERROR_HPP
