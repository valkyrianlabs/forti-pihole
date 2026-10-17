#include "pihole/error.hpp"
#include "pihole/text.hpp"

#include <nlohmann/json.hpp>

#include <format>

namespace fph::pihole {

    namespace {

        std::string string_field(const nlohmann::json& object, const char* name) {
            auto it = object.find(name);
            return it != object.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

    }  // namespace

    bool is_duplicate_message(std::string_view text) {
        return text.find("The item is already present") != std::string_view::npos ||
               text.find("UNIQUE constraint failed") != std::string_view::npos;
    }

    void throw_api_error(std::string_view where, long status, std::string_view body) {
        std::string key, message, hint;
        // Pi-hole's error object: {"error": {"key", "message", "hint"}, "took"} (common.yaml, errors).
        // POST /api/auth with a wrong password and DELETE /api/auth without a session answer 401 with
        // the session object instead ({"session": {"valid": false, "message": "password incorrect"}},
        // auth.c send_api_auth_status()), so its message is taken from there.
        auto json = nlohmann::json::parse(body, nullptr, false);
        if (json.is_object()) {
            if (auto error = json.find("error"); error != json.end() && error->is_object()) {
                key = string_field(*error, "key");
                message = string_field(*error, "message");
                hint = string_field(*error, "hint");
            } else if (auto session = json.find("session"); session != json.end() && session->is_object()) {
                key = "unauthorized";
                message = string_field(*session, "message");
            }
        }

        // Pi-hole echoes request items (client strings, comments) in hints: untrusted text, kept
        // printable and short in the message.
        std::string what = std::format("Pi-hole: {}: HTTP {}", where, status);
        if (!key.empty()) what += std::format(" {}", printable(key, 64));
        if (!message.empty()) what += std::format(": {}", printable(message, 200));
        if (!hint.empty()) what += std::format(" ({})", printable(hint, 200));
        if (key.empty() && message.empty()) {
            if (status >= 300 && status < 400)
                what += ": redirect refused (forti-pihole never follows redirects; use the final URL)";
            else if (!body.empty())
                what += ": not a Pi-hole API reply (is the URL the Pi-hole web server?)";
        }

        if (status == 401) {
            if (message == "password incorrect") what += "; check the app password (no retry: FTL rate-limits logins)";
            throw AuthError(what, status, key, message, hint);
        }
        if (status == 429) throw RateLimitError(what, status, key, message, hint);
        if (status == 404) throw NotFoundError(what, status, key, message, hint);
        if (status == 400 && key == "database_error" && (is_duplicate_message(hint) || is_duplicate_message(message)))
            throw ConflictError(what, status, key, message, hint);
        throw ApiError(what, status, key, message, hint);
    }

}  // namespace fph::pihole
