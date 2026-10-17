//
// The Pi-hole v6 API client: session login and logout, version check, groups (list and create) and
// client entries (list, create, update, delete). Nothing else is reachable through it.
//
// Authentication (auth.yaml; FTL src/api/auth.c): POST /api/auth {"password"} answers a session
// {"sid", "csrf", "validity"}; every later request carries the SID in the X-FTL-SID header (the
// CSRF token is only needed for cookie authentication, which this client never uses). An app
// password (Settings > Web interface / API > "Configure app password") is the credential to use: it
// skips 2FA, which a periodic job cannot answer, and can be revoked without touching the admin
// password. FTL has a fixed number of session slots (webserver.api.max_sessions, default 16) that
// expire only after webserver.session.timeout (default 1800 s), so every login is paired with a
// DELETE /api/auth: the destructor logs out whatever happens.
//
// A login is attempted once per Client. FTL rate-limits logins (more than 3 attempts in a second
// answers 429, password.c verify_password()), and a wrong password does not become right by trying
// again; an AuthError is final for the run. A 401 later in the run (the session expired or was
// revoked) is an AuthError as well and is not answered by logging in again.
//
// Writes (AGENTS.md rules 2 and 3, applied to Pi-hole):
//   - groups are only ever created. No request that renames, disables or deletes a group, or touches
//     a group's adlists or domains, exists in this client: forti-pihole manages which groups a
//     client entry is in, nothing more;
//   - a client entry is created with the ownership marker in its comment, and updated or deleted
//     only when a fresh read of it shows the marker (OwnershipError otherwise). The comment of an
//     update must keep the marker;
//   - every request is checked against an allowlist of (method, path) before it is sent
//     (RequestRefused), as the guard transport does for FortiOS.
//
// FTL quirks the write path accounts for (src/api/list.c, src/database/gravity-db.c):
//   - PUT /api/clients/{client} is an upsert ("INSERT ... ON CONFLICT(ip) DO UPDATE"): it would
//     create a missing entry, so an update first reads the entry and refuses when it is gone;
//   - PUT replaces the comment with whatever is sent (an omitted or empty comment becomes null,
//     which would drop the marker), so the comment is always sent;
//   - group membership is written in a second step outside any transaction (delete all, then insert
//     each id), so an unknown group id fails with a FOREIGN KEY error after the old memberships are
//     gone. The client therefore checks every group id against GET /api/groups first, sends no
//     duplicates, and verifies the groups in the reply;
//   - the client column is UNIQUE byte for byte while lookups ignore case, so "aa:bb:..." and
//     "AA:BB:..." can both exist; the client refuses to create an entry that equals an existing one
//     case-insensitively, and only writes canonical_client() spellings.
//

#ifndef FORTI_PIHOLE_PIHOLE_CLIENT_HPP
#define FORTI_PIHOLE_PIHOLE_CLIENT_HPP

#include "pihole/error.hpp"
#include "pihole/model.hpp"
#include "pihole/transport.hpp"

#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fph::pihole {

    // A client entry to create or the new state of one to update.
    struct ClientSpec {
        std::string client;             // canonical_client() spelling
        std::string comment;            // must contain the ownership marker
        std::vector<int> groups;        // group ids; replaces the entry's set
        // An entry in no group gets no blocking at all (see model.hpp). That is never the result of
        // an empty list by accident: it has to be asked for.
        bool allow_no_groups = false;
    };

    // Empty when the request may be sent, else why not. The allowlist: GET /api/auth, /api/info/version,
    // /api/groups, /api/clients and /api/clients/{client}; POST and DELETE /api/auth; POST /api/groups;
    // POST /api/clients; PUT and DELETE /api/clients/{client}.
    [[nodiscard]] std::string refuse_request(Method method, std::string_view path);

    class Client {
        std::shared_ptr<Transport> transport_;
        std::string sid_;                 // empty when no session is open
        bool session_ = false;            // a session this client opened and must close
        bool login_attempted_ = false;
        bool open_api_ = false;           // the Pi-hole has no password: requests need no session

        nlohmann::json send(Method method, const std::string& path, const nlohmann::json* body = nullptr);
        void check_groups_exist(const std::vector<int>& groups);
        ClientEntry checked_reply(const nlohmann::json& reply, std::string_view where, const ClientSpec& spec);
        static void check_spec(const ClientSpec& spec, std::string_view action);

    public:
        explicit Client(std::shared_ptr<Transport> transport);
        ~Client();   // logout(), never throws
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        // POST /api/auth. Throws AuthError (wrong password, 2FA required: use an app password),
        // RateLimitError (429: login rate limit or no free API seat), TransportError. Once per Client.
        void login(std::string_view password);

        // DELETE /api/auth when a session is open. True when Pi-hole confirmed (204) or the session was
        // already gone (404, 401); false when the request failed (the slot then frees itself when the
        // session times out). Never throws.
        bool logout() noexcept;

        [[nodiscard]] bool logged_in() const { return session_ || open_api_; }

        // GET /api/info/version.
        [[nodiscard]] VersionInfo version();
        // version(), then check_supported(): VersionError below minimum_ftl_version.
        VersionInfo require_supported_version();

        // GET /api/groups.
        [[nodiscard]] std::vector<Group> groups();
        // POST /api/groups {"name", "comment", "enabled": true}. ConflictError when the name exists.
        // The comment must carry the ownership marker (what forti-pihole creates says so).
        Group create_group(std::string_view name, std::string_view comment);

        // GET /api/clients.
        [[nodiscard]] std::vector<ClientEntry> clients();
        // GET /api/clients/{client}: the entry whose text is exactly `client`, or nullopt.
        [[nodiscard]] std::optional<ClientEntry> client(std::string_view client);

        // POST /api/clients. Refuses (Error) a non-canonical client string, a comment without the
        // marker, unknown or duplicate group ids, an empty group set unless allowed, and an existing
        // entry with the same text in any letter case (ConflictError).
        ClientEntry create_client(const ClientSpec& spec);

        // PUT /api/clients/{spec.client} with {"comment", "groups"}, after a fresh read: NotFoundError
        // when the entry does not exist, OwnershipError when it does not carry the marker.
        ClientEntry update_client(const ClientSpec& spec);

        // DELETE /api/clients/{client}, after a fresh read: false when there was no such entry,
        // OwnershipError when it does not carry the marker.
        bool delete_client(std::string_view client);
    };

    // Throws OwnershipError unless the entry carries the ownership marker.
    void require_managed(const ClientEntry& entry, std::string_view action);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_CLIENT_HPP
