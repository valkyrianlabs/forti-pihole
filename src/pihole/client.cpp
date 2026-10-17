#include "pihole/client.hpp"
#include "pihole/marker.hpp"
#include "pihole/text.hpp"

#include <algorithm>
#include <format>
#include <set>

namespace fph::pihole {

    using nlohmann::json;

    namespace {

        constexpr std::string_view auth_path = "/api/auth";

        void wipe(std::string& text) {
            volatile char* p = text.data();
            for (std::size_t i = 0; i < text.size(); ++i) p[i] = 0;
            text.clear();
        }

        // One encoded path segment after `prefix`: non-empty, no further '/'.
        bool single_segment(std::string_view path, std::string_view prefix) {
            if (!path.starts_with(prefix)) return false;
            std::string_view rest = path.substr(prefix.size());
            return !rest.empty() && rest.find('/') == std::string_view::npos;
        }

        std::string list(const std::vector<int>& ids) {
            std::string out = "[";
            for (std::size_t i = 0; i < ids.size(); ++i) out += (i ? ", " : "") + std::to_string(ids[i]);
            return out + "]";
        }

        bool has_control(std::string_view text) {
            return std::ranges::any_of(text, [](char c) { return static_cast<unsigned char>(c) < 0x20 || c == 0x7f; });
        }

    }  // namespace

    std::string refuse_request(Method method, std::string_view path) {
        if (path.find_first_of("?#") != std::string_view::npos) return "a query string is never sent";
        switch (method) {
            case Method::get:
                if (path == auth_path || path == "/api/info/version" || path == "/api/groups" || path == "/api/clients" ||
                    single_segment(path, "/api/clients/"))
                    return {};
                break;
            case Method::post:
                if (path == auth_path || path == "/api/groups" || path == "/api/clients") return {};
                break;
            case Method::put:
                if (single_segment(path, "/api/clients/")) return {};
                break;
            case Method::del:
                if (path == auth_path || single_segment(path, "/api/clients/")) return {};
                break;
        }
        return std::format("{} {} is outside what forti-pihole may send to Pi-hole", to_string(method), printable(path, 120));
    }

    void require_managed(const ClientEntry& entry, std::string_view action) {
        if (!entry.managed())
            throw OwnershipError(std::format("Pi-hole: refusing to {} client entry \"{}\" (id {}): its comment does not "
                                             "carry \"{}\", so it belongs to an administrator",
                                             action, printable(entry.client, 80), entry.id, ownership_marker));
    }

    Client::Client(std::shared_ptr<Transport> transport) : transport_(std::move(transport)) {
        if (!transport_) throw Error("Pi-hole: no transport");
    }

    Client::~Client() { logout(); }

    json Client::send(Method method, const std::string& path, const json* body) {
        if (auto why = refuse_request(method, path); !why.empty()) throw RequestRefused("Pi-hole: refused: " + why);
        if (!logged_in()) throw AuthError("Pi-hole: not logged in", 0, "", "", "");

        Request request;
        request.method = method;
        request.path = path;
        request.headers.emplace_back("Accept", "application/json");
        if (body) {
            request.headers.emplace_back("Content-Type", "application/json");
            request.body = body->dump();
        }
        if (!sid_.empty()) request.headers.emplace_back("X-FTL-SID", sid_);
        Response response = transport_->perform(request);
        for (auto& [name, value]: request.headers) wipe(value);

        std::string where = std::format("{} {}", to_string(method), path);
        if (response.status < 200 || response.status >= 300) {
            // The session is gone (expired, revoked, or FTL restarted): nothing left to log out, and
            // no new login here (see client.hpp).
            if (response.status == 401) {
                session_ = false;
                wipe(sid_);
            }
            throw_api_error(where, response.status, response.body);
        }
        if (response.body.empty()) return nullptr;
        auto reply = json::parse(response.body, nullptr, false);
        if (reply.is_discarded())
            throw DecodeError(std::format("Pi-hole: {}: HTTP {} with a body that is not JSON ({})", where,
                                          response.status, printable(response.content_type, 60)));
        return reply;
    }

    void Client::login(std::string_view password) {
        if (login_attempted_)
            throw AuthError("Pi-hole: a login was already attempted; forti-pihole does not log in twice in a run "
                            "(FTL rate-limits logins)", 0, "", "", "");
        login_attempted_ = true;
        if (password.empty()) throw AuthError("Pi-hole: no password configured (use an app password)", 0, "", "", "");

        Request request;
        request.method = Method::post;
        request.path = std::string(auth_path);
        request.headers = {{"Accept", "application/json"}, {"Content-Type", "application/json"}};
        {
            json payload = {{"password", std::string(password)}};
            request.body = payload.dump();
            wipe(payload["password"].get_ref<std::string&>());
        }
        Response response;
        try {
            response = transport_->perform(request);
        } catch (...) {
            wipe(request.body);
            throw;
        }
        wipe(request.body);

        std::string where = std::format("POST {}", auth_path);
        if (response.status != 200) {
            try {
                throw_api_error(where, response.status, response.body);
            } catch (const ApiError& error) {
                // A regular password with 2FA enabled: FTL wants a TOTP code (auth.c api_auth()). An app
                // password never needs one.
                if (response.status == 400 && error.message().find("2FA") != std::string::npos)
                    throw AuthError(std::string(error.what()) + "; 2FA is enabled: configure an app password instead",
                                    error.status(), error.key(), error.message(), error.hint());
                throw;
            }
        }
        auto reply = json::parse(response.body, nullptr, false);
        if (!reply.is_object() || !reply.contains("session") || !reply["session"].is_object())
            throw DecodeError("Pi-hole: POST /api/auth: the reply has no session object");
        const json& session = reply["session"];
        if (!session.value("valid", false))
            throw AuthError("Pi-hole: POST /api/auth: the login was not accepted", response.status, "unauthorized",
                            printable(session.value("message", ""), 120), "");
        auto sid = session.find("sid");
        if (sid != session.end() && sid->is_string() && !sid->get<std::string>().empty()) {
            sid_ = sid->get<std::string>();
            session_ = true;
            wipe(reply["session"]["sid"].get_ref<std::string&>());
            if (reply["session"].contains("csrf") && reply["session"]["csrf"].is_string())
                wipe(reply["session"]["csrf"].get_ref<std::string&>());
        } else {
            // valid with a null SID: the Pi-hole has no password set ("no auth for local user" or an
            // empty webserver.api.pwhash, auth.c get_session_object() API_AUTH_EMPTYPASS). Requests
            // succeed without a session, and there is none to close.
            open_api_ = true;
        }
    }

    bool Client::logout() noexcept {
        if (!session_) return true;
        bool ok = false;
        try {
            Request request;
            request.method = Method::del;
            request.path = std::string(auth_path);
            request.headers = {{"Accept", "application/json"}, {"X-FTL-SID", sid_}};
            Response response = transport_->perform(request);
            wipe(request.headers.back().second);
            // 204: deleted. 404: no such session any more. 401: the SID is no longer valid (expired).
            ok = response.status == 204 || response.status == 404 || response.status == 401 || response.status == 200;
        } catch (...) {
            ok = false;
        }
        session_ = false;
        wipe(sid_);
        return ok;
    }

    VersionInfo Client::version() { return decode_version(send(Method::get, "/api/info/version")); }

    VersionInfo Client::require_supported_version() {
        VersionInfo info = version();
        check_supported(info);
        return info;
    }

    std::vector<Group> Client::groups() { return decode_groups(send(Method::get, "/api/groups")); }

    Group Client::create_group(std::string_view name, std::string_view comment) {
        if (name.empty() || name.size() > 255 || has_control(name))
            throw Error(std::format("Pi-hole: invalid group name \"{}\"", printable(name, 80)));
        if (!carries_marker(comment) || has_control(comment))
            throw OwnershipError(std::format("Pi-hole: a group forti-pihole creates must carry \"{}\" in its comment",
                                             ownership_marker));
        json body = {{"name", name}, {"comment", comment}, {"enabled", true}};
        json reply = send(Method::post, "/api/groups", &body);
        if (auto errors = processed_errors(reply); !errors.empty()) {
            std::string what = std::format("Pi-hole: POST /api/groups: group \"{}\" was not created: {}",
                                           printable(name, 80), printable(errors.front(), 200));
            if (is_duplicate_message(errors.front())) throw ConflictError(what, 400, "database_error", errors.front(), "");
            throw ApiError(what, 400, "database_error", errors.front(), "");
        }
        for (auto& group: decode_groups(reply))
            if (group.name == name) return group;
        throw DecodeError(std::format("Pi-hole: POST /api/groups: the reply does not contain group \"{}\"",
                                      printable(name, 80)));
    }

    std::vector<ClientEntry> Client::clients() { return decode_clients(send(Method::get, "/api/clients")); }

    std::optional<ClientEntry> Client::client(std::string_view client) {
        if (client.empty()) throw Error("Pi-hole: empty client");
        // An unknown client is 200 with an empty array (list.c reads with "WHERE ip = :item"), not 404.
        auto entries = decode_clients(send(Method::get, "/api/clients/" + encode_segment(client)));
        for (auto& entry: entries)
            if (entry.client == client) return std::move(entry);
        return std::nullopt;
    }

    void Client::check_spec(const ClientSpec& spec, std::string_view action) {
        auto canonical = canonical_client(spec.client);
        if (!canonical)
            throw Error(std::format("Pi-hole: cannot {} client \"{}\": not an address, subnet, MAC address, hostname "
                                    "or :interface Pi-hole can match", action, printable(spec.client, 80)));
        if (*canonical != spec.client)
            throw Error(std::format("Pi-hole: cannot {} client \"{}\": write it as \"{}\"", action,
                                    printable(spec.client, 80), *canonical));
        if (!carries_marker(spec.comment))
            throw OwnershipError(std::format("Pi-hole: cannot {} client \"{}\": the comment must carry \"{}\"", action,
                                             spec.client, ownership_marker));
        if (has_control(spec.comment))
            throw Error(std::format("Pi-hole: cannot {} client \"{}\": control characters in the comment", action,
                                    spec.client));
        if (spec.groups.empty() && !spec.allow_no_groups)
            throw Error(std::format("Pi-hole: cannot {} client \"{}\" with no group: no list would apply to it "
                                    "(set allow_no_groups to mean that)", action, spec.client));
        std::set<int> seen;
        for (int id: spec.groups) {
            if (id < 0) throw Error(std::format("Pi-hole: invalid group id {}", id));
            if (!seen.insert(id).second)
                throw Error(std::format("Pi-hole: cannot {} client \"{}\": group {} is listed twice", action, spec.client, id));
        }
    }

    void Client::check_groups_exist(const std::vector<int>& ids) {
        if (ids.empty()) return;
        auto existing = groups();
        for (int id: ids)
            if (std::ranges::none_of(existing, [id](const Group& group) { return group.id == id; }))
                throw Error(std::format("Pi-hole: group {} does not exist (sending it would fail half-way: FTL drops the "
                                        "old memberships before it inserts the new ones)", id));
    }

    ClientEntry Client::checked_reply(const json& reply, std::string_view where, const ClientSpec& spec) {
        if (auto errors = processed_errors(reply); !errors.empty())
            throw ApiError(std::format("Pi-hole: {}: client \"{}\" failed: {}", where, spec.client,
                                       printable(errors.front(), 200)),
                           400, "database_error", errors.front(), "");
        std::vector<int> expected = spec.groups;
        std::ranges::sort(expected);
        for (auto& entry: decode_clients(reply)) {
            if (entry.client != spec.client) continue;
            if (entry.groups != expected)
                throw Error(std::format("Pi-hole: {}: client \"{}\" is now in groups {}, expected {}", where, spec.client,
                                        list(entry.groups), list(expected)));
            if (!entry.managed())
                throw Error(std::format("Pi-hole: {}: client \"{}\" came back without the ownership marker", where,
                                        spec.client));
            return std::move(entry);
        }
        throw DecodeError(std::format("Pi-hole: {}: the reply does not contain client \"{}\"", where, spec.client));
    }

    ClientEntry Client::create_client(const ClientSpec& spec) {
        check_spec(spec, "create");
        for (const auto& entry: clients())
            if (equals_nocase(entry.client, spec.client))
                throw ConflictError(std::format("Pi-hole: client \"{}\" already exists as \"{}\" (id {}{})", spec.client,
                                                printable(entry.client, 80), entry.id,
                                                entry.managed() ? "" : ", an administrator's entry"),
                                    0, "conflict", "The item is already present", "");
        check_groups_exist(spec.groups);
        json body = {{"client", spec.client}, {"comment", spec.comment}, {"groups", spec.groups}};
        return checked_reply(send(Method::post, "/api/clients", &body), "POST /api/clients", spec);
    }

    ClientEntry Client::update_client(const ClientSpec& spec) {
        check_spec(spec, "update");
        auto current = client(spec.client);
        // PUT would create it (an upsert): an update of something that is not there is refused.
        if (!current)
            throw NotFoundError(std::format("Pi-hole: cannot update client \"{}\": no such entry", spec.client), 404,
                                "not_found", "", "");
        require_managed(*current, "update");
        check_groups_exist(spec.groups);
        // The comment is always sent: PUT stores null for a missing one, and the marker would go with it.
        json body = {{"comment", spec.comment}, {"groups", spec.groups}};
        std::string path = "/api/clients/" + encode_segment(spec.client);
        return checked_reply(send(Method::put, path, &body), "PUT " + path, spec);
    }

    bool Client::delete_client(std::string_view client) {
        auto current = this->client(client);
        if (!current) return false;
        require_managed(*current, "delete");
        try {
            send(Method::del, "/api/clients/" + encode_segment(client));
        } catch (const NotFoundError&) {
            return false;   // removed meanwhile
        }
        return true;
    }

}  // namespace fph::pihole
