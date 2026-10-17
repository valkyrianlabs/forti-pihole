// The client on a scripted transport: sessions, the write allowlist, ownership refusals and errors.

#include "pihole/client.hpp"
#include "pihole/fake_transport.hpp"
#include "pihole/marker.hpp"

#include <gtest/gtest.h>

#include <format>
#include <optional>

using namespace fph::pihole;

namespace {

    constexpr const char* password = "app-secret-5e1f";
    constexpr const char* sid = "vFA+EP4MQ5JJvJg+3Q2Jnw=";

    std::string login_ok() {
        return std::format(R"({{"session": {{"valid": true, "totp": false, "sid": "{}", "csrf": "Ux87YTIiMOf/GKCefVIOMw=",
                              "validity": 1800, "message": "app-password correct"}}, "took": 0.003}})", sid);
    }

    constexpr const char* groups_reply = R"({"groups": [
        {"name": "Default", "comment": "The default group", "enabled": true, "id": 0, "date_added": 1, "date_modified": 1},
        {"name": "iot", "comment": "managed by forti-pihole", "enabled": true, "id": 2, "date_added": 1, "date_modified": 1}],
        "took": 0.001})";

    std::string client_reply(std::string_view client, std::string_view comment, std::string_view groups, int id = 7) {
        return std::format(R"({{"clients": [{{"client": "{}", "name": "", "comment": {}, "groups": {}, "id": {},
                              "date_added": 1, "date_modified": 2}}], "processed": {{"errors": [], "success": [{{"item": "{}"}}]}},
                              "took": 0.001}})",
                           client, comment.empty() ? "null" : std::format("\"{}\"", comment), groups, id, client);
    }

    constexpr const char* no_clients = R"({"clients": [], "took": 0.001})";

    ClientSpec spec(std::string client, std::string comment, std::vector<int> groups) {
        ClientSpec out;
        out.client = std::move(client);
        out.comment = std::move(comment);
        out.groups = std::move(groups);
        return out;
    }

    struct Session {
        std::shared_ptr<FakeTransport> fake = std::make_shared<FakeTransport>();
        std::optional<Client> client;

        Session() {
            fake->expect(Method::post, "/api/auth", 200, login_ok());
            client.emplace(fake);
            client->login(password);
        }

        // Expect the logout the destructor sends, and run it.
        void finish() {
            fake->expect(Method::del, "/api/auth", 204);
            client.reset();
            EXPECT_EQ(fake->pending(), 0u);
        }

        [[nodiscard]] std::size_t sent(Method method, std::string_view path) const {
            std::size_t n = 0;
            for (const auto& r: fake->requests())
                if (r.method == method && r.path == path) ++n;
            return n;
        }
    };

}  // namespace

TEST(PiholeClient, LogsInWithThePasswordInTheBodyAndUsesTheSidHeader) {
    Session s;
    s.fake->expect(Method::get, "/api/info/version", 200,
                   R"({"version": {"ftl": {"local": {"version": "v6.7.1"}}}, "took": 0.001})");
    auto info = s.client->require_supported_version();
    EXPECT_EQ(info.ftl.version, "v6.7.1");

    const auto& login = s.fake->requests().at(0);
    EXPECT_EQ(nlohmann::json::parse(login.body)["password"], password);
    EXPECT_EQ(login.path.find(password), std::string::npos);
    EXPECT_EQ(FakeTransport::header(login, "X-FTL-SID"), "");

    const auto& version = s.fake->requests().at(1);
    EXPECT_EQ(FakeTransport::header(version, "X-FTL-SID"), sid);
    EXPECT_TRUE(version.body.empty());
    s.finish();
    EXPECT_EQ(FakeTransport::header(s.fake->requests().back(), "X-FTL-SID"), sid);
}

TEST(PiholeClient, LogsOutWhenAnExceptionUnwinds) {
    auto fake = std::make_shared<FakeTransport>();
    fake->expect(Method::post, "/api/auth", 200, login_ok());
    fake->expect(Method::get, "/api/info/version", 200,
                 R"({"version": {"ftl": {"local": {"version": "v6.4.3"}}}, "took": 0.001})");
    fake->expect(Method::del, "/api/auth", 204);
    try {
        Client client(fake);
        client.login(password);
        client.require_supported_version();
        FAIL() << "an old FTL was accepted";
    } catch (const VersionError&) {
    }
    EXPECT_EQ(fake->pending(), 0u);
}

TEST(PiholeClient, AWrongPasswordIsFinal) {
    auto fake = std::make_shared<FakeTransport>();
    fake->expect(Method::post, "/api/auth", 401,
                 R"({"session": {"valid": false, "totp": false, "sid": null, "validity": -1, "message": "password incorrect"},
                     "took": 0.003})");
    {
        Client client(fake);
        try {
            client.login("wrong");
            FAIL();
        } catch (const AuthError& error) {
            EXPECT_EQ(error.status(), 401);
            EXPECT_EQ(error.message(), "password incorrect");
            EXPECT_EQ(std::string(error.what()).find("wrong"), std::string::npos);
        }
        // No second attempt, and nothing to log out.
        EXPECT_THROW(client.login(password), AuthError);
        EXPECT_FALSE(client.logged_in());
        EXPECT_THROW((void) client.groups(), AuthError);
    }
    EXPECT_EQ(fake->requests().size(), 1u);
}

TEST(PiholeClient, TwoFactorAuthenticationAsksForAnAppPassword) {
    auto fake = std::make_shared<FakeTransport>();
    fake->expect(Method::post, "/api/auth", 400,
                 R"({"error": {"key": "bad_request", "message": "No 2FA token found in JSON payload", "hint": null}, "took": 0})");
    Client client(fake);
    try {
        client.login("admin-password");
        FAIL();
    } catch (const AuthError& error) {
        EXPECT_NE(std::string(error.what()).find("app password"), std::string::npos) << error.what();
    }
}

TEST(PiholeClient, RateLimitsAndSeatsAreRateLimitErrors) {
    for (auto body: {R"({"error": {"key": "rate_limiting", "message": "Rate-limiting login attempts", "hint": null}})",
                     R"({"error": {"key": "api_seats_exceeded", "message": "API seats exceeded",
                                   "hint": "increase webserver.api.max_sessions"}})"}) {
        auto fake = std::make_shared<FakeTransport>();
        fake->expect(Method::post, "/api/auth", 429, body);
        Client client(fake);
        EXPECT_THROW(client.login(password), RateLimitError);
        EXPECT_EQ(fake->requests().size(), 1u);
    }
}

TEST(PiholeClient, APiholeWithoutPasswordNeedsNoSession) {
    auto fake = std::make_shared<FakeTransport>();
    fake->expect(Method::post, "/api/auth", 200,
                 R"({"session": {"valid": true, "totp": false, "sid": null, "validity": -1, "message": "no password set"}})");
    fake->expect(Method::get, "/api/groups", 200, groups_reply);
    {
        Client client(fake);
        client.login(password);
        EXPECT_TRUE(client.logged_in());
        EXPECT_EQ(client.groups().size(), 2u);
        EXPECT_EQ(FakeTransport::header(fake->requests().back(), "X-FTL-SID"), "");
    }
    EXPECT_EQ(fake->requests().size(), 2u);   // no DELETE /api/auth
}

TEST(PiholeClient, AnExpiredSessionIsNotRenewed) {
    Session s;
    s.fake->expect(Method::get, "/api/clients", 401,
                   R"({"error": {"key": "unauthorized", "message": "Unauthorized", "hint": null}, "took": 0})");
    EXPECT_THROW((void) s.client->clients(), AuthError);
    EXPECT_FALSE(s.client->logged_in());
    EXPECT_THROW((void) s.client->clients(), AuthError);   // refused locally, no request, no login
    s.client.reset();
    EXPECT_EQ(s.fake->requests().size(), 2u);              // no logout either: the session is gone
}

TEST(PiholeClient, ALogoutThatFailsDoesNotThrow) {
    auto fake = std::make_shared<FakeTransport>();
    fake->expect(Method::post, "/api/auth", 200, login_ok());
    fake->expect_failure(Method::del, "/api/auth");
    Client client(fake);
    client.login(password);
    EXPECT_FALSE(client.logout());
    EXPECT_FALSE(client.logged_in());
    EXPECT_TRUE(client.logout());   // nothing left to close
}

TEST(PiholeClient, TheAllowlist) {
    EXPECT_EQ(refuse_request(Method::get, "/api/auth"), "");
    EXPECT_EQ(refuse_request(Method::post, "/api/auth"), "");
    EXPECT_EQ(refuse_request(Method::del, "/api/auth"), "");
    EXPECT_EQ(refuse_request(Method::get, "/api/info/version"), "");
    EXPECT_EQ(refuse_request(Method::get, "/api/groups"), "");
    EXPECT_EQ(refuse_request(Method::post, "/api/groups"), "");
    EXPECT_EQ(refuse_request(Method::get, "/api/clients"), "");
    EXPECT_EQ(refuse_request(Method::post, "/api/clients"), "");
    EXPECT_EQ(refuse_request(Method::get, "/api/clients/10.0.0.0%2F24"), "");
    EXPECT_EQ(refuse_request(Method::put, "/api/clients/10.0.0.0%2F24"), "");
    EXPECT_EQ(refuse_request(Method::del, "/api/clients/AA%3ABB%3ACC%3ADD%3AEE%3AFF"), "");

    // Groups are never changed or removed; nothing else in the API is reachable.
    EXPECT_NE(refuse_request(Method::put, "/api/groups/iot"), "");
    EXPECT_NE(refuse_request(Method::del, "/api/groups/iot"), "");
    EXPECT_NE(refuse_request(Method::post, "/api/groups:batchDelete"), "");
    EXPECT_NE(refuse_request(Method::post, "/api/clients:batchDelete"), "");
    EXPECT_NE(refuse_request(Method::put, "/api/clients"), "");
    EXPECT_NE(refuse_request(Method::del, "/api/clients"), "");
    EXPECT_NE(refuse_request(Method::del, "/api/clients/a/b"), "");
    EXPECT_NE(refuse_request(Method::get, "/api/clients?sid=x"), "");
    EXPECT_NE(refuse_request(Method::get, "/api/auth/app"), "");          // would mint an app password
    EXPECT_NE(refuse_request(Method::get, "/api/teleporter"), "");        // a full backup
    EXPECT_NE(refuse_request(Method::get, "/api/config"), "");
    EXPECT_NE(refuse_request(Method::post, "/api/lists"), "");
    EXPECT_NE(refuse_request(Method::post, "/api/domains/deny/exact"), "");
    EXPECT_NE(refuse_request(Method::post, "/api/action/gravity"), "");
    EXPECT_NE(refuse_request(Method::del, "/api/auth/session/3"), "");
}

TEST(PiholeClient, CreatesAClientWithItsGroups) {
    Session s;
    s.fake->expect(Method::get, "/api/clients", 200, no_clients);
    s.fake->expect(Method::get, "/api/groups", 200, groups_reply);
    s.fake->expect(Method::post, "/api/clients", 201, client_reply("10.0.0.0/24", "managed by forti-pihole: segment iot", "[2]"));
    auto entry = s.client->create_client(spec("10.0.0.0/24", "managed by forti-pihole: segment iot", {2}));
    EXPECT_EQ(entry.id, 7);
    EXPECT_EQ(entry.groups, (std::vector<int>{2}));
    auto body = nlohmann::json::parse(s.fake->requests().back().body);
    EXPECT_EQ(body, nlohmann::json::parse(
                            R"({"client": "10.0.0.0/24", "comment": "managed by forti-pihole: segment iot", "groups": [2]})"));
    s.finish();
}

TEST(PiholeClient, NoticesWhenPiholeStoredOtherGroups) {
    Session s;
    s.fake->expect(Method::get, "/api/clients", 200, no_clients);
    s.fake->expect(Method::get, "/api/groups", 200, groups_reply);
    s.fake->expect(Method::post, "/api/clients", 201, client_reply("10.0.0.5", "managed by forti-pihole", "[0]"));
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", "managed by forti-pihole", {2})), Error);
    s.finish();
}

TEST(PiholeClient, RefusesBadCreatesBeforeSendingAnything) {
    Session s;
    std::string marker(fph::ownership_marker);
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", "kids' tablet", {2})), OwnershipError);
    EXPECT_THROW(s.client->create_client(spec("10.0.0.7/24", marker, {2})), Error);           // not canonical
    EXPECT_THROW(s.client->create_client(spec("aa:bb:cc:dd:ee:ff", marker, {2})), Error);     // not canonical
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5 ", marker, {2})), Error);
    EXPECT_THROW(s.client->create_client(spec("0.0.0.0/0", marker, {2})), Error);
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", marker, {})), Error);               // no group by accident
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", marker, {2, 2})), Error);
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", marker + "\nx", {2})), Error);
    EXPECT_EQ(s.fake->requests().size(), 1u);   // only the login
    s.finish();
}

TEST(PiholeClient, RefusesUnknownGroupsBeforeWriting) {
    // FTL drops the old memberships before inserting the new ones, so an unknown id would fail half-way.
    Session s;
    s.fake->expect(Method::get, "/api/clients", 200, no_clients);
    s.fake->expect(Method::get, "/api/groups", 200, groups_reply);
    EXPECT_THROW(s.client->create_client(spec("10.0.0.5", "managed by forti-pihole", {2, 9})), Error);
    EXPECT_EQ(s.sent(Method::post, "/api/clients"), 0u);
    s.finish();
}

TEST(PiholeClient, RefusesACaseVariantOfAnExistingEntry) {
    Session s;
    s.fake->expect(Method::get, "/api/clients", 200,
                   R"({"clients": [{"client": "aa:bb:cc:dd:ee:ff", "name": "", "comment": null, "groups": [0], "id": 3,
                                    "date_added": 1, "date_modified": 1}]})");
    EXPECT_THROW(s.client->create_client(spec("AA:BB:CC:DD:EE:FF", "managed by forti-pihole", {2})), ConflictError);
    EXPECT_EQ(s.sent(Method::post, "/api/clients"), 0u);
    s.finish();
}

TEST(PiholeClient, NoGroupsWhenAskedFor) {
    Session s;
    s.fake->expect(Method::get, "/api/clients", 200, no_clients);
    s.fake->expect(Method::post, "/api/clients", 201, client_reply("10.0.0.5", "managed by forti-pihole", "[]"));
    ClientSpec unfiltered = spec("10.0.0.5", "managed by forti-pihole", {});
    unfiltered.allow_no_groups = true;
    EXPECT_TRUE(s.client->create_client(unfiltered).groups.empty());
    EXPECT_EQ(nlohmann::json::parse(s.fake->requests().back().body)["groups"], nlohmann::json::array());
    s.finish();
}

TEST(PiholeClient, UpdatesOnlyManagedEntriesAndKeepsTheMarker) {
    Session s;
    s.fake->expect(Method::get, "/api/clients/10.0.0.0%2F24", 200, client_reply("10.0.0.0/24", "managed by forti-pihole", "[2]"));
    s.fake->expect(Method::get, "/api/groups", 200, groups_reply);
    s.fake->expect(Method::put, "/api/clients/10.0.0.0%2F24", 200,
                   client_reply("10.0.0.0/24", "managed by forti-pihole: segment lab", "[0, 2]"));
    auto entry = s.client->update_client(spec("10.0.0.0/24", "managed by forti-pihole: segment lab", {2, 0}));
    EXPECT_EQ(entry.groups, (std::vector<int>{0, 2}));
    auto body = nlohmann::json::parse(s.fake->requests().back().body);
    EXPECT_EQ(body["comment"], "managed by forti-pihole: segment lab");   // always sent: PUT would null it
    EXPECT_FALSE(body.contains("client"));
    s.finish();
}

TEST(PiholeClient, RefusesToUpdateAnAdministratorsEntry) {
    Session s;
    s.fake->expect(Method::get, "/api/clients/10.0.0.5", 200, client_reply("10.0.0.5", "dad's laptop", "[0]"));
    EXPECT_THROW(s.client->update_client(spec("10.0.0.5", "managed by forti-pihole", {2})), OwnershipError);
    s.fake->expect(Method::get, "/api/clients/10.0.0.6", 200, client_reply("10.0.0.6", "", "[0]"));
    EXPECT_THROW(s.client->update_client(spec("10.0.0.6", "managed by forti-pihole", {2})), OwnershipError);
    EXPECT_EQ(s.sent(Method::put, "/api/clients/10.0.0.5") + s.sent(Method::put, "/api/clients/10.0.0.6"), 0u);
    s.finish();
}

TEST(PiholeClient, RefusesToUpdateAMissingEntry) {
    // PUT is an upsert in FTL: it would create the entry.
    Session s;
    s.fake->expect(Method::get, "/api/clients/10.0.0.5", 200, no_clients);
    EXPECT_THROW(s.client->update_client(spec("10.0.0.5", "managed by forti-pihole", {2})), NotFoundError);
    EXPECT_EQ(s.sent(Method::put, "/api/clients/10.0.0.5"), 0u);
    s.finish();
}

TEST(PiholeClient, UpdateRefusesToDropTheMarker) {
    Session s;
    EXPECT_THROW(s.client->update_client(spec("10.0.0.5", "", {2})), OwnershipError);
    EXPECT_THROW(s.client->update_client(spec("10.0.0.5", "laptop", {2})), OwnershipError);
    EXPECT_EQ(s.fake->requests().size(), 1u);
    s.finish();
}

TEST(PiholeClient, DeletesOnlyManagedEntries) {
    Session s;
    s.fake->expect(Method::get, "/api/clients/AA%3ABB%3ACC%3ADD%3AEE%3AFF", 200,
                   client_reply("AA:BB:CC:DD:EE:FF", "managed by forti-pihole", "[2]"));
    s.fake->expect(Method::del, "/api/clients/AA%3ABB%3ACC%3ADD%3AEE%3AFF", 204);
    EXPECT_TRUE(s.client->delete_client("AA:BB:CC:DD:EE:FF"));

    s.fake->expect(Method::get, "/api/clients/10.0.0.5", 200, client_reply("10.0.0.5", "printer", "[0]"));
    EXPECT_THROW(s.client->delete_client("10.0.0.5"), OwnershipError);
    EXPECT_EQ(s.sent(Method::del, "/api/clients/10.0.0.5"), 0u);

    s.fake->expect(Method::get, "/api/clients/10.0.0.9", 200, no_clients);
    EXPECT_FALSE(s.client->delete_client("10.0.0.9"));

    // Gone between the read and the delete.
    s.fake->expect(Method::get, "/api/clients/10.0.0.8", 200, client_reply("10.0.0.8", "managed by forti-pihole", "[2]"));
    s.fake->expect(Method::del, "/api/clients/10.0.0.8", 404, R"({"took": 0.001})");
    EXPECT_FALSE(s.client->delete_client("10.0.0.8"));
    s.finish();
}

TEST(PiholeClient, CreatesGroupsAndReportsDuplicates) {
    Session s;
    s.fake->expect(Method::post, "/api/groups", 201,
                   R"({"groups": [{"name": "kids", "comment": "managed by forti-pihole", "enabled": true, "id": 4,
                                   "date_added": 1, "date_modified": 1}],
                       "processed": {"errors": [], "success": [{"item": "kids"}]}, "took": 0.001})");
    auto group = s.client->create_group("kids", "managed by forti-pihole");
    EXPECT_EQ(group.id, 4);
    EXPECT_EQ(nlohmann::json::parse(s.fake->requests().back().body),
              nlohmann::json::parse(R"({"name": "kids", "comment": "managed by forti-pihole", "enabled": true})"));

    s.fake->expect(Method::post, "/api/groups", 400,
                   R"({"error": {"key": "database_error", "message": "Could not add to gravity database",
                                 "hint": "The item is already present"}, "took": 0.001})");
    EXPECT_THROW(s.client->create_group("kids", "managed by forti-pihole"), ConflictError);
    EXPECT_THROW(s.client->create_group("kids", "no marker"), OwnershipError);
    EXPECT_THROW(s.client->create_group("", "managed by forti-pihole"), Error);
    EXPECT_THROW(s.client->create_group("a\r\nb", "managed by forti-pihole"), Error);
    s.finish();
}

TEST(PiholeClient, ATransportFailureIsATransportError) {
    Session s;
    s.fake->expect_failure(Method::get, "/api/groups");
    EXPECT_THROW((void) s.client->groups(), TransportError);
    s.finish();
}

TEST(PiholeClient, ANonJsonReplyIsADecodeError) {
    Session s;
    s.fake->expect(Method::get, "/api/groups", 200, "<html>proxy login</html>");
    EXPECT_THROW((void) s.client->groups(), DecodeError);
    s.finish();
}
