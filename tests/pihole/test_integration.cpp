// The client and the real libcurl transport against tests/mock-pihole/mock_pihole.py, which
// tests/mock-pihole/harness.py starts (PIHOLE_MOCK_URL). Each test resets the mock, drives a Client,
// and inspects the mock's state and request log through its /_mock endpoints. Skipped without the
// harness.

#include "pihole/client.hpp"
#include "pihole/marker.hpp"
#include "pihole/resolve.hpp"
#include "pihole/transport.hpp"

#include <gtest/gtest.h>

#include <cstdlib>
#include <memory>
#include <optional>

using namespace fph::pihole;
using nlohmann::json;

namespace {

    const std::string marker(fph::ownership_marker);

    ClientSpec spec(std::string client, std::string comment, std::vector<int> groups) {
        ClientSpec out;
        out.client = std::move(client);
        out.comment = std::move(comment);
        out.groups = std::move(groups);
        return out;
    }

    std::string env(const char* name) {
        const char* value = std::getenv(name);
        return value ? value : "";
    }

    class PiholeMock : public ::testing::Test {
    protected:
        std::string url = env("PIHOLE_MOCK_URL");
        std::string app_password = env("PIHOLE_MOCK_APP_PASSWORD");
        std::string admin_password = env("PIHOLE_MOCK_ADMIN_PASSWORD");
        std::shared_ptr<CurlTransport> control;

        void SetUp() override {
            if (url.empty()) GTEST_SKIP() << "PIHOLE_MOCK_URL is not set (run through tests/mock-pihole/harness.py)";
            control = std::make_shared<CurlTransport>(Endpoint{url, std::nullopt, 10000});
            reset(json::object());
        }

        json call(Method method, const std::string& path, const json& body = nullptr) {
            Request request{method, path, {{"Content-Type", "application/json"}}, body.is_null() ? "" : body.dump()};
            auto response = control->perform(request);
            EXPECT_EQ(response.status, 200) << path << ": " << response.body;
            return json::parse(response.body);
        }

        void reset(const json& settings) { call(Method::post, "/_mock/reset", settings); }
        json state() { return call(Method::get, "/_mock/state"); }
        void fault(const json& spec) { call(Method::post, "/_mock/fault", spec); }

        std::shared_ptr<Transport> transport() { return std::make_shared<CurlTransport>(Endpoint{url, std::nullopt, 10000}); }

        std::unique_ptr<Client> logged_in() {
            auto client = std::make_unique<Client>(transport());
            client->login(app_password);
            return client;
        }

        std::size_t sent(std::string_view method, std::string_view path) {
            std::size_t n = 0;
            const json snapshot = state();   // named: a range over state()["requests"] would outlive it
            for (const auto& r: snapshot["requests"])
                if (r["method"] == method && r["path"] == path) ++n;
            return n;
        }

        json mock_client(std::string_view client) {
            const json snapshot = state();   // named: a range over state()["clients"] would outlive it
            for (const auto& c: snapshot["clients"])
                if (c["client"] == client) return c;
            return nullptr;
        }
    };

}  // namespace

TEST_F(PiholeMock, ASessionIsOpenedUsedAndClosed) {
    {
        auto client = logged_in();
        auto info = client->require_supported_version();
        EXPECT_EQ(info.ftl.version, "v6.7.1");
        EXPECT_EQ(info.core.version, "v6.4.3");
        EXPECT_EQ(state()["active_sessions"], 1);
    }
    auto s = state();
    EXPECT_EQ(s["active_sessions"], 0);
    const auto& requests = s["requests"];
    ASSERT_EQ(requests.size(), 3u);
    EXPECT_EQ(requests[0]["method"], "POST");
    EXPECT_EQ(requests[0]["has_sid"], false);
    EXPECT_EQ(requests[1]["path"], "/api/info/version");
    EXPECT_EQ(requests[1]["has_sid"], true);
    EXPECT_EQ(requests[2]["method"], "DELETE");
    EXPECT_EQ(requests[2]["path"], "/api/auth");
}

TEST_F(PiholeMock, AWrongPasswordIsTriedOnce) {
    Client client(transport());
    EXPECT_THROW(client.login("not-the-password"), AuthError);
    EXPECT_THROW(client.login(app_password), AuthError);
    EXPECT_EQ(sent("POST", "/api/auth"), 1u);
}

TEST_F(PiholeMock, TwoFactorNeedsTheAppPassword) {
    reset({{"totp", true}});
    {
        Client admin(transport());
        try {
            admin.login(admin_password);
            FAIL();
        } catch (const AuthError& error) {
            EXPECT_NE(std::string(error.what()).find("app password"), std::string::npos) << error.what();
            EXPECT_EQ(std::string(error.what()).find(admin_password), std::string::npos);
        }
    }
    auto client = logged_in();
    EXPECT_NO_THROW((void) client->groups());
}

TEST_F(PiholeMock, NoFreeSeatIsARateLimitError) {
    reset({{"max_sessions", 1}});
    auto first = logged_in();
    Client second(transport());
    try {
        second.login(app_password);
        FAIL();
    } catch (const RateLimitError& error) {
        EXPECT_EQ(error.key(), "api_seats_exceeded");
        EXPECT_EQ(error.hint(), "increase webserver.api.max_sessions");
    }
}

TEST_F(PiholeMock, AnOldPiholeIsRefusedAndStillLoggedOut) {
    reset({{"versions", {{"ftl", "v6.6.2"}}}});
    {
        auto client = logged_in();
        EXPECT_THROW(client->require_supported_version(), VersionError);
    }
    EXPECT_EQ(state()["active_sessions"], 0);
}

TEST_F(PiholeMock, AnExpiredSessionEndsTheRun) {
    auto client = logged_in();
    call(Method::post, "/_mock/expire");
    EXPECT_THROW((void) client->clients(), AuthError);
    client.reset();
    EXPECT_EQ(sent("POST", "/api/auth"), 1u);     // no new login
    EXPECT_EQ(sent("DELETE", "/api/auth"), 0u);   // and nothing to log out
}

TEST_F(PiholeMock, GroupsIncludeDefaultAndAreCreated) {
    auto client = logged_in();
    auto groups = client->groups();
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(groups[0].id, default_group_id);
    EXPECT_EQ(groups[0].name, "Default");

    auto iot = client->create_group("iot devices", marker + ": segment iot");
    EXPECT_GT(iot.id, 0);
    EXPECT_EQ(iot.comment, marker + ": segment iot");
    EXPECT_THROW(client->create_group("iot devices", marker), ConflictError);
    EXPECT_EQ(client->groups().size(), 2u);
}

TEST_F(PiholeMock, AClientEntryRoundTripsThroughCidrPaths) {
    reset({{"groups", json::array({{{"name", "iot"}, {"comment", marker}}, {{"name", "kids"}, {"comment", marker}}})}});
    auto client = logged_in();
    auto groups = client->groups();
    ASSERT_EQ(groups.size(), 3u);
    int iot = groups[1].id, kids = groups[2].id;

    auto created = client->create_client(spec("10.20.0.0/24", marker + ": segment iot", {iot}));
    EXPECT_EQ(created.groups, (std::vector<int>{iot}));   // not in Default: the given set replaces it
    EXPECT_EQ(mock_client("10.20.0.0/24")["groups"], json::array({iot}));
    EXPECT_EQ(sent("POST", "/api/clients"), 1u);

    auto read = client->client("10.20.0.0/24");
    ASSERT_TRUE(read.has_value());
    EXPECT_TRUE(read->managed());
    EXPECT_EQ(sent("GET", "/api/clients/10.20.0.0%2F24"), 1u);

    auto updated = client->update_client(spec("10.20.0.0/24", marker + ": segment kids", {kids, default_group_id}));
    EXPECT_EQ(updated.groups, (std::vector<int>{default_group_id, kids}));
    EXPECT_EQ(updated.comment, marker + ": segment kids");

    EXPECT_TRUE(client->delete_client("10.20.0.0/24"));
    EXPECT_FALSE(client->client("10.20.0.0/24").has_value());
    EXPECT_FALSE(client->delete_client("10.20.0.0/24"));
}

TEST_F(PiholeMock, IPv6MacAndInterfaceEntries) {
    reset({{"groups", json::array({{{"name", "iot"}, {"comment", marker}}})}});
    auto client = logged_in();
    for (const char* text: {"fd00:20::/64", "AA:BB:CC:DD:EE:FF", ":eth0.20", "tv.lan"}) {
        auto entry = client->create_client(spec(text, marker, {1}));
        EXPECT_EQ(entry.client, text);
        ASSERT_TRUE(client->client(text).has_value()) << text;
        EXPECT_TRUE(client->delete_client(text)) << text;
    }
    EXPECT_TRUE(state()["clients"].empty());
}

TEST_F(PiholeMock, AdministratorEntriesAreNeverChanged) {
    reset({{"groups", json::array({{{"name", "iot"}, {"comment", marker}}})},
           {"clients", json::array({{{"client", "10.0.0.5"}, {"comment", "dad's laptop"}, {"groups", json::array({0})}},
                                    {{"client", "aa:bb:cc:dd:ee:ff"}, {"groups", json::array({0})}}})}});
    auto client = logged_in();
    EXPECT_THROW(client->update_client(spec("10.0.0.5", marker, {1})), OwnershipError);
    EXPECT_THROW(client->delete_client("10.0.0.5"), OwnershipError);
    // A case variant of the administrator's MAC entry would be a second row Pi-hole cannot order.
    EXPECT_THROW(client->create_client(spec("AA:BB:CC:DD:EE:FF", marker, {1})), ConflictError);
    EXPECT_EQ(sent("PUT", "/api/clients/10.0.0.5"), 0u);
    EXPECT_EQ(sent("DELETE", "/api/clients/10.0.0.5"), 0u);
    EXPECT_EQ(sent("POST", "/api/clients"), 0u);
    EXPECT_EQ(mock_client("10.0.0.5")["comment"], "dad's laptop");
    EXPECT_EQ(mock_client("10.0.0.5")["groups"], json::array({0}));
}

TEST_F(PiholeMock, AMissingEntryIsNotCreatedByAnUpdate) {
    auto client = logged_in();
    EXPECT_THROW(client->update_client(spec("10.0.0.9", marker, {0})), NotFoundError);
    EXPECT_EQ(sent("PUT", "/api/clients/10.0.0.9"), 0u);
    EXPECT_TRUE(state()["clients"].empty());
}

TEST_F(PiholeMock, UnknownGroupsNeverReachPihole) {
    // The mock, like FTL, would delete the memberships and then fail on the foreign key.
    reset({{"clients", json::array({{{"client", "10.0.0.5"}, {"comment", marker}, {"groups", json::array({0})}}})}});
    auto client = logged_in();
    EXPECT_THROW(client->update_client(spec("10.0.0.5", marker, {0, 42})), Error);
    EXPECT_EQ(sent("PUT", "/api/clients/10.0.0.5"), 0u);
    EXPECT_EQ(mock_client("10.0.0.5")["groups"], json::array({0}));
}

TEST_F(PiholeMock, ErrorsCarryPiholesKeyMessageAndHint) {
    auto client = logged_in();
    fault({{"method", "POST"}, {"path", "/api/clients"}, {"status", 500},
           {"body", {{"error", {{"key", "database_error"}, {"message", "Could not open gravity database"}, {"hint", nullptr}}}}}});
    try {
        client->create_client(spec("10.0.0.5", marker, {0}));
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_EQ(error.status(), 500);
        EXPECT_EQ(error.key(), "database_error");
        EXPECT_EQ(error.message(), "Could not open gravity database");
    }
}

TEST_F(PiholeMock, RedirectsAreNotFollowed) {
    auto client = logged_in();
    fault({{"method", "GET"}, {"path", "/api/groups"}, {"status", 302},
           {"headers", {{"Location", "http://127.0.0.2:9/api/groups"}}}});
    try {
        (void) client->groups();
        FAIL();
    } catch (const ApiError& error) {
        EXPECT_EQ(error.status(), 302);
        EXPECT_NE(std::string(error.what()).find("redirect refused"), std::string::npos);
    }
}

TEST_F(PiholeMock, ResolutionOverTheLiveClientList) {
    // A VLAN subnet, a slice inside it, one pinned device, and a MAC entry the subnet shadows.
    reset({{"groups", json::array({{{"name", "vlan"}, {"comment", marker}}, {{"name", "slice"}, {"comment", marker}},
                                   {{"name", "pinned"}, {"comment", marker}}, {{"name", "by-mac"}, {"comment", marker}}})}});
    auto client = logged_in();
    client->create_client(spec("10.30.0.0/24", marker, {1}));
    client->create_client(spec("10.30.0.16/28", marker, {2}));
    client->create_client(spec("10.30.0.20", marker, {3}));
    client->create_client(spec("AA:BB:CC:DD:EE:01", marker, {4}));
    auto clients = client->clients();
    ASSERT_EQ(clients.size(), 4u);
    EXPECT_TRUE(find_ambiguities(clients).empty());

    EXPECT_EQ(effective_groups(clients, "10.30.0.20", "aa:bb:cc:dd:ee:01"), (std::vector<int>{3}));
    EXPECT_EQ(effective_groups(clients, "10.30.0.21", "aa:bb:cc:dd:ee:01"), (std::vector<int>{2}));
    EXPECT_EQ(effective_groups(clients, "10.30.0.99", "aa:bb:cc:dd:ee:01"), (std::vector<int>{1}));   // MAC shadowed
    EXPECT_EQ(effective_groups(clients, "192.168.9.9", "aa:bb:cc:dd:ee:01"), (std::vector<int>{4}));
    EXPECT_EQ(effective_groups(clients, "192.168.9.9"), (std::vector<int>{0}));
}
