// Endpoint validation, path encoding and the mapping of Pi-hole's error replies.

#include "pihole/error.hpp"
#include "pihole/marker.hpp"
#include "pihole/transport.hpp"

#include <gtest/gtest.h>

using namespace fph::pihole;

static_assert(fph::ownership_marker == "managed by forti-pihole");
static_assert(fph::carries_marker("managed by forti-pihole: segment iot"));
static_assert(!fph::carries_marker(""));

namespace {

    std::string base(std::string url) { return validated_base_url(Endpoint{std::move(url), std::nullopt, 15000}); }

    template <typename E>
    E caught(long status, std::string_view body) {
        try {
            throw_api_error("POST /api/clients", status, body);
        } catch (const E& error) {
            return error;
        } catch (const std::exception& other) {
            ADD_FAILURE() << "wrong error type: " << other.what();
        }
        throw std::logic_error("unreachable");
    }

}  // namespace

TEST(PiholeTransport, AcceptsHttpsAndLoopbackHttp) {
    EXPECT_EQ(base("https://pihole.example.net"), "https://pihole.example.net");
    EXPECT_EQ(base("https://pihole.example.net/"), "https://pihole.example.net");
    EXPECT_EQ(base("https://pihole.example.net/api"), "https://pihole.example.net");
    EXPECT_EQ(base("https://pihole.example.net/api/"), "https://pihole.example.net");
    EXPECT_EQ(base("https://10.0.0.53:8443/pihole/"), "https://10.0.0.53:8443/pihole");
    EXPECT_EQ(base("https://[fd00::53]:443"), "https://[fd00::53]:443");
    EXPECT_EQ(base("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
    EXPECT_EQ(base("http://localhost:8080/"), "http://localhost:8080");
    EXPECT_EQ(base("http://[::1]:8080"), "http://[::1]:8080");
}

TEST(PiholeTransport, RefusesUnsafeEndpoints) {
    EXPECT_THROW(base("http://pihole.example.net"), Error);        // password in clear over a network
    EXPECT_THROW(base("http://10.0.0.53"), Error);
    EXPECT_THROW(base("http://127.0.0.1.example.net"), Error);
    EXPECT_THROW(base("ftp://pihole.example.net"), Error);
    EXPECT_THROW(base("pihole.example.net"), Error);
    EXPECT_THROW(base("https://admin:secret@pihole.example.net"), Error);
    EXPECT_THROW(base("https://pihole.example.net/?sid=x"), Error);
    EXPECT_THROW(base("https://pihole.example.net/#x"), Error);
    EXPECT_THROW(base("https://"), Error);
    EXPECT_THROW(base("https://pi hole"), Error);
    EXPECT_THROW((void) validated_base_url(Endpoint{"https://pi.hole", std::nullopt, 0}), Error);
    try {
        base("https://admin:hunter2@pi.hole");
    } catch (const Error& error) {
        EXPECT_EQ(std::string(error.what()).find("hunter2"), std::string::npos);
    }
}

TEST(PiholeTransport, EncodesPathSegments) {
    EXPECT_EQ(encode_segment("10.0.0.0/24"), "10.0.0.0%2F24");
    EXPECT_EQ(encode_segment("fd00::/64"), "fd00%3A%3A%2F64");
    EXPECT_EQ(encode_segment("AA:BB:CC:DD:EE:FF"), "AA%3ABB%3ACC%3ADD%3AEE%3AFF");
    EXPECT_EQ(encode_segment(":eth0"), "%3Aeth0");
    EXPECT_EQ(encode_segment("tv.lan"), "tv.lan");
    EXPECT_EQ(encode_segment("a b+c?d#e%"), "a%20b%2Bc%3Fd%23e%25");
}

TEST(PiholeErrors, MapsPiholeErrorObjects) {
    auto error = caught<ApiError>(500, R"({"error": {"key": "database_error", "message": "Could not read domains from database table",
                                                     "hint": "disk I/O error"}, "took": 0.001})");
    EXPECT_EQ(error.status(), 500);
    EXPECT_EQ(error.key(), "database_error");
    EXPECT_EQ(error.message(), "Could not read domains from database table");
    EXPECT_EQ(error.hint(), "disk I/O error");
    EXPECT_NE(std::string(error.what()).find("POST /api/clients: HTTP 500 database_error"), std::string::npos);

    auto bad = caught<ApiError>(400, R"({"error": {"key": "bad_request", "message": "Spaces and tabs are not allowed in domains and URLs",
                                                  "hint": "10.0.0.1 "}})");
    EXPECT_EQ(bad.key(), "bad_request");
    EXPECT_EQ(bad.hint(), "10.0.0.1 ");
}

TEST(PiholeErrors, MapsStatusesToTypes) {
    caught<AuthError>(401, R"({"error": {"key": "unauthorized", "message": "Unauthorized", "hint": null}, "took": 0})");
    auto login = caught<AuthError>(401, R"({"session": {"valid": false, "totp": false, "sid": null, "validity": -1,
                                                        "message": "password incorrect"}, "took": 0})");
    EXPECT_EQ(login.message(), "password incorrect");
    EXPECT_NE(std::string(login.what()).find("no retry"), std::string::npos);
    caught<RateLimitError>(429, R"({"error": {"key": "rate_limiting", "message": "Rate-limiting login attempts", "hint": null}})");
    caught<NotFoundError>(404, R"({"took": 0.001})");
    auto duplicate = caught<ConflictError>(400, R"({"error": {"key": "database_error", "message": "Could not add to gravity database",
                                                             "hint": "The item is already present"}})");
    EXPECT_EQ(duplicate.hint(), "The item is already present");
    caught<ConflictError>(400, R"({"error": {"key": "database_error", "message": "Could not add to gravity database",
                                            "hint": "UNIQUE constraint failed: client.ip"}})");
    // A foreign-key failure is not a duplicate. (Caught by type: caught<ApiError> returns a copy, which
    // could never be a ConflictError whatever was thrown.)
    try {
        throw_api_error("POST /api/clients", 400, R"({"error": {"key": "database_error", "message": "Could not add to gravity database",
                                                             "hint": "FOREIGN KEY constraint failed"}})");
        ADD_FAILURE() << "no error thrown";
    } catch (const ConflictError& error) {
        ADD_FAILURE() << "a foreign-key failure classified as a duplicate: " << error.what();
    } catch (const ApiError& error) {
        EXPECT_EQ(error.status(), 400);
    }
}

TEST(PiholeErrors, NonApiReplies) {
    auto redirect = caught<ApiError>(302, "");
    EXPECT_NE(std::string(redirect.what()).find("redirect refused"), std::string::npos);
    auto html = caught<ApiError>(502, "<html><body>Bad Gateway</body></html>");
    EXPECT_NE(std::string(html.what()).find("not a Pi-hole API reply"), std::string::npos);
    EXPECT_EQ(std::string(html.what()).find("Bad Gateway"), std::string::npos);
}

TEST(PiholeErrors, UntrustedTextStaysPrintable) {
    auto error = caught<ApiError>(400, R"({"error": {"key": "bad_request", "message": "bad\r\nX-Injected: 1",
                                                    "hint": "\u001b[31mred"}})");
    std::string what = error.what();
    EXPECT_EQ(what.find('\r'), std::string::npos);
    EXPECT_EQ(what.find('\n'), std::string::npos);
    EXPECT_EQ(what.find('\x1b'), std::string::npos);
}
