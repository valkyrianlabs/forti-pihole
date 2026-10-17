// The request parser: well-formed requests (whole and byte by byte), every refusal, the size limits,
// and a deterministic fuzz pass that must never crash or accept garbage.

#include <http.hpp>

#include <gtest/gtest.h>

#include <random>

namespace fph::daemon::test {

    using http::RequestParser;
    using Progress = RequestParser::Progress;

    namespace {

        const std::string good = "POST /v1/fortigate/events?x=1 HTTP/1.1\r\n"
                                 "Host: 192.0.2.10:8735\r\n"
                                 "Authorization: Bearer abc\r\n"
                                 "Content-Type: application/json\r\n"
                                 "Content-Length: 14\r\n"
                                 "\r\n"
                                 "{\"cfgobj\":\"x\"}";

        // Feeds everything and continues past head_complete; returns the final progress.
        Progress run(RequestParser& parser, std::string_view bytes) {
            auto progress = parser.feed(bytes);
            if (progress == Progress::head_complete) progress = parser.feed({});
            return progress;
        }

        int refusal(std::string_view bytes, http::Limits limits = {}) {
            RequestParser parser(limits);
            auto progress = run(parser, bytes);
            return progress == Progress::failed ? parser.error_status() : 0;
        }

    }  // namespace

    TEST(HttpParser, ParsesAWholeRequest) {
        RequestParser parser;
        ASSERT_EQ(parser.feed(good), Progress::head_complete);
        EXPECT_EQ(parser.head().method, "POST");
        EXPECT_EQ(parser.head().target, "/v1/fortigate/events?x=1");
        EXPECT_EQ(parser.head().path, "/v1/fortigate/events");
        ASSERT_NE(parser.head().header("authorization"), nullptr);
        EXPECT_EQ(*parser.head().header("authorization"), "Bearer abc");
        EXPECT_EQ(parser.head().content_length, 14u);
        ASSERT_EQ(parser.feed({}), Progress::complete);
        EXPECT_EQ(parser.request().body, "{\"cfgobj\":\"x\"}");
    }

    TEST(HttpParser, ParsesOneByteAtATime) {
        RequestParser parser;
        bool head = false, complete = false;
        for (char c: good) {
            auto progress = parser.feed(std::string_view(&c, 1));
            ASSERT_NE(progress, Progress::failed) << parser.error();
            if (progress == Progress::head_complete) {
                head = true;
                progress = parser.feed({});
            }
            complete = progress == Progress::complete;
        }
        EXPECT_TRUE(head);
        EXPECT_TRUE(complete);
        EXPECT_EQ(parser.request().body, "{\"cfgobj\":\"x\"}");
    }

    TEST(HttpParser, GetWithoutBodyAndHttp10WithoutHost) {
        RequestParser parser;
        EXPECT_EQ(run(parser, "GET /v1/health HTTP/1.1\r\nHost: a\r\n\r\n"), Progress::complete);
        RequestParser old;
        EXPECT_EQ(run(old, "GET /v1/health HTTP/1.0\r\n\r\n"), Progress::complete);
    }

    TEST(HttpParser, IgnoresBytesAfterTheRequest) {
        RequestParser parser;
        EXPECT_EQ(run(parser, "GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /again HTTP/1.1\r\n"), Progress::complete);
        EXPECT_EQ(parser.head().path, "/");
    }

    TEST(HttpParser, RefusesMalformedRequests) {
        EXPECT_EQ(refusal("GET / HTTP/1.1\nHost: a\n\n"), 400);                        // bare LF
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n"), 400);               // bare CR
        EXPECT_EQ(refusal("GET  / HTTP/1.1\r\nHost: a\r\n\r\n"), 400);                 // double space
        EXPECT_EQ(refusal("GET / HTTP/1.1 x\r\nHost: a\r\n\r\n"), 400);                // extra token
        EXPECT_EQ(refusal("get / HTTP/1.1\r\nHost: a\r\n\r\n"), 400);                  // lower-case method
        EXPECT_EQ(refusal("GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\n"), 400);          // absolute-form
        EXPECT_EQ(refusal("GET * HTTP/1.1\r\nHost: a\r\n\r\n"), 400);                  // asterisk-form
        EXPECT_EQ(refusal("GET / HTTP/2.0\r\nHost: a\r\n\r\n"), 505);
        EXPECT_EQ(refusal("GET / FTP/1.1\r\nHost: a\r\n\r\n"), 400);
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\n\r\n"), 400);                             // no Host
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n"), 400);       // obs-fold
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost : a\r\n\r\n"), 400);                 // space before colon
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost: a\r\nNoColon\r\n\r\n"), 400);
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost: a\r\nX: a\x01b\r\n\r\n"), 400);     // control character
        constexpr char nul[] = "GET / HTTP/1.1\r\nHost: a\r\nX: a\0b\r\n\r\n";
        EXPECT_EQ(refusal(std::string(nul, sizeof nul - 1)), 400);   // NUL
        EXPECT_EQ(refusal("GET /\x7f HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        EXPECT_EQ(refusal("\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"), 400);              // leading blank line
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"), 501);
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"), 400);
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"), 400);
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1x\r\n\r\n"), 400);
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999999999999999\r\n\r\n"), 400);
        EXPECT_EQ(refusal("POST / HTTP/1.1\r\nHost: a\r\nExpect: something\r\n\r\n"), 400);
    }

    TEST(HttpParser, AgreeingDuplicateContentLengthIsAccepted) {
        RequestParser parser;
        EXPECT_EQ(run(parser, "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\nab"), Progress::complete);
    }

    TEST(HttpParser, EnforcesHeaderLimit) {
        http::Limits limits;
        limits.max_header_bytes = 256;
        std::string big = "GET / HTTP/1.1\r\nHost: a\r\nX: " + std::string(300, 'a') + "\r\n\r\n";
        EXPECT_EQ(refusal(big, limits), 431);
        // Without a terminator: refused as soon as the buffer passes the limit, not at the end.
        RequestParser parser(limits);
        EXPECT_EQ(parser.feed("GET / HTTP/1.1\r\nX: " + std::string(250, 'a')), Progress::failed);
        EXPECT_EQ(parser.error_status(), 431);
        // At the default limit: exactly 8 KiB passes, a byte more does not.
        std::string head = "GET / HTTP/1.1\r\nHost: a\r\nX: ";
        std::string fill(8192 - head.size() - 4, 'b');
        RequestParser exact;
        EXPECT_EQ(run(exact, head + fill + "\r\n\r\n"), Progress::complete);
        EXPECT_EQ(refusal(head + fill + "b\r\n\r\n"), 431);
    }

    TEST(HttpParser, EnforcesHeaderCountAndTargetLength) {
        http::Limits limits;
        limits.max_headers = 3;
        EXPECT_EQ(refusal("GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n", limits), 431);
        EXPECT_EQ(refusal("GET /" + std::string(3000, 'a') + " HTTP/1.1\r\nHost: a\r\n\r\n"), 431);
    }

    TEST(HttpParser, RefusesOversizedBodyBeforeReadingIt) {
        http::Limits limits;
        limits.max_body_bytes = 64 * 1024;
        RequestParser parser(limits);
        auto progress = parser.feed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 65537\r\n\r\n");
        EXPECT_EQ(progress, Progress::failed);
        EXPECT_EQ(parser.error_status(), 413);
        RequestParser fits(limits);
        EXPECT_EQ(fits.feed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 65536\r\n\r\n"), Progress::head_complete);
        EXPECT_EQ(fits.feed(std::string(65536, 'x')), Progress::complete);
    }

    TEST(HttpParser, WaitsForTheWholeBody) {
        RequestParser parser;
        EXPECT_EQ(parser.feed("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nab"), Progress::head_complete);
        EXPECT_EQ(parser.feed({}), Progress::need_more);
        EXPECT_EQ(parser.feed("cd"), Progress::complete);
        EXPECT_EQ(parser.request().body, "abcd");
    }

    TEST(HttpParser, ExpectContinue) {
        RequestParser parser;
        ASSERT_EQ(parser.feed("POST / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 1\r\n\r\n"), Progress::head_complete);
        EXPECT_TRUE(parser.head().expect_continue);
    }

    TEST(HttpParser, FuzzNeverCrashesNorAcceptsGarbage) {
        // Deterministic: the same seed every run, so a failure reproduces.
        std::mt19937 random(20261017);
        const std::string alphabet = "GETPOST /HTTP1.0\r\n:abc-\t\x01\x7f\x80\xff%?=";
        for (int round = 0; round < 3000; ++round) {
            std::string input;
            auto length = random() % 300;
            for (unsigned i = 0; i < length; ++i) input += alphabet[random() % alphabet.size()];
            http::Limits limits;
            limits.max_header_bytes = 1 + random() % 512;
            RequestParser parser(limits);
            // Split at random points, as a socket would deliver it.
            std::size_t at = 0;
            Progress progress = Progress::need_more;
            while (at < input.size() && progress != Progress::failed && progress != Progress::complete) {
                auto chunk = 1 + random() % 17;
                progress = parser.feed(std::string_view(input).substr(at, chunk));
                if (progress == Progress::head_complete) progress = parser.feed({});
                at += chunk;
            }
            if (progress == Progress::failed) {
                EXPECT_TRUE(parser.error_status() >= 400 && parser.error_status() < 600);
            }
            if (progress == Progress::complete) {
                // Whatever got through is a well-formed request line.
                EXPECT_FALSE(parser.head().method.empty());
                EXPECT_EQ(parser.head().path.front(), '/');
            }
        }
        // Mutations of a valid request: every result is either a complete request or a clean refusal.
        for (int round = 0; round < 3000; ++round) {
            std::string input = good;
            for (int edits = 1 + static_cast<int>(random() % 4); edits > 0; --edits)
                input[random() % input.size()] = static_cast<char>(random() % 256);
            RequestParser parser;
            auto progress = run(parser, input);
            EXPECT_TRUE(progress == Progress::complete || progress == Progress::failed || progress == Progress::need_more);
        }
    }

    TEST(HttpResponse, SerializesWithFixedHeaders) {
        auto response = http::Response::status_only(401, "unauthorized");
        response.headers.emplace_back("WWW-Authenticate", "Bearer");
        auto text = response.serialize();
        EXPECT_TRUE(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        EXPECT_NE(text.find("Connection: close\r\n"), std::string::npos);
        EXPECT_NE(text.find("Content-Length: 26\r\n"), std::string::npos);
        EXPECT_NE(text.find("WWW-Authenticate: Bearer\r\n"), std::string::npos);
        EXPECT_TRUE(text.ends_with("\r\n\r\n{\"status\":\"unauthorized\"}\n"));
        auto head = response.serialize(true);
        EXPECT_TRUE(head.ends_with("\r\n\r\n"));
        EXPECT_NE(head.find("Content-Length: 26\r\n"), std::string::npos);
    }

}  // namespace fph::daemon::test
