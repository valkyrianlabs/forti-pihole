//
// The smallest HTTP/1.1 the receiver needs: one request per connection, Content-Length bodies only,
// every response `Connection: close`. The parser is incremental (bytes arrive as poll(2) delivers
// them) and strict: anything a FortiGate's webhook client would not send is refused rather than
// interpreted, because a lenient parser on a listening socket is attack surface.
//
// Refused outright: obs-fold, bare CR or LF, whitespace before a header colon, control characters in
// a value, Transfer-Encoding (501; no chunked bodies), conflicting Content-Length, a missing Host on
// HTTP/1.1, a header section over the limit (431) and a declared body over the limit (413, decided
// before a byte of the body is read).
//

#ifndef FORTI_PIHOLED_HTTP_HPP
#define FORTI_PIHOLED_HTTP_HPP

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fph::daemon::http {

    struct Limits {
        std::size_t max_header_bytes = 8 * 1024;   // request line + headers + the blank line
        std::size_t max_body_bytes = 64 * 1024;
        std::size_t max_headers = 64;
        std::size_t max_target_bytes = 2048;
    };

    struct Header {
        std::string name;   // lower-cased
        std::string value;  // surrounding whitespace removed
    };

    struct RequestHead {
        std::string method;    // "POST"
        std::string target;    // "/v1/fortigate/events?x=1"
        std::string path;      // the target without its query
        std::string version;   // "HTTP/1.1" or "HTTP/1.0"
        std::vector<Header> headers;
        std::optional<std::size_t> content_length;
        bool expect_continue = false;

        // The first header named `name` (lower-case), or null.
        [[nodiscard]] const std::string* header(std::string_view name) const;
    };

    struct Request {
        RequestHead head;
        std::string body;
    };

    struct Response {
        int status = 200;
        std::vector<std::pair<std::string, std::string>> headers;   // beyond the fixed set
        std::string body;                                           // JSON text

        // {"status": <short word>} bodies: they say nothing a scanner could use.
        static Response status_only(int status, std::string_view word);
        // The full message. `head_only` (a HEAD request) keeps Content-Length but drops the body.
        [[nodiscard]] std::string serialize(bool head_only = false) const;
    };

    std::string_view reason_phrase(int status);

    class RequestParser {
    public:
        enum class Progress {
            need_more,       // feed more bytes
            head_complete,   // the head parsed (returned once); head() is valid, the body may follow
            complete,        // head and body are in; request() is valid
            failed,          // error_status() says why; respond and close
        };

        explicit RequestParser(Limits limits = {}) : limits_(limits) {}

        // Appends bytes and advances. After head_complete, call again (with no bytes, if none are
        // new) to continue into the body.
        Progress feed(std::string_view bytes);

        [[nodiscard]] const RequestHead& head() const { return request_.head; }
        [[nodiscard]] const Request& request() const { return request_; }
        [[nodiscard]] int error_status() const { return error_status_; }
        [[nodiscard]] const std::string& error() const { return error_; }
        // Some bytes of a request have arrived (a timeout before any is a silent close).
        [[nodiscard]] bool started() const { return !buffer_.empty() || state_ != State::head; }

    private:
        enum class State { head, body, done, failed };

        Progress fail(int status, std::string message);
        Progress parse_head(std::string_view head);

        Limits limits_;
        State state_ = State::head;
        std::string buffer_;
        Request request_;
        int error_status_ = 0;
        std::string error_;
    };

}  // namespace fph::daemon::http

#endif  // FORTI_PIHOLED_HTTP_HPP
