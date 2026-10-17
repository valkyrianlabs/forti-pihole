#include "http.hpp"

#include <algorithm>
#include <charconv>
#include <format>

namespace fph::daemon::http {

    namespace {

        // RFC 9110 tchar.
        bool token_char(unsigned char c) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return true;
            return std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(c)) != std::string_view::npos;
        }

        // Field values: visible ASCII, space, tab and obs-text; never CTLs (a NUL or ESC in a header is
        // never legitimate and could reach a log).
        bool value_char(unsigned char c) { return c == '\t' || (c >= 0x20 && c != 0x7f); }

        std::string lower(std::string_view text) {
            std::string out(text);
            for (auto& c: out) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            return out;
        }

        std::string_view trim(std::string_view text) {
            while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
            while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
            return text;
        }

    }  // namespace

    const std::string* RequestHead::header(std::string_view name) const {
        for (const auto& h: headers)
            if (h.name == name) return &h.value;
        return nullptr;
    }

    std::string_view reason_phrase(int status) {
        switch (status) {
            case 100: return "Continue";
            case 200: return "OK";
            case 202: return "Accepted";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 408: return "Request Timeout";
            case 411: return "Length Required";
            case 413: return "Content Too Large";
            case 415: return "Unsupported Media Type";
            case 429: return "Too Many Requests";
            case 431: return "Request Header Fields Too Large";
            case 500: return "Internal Server Error";
            case 501: return "Not Implemented";
            case 503: return "Service Unavailable";
            case 505: return "HTTP Version Not Supported";
            default: return "Unknown";
        }
    }

    Response Response::status_only(int status, std::string_view word) {
        Response response;
        response.status = status;
        response.body = std::format("{{\"status\":\"{}\"}}\n", word);
        return response;
    }

    std::string Response::serialize(bool head_only) const {
        std::string out = std::format("HTTP/1.1 {} {}\r\n", status, reason_phrase(status));
        out += "Content-Type: application/json\r\n";
        out += std::format("Content-Length: {}\r\n", body.size());
        // One request per connection: nothing to keep alive, and nothing a proxy should cache.
        out += "Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n";
        for (const auto& [name, value]: headers) out += std::format("{}: {}\r\n", name, value);
        out += "\r\n";
        if (!head_only) out += body;
        return out;
    }

    RequestParser::Progress RequestParser::fail(int status, std::string message) {
        state_ = State::failed;
        error_status_ = status;
        error_ = std::move(message);
        buffer_.clear();
        return Progress::failed;
    }

    RequestParser::Progress RequestParser::feed(std::string_view bytes) {
        if (state_ == State::failed) return Progress::failed;
        if (state_ == State::done) return Progress::complete;   // one request per connection: extra bytes ignored
        buffer_.append(bytes);

        if (state_ == State::head) {
            auto end = buffer_.find("\r\n\r\n");
            if (end == std::string::npos) {
                if (buffer_.size() > limits_.max_header_bytes) return fail(431, "header section too large");
                // A bare LF anywhere means the client does not speak CRLF HTTP; refuse early instead of
                // waiting for a terminator that never comes.
                for (std::size_t i = 0; i < buffer_.size(); ++i)
                    if (buffer_[i] == '\n' && (i == 0 || buffer_[i - 1] != '\r')) return fail(400, "bare LF in header section");
                return Progress::need_more;
            }
            if (end + 4 > limits_.max_header_bytes) return fail(431, "header section too large");
            auto result = parse_head(std::string_view(buffer_).substr(0, end + 2));
            if (result == Progress::failed) return result;
            buffer_.erase(0, end + 4);
            state_ = State::body;
            return Progress::head_complete;
        }

        // State::body
        std::size_t want = request_.head.content_length.value_or(0);
        if (buffer_.size() < want) return Progress::need_more;
        request_.body = buffer_.substr(0, want);
        buffer_.clear();
        state_ = State::done;
        return Progress::complete;
    }

    // `head` is the request line and header lines, each ending in CRLF (the blank line excluded).
    RequestParser::Progress RequestParser::parse_head(std::string_view head) {
        auto& h = request_.head;
        std::vector<std::string_view> lines;
        for (std::size_t start = 0; start < head.size();) {
            auto crlf = head.find("\r\n", start);
            auto line = head.substr(start, crlf - start);
            if (line.find_first_of("\r\n") != std::string_view::npos) return fail(400, "bare CR or LF");
            lines.push_back(line);
            start = crlf + 2;
        }
        if (lines.empty() || lines[0].empty()) return fail(400, "empty request line");

        // request-line = method SP request-target SP HTTP-version, single spaces only.
        auto line = lines[0];
        auto sp1 = line.find(' ');
        auto sp2 = sp1 == std::string_view::npos ? sp1 : line.find(' ', sp1 + 1);
        if (sp1 == std::string_view::npos || sp2 == std::string_view::npos || line.find(' ', sp2 + 1) != std::string_view::npos)
            return fail(400, "malformed request line");
        auto method = line.substr(0, sp1);
        auto target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        auto version = line.substr(sp2 + 1);
        if (method.empty() || method.size() > 16 || !std::ranges::all_of(method, [](char c) { return c >= 'A' && c <= 'Z'; }))
            return fail(400, "malformed method");
        if (target.empty() || target.front() != '/') return fail(400, "only origin-form targets are accepted");
        if (target.size() > limits_.max_target_bytes) return fail(431, "request target too long");
        if (!std::ranges::all_of(target, [](char c) { return c > 0x20 && c < 0x7f; })) return fail(400, "malformed target");
        if (version != "HTTP/1.1" && version != "HTTP/1.0") {
            if (version.starts_with("HTTP/")) return fail(505, "unsupported HTTP version");
            return fail(400, "malformed HTTP version");
        }
        h.method = method;
        h.target = target;
        h.path = target.substr(0, target.find('?'));
        h.version = version;

        for (std::size_t i = 1; i < lines.size(); ++i) {
            auto field = lines[i];
            if (field.empty()) return fail(400, "empty header line");
            if (field.front() == ' ' || field.front() == '\t') return fail(400, "obsolete line folding");
            auto colon = field.find(':');
            if (colon == std::string_view::npos || colon == 0) return fail(400, "malformed header line");
            auto name = field.substr(0, colon);
            if (!std::ranges::all_of(name, [](char c) { return token_char(static_cast<unsigned char>(c)); }))
                return fail(400, "malformed header name");
            auto value = field.substr(colon + 1);
            if (!std::ranges::all_of(value, [](char c) { return value_char(static_cast<unsigned char>(c)); }))
                return fail(400, "control character in header value");
            if (h.headers.size() >= limits_.max_headers) return fail(431, "too many headers");
            h.headers.push_back({lower(name), std::string(trim(value))});
        }

        if (h.version == "HTTP/1.1" && !h.header("host")) return fail(400, "missing Host");
        if (h.header("transfer-encoding")) return fail(501, "Transfer-Encoding is not supported");
        for (const auto& header: h.headers) {
            if (header.name != "content-length") continue;
            const auto& text = header.value;
            std::size_t length = 0;
            auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), length);
            if (text.empty() || text.size() > 18 || error != std::errc() || end != text.data() + text.size())
                return fail(400, "malformed Content-Length");
            if (h.content_length && *h.content_length != length) return fail(400, "conflicting Content-Length");
            h.content_length = length;
        }
        if (h.content_length && *h.content_length > limits_.max_body_bytes) return fail(413, "body too large");
        if (const auto* expect = h.header("expect")) {
            if (lower(*expect) != "100-continue") return fail(400, "unsupported Expect");
            h.expect_continue = h.version == "HTTP/1.1";
        }
        return Progress::head_complete;
    }

}  // namespace fph::daemon::http
