//
// HTTP to the Pi-hole API. `Transport` is the seam: `CurlTransport` talks to a real Pi-hole, and
// tests script `FakeTransport` (fake_transport.hpp) or run the mock server (tests/mock-pihole).
//
// What CurlTransport guarantees, whatever the caller asks for:
//   - TLS peer and host verification are always on (an optional CA bundle adds a private CA, it
//     never turns verification off). Plain http:// is accepted for loopback addresses only, where
//     nothing crosses a network: the password and session ID are never sent in clear otherwise.
//   - Redirects are never followed: a 3xx reply comes back as is and the client reports it, so a
//     credential can never be replayed to another host.
//   - A reply body is bounded (max_response_bytes); a larger one fails the request.
//   - Errors name the method and path, never a header or body (that is where the secrets are).
//

#ifndef FORTI_PIHOLE_PIHOLE_TRANSPORT_HPP
#define FORTI_PIHOLE_PIHOLE_TRANSPORT_HPP

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fph::pihole {

    // The Pi-hole web server, e.g. "https://pi.hole" or "https://pihole.example.net:8443". A path
    // prefix is kept (a reverse proxy may serve Pi-hole below one); a trailing "/" or "/api" is
    // dropped, since every request path starts with "/api/".
    struct Endpoint {
        std::string url;
        std::optional<std::string> ca_bundle;   // PEM file of extra trusted CAs; verification stays on
        long timeout_ms = 15000;                // whole request; connecting gets at most 10 s of it
    };

    // A validated Endpoint: the base URL to which request paths are appended. Throws Error (with the
    // reason) for anything else: other schemes, http:// to a non-loopback host, user:password@ in
    // the URL, a query or fragment, a timeout that is not positive.
    [[nodiscard]] std::string validated_base_url(const Endpoint& endpoint);

    enum class Method { get, post, put, del };

    [[nodiscard]] std::string_view to_string(Method method);

    struct Request {
        Method method = Method::get;
        std::string path;                                          // "/api/clients/..." (already encoded)
        std::vector<std::pair<std::string, std::string>> headers;  // name, value
        std::string body;                                          // JSON, or empty
    };

    struct Response {
        long status = 0;
        std::string body;
        std::string content_type;   // "" when none
    };

    class Transport {
    public:
        virtual ~Transport() = default;
        // Throws TransportError when no HTTP reply arrived; any HTTP status is a Response.
        virtual Response perform(const Request& request) = 0;
    };

    inline constexpr std::size_t max_response_bytes = 8u * 1024u * 1024u;

    // libcurl. One easy handle, reused (keep-alive, TLS session cache) and serialized by a mutex. A
    // write (POST, PUT, DELETE) gets a fresh connection that is closed after it and speaks HTTP/1.1:
    // libcurl re-sends a request by itself only on a reused connection or an HTTP/2 stream retry,
    // and a write must never reach Pi-hole twice (forti-api's CurlTransport makes the same choice).
    class CurlTransport final : public Transport {
        struct Handle;
        std::string base_;
        std::optional<std::string> ca_bundle_;
        long timeout_ms_;
        std::unique_ptr<Handle> handle_;
        std::mutex mutex_;

    public:
        explicit CurlTransport(const Endpoint& endpoint);
        ~CurlTransport() override;
        CurlTransport(const CurlTransport&) = delete;
        CurlTransport& operator=(const CurlTransport&) = delete;

        Response perform(const Request& request) override;
    };

    // Percent-encodes one path segment (a client string like "10.0.0.0/24" or "aa:bb:...", a group
    // name): everything but RFC 3986 unreserved characters. FTL takes the item as the URL-decoded
    // rest of the path after "/api/clients/" (http-common.c startsWith(), on civetweb's decoded
    // local_uri_raw), so an encoded "/" in a CIDR survives a reverse proxy that decodes it, too.
    [[nodiscard]] std::string encode_segment(std::string_view segment);

}  // namespace fph::pihole

#endif  // FORTI_PIHOLE_PIHOLE_TRANSPORT_HPP
