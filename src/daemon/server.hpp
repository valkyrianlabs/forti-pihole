//
// The listener: POSIX sockets, non-blocking, driven by the daemon's single poll(2) loop (the server
// contributes its descriptors with collect() and handles their readiness with dispatch(), so signals,
// the run worker and HTTP share one thread and one wait).
//
// Each connection carries exactly one request. Its whole life, from accept to the last byte of the
// response, is bounded by `read_timeout_ms`: a client that trickles bytes (slowloris) is cut off at the
// deadline however steadily it sends. Past `max_connections` the listener is simply not polled, so
// further clients wait in the kernel's backlog instead of costing anything here.
//

#ifndef FORTI_PIHOLED_SERVER_HPP
#define FORTI_PIHOLED_SERVER_HPP

#include "http.hpp"
#include "net.hpp"

#include <cstdint>
#include <list>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <poll.h>

namespace fph::daemon {

    class ServerError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    struct Peer {
        IpAddress address;
        std::uint16_t port = 0;
    };

    // What the server asks at each stage. A returned Response ends the exchange (it is sent and the
    // connection closed); nullopt lets it continue.
    class Handler {
    public:
        virtual ~Handler() = default;
        // Right after accept, before a byte is read: source allowlist and rate limit.
        virtual std::optional<http::Response> on_connect(const Peer& peer, std::int64_t now_ms) = 0;
        // The head is in: route, method and authentication, before the body is read (and before
        // `100 Continue` is sent).
        virtual std::optional<http::Response> on_head(const http::RequestHead& head, const Peer& peer, std::int64_t now_ms) = 0;
        virtual http::Response on_request(const http::Request& request, const Peer& peer, std::int64_t now_ms) = 0;
        // The parser refused the request or it timed out (status 400/408/413/431/501/505).
        virtual void on_refused(const Peer& peer, int status, const std::string& reason, std::int64_t now_ms) = 0;
    };

    class Server {
    public:
        struct Options {
            http::Limits limits;
            int read_timeout_ms = 5000;
            int max_connections = 16;
        };

        Server(Handler& handler, Options options) : handler_(handler), options_(options) {}
        ~Server();
        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        // Binds and listens (SO_REUSEADDR; IPv6 sockets are v6-only so "::" never silently widens
        // to IPv4). Port 0 picks a free port (port() tells which). Throws ServerError.
        void listen(const std::string& address, std::uint16_t port);
        void close_all();   // listener and every connection
        [[nodiscard]] bool listening() const { return listen_fd_ >= 0; }
        [[nodiscard]] std::uint16_t port() const { return port_; }
        [[nodiscard]] std::size_t connections() const { return connections_.size(); }
        void set_options(const Options& options) { options_ = options; }

        // Appends this server's descriptors; returns where they start in `fds`.
        std::size_t collect(std::vector<pollfd>& fds);
        // Handles readiness for the descriptors collect() added at `offset`, and expired deadlines.
        void dispatch(const std::vector<pollfd>& fds, std::size_t offset, std::int64_t now_ms);
        // Milliseconds until the earliest connection deadline, -1 without connections.
        [[nodiscard]] int timeout_ms(std::int64_t now_ms) const;

    private:
        struct Connection {
            int fd = -1;
            Peer peer;
            std::int64_t deadline_ms = 0;
            http::RequestParser parser;
            enum class Phase { reading, writing, draining } phase = Phase::reading;
            std::string out;
            std::size_t sent = 0;
            bool head_only = false;
        };

        void accept_ready(std::int64_t now_ms);
        void on_readable(Connection& c, std::int64_t now_ms);
        void on_writable(Connection& c, std::int64_t now_ms);
        void respond(Connection& c, const http::Response& response, std::int64_t now_ms);
        void advance(Connection& c, http::RequestParser::Progress progress, std::int64_t now_ms);
        static void close(Connection& c);

        Handler& handler_;
        Options options_;
        int listen_fd_ = -1;
        std::uint16_t port_ = 0;
        std::list<Connection> connections_;
        std::vector<Connection*> polled_;   // the order collect() added them in
        bool listener_polled_ = false;
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_SERVER_HPP
