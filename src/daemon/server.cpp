#include "server.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <format>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace fph::daemon {

    namespace {

#if defined(MSG_NOSIGNAL)
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;   // Apple: SO_NOSIGPIPE on the socket instead
#endif

        // After the response, how long a client may take to close its side before the socket is
        // closed anyway (reading what it still sends keeps the kernel from answering with an RST that
        // could destroy the response in flight).
        constexpr std::int64_t drain_ms = 1000;

        bool set_nonblocking_cloexec(int fd) {
            int flags = ::fcntl(fd, F_GETFL);
            if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;
            int fdflags = ::fcntl(fd, F_GETFD);
            return fdflags >= 0 && ::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) >= 0;
        }

        std::string_view status_word(int status) {
            switch (status) {
                case 400: return "bad-request";
                case 408: return "timeout";
                case 413: return "too-large";
                case 431: return "headers-too-large";
                case 501: return "not-implemented";
                case 505: return "version-not-supported";
                default: return "error";
            }
        }

    }  // namespace

    Server::~Server() { close_all(); }

    void Server::listen(const std::string& address, std::uint16_t port) {
        auto ip = IpAddress::parse(address);
        if (!ip) throw ServerError(std::format("cannot listen on {}: not an IP address", address));
        int fd = ::socket(ip->v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        if (fd < 0) throw ServerError(std::format("socket: {}", std::strerror(errno)));
        auto fail = [&](std::string_view what) {
            auto message = std::format("cannot listen on {}:{}: {}: {}", address, port, what, std::strerror(errno));
            ::close(fd);
            throw ServerError(message);
        };
        if (!set_nonblocking_cloexec(fd)) fail("fcntl");
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        sockaddr_storage storage{};
        socklen_t length = 0;
        if (ip->v6) {
            ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
            sockaddr_in6 in6{};
            in6.sin6_family = AF_INET6;
            in6.sin6_port = htons(port);
            std::memcpy(&in6.sin6_addr, ip->bytes.data(), 16);
            std::memcpy(&storage, &in6, sizeof in6);
            length = sizeof in6;
        } else {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(port);
            std::memcpy(&in.sin_addr, ip->bytes.data(), 4);
            std::memcpy(&storage, &in, sizeof in);
            length = sizeof in;
        }
        if (::bind(fd, reinterpret_cast<sockaddr*>(&storage), length) != 0) fail("bind");
        if (::listen(fd, 64) != 0) fail("listen");
        sockaddr_storage bound{};
        socklen_t bound_length = sizeof bound;
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) fail("getsockname");
        std::uint16_t net_port = 0;
        if (bound.ss_family == AF_INET6) {
            sockaddr_in6 in6{};
            std::memcpy(&in6, &bound, sizeof in6);
            net_port = in6.sin6_port;
        } else {
            sockaddr_in in{};
            std::memcpy(&in, &bound, sizeof in);
            net_port = in.sin_port;
        }
        if (listen_fd_ >= 0) ::close(listen_fd_);
        listen_fd_ = fd;
        port_ = ntohs(net_port);
    }

    void Server::close_all() {
        if (listen_fd_ >= 0) ::close(listen_fd_);
        listen_fd_ = -1;
        for (auto& c: connections_) close(c);
        connections_.clear();
        polled_.clear();
    }

    void Server::close(Connection& c) {
        if (c.fd >= 0) ::close(c.fd);
        c.fd = -1;
    }

    std::size_t Server::collect(std::vector<pollfd>& fds) {
        std::size_t offset = fds.size();
        listener_polled_ = listen_fd_ >= 0 && connections_.size() < static_cast<std::size_t>(std::max(1, options_.max_connections));
        if (listener_polled_) fds.push_back({listen_fd_, POLLIN, 0});
        polled_.clear();
        for (auto& c: connections_) {
            short events = 0;
            switch (c.phase) {
                case Connection::Phase::reading: events = static_cast<short>(POLLIN | (c.sent < c.out.size() ? POLLOUT : 0)); break;
                case Connection::Phase::writing: events = POLLOUT; break;
                case Connection::Phase::draining: events = POLLIN; break;
            }
            fds.push_back({c.fd, events, 0});
            polled_.push_back(&c);
        }
        return offset;
    }

    int Server::timeout_ms(std::int64_t now_ms) const {
        if (connections_.empty()) return -1;
        std::int64_t earliest = connections_.front().deadline_ms;
        for (const auto& c: connections_) earliest = std::min(earliest, c.deadline_ms);
        return static_cast<int>(std::clamp<std::int64_t>(earliest - now_ms, 0, 60'000));
    }

    void Server::dispatch(const std::vector<pollfd>& fds, std::size_t offset, std::int64_t now_ms) {
        std::size_t index = offset;
        bool accept_now = false;
        if (listener_polled_ && index < fds.size()) {
            accept_now = (fds[index].revents & POLLIN) != 0;
            ++index;
        }
        for (auto* c: polled_) {
            if (index >= fds.size()) break;
            auto revents = fds[index++].revents;
            if (c->fd < 0 || revents == 0) continue;
            if (revents & (POLLIN | POLLHUP | POLLERR)) on_readable(*c, now_ms);
            if (c->fd >= 0 && (revents & POLLOUT)) on_writable(*c, now_ms);
        }
        polled_.clear();

        for (auto& c: connections_) {
            if (c.fd < 0 || now_ms < c.deadline_ms) continue;
            if (c.phase == Connection::Phase::reading && c.parser.started()) {
                // One best-effort 408 within a short grace, then the connection goes regardless.
                handler_.on_refused(c.peer, 408, "request not complete within the read timeout", now_ms);
                respond(c, http::Response::status_only(408, "timeout"), now_ms);
                c.deadline_ms = now_ms + drain_ms;
                if (c.fd >= 0 && c.phase == Connection::Phase::writing) continue;
            }
            if (c.fd >= 0 && now_ms >= c.deadline_ms) close(c);
        }
        if (accept_now) accept_ready(now_ms);
        std::erase_if(connections_, [](const Connection& c) { return c.fd < 0; });
    }

    void Server::accept_ready(std::int64_t now_ms) {
        while (listen_fd_ >= 0 && connections_.size() < static_cast<std::size_t>(std::max(1, options_.max_connections))) {
            sockaddr_storage storage{};
            socklen_t length = sizeof storage;
            int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&storage), &length);
            if (fd < 0) {
                if (errno == EINTR) continue;
                return;   // EAGAIN, or a transient error (ECONNABORTED, EMFILE): try at the next readiness
            }
            if (!set_nonblocking_cloexec(fd)) {
                ::close(fd);
                continue;
            }
#if defined(SO_NOSIGPIPE)
            int one = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            auto address = IpAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&storage));
            if (!address) {
                ::close(fd);
                continue;
            }
            std::uint16_t port = 0;
            if (storage.ss_family == AF_INET6) {
                sockaddr_in6 in6{};
                std::memcpy(&in6, &storage, sizeof in6);
                port = ntohs(in6.sin6_port);
            } else {
                sockaddr_in in{};
                std::memcpy(&in, &storage, sizeof in);
                port = ntohs(in.sin_port);
            }
            auto& c = connections_.emplace_back();
            c.fd = fd;
            c.peer = {*address, port};
            c.deadline_ms = now_ms + options_.read_timeout_ms;
            c.parser = http::RequestParser(options_.limits);
            if (auto rejection = handler_.on_connect(c.peer, now_ms)) respond(c, *rejection, now_ms);
        }
    }

    void Server::on_readable(Connection& c, std::int64_t now_ms) {
        char buffer[4096];
        for (;;) {
            auto n = ::recv(c.fd, buffer, sizeof buffer, 0);
            if (n > 0) {
                if (c.phase != Connection::Phase::reading) continue;   // draining: discard
                advance(c, c.parser.feed(std::string_view(buffer, static_cast<std::size_t>(n))), now_ms);
                if (c.fd < 0) return;
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            // EOF or error. While reading, the client gave up; while draining, it is done.
            if (c.phase != Connection::Phase::writing) close(c);
            return;
        }
    }

    void Server::advance(Connection& c, http::RequestParser::Progress progress, std::int64_t now_ms) {
        using Progress = http::RequestParser::Progress;
        switch (progress) {
            case Progress::need_more: return;
            case Progress::failed:
                handler_.on_refused(c.peer, c.parser.error_status(), c.parser.error(), now_ms);
                respond(c, http::Response::status_only(c.parser.error_status(), status_word(c.parser.error_status())), now_ms);
                return;
            case Progress::head_complete: {
                c.head_only = c.parser.head().method == "HEAD";
                if (auto rejection = handler_.on_head(c.parser.head(), c.peer, now_ms)) {
                    respond(c, *rejection, now_ms);
                    return;
                }
                if (c.parser.head().expect_continue && c.parser.head().content_length.value_or(0) > 0) {
                    c.out += "HTTP/1.1 100 Continue\r\n\r\n";
                    on_writable(c, now_ms);
                    if (c.fd < 0) return;
                }
                advance(c, c.parser.feed({}), now_ms);
                return;
            }
            case Progress::complete:
                respond(c, handler_.on_request(c.parser.request(), c.peer, now_ms), now_ms);
                return;
        }
    }

    void Server::respond(Connection& c, const http::Response& response, std::int64_t now_ms) {
        if (c.fd < 0 || c.phase != Connection::Phase::reading) return;
        c.out += response.serialize(c.head_only);
        c.phase = Connection::Phase::writing;
        on_writable(c, now_ms);
    }

    void Server::on_writable(Connection& c, std::int64_t now_ms) {
        while (c.sent < c.out.size()) {
            auto n = ::send(c.fd, c.out.data() + c.sent, c.out.size() - c.sent, send_flags);
            if (n > 0) {
                c.sent += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            close(c);
            return;
        }
        if (c.phase == Connection::Phase::writing) {
            ::shutdown(c.fd, SHUT_WR);
            c.phase = Connection::Phase::draining;
            c.deadline_ms = std::min(c.deadline_ms, now_ms + drain_ms);
        }
    }

}  // namespace fph::daemon
