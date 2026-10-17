#include "webhook.hpp"

#include "token.hpp"

#include <format>

namespace fph::daemon {

    using http::Response;

    namespace {

        Response with_header(Response response, std::string name, std::string value) {
            response.headers.emplace_back(std::move(name), std::move(value));
            return response;
        }

    }  // namespace

    void WebhookApp::refuse_log(const Peer& peer, int status, std::string_view reason, std::int64_t now_ms) {
        auto key = std::make_pair(peer.address.to_string(), status);
        auto it = last_logged_.find(key);
        if (it != last_logged_.end() && now_ms - it->second < 60'000) return;
        if (last_logged_.size() > 1024) last_logged_.clear();
        last_logged_[key] = now_ms;
        log_.warn("http.refused", {{"source", key.first}, {"status", std::to_string(status)}, {"reason", std::string(reason)}});
    }

    std::optional<Response> WebhookApp::on_connect(const Peer& peer, std::int64_t now_ms) {
        // Loopback may reach the health check; the events endpoint re-checks the allowlist itself.
        if (!allowlist_.allows(peer.address) && !peer.address.loopback()) {
            refuse_log(peer, 403, "source not allowed", now_ms);
            return Response::status_only(403, "forbidden");
        }
        auto source = peer.address.to_string();
        if (!limiter_.allow(source, now_ms)) {
            refuse_log(peer, 429, "rate limited", now_ms);
            return with_header(Response::status_only(429, "rate-limited"), "Retry-After",
                               std::to_string(std::max<std::int64_t>(1, limiter_.retry_after_s(source, now_ms))));
        }
        return std::nullopt;
    }

    std::optional<Response> WebhookApp::on_head(const http::RequestHead& head, const Peer& peer, std::int64_t now_ms) {
        if (head.path == health_path) {
            if (head.method != "GET" && head.method != "HEAD")
                return with_header(Response::status_only(405, "method-not-allowed"), "Allow", "GET, HEAD");
            return std::nullopt;
        }
        if (head.path != events_path) return Response::status_only(404, "not-found");
        if (head.method != "POST") return with_header(Response::status_only(405, "method-not-allowed"), "Allow", "POST");
        if (!allowlist_.allows(peer.address)) {
            refuse_log(peer, 403, "source not allowed for events", now_ms);
            return Response::status_only(403, "forbidden");
        }
        if (!token_) {
            refuse_log(peer, 503, "no webhook token configured", now_ms);
            return Response::status_only(503, "unavailable");
        }
        const std::string* authorization = head.header("authorization");
        auto presented = authorization ? bearer_token(*authorization) : std::nullopt;
        if (!presented || !constant_time_equal(*presented, *token_)) {
            refuse_log(peer, 401, authorization ? "wrong token" : "missing token", now_ms);
            return with_header(Response::status_only(401, "unauthorized"), "WWW-Authenticate", "Bearer realm=\"forti-piholed\"");
        }
        if (!head.content_length) return Response::status_only(411, "length-required");
        return std::nullopt;
    }

    Response WebhookApp::on_request(const http::Request& request, const Peer& peer, std::int64_t now_ms) {
        if (request.head.path == health_path) return Response::status_only(200, "ok");
        auto event = parse_event(request.body);
        if (sink_) sink_(event, peer, now_ms);
        return Response::status_only(202, "accepted");
    }

    void WebhookApp::on_refused(const Peer& peer, int status, const std::string& reason, std::int64_t now_ms) {
        refuse_log(peer, status, reason, now_ms);
    }

}  // namespace fph::daemon
