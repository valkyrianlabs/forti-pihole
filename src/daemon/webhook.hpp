//
// The receiver's two endpoints, as a Handler the Server drives:
//
//   POST /v1/fortigate/events   Authorization: Bearer <token>; source on the allowlist. 202 for any
//                               accepted event (suppressed or not: the caller learns nothing about
//                               the daemon's state).
//   GET|HEAD /v1/health         liveness only ({"status":"ok"}), no authentication; allowed from the
//                               allowlist and from loopback (local monitoring).
//
// Checks in order, each before anything later is read: source allowlist (403) and per-source rate
// limit (429 + Retry-After) at accept; then path (404), method (405 + Allow), source for the events
// endpoint (403), token configured (503), Authorization (401 + WWW-Authenticate), Content-Length (411);
// the parser enforces the size limits (413/431) on its own. Nothing about a refused request is echoed
// back.
//

#ifndef FORTI_PIHOLED_WEBHOOK_HPP
#define FORTI_PIHOLED_WEBHOOK_HPP

#include "events.hpp"
#include "log.hpp"
#include "net.hpp"
#include "rate_limit.hpp"
#include "server.hpp"

#include <functional>
#include <map>
#include <optional>
#include <string>

namespace fph::daemon {

    inline constexpr std::string_view events_path = "/v1/fortigate/events";
    inline constexpr std::string_view health_path = "/v1/health";

    class WebhookApp : public Handler {
    public:
        // Called for every authenticated, well-formed event.
        using Sink = std::function<void(const ConfigEvent& event, const Peer& peer, std::int64_t now_ms)>;

        WebhookApp(Allowlist allowlist, std::optional<std::string> token, RateLimiter& limiter, const Logger& log, Sink sink)
                : allowlist_(std::move(allowlist)), token_(std::move(token)), limiter_(limiter), log_(log), sink_(std::move(sink)) {}

        void set_allowlist(Allowlist allowlist) { allowlist_ = std::move(allowlist); }
        // nullopt: no token is configured; the events endpoint answers 503.
        void set_token(std::optional<std::string> token) { token_ = std::move(token); }

        std::optional<http::Response> on_connect(const Peer& peer, std::int64_t now_ms) override;
        std::optional<http::Response> on_head(const http::RequestHead& head, const Peer& peer, std::int64_t now_ms) override;
        http::Response on_request(const http::Request& request, const Peer& peer, std::int64_t now_ms) override;
        void on_refused(const Peer& peer, int status, const std::string& reason, std::int64_t now_ms) override;

    private:
        // Logs a refusal, at most once per source and status every 60 s: a flood must not become a
        // log flood.
        void refuse_log(const Peer& peer, int status, std::string_view reason, std::int64_t now_ms);

        Allowlist allowlist_;
        std::optional<std::string> token_;
        RateLimiter& limiter_;
        const Logger& log_;
        Sink sink_;
        std::map<std::pair<std::string, int>, std::int64_t> last_logged_;
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_WEBHOOK_HPP
