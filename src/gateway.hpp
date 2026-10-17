//
// The one door to the FortiGate. Production uses EngineGateway (forti-engine: profiles, read
// redaction, plan/apply with digests, verification, audit and rollback plans). Tests use an
// in-memory FortiGate. Requests and results are the engine's JSON contract unchanged
// (architecture.md, "Engine contract"), so nothing here re-implements engine semantics.
//

#ifndef FORTI_PIHOLE_GATEWAY_HPP
#define FORTI_PIHOLE_GATEWAY_HPP

#include <nlohmann/json.hpp>

#include <memory>
#include <string>

namespace forti::engine {
    class Engine;
}

namespace fph {

    struct Config;

    class Gateway {
    public:
        virtual ~Gateway() = default;
        // Engine envelopes: {"ok": true, "data", "meta"} or {"ok": false, "error"}.
        virtual nlohmann::json read(const nlohmann::json& request) = 0;
        virtual nlohmann::json plan(const nlohmann::json& request) = 0;
        virtual nlohmann::json apply(const nlohmann::json& request) = 0;
        virtual nlohmann::json discover(const nlohmann::json& request) = 0;
    };

    // Raised when a read the companion depends on fails: the envelope's error, verbatim.
    class GatewayError : public std::runtime_error {
        nlohmann::json error_;

    public:
        explicit GatewayError(nlohmann::json error)
                : std::runtime_error(error.value("message", std::string("FortiGate request failed"))), error_(std::move(error)) {}
        [[nodiscard]] const nlohmann::json& error() const { return error_; }
        [[nodiscard]] std::string code() const { return error_.value("code", std::string("internal")); }
    };

    // Every page of a listing (the engine caps a page at 1000 items).
    nlohmann::json read_all(Gateway& gateway, nlohmann::json request);

    // A forti-engine on the user's forti home, with the write guard (guard.hpp) wrapped around the
    // SDK transport so nothing outside the managed objects can be written even by a bug here.
    struct WritePermits;
    std::unique_ptr<Gateway> engine_gateway(const Config& config, std::shared_ptr<WritePermits> permits = nullptr);

}  // namespace fph

#endif  // FORTI_PIHOLE_GATEWAY_HPP
