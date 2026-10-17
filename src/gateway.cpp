#include "gateway.hpp"

#include "config.hpp"
#include "guard.hpp"

#include <forti/engine/engine.hpp>

namespace fph {

    namespace {

        class EngineGateway final : public Gateway {
            forti::engine::Engine engine_;

        public:
            explicit EngineGateway(forti::engine::Options options) : engine_(std::move(options)) {}

            nlohmann::json read(const nlohmann::json& request) override {
                return forti::engine::Engine::envelope([&] { return engine_.read(request); });
            }
            nlohmann::json plan(const nlohmann::json& request) override {
                return forti::engine::Engine::envelope([&] { return engine_.plan(request); });
            }
            nlohmann::json apply(const nlohmann::json& request) override {
                return forti::engine::Engine::envelope([&] { return engine_.apply(request); });
            }
            nlohmann::json discover(const nlohmann::json& request) override {
                return forti::engine::Engine::envelope([&] { return engine_.discover(request); });
            }
        };

    }  // namespace

    std::unique_ptr<Gateway> engine_gateway(const Config& config) {
        forti::engine::Options options;
        options.actor = "forti-pihole";
        std::string prefix = config.prefix;
        // The guard sits under the engine, around the SDK's own libcurl transport, so it sees every
        // request the engine makes, including the ones plan and apply make on their own.
        options.transport = [prefix](const fortiapi::Config& sdk) -> std::shared_ptr<fortiapi::Transport> {
            return std::make_shared<GuardTransport>(std::make_shared<fortiapi::CurlTransport>(sdk), prefix);
        };
        return std::make_unique<EngineGateway>(std::move(options));
    }

}  // namespace fph
