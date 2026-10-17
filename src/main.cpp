#include "cli.hpp"
#include "config.hpp"
#include "guard.hpp"
#include "pihole_link.hpp"

#include <forti/engine/profile.hpp>

#include <chrono>
#include <iostream>
#include <thread>

#include <sys/resource.h>

int main(int argc, char** argv) {
    // Like forti and forti-mcp: a core dump could hold the API key the engine resolved.
    struct rlimit no_core{0, 0};
    ::setrlimit(RLIMIT_CORE, &no_core);

    fph::Environment environment;
    environment.gateway = [](const fph::Config& config, std::shared_ptr<fph::WritePermits> permits) {
        return fph::engine_gateway(config, std::move(permits));
    };
    environment.pihole = [](const fph::Config& config) {
        auto store = forti::engine::default_secret_store(forti::engine::Paths::from_env());
        return fph::pihole_connect(config, *store);
    };
    environment.pihole_with_password = [](const fph::PiholeConfig& pihole, const std::string& password) {
        return fph::pihole_connect(pihole, password);
    };
    environment.sleep = [](int seconds) { std::this_thread::sleep_for(std::chrono::seconds(seconds)); };
    environment.in = &std::cin;
    environment.clock = [] {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    };
    environment.out = &std::cout;
    environment.err = &std::cerr;
    return fph::run(std::vector<std::string>(argv + 1, argv + argc), environment);
}
