#include "cli.hpp"
#include "config.hpp"

#include <chrono>
#include <iostream>

#include <sys/resource.h>

int main(int argc, char** argv) {
    // Like forti and forti-mcp: a core dump could hold the API key the engine resolved.
    struct rlimit no_core{0, 0};
    ::setrlimit(RLIMIT_CORE, &no_core);

    fvm::Environment environment;
    environment.gateway = [](const fvm::Config& config) { return fvm::engine_gateway(config); };
    environment.clock = [] {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    };
    environment.out = &std::cout;
    environment.err = &std::cerr;
    return fvm::run(std::vector<std::string>(argv + 1, argv + argc), environment);
}
