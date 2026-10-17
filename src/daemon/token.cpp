#include "token.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>

#include <unistd.h>
#if defined(__APPLE__)
#include <sys/random.h>
#endif

namespace fph::daemon {

    bool constant_time_equal(std::string_view a, std::string_view b) {
        // Branches depend only on the lengths; the bytes are folded in with XOR/OR. volatile keeps the
        // compiler from turning the loop back into an early-exit memcmp.
        volatile unsigned char diff = a.size() == b.size() ? 0 : 1;
        std::size_t n = std::max(a.size(), b.size());
        for (std::size_t i = 0; i < n; ++i) {
            auto x = static_cast<unsigned char>(i < a.size() ? a[i] : 0);
            auto y = static_cast<unsigned char>(i < b.size() ? b[i] : 0);
            diff = static_cast<unsigned char>(diff | (x ^ y));
        }
        return diff == 0;
    }

    std::optional<std::string_view> bearer_token(std::string_view authorization) {
        constexpr std::string_view scheme = "bearer";
        if (authorization.size() <= scheme.size() + 1) return std::nullopt;
        for (std::size_t i = 0; i < scheme.size(); ++i) {
            char c = authorization[i];
            if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c) != scheme[i]) return std::nullopt;
        }
        auto rest = authorization.substr(scheme.size());
        if (rest.front() != ' ') return std::nullopt;
        while (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
        if (rest.empty() || rest.find_first_of(" \t") != std::string_view::npos) return std::nullopt;
        return rest;
    }

    std::string generate_token() {
        std::array<std::uint8_t, 32> bytes{};
        // getentropy: at most 256 bytes per call, never blocks once the pool is seeded, no fd needed.
        if (::getentropy(bytes.data(), bytes.size()) != 0) throw TokenError("cannot read random bytes from the OS");
        std::string out;
        out.reserve(64);
        for (auto b: bytes) out += std::format("{:02x}", b);
        return out;
    }

    bool valid_token(std::string_view token) {
        if (token.size() < 32 || token.size() > 512) return false;
        return std::ranges::all_of(token, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   std::string_view("-._~+/=").find(c) != std::string_view::npos;
        });
    }

    std::string token_account(std::string_view profile) { return std::format("pihole/{}/webhook-token", profile); }

    std::optional<std::string> load_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding) {
        auto stored = store.get(account);
        if (!stored) return std::nullopt;
        // Same rule as the engine's API keys: a token is released only to a profile that still points
        // at the device it was made for.
        if (stored->binding != binding)
            throw TokenError(std::format("the secret {} belongs to another device; rotate it for this profile", account));
        if (!valid_token(stored->secret)) throw TokenError(std::format("the secret {} is not a valid webhook token", account));
        return std::move(stored->secret);
    }

    std::string ensure_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding) {
        if (auto existing = load_token(store, account, binding)) return *existing;
        return rotate_token(store, account, binding);
    }

    std::string rotate_token(forti::engine::SecretStore& store, std::string_view account, std::string_view binding) {
        auto token = generate_token();
        store.put(account, token, binding);
        return token;
    }

}  // namespace fph::daemon
