#include "daemon_config.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <regex>
#include <sstream>

namespace fph::daemon {

    using json = nlohmann::json;

    namespace {

        void allow_keys(const json& object, std::initializer_list<std::string_view> keys, std::string_view where) {
            if (!object.is_object()) throw DaemonConfigError(std::format("{}: must be an object", where));
            for (auto it = object.begin(); it != object.end(); ++it)
                if (std::ranges::find(keys, std::string_view(it.key())) == keys.end())
                    throw DaemonConfigError(std::format("{}: unknown key \"{}\"", where, it.key()));
        }

        const json* section(const json& root, const char* key, std::string_view where,
                            std::initializer_list<std::string_view> keys) {
            auto it = root.find(key);
            if (it == root.end() || it->is_null()) return nullptr;
            auto name = std::format("{}.{}", where, key);
            allow_keys(*it, keys, name);
            return &*it;
        }

        std::string text(const json* object, const char* key, std::string_view where, std::string fallback) {
            if (!object) return fallback;
            auto it = object->find(key);
            if (it == object->end() || it->is_null()) return fallback;
            if (!it->is_string()) throw DaemonConfigError(std::format("{}.{}: must be a string", where, key));
            return it->get<std::string>();
        }

        template<typename T>
        T integer(const json* object, const char* key, std::string_view where, T fallback, long long lo, long long hi) {
            if (!object) return fallback;
            auto it = object->find(key);
            if (it == object->end() || it->is_null()) return fallback;
            if (!it->is_number_integer()) throw DaemonConfigError(std::format("{}.{}: must be an integer", where, key));
            auto value = it->get<long long>();
            if (value < lo || value > hi) throw DaemonConfigError(std::format("{}.{}: must be {}..{}", where, key, lo, hi));
            return static_cast<T>(value);
        }

    }  // namespace

    DaemonConfig DaemonConfig::from_json(const json& root) {
        allow_keys(root, {"profile", "listen", "allow_sources", "limits", "rate_limit", "schedule", "event_log", "token_account", "$comment"},
                   "daemon");
        DaemonConfig c;
        c.profile = text(&root, "profile", "daemon", c.profile);
        if (!c.profile.empty()) {
            static const std::regex pattern("^[A-Za-z0-9_-]{1,64}$");   // forti::engine::validate_profile_name
            if (!std::regex_match(c.profile, pattern)) throw DaemonConfigError("daemon.profile: 1-64 characters of [A-Za-z0-9_-]");
        }

        const json* listen = section(root, "listen", "daemon", {"address", "port"});
        c.listen_address = text(listen, "address", "daemon.listen", c.listen_address);
        // A literal, not a name: what the socket binds to must not change with DNS.
        if (!IpAddress::parse(c.listen_address))
            throw DaemonConfigError("daemon.listen.address: must be an IPv4 or IPv6 address literal");
        c.listen_port = integer<unsigned>(listen, "port", "daemon.listen", c.listen_port, 1, 65535);

        if (auto it = root.find("allow_sources"); it != root.end() && !it->is_null()) {
            if (!it->is_array()) throw DaemonConfigError("daemon.allow_sources: must be an array of CIDR strings");
            for (std::size_t i = 0; i < it->size(); ++i) {
                const auto& item = (*it)[i];
                std::optional<Cidr> cidr;
                if (item.is_string()) cidr = Cidr::parse(item.get<std::string>());
                if (!cidr)
                    throw DaemonConfigError(std::format("daemon.allow_sources[{}]: not an address or CIDR block (host bits must be zero)", i));
                c.allow_sources.push_back(*cidr);
            }
        }

        const json* limits = section(root, "limits", "daemon", {"max_header_bytes", "max_body_bytes", "read_timeout_ms", "max_connections"});
        c.max_header_bytes = integer<std::size_t>(limits, "max_header_bytes", "daemon.limits", c.max_header_bytes, 1024, 64 * 1024);
        c.max_body_bytes = integer<std::size_t>(limits, "max_body_bytes", "daemon.limits", c.max_body_bytes, 1024, 1024 * 1024);
        c.read_timeout_ms = integer<int>(limits, "read_timeout_ms", "daemon.limits", c.read_timeout_ms, 100, 60'000);
        c.max_connections = integer<int>(limits, "max_connections", "daemon.limits", c.max_connections, 1, 256);

        const json* rate = section(root, "rate_limit", "daemon", {"burst", "per_minute"});
        c.rate_burst = integer<int>(rate, "burst", "daemon.rate_limit", c.rate_burst, 1, 10'000);
        c.rate_per_minute = integer<int>(rate, "per_minute", "daemon.rate_limit", c.rate_per_minute, 1, 60'000);

        const json* schedule = section(root, "schedule", "daemon",
                                       {"debounce_seconds", "max_delay_seconds", "full_reconcile_minutes", "backoff_initial_seconds",
                                        "backoff_max_seconds", "suppression_seconds"});
        const char* s = "daemon.schedule";
        c.debounce_seconds = integer<int>(schedule, "debounce_seconds", s, c.debounce_seconds, 1, 3600);
        c.max_delay_seconds = integer<int>(schedule, "max_delay_seconds", s, c.max_delay_seconds, 1, 86'400);
        c.full_reconcile_minutes = integer<int>(schedule, "full_reconcile_minutes", s, c.full_reconcile_minutes, 1, 7 * 24 * 60);
        c.backoff_initial_seconds = integer<int>(schedule, "backoff_initial_seconds", s, c.backoff_initial_seconds, 1, 3600);
        c.backoff_max_seconds = integer<int>(schedule, "backoff_max_seconds", s, c.backoff_max_seconds, 1, 86'400);
        c.suppression_seconds = integer<int>(schedule, "suppression_seconds", s, c.suppression_seconds, 0, 3600);
        if (c.max_delay_seconds < c.debounce_seconds)
            throw DaemonConfigError("daemon.schedule.max_delay_seconds: must be at least debounce_seconds");
        if (c.backoff_max_seconds < c.backoff_initial_seconds)
            throw DaemonConfigError("daemon.schedule.backoff_max_seconds: must be at least backoff_initial_seconds");

        const json* log = section(root, "event_log", "daemon", {"max_mib"});
        c.event_log_max_mib = integer<int>(log, "max_mib", "daemon.event_log", c.event_log_max_mib, 1, 1024);

        c.token_account = text(&root, "token_account", "daemon", c.token_account);
        if (!c.token_account.empty()) {
            // Segments of [A-Za-z0-9_.-], none of them "." or "..".
            static const std::regex pattern("^(?!\\.\\.?(/|$))[A-Za-z0-9_.-]+(/(?!\\.\\.?(/|$))[A-Za-z0-9_.-]+)*$");
            if (c.token_account.size() > 128 || !std::regex_match(c.token_account, pattern))
                throw DaemonConfigError("daemon.token_account: a secret-store account name such as pihole/fw01/webhook-token");
        }
        return c;
    }

    json DaemonConfig::to_json() const {
        json allow = json::array();
        for (const auto& cidr: allow_sources) allow.push_back(cidr.to_string());
        return {{"profile", profile},
                {"listen", {{"address", listen_address}, {"port", listen_port}}},
                {"allow_sources", allow},
                {"limits", {{"max_header_bytes", max_header_bytes}, {"max_body_bytes", max_body_bytes},
                            {"read_timeout_ms", read_timeout_ms}, {"max_connections", max_connections}}},
                {"rate_limit", {{"burst", rate_burst}, {"per_minute", rate_per_minute}}},
                {"schedule", {{"debounce_seconds", debounce_seconds}, {"max_delay_seconds", max_delay_seconds},
                              {"full_reconcile_minutes", full_reconcile_minutes}, {"backoff_initial_seconds", backoff_initial_seconds},
                              {"backoff_max_seconds", backoff_max_seconds}, {"suppression_seconds", suppression_seconds}}},
                {"event_log", {{"max_mib", event_log_max_mib}}},
                {"token_account", token_account}};
    }

    Timing DaemonConfig::timing() const {
        return {.debounce_ms = debounce_seconds * 1000LL,
                .max_delay_ms = max_delay_seconds * 1000LL,
                .periodic_ms = full_reconcile_minutes * 60'000LL,
                .backoff_initial_ms = backoff_initial_seconds * 1000LL,
                .backoff_max_ms = backoff_max_seconds * 1000LL,
                .suppression_ms = suppression_seconds * 1000LL};
    }

    http::Limits DaemonConfig::http_limits() const {
        http::Limits limits;
        limits.max_header_bytes = max_header_bytes;
        limits.max_body_bytes = max_body_bytes;
        return limits;
    }

    DaemonConfig load_daemon_config(const std::filesystem::path& path) {
        std::error_code error;
        if (!std::filesystem::exists(path, error)) return {};
        std::ifstream in(path);
        if (!in) throw DaemonConfigError(std::format("cannot read {}", path.string()));
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto parsed = json::parse(buffer.str(), nullptr, false);
        if (parsed.is_discarded()) throw DaemonConfigError(std::format("{} is not valid JSON", path.string()));
        return DaemonConfig::from_json(parsed);
    }

}  // namespace fph::daemon
