// Durable state (round trip, corruption, the pause flag shared with the CLI, file modes), the event
// log's rotation, and daemon.json validation.

#include "support.hpp"

#include <daemon_config.hpp>
#include <daemon_state.hpp>

#include <sys/stat.h>

#include <sstream>

namespace fph::daemon::test {

    using json = nlohmann::json;

    namespace {

        unsigned mode_of(const fs::path& path) {
            struct stat info{};
            ::stat(path.c_str(), &info);
            return info.st_mode & 0777;
        }

        DaemonConfig parse_config(const char* text) { return DaemonConfig::from_json(json::parse(text)); }

        std::string config_error(const char* text) {
            try {
                parse_config(text);
            } catch (const DaemonConfigError& e) {
                return e.what();
            }
            return "";
        }

    }  // namespace

    TEST(DaemonState, RoundTrip) {
        TempDir dir;
        StateFiles files{dir.path() / "pihole"};
        auto missing = load_daemon_state(files);
        EXPECT_FALSE(missing.corrupt);
        EXPECT_EQ(missing.state.consecutive_failures, 0);

        DaemonState state;
        state.last_event_at = 1700000000;
        state.last_event = {{"cfgpath", "firewall.address"}, {"cfgobj", "x"}};
        state.last_run_started = 1700000010;
        state.last_run_finished = 1700000012;
        state.last_run_reason = "event";
        state.last_run_ok = false;
        state.last_error = "connection refused";
        state.consecutive_failures = 3;
        state.next_retry_at = 1700000100;
        state.pending = true;
        save_daemon_state(files, state);
        EXPECT_EQ(mode_of(files.state()), 0600u);
        EXPECT_EQ(mode_of(files.dir), 0700u);

        auto loaded = load_daemon_state(files);
        EXPECT_FALSE(loaded.corrupt);
        EXPECT_EQ(loaded.state.to_json(), state.to_json());
        // Atomic replace: no temp file left behind.
        for (const auto& entry: fs::directory_iterator(files.dir)) EXPECT_FALSE(entry.path().string().ends_with(".tmp"));
    }

    TEST(DaemonState, CorruptFileIsMovedAsideAndAFullRunIsOwed) {
        TempDir dir;
        StateFiles files{dir.path() / "pihole"};
        for (const char* corrupt: {"{not json", "[]", R"({"consecutive_failures": "three"})", R"({"paused": 1})",
                                   R"({"consecutive_failures": -4})"}) {
            write_file(files.state(), corrupt);
            auto loaded = load_daemon_state(files);
            EXPECT_TRUE(loaded.corrupt) << corrupt;
            EXPECT_TRUE(loaded.state.pending) << corrupt;
            EXPECT_FALSE(fs::exists(files.state()));
            EXPECT_EQ(read_file(fs::path(files.state().string() + ".corrupt")), corrupt);
            // Readers that only want the pause flag see "not paused" rather than failing.
            write_file(files.state(), corrupt);
            EXPECT_FALSE(read_paused(files));
            fs::remove(files.state());
        }
        // Unknown keys (a newer writer) are not corruption.
        write_file(files.state(), R"({"version": 2, "future_field": {"x": 1}, "consecutive_failures": 1})");
        auto loaded = load_daemon_state(files);
        EXPECT_FALSE(loaded.corrupt);
        EXPECT_EQ(loaded.state.consecutive_failures, 1);
    }

    TEST(DaemonState, PauseFlagBelongsToTheCli) {
        TempDir dir;
        StateFiles files{dir.path() / "pihole"};
        EXPECT_FALSE(read_paused(files));
        set_paused(files, true, 1700000000);
        EXPECT_TRUE(read_paused(files));

        // The daemon's own writes never undo a pause it did not make...
        DaemonState daemon_view;
        daemon_view.pending = true;
        daemon_view.paused = false;
        save_daemon_state(files, daemon_view);
        EXPECT_TRUE(read_paused(files));
        auto loaded = load_daemon_state(files).state;
        EXPECT_TRUE(loaded.pending);
        EXPECT_EQ(loaded.paused_at, 1700000000);

        // ...nor invent one.
        set_paused(files, false, 1700000100);
        daemon_view.paused = true;
        save_daemon_state(files, daemon_view);
        EXPECT_FALSE(read_paused(files));

        write_file(files.state(), "{corrupt");
        EXPECT_THROW(set_paused(files, true, 0), DaemonStateError);
    }

    TEST(EventLog, AppendsAndRotates) {
        TempDir dir;
        auto path = dir.path() / "pihole" / "events.jsonl";
        EventLog log(path, 300);
        for (int i = 0; i < 20; ++i) log.append({{"type", "event"}, {"n", i}, {"pad", std::string(20, 'x')}});
        EXPECT_EQ(mode_of(path), 0600u);
        EXPECT_LE(fs::file_size(path), 300u);
        auto rotated = fs::path(path.string() + ".1");
        ASSERT_TRUE(fs::exists(rotated));
        EXPECT_LE(fs::file_size(rotated), 300u);
        // Every line is a whole JSON object; the newest entry is in the current file.
        auto text = read_file(path);
        std::istringstream lines(text);
        std::string line, last;
        while (std::getline(lines, line)) {
            EXPECT_FALSE(json::parse(line, nullptr, false).is_discarded()) << line;
            last = line;
        }
        EXPECT_EQ(json::parse(last)["n"], 19);
        // Invalid UTF-8 from a device never makes an append throw.
        log.append({{"cfgobj", std::string("\xff\xfe", 2)}});
    }

    TEST(DaemonConfig, Defaults) {
        auto c = parse_config("{}");
        EXPECT_EQ(c.listen_address, "127.0.0.1");
        EXPECT_EQ(c.listen_port, 8735u);
        EXPECT_TRUE(c.allow_sources.empty());
        EXPECT_EQ(c.max_header_bytes, 8192u);
        EXPECT_EQ(c.max_body_bytes, 65536u);
        EXPECT_EQ(c.read_timeout_ms, 5000);
        EXPECT_EQ(c.debounce_seconds, 10);
        EXPECT_EQ(c.max_delay_seconds, 60);
        EXPECT_EQ(c.full_reconcile_minutes, 15);
        EXPECT_EQ(c.backoff_max_seconds, 900);
        EXPECT_EQ(c.suppression_seconds, 60);
        auto timing = c.timing();
        EXPECT_EQ(timing.debounce_ms, 10'000);
        EXPECT_EQ(timing.periodic_ms, 900'000);
        EXPECT_EQ(timing.backoff_max_ms, 900'000);
        TempDir dir;
        EXPECT_EQ(load_daemon_config(dir.path() / "absent.json").to_json(), c.to_json());
    }

    TEST(DaemonConfig, FullFileRoundTrips) {
        auto c = parse_config(R"({
            "$comment": "management network only",
            "profile": "fw01",
            "listen": {"address": "192.0.2.10", "port": 9000},
            "allow_sources": ["192.0.2.1", "2001:db8::/64"],
            "limits": {"max_header_bytes": 4096, "max_body_bytes": 16384, "read_timeout_ms": 2000, "max_connections": 4},
            "rate_limit": {"burst": 5, "per_minute": 30},
            "schedule": {"debounce_seconds": 5, "max_delay_seconds": 30, "full_reconcile_minutes": 60,
                         "backoff_initial_seconds": 2, "backoff_max_seconds": 600, "suppression_seconds": 120},
            "event_log": {"max_mib": 8},
            "token_account": "pihole/fw01/webhook-token"
        })");
        EXPECT_EQ(c.profile, "fw01");
        EXPECT_EQ(c.listen_port, 9000u);
        ASSERT_EQ(c.allow_sources.size(), 2u);
        EXPECT_EQ(c.allow_sources[1].to_string(), "2001:db8::/64");
        EXPECT_EQ(c.http_limits().max_body_bytes, 16384u);
        EXPECT_EQ(DaemonConfig::from_json(c.to_json()).to_json(), c.to_json());
    }

    TEST(DaemonConfig, RejectsUnknownKeysAndBadValues) {
        EXPECT_NE(config_error(R"({"tokn": "x"})").find("unknown key \"tokn\""), std::string::npos);
        EXPECT_NE(config_error(R"({"token": "secret"})").find("unknown key"), std::string::npos);   // never a token here
        EXPECT_NE(config_error(R"({"listen": {"adress": "1.2.3.4"}})").find("daemon.listen: unknown key"), std::string::npos);
        EXPECT_NE(config_error(R"({"schedule": {"debounce": 1}})").find("daemon.schedule: unknown key"), std::string::npos);
        EXPECT_NE(config_error(R"({"limits": {"max_body": 1}})").find("daemon.limits"), std::string::npos);
        EXPECT_NE(config_error(R"({"rate_limit": {"burst": 0}})").find("daemon.rate_limit.burst"), std::string::npos);
        EXPECT_NE(config_error(R"({"event_log": {"max_mib": 0}})").find("max_mib"), std::string::npos);
        EXPECT_NE(config_error(R"({"listen": {"address": "fw.example"}})").find("address literal"), std::string::npos);
        EXPECT_NE(config_error(R"({"listen": {"port": 0}})").find("1..65535"), std::string::npos);
        EXPECT_NE(config_error(R"({"listen": {"port": "8735"}})").find("must be an integer"), std::string::npos);
        EXPECT_NE(config_error(R"({"listen": []})").find("must be an object"), std::string::npos);
        EXPECT_NE(config_error(R"({"allow_sources": "192.0.2.1"})").find("array"), std::string::npos);
        EXPECT_NE(config_error(R"({"allow_sources": ["192.0.2.1/24"]})").find("allow_sources[0]"), std::string::npos);
        EXPECT_NE(config_error(R"({"allow_sources": [7]})").find("allow_sources[0]"), std::string::npos);
        EXPECT_NE(config_error(R"({"limits": {"max_body_bytes": 99999999}})").find("max_body_bytes"), std::string::npos);
        EXPECT_NE(config_error(R"({"limits": {"read_timeout_ms": 10}})").find("read_timeout_ms"), std::string::npos);
        EXPECT_NE(config_error(R"({"schedule": {"debounce_seconds": 30, "max_delay_seconds": 10}})").find("max_delay_seconds"),
                  std::string::npos);
        EXPECT_NE(config_error(R"({"schedule": {"backoff_initial_seconds": 60, "backoff_max_seconds": 10}})").find("backoff_max"),
                  std::string::npos);
        EXPECT_NE(config_error(R"({"profile": "bad name"})").find("daemon.profile"), std::string::npos);
        EXPECT_NE(config_error(R"({"token_account": "../../etc"})").find("token_account"), std::string::npos);
        EXPECT_NE(config_error("[]").find("must be an object"), std::string::npos);
        EXPECT_EQ(config_error(R"({"listen": null, "schedule": null})"), "");   // null: the default

        TempDir dir;
        write_file(dir.path() / "daemon.json", "{not json");
        EXPECT_THROW(load_daemon_config(dir.path() / "daemon.json"), DaemonConfigError);
    }

}  // namespace fph::daemon::test
