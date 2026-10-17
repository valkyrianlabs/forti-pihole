//
// What forti-piholed remembers across restarts, and the event log.
//
//   $FORTI_HOME/pihole/daemon-state.json   0600, atomic (temp + rename): the last event and run, the
//                                          failure count and next retry (so a restart resumes the
//                                          backoff instead of hammering a failing FortiGate), the
//                                          pending flag, and the pause flag
//   $FORTI_HOME/pihole/daemon-state.lock   flock taken around every read-modify-write, because two
//                                          writers share the file: the daemon (everything but the
//                                          pause flag) and the CLI's pause/resume (only the flag)
//   $FORTI_HOME/pihole/events.jsonl        0600, append-only, one JSON object per accepted event or
//                                          finished run; renamed to events.jsonl.1 at the size limit
//
// The state is reconstructible (unlike state.json, which records GUI overrides): a corrupt file is
// moved aside to daemon-state.json.corrupt and the daemon starts fresh with a full reconcile.
// Times are Unix seconds (wall clock); the scheduler converts them to its monotonic clock.
//

#ifndef FORTI_PIHOLED_DAEMON_STATE_HPP
#define FORTI_PIHOLED_DAEMON_STATE_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace fph::daemon {

    class DaemonStateError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    struct DaemonState {
        std::int64_t last_event_at = 0;
        nlohmann::json last_event = nlohmann::json::object();   // ConfigEvent::summary()
        std::int64_t last_run_started = 0, last_run_finished = 0;
        std::string last_run_reason;
        bool last_run_ok = false;
        std::string last_error;
        int consecutive_failures = 0;
        std::int64_t next_retry_at = 0;   // 0: none
        bool pending = false;             // a run is owed (events, retry, follow-up)
        bool running = false;             // set while a run is in progress: still set at start = it crashed
        bool paused = false;              // written only by set_paused (the CLI's pause/resume)
        std::int64_t paused_at = 0;

        // Throws DaemonStateError on a wrong type; unknown keys are ignored (a newer writer).
        static DaemonState from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;
    };

    struct StateFiles {
        std::filesystem::path dir;   // $FORTI_HOME/pihole
        [[nodiscard]] std::filesystem::path state() const { return dir / "daemon-state.json"; }
        [[nodiscard]] std::filesystem::path lock() const { return dir / "daemon-state.lock"; }
        [[nodiscard]] std::filesystem::path events() const { return dir / "events.jsonl"; }
        [[nodiscard]] std::filesystem::path daemon_config() const { return dir / "daemon.json"; }
    };

    struct LoadedState {
        DaemonState state;
        bool corrupt = false;   // the file was unreadable and has been moved aside
    };

    // Missing: defaults. Corrupt: moved to <file>.corrupt, defaults with pending set.
    LoadedState load_daemon_state(const StateFiles& files);
    // Reads only the pause flag (and when it was set); false when the file is missing or corrupt.
    bool read_paused(const StateFiles& files);
    // The daemon's write: everything from `state` except the pause flag, which is kept as on disk.
    void save_daemon_state(const StateFiles& files, const DaemonState& state);
    // The CLI's pause/resume: changes only the pause flag. The daemon re-reads it before every run.
    void set_paused(const StateFiles& files, bool paused, std::int64_t now_s);

    class EventLog {
        std::filesystem::path path_;
        std::uintmax_t max_bytes_;

    public:
        EventLog(std::filesystem::path path, std::uintmax_t max_bytes) : path_(std::move(path)), max_bytes_(max_bytes) {}
        void set_max_bytes(std::uintmax_t max_bytes) { max_bytes_ = max_bytes; }
        // Appends one line; rotates first when the line would take the file past the limit.
        void append(const nlohmann::json& entry);
        [[nodiscard]] const std::filesystem::path& path() const { return path_; }
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_DAEMON_STATE_HPP
