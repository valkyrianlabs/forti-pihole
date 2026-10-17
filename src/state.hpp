//
// What the companion remembers between runs. None of it is needed for the network to work (the
// FortiGate keeps its configuration); it exists so the companion can tell its own past writes from
// an operator's GUI changes, keep devices it has stopped seeing for a grace period, and hold
// reassociation candidates until the operator decides.
//
//   $FORTI_HOME/pihole/state.json     0600, written atomically (temp file + rename)
//   $FORTI_HOME/pihole/history.jsonl  one line per apply (append-only)
//   $FORTI_HOME/pihole/lock           flock: one run at a time (timer vs. a manual run)
//

#ifndef FORTI_PIHOLE_STATE_HPP
#define FORTI_PIHOLE_STATE_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace fph {

    struct DeviceRecord {
        std::string label, hostname, vendor, family, os, os_version;
        bool randomized = false;
        std::int64_t first_seen = 0, last_seen = 0;
        std::string object;            // the member name used for it (managed or adopted)
        std::string written_group;   // the group group the companion last put that member in
    };

    struct Pin {
        std::string group;
        std::string source;   // "assign" (CLI), "gui" (moved in the FortiGate GUI), "confirm" (reassociation)
        std::int64_t at = 0;
    };

    struct Candidate {
        std::string id;        // stable: hash of both MACs
        std::string old_mac, new_mac;
        int score = 0;
        std::vector<std::string> reasons;
        std::int64_t found_at = 0;
    };

    // A plan made but not (fully) applied: waiting for approval (guarded mode) or cut short by a
    // failure. Its intended placements count as the companion's own until a later apply completes, so
    // a half-applied change is never mistaken for an operator's GUI move.
    struct Pending {
        std::string plan_id;
        std::map<std::string, std::pair<std::string, std::string>> written;   // mac -> (object, group)
        std::vector<std::string> retired;
        std::int64_t at = 0;
    };

    // What the operator explicitly allowed forti-pihole to change when it moves this device's
    // address (forti-pihole adopt): administrator host objects that follow the device, and its own
    // administrator reservation. Nothing is adopted implicitly.
    struct Adoption {
        std::set<std::string> objects;
        bool reservation = false;
        std::int64_t at = 0;
    };

    struct State {
        std::optional<Pending> pending;
        std::map<std::string, Adoption> adoptions;   // by MAC
        std::map<std::string, DeviceRecord> devices;   // by MAC
        std::map<std::string, Pin> pins;               // by MAC
        std::vector<Candidate> candidates;
        std::set<std::string> dismissed;               // candidate ids the operator rejected
        std::set<std::string> retire_now;              // MACs to retire at the next apply (confirmed reassociations)
        std::int64_t last_apply = 0;
        std::string last_plan;

        static State from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;
        [[nodiscard]] const Candidate* candidate(std::string_view id) const;
        // The companion put `object` into `group` for `mac` (last completed apply, or a pending plan).
        [[nodiscard]] bool wrote(std::string_view mac, std::string_view object, std::string_view group) const;
        [[nodiscard]] bool has_written(std::string_view mac) const;
    };

    struct Home {
        std::filesystem::path dir;   // $FORTI_HOME/pihole
        [[nodiscard]] std::filesystem::path config() const { return dir / "config.json"; }
        [[nodiscard]] std::filesystem::path state() const { return dir / "state.json"; }
        [[nodiscard]] std::filesystem::path history() const { return dir / "history.jsonl"; }
        [[nodiscard]] std::filesystem::path lock() const { return dir / "lock"; }

        // The forti home the engine uses ($FORTI_HOME, else ~/.forti), plus "pihole".
        static Home from_env();
    };

    // Missing file: an empty State. Corrupt file: StateError (never silently reset; the operator's
    // GUI overrides are recorded there).
    class StateError : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };
    State load_state(const std::filesystem::path& path);
    void save_state(const std::filesystem::path& path, const State& state);

    // Writes `text` to `path` with mode 0600 in a 0700 directory, atomically.
    void write_private(const std::filesystem::path& path, const std::string& text);

    void append_history(const std::filesystem::path& path, const nlohmann::json& entry);
    std::vector<nlohmann::json> read_history(const std::filesystem::path& path, std::size_t last);

    // An exclusive, non-blocking flock held for the object's lifetime. Throws StateError when another
    // run holds it.
    class RunLock {
        int fd_ = -1;

    public:
        explicit RunLock(const std::filesystem::path& path);
        ~RunLock();
        RunLock(const RunLock&) = delete;
        RunLock& operator=(const RunLock&) = delete;
    };

}  // namespace fph

#endif  // FORTI_PIHOLE_STATE_HPP
