#include "state.hpp"

#include <forti/engine/profile.hpp>

#include <deque>
#include <format>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fph {

    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        std::string str(const json& object, const char* key) {
            auto it = object.find(key);
            return it != object.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        std::int64_t num(const json& object, const char* key) {
            auto it = object.find(key);
            return it != object.end() && it->is_number_integer() ? it->get<std::int64_t>() : 0;
        }

        void ensure_private_dir(const fs::path& dir) {
            std::error_code error;
            fs::create_directories(dir, error);
            if (error) throw StateError(std::format("cannot create {}: {}", dir.string(), error.message()));
            ::chmod(dir.c_str(), 0700);
        }

    }  // namespace

    State State::from_json(const json& root) {
        if (!root.is_object()) throw StateError("state: not an object");
        State state;
        for (const auto& [mac, item]: root.value("devices", json::object()).items()) {
            DeviceRecord record;
            record.label = str(item, "label");
            record.hostname = str(item, "hostname");
            record.vendor = str(item, "vendor");
            record.family = str(item, "family");
            record.os = str(item, "os");
            record.os_version = str(item, "os_version");
            record.randomized = item.value("randomized", false);
            record.first_seen = num(item, "first_seen");
            record.last_seen = num(item, "last_seen");
            record.object = str(item, "object");
            record.written_segment = str(item, "written_segment");
            state.devices.emplace(mac, std::move(record));
        }
        for (const auto& [mac, item]: root.value("pins", json::object()).items())
            state.pins.emplace(mac, Pin{str(item, "segment"), str(item, "source"), num(item, "at")});
        for (const auto& item: root.value("candidates", json::array())) {
            Candidate candidate;
            candidate.id = str(item, "id");
            candidate.old_mac = str(item, "old_mac");
            candidate.new_mac = str(item, "new_mac");
            candidate.score = static_cast<int>(num(item, "score"));
            candidate.found_at = num(item, "found_at");
            for (const auto& reason: item.value("reasons", json::array()))
                if (reason.is_string()) candidate.reasons.push_back(reason.get<std::string>());
            state.candidates.push_back(std::move(candidate));
        }
        for (const auto& id: root.value("dismissed", json::array()))
            if (id.is_string()) state.dismissed.insert(id.get<std::string>());
        for (const auto& mac: root.value("retire_now", json::array()))
            if (mac.is_string()) state.retire_now.insert(mac.get<std::string>());
        state.last_apply = num(root, "last_apply");
        state.last_plan = str(root, "last_plan");
        if (auto it = root.find("pending"); it != root.end() && it->is_object()) {
            Pending pending;
            pending.plan_id = str(*it, "plan_id");
            pending.at = num(*it, "at");
            for (const auto& [mac, entry]: it->value("written", json::object()).items())
                pending.written[mac] = {str(entry, "object"), str(entry, "segment")};
            for (const auto& mac: it->value("retired", json::array()))
                if (mac.is_string()) pending.retired.push_back(mac.get<std::string>());
            state.pending = std::move(pending);
        }
        return state;
    }

    bool State::wrote(std::string_view mac, std::string_view object, std::string_view segment) const {
        if (auto it = devices.find(std::string(mac)); it != devices.end())
            if (it->second.object == object && it->second.written_segment == segment) return true;
        if (pending)
            if (auto it = pending->written.find(std::string(mac)); it != pending->written.end())
                return it->second.first == object && it->second.second == segment;
        return false;
    }

    bool State::has_written(std::string_view mac) const {
        if (auto it = devices.find(std::string(mac)); it != devices.end() && !it->second.written_segment.empty()) return true;
        return pending && pending->written.contains(std::string(mac));
    }

    json State::to_json() const {
        json devices_json = json::object();
        for (const auto& [mac, r]: devices)
            devices_json[mac] = {{"label", r.label}, {"hostname", r.hostname}, {"vendor", r.vendor}, {"family", r.family},
                                 {"os", r.os}, {"os_version", r.os_version}, {"randomized", r.randomized},
                                 {"first_seen", r.first_seen}, {"last_seen", r.last_seen}, {"object", r.object},
                                 {"written_segment", r.written_segment}};
        json pins_json = json::object();
        for (const auto& [mac, p]: pins) pins_json[mac] = {{"segment", p.segment}, {"source", p.source}, {"at", p.at}};
        json candidates_json = json::array();
        for (const auto& c: candidates)
            candidates_json.push_back({{"id", c.id}, {"old_mac", c.old_mac}, {"new_mac", c.new_mac}, {"score", c.score},
                                       {"reasons", c.reasons}, {"found_at", c.found_at}});
        json out = {{"version", 1}, {"devices", devices_json}, {"pins", pins_json}, {"candidates", candidates_json},
                    {"dismissed", dismissed}, {"retire_now", retire_now}, {"last_apply", last_apply}, {"last_plan", last_plan}};
        if (pending) {
            json written = json::object();
            for (const auto& [mac, entry]: pending->written) written[mac] = {{"object", entry.first}, {"segment", entry.second}};
            out["pending"] = {{"plan_id", pending->plan_id}, {"written", written}, {"retired", pending->retired}, {"at", pending->at}};
        }
        return out;
    }

    const Candidate* State::candidate(std::string_view id) const {
        for (const auto& c: candidates)
            if (c.id == id) return &c;
        return nullptr;
    }

    Home Home::from_env() {
        auto paths = forti::engine::Paths::from_env();
        // Before `forti home migrate` (legacy XDG layout) there is no home; keep our files with the
        // engine's state so they still sit beside the plans and audit log.
        fs::path base = paths.home.empty() ? paths.state : paths.home;
        return {base / "pihole"};
    }

    State load_state(const fs::path& path) {
        std::ifstream in(path);
        if (!in) return {};
        std::stringstream buffer;
        buffer << in.rdbuf();
        json parsed = json::parse(buffer.str(), nullptr, false);
        if (parsed.is_discarded())
            throw StateError(std::format("{} is not valid JSON; fix or move it aside (it records GUI overrides)", path.string()));
        return State::from_json(parsed);
    }

    void write_private(const fs::path& path, const std::string& text) {
        ensure_private_dir(path.parent_path());
        auto temp = path;
        temp += ".tmp";
        int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) throw StateError(std::format("cannot write {}", temp.string()));
        std::size_t written = 0;
        while (written < text.size()) {
            auto n = ::write(fd, text.data() + written, text.size() - written);
            if (n <= 0) {
                ::close(fd);
                throw StateError(std::format("cannot write {}", temp.string()));
            }
            written += static_cast<std::size_t>(n);
        }
        bool synced = ::fsync(fd) == 0;
        ::close(fd);
        if (!synced) throw StateError(std::format("cannot write {}", temp.string()));
        std::error_code error;
        fs::rename(temp, path, error);
        if (error) throw StateError(std::format("cannot replace {}: {}", path.string(), error.message()));
    }

    void save_state(const fs::path& path, const State& state) { write_private(path, state.to_json().dump(2) + "\n"); }

    void append_history(const fs::path& path, const json& entry) {
        ensure_private_dir(path.parent_path());
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) throw StateError(std::format("cannot append to {}", path.string()));
        auto line = entry.dump() + "\n";
        auto n = ::write(fd, line.data(), line.size());
        ::close(fd);
        if (n != static_cast<ssize_t>(line.size())) throw StateError(std::format("cannot append to {}", path.string()));
    }

    std::vector<json> read_history(const fs::path& path, std::size_t last) {
        std::ifstream in(path);
        std::deque<json> window;
        std::string line;
        while (std::getline(in, line)) {
            auto entry = json::parse(line, nullptr, false);
            if (entry.is_discarded()) continue;
            window.push_back(std::move(entry));
            if (window.size() > last) window.pop_front();
        }
        return {window.begin(), window.end()};
    }

    RunLock::RunLock(const fs::path& path) {
        ensure_private_dir(path.parent_path());
        fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (fd_ < 0) throw StateError(std::format("cannot open {}", path.string()));
        if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
            ::close(fd_);
            fd_ = -1;
            throw StateError("another forti-pihole run is in progress");
        }
    }

    RunLock::~RunLock() {
        if (fd_ >= 0) ::close(fd_);
    }

}  // namespace fph
