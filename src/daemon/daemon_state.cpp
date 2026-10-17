#include "daemon_state.hpp"

#include <forti/engine/profile.hpp>

#include <cerrno>
#include <format>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace fph::daemon {

    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        std::int64_t num(const json& o, const char* key) {
            auto it = o.find(key);
            if (it == o.end() || it->is_null()) return 0;
            if (!it->is_number_integer()) throw DaemonStateError(std::format("{}: must be an integer", key));
            return it->get<std::int64_t>();
        }

        bool flag(const json& o, const char* key) {
            auto it = o.find(key);
            if (it == o.end() || it->is_null()) return false;
            if (!it->is_boolean()) throw DaemonStateError(std::format("{}: must be true or false", key));
            return it->get<bool>();
        }

        std::string str(const json& o, const char* key) {
            auto it = o.find(key);
            if (it == o.end() || it->is_null()) return {};
            if (!it->is_string()) throw DaemonStateError(std::format("{}: must be a string", key));
            return it->get<std::string>();
        }

        // Exclusive flock on the lock file for the object's lifetime (blocking: the other writer only
        // ever holds it for one small read-modify-write).
        class FileLock {
            int fd_ = -1;

        public:
            explicit FileLock(const fs::path& path) {
                forti::engine::ensure_private_dir(path.parent_path());
                fd_ = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
                if (fd_ < 0) throw DaemonStateError(std::format("cannot open {}", path.string()));
                while (::flock(fd_, LOCK_EX) != 0)
                    if (errno != EINTR) {
                        ::close(fd_);
                        throw DaemonStateError(std::format("cannot lock {}", path.string()));
                    }
            }
            ~FileLock() {
                if (fd_ >= 0) ::close(fd_);
            }
            FileLock(const FileLock&) = delete;
            FileLock& operator=(const FileLock&) = delete;
        };

        enum class Read { missing, ok, corrupt };

        Read read_state(const fs::path& path, DaemonState& out) {
            std::ifstream in(path);
            if (!in) {
                std::error_code error;
                return fs::exists(path, error) ? Read::corrupt : Read::missing;
            }
            std::stringstream buffer;
            buffer << in.rdbuf();
            auto parsed = json::parse(buffer.str(), nullptr, false);
            if (parsed.is_discarded()) return Read::corrupt;
            try {
                out = DaemonState::from_json(parsed);
            } catch (const DaemonStateError&) {
                return Read::corrupt;
            }
            return Read::ok;
        }

        void write_state(const fs::path& path, const DaemonState& state) {
            try {
                forti::engine::write_private_file(path, state.to_json().dump(2) + "\n");
            } catch (const std::exception& e) {
                throw DaemonStateError(std::format("cannot write {}: {}", path.string(), e.what()));
            }
        }

    }  // namespace

    DaemonState DaemonState::from_json(const json& root) {
        if (!root.is_object()) throw DaemonStateError("daemon state: not an object");
        DaemonState s;
        s.last_event_at = num(root, "last_event_at");
        if (auto it = root.find("last_event"); it != root.end() && !it->is_null()) {
            if (!it->is_object()) throw DaemonStateError("last_event: must be an object");
            s.last_event = *it;
        }
        s.last_run_started = num(root, "last_run_started");
        s.last_run_finished = num(root, "last_run_finished");
        s.last_run_reason = str(root, "last_run_reason");
        s.last_run_ok = flag(root, "last_run_ok");
        s.last_error = str(root, "last_error");
        auto failures = num(root, "consecutive_failures");
        if (failures < 0 || failures > 1'000'000) throw DaemonStateError("consecutive_failures: out of range");
        s.consecutive_failures = static_cast<int>(failures);
        s.next_retry_at = num(root, "next_retry_at");
        s.pending = flag(root, "pending");
        s.running = flag(root, "running");
        s.paused = flag(root, "paused");
        s.paused_at = num(root, "paused_at");
        return s;
    }

    json DaemonState::to_json() const {
        return {{"version", 1},
                {"last_event_at", last_event_at},
                {"last_event", last_event},
                {"last_run_started", last_run_started},
                {"last_run_finished", last_run_finished},
                {"last_run_reason", last_run_reason},
                {"last_run_ok", last_run_ok},
                {"last_error", last_error},
                {"consecutive_failures", consecutive_failures},
                {"next_retry_at", next_retry_at},
                {"pending", pending},
                {"running", running},
                {"paused", paused},
                {"paused_at", paused_at}};
    }

    LoadedState load_daemon_state(const StateFiles& files) {
        FileLock lock(files.lock());
        LoadedState loaded;
        switch (read_state(files.state(), loaded.state)) {
            case Read::missing:
            case Read::ok: return loaded;
            case Read::corrupt: break;
        }
        auto aside = files.state();
        aside += ".corrupt";
        std::error_code error;
        fs::rename(files.state(), aside, error);
        loaded = {};
        loaded.corrupt = true;
        loaded.state.pending = true;
        return loaded;
    }

    bool read_paused(const StateFiles& files) {
        DaemonState state;
        return read_state(files.state(), state) == Read::ok && state.paused;
    }

    void save_daemon_state(const StateFiles& files, const DaemonState& state) {
        FileLock lock(files.lock());
        DaemonState on_disk;
        DaemonState out = state;
        if (read_state(files.state(), on_disk) == Read::ok) {
            out.paused = on_disk.paused;
            out.paused_at = on_disk.paused_at;
        } else {
            out.paused = false;
            out.paused_at = 0;
        }
        write_state(files.state(), out);
    }

    void set_paused(const StateFiles& files, bool paused, std::int64_t now_s) {
        FileLock lock(files.lock());
        DaemonState state;
        if (read_state(files.state(), state) == Read::corrupt)
            throw DaemonStateError(std::format("{} is corrupt; the daemon moves it aside at its next start", files.state().string()));
        if (state.paused == paused) return;
        state.paused = paused;
        state.paused_at = paused ? now_s : 0;
        write_state(files.state(), state);
    }

    void EventLog::append(const json& entry) {
        auto line = entry.dump(-1, ' ', false, json::error_handler_t::replace) + "\n";
        forti::engine::ensure_private_dir(path_.parent_path());
        std::error_code error;
        auto size = fs::file_size(path_, error);
        if (!error && size + line.size() > max_bytes_) {
            auto old = path_;
            old += ".1";
            fs::rename(path_, old, error);   // one generation: bounded at about twice the limit
        }
        int fd = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0) throw DaemonStateError(std::format("cannot append to {}", path_.string()));
        auto n = ::write(fd, line.data(), line.size());
        ::close(fd);
        if (n != static_cast<ssize_t>(line.size())) throw DaemonStateError(std::format("cannot append to {}", path_.string()));
    }

}  // namespace fph::daemon
