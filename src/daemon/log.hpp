//
// Terse structured logging to stderr, which journald (systemd) or launchd (brew services) captures:
//
//   level=info event=run.finished reason=event ok=true duration_ms=812 written=3
//
// logfmt: key=value pairs, values quoted when they hold spaces, quotes or '=', control characters
// escaped (event fields are device data). A timestamp is added only when stderr is not journald's
// (JOURNAL_STREAM unset), since journald stamps every line itself. Nothing secret is ever passed in:
// callers log event summaries, never request bodies or headers.
//

#ifndef FORTI_PIHOLED_LOG_HPP
#define FORTI_PIHOLED_LOG_HPP

#include <nlohmann/json.hpp>

#include <functional>
#include <initializer_list>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>

namespace fph::daemon {

    class Logger {
    public:
        using Field = std::pair<std::string_view, std::string>;

        // `out` null: discard. `timestamps`: prefix ts=<UTC ISO 8601>.
        explicit Logger(std::ostream* out = nullptr, bool timestamps = false) : out_(out), timestamps_(timestamps) {}

        void info(std::string_view event, std::initializer_list<Field> fields = {}) const { write("info", event, fields); }
        void warn(std::string_view event, std::initializer_list<Field> fields = {}) const { write("warn", event, fields); }
        void error(std::string_view event, std::initializer_list<Field> fields = {}) const { write("error", event, fields); }

        // An event summary's fields as logfmt pairs ("path=firewall.address object=fp-dev-x").
        static std::string fields_of(const nlohmann::json& summary);
        static std::string quote(std::string_view value);

    private:
        void write(std::string_view level, std::string_view event, std::initializer_list<Field> fields) const;

        std::ostream* out_;
        bool timestamps_;
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_LOG_HPP
