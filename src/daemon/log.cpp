#include "log.hpp"

#include <chrono>
#include <format>

namespace fph::daemon {

    std::string Logger::quote(std::string_view value) {
        bool plain = !value.empty();
        for (char c: value) {
            auto u = static_cast<unsigned char>(c);
            if (u <= 0x20 || u == 0x7f || c == '"' || c == '=' || c == '\\') plain = false;
        }
        if (plain) return std::string(value.substr(0, 512));
        std::string out = "\"";
        for (char c: value.substr(0, 512)) {
            auto u = static_cast<unsigned char>(c);
            if (c == '"' || c == '\\') out += std::string("\\") + c;
            else if (u < 0x20 || u == 0x7f) out += std::format("\\x{:02x}", u);
            else out += c;
        }
        return out + "\"";
    }

    std::string Logger::fields_of(const nlohmann::json& summary) {
        std::string out;
        if (!summary.is_object()) return out;
        for (const auto& [key, value]: summary.items()) {
            if (!out.empty()) out += ' ';
            out += key + "=" + quote(value.is_string() ? value.get<std::string>() : value.dump());
        }
        return out;
    }

    void Logger::write(std::string_view level, std::string_view event, std::initializer_list<Field> fields) const {
        if (!out_) return;
        std::string line;
        if (timestamps_)
            line += std::format("ts={:%FT%TZ} ",
                                std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
        line += std::format("level={} event={}", level, event);
        for (const auto& [key, value]: fields) {
            if (key == "fields") {   // pre-rendered pairs (fields_of)
                if (!value.empty()) line += " " + value;
                continue;
            }
            line += std::format(" {}={}", key, quote(value));
        }
        line += '\n';
        // One write per line, so lines from a signal-driven shutdown never interleave mid-line.
        *out_ << line << std::flush;
    }

}  // namespace fph::daemon
