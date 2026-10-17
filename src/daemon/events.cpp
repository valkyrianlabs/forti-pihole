#include "events.hpp"

#include <algorithm>

namespace fph::daemon {

    using json = nlohmann::json;

    namespace {

        struct Field {
            const char* key;
            std::string ConfigEvent::* member;
        };

        constexpr Field fields[] = {
                {"logid", &ConfigEvent::logid},     {"eventtime", &ConfigEvent::eventtime}, {"vd", &ConfigEvent::vd},
                {"user", &ConfigEvent::user},       {"ui", &ConfigEvent::ui},               {"action", &ConfigEvent::action},
                {"cfgtid", &ConfigEvent::cfgtid},   {"cfgpath", &ConfigEvent::cfgpath},     {"cfgobj", &ConfigEvent::cfgobj},
                {"logdesc", &ConfigEvent::logdesc},
        };

        // A variable FortiOS left unsubstituted (the log had no such field) carries no information.
        std::string clean(std::string_view value) {
            while (!value.empty() && value.front() == '"') value.remove_prefix(1);
            while (!value.empty() && value.back() == '"') value.remove_suffix(1);
            if (value.starts_with("%%") && value.ends_with("%%")) return {};
            return sanitize(value);
        }

        std::string scalar(const json& value) {
            if (value.is_string()) return value.get<std::string>();
            if (value.is_number_integer()) return std::to_string(value.get<long long>());
            if (value.is_number_unsigned()) return std::to_string(value.get<unsigned long long>());
            return {};
        }

        // `"key"<ws>:<ws>"value"` where the value ends at the first quote followed by `,` or `}` (or the
        // end): survives an unescaped quote inside the value, which strict JSON parsing does not.
        std::string extract(std::string_view body, std::string_view key) {
            std::string needle = "\"" + std::string(key) + "\"";
            for (auto at = body.find(needle); at != std::string_view::npos; at = body.find(needle, at + 1)) {
                auto pos = at + needle.size();
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
                if (pos >= body.size() || body[pos] != ':') continue;
                ++pos;
                while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) ++pos;
                if (pos >= body.size()) return {};
                if (body[pos] != '"') {
                    auto end = body.find_first_of(",}", pos);
                    return clean(body.substr(pos, end == std::string_view::npos ? body.size() - pos : end - pos));
                }
                auto start = pos + 1;
                for (auto q = body.find('"', start); q != std::string_view::npos; q = body.find('"', q + 1)) {
                    auto next = q + 1;
                    while (next < body.size() && (body[next] == ' ' || body[next] == '\t' || body[next] == '"')) ++next;
                    if (next >= body.size() || body[next] == ',' || body[next] == '}') return clean(body.substr(start, q - start));
                }
                return clean(body.substr(start));
            }
            return {};
        }

        std::string lower(std::string text) {
            for (auto& c: text) c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            return text;
        }

        // Both spellings to one: "firewall.address" / "Firewall/Address" -> "firewall/address".
        std::string normalize_resource(std::string_view text) {
            std::string out = lower(std::string(text));
            std::ranges::replace(out, '.', '/');
            return out;
        }

    }  // namespace

    std::string sanitize(std::string_view text, std::size_t max) {
        std::string out;
        out.reserve(std::min(text.size(), max));
        for (char c: text) {
            if (out.size() >= max) break;
            auto u = static_cast<unsigned char>(c);
            out += (u < 0x20 || u == 0x7f) ? '?' : c;
        }
        return out;
    }

    std::string ConfigEvent::resource() const { return normalize_resource(cfgpath); }

    json ConfigEvent::summary() const {
        json out = json::object();
        for (const auto& field: fields)
            if (const auto& value = this->*field.member; !value.empty()) out[field.key] = value;
        if (!structured) out["structured"] = false;
        return out;
    }

    ConfigEvent parse_event(std::string_view body) {
        ConfigEvent event;
        auto parsed = json::parse(body, nullptr, false);
        if (!parsed.is_discarded() && parsed.is_object()) {
            event.structured = true;
            for (const auto& field: fields)
                if (auto it = parsed.find(field.key); it != parsed.end()) event.*field.member = clean(scalar(*it));
            return event;
        }
        for (const auto& field: fields) event.*field.member = extract(body, field.key);
        return event;
    }

    std::vector<WrittenObject> written_by(const json& operations) {
        std::vector<WrittenObject> out;
        if (!operations.is_array()) return out;
        for (const auto& op: operations) {
            if (!op.is_object()) continue;
            auto resource = op.value("resource", std::string());
            if (resource.empty()) continue;
            std::string name;
            if (auto key = op.find("key"); key != op.end()) name = scalar(*key);
            else if (auto object = op.find("object"); object != op.end() && object->is_object())
                name = scalar(object->value("name", json()));
            out.push_back({resource, name});
        }
        return out;
    }

    void LoopGuard::record(std::int64_t now_ms, const std::vector<WrittenObject>& written) {
        prune(now_ms);
        for (const auto& object: written) until_[{normalize_resource(object.resource), object.name}] = now_ms + window_ms_;
    }

    bool LoopGuard::suppresses(std::int64_t now_ms, const ConfigEvent& event) const {
        // Without a path the event cannot be attributed: it might be anyone's change.
        if (event.cfgpath.empty()) return false;
        auto it = until_.find({event.resource(), event.cfgobj});
        return it != until_.end() && now_ms < it->second;
    }

    void LoopGuard::prune(std::int64_t now_ms) {
        std::erase_if(until_, [&](const auto& entry) { return entry.second <= now_ms; });
    }

}  // namespace fph::daemon
