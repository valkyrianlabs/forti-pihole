//
// A FortiGate config-change event as the webhook action delivers it, and the loop guard that tells
// the companion's own writes from everyone else's.
//
// The body is the JSON template stitch.hpp installs (webhook_body()): FortiOS substitutes the
// %%log.<field>%% variables with fields of the triggering config-change event log (FortiOS 7.4.8 Log
// Message Reference: 44544 LOGID_EVENT_CONFIG_PATH, 44545 _OBJ, 44546 _ATTR, 44547 _OBJATTR): cfgpath
// ("firewall.address"), cfgobj (the object's name), action ("Add"/"Edit"/"Delete"), user, ui, vd,
// cfgtid, logid, eventtime, logdesc. Fortinet does not document whether substituted values are
// JSON-escaped, so a value holding a quote may break the JSON; the parser then falls back to pulling
// the known fields out leniently. A body with none of them is still an event (it triggers a run); it
// just cannot be attributed to an object, so it is never suppressed.
//
// Every field is untrusted device data: it is cut to 256 bytes and stripped of control characters
// before it is stored or logged.
//

#ifndef FORTI_PIHOLED_EVENTS_HPP
#define FORTI_PIHOLED_EVENTS_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace fph::daemon {

    struct ConfigEvent {
        std::string logid, eventtime, vd, user, ui, action, cfgtid, cfgpath, cfgobj, logdesc;
        bool structured = false;   // the body was the JSON template (else: lenient extraction or nothing)

        // cfgpath in the engine's resource spelling, lower-cased: "firewall.address" -> "firewall/address".
        [[nodiscard]] std::string resource() const;
        // For the event log and stderr: only the attribution fields, never the raw body.
        [[nodiscard]] nlohmann::json summary() const;
    };

    ConfigEvent parse_event(std::string_view body);

    // Untrusted text made safe to log and store: control characters become '?', at most `max` bytes.
    std::string sanitize(std::string_view text, std::size_t max = 256);

    // An object the reconcile wrote on the FortiGate (created, updated or deleted). `resource` in the
    // engine's spelling ("firewall/address") or FortiOS's cfgpath ("firewall.address"); `name` empty
    // means the whole path (a singleton such as system/global).
    struct WrittenObject {
        std::string resource;
        std::string name;
        auto operator<=>(const WrittenObject&) const = default;
    };

    // What an engine plan's operations write: their resource and key (or object.name for a create).
    // The reconcile callback can return this for the operations it applied.
    std::vector<WrittenObject> written_by(const nlohmann::json& operations);

    // Remembers, for a window after each run, what that run wrote. A config-change event that names
    // one of those objects is the FortiGate echoing the companion's own write and is ignored; anything
    // else (another object, another path, an event without attribution) is not.
    class LoopGuard {
        std::int64_t window_ms_;
        std::map<std::pair<std::string, std::string>, std::int64_t> until_;   // (resource, name) -> expiry

    public:
        explicit LoopGuard(std::int64_t window_ms) : window_ms_(window_ms) {}
        void set_window(std::int64_t window_ms) { window_ms_ = window_ms; }
        void record(std::int64_t now_ms, const std::vector<WrittenObject>& written);
        [[nodiscard]] bool suppresses(std::int64_t now_ms, const ConfigEvent& event) const;
        void prune(std::int64_t now_ms);
        [[nodiscard]] std::size_t size() const { return until_.size(); }
    };

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_EVENTS_HPP
