#include "stitch.hpp"

#include "token.hpp"

#include <algorithm>
#include <format>

namespace fph::daemon {

    using json = nlohmann::json;

    namespace {

        // config.hpp's fph::marker; repeated so the daemon library does not depend on the CLI's core.
        constexpr std::string_view marker = "managed by forti-pihole";

        // FortiOS 7.4.8 sizes: automation-trigger/stitch name 35, automation-action name 64,
        // uri 1023, http-body 4095.
        constexpr std::size_t trigger_name_max = 35, stitch_name_max = 35, action_name_max = 64;
        constexpr std::size_t uri_max = 1023, body_max = 4095;

        // The fields the receiver reads (events.hpp), all present in config-change logs 44544-44547.
        // Values are quoted, as in Fortinet's own JSON body examples, on the reading that FortiOS
        // substitutes the bare text (events.hpp copes when a value breaks the JSON). cfgattr is left
        // out on purpose: it can
        // be 4 KiB, it is not needed for attribution, and for credential attributes it carries ENC
        // blobs that have no business in a webhook.
        constexpr const char* body_fields[] = {"logid", "eventtime", "vd", "user", "ui", "action", "cfgtid", "cfgpath", "cfgobj", "logdesc"};

        bool valid_prefix(std::string_view prefix) {
            return prefix.size() >= 2 && prefix.size() <= 24 && std::ranges::all_of(prefix, [](char c) {
                       return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
                   });
        }

        std::string uri_host(const std::string& host) {
            if (host.empty() || host.size() > 253) throw StitchError("webhook host: required (at most 253 characters)");
            if (!std::ranges::all_of(host, [](char c) {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':' ||
                           c == '[' || c == ']';
                }))
                throw StitchError("webhook host: a hostname or IP address, without scheme, port or path");
            // An IPv6 literal needs brackets in a URI.
            if (host.find(':') != std::string::npos && host.front() != '[') return "[" + host + "]";
            return host;
        }

    }  // namespace

    StitchNames stitch_names(std::string_view prefix) {
        if (!valid_prefix(prefix)) throw StitchError("prefix: 2-24 characters of [A-Za-z0-9_-]");
        StitchNames names{std::format("{}sync-event", prefix), std::format("{}sync-webhook", prefix), std::format("{}sync", prefix)};
        if (names.trigger.size() > trigger_name_max || names.stitch.size() > stitch_name_max || names.action.size() > action_name_max)
            throw StitchError("prefix: too long for FortiOS automation object names");
        return names;
    }

    std::string webhook_body() {
        std::string body = "{\"source\":\"fortigate\"";
        for (const auto* field: body_fields) body += std::format(",\"{}\":\"%%log.{}%%\"", field, field);
        return body + "}";
    }

    json stitch_create_operations(const WebhookTarget& target, std::string_view token, std::string_view prefix) {
        auto names = stitch_names(prefix);
        if (target.protocol != "http" && target.protocol != "https") throw StitchError("webhook protocol: http or https");
        if (target.port < 1 || target.port > 65535) throw StitchError("webhook port: 1..65535");
        if (target.path.empty() || target.path.front() != '/' ||
            !std::ranges::all_of(target.path, [](char c) { return c > 0x20 && c < 0x7f && c != '%'; }))
            throw StitchError("webhook path: an absolute path without spaces or escapes");
        if (!valid_token(token)) throw StitchError("webhook token: not a valid token");
        auto uri = uri_host(target.host) + target.path;
        if (uri.size() > uri_max) throw StitchError("webhook uri: too long for FortiOS (1023)");
        auto body = webhook_body();
        if (body.size() > body_max) throw StitchError("webhook body: too long for FortiOS (4095)");

        json trigger = {{"name", names.trigger},
                        {"description", marker},
                        {"trigger-type", "event-based"},
                        {"event-type", "config-change"}};
        json action = {{"name", names.action},
                       {"description", marker},
                       {"action-type", "webhook"},
                       {"protocol", target.protocol},
                       {"method", "post"},
                       {"uri", uri},
                       {"port", target.port},
                       {"http-headers", json::array({{{"id", 1}, {"key", "Authorization"}, {"value", std::format("Bearer {}", token)}},
                                                     {{"id", 2}, {"key", "Content-Type"}, {"value", "application/json"}}})},
                       {"http-body", body}};
        if (target.protocol == "https") action["verify-host-cert"] = target.verify_host_cert ? "enable" : "disable";
        json stitch = {{"name", names.stitch},
                       {"description", marker},
                       {"status", "enable"},
                       {"trigger", names.trigger},
                       {"actions", json::array({{{"id", 1}, {"action", names.action}, {"delay", 0}, {"required", "enable"}}})}};
        return json::array({{{"op", "create"}, {"resource", "system/automation-trigger"}, {"object", trigger}},
                            {{"op", "create"}, {"resource", "system/automation-action"}, {"object", action}},
                            {{"op", "create"}, {"resource", "system/automation-stitch"}, {"object", stitch}}});
    }

    json stitch_delete_operations(std::string_view prefix) {
        auto names = stitch_names(prefix);
        // The stitch references the trigger and the action, so it goes first.
        return json::array({{{"op", "delete"}, {"resource", "system/automation-stitch"}, {"key", names.stitch}},
                            {{"op", "delete"}, {"resource", "system/automation-action"}, {"key", names.action}},
                            {{"op", "delete"}, {"resource", "system/automation-trigger"}, {"key", names.trigger}}});
    }

    bool is_managed(const json& object) {
        if (!object.is_object()) return false;
        auto it = object.find("description");
        return it != object.end() && it->is_string() && it->get<std::string>().find(marker) != std::string::npos;
    }

}  // namespace fph::daemon
