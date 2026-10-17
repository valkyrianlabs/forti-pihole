//
// The FortiGate side of the receiver: an automation stitch that calls forti-piholed on every config
// change. Pure functions that build forti-engine plan operations ({"op": "create", "resource": ...,
// "object": ...}); nothing here talks to a device. Attribute names and limits follow the FortiOS 7.4.8
// schema (forti-api codegen/schema/7.4.8/cmdb/system/automation-{trigger,action,stitch}.json):
//
//   system/automation-trigger  <prefix>sync-event    trigger-type event-based, event-type config-change
//   system/automation-action   <prefix>sync-webhook  action-type webhook, protocol, method post, uri,
//                                                     port, http-headers (Authorization, Content-Type),
//                                                     http-body (webhook_body())
//   system/automation-stitch   <prefix>sync          trigger + actions[{id 1, action, required enable}]
//
// Each carries the description "managed by forti-pihole" (the ownership marker; automation objects
// have `description`, not `comment`). FortiOS's `uri` is host and path without the scheme (the scheme
// comes from `protocol`, the port from `port`).
//
// The create operations embed the bearer token in the action's http-headers, so a plan built from
// them is secret-bearing: keep it out of logs and output. These are system/* writes, outside the
// guard transport's address/addrgrp allowlist (AGENTS.md rule 2); applying them needs that
// allowlist widened by a recorded decision, or the operator applying the plan with `forti`.
//

#ifndef FORTI_PIHOLED_STITCH_HPP
#define FORTI_PIHOLED_STITCH_HPP

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>

namespace fph::daemon {

    class StitchError : public std::invalid_argument {
    public:
        using std::invalid_argument::invalid_argument;
    };

    struct WebhookTarget {
        std::string host;                            // the daemon's address as the FortiGate reaches it
        unsigned port = 8735;
        std::string protocol = "http";               // "http" or "https" (https needs a TLS proxy in 0.1)
        std::string path = "/v1/fortigate/events";
        bool verify_host_cert = true;                // https only
    };

    struct StitchNames {
        std::string trigger, action, stitch;
    };

    // Throws StitchError when a name would exceed FortiOS's limits (35 for triggers and stitches).
    StitchNames stitch_names(std::string_view prefix = "fp-");

    // The http-body template: a JSON object of %%log.<field>%% variables (see events.hpp).
    std::string webhook_body();

    // trigger, action, stitch (in dependency order). Throws StitchError on an invalid target or token.
    nlohmann::json stitch_create_operations(const WebhookTarget& target, std::string_view token, std::string_view prefix = "fp-");

    // The inverse: stitch, action, trigger. Delete only what is_managed() confirms on the live device.
    nlohmann::json stitch_delete_operations(std::string_view prefix = "fp-");

    // A live automation object carries the ownership marker (its description).
    bool is_managed(const nlohmann::json& object);

}  // namespace fph::daemon

#endif  // FORTI_PIHOLED_STITCH_HPP
