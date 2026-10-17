#include "migrate.hpp"

#include <algorithm>
#include <format>

namespace fph {

    using json = nlohmann::json;

    namespace {

        bool blocks_target(const IpReference& r) {
            // A broader subnet object containing the target is normal (the LAN object); anything that
            // names the address itself means someone uses it.
            return r.kind != "subnet" && r.kind != "range";
        }

        json reach_json(const Reach& r) {
            return {{"internet", {{"action", r.internet.action}, {"policy", r.internet.policy}}},
                    {"dns", {{"action", r.dns.action}, {"policy", r.dns.policy}}}};
        }

    }  // namespace

    std::string reservation_description(const SliceAction& action) {
        std::string label;
        for (char c: action.label)
            if (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') label += c;
        if (label.size() > 64) label.resize(64);
        return std::format("{}: {} in {} ({})", marker, label, action.group, action.slice);
    }

    json reservation_operations(const SliceAction& action, const std::string& description) {
        json ops = json::array();
        std::string server = std::to_string(action.dhcp_server);
        if (action.reservation_id) {
            ops.push_back({{"op", "update"}, {"resource", "system.dhcp/server"}, {"parent", server}, {"child", "reserved-address"},
                           {"key", std::to_string(*action.reservation_id)},
                           {"set", {{"ip", action.to_ip}, {"action", "reserved"}, {"description", description}}}});
        } else {
            ops.push_back({{"op", "create"}, {"resource", "system.dhcp/server"}, {"parent", server}, {"child", "reserved-address"},
                           {"object", {{"id", 0}, {"type", "mac"}, {"mac", action.mac}, {"ip", action.to_ip}, {"action", "reserved"},
                                       {"description", description}}}});
        }
        return ops;
    }

    json object_operations(const std::vector<std::string>& objects, const std::string& ip) {
        json ops = json::array();
        for (const auto& name: objects)
            ops.push_back({{"op", "update"}, {"resource", "firewall/address"}, {"key", name}, {"set", {{"subnet", ip + " 255.255.255.255"}}}});
        return ops;
    }

    json revoke_operation(const std::string& ip) {
        // monitor/system/dhcp/revoke: revoke the listed leases (FortiOS 7.4 REST API).
        return {{"op", "action"}, {"resource", "monitor/system/dhcp/revoke"}, {"body", {{"ip", json::array({ip})}}}};
    }

    MigrationPlan plan_migration(const Config& config, const Snapshot& snapshot, const SliceAction& action, const Adoptions& adoptions,
                                 std::int64_t now) {
        MigrationPlan plan;
        auto refuse = [&](std::string reason, std::vector<std::string> needs = {}) {
            plan.refusal = {std::move(reason), std::move(needs)};
            return plan;
        };
        if (action.kind != "move") return refuse("not a move");
        const Device* device = snapshot.device(action.mac);
        if (!device) return refuse(std::format("{} is not in the inventory", action.mac));

        plan.old_references = references_to(snapshot, action.from_ip);
        plan.new_references = references_to(snapshot, action.to_ip);

        for (const auto& r: plan.new_references)
            if (blocks_target(r) && !(r.kind == "lease" && r.detail == action.mac))
                return refuse(std::format("target {} is in use: {} {} {}", action.to_ip, r.kind, r.name, r.detail));
        for (const auto& r: plan.old_references)
            if (r.kind == "vip")
                return refuse(std::format("VIP {} forwards to {} ({}); a port forward follows the address, not the device", r.name,
                                          action.from_ip, r.detail),
                              {"move or remove the VIP first"});

        if (action.reservation_id && !action.reservation_managed && !adoptions.reservation)
            return refuse(std::format("{}'s reservation {} is an administrator's; adopt it to let forti-pihole change it", action.label,
                                      *action.reservation_id),
                          {"--adopt-reservation"});

        std::vector<std::string> follow;
        std::vector<std::string> needs;
        for (const auto* host: privileged_hosts(plan.old_references)) {
            if (adoptions.address_objects.contains(host->name)) follow.push_back(host->name);
            else {
                std::string policies;
                for (const auto& p: host->policies)
                    if (p.source && p.enabled) policies += std::format("{}{} \"{}\"", policies.empty() ? "" : ", ", p.id, p.name);
                needs.push_back(std::format("--update-object \"{}\" (source of policy {})", host->name, policies));
            }
        }
        if (!needs.empty())
            return refuse(std::format("{} is privileged by address: the objects below would keep those privileges on {} for whoever "
                                      "gets it next",
                                      action.from_ip, action.from_ip),
                          needs);

        // What the migration leaves as it is, so the report can say so.
        for (const auto& r: plan.old_references)
            if (r.kind == "range" || (r.kind == "host" && !std::ranges::contains(follow, r.name)))
                plan.notes.push_back(std::format("{} {} ({}) still contains {} afterwards", r.kind, r.name, r.detail, action.from_ip));

        plan.before = evaluate(snapshot, *device);

        Operation op;
        op.id = new_operation_id(now);
        op.kind = "migrate";
        op.created = now;
        op.subject = {{"mac", action.mac}, {"label", action.label}, {"group", action.group}, {"interface", action.interface},
                      {"slice", action.slice}, {"from_ip", action.from_ip}, {"to_ip", action.to_ip},
                      {"dhcp_server", action.dhcp_server}, {"reservation_id", action.reservation_id ? json(*action.reservation_id) : json()},
                      {"objects", follow}, {"before", reach_json(plan.before)}};
        const DeviceGroup* group = config.group(action.group);

        Step pihole;
        pihole.id = "pihole";
        pihole.description = std::format("Pi-hole: {} -> group \"{}\"", action.slice, group ? group->pihole_group : "");
        pihole.forward = {{"cidr", action.slice}, {"pihole_group", group ? group->pihole_group : ""}, {"interface", action.interface}};
        op.steps.push_back(pihole);

        Step reservation;
        reservation.id = "reservation";
        reservation.description = action.reservation_id
                                          ? std::format("DHCP reservation {}: {} -> {}", *action.reservation_id, action.from_ip, action.to_ip)
                                          : std::format("DHCP reservation for {}: {}", action.mac, action.to_ip);
        reservation.forward = {{"operations", reservation_operations(action, reservation_description(action))},
                               {"revoke_on_undo", action.to_ip}};
        op.steps.push_back(reservation);

        if (!follow.empty()) {
            Step objects;
            objects.id = "objects";
            std::string names;
            for (const auto& n: follow) names += (names.empty() ? "" : ", ") + n;
            objects.description = std::format("address objects {}: {} -> {}", names, action.from_ip, action.to_ip);
            objects.forward = {{"operations", object_operations(follow, action.to_ip)}};
            op.steps.push_back(objects);
        }

        Step revoke;
        revoke.id = "revoke";
        revoke.description = std::format("revoke the lease on {} (only this device's)", action.from_ip);
        revoke.forward = {{"operation", revoke_operation(action.from_ip)}, {"mac", action.mac}};
        op.steps.push_back(revoke);

        Step observe;
        observe.id = "observe";
        observe.description = std::format("wait for {} to take {}", action.label, action.to_ip);
        observe.forward = {{"mac", action.mac}, {"ip", action.to_ip}, {"timeout_s", 180}, {"poll_s", 5}};
        op.steps.push_back(observe);

        Step verify;
        verify.id = "verify";
        verify.description = "verify lease, firewall reach and Pi-hole group";
        verify.forward = {{"mac", action.mac}, {"ip", action.to_ip}, {"pihole_group", group ? group->pihole_group : ""},
                          {"before", reach_json(plan.before)}};
        op.steps.push_back(verify);

        plan.operation = std::move(op);
        return plan;
    }

}  // namespace fph
