#include "executors.hpp"

#include "connectivity.hpp"
#include "inventory.hpp"
#include "mac.hpp"

#include <algorithm>
#include <format>

namespace fph {

    using json = nlohmann::json;

    namespace {

        std::string text(const json& j) { return j.is_string() ? j.get<std::string>() : j.dump(); }

        std::uint64_t id_of(const json& j) {
            try {
                return j.is_number_unsigned() ? j.get<std::uint64_t>() : static_cast<std::uint64_t>(std::stoull(text(j)));
            } catch (...) {
                return 0;
            }
        }

        json base(const Config& config) {
            json request = json::object();
            if (!config.profile.empty()) request["profile"] = config.profile;
            if (!config.vdom.empty()) request["vdom"] = config.vdom;
            return request;
        }

        json permits_json(const WritePermits& p) {
            json reservations = json::array();
            for (const auto& [s, e]: p.reservations) reservations.push_back({s, e});
            return {{"dhcp_servers", p.dhcp_servers}, {"reservations", reservations}, {"address_objects", p.address_objects},
                    {"revoke_ips", p.revoke_ips}};
        }

        WritePermits permits_from(const json& j) {
            WritePermits p;
            for (const auto& s: j.value("dhcp_servers", json::array())) p.dhcp_servers.insert(s.get<std::uint64_t>());
            for (const auto& r: j.value("reservations", json::array())) p.reservations.insert({r[0].get<std::uint64_t>(), r[1].get<std::uint64_t>()});
            for (const auto& o: j.value("address_objects", json::array())) p.address_objects.insert(o.get<std::string>());
            for (const auto& i: j.value("revoke_ips", json::array())) p.revoke_ips.insert(i.get<std::string>());
            return p;
        }

        std::optional<Lease> lease_for(Runtime& rt, const std::string& mac) {
            auto request = base(rt.config);
            request["resource"] = "monitor/system/dhcp";
            auto leases = read_all(rt.gateway, request);
            for (const auto& l: leases) {
                auto m = normalize_mac(l.value("mac", std::string()));
                if (m && *m == mac && l.value("type", std::string("ipv4")) == "ipv4")
                    return Lease{l.value("ip", std::string()), *m, l.value("hostname", std::string()), l.value("interface", std::string()),
                                 l.value("reserved", false), 0};
            }
            return std::nullopt;
        }

        StepOutcome revoke_now(Runtime& rt, const std::string& ip) {
            json op = json::array({{{"op", "action"}, {"resource", "monitor/system/dhcp/revoke"}, {"body", {{"ip", json::array({ip})}}}}});
            WritePermits p;
            p.revoke_ips = {ip};
            return engine_apply(rt, op, p, json::object());
        }

    }  // namespace

    WritePermits permits_for(const json& operations) {
        WritePermits p;
        for (const auto& op: operations) {
            auto resource = op.value("resource", std::string());
            if (resource == "system.dhcp/server" && op.contains("parent")) {
                auto server = id_of(op["parent"]);
                p.dhcp_servers.insert(server);
                if (op.contains("key")) p.reservations.insert({server, id_of(op["key"])});
            } else if (resource == "firewall/address" && op.value("op", std::string()) == "update") {
                p.address_objects.insert(op.value("key", std::string()));
            } else if (resource == "monitor/system/dhcp/revoke") {
                for (const auto& ip: op.value("body", json::object()).value("ip", json::array())) p.revoke_ips.insert(text(ip));
            }
        }
        return p;
    }

    StepOutcome engine_apply(Runtime& rt, const json& operations, const WritePermits& granted, const json& previous) {
        std::string plan_id = previous.value("plan_id", std::string());
        if (plan_id.empty() || previous.value("applied", false)) {
            auto request = base(rt.config);
            request["operations"] = operations;
            auto planned = rt.gateway.plan(request);
            if (!planned.value("ok", false))
                return {StepOutcome::Kind::failed, json::object(), json(), "planning failed: " + planned["error"].value("message", std::string())};
            plan_id = planned["data"].value("id", std::string());
        }
        json applied;
        {
            PermitScope scope(rt.permits, granted);
            applied = rt.gateway.apply({{"plan_id", plan_id}});
        }
        if (!applied.value("ok", false)) {
            auto code = applied["error"].value("code", std::string());
            if (code == "approval_required")
                return {StepOutcome::Kind::waiting, json{{"plan_id", plan_id}}, json(),
                        std::format("waiting for approval: forti approve {}", plan_id)};
            return {StepOutcome::Kind::failed, json{{"plan_id", plan_id}, {"error", applied["error"]}}, json(),
                    std::format("apply {} failed ({}): {}", plan_id, code, applied["error"].value("message", std::string()))};
        }
        json result = {{"plan_id", plan_id}, {"applied", true}, {"record", applied["data"].value("operations", json::array())}};
        if (applied["data"].contains("rollback")) result["rollback_plan"] = applied["data"]["rollback"].value("plan_id", std::string());
        return {StepOutcome::Kind::done, result, json(), {}};
    }

    MigrationExecutors::MigrationExecutors(Runtime& runtime) : rt_(runtime) {
        // pihole: the slice's managed CIDR entry.
        pihole_.forward = [this](const Step& step) -> StepOutcome {
            if (!rt_.pihole) return {StepOutcome::Kind::failed, json::object(), json(), "Pi-hole is not configured"};
            auto cidr = step.forward.value("cidr", std::string());
            auto group_name = step.forward.value("pihole_group", std::string());
            auto view = rt_.pihole->view();
            const PiholeGroupInfo* group = view.group(group_name);
            if (!group) return {StepOutcome::Kind::failed, json::object(), json(), std::format("Pi-hole has no group \"{}\"", group_name)};
            for (const auto& c: view.clients)
                if (c.client == cidr) {
                    if (!c.managed())
                        return {StepOutcome::Kind::done, json{{"existing", "operator"}, {"client_id", c.id}}, json::object(),
                                "an operator entry already maps " + cidr + "; left as it is"};
                    if (c.groups == std::vector<int>{group->id})
                        return {StepOutcome::Kind::done, json{{"existing", "managed"}, {"client_id", c.id}}, json::object(), {}};
                    auto applied = rt_.pihole->apply({{"update", cidr, group_name, c.comment, "slice", c.id, {group->id}}});
                    bool ok = !applied.empty() && applied.back().ok;
                    return {ok ? StepOutcome::Kind::done : StepOutcome::Kind::failed, json{{"updated", c.id}}, json::object(),
                            ok ? "" : applied.back().error};
                }
            std::string comment = std::format("{}: {} slice", marker, step.forward.value("interface", std::string()));
            auto applied = rt_.pihole->apply({{"create", cidr, group_name, comment, "slice", 0, {group->id}}});
            if (applied.empty() || !applied.back().ok)
                return {StepOutcome::Kind::failed, json::object(), json(), applied.empty() ? "no result" : applied.back().error};
            // Undo only what this step created.
            return {StepOutcome::Kind::done, json{{"created", applied.back().client_id}}, json{{"delete", cidr}}, {}};
        };
        pihole_.already = [this](const Step& step) {
            if (!rt_.pihole) return false;
            auto view = rt_.pihole->view();
            const PiholeGroupInfo* g = view.group(step.forward.value("pihole_group", std::string()));
            return g && std::ranges::any_of(view.clients, [&](const auto& c) {
                       return c.client == step.forward.value("cidr", std::string()) && c.groups == std::vector<int>{g->id};
                   });
        };
        pihole_.compensate = [this](const Step& step) -> StepOutcome {
            if (!rt_.pihole) return {StepOutcome::Kind::failed, json::object(), json(), "Pi-hole is not configured"};
            auto cidr = step.compensate.value("delete", std::string());
            if (cidr.empty()) return {};
            auto applied = rt_.pihole->apply({{"delete", cidr, {}, {}, "rollback", 0, {}}});
            bool ok = !applied.empty() && applied.back().ok;
            return {ok ? StepOutcome::Kind::done : StepOutcome::Kind::failed, json::object(), json(), ok ? "" : applied.back().error};
        };

        // reservation / objects: engine operations; undo = the engine's rollback plan (+ revoke of the new lease).
        engine_.forward = [this](const Step& step) -> StepOutcome {
            const auto& ops = step.forward["operations"];
            auto outcome = engine_apply(rt_, ops, permits_for(ops), step.result);
            if (outcome.kind != StepOutcome::Kind::done) return outcome;
            // The rollback plan touches the same entries, including a device-assigned id from the record.
            auto undo = permits_for(ops);
            for (const auto& r: outcome.result.value("record", json::array()))
                if (r.value("resource", std::string()) == "system.dhcp/server" && r.contains("parent") && r.contains("key"))
                    undo.reservations.insert({id_of(r["parent"]), id_of(r["key"])});
            if (auto ip = step.forward.value("revoke_on_undo", std::string()); !ip.empty()) undo.revoke_ips.insert(ip);
            outcome.compensate = {{"rollback_plan", outcome.result.value("rollback_plan", std::string())}, {"permits", permits_json(undo)},
                                  {"revoke", step.forward.value("revoke_on_undo", std::string())}};
            return outcome;
        };
        // A step found running after a crash: done when the engine recorded the apply. Otherwise the
        // forward action re-applies the stored plan, which the engine refuses if it already ran or
        // the device changed meanwhile (stale_plan), so nothing is applied twice.
        engine_.already = [](const Step& step) { return step.result.value("applied", false); };
        engine_.compensate = [this](const Step& step) -> StepOutcome {
            auto rollback = step.compensate.value("rollback_plan", std::string());
            auto granted = permits_from(step.compensate.value("permits", json::object()));
            if (!rollback.empty()) {
                json applied;
                {
                    PermitScope scope(rt_.permits, granted);
                    applied = rt_.gateway.apply({{"plan_id", rollback}});
                }
                if (!applied.value("ok", false))
                    return {StepOutcome::Kind::failed, json::object(), json(),
                            std::format("rollback plan {} failed: {}", rollback, applied["error"].value("message", std::string()))};
            }
            if (auto ip = step.compensate.value("revoke", std::string()); !ip.empty()) {
                auto r = revoke_now(rt_, ip);
                if (r.kind != StepOutcome::Kind::done) return r;
                return {StepOutcome::Kind::done, json::object(), json(), "revoked " + ip + " so the device renews into its old address"};
            }
            return {};
        };

        revoke_.forward = [this](const Step& step) -> StepOutcome {
            const auto& op = step.forward["operation"];
            return engine_apply(rt_, json::array({op}), permits_for(json::array({op})), step.result);
        };
        revoke_.already = [this](const Step& step) {
            // Already revoked when the device no longer holds the old address.
            auto lease = lease_for(rt_, step.forward.value("mac", std::string()));
            auto old = step.forward["operation"]["body"]["ip"][0].get<std::string>();
            return !lease || lease->ip != old;
        };

        observe_.forward = [this](const Step& step) -> StepOutcome {
            auto mac = step.forward.value("mac", std::string());
            auto ip = step.forward.value("ip", std::string());
            int timeout = step.forward.value("timeout_s", 180), poll = std::max(1, step.forward.value("poll_s", 5));
            std::string seen;
            for (int waited = 0; waited <= timeout; waited += poll) {
                auto lease = lease_for(rt_, mac);
                seen = lease ? lease->ip : std::string("no lease");
                if (lease && lease->ip == ip) return {StepOutcome::Kind::done, json{{"lease", ip}, {"after_s", waited}}, json(), {}};
                if (waited + poll > timeout) break;
                rt_.sleep(poll);
            }
            // No repeated revokes: the device decides when it renews. A person reconnects it.
            return {StepOutcome::Kind::waiting, json{{"seen", seen}}, json(),
                    std::format("the device has not taken {} (it has {}); reconnect its Wi-Fi or power-cycle it, then run "
                                "forti-pihole operations resume",
                                ip, seen)};
        };
        observe_.already = [this](const Step& step) {
            auto lease = lease_for(rt_, step.forward.value("mac", std::string()));
            return lease && lease->ip == step.forward.value("ip", std::string());
        };

        verify_.forward = [this](const Step& step) -> StepOutcome {
            auto mac = step.forward.value("mac", std::string());
            auto ip = step.forward.value("ip", std::string());
            auto snapshot = collect(rt_.gateway, rt_.config, rt_.clock());
            json result = json::object();
            std::vector<std::string> problems;
            auto lease = lease_for(rt_, mac);
            result["lease"] = lease ? lease->ip : "";
            if (!lease || lease->ip != ip) problems.push_back(std::format("lease is {}, not {}", lease ? lease->ip : "missing", ip));
            if (const Device* d = snapshot.device(mac)) {
                Device moved = *d;
                moved.ip = ip;
                auto after = evaluate(snapshot, moved);
                auto before = step.forward.value("before", json::object());
                result["reach"] = {{"internet", after.internet.describe()}, {"dns", after.dns.describe()}};
                auto was = [&](const char* probe) { return before.value(probe, json::object()).value("action", std::string()); };
                if ((was("internet") == "accept") && !after.internet.reaches()) problems.push_back("lost internet reach");
                if ((was("dns") == "accept") && !after.dns.reaches()) problems.push_back("lost DNS reach");
                if (was("internet") == "accept" && after.internet.action == "accept" &&
                    before["internet"].value("policy", 0) != static_cast<int>(after.internet.policy))
                    result["note"] = std::format("internet now via policy {} (was {})", after.internet.policy, before["internet"].value("policy", 0));
            }
            if (rt_.pihole) {
                auto view = rt_.pihole->view();
                const PiholeGroupInfo* want = view.group(step.forward.value("pihole_group", std::string()));
                auto groups = rt_.pihole->effective_groups(ip);
                result["pihole_groups"] = groups;
                if (!want || groups != std::vector<int>{want->id})
                    problems.push_back(std::format("Pi-hole resolves {} to groups {} instead of \"{}\"", ip, json(groups).dump(),
                                                   step.forward.value("pihole_group", std::string())));
            }
            if (!problems.empty()) {
                std::string text;
                for (const auto& p: problems) text += (text.empty() ? "" : "; ") + p;
                return {StepOutcome::Kind::failed, result, json(), text};
            }
            return {StepOutcome::Kind::done, result, json(), {}};
        };
    }

    const StepExecutor* MigrationExecutors::operator()(const Step& step) const {
        if (step.id == "pihole") return &pihole_;
        if (step.id == "reservation" || step.id == "objects") return &engine_;
        if (step.id == "revoke") return &revoke_;
        if (step.id == "observe") return &observe_;
        if (step.id == "verify") return &verify_;
        return nullptr;
    }

}  // namespace fph
