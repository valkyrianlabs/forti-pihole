#include "sync.hpp"

#include "alloc/cidr.hpp"
#include "executors.hpp"
#include "reassociate.hpp"
#include "report.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <set>

namespace fph {

    using json = nlohmann::json;

    namespace {

        std::string iso_time(std::int64_t epoch) {
            return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::sys_seconds(std::chrono::seconds(epoch)));
        }

        json base_request(const Config& config) {
            json request = json::object();
            if (!config.profile.empty()) request["profile"] = config.profile;
            if (!config.vdom.empty()) request["vdom"] = config.vdom;
            return request;
        }

        // Observations worth keeping whatever happens to the writes: devices seen, GUI moves, candidates.
        void observe(State& state, const SyncResult& r, std::int64_t now) {
            for (const auto& d: r.snapshot.devices) {
                auto& rec = state.devices[d.mac];
                if (rec.first_seen == 0) rec.first_seen = now;
                if (d.last_seen > rec.last_seen) rec.last_seen = d.last_seen;
                if (d.online && rec.last_seen < now - 300) rec.last_seen = now;
                rec.label = d.label();
                if (!d.hostname.empty()) rec.hostname = d.hostname;
                if (!d.vendor.empty()) rec.vendor = d.vendor;
                if (!d.family.empty()) rec.family = d.family;
                if (!d.os.empty()) rec.os = d.os;
                if (!d.os_version.empty()) rec.os_version = d.os_version;
                rec.randomized = d.randomized;
            }
            for (const auto& [mac, pin]: r.classification.new_pins) state.pins[mac] = pin;
            for (const auto& mac: r.classification.cleared_pins) state.pins.erase(mac);
            for (const auto& k: r.found) state.candidates.push_back(k);
            std::erase_if(state.candidates, [&](const Candidate& k) { return now - k.found_at > 30 * 86400; });
        }

        void commit(State& state, const std::map<std::string, Written>& written, const std::vector<std::string>& retired) {
            for (const auto& [mac, w]: written) {
                auto& rec = state.devices[mac];
                rec.object = w.object;
                rec.written_group = w.group;
            }
            for (const auto& mac: retired) {
                state.devices.erase(mac);
                state.pins.erase(mac);
                state.retire_now.erase(mac);
                state.adoptions.erase(mac);
            }
        }

        void commit_pending(State& state) {
            if (!state.pending) return;
            std::map<std::string, Written> written;
            for (const auto& [mac, entry]: state.pending->written) written[mac] = {entry.first, entry.second};
            commit(state, written, state.pending->retired);
            state.pending.reset();
        }

        void note_written(SyncResult& r, const json& operations) {
            for (const auto& op: operations) {
                auto name = op.contains("key") ? (op["key"].is_string() ? op["key"].get<std::string>() : op["key"].dump())
                                               : op.value("object", json::object()).value("name", std::string());
                r.written.push_back({{"resource", op.value("resource", std::string())}, {"name", name}});
            }
        }

        void history(const SyncContext& ctx, const std::string& stage, const StageResult& s, std::int64_t now, json extra = json::object()) {
            json entry = {{"time", iso_time(now)}, {"epoch", now}, {"stage", stage}, {"status", s.status}, {"summary", s.detail}};
            if (!s.plan_id.empty()) entry["plan_id"] = s.plan_id;
            if (!s.rollback_plan.empty()) entry["rollback_plan"] = s.rollback_plan;
            for (auto it = extra.begin(); it != extra.end(); ++it) entry[it.key()] = it.value();
            append_history(ctx.home.history(), entry);
        }

        std::string summary_of(const Changeset& changes) {
            std::map<std::string, int> counts;
            for (const auto& c: changes.changes) ++counts[c.kind];
            std::string out;
            for (const auto& [kind, n]: counts) out += std::format("{}{} {}", out.empty() ? "" : ", ", n, kind);
            return out.empty() ? "no changes" : out;
        }

        // Stage 1: managed FortiGate objects (the original apply flow, with guarded pending plans).
        StageResult apply_objects(SyncContext& ctx, State& state, SyncResult& r, std::int64_t now) {
            StageResult s{"objects", "in-sync", {}, {}, {}};
            if (state.pending && now - state.pending->at < 86400) {
                auto applied = ctx.gateway.apply({{"plan_id", state.pending->plan_id}});
                if (applied.value("ok", false)) {
                    s.plan_id = state.pending->plan_id;
                    commit_pending(state);
                    state.last_apply = now;
                    state.last_plan = s.plan_id;
                    s.status = "applied";
                    s.detail = "pending plan applied after approval";
                    history(ctx, "objects", s, now);
                    return s;   // the next run plans again from fresh reads
                }
                if (applied["error"].value("code", std::string()) == "approval_required") {
                    s.status = "waiting";
                    s.plan_id = state.pending->plan_id;
                    s.detail = "waiting for approval: forti approve " + s.plan_id;
                    return s;
                }
                // Stale, unknown or already executed: plan again. Its placements stay "ours" until a
                // later apply completes.
            }
            if (r.objects.empty()) {
                commit(state, r.objects.written, r.objects.retired);
                state.pending.reset();
                return s;
            }
            json request = base_request(ctx.config);
            request["operations"] = r.objects.operations;
            auto planned = ctx.gateway.plan(request);
            if (!planned.value("ok", false)) {
                s.status = "failed";
                s.detail = "planning failed: " + planned["error"].value("message", std::string());
                return s;
            }
            s.plan_id = planned["data"].value("id", std::string());
            Pending pending;
            pending.plan_id = s.plan_id;
            pending.at = now;
            for (const auto& [mac, w]: r.objects.written) pending.written[mac] = {w.object, w.group};
            pending.retired = r.objects.retired;
            state.pending = pending;
            save_state(ctx.home.state(), state);   // before the apply: a crash now keeps the placements "ours"
            auto applied = ctx.gateway.apply({{"plan_id", s.plan_id}});
            if (applied.value("ok", false)) {
                commit_pending(state);
                state.last_apply = now;
                state.last_plan = s.plan_id;
                s.status = "applied";
                s.detail = summary_of(r.objects);
                // The engine reports "rollback": {"plan_id": null} when there is nothing to undo.
                if (auto rb = applied["data"].value("rollback", json::object()); rb.is_object() && rb.value("plan_id", json()).is_string())
                    s.rollback_plan = rb["plan_id"].get<std::string>();
                note_written(r, r.objects.operations);
            } else {
                auto code = applied["error"].value("code", std::string());
                // A guarded profile waits for a person; a read-only one refuses by the operator's policy.
                // Both are decisions, not failures (exit 7, as the engine's codes say).
                s.status = code == "approval_required" || code == "policy_denied" ? "waiting" : "failed";
                s.detail = code == "approval_required" ? "waiting for approval: forti approve " + s.plan_id
                           : code == "policy_denied"   ? "the forti profile is read-only: nothing applied (plan " + s.plan_id + ")"
                                                       : std::format("{}: {}", code, applied["error"].value("message", std::string()));
            }
            history(ctx, "objects", s, now);
            return s;
        }

        // Stage 2: Pi-hole managed entries.
        StageResult apply_pihole(SyncContext& ctx, SyncResult& r, std::int64_t now, PiholeApi* api) {
            StageResult s{"pihole", "in-sync", {}, {}, {}};
            if (!api || !r.pihole) {
                s.status = "skipped";
                s.detail = r.pihole_error.empty() ? "Pi-hole not configured" : r.pihole_error;
                return s;
            }
            if (r.pihole->changes.empty()) return s;
            auto applied = api->apply(r.pihole->changes);
            int ok = 0;
            for (const auto& a: applied)
                if (a.ok) ++ok;
            s.status = ok == static_cast<int>(r.pihole->changes.size()) ? "applied" : "failed";
            s.detail = std::format("{} of {} client entr{} changed", ok, r.pihole->changes.size(), r.pihole->changes.size() == 1 ? "y" : "ies");
            if (!applied.empty() && !applied.back().ok) s.detail += ": " + applied.back().error;
            history(ctx, "pihole", s, now);
            return s;
        }

        // Stage 3: reservations at the address a device already holds inside its slice.
        StageResult apply_reservations(SyncContext& ctx, SyncResult& r, std::int64_t now, int budget) {
            StageResult s{"reservations", "in-sync", {}, {}, {}};
            json operations = json::array();
            int skipped = 0;
            for (const auto& a: r.slicing.actions) {
                if (a.kind != "reserve") continue;
                const Network* network = ctx.config.network(a.interface);
                if (!network || !network->manage_reservations) continue;
                if (a.reservation_id) {
                    ++skipped;   // an existing reservation elsewhere: that is a move, handled by migrations
                    continue;
                }
                if (static_cast<int>(operations.size()) >= budget) break;
                for (const auto& op: reservation_operations(a, reservation_description(a))) operations.push_back(op);
            }
            if (operations.empty()) return s;
            Runtime rt{ctx.gateway, ctx.permits, nullptr, ctx.config, ctx.clock, ctx.sleep};
            auto outcome = engine_apply(rt, operations, permits_for(operations), json::object());
            s.status = outcome.kind == StepOutcome::Kind::done ? "applied" : outcome.kind == StepOutcome::Kind::waiting ? "waiting" : "failed";
            s.plan_id = outcome.result.value("plan_id", std::string());
            s.rollback_plan = outcome.result.value("rollback_plan", std::string());
            s.detail = outcome.kind == StepOutcome::Kind::done ? std::format("{} reservation(s) added at current addresses", operations.size())
                                                                : outcome.message;
            if (outcome.kind == StepOutcome::Kind::done) note_written(r, operations);
            (void) skipped;
            history(ctx, "reservations", s, now);
            return s;
        }

    }  // namespace

    SyncResult run_sync(SyncContext& ctx, State& state, const SyncOptions& options) {
        SyncResult r;
        const auto& config = ctx.config;
        auto now = ctx.clock();

        // Reads.
        r.snapshot = collect(ctx.gateway, config, now);
        r.classification = classify(r.snapshot, config, state, now);
        r.found = find_candidates(r.snapshot, state, r.classification, now);
        r.candidates = state.candidates;
        for (const auto& k: r.found) r.candidates.push_back(k);
        r.objects = reconcile(r.snapshot, r.classification, config, state, now, options.max_changes);
        r.slicing = plan_slicing(config, r.snapshot, r.classification);

        PiholeApi* api = nullptr;
        if (!config.pihole.url.empty()) {
            try {
                api = ctx.pihole ? ctx.pihole() : nullptr;
                if (api) {
                    PiholeSyncOptions po;
                    po.most_specific_wins = true;   // FTL resolves the longest matching prefix (pihole/resolve.hpp)
                    po.prune = options.prune;
                    po.complement = complement_strings;
                    r.pihole = plan_pihole(config, r.snapshot, api->view(), po);
                    // How Pi-hole resolves each managed range today (first address), with FTL's own rules:
                    // a mismatch means an operator entry shadows it, or the entry is not there yet.
                    for (const auto& d: r.pihole->desired) {
                        auto cidr = alloc::Cidr::parse(d.cidr);
                        if (!cidr) continue;
                        auto probe = alloc::format_ipv4(cidr->prefix >= 31 ? cidr->network : cidr->network + 1);
                        auto groups = api->effective_groups(probe);
                        auto view = api->view();
                        const PiholeGroupInfo* want = view.group(d.pihole_group);
                        bool pending = std::ranges::any_of(r.pihole->changes, [&](const PiholeChange& c) { return c.cidr == d.cidr; });
                        if (want && groups != std::vector<int>{want->id} && !pending) {
                            std::string names;
                            for (int id: groups) {
                                const PiholeGroupInfo* g = view.group(id);
                                names += (names.empty() ? "" : ", ") + (g ? g->name : std::to_string(id));
                            }
                            r.pihole->findings.push_back({"resolution", d.cidr,
                                                          std::format("Pi-hole resolves {} to [{}], not \"{}\"", probe, names, d.pihole_group), 0});
                        }
                    }
                }
            } catch (const std::exception& e) {
                r.pihole_error = e.what();
            }
        }

        // Moves this run would make: planned (and refused ones explained) whether or not anything is written.
        Journal journal(ctx.home.dir / "operations");
        auto open = journal.open();
        std::set<std::string> busy;
        for (const auto& op: open) busy.insert(op.subject.value("mac", std::string()));
        for (const auto& a: r.slicing.actions) {
            if (a.kind != "move" || busy.contains(a.mac)) continue;
            Adoptions adopt;
            if (auto it = state.adoptions.find(a.mac); it != state.adoptions.end()) {
                adopt.address_objects = it->second.objects;
                adopt.reservation = it->second.reservation;
            }
            r.migrations.push_back(plan_migration(config, r.snapshot, a, adopt, now));
        }

        if (!options.apply) {
            r.status = "planned";
            observe(state, r, now);
            return r;
        }
        if (!config.enabled) {
            r.status = "disabled";
            r.exit_code = 7;
            observe(state, r, now);
            return r;
        }
        if (options.paused) {
            r.status = "paused";
            observe(state, r, now);
            return r;
        }
        observe(state, r, now);

        r.stages.push_back(apply_objects(ctx, state, r, now));
        r.stages.push_back(apply_pihole(ctx, r, now, api));
        r.stages.push_back(apply_reservations(ctx, r, now, options.max_changes));

        if (options.migrations) {
            Runtime rt{ctx.gateway, ctx.permits, api, config, ctx.clock, ctx.sleep};
            MigrationExecutors executors(rt);
            auto pick = [&](const Step& step) { return executors(step); };
            StageResult resumed{"migrations", "in-sync", {}, {}, {}};
            for (auto& op: open) {
                if (op.status != "waiting" && op.status != "running") continue;   // failed ones wait for a person
                auto status = run_operation(op, journal, pick, ctx.clock);
                r.operations.push_back(op.id);
                resumed.status = status == "done" ? "applied" : status;
                resumed.detail += std::format("{}{} {} ({})", resumed.detail.empty() ? "" : "; ", op.id, status,
                                              op.subject.value("label", std::string()));
            }
            int started = 0;
            for (auto& m: r.migrations) {
                if (!m.operation || started >= options.max_migrations) continue;
                const Network* network = config.network(m.operation->subject.value("interface", std::string()));
                if (!network || !network->manage_reservations) continue;
                journal.save(*m.operation, ctx.clock());
                auto status = run_operation(*m.operation, journal, pick, ctx.clock);
                ++started;
                r.operations.push_back(m.operation->id);
                for (const auto& step: m.operation->steps)
                    if ((step.status == "done" || step.status == "waiting") && step.forward.contains("operations"))
                        note_written(r, step.forward["operations"]);
                resumed.status = status == "done" ? "applied" : status;
                resumed.detail += std::format("{}{} {} ({} {} -> {})", resumed.detail.empty() ? "" : "; ", m.operation->id, status,
                                              m.operation->subject.value("label", std::string()),
                                              m.operation->subject.value("from_ip", std::string()),
                                              m.operation->subject.value("to_ip", std::string()));
            }
            if (!resumed.detail.empty()) history(ctx, "migrations", resumed, now, {{"operations", r.operations}});
            r.stages.push_back(resumed);
        }

        r.status = "applied";
        for (const auto& s: r.stages) {
            if (s.status == "failed") {
                r.status = "failed";
                r.exit_code = 6;
            } else if (s.status == "waiting" && r.status != "failed") {
                r.status = "waiting";
                r.exit_code = 7;
            }
        }
        if (!r.pihole_error.empty() && r.status == "applied") r.status = "applied";   // reported, FortiGate side unaffected
        return r;
    }

    json sync_json(const SyncResult& r, const Config& config, std::int64_t now) {
        Run run{&r.snapshot, &r.classification, &r.objects, &r.candidates, &config, now};
        json out = report_json(run);
        out["status"] = r.status;
        json pihole = json::object();
        if (r.pihole) {
            json changes = json::array(), findings = json::array(), desired = json::array();
            for (const auto& c: r.pihole->changes)
                changes.push_back({{"kind", c.kind}, {"cidr", c.cidr}, {"pihole_group", c.pihole_group}, {"why", c.why}, {"client_id", c.client_id}});
            for (const auto& f: r.pihole->findings) findings.push_back({{"kind", f.kind}, {"client", f.client}, {"detail", f.detail}});
            for (const auto& d: r.pihole->desired)
                desired.push_back({{"cidr", d.cidr}, {"pihole_group", d.pihole_group}, {"interface", d.interface}, {"why", d.why}});
            pihole = {{"desired", desired}, {"changes", changes}, {"findings", findings}};
        }
        if (!r.pihole_error.empty()) pihole["error"] = r.pihole_error;
        out["pihole"] = pihole;
        json slicing = json::array(), sfind = json::array();
        for (const auto& a: r.slicing.actions)
            slicing.push_back({{"kind", a.kind}, {"mac", a.mac}, {"label", a.label}, {"group", a.group}, {"interface", a.interface},
                               {"from", a.from_ip}, {"to", a.to_ip}, {"slice", a.slice}, {"why", a.why}});
        for (const auto& f: r.slicing.findings) sfind.push_back({{"kind", f.kind}, {"interface", f.interface}, {"mac", f.mac}, {"detail", f.detail}});
        out["slicing"] = {{"actions", slicing}, {"findings", sfind}};
        json migrations = json::array();
        for (const auto& m: r.migrations) {
            json item = {{"refused", !m.operation.has_value()}, {"notes", m.notes}};
            if (m.operation) item["operation"] = m.operation->to_json();
            else item["refusal"] = {{"reason", m.refusal.reason}, {"needs", m.refusal.needs}};
            migrations.push_back(std::move(item));
        }
        out["migrations"] = migrations;
        json stages = json::array();
        for (const auto& s: r.stages)
            stages.push_back({{"stage", s.stage}, {"status", s.status}, {"detail", s.detail}, {"plan_id", s.plan_id}, {"rollback_plan", s.rollback_plan}});
        out["stages"] = stages;
        out["operations"] = r.operations;
        return out;
    }

    std::string sync_text(const SyncResult& r, const Config& config, std::int64_t now, bool verbose) {
        Run run{&r.snapshot, &r.classification, &r.objects, &r.candidates, &config, now};
        std::string out = report_text(run, verbose);
        out += "\nPi-hole\n";
        if (!r.pihole_error.empty()) out += "  " + safe(r.pihole_error, 240) + "\n";
        else if (!r.pihole) out += "  not configured (forti-pihole setup)\n";
        else {
            if (r.pihole->changes.empty()) out += "  client entries in sync\n";
            for (const auto& c: r.pihole->changes)
                out += std::format("  {} {} -> {}   [{}]\n", c.kind, c.cidr, c.pihole_group.empty() ? "-" : c.pihole_group, c.why);
            for (const auto& f: r.pihole->findings) out += std::format("  note ({}): {}\n", f.kind, safe(f.detail, 240));
        }
        bool any_slicing = !r.slicing.actions.empty() || !r.slicing.findings.empty();
        if (any_slicing) {
            out += "\nAddress slices\n";
            for (const auto& a: r.slicing.actions)
                if (a.kind != "in-place")
                    out += std::format("  {} {}  {}  {} -> {}  ({})\n", a.kind, a.mac, safe(a.label, 28), a.from_ip, a.to_ip, a.slice);
            std::size_t in_place = std::ranges::count_if(r.slicing.actions, [](const auto& a) { return a.kind == "in-place"; });
            if (in_place) out += std::format("  {} device(s) already reserved inside their slice\n", in_place);
            for (const auto& f: r.slicing.findings) out += std::format("  note ({}): {}\n", f.kind, safe(f.detail, 240));
        }
        for (const auto& m: r.migrations) {
            if (m.operation) continue;
            out += std::format("  migration refused: {}\n", safe(m.refusal.reason, 240));
            for (const auto& n: m.refusal.needs) out += "    needs: " + safe(n, 200) + "\n";
        }
        if (!r.stages.empty()) {
            out += "\nApplied\n";
            for (const auto& s: r.stages)
                out += std::format("  {:<13} {:<9} {}{}\n", s.stage, s.status, safe(s.detail, 240),
                                   s.rollback_plan.empty() ? "" : "  (rollback: forti apply " + s.rollback_plan + ")");
        }
        if (r.status == "disabled") out += "\nnothing written: the configuration is not enabled (set \"enabled\": true after reviewing this plan)\n";
        if (r.status == "paused") out += "\nnothing written: sync is paused (forti-pihole resume)\n";
        return out;
    }

}  // namespace fph
