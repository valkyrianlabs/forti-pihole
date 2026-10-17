#include "cli.hpp"

#include "classify.hpp"
#include "config.hpp"
#include "guard.hpp"
#include "inventory.hpp"
#include "mac.hpp"
#include "reassociate.hpp"
#include "reconcile.hpp"
#include "report.hpp"

#include <forti/engine/error.hpp>

#include <forti_pihole_version.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <format>
#include <ostream>

namespace fph {

    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        struct Usage : std::runtime_error {
            using std::runtime_error::runtime_error;
        };

        struct Options {
            std::string command;
            std::vector<std::string> positional;
            std::string profile, config_path;
            bool json_output = false, quiet = false, verbose = false, reject = false;
            std::optional<int> max_changes;
            std::size_t count = 20;
        };

        Options parse(const std::vector<std::string>& args) {
            Options options;
            for (std::size_t i = 0; i < args.size(); ++i) {
                const auto& a = args[i];
                auto value = [&](const char* flag) -> std::string {
                    if (i + 1 >= args.size()) throw Usage(std::format("{} needs a value", flag));
                    return args[++i];
                };
                auto number = [&](const char* flag, int lo, int hi) {
                    auto text = value(flag);
                    int n = 0;
                    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), n);
                    if (error != std::errc() || end != text.data() + text.size() || n < lo || n > hi)
                        throw Usage(std::format("{}: a number {}..{}", flag, lo, hi));
                    return n;
                };
                if (a == "-p" || a == "--profile") options.profile = value("--profile");
                else if (a == "--config") options.config_path = value("--config");
                else if (a == "--json") options.json_output = true;
                else if (a == "-q" || a == "--quiet") options.quiet = true;
                else if (a == "-v" || a == "--verbose") options.verbose = true;
                else if (a == "--reject") options.reject = true;
                else if (a == "--max-changes") options.max_changes = number("--max-changes", 1, 1000);
                else if (a == "--count") options.count = static_cast<std::size_t>(number("--count", 1, 10000));
                else if (a == "-h" || a == "--help") options.command = "help";
                else if (a == "--version") options.command = "version";
                else if (a.starts_with("-") && a != "-") throw Usage(std::format("unknown option {}", a));
                else if (options.command.empty()) options.command = a;
                else options.positional.push_back(a);
            }
            if (options.command.empty()) options.command = "help";
            return options;
        }

        int exit_for(const std::string& code) {
            if (auto parsed = forti::engine::parse_code(code)) return forti::engine::exit_code(*parsed);
            return 1;
        }

        // Everything one run computes (report, plan and apply share it).
        struct Computed {
            Snapshot snapshot;
            Classification classification;
            std::vector<Candidate> candidates;   // open: from state, plus new ones
            std::vector<Candidate> found;        // new this run
            Changeset changes;
        };

        Computed compute(Gateway& gateway, const Config& config, const State& state, std::int64_t now, int max_changes) {
            Computed c;
            c.snapshot = collect(gateway, config, now);
            c.classification = classify(c.snapshot, config, state, now);
            c.found = find_candidates(c.snapshot, state, c.classification, now);
            c.candidates = state.candidates;
            for (const auto& k: c.found) c.candidates.push_back(k);
            c.changes = reconcile(c.snapshot, c.classification, config, state, now, max_changes);
            return c;
        }

        // Observations worth keeping whatever happens to the apply: devices seen, GUI moves, candidates.
        void observe(State& state, const Computed& c, std::int64_t now) {
            for (const auto& d: c.snapshot.devices) {
                auto& r = state.devices[d.mac];
                if (r.first_seen == 0) r.first_seen = now;
                if (d.last_seen > r.last_seen) r.last_seen = d.last_seen;
                if (d.online && r.last_seen < now - 300) r.last_seen = now;
                r.label = d.label();
                if (!d.hostname.empty()) r.hostname = d.hostname;
                if (!d.vendor.empty()) r.vendor = d.vendor;
                if (!d.family.empty()) r.family = d.family;
                if (!d.os.empty()) r.os = d.os;
                if (!d.os_version.empty()) r.os_version = d.os_version;
                r.randomized = d.randomized;
            }
            for (const auto& [mac, pin]: c.classification.new_pins) state.pins[mac] = pin;
            for (const auto& mac: c.classification.cleared_pins) state.pins.erase(mac);
            for (const auto& k: c.found) state.candidates.push_back(k);
            // Candidates expire after 30 days, or when the new MAC is gone.
            std::erase_if(state.candidates, [&](const Candidate& k) { return now - k.found_at > 30 * 86400; });
        }

        void commit(State& state, const std::map<std::string, Written>& written, const std::vector<std::string>& retired) {
            for (const auto& [mac, w]: written) {
                auto& r = state.devices[mac];
                r.object = w.object;
                r.written_group = w.group;
            }
            for (const auto& mac: retired) {
                state.devices.erase(mac);
                state.pins.erase(mac);
                state.retire_now.erase(mac);
            }
        }

        Pending pending_from(const std::string& plan_id, const Changeset& changes, std::int64_t now) {
            Pending pending;
            pending.plan_id = plan_id;
            pending.at = now;
            for (const auto& [mac, w]: changes.written) pending.written[mac] = {w.object, w.group};
            pending.retired = changes.retired;
            return pending;
        }

        void commit_pending(State& state) {
            if (!state.pending) return;
            std::map<std::string, Written> written;
            for (const auto& [mac, entry]: state.pending->written) written[mac] = {entry.first, entry.second};
            commit(state, written, state.pending->retired);
            state.pending.reset();
        }

        // History lines carry both a readable UTC time and the epoch.
        std::string iso_time(std::int64_t epoch) {
            auto tp = std::chrono::sys_seconds(std::chrono::seconds(epoch));
            return std::format("{:%Y-%m-%dT%H:%M:%SZ}", tp);
        }

        json base_request(const Config& config) {
            json request = json::object();
            if (!config.profile.empty()) request["profile"] = config.profile;
            if (!config.vdom.empty()) request["vdom"] = config.vdom;
            return request;
        }

        std::string summary_of(const Changeset& changes) {
            std::map<std::string, int> counts;
            for (const auto& c: changes.changes) ++counts[c.kind];
            std::string out;
            for (const auto& [kind, n]: counts) out += std::format("{}{} {}", out.empty() ? "" : ", ", n, kind);
            return out.empty() ? "no changes" : out;
        }

    }  // namespace

    std::string usage_text() {
        return R"(usage: forti-pihole <command> [options]

Keeps the FortiGate's device inventory classified into groups: one MAC address object per
device (<prefix>dev-*) and one address group per group (<prefix>grp-<group>), native FortiOS
objects you can edit in the GUI. Never in the traffic path; nothing breaks if it stops running.

commands:
  init                    write a starting configuration ($FORTI_HOME/pihole/config.json)
  report [-v]             classify the inventory and show what would change (read-only)
  plan                    make an engine plan for the pending changes (read-only preview)
  apply [--max-changes N] plan and apply (as the profile's mode allows); the timer runs this
  assign MAC SEGMENT      pin a device to a group (explicit; allows privileged groups)
  assign MAC auto         drop the pin: back to rules
  confirm ID [--reject]   accept or reject a reassociation candidate
  status                  configuration, profile mode, last apply, pending plan
  history [--count N]     the last applies

options:
  -p, --profile NAME      forti profile (default: the configuration's, else forti's default)
  --config PATH           configuration file (default $FORTI_HOME/pihole/config.json)
  --json                  machine-readable output
  -q, --quiet             print only problems (for the timer)
  -v, --verbose           report: offline devices and the reasons for every decision
  --version, -h/--help

Subnet assignment through DHCP is not available: FortiOS behaviour for it is unproven.
)";
    }

    int run(const std::vector<std::string>& args, Environment& env) {
        auto& out = *env.out;
        auto& err = *env.err;
        Options options;
        try {
            options = parse(args);
        } catch (const Usage& e) {
            err << "forti-pihole: " << e.what() << "\n\n" << usage_text();
            return 2;
        }
        if (options.command == "help") {
            out << usage_text();
            return 0;
        }
        if (options.command == "version") {
            out << "forti-pihole " << FORTI_PIHOLE_VERSION << " (" << FORTI_PIHOLE_BUILT_FROM << ")\n";
            return 0;
        }
        static const std::vector<std::string> commands = {"init", "report", "plan", "apply", "assign", "confirm", "status", "history"};
        if (std::ranges::find(commands, options.command) == commands.end()) {
            err << "forti-pihole: unknown command \"" << options.command << "\"\n\n" << usage_text();
            return 2;
        }

        fs::path config_path = options.config_path.empty() ? env.home.config() : fs::path(options.config_path);
        auto now = env.clock();

        if (options.command == "init") {
            if (fs::exists(config_path)) {
                err << "forti-pihole: " << config_path.string() << " exists; not overwriting it\n";
                return 3;
            }
            write_private(config_path, example_config().dump(2) + "\n");
            out << "wrote " << config_path.string() << "\nedit the groups and rules, then run: forti-pihole report\n";
            return 0;
        }

        if (options.command == "history") {
            auto entries = read_history(env.home.history(), options.count);
            if (options.json_output) out << json(entries).dump(2) << "\n";
            else if (entries.empty()) out << "no applies recorded yet\n";
            else
                for (const auto& e: entries)
                    out << std::format("{}  {}  {}  {}\n", e.value("time", std::string()), e.value("status", std::string()),
                                       e.value("plan_id", std::string()), e.value("summary", std::string()));
            return 0;
        }

        try {
            Config config = load_config(config_path);
            if (!options.profile.empty()) config.profile = options.profile;
            int max_changes = options.max_changes.value_or(config.max_changes);

            if (options.command == "assign") {
                if (options.positional.size() != 2) throw Usage("assign MAC SEGMENT|auto");
                auto mac = normalize_mac(options.positional[0]);
                if (!mac) throw Usage(std::format("\"{}\" is not a MAC address", options.positional[0]));
                const auto& group = options.positional[1];
                if (group != "auto" && !config.group(group)) throw Usage(std::format("no group \"{}\" in the configuration", group));
                RunLock lock(env.home.lock());
                State state = load_state(env.home.state());
                if (group == "auto") state.pins.erase(*mac);
                else state.pins[*mac] = {group, "assign", now};
                save_state(env.home.state(), state);
                out << std::format("{} {}; takes effect at the next apply\n", *mac,
                                   group == "auto" ? "is classified by rules again" : "pinned to " + group);
                return 0;
            }

            if (options.command == "confirm") {
                if (options.positional.size() != 1) throw Usage("confirm ID [--reject]");
                RunLock lock(env.home.lock());
                State state = load_state(env.home.state());
                const Candidate* k = state.candidate(options.positional[0]);
                if (!k) throw Usage(std::format("no open reassociation candidate {} (run forti-pihole report)", options.positional[0]));
                Candidate candidate = *k;
                std::erase_if(state.candidates, [&](const Candidate& c) { return c.id == candidate.id; });
                if (options.reject) {
                    state.dismissed.insert(candidate.id);
                    save_state(env.home.state(), state);
                    out << std::format("rejected {}: {} and {} stay separate devices\n", candidate.id, candidate.old_mac, candidate.new_mac);
                    return 0;
                }
                std::string group;
                if (auto pin = state.pins.find(candidate.old_mac); pin != state.pins.end()) group = pin->second.group;
                else if (auto r = state.devices.find(candidate.old_mac); r != state.devices.end()) group = r->second.written_group;
                if (group.empty() || !config.group(group)) throw Usage("the old device has no group to transfer");
                state.pins[candidate.new_mac] = {group, "confirm", now};
                state.retire_now.insert(candidate.old_mac);
                save_state(env.home.state(), state);
                out << std::format("{} takes over {} from {}; the old entry is retired at the next apply\n", candidate.new_mac, group,
                                   candidate.old_mac);
                return 0;
            }

            auto gateway = env.gateway(config);

            if (options.command == "status") {
                State state = load_state(env.home.state());
                json request = base_request(config);
                request["what"] = "capabilities";
                auto caps = gateway->discover(request);
                json status = {{"config", config_path.string()}, {"state", env.home.state().string()},
                               {"profile", caps.value("ok", false) ? caps["data"].value("profile", std::string()) : config.profile},
                               {"mode", caps.value("ok", false) ? caps["data"].value("mode", std::string()) : std::string("unknown")},
                               {"last_apply", state.last_apply}, {"last_plan", state.last_plan},
                               {"pending_plan", state.pending ? state.pending->plan_id : std::string()},
                               {"known_devices", state.devices.size()}, {"pins", state.pins.size()},
                               {"candidates", state.candidates.size()}};
                if (!caps.value("ok", false)) status["device_error"] = caps["error"];
                if (options.json_output) out << status.dump(2) << "\n";
                else {
                    out << std::format("config      {}\nstate       {}\nprofile     {}  (mode {})\n", status["config"].get<std::string>(),
                                       status["state"].get<std::string>(), status["profile"].get<std::string>(),
                                       status["mode"].get<std::string>());
                    out << std::format("last apply  {}\npending     {}\ndevices     {} known, {} pinned, {} reassociation candidate(s)\n",
                                       state.last_apply ? std::format("{} ({})", state.last_plan, state.last_apply) : std::string("never"),
                                       state.pending ? state.pending->plan_id : std::string("none"), state.devices.size(),
                                       state.pins.size(), state.candidates.size());
                    if (status.contains("device_error"))
                        out << "device      " << status["device_error"].value("message", std::string()) << "\n";
                }
                return 0;
            }

            if (options.command == "report") {
                State state = load_state(env.home.state());
                auto c = compute(*gateway, config, state, now, max_changes);
                Run run{&c.snapshot, &c.classification, &c.changes, &c.candidates, &config, now};
                if (options.json_output) out << report_json(run).dump(2) << "\n";
                else out << report_text(run, options.verbose);
                return 0;
            }

            // plan / apply
            RunLock lock(env.home.lock());
            State state = load_state(env.home.state());

            // A plan from an earlier run that was waiting for approval (guarded) goes first.
            if (options.command == "apply" && state.pending && now - state.pending->at < 86400) {
                auto applied = gateway->apply({{"plan_id", state.pending->plan_id}});
                if (applied.value("ok", false)) {
                    auto id = state.pending->plan_id;
                    commit_pending(state);
                    state.last_apply = now;
                    state.last_plan = id;
                    append_history(env.home.history(), {{"time", iso_time(now)}, {"epoch", now}, {"plan_id", id}, {"status", "applied"},
                                                        {"summary", "pending plan applied after approval"}});
                    save_state(env.home.state(), state);
                    if (!options.quiet) out << "applied pending plan " << id << "\n";
                } else {
                    auto code = applied["error"].value("code", std::string());
                    if (code == "approval_required") {
                        save_state(env.home.state(), state);
                        err << std::format("plan {} is still waiting for approval: forti approve {}\n", state.pending->plan_id,
                                           state.pending->plan_id);
                        return 7;
                    }
                    // Stale, unknown or already executed: plan again from fresh reads. Its intended
                    // placements stay "ours" until this run's apply completes.
                }
            }

            auto c = compute(*gateway, config, state, now, max_changes);
            observe(state, c, now);
            Run run{&c.snapshot, &c.classification, &c.changes, &c.candidates, &config, now};

            if (c.changes.empty()) {
                commit(state, c.changes.written, c.changes.retired);
                state.pending.reset();
                save_state(env.home.state(), state);
                if (options.json_output) out << report_json(run).dump(2) << "\n";
                else if (!options.quiet) out << "in sync: no changes\n";
                for (const auto& b: c.changes.blocked)
                    err << std::format("blocked {} ({}): would lose {}\n", b.mac, safe(b.label), b.probe);
                return 0;
            }

            json request = base_request(config);
            request["operations"] = c.changes.operations;
            auto planned = gateway->plan(request);
            if (!planned.value("ok", false)) {
                save_state(env.home.state(), state);
                err << "forti-pihole: planning failed: " << planned["error"].value("message", std::string()) << "\n";
                return exit_for(planned["error"].value("code", std::string()));
            }
            auto plan_id = planned["data"].value("id", std::string());

            if (options.command == "plan") {
                save_state(env.home.state(), state);
                if (options.json_output) {
                    auto report = report_json(run);
                    report["plan"] = planned["data"];
                    out << report.dump(2) << "\n";
                } else {
                    out << report_text(run, options.verbose);
                    out << std::format("\nplan {} ({}; risk {}). Apply with: forti-pihole apply\n", plan_id,
                                       planned["data"].value("summary", std::string()), planned["data"].value("risk", std::string()));
                }
                return 0;
            }

            state.pending = pending_from(plan_id, c.changes, now);
            save_state(env.home.state(), state);
            auto applied = gateway->apply({{"plan_id", plan_id}});
            json entry = {{"time", iso_time(now)}, {"epoch", now}, {"plan_id", plan_id}, {"summary", summary_of(c.changes)}};
            json changes = json::array();
            for (const auto& x: c.changes.changes)
                changes.push_back({{"kind", x.kind}, {"mac", x.mac}, {"label", x.label}, {"object", x.object}, {"group", x.group},
                                   {"from", x.from}});
            entry["changes"] = changes;

            if (applied.value("ok", false)) {
                commit_pending(state);
                state.last_apply = now;
                state.last_plan = plan_id;
                entry["status"] = "applied";
                if (applied["data"].contains("rollback")) entry["rollback_plan"] = applied["data"]["rollback"].value("plan_id", std::string());
                append_history(env.home.history(), entry);
                save_state(env.home.state(), state);
                if (options.json_output) {
                    auto report = report_json(run);
                    report["apply"] = applied["data"];
                    out << report.dump(2) << "\n";
                } else if (!options.quiet) {
                    out << report_text(run, false);
                    out << std::format("\napplied plan {}: {}; rollback: forti apply {}\n", plan_id, summary_of(c.changes),
                                       entry.value("rollback_plan", std::string("(none)")));
                }
                return 0;
            }

            auto error = applied["error"];
            auto code = error.value("code", std::string());
            entry["status"] = code;
            entry["error"] = error.value("message", std::string());
            append_history(env.home.history(), entry);
            save_state(env.home.state(), state);
            if (code == "approval_required")
                err << std::format("plan {} needs your approval (guarded profile): forti approve {}, then run forti-pihole apply again\n",
                                   plan_id, plan_id);
            else if (code == "policy_denied")
                err << std::format("the profile is read-only: nothing applied. Plan {} shows the change; allow changes with forti configure\n",
                                   plan_id);
            else
                err << "forti-pihole: apply " << plan_id << " failed (" << code << "): " << error.value("message", std::string())
                    << "\n  the next run re-reads the FortiGate and plans again\n";
            return exit_for(code);
        } catch (const Usage& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 2;
        } catch (const ConfigError& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 3;
        } catch (const StateError& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 3;
        } catch (const GatewayError& e) {
            err << "forti-pihole: reading the FortiGate failed (" << e.code() << "): " << e.what()
                << "\n  nothing was changed\n";
            return exit_for(e.code());
        } catch (const GuardViolation& e) {
            err << "forti-pihole: internal error, refused by the write guard: " << e.what() << "\n  nothing was sent\n";
            return 1;
        }
    }

}  // namespace fph
