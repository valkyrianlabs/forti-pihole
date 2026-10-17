#include "cli.hpp"

#include "alloc/render.hpp"
#include "classify.hpp"
#include "config.hpp"
#include "daemon_state.hpp"
#include "executors.hpp"
#include "guard.hpp"
#include "inventory.hpp"
#include "mac.hpp"
#include "migrate.hpp"
#include "references.hpp"
#include "report.hpp"
#include "stitch.hpp"
#include "sync.hpp"
#include "token.hpp"

#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <forti_pihole_version.hpp>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <format>
#include <iostream>
#include <ostream>

#include <termios.h>
#include <unistd.h>

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
            std::string profile, config_path, pihole_url, url, group;
            bool json_output = false, quiet = false, verbose = false, reject = false, prune = false, propose = false;
            bool password_stdin = false, no_migrations = false, adopt_reservation = false, clear = false, dry_run = false;
            std::vector<std::string> objects;
            std::optional<int> max_changes, max_migrations;
            std::size_t count = 20;
        };

        const std::vector<std::string> commands = {"setup", "init", "discover", "devices", "report", "groups", "networks", "slices",
                                                   "plan", "sync", "apply", "status", "history", "pause", "resume", "assign",
                                                   "confirm", "adopt", "migrate", "operations", "references", "events"};

        Options parse(const std::vector<std::string>& args) {
            Options o;
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
                if (a == "-p" || a == "--profile") o.profile = value("--profile");
                else if (a == "--config") o.config_path = value("--config");
                else if (a == "--json") o.json_output = true;
                else if (a == "-q" || a == "--quiet") o.quiet = true;
                else if (a == "-v" || a == "--verbose") o.verbose = true;
                else if (a == "--reject") o.reject = true;
                else if (a == "--prune") o.prune = true;
                else if (a == "--propose") o.propose = true;
                else if (a == "--dry-run") o.dry_run = true;
                else if (a == "--no-migrations") o.no_migrations = true;
                else if (a == "--pihole-url") o.pihole_url = value("--pihole-url");
                else if (a == "--password-stdin") o.password_stdin = true;
                else if (a == "--url") o.url = value("--url");
                else if (a == "--group") o.group = value("--group");
                else if (a == "--object") o.objects.push_back(value("--object"));
                else if (a == "--reservation") o.adopt_reservation = true;
                else if (a == "--clear") o.clear = true;
                else if (a == "--max-changes") o.max_changes = number("--max-changes", 1, 1000);
                else if (a == "--max-migrations") o.max_migrations = number("--max-migrations", 0, 50);
                else if (a == "--count") o.count = static_cast<std::size_t>(number("--count", 1, 10000));
                else if (a == "-h" || a == "--help") o.command = "help";
                else if (a == "--version") o.command = "version";
                else if (a.starts_with("-") && a != "-") throw Usage(std::format("unknown option {}", a));
                else if (o.command.empty()) o.command = a;
                else o.positional.push_back(a);
            }
            if (o.command.empty()) o.command = "help";
            if (o.command == "report") o.command = "devices";
            if (o.command == "apply") o.command = "sync";
            return o;
        }

        int exit_for(const std::string& code) {
            if (auto parsed = forti::engine::parse_code(code)) return forti::engine::exit_code(*parsed);
            return 1;
        }

        json base_request(const Config& config) {
            json request = json::object();
            if (!config.profile.empty()) request["profile"] = config.profile;
            if (!config.vdom.empty()) request["vdom"] = config.vdom;
            return request;
        }

        std::string read_password(std::istream& in, bool from_stdin, std::ostream& err) {
            std::string password;
            if (!from_stdin && ::isatty(STDIN_FILENO)) {
                err << "Pi-hole app password (input hidden): " << std::flush;
                termios old{};
                ::tcgetattr(STDIN_FILENO, &old);
                termios quiet = old;
                quiet.c_lflag &= static_cast<tcflag_t>(~ECHO);
                ::tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
                std::getline(in, password);
                ::tcsetattr(STDIN_FILENO, TCSANOW, &old);
                err << "\n";
            } else std::getline(in, password);
            while (!password.empty() && (password.back() == '\r' || password.back() == '\n')) password.pop_back();
            return password;
        }

        // Suggested Pi-hole group for a device group: an unambiguous case-insensitive match.
        std::string suggest(const std::string& group, const PiholeView& view) {
            auto lower = [](std::string s) {
                for (auto& c: s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                return s;
            };
            auto g = lower(group);
            std::vector<std::string> hits;
            for (const auto& p: view.groups) {
                if (p.id == 0) continue;
                auto n = lower(p.name);
                if (n == g || (g.size() >= 2 && (n.starts_with(g) || g.starts_with(n)))) hits.push_back(p.name);
            }
            return hits.size() == 1 ? hits.front() : std::string();
        }

        std::string paused_detail(const Home& home) {
            try {
                daemon::StateFiles files{home.dir};
                return daemon::load_daemon_state(files).state.paused ? "paused" : "";
            } catch (...) {
                return "";
            }
        }

    }  // namespace

    std::string usage_text() {
        return R"(usage: forti-pihole <command> [options]

Unified FortiGate network identity and Pi-hole DNS policy synchronization. Device groups live on
the FortiGate as address groups (<prefix>grp-<group>, one MAC object per device), networks map to
Pi-hole groups either as whole subnets (native VLANs) or as DHCP address slices on a flat network.
Never in the traffic path: when forti-pihole stops, both keep their last configuration.

getting started:
  setup [--pihole-url URL] [--password-stdin]   connect, discover, write a starting configuration (writes nothing else)
  discover                                     networks, groups and Pi-hole at a glance (read-only)

inspect (read-only):
  devices [-v]          the inventory, classified, with reasons
  groups                device groups -> FortiGate address groups -> Pi-hole groups
  networks              interfaces, subnets, strategy and DHCP pools
  slices [--propose]    slice layout per network; --propose plans slices for the current members
  plan                  everything sync would do, FortiGate and Pi-hole
  references IP         what on the FortiGate refers to an address
  status | history [--count N]

change:
  sync [--prune] [--max-changes N] [--max-migrations N] [--no-migrations]
                        apply the plan (needs "enabled": true; honours pause)
  pause | resume        stop/start syncing (CLI and forti-piholed)
  assign MAC GROUP|auto pin a device to a group (explicit; allows privileged groups)
  confirm ID [--reject] accept or reject a reassociation candidate
  adopt MAC [--object NAME]... [--reservation] | adopt MAC --clear
                        let a migration change these administrator objects for this device
  migrate MAC [--dry-run]               move one device into its group's slice now
  operations [show|resume|rollback ID]  migrations and their journal
  events plan|install|remove --url http://HOST:PORT
                        the FortiGate automation stitch that notifies forti-piholed

options:
  -p, --profile NAME    forti profile (default: the configuration's, else forti's default)
  --config PATH         configuration file (default $FORTI_HOME/pihole/config.json)
  --json                machine-readable output
  -q, --quiet           print only problems
  -v, --verbose         offline devices and the reasons for every decision
  --version, -h/--help

Address slicing is a DHCP allocation and DNS classification unit, not a routed subnet: devices keep
the interface's mask and gateway, and nothing isolates them at Layer 2.
)";
    }

    int run(const std::vector<std::string>& args, Environment& env) {
        auto& out = *env.out;
        auto& err = *env.err;
        Options o;
        try {
            o = parse(args);
        } catch (const Usage& e) {
            err << "forti-pihole: " << e.what() << "\n\n" << usage_text();
            return 2;
        }
        if (o.command == "help") {
            out << usage_text();
            return 0;
        }
        if (o.command == "version") {
            out << "forti-pihole " << FORTI_PIHOLE_VERSION << " (" << FORTI_PIHOLE_BUILT_FROM << ")\n";
            return 0;
        }
        if (std::ranges::find(commands, o.command) == commands.end()) {
            err << "forti-pihole: unknown command \"" << o.command << "\"\n\n" << usage_text();
            return 2;
        }

        fs::path config_path = o.config_path.empty() ? env.home.config() : fs::path(o.config_path);
        auto now = env.clock();

        if (o.command == "init") {
            if (fs::exists(config_path)) {
                err << "forti-pihole: " << config_path.string() << " exists; not overwriting it\n";
                return 3;
            }
            write_private(config_path, example_config().dump(2) + "\n");
            out << "wrote " << config_path.string() << "\nnext: forti-pihole setup (connects Pi-hole and discovers networks)\n";
            return 0;
        }
        if (o.command == "history") {
            auto entries = read_history(env.home.history(), o.count);
            if (o.json_output) out << json(entries).dump(2) << "\n";
            else if (entries.empty()) out << "nothing recorded yet\n";
            else
                for (const auto& e: entries)
                    out << std::format("{}  {:<13} {:<9} {}  {}\n", e.value("time", std::string()), e.value("stage", std::string("objects")),
                                       e.value("status", std::string()), e.value("plan_id", std::string()), e.value("summary", std::string()));
            return 0;
        }
        if (o.command == "pause" || o.command == "resume") {
            daemon::set_paused(daemon::StateFiles{env.home.dir}, o.command == "pause", now);
            out << (o.command == "pause" ? "paused: sync and forti-piholed write nothing until forti-pihole resume\n" : "resumed\n");
            return 0;
        }

        try {
            if (o.command == "setup" && !fs::exists(config_path)) write_private(config_path, example_config().dump(2) + "\n");
            Config config = load_config(config_path);
            if (!o.profile.empty()) config.profile = o.profile;
            int max_changes = o.max_changes.value_or(config.max_changes);

            if (o.command == "assign") {
                if (o.positional.size() != 2) throw Usage("assign MAC GROUP|auto");
                auto mac = normalize_mac(o.positional[0]);
                if (!mac) throw Usage(std::format("\"{}\" is not a MAC address", o.positional[0]));
                const auto& group = o.positional[1];
                if (group != "auto" && !config.group(group)) throw Usage(std::format("no group \"{}\" in the configuration", group));
                RunLock lock(env.home.lock());
                State state = load_state(env.home.state());
                if (group == "auto") state.pins.erase(*mac);
                else state.pins[*mac] = {group, "assign", now};
                save_state(env.home.state(), state);
                out << std::format("{} {}; takes effect at the next sync\n", *mac, group == "auto" ? "is classified by rules again" : "pinned to " + group);
                return 0;
            }
            if (o.command == "adopt") {
                if (o.positional.size() != 1) throw Usage("adopt MAC [--object NAME]... [--reservation] | adopt MAC --clear");
                auto mac = normalize_mac(o.positional[0]);
                if (!mac) throw Usage(std::format("\"{}\" is not a MAC address", o.positional[0]));
                RunLock lock(env.home.lock());
                State state = load_state(env.home.state());
                if (o.clear) state.adoptions.erase(*mac);
                else {
                    if (o.objects.empty() && !o.adopt_reservation) throw Usage("adopt needs --object NAME and/or --reservation");
                    auto& a = state.adoptions[*mac];
                    for (const auto& name: o.objects) a.objects.insert(name);
                    a.reservation = a.reservation || o.adopt_reservation;
                    a.at = now;
                }
                save_state(env.home.state(), state);
                out << std::format("{}: {}\n", *mac, o.clear ? "adoptions cleared" : "a migration of this device may now change those objects");
                return 0;
            }
            if (o.command == "confirm") {
                if (o.positional.size() != 1) throw Usage("confirm ID [--reject]");
                RunLock lock(env.home.lock());
                State state = load_state(env.home.state());
                const Candidate* k = state.candidate(o.positional[0]);
                if (!k) throw Usage(std::format("no open reassociation candidate {} (run forti-pihole devices)", o.positional[0]));
                Candidate candidate = *k;
                std::erase_if(state.candidates, [&](const Candidate& c) { return c.id == candidate.id; });
                if (o.reject) {
                    state.dismissed.insert(candidate.id);
                    save_state(env.home.state(), state);
                    out << std::format("rejected {}: {} and {} stay separate devices\n", candidate.id, candidate.old_mac, candidate.new_mac);
                    return 0;
                }
                std::string group;
                if (auto pin = state.pins.find(candidate.old_mac); pin != state.pins.end()) group = pin->second.group;
                else if (auto rec = state.devices.find(candidate.old_mac); rec != state.devices.end()) group = rec->second.written_group;
                if (group.empty() || !config.group(group)) throw Usage("the old device has no group to transfer");
                state.pins[candidate.new_mac] = {group, "confirm", now};
                state.retire_now.insert(candidate.old_mac);
                if (auto a = state.adoptions.find(candidate.old_mac); a != state.adoptions.end()) state.adoptions[candidate.new_mac] = a->second;
                save_state(env.home.state(), state);
                out << std::format("{} takes over {} from {}; the old entry is retired at the next sync\n", candidate.new_mac, group, candidate.old_mac);
                return 0;
            }

            auto permits = std::make_shared<WritePermits>();
            auto gateway = env.gateway(config, permits);
            std::unique_ptr<PiholeApi> pihole_owner;
            auto pihole = [&]() -> PiholeApi* {
                if (config.pihole.url.empty()) return nullptr;
                if (!pihole_owner) pihole_owner = env.pihole(config);
                return pihole_owner.get();
            };
            SyncContext ctx{config, *gateway, permits, pihole, env.home, env.clock, env.sleep};

            if (o.command == "setup") {
                out << "FortiGate\n";
                json caps_request = base_request(config);
                caps_request["what"] = "capabilities";
                auto caps = gateway->discover(caps_request);
                if (!caps.value("ok", false)) throw GatewayError(caps["error"]);
                const auto& device = caps["data"]["device"];
                out << std::format("  {} {} ({}), FortiOS {}, profile {} in {} mode\n", device.value("model_name", std::string()),
                                   device.value("model_number", std::string()), device.value("hostname", std::string()),
                                   device.value("version", std::string()), caps["data"].value("profile", std::string()),
                                   caps["data"].value("mode", std::string()));
                bool changed = false;
                json root = config.to_json();
                if (!o.pihole_url.empty()) {
                    root["pihole"]["url"] = o.pihole_url;
                    config = Config::from_json(root);
                    changed = true;
                }
                out << "\nPi-hole\n";
                PiholeView view;
                if (config.pihole.url.empty()) out << "  not configured: forti-pihole setup --pihole-url https://pihole.example.net\n";
                else {
                    std::unique_ptr<PiholeApi> api;
                    try {
                        api = env.pihole(config);   // a stored password
                    } catch (const PiholeLinkError&) {
                        auto password = read_password(*env.in, o.password_stdin, err);
                        if (password.empty()) throw Usage("no Pi-hole password given");
                        api = env.pihole_with_password(config.pihole, password);   // verified before it is stored
                        auto store = forti::engine::default_secret_store(forti::engine::Paths::from_env());
                        store->put(pihole_account(config.pihole), password, pihole_binding(config.pihole));
                        out << std::format("  stored the password in forti's secret store ({}) as {}\n", store->kind(), pihole_account(config.pihole));
                    }
                    out << std::format("  {} at {}\n", api->version(), config.pihole.url);
                    view = api->view();
                    std::string names;
                    for (const auto& g: view.groups) names += (names.empty() ? "" : ", ") + g.name;
                    out << std::format("  groups: {}\n  client entries: {}\n", names, view.clients.size());
                }

                // Networks: add every LAN-side interface with an address as "observe"; suggest a strategy.
                auto snapshot = collect(*gateway, config, now);
                out << "\nNetworks\n";
                for (const auto& [name, i]: snapshot.interfaces) {
                    auto cidr = to_cidr(i.ip);
                    if (cidr.empty() || i.role == "wan" || i.type == "tunnel" || i.type == "loopback") continue;
                    const DhcpServer* dhcp = snapshot.dhcp_for(name);
                    bool vlan = i.type == "vlan" || i.type == "emac-vlan";
                    std::string suggestion = vlan ? "subnet (a VLAN: map its whole subnet to a Pi-hole group)"
                                                  : dhcp ? "slices (a flat network with DHCP: slice it per group)" : "observe";
                    bool known = config.network(name) != nullptr;
                    out << std::format("  {:<14} {:<18} {}{}  suggested: {}{}\n", name, cidr, i.type,
                                       vlan ? std::format(" (VLAN {} on {})", i.vlanid, i.parent) : "", suggestion, known ? "  [configured]" : "");
                    if (!known && dhcp) {
                        root = config.to_json();
                        root["networks"].push_back({{"interface", name}, {"mode", "observe"}, {"group", config.default_group},
                                                    {"slices", json::array()}, {"manage_reservations", false}});
                        config = Config::from_json(root);
                        changed = true;
                    }
                }
                if (!view.groups.empty()) {
                    out << "\nGroup mappings\n";
                    root = config.to_json();
                    for (auto& g: root["groups"]) {
                        auto current = g.value("pihole_group", std::string());
                        auto proposal = current.empty() ? suggest(g["name"], view) : current;
                        bool exists = !proposal.empty() && view.group(proposal);
                        out << std::format("  {:<16} -> {}{}\n", g["name"].get<std::string>(), proposal.empty() ? "(Default)" : proposal,
                                           current.empty() && !proposal.empty() ? "  [suggested]" : !proposal.empty() && !exists ? "  [missing in Pi-hole]" : "");
                        if (current.empty() && !proposal.empty()) {
                            g["pihole_group"] = proposal;
                            changed = true;
                        }
                    }
                    if (changed) config = Config::from_json(root);
                }
                if (changed) write_private(config_path, config.to_json().dump(2) + "\n");
                out << std::format("\n{} {}\n", changed ? "updated" : "unchanged:", config_path.string());
                out << "nothing was written to the FortiGate or Pi-hole. Review the networks (mode, slices) and groups, then:\n"
                       "  forti-pihole slices --propose   forti-pihole plan   and set \"enabled\": true when the plan looks right\n";
                return 0;
            }

            if (o.command == "status") {
                State state = load_state(env.home.state());
                json request = base_request(config);
                request["what"] = "capabilities";
                auto caps = gateway->discover(request);
                Journal journal(env.home.dir / "operations");
                auto open = journal.open();
                json status = {{"config", config_path.string()}, {"enabled", config.enabled}, {"paused", paused_detail(env.home) == "paused"},
                               {"profile", caps.value("ok", false) ? caps["data"].value("profile", std::string()) : config.profile},
                               {"mode", caps.value("ok", false) ? caps["data"].value("mode", std::string()) : std::string("unknown")},
                               {"pihole", config.pihole.url}, {"last_apply", state.last_apply}, {"last_plan", state.last_plan},
                               {"pending_plan", state.pending ? state.pending->plan_id : std::string()},
                               {"known_devices", state.devices.size()}, {"pins", state.pins.size()}, {"adoptions", state.adoptions.size()},
                               {"candidates", state.candidates.size()}, {"open_operations", open.size()}};
                if (!caps.value("ok", false)) status["device_error"] = caps["error"];
                if (o.json_output) out << status.dump(2) << "\n";
                else {
                    out << std::format("config      {}  ({}{})\n", config_path.string(), config.enabled ? "enabled" : "NOT enabled: plans only",
                                       status["paused"].get<bool>() ? ", paused" : "");
                    out << std::format("profile     {}  (mode {})\n", status["profile"].get<std::string>(), status["mode"].get<std::string>());
                    out << std::format("pihole      {}\n", config.pihole.url.empty() ? "(not configured)" : config.pihole.url);
                    out << std::format("last sync   {}\npending     {}\n", state.last_apply ? state.last_plan : std::string("never"),
                                       state.pending ? state.pending->plan_id : std::string("none"));
                    out << std::format("devices     {} known, {} pinned, {} adopted, {} reassociation candidate(s)\n", state.devices.size(),
                                       state.pins.size(), state.adoptions.size(), state.candidates.size());
                    for (const auto& op: open)
                        out << std::format("operation   {} {} ({})\n", op.id, op.status, op.subject.value("label", std::string()));
                }
                return 0;
            }

            if (o.command == "references") {
                if (o.positional.size() != 1) throw Usage("references IP");
                auto snapshot = collect(*gateway, config, now);
                auto refs = references_to(snapshot, o.positional[0]);
                json list = json::array();
                for (const auto& r: refs) {
                    json policies = json::array();
                    for (const auto& p: r.policies)
                        policies.push_back({{"id", p.id}, {"name", p.name}, {"source", p.source}, {"enabled", p.enabled}, {"via", p.via}});
                    list.push_back({{"kind", r.kind}, {"name", r.name}, {"detail", r.detail}, {"managed", r.managed}, {"policies", policies}});
                    if (!o.json_output) {
                        out << std::format("{:<12} {}  {}\n", r.kind, safe(r.name, 60), safe(r.detail, 60));
                        for (const auto& p: r.policies) {
                            std::string via;
                            for (const auto& v: p.via) via += " via " + v;
                            out << std::format("             policy {} \"{}\" {}{}{}\n", p.id, safe(p.name, 40), p.source ? "source" : "destination",
                                               p.enabled ? "" : " (disabled)", safe(via, 120));
                        }
                    }
                }
                if (o.json_output) out << list.dump(2) << "\n";
                else if (refs.empty()) out << "nothing refers to " << o.positional[0] << "\n";
                return 0;
            }

            if (o.command == "operations") {
                Journal journal(env.home.dir / "operations");
                std::string verb = o.positional.empty() ? "list" : o.positional[0];
                if (verb == "list") {
                    auto all = journal.list();
                    if (o.json_output) {
                        json list = json::array();
                        for (const auto& op: all) list.push_back(op.to_json());
                        out << list.dump(2) << "\n";
                    } else if (all.empty()) out << "no operations yet\n";
                    for (const auto& op: o.json_output ? std::vector<Operation>{} : all)
                        out << std::format("{}  {:<12} {}  {} -> {}\n", op.id, op.status, safe(op.subject.value("label", std::string()), 28),
                                           op.subject.value("from_ip", std::string()), op.subject.value("to_ip", std::string()));
                    return 0;
                }
                if (o.positional.size() != 2) throw Usage("operations show|resume|rollback ID");
                auto op = journal.load(o.positional[1]);
                if (!op) throw Usage("no operation " + o.positional[1]);
                if (verb == "show") {
                    if (o.json_output) out << op->to_json().dump(2) << "\n";
                    else {
                        out << std::format("{}  {}  {}\n", op->id, op->status, op->subject.dump());
                        for (const auto& s: op->steps)
                            out << std::format("  {:<12} {:<20} {}{}\n", s.id, s.status, safe(s.description, 120), s.error.empty() ? "" : "  -- " + safe(s.error, 200));
                        for (const auto& line: op->log) out << "  log " << safe(line, 240) << "\n";
                    }
                    return 0;
                }
                if (verb != "resume" && verb != "rollback") throw Usage("operations show|resume|rollback ID");
                if (!config.enabled) throw ConfigError("the configuration is not enabled; nothing is written");
                // Rollback stays available while paused: it is how a person backs out.
                if (verb == "resume" && paused_detail(env.home) == "paused") throw ConfigError("sync is paused (forti-pihole resume)");
                RunLock lock(env.home.lock());
                PiholeApi* api = pihole();
                Runtime rt{*gateway, permits, api, config, env.clock, env.sleep};
                MigrationExecutors executors(rt);
                auto pick = [&](const Step& s) { return executors(s); };
                auto status = verb == "resume" ? run_operation(*op, journal, pick, env.clock) : rollback_operation(*op, journal, pick, env.clock);
                out << std::format("{} {}\n", op->id, status);
                for (const auto& s: op->steps)
                    if (!s.error.empty()) out << std::format("  {}: {}\n", s.id, safe(s.error, 240));
                return status == "done" || status == "rolled-back" ? 0 : status == "waiting" ? 7 : 8;
            }

            if (o.command == "events") {
                if (o.positional.empty() || o.url.empty()) throw Usage("events plan|install|remove --url http://HOST:PORT");
                std::string verb = o.positional[0];
                daemon::WebhookTarget target;
                std::string_view url = o.url;
                if (url.starts_with("https://")) {
                    target.protocol = "https";
                    url.remove_prefix(8);
                } else if (url.starts_with("http://")) url.remove_prefix(7);
                else throw Usage("--url must start with http:// or https://");
                auto colon = url.rfind(':');
                target.host = std::string(url.substr(0, colon));
                if (colon != std::string_view::npos) {
                    unsigned port = 0;
                    auto text = url.substr(colon + 1);
                    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), port);
                    if (error != std::errc() || end != text.data() + text.size() || port == 0 || port > 65535)
                        throw Usage("--url: the port must be a number 1..65535");
                    target.port = port;
                }
                if (target.host.empty()) throw Usage("--url needs a host");
                auto store = forti::engine::default_secret_store(forti::engine::Paths::from_env());
                json caps_request = base_request(config);
                caps_request["what"] = "devices";
                auto devices = gateway->discover(caps_request);
                std::string binding;
                for (const auto& d: devices.value("data", json::array()))
                    if (d.value("name", std::string()) == (config.profile.empty() ? devices["meta"].value("default_profile", std::string()) : config.profile))
                        binding = std::format("{}:{}", d.value("host", std::string()), d.value("port", 443));
                std::string profile = config.profile.empty() ? devices["meta"].value("default_profile", std::string()) : config.profile;
                std::string account = "pihole/" + profile + "/webhook-token";
                // `plan` shows the operations with a well-formed stand-in token; install generates (or
                // reuses) the real one in forti's secret store and never prints it.
                const std::string placeholder(64, '0');
                json operations = verb == "remove" ? daemon::stitch_delete_operations(config.prefix)
                                                   : daemon::stitch_create_operations(target, verb == "plan" ? placeholder
                                                                                                             : daemon::ensure_token(*store, account, binding),
                                                                                      config.prefix);
                if (verb == "plan") {
                    auto text = operations.dump(2);
                    for (auto at = text.find(placeholder); at != std::string::npos; at = text.find(placeholder))
                        text.replace(at, placeholder.size(), "<generated at install>");
                    out << text << "\n";
                    return 0;
                }
                if (verb != "install" && verb != "remove") throw Usage("events plan|install|remove --url http://HOST:PORT");
                WritePermits granted;
                granted.automation = true;
                Runtime rt{*gateway, permits, nullptr, config, env.clock, env.sleep};
                auto outcome = engine_apply(rt, operations, granted, json::object());
                if (outcome.kind != StepOutcome::Kind::done) {
                    err << "forti-pihole: " << outcome.message << "\n";
                    return outcome.kind == StepOutcome::Kind::waiting ? 7 : 6;
                }
                out << std::format("{} the FortiGate automation stitch {}sync (plan {})\n", verb == "install" ? "installed" : "removed",
                                   config.prefix, outcome.result.value("plan_id", std::string()));
                return 0;
            }

            // Everything below computes a full sync picture.
            RunLock lock(env.home.lock());
            State state = load_state(env.home.state());
            SyncOptions options;
            options.apply = o.command == "sync" || o.command == "migrate";
            options.prune = o.prune;
            options.max_changes = max_changes;
            options.max_migrations = o.max_migrations.value_or(1);
            options.migrations = !o.no_migrations && o.command == "sync";
            options.paused = paused_detail(env.home) == "paused";

            if (o.command == "migrate") {
                if (o.positional.size() != 1) throw Usage("migrate MAC [--dry-run]");
                auto mac = normalize_mac(o.positional[0]);
                if (!mac) throw Usage(std::format("\"{}\" is not a MAC address", o.positional[0]));
                options.apply = false;
                auto r = run_sync(ctx, state, options);
                const MigrationPlan* found = nullptr;
                for (const auto& m: r.migrations)
                    if (m.mac == *mac) found = &m;
                if (!found) {
                    for (const auto& a: r.slicing.actions)
                        if (a.mac == *mac) {
                            out << std::format("{}: {} ({})\n", *mac, a.kind, a.why);
                            return 0;
                        }
                    err << "forti-pihole: no move planned for " << *mac << " (not in a slice network, no slice for its group, or already moving)\n";
                    return 2;
                }
                if (!found->operation) {
                    err << "forti-pihole: migration refused: " << found->refusal.reason << "\n";
                    for (const auto& n: found->refusal.needs) err << "  needs: " << n << "\n";

                    return 7;
                }
                Operation op = *found->operation;
                if (o.json_output && o.dry_run) {
                    out << op.to_json().dump(2) << "\n";
                    return 0;
                }
                out << std::format("migration {}: {} {} -> {} ({})\n", op.id, op.subject.value("label", std::string()),
                                   op.subject.value("from_ip", std::string()), op.subject.value("to_ip", std::string()), op.subject.value("slice", std::string()));
                for (const auto& s: op.steps) out << "  " << s.id << ": " << safe(s.description, 160) << "\n";
                for (const auto& n: found->notes) out << "  note: " << safe(n, 200) << "\n";
                if (o.dry_run) return 0;
                if (!config.enabled) throw ConfigError("the configuration is not enabled; nothing is written (--dry-run shows the steps)");
                if (options.paused) throw ConfigError("sync is paused (forti-pihole resume)");
                Journal journal(env.home.dir / "operations");
                journal.save(op, env.clock());
                Runtime rt{*gateway, permits, pihole(), config, env.clock, env.sleep};
                MigrationExecutors executors(rt);
                auto status = run_operation(op, journal, [&](const Step& s) { return executors(s); }, env.clock);
                out << std::format("{} {}\n", op.id, status);
                for (const auto& s: op.steps)
                    if (!s.error.empty()) out << std::format("  {}: {}\n", s.id, safe(s.error, 240));
                return status == "done" ? 0 : status == "waiting" ? 7 : 8;
            }

            if (o.command == "slices") {
                auto r = run_sync(ctx, state, options);
                json all = json::array();
                for (const auto& network: config.networks) {
                    if (network.mode != Network::Mode::slices && network.mode != Network::Mode::hybrid && !o.propose) continue;
                    auto input = plan_input(config, network, r.snapshot, r.classification);
                    if (!input) continue;
                    auto proposal = alloc::propose(*input);
                    auto j = alloc::to_json(proposal);
                    j["interface"] = network.interface;
                    all.push_back(j);
                    if (o.json_output) continue;
                    out << std::format("{}  {}  ({})\n", network.interface, proposal.network.str(), to_string(network.mode));
                    for (const auto& s: proposal.slices)
                        out << std::format("  {:<18} {:<16} {}\n", s.cidr.str(), s.group, s.retained ? "configured" : "proposed");
                    for (const auto& u: proposal.utilization.slices)
                        out << std::format("  {:<18} used {}/{}\n", u.slice.cidr.str(), u.usage.used, u.usage.total);
                    for (const auto& c: proposal.conflicts) out << "  conflict: " << safe(c.detail, 200) << "\n";
                    for (const auto& g: proposal.groups)
                        if (g.missing > 0) {
                            out << std::format("  {} needs {} more address(es)\n", g.group, g.missing);
                            for (const auto& a: g.alternatives) out << "    option: " << safe(a.detail, 200) << "\n";
                        }
                    for (const auto& pc: proposal.pool_changes) out << "  pool change: " << safe(pc.detail, 200) << "\n";
                }
                if (o.json_output) out << all.dump(2) << "\n";
                else if (all.empty()) out << "no slice networks configured (set a network's mode to slices or hybrid, or use --propose)\n";
                return 0;
            }

            auto r = run_sync(ctx, state, options);
            // Only sync records what it observed; inspecting never writes, not even local state.
            if (o.command == "sync") save_state(env.home.state(), state);
            if (o.command == "groups") {
                json list = json::array();
                PiholeView view;
                if (r.pihole) try {
                        view = pihole()->view();
                    } catch (...) {
                    }
                for (const auto& g: config.groups) {
                    std::size_t members = std::ranges::count_if(r.classification.decisions, [&](const auto& d) { return d.group == g.name; });
                    const PiholeGroupInfo* pg = g.pihole_group.empty() ? nullptr : view.group(g.pihole_group);
                    list.push_back({{"group", g.name}, {"addrgrp", config.addrgrp_name(g.name)}, {"members", members}, {"privileged", g.privileged},
                                    {"pihole_group", g.pihole_group}, {"pihole_group_id", pg ? json(pg->id) : json()}});
                    if (!o.json_output)
                        out << std::format("{:<16} {:<22} {:>3} member(s)  -> Pi-hole {}{}{}\n", g.name, config.addrgrp_name(g.name), members,
                                           g.pihole_group.empty() ? "Default" : g.pihole_group,
                                           !g.pihole_group.empty() && r.pihole && !pg ? " [missing in Pi-hole]" : "", g.privileged ? "  [privileged]" : "");
                }
                if (o.json_output) out << list.dump(2) << "\n";
                return 0;
            }
            if (o.command == "networks" || o.command == "discover") {
                json list = json::array();
                for (const auto& [name, i]: r.snapshot.interfaces) {
                    auto cidr = to_cidr(i.ip);
                    if (cidr.empty() || i.role == "wan") continue;
                    const Network* n = config.network(name);
                    const DhcpServer* dhcp = r.snapshot.dhcp_for(name);
                    std::string pools;
                    if (dhcp)
                        for (const auto& p: dhcp->ranges) pools += (pools.empty() ? "" : ", ") + p.start + "-" + p.end;
                    std::size_t devices = std::ranges::count_if(r.snapshot.devices, [&](const Device& d) { return d.interface == name; });
                    list.push_back({{"interface", name}, {"subnet", cidr}, {"type", i.type}, {"vlanid", i.vlanid}, {"parent", i.parent},
                                    {"mode", n ? std::string(to_string(n->mode)) : "unconfigured"}, {"dhcp_pools", pools}, {"devices", devices}});
                    if (!o.json_output)
                        out << std::format("{:<14} {:<18} {:<12} {:<13} dhcp {:<28} {} device(s)\n", name, cidr,
                                           i.vlanid ? std::format("vlan {}", i.vlanid) : i.type, n ? to_string(n->mode) : "unconfigured",
                                           pools.empty() ? "-" : pools, devices);
                }
                if (o.command == "discover" && !o.json_output) {
                    out << "\n";
                    out << sync_text(r, config, now, false);
                }
                if (o.json_output) out << (o.command == "discover" ? json{{"networks", list}, {"sync", sync_json(r, config, now)}} : list).dump(2) << "\n";
                return 0;
            }
            if (o.json_output) out << sync_json(r, config, now).dump(2) << "\n";
            else if (o.command == "devices") {
                Run run{&r.snapshot, &r.classification, nullptr, &r.candidates, &config, now};
                out << report_text(run, o.verbose);
            } else if (!(o.quiet && o.command == "sync" && r.status == "applied")) out << sync_text(r, config, now, o.verbose);
            // What needs a person goes to stderr too, so the timer's mail/journal shows it.
            for (const auto& stage: r.stages)
                if (stage.status == "waiting" || stage.status == "failed") err << std::format("{}: {}\n", stage.stage, stage.detail);
            if (!r.pihole_error.empty() && o.command == "sync") err << "pihole: " << r.pihole_error << "\n";
            return r.exit_code;
        } catch (const Usage& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 2;
        } catch (const ConfigError& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 3;
        } catch (const StateError& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 3;
        } catch (const PiholeLinkError& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return 4;
        } catch (const GatewayError& e) {
            err << "forti-pihole: reading the FortiGate failed (" << e.code() << "): " << e.what() << "\n  nothing was changed\n";
            return exit_for(e.code());
        } catch (const GuardViolation& e) {
            err << "forti-pihole: internal error, refused by the write guard: " << e.what() << "\n  nothing was sent\n";
            return 1;
        } catch (const forti::engine::Failure& e) {
            err << "forti-pihole: " << e.what() << "\n";
            return forti::engine::exit_code(e.code());
        } catch (const std::exception& e) {
            // Anything else is a bug or an environment problem; report it rather than abort.
            err << "forti-pihole: " << e.what() << "\n";
            return 1;
        }
    }

}  // namespace fph
