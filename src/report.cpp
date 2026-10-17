#include "report.hpp"

#include <algorithm>
#include <format>
#include <map>

namespace fvm {

    using json = nlohmann::json;

    namespace {

        std::string pad(std::string_view text, std::size_t width) {
            std::string out(text);
            if (out.size() < width) out.append(width - out.size(), ' ');
            return out;
        }

        std::string ago(std::int64_t now, std::int64_t then) {
            if (then <= 0) return "never";
            auto seconds = now - then;
            if (seconds < 120) return "now";
            if (seconds < 7200) return std::format("{}m ago", seconds / 60);
            if (seconds < 172800) return std::format("{}h ago", seconds / 3600);
            return std::format("{}d ago", seconds / 86400);
        }

        json loss_json(const Loss& loss) {
            return {{"mac", loss.mac}, {"label", loss.label}, {"probe", loss.probe}, {"before", loss.before.describe()},
                    {"after", loss.after.describe()}};
        }

    }  // namespace

    std::string safe(std::string_view text, std::size_t limit) {
        std::string out;
        for (unsigned char c: text) {
            if (out.size() >= limit) {
                out += "…";
                break;
            }
            out += (c >= 0x20 && c != 0x7f) ? static_cast<char>(c) : '?';
        }
        return out;
    }

    json report_json(const Run& run) {
        const auto& c = *run.classification;
        json devices = json::array();
        for (const auto& d: c.decisions) {
            json placements = json::array();
            for (const auto& p: d.placements) placements.push_back({{"segment", p.segment}, {"member", p.member}, {"by_companion", p.by_companion}});
            json matches = json::array();
            for (const auto& m: d.matches)
                matches.push_back({{"segment", m.segment}, {"rule", m.rule}, {"priority", m.priority}, {"native", m.native}});
            devices.push_back({{"mac", d.device.mac}, {"label", d.device.label()}, {"ip", d.device.ip}, {"interface", d.device.interface},
                               {"online", d.device.online}, {"randomized", d.device.randomized}, {"vendor", d.device.vendor},
                               {"family", d.device.family}, {"type", d.device.type}, {"os", d.device.os},
                               {"last_seen", d.device.last_seen}, {"segment", d.segment}, {"source", d.source}, {"detail", d.detail},
                               {"reasons", d.reasons}, {"matches", matches}, {"placements", placements}, {"member", d.member},
                               {"create_member", d.create_member}, {"adopted", d.adopted}, {"protected", d.keep}});
        }
        json overlaps = json::array();
        for (const auto& o: c.overlaps)
            overlaps.push_back({{"mac", o.mac}, {"label", o.label}, {"segments", o.segments}, {"winner", o.winner}, {"why", o.why}});
        json candidates = json::array();
        if (run.candidates)
            for (const auto& k: *run.candidates)
                candidates.push_back({{"id", k.id}, {"old_mac", k.old_mac}, {"new_mac", k.new_mac}, {"score", k.score}, {"reasons", k.reasons}});
        json segments = json::array();
        for (const auto& s: run.config->segments) {
            std::size_t count = std::ranges::count_if(c.decisions, [&](const auto& d) { return d.segment == s.name; });
            json item = {{"name", s.name}, {"group", run.config->group_name(s.name)}, {"privileged", s.privileged}, {"devices", count},
                         {"managed", !c.unusable_segments.contains(s.name)}};
            if (!s.subnet.empty()) item["subnet"] = s.subnet;
            segments.push_back(std::move(item));
        }
        json out = {{"taken_at", run.snapshot->taken_at}, {"segments", segments}, {"devices", devices}, {"overlaps", overlaps},
                    {"candidates", candidates}, {"warnings", c.warnings},
                    {"subnet_assignment", "not available: FortiOS DHCP behaviour for it is unproven"}};
        if (run.changes) {
            json changes = json::array();
            for (const auto& ch: run.changes->changes)
                changes.push_back({{"kind", ch.kind}, {"mac", ch.mac}, {"label", ch.label}, {"object", ch.object}, {"segment", ch.segment},
                                   {"from", ch.from}, {"reason", ch.reason}});
            json blocked = json::array();
            for (const auto& b: run.changes->blocked) blocked.push_back(loss_json(b));
            out["pending"] = {{"changes", changes}, {"operations", run.changes->operations}, {"blocked", blocked},
                              {"deferred", run.changes->deferred}, {"notes", run.changes->notes}};
        }
        return out;
    }

    std::string report_text(const Run& run, bool verbose) {
        const auto& c = *run.classification;
        const auto& config = *run.config;
        std::string out;

        std::size_t online = std::ranges::count_if(c.decisions, [](const auto& d) { return d.device.online; });
        out += std::format("{} devices on {} ({} online)\n\n", c.decisions.size(),
                           [&] {
                               std::string list;
                               for (const auto& i: config.interfaces) list += (list.empty() ? "" : ", ") + i;
                               return list;
                           }(),
                           online);

        out += "Segments\n";
        for (const auto& s: config.segments) {
            std::size_t count = std::ranges::count_if(c.decisions, [&](const auto& d) { return d.segment == s.name; });
            out += std::format("  {} {:>3} device(s)  {}{}{}\n", pad(s.name, 16), count, config.group_name(s.name),
                               s.privileged ? "  [privileged: explicit only]" : "",
                               c.unusable_segments.contains(s.name) ? "  [NOT MANAGED: name clash]" : "");
        }
        out += "  (subnet assignment: not available; segments are address groups only)\n\n";

        // Devices grouped by segment, in config order; protected ones last.
        out += "Devices\n";
        for (const auto& s: config.segments) {
            bool header = false;
            for (const auto& d: c.decisions) {
                if (d.segment != s.name || d.keep) continue;
                if (!d.device.online && !verbose) continue;
                if (!header) {
                    out += std::format("  {}\n", s.name);
                    header = true;
                }
                std::string fingerprint = d.device.vendor;
                if (!d.device.family.empty()) fingerprint += (fingerprint.empty() ? "" : " ") + d.device.family;
                out += std::format("    {}  {}  {}  {}{}\n", d.device.mac, pad(safe(d.device.label(), 28), 28), pad(d.device.ip, 15),
                                   pad(d.source + (d.detail.empty() ? "" : ":" + safe(d.detail, 32)), 30),
                                   d.device.online ? "" : "  (offline " + ago(run.now, d.device.last_seen) + ")");
                if (verbose) {
                    out += std::format("        {}{}{}\n", safe(fingerprint, 60), d.device.randomized ? "  randomized MAC" : "",
                                       d.adopted ? "  member: " + safe(d.member, 60) + " (administrator's object)" : "");
                    for (const auto& r: d.reasons) out += "        - " + safe(r, 160) + "\n";
                }
            }
        }
        for (const auto& d: c.decisions)
            if (d.keep)
                out += std::format("  protected  {}  {}  {}\n", d.device.mac, safe(d.device.label(), 28),
                                   d.segment.empty() ? "(no segment)" : "in " + d.segment);
        if (!verbose) out += "  (offline devices hidden; --verbose shows them and the reasons)\n";

        if (!c.overlaps.empty()) {
            out += "\nOverlaps (one device in several segment groups)\n";
            for (const auto& o: c.overlaps) {
                std::string list;
                for (const auto& s: o.segments) list += (list.empty() ? "" : ", ") + s;
                out += std::format("  {}  {}: {} -> {} wins: {}\n", o.mac, safe(o.label, 28), list, o.winner, safe(o.why, 200));
            }
        }
        std::vector<const Decision*> ambiguous;
        for (const auto& d: c.decisions)
            if (d.source == "ambiguous") ambiguous.push_back(&d);
        if (!ambiguous.empty()) {
            out += "\nAmbiguous (default segment until a rule priority or an assignment decides)\n";
            for (const auto* d: ambiguous) out += std::format("  {}  {}: {}\n", d->device.mac, safe(d->device.label(), 28), safe(d->reasons.back(), 160));
        }
        if (run.candidates && !run.candidates->empty()) {
            out += "\nReassociation candidates (nothing moves until you confirm)\n";
            for (const auto& k: *run.candidates) {
                std::string reasons;
                for (const auto& r: k.reasons) reasons += (reasons.empty() ? "" : ", ") + r;
                out += std::format("  {}  {} -> {}  score {}: {}\n      forti-vlan-mac confirm {}   |   forti-vlan-mac confirm --reject {}\n",
                                   k.id, k.old_mac, k.new_mac, k.score, safe(reasons, 200), k.id, k.id);
            }
        }
        if (!c.warnings.empty()) {
            out += "\nWarnings\n";
            for (const auto& w: c.warnings) out += "  " + safe(w, 240) + "\n";
        }

        if (run.changes) {
            const auto& ch = *run.changes;
            out += "\nPending changes\n";
            if (ch.changes.empty()) out += "  none: the FortiGate matches the classification\n";
            for (const auto& x: ch.changes) {
                if (x.kind == "create-group") out += std::format("  create group {}\n", x.object);
                else if (x.kind == "retire") out += std::format("  retire {} ({}): {}\n", x.object, safe(x.label, 28), x.reason);
                else if (x.kind == "comment") out += std::format("  describe {} ({})\n", x.object, safe(x.label, 28));
                else
                    out += std::format("  {} {}  {} -> {}{}   [{}]\n", x.kind, x.mac, safe(x.label, 28), x.segment,
                                       x.from.empty() ? "" : " (from " + x.from + ")", safe(x.reason, 120));
            }
            for (const auto& b: ch.blocked)
                out += std::format("  BLOCKED {}  {}: would lose {} ({} -> {}); left where it is\n", b.mac, safe(b.label, 28), b.probe,
                                   b.before.describe(), b.after.describe());
            if (!ch.deferred.empty()) out += std::format("  {} more device change(s) deferred to the next run (max_changes)\n", ch.deferred.size());
            for (const auto& n: ch.notes) out += "  note: " + safe(n, 240) + "\n";
        }
        return out;
    }

}  // namespace fvm
