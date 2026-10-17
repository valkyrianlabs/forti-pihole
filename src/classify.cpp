#include "classify.hpp"

#include "address_match.hpp"
#include "mac.hpp"

#include <algorithm>
#include <format>

namespace fvm {

    namespace {

        char lower(char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; }

        bool single_mac(const Address& address, std::string_view mac) {
            return address.type == "mac" && address.macs.size() == 1 && normalize_mac(address.macs.front()) == std::string(mac);
        }

        void add_unique(std::vector<std::string>& list, const std::string& value) {
            if (std::ranges::find(list, value) == list.end()) list.push_back(value);
        }

        // Native rule objects: <prefix>rule-<segment>-<label>, dynamic device-identification. Segment
        // names never contain '-', so the first '-' after the rule prefix ends the segment.
        std::string native_rule_segment(const Config& config, const Address& address) {
            auto prefix = config.rule_prefix();
            if (!address.name.starts_with(prefix)) return {};
            auto rest = std::string_view(address.name).substr(prefix.size());
            auto dash = rest.find('-');
            return std::string(rest.substr(0, dash));
        }

        std::string pick_by_rank(const Config& config, std::vector<std::string> segments) {
            std::ranges::sort(segments, [&](const auto& a, const auto& b) { return config.segment_rank(a) < config.segment_rank(b); });
            return segments.empty() ? std::string() : segments.front();
        }

    }  // namespace

    const Decision* Classification::decision(std::string_view mac) const {
        for (const auto& d: decisions)
            if (d.device.mac == mac) return &d;
        return nullptr;
    }

    bool glob_match(std::string_view pattern, std::string_view text) {
        // Iterative matcher with single-star backtracking: linear in practice, no recursion.
        std::size_t p = 0, t = 0, star = std::string_view::npos, mark = 0;
        while (t < text.size()) {
            if (p < pattern.size() && (pattern[p] == '?' || lower(pattern[p]) == lower(text[t]))) {
                ++p;
                ++t;
            } else if (p < pattern.size() && pattern[p] == '*') {
                star = p++;
                mark = t;
            } else if (star != std::string_view::npos) {
                p = star + 1;
                t = ++mark;
            } else return false;
        }
        while (p < pattern.size() && pattern[p] == '*') ++p;
        return p == pattern.size();
    }

    bool rule_matches(const Match& match, const Device& device) {
        auto check = [](const std::string& pattern, const std::string& value) {
            return pattern.empty() || (!value.empty() && glob_match(pattern, value));
        };
        if (!check(match.vendor, device.vendor)) return false;
        if (!check(match.family, device.family)) return false;
        if (!check(match.type, device.type)) return false;
        if (!check(match.os, device.os)) return false;
        if (!check(match.hostname, device.hostname)) return false;
        if (!check(match.vci, device.vci)) return false;
        if (!match.mac_prefix.empty() && !device.mac.starts_with(match.mac_prefix)) return false;
        return true;
    }

    bool covers(const Snapshot& snapshot, std::string_view name, const Device& device) {
        Endpoint endpoint{device.mac, device.ip};
        return address_covers(snapshot, name, endpoint);
    }

    std::string device_object_name(const Config& config, const Device& device, const Snapshot& snapshot) {
        std::string slug;
        for (char c: device.label()) {
            char l = lower(c);
            if ((l >= 'a' && l <= 'z') || (l >= '0' && l <= '9')) slug += l;
            else if (!slug.empty() && slug.back() != '-') slug += '-';
        }
        while (!slug.empty() && slug.back() == '-') slug.pop_back();
        if (slug == mac_suffix(device.mac) || slug.empty()) slug = "device";
        auto suffix = mac_suffix(device.mac);
        auto base = config.device_prefix();
        // 79 is FortiOS's address name limit; leave room for "-<suffix>" and a collision counter.
        std::size_t room = 79 - base.size() - suffix.size() - 4;
        if (slug.size() > room) slug.resize(room);
        while (!slug.empty() && slug.back() == '-') slug.pop_back();
        std::string name = std::format("{}{}-{}", base, slug, suffix);
        for (int n = 2; snapshot.address(name) && n < 100; ++n) name = std::format("{}{}-{}-{}", base, slug, suffix, n);
        return name;
    }

    Classification classify(const Snapshot& snapshot, const Config& config, const State& state, std::int64_t now) {
        Classification result;

        // Segment groups that exist but are not ours (no marker): a name clash with an administrator's
        // object. Those segments are left alone entirely.
        for (const auto& segment: config.segments) {
            const Group* group = snapshot.group(config.group_name(segment.name));
            if (group && !group->managed()) {
                result.unusable_segments.insert(segment.name);
                result.warnings.push_back(std::format(
                        "address group {} exists without the \"{}\" marker; segment {} is not managed until it is renamed or marked",
                        group->name, marker, segment.name));
            }
        }

        // Native rule objects (GUI-made dynamic device-identification addresses).
        struct NativeRule {
            const Address* address;
            std::string segment;
        };
        std::vector<NativeRule> native_rules;
        for (const auto& [name, address]: snapshot.addresses) {
            if (!name.starts_with(config.rule_prefix())) continue;
            auto segment_name = native_rule_segment(config, address);
            const Segment* segment = config.segment(segment_name);
            if (address.type != "dynamic" || address.sub_type != "device-identification") {
                result.warnings.push_back(std::format("{}: rule objects must be dynamic device-identification addresses; ignored", name));
            } else if (!segment) {
                result.warnings.push_back(std::format("{}: no segment \"{}\" in the configuration; ignored", name, segment_name));
            } else if (segment->privileged) {
                result.warnings.push_back(std::format(
                        "{}: segment {} is privileged and only entered by explicit assignment; rule ignored", name, segment_name));
            } else native_rules.push_back({&address, segment_name});
        }

        for (const auto& device: snapshot.devices) {
            Decision decision;
            decision.device = device;
            const auto& mac = device.mac;
            const DeviceRecord* record = nullptr;
            if (auto it = state.devices.find(mac); it != state.devices.end()) record = &it->second;

            // Observed placements, in config order.
            for (const auto& segment: config.segments) {
                if (result.unusable_segments.contains(segment.name)) continue;
                const Group* group = snapshot.group(config.group_name(segment.name));
                if (!group) continue;
                for (const auto& member: group->members) {
                    if (!covers(snapshot, member, device)) continue;
                    bool ours = state.wrote(mac, member, segment.name);
                    decision.placements.push_back({segment.name, member, ours});
                }
            }

            // Rule matches.
            for (const auto& rule: config.rules)
                if (rule_matches(rule.match, device)) decision.matches.push_back({rule.segment, rule.name, rule.priority, false});
            for (const auto& native: native_rules)
                if (std::ranges::find(native.address->resolved, mac) != native.address->resolved.end())
                    decision.matches.push_back({native.segment, native.address->name, config.native_rule_priority, true});
            std::ranges::stable_sort(decision.matches, [](const auto& a, const auto& b) { return a.priority > b.priority; });

            // Member object for this device.
            const Address* existing = nullptr;
            if (record && !record->object.empty())
                if (const Address* a = snapshot.address(record->object); a && single_mac(*a, mac)) existing = a;
            if (!existing)
                for (const auto& [name, address]: snapshot.addresses)
                    if (address.managed() && single_mac(address, mac) && name.starts_with(config.device_prefix())) {
                        existing = &address;
                        break;
                    }
            if (!existing && config.adopt_existing) {
                if (const Address* a = snapshot.address(device.firewall_address); a && !a->managed() && single_mac(*a, mac))
                    existing = a;
                else
                    for (const auto& [name, address]: snapshot.addresses)
                        if (!address.managed() && single_mac(address, mac) && !name.starts_with(config.prefix)) {
                            existing = &address;
                            break;
                        }
            }
            if (existing) {
                decision.member = existing->name;
                decision.adopted = !existing->managed();
            } else {
                decision.member = device_object_name(config, device, snapshot);
                decision.create_member = true;
            }

            // A managed object the operator re-pointed at another MAC in the GUI: report, never "fix".
            if (record && !record->object.empty())
                if (const Address* a = snapshot.address(record->object); a && a->managed() && !single_mac(*a, mac))
                    result.warnings.push_back(std::format(
                            "{} no longer holds only {} ({}); it was edited outside forti-vlan-mac and is left as it is",
                            record->object, mac, device.label()));

            // 1. protected
            if (config.is_protected(mac)) {
                decision.keep = true;
                decision.source = "protected";
                std::vector<std::string> observed;
                for (const auto& p: decision.placements) add_unique(observed, p.segment);
                decision.segment = pick_by_rank(config, observed);
                decision.reasons.push_back("listed in config \"protected\": never classified or moved automatically");
                result.decisions.push_back(std::move(decision));
                continue;
            }

            // Operator placements: everything observed that the companion did not write itself.
            std::vector<std::string> operator_segments;
            for (const auto& p: decision.placements)
                if (!p.by_companion) add_unique(operator_segments, p.segment);
            std::vector<std::string> observed;
            for (const auto& p: decision.placements) add_unique(observed, p.segment);

            std::optional<Pin> pin;
            if (auto it = state.pins.find(mac); it != state.pins.end()) pin = it->second;

            if (state.has_written(mac)) {
                std::string written_object = record ? record->object : std::string();
                std::string written_segment = record ? record->written_segment : std::string();
                if (state.pending)
                    if (auto it = state.pending->written.find(mac); it != state.pending->written.end())
                        std::tie(written_object, written_segment) = it->second;
                bool member_exists = snapshot.address(written_object) != nullptr;
                if (!operator_segments.empty()) {
                    auto chosen = pick_by_rank(config, operator_segments);
                    if (!pin || pin->segment != chosen) {
                        pin = Pin{chosen, "gui", now};
                        result.new_pins[mac] = *pin;
                        decision.reasons.push_back(std::format("moved to {} in the FortiGate GUI", chosen));
                    }
                } else if (observed.empty() && member_exists) {
                    // Taken out of every segment group but the object kept: the operator wants it out of
                    // where it was; the safe place is the default segment.
                    if (!pin || pin->segment != config.default_segment) {
                        pin = Pin{config.default_segment, "gui", now};
                        result.new_pins[mac] = *pin;
                        decision.reasons.push_back(std::format("removed from {} in the FortiGate GUI; default segment", written_segment));
                    }
                } else if (observed.empty() && !member_exists && pin && pin->source == "gui") {
                    // The operator deleted the object: back to automatic classification.
                    result.cleared_pins.insert(mac);
                    pin.reset();
                    decision.reasons.push_back(std::format("{} was deleted in the GUI; classification is automatic again", written_object));
                }
            } else if (!operator_segments.empty()) {
                // Placed by the operator before the companion ever wrote anything for it.
                auto chosen = pick_by_rank(config, operator_segments);
                if (!pin || pin->segment != chosen) {
                    pin = Pin{chosen, "gui", now};
                    result.new_pins[mac] = *pin;
                    decision.reasons.push_back(std::format("placed in {} by the operator", chosen));
                }
            }

            if (observed.size() > 1) {
                Overlap overlap{mac, device.label(), observed, {}, {}};
                result.overlaps.push_back(std::move(overlap));
            }

            // 2-5.
            if (auto it = config.assignments.find(mac); it != config.assignments.end()) {
                decision.segment = it->second;
                decision.source = "assignment";
                decision.reasons.push_back("explicit assignment in config.json");
            } else if (pin && config.segment(pin->segment)) {
                decision.segment = pin->segment;
                decision.source = "pin";
                decision.detail = pin->source;
                decision.reasons.push_back(pin->source == "gui" ? "operator placement in the FortiGate GUI"
                                           : pin->source == "confirm" ? "confirmed reassociation"
                                                                      : "explicit assignment (forti-vlan-mac assign)");
            } else if (!decision.matches.empty()) {
                const auto& top = decision.matches.front();
                std::vector<std::string> rivals;
                for (const auto& m: decision.matches)
                    if (m.priority == top.priority) add_unique(rivals, m.segment);
                if (rivals.size() > 1) {
                    decision.segment = config.default_segment;
                    decision.source = "ambiguous";
                    std::string list;
                    for (const auto& s: rivals) list += (list.empty() ? "" : ", ") + s;
                    decision.reasons.push_back(std::format("rules of equal priority {} disagree ({}); default segment until resolved",
                                                           top.priority, list));
                } else {
                    decision.segment = top.segment;
                    decision.source = "rule";
                    decision.detail = top.rule;
                    decision.reasons.push_back(std::format("{} rule {} (priority {})", top.native ? "native" : "config", top.rule,
                                                           top.priority));
                }
            } else {
                decision.segment = config.default_segment;
                decision.source = "default";
                decision.reasons.push_back("no rule matched");
            }

            if (result.unusable_segments.contains(decision.segment)) {
                decision.reasons.push_back(std::format("segment {} is not managed (name clash); default segment", decision.segment));
                decision.segment = config.default_segment;
            }
            if (!result.overlaps.empty() && result.overlaps.back().mac == mac) {
                auto& overlap = result.overlaps.back();
                overlap.winner = decision.segment;
                overlap.why = std::format("{} ({}); until the extra placements are removed, FortiGate policies match "
                                          "whichever segment's policy comes first",
                                          decision.source, decision.reasons.empty() ? "" : decision.reasons.back());
            }
            result.decisions.push_back(std::move(decision));
        }
        return result;
    }

}  // namespace fvm
