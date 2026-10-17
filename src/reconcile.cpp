#include "reconcile.hpp"

#include "address_match.hpp"
#include "guard.hpp"
#include "mac.hpp"

#include <algorithm>
#include <format>
#include <set>

namespace fph {

    using json = nlohmann::json;

    namespace {

        std::string printable(std::string_view text, std::size_t limit) {
            std::string out;
            for (char c: text) {
                if (out.size() >= limit) break;
                out += (c >= 0x20 && c < 0x7f && c != '"' && c != '\\') ? c : ' ';
            }
            return out;
        }

        // Members that stand for exactly this device: a single-MAC address of its MAC, or a host IP
        // object of its address. Anything broader (ranges, subnets, groups, dynamic objects) also
        // covers other devices and is never removed on one device's behalf.
        bool single_device_member(const Snapshot& snapshot, std::string_view name, const Device& device) {
            const Address* a = snapshot.address(name);
            if (!a) return false;
            if (a->type == "mac") return a->macs.size() == 1 && normalize_mac(a->macs.front()) == device.mac;
            if (a->type == "ipmask") return !device.ip.empty() && a->subnet == device.ip + " 255.255.255.255";
            return false;
        }

        json member_list(const std::vector<std::string>& members) {
            json out = json::array();
            for (const auto& m: members) out.push_back({{"name", m}});
            return out;
        }

        bool referenced_outside(const Snapshot& snapshot, const Config& config, std::string_view object) {
            for (const auto& [name, group]: snapshot.groups) {
                bool segment_group = group.managed() && name.starts_with(config.prefix + "seg-");
                if (segment_group) continue;
                if (std::ranges::find(group.members, object) != group.members.end()) return true;
                if (std::ranges::find(group.exclude_members, object) != group.exclude_members.end()) return true;
            }
            for (const auto& policy: snapshot.policies)
                if (std::ranges::find(policy.srcaddr, object) != policy.srcaddr.end() ||
                    std::ranges::find(policy.dstaddr, object) != policy.dstaddr.end())
                    return true;
            return false;
        }

    }  // namespace

    std::string object_comment(const Device& device) {
        std::string text = std::string(marker) + ": " + printable(device.label(), 80);
        std::string fingerprint = device.vendor;
        if (!device.family.empty()) fingerprint += (fingerprint.empty() ? "" : " ") + device.family;
        if (!fingerprint.empty() && fingerprint != device.label()) text += " (" + printable(fingerprint, 80) + ")";
        return text;
    }

    std::string group_comment(const Segment& segment) {
        std::string text = std::string(marker) + ": segment " + segment.name;
        if (!segment.description.empty()) text += " - " + printable(segment.description, 150);
        return text;
    }

    Changeset reconcile(const Snapshot& snapshot, const Classification& classification, const Config& config, const State& state,
                        std::int64_t now, int max_changes) {
        Changeset out;

        // Desired members per segment group, starting from what is there.
        std::map<std::string, std::vector<std::string>> desired;   // segment -> members
        std::set<std::string> missing_groups;
        for (const auto& segment: config.segments) {
            if (classification.unusable_segments.contains(segment.name)) continue;
            if (const Group* g = snapshot.group(config.group_name(segment.name))) desired[segment.name] = g->members;
            else {
                desired[segment.name] = {};
                missing_groups.insert(segment.name);
            }
        }
        auto current = desired;

        // New managed objects to create, by member name.
        std::map<std::string, const Device*> new_objects;
        std::vector<std::string> changed_devices;   // in order, for max_changes

        for (const auto& decision: classification.decisions) {
            if (decision.keep || decision.segment.empty() || !desired.contains(decision.segment)) continue;
            const auto& device = decision.device;
            bool changed = false;
            std::string from;
            // Out of every other segment group (single-device members only).
            for (auto& [segment, members]: desired) {
                if (segment == decision.segment) continue;
                auto before = members.size();
                std::erase_if(members, [&](const auto& m) { return single_device_member(snapshot, m, device); });
                if (members.size() != before) {
                    changed = true;
                    if (from.empty()) from = segment;
                }
            }
            // Into its segment group, unless a member there already covers it.
            auto& target = desired[decision.segment];
            bool covered = std::ranges::any_of(target, [&](const auto& m) { return address_covers(snapshot, m, Endpoint{device.mac, device.ip}); });
            std::string member = decision.member;
            if (!covered) {
                target.push_back(member);
                if (decision.create_member) new_objects[member] = &decision.device;
                changed = true;
            } else {
                // Record what actually holds it there, so the next run does not mistake it for a GUI move.
                for (const auto& m: target)
                    if (address_covers(snapshot, m, Endpoint{device.mac, device.ip})) {
                        member = m;
                        break;
                    }
            }
            out.written[device.mac] = {member, decision.segment};
            if (changed) {
                changed_devices.push_back(device.mac);
                out.changes.push_back({from.empty() ? "place" : "move", device.mac, device.label(), member, decision.segment, from,
                                       decision.reasons.empty() ? decision.source : decision.reasons.back()});
            }
        }

        // max_changes: devices beyond the budget keep their current placement this run.
        if (static_cast<int>(changed_devices.size()) > max_changes) {
            std::set<std::string> deferred(changed_devices.begin() + max_changes, changed_devices.end());
            for (const auto& mac: deferred) {
                out.deferred.push_back(mac);
                const Device* device = snapshot.device(mac);
                auto it = out.written.find(mac);
                if (device && it != out.written.end()) {
                    // Restore: every single-device member of it back to its current groups.
                    for (auto& [segment, members]: desired) {
                        std::erase_if(members, [&](const auto& m) { return m == it->second.object || single_device_member(snapshot, m, *device); });
                        for (const auto& m: current[segment])
                            if ((m == it->second.object || single_device_member(snapshot, m, *device)) && std::ranges::find(members, m) == members.end())
                                members.push_back(m);
                    }
                    new_objects.erase(it->second.object);
                    out.written.erase(it);
                }
            }
            std::erase_if(out.changes, [&](const Change& c) { return deferred.contains(c.mac); });
        }

        // Retirement of managed objects for devices long gone or replaced by a confirmed reassociation.
        // Never when the inventory came back empty: that is a read problem, not departed devices.
        std::set<std::string> retiring_objects;
        if (!snapshot.devices.empty()) {
            for (const auto& [mac, record]: state.devices) {
                const Device* device = snapshot.device(mac);
                if (device && device->online) continue;
                bool expired = record.last_seen > 0 && now - record.last_seen > static_cast<std::int64_t>(config.retire_after_days) * 86400;
                bool replaced = state.retire_now.contains(mac);
                if (!expired && !replaced) continue;
                const Address* object = snapshot.address(record.object);
                if (!object) {
                    out.retired.push_back(mac);   // already gone (deleted in the GUI): just forget it
                    continue;
                }
                bool ours = object->managed() && object->name.starts_with(config.device_prefix()) && object->type == "mac" &&
                            object->macs.size() == 1 && normalize_mac(object->macs.front()) == mac;
                if (!ours) {
                    // Adopted (an administrator's object) or edited since: remove our reference, keep the object.
                    for (auto& [segment, members]: desired) std::erase(members, record.object);
                    out.retired.push_back(mac);
                    out.changes.push_back({"retire", mac, record.label, record.object, {}, record.written_segment,
                                           "not an object forti-pihole owns: reference removed, object kept"});
                    continue;
                }
                if (referenced_outside(snapshot, config, object->name)) {
                    out.notes.push_back(std::format("{} ({}) is due for retirement but is used outside the segment groups; kept",
                                                    object->name, record.label));
                    continue;
                }
                for (auto& [segment, members]: desired) std::erase(members, object->name);
                retiring_objects.insert(object->name);
                out.retired.push_back(mac);
                out.changes.push_back({"retire", mac, record.label, object->name, {}, record.written_segment,
                                       replaced ? "replaced by a confirmed reassociation"
                                                : std::format("not seen for more than {} days", config.retire_after_days)});
            }
        }

        // Connectivity: simulate the result, and keep the current placement of any device that would
        // lose its reach. Repeats until stable (restoring one device cannot hurt another: the members
        // restored are its own single-device objects).
        auto build_after = [&]() {
            Snapshot after = snapshot;
            for (const auto& [name, device]: new_objects) {
                Address a;
                a.name = name;
                a.type = "mac";
                a.macs = {device->mac};
                a.comment = object_comment(*device);
                after.addresses[name] = a;
            }
            for (const auto& [segment, members]: desired) {
                auto name = config.group_name(segment);
                auto& group = after.groups[name];
                group.name = name;
                if (group.comment.empty()) group.comment = group_comment(*config.segment(segment));
                group.members = members;
            }
            for (const auto& name: retiring_objects) after.addresses.erase(name);
            return after;
        };
        for (int round = 0; round < 8; ++round) {
            auto losses = compare(snapshot, build_after());
            if (losses.empty()) break;
            for (const auto& loss: losses) {
                out.blocked.push_back(loss);
                const Device* device = snapshot.device(loss.mac);
                if (!device) continue;
                auto written = out.written.find(loss.mac);
                for (auto& [segment, members]: desired) {
                    std::erase_if(members, [&](const auto& m) {
                        return (written != out.written.end() && m == written->second.object) || single_device_member(snapshot, m, *device);
                    });
                    for (const auto& m: current[segment])
                        if (single_device_member(snapshot, m, *device) || (written != out.written.end() && m == written->second.object))
                            if (std::ranges::find(members, m) == members.end()) members.push_back(m);
                }
                if (written != out.written.end()) {
                    new_objects.erase(written->second.object);
                    out.written.erase(written);
                }
                std::erase_if(out.changes, [&](const Change& c) { return c.mac == loss.mac && c.kind != "retire"; });
            }
        }

        // Operations: create objects, create groups, update groups, delete retired objects.
        for (const auto& [name, device]: new_objects) {
            bool used = std::ranges::any_of(desired, [&](const auto& entry) { return std::ranges::find(entry.second, name) != entry.second.end(); });
            if (!used) continue;
            out.operations.push_back({{"op", "create"}, {"resource", "firewall/address"},
                                      {"object", {{"name", name}, {"type", "mac"}, {"macaddr", json::array({{{"macaddr", device->mac}}})},
                                                  {"comment", object_comment(*device)}}}});
        }
        for (const auto& segment: config.segments) {
            if (!missing_groups.contains(segment.name)) continue;
            out.operations.push_back({{"op", "create"}, {"resource", "firewall/addrgrp"},
                                      {"object", {{"name", config.group_name(segment.name)}, {"member", member_list(desired[segment.name])},
                                                  {"comment", group_comment(segment)}}}});
            out.changes.push_back({"create-group", {}, {}, config.group_name(segment.name), segment.name, {}, "segment group missing"});
        }
        for (const auto& segment: config.segments) {
            if (missing_groups.contains(segment.name) || !desired.contains(segment.name)) continue;
            auto want = desired[segment.name];
            auto have = current[segment.name];
            auto sorted_want = want, sorted_have = have;
            std::ranges::sort(sorted_want);
            std::ranges::sort(sorted_have);
            if (sorted_want == sorted_have) continue;
            out.operations.push_back({{"op", "update"}, {"resource", "firewall/addrgrp"}, {"key", config.group_name(segment.name)},
                                      {"set", {{"member", member_list(want)}}}});
        }
        for (const auto& name: retiring_objects)
            out.operations.push_back({{"op", "delete"}, {"resource", "firewall/address"}, {"key", name}});

        // Comments of managed device objects follow what the inventory learns (a hostname appearing).
        for (const auto& decision: classification.decisions) {
            if (decision.adopted || decision.create_member) continue;
            const Address* a = snapshot.address(decision.member);
            if (!a || !a->managed() || retiring_objects.contains(a->name)) continue;
            auto comment = object_comment(decision.device);
            if (a->comment == comment) continue;
            out.operations.push_back({{"op", "update"}, {"resource", "firewall/address"}, {"key", a->name}, {"set", {{"comment", comment}}}});
            out.changes.push_back({"comment", decision.device.mac, decision.device.label(), a->name, {}, {}, "description refreshed"});
        }

        // Managed segment groups whose segment is no longer configured.
        for (const auto& [name, group]: snapshot.groups) {
            if (!group.managed() || !name.starts_with(config.prefix + "seg-")) continue;
            auto segment = name.substr(config.prefix.size() + 4);
            if (!config.segment(segment))
                out.notes.push_back(std::format("{} belongs to no configured segment; left as it is (delete it in the GUI when unused)", name));
        }

        // The allowlist, before anything reaches the engine.
        check_operations(out.operations, snapshot, config);
        return out;
    }

}  // namespace fph
