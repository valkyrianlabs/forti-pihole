#include "reassociate.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <map>

namespace fvm {

    namespace {

        std::string lowered(std::string_view text) {
            std::string out;
            for (char c: text) out += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
            return out;
        }

        bool same(const std::string& a, const std::string& b) { return !a.empty() && lowered(a) == lowered(b); }

    }  // namespace

    bool generic_hostname(std::string_view hostname) {
        // Names devices use when the owner never named them; seen many times on one network.
        static constexpr std::array generic = {"iphone", "ipad", "watch", "macbook-air", "macbook-pro", "macbook", "android",
                                               "galaxy", "samsung", "localhost", "none", "unknown", "espressif", "amazon",
                                               "echo", "chromecast", "roku", "hs103", "hs300", "hs105", "kp115"};
        auto name = lowered(hostname);
        if (name.empty()) return true;
        // "iphone-303", "android-3": a generic stem plus a counter is still generic.
        auto stem = name.substr(0, name.find_first_of("-_0123456789"));
        return std::ranges::any_of(generic, [&](const char* g) { return name == g || stem == g; });
    }

    std::string candidate_id(std::string_view old_mac, std::string_view new_mac) {
        // FNV-1a over both MACs: stable across runs, short enough to type.
        std::uint32_t hash = 2166136261u;
        for (auto text: {old_mac, std::string_view("|"), new_mac})
            for (char c: text) {
                hash ^= static_cast<unsigned char>(c);
                hash *= 16777619u;
            }
        return std::format("{:08x}", hash);
    }

    std::vector<Candidate> find_candidates(const Snapshot& snapshot, const State& state, const Classification& classification,
                                           std::int64_t now) {
        std::vector<Candidate> found;

        // A hostname more than one current device carries identifies none of them.
        std::map<std::string, int> name_count;
        // Offline entries do not count: the device's own old MAC usually still carries the name.
        for (const auto& d: snapshot.devices)
            if (d.online && !d.hostname.empty()) ++name_count[lowered(d.hostname)];

        for (const auto& device: snapshot.devices) {
            if (state.devices.contains(device.mac)) continue;   // not new
            if (device.hostname.empty() || generic_hostname(device.hostname) || name_count[lowered(device.hostname)] > 1) continue;

            for (const auto& [old_mac, record]: state.devices) {
                if (old_mac == device.mac) continue;
                const Device* old_now = snapshot.device(old_mac);
                if (old_now && old_now->online) continue;   // both alive: two devices, not one
                bool has_segment = !record.written_segment.empty() || state.pins.contains(old_mac);
                if (!has_segment) continue;
                if (!same(record.hostname, device.hostname)) continue;

                Candidate candidate;
                candidate.old_mac = old_mac;
                candidate.new_mac = device.mac;
                candidate.score = 3;
                candidate.reasons.push_back(std::format("hostname \"{}\"", device.hostname));
                if (same(record.family, device.family)) {
                    candidate.score += 1;
                    candidate.reasons.push_back("hardware family " + device.family);
                }
                if (same(record.os, device.os)) {
                    candidate.score += 1;
                    candidate.reasons.push_back("OS " + device.os);
                }
                if (same(record.os_version, device.os_version)) {
                    candidate.score += 1;
                    candidate.reasons.push_back("OS version " + device.os_version);
                }
                if (same(record.vendor, device.vendor)) {
                    candidate.score += 1;
                    candidate.reasons.push_back("vendor " + device.vendor);
                }
                if (device.randomized) candidate.reasons.push_back("new MAC is randomized (private address)");
                if (candidate.score < candidate_threshold) continue;
                candidate.id = candidate_id(old_mac, device.mac);
                if (state.dismissed.contains(candidate.id) || state.candidate(candidate.id)) continue;
                candidate.found_at = now;
                found.push_back(std::move(candidate));
            }
        }
        (void) classification;
        return found;
    }

}  // namespace fvm
