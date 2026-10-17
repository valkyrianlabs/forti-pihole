//
// Human-readable and JSON renderings of a run: the inventory as classified, overlaps, ambiguity,
// reassociation candidates, drift and the pending change set. Device strings are untrusted; the text
// renderer strips control characters so a hostname cannot rewrite the terminal.
//

#ifndef FORTI_VLAN_MAC_REPORT_HPP
#define FORTI_VLAN_MAC_REPORT_HPP

#include "classify.hpp"
#include "config.hpp"
#include "inventory.hpp"
#include "reconcile.hpp"
#include "state.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

namespace fvm {

    struct Run {
        const Snapshot* snapshot = nullptr;
        const Classification* classification = nullptr;
        const Changeset* changes = nullptr;
        const std::vector<Candidate>* candidates = nullptr;   // all open candidates (state + new)
        const Config* config = nullptr;
        std::int64_t now = 0;
    };

    nlohmann::json report_json(const Run& run);
    std::string report_text(const Run& run, bool verbose);

    // Strips control characters and bounds length (device-provided text).
    std::string safe(std::string_view text, std::size_t limit = 64);

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_REPORT_HPP
