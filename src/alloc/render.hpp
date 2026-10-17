//
// JSON renderings of the planner's results for the CLI's --json output. Addresses, ranges and
// blocks are strings ("192.168.1.2", "192.168.1.2-192.168.1.200", "192.168.1.224/28"), enums are
// kebab-case names (use_name and friends in plan.hpp); field order follows the structs.
//

#ifndef FORTI_PIHOLE_ALLOC_RENDER_HPP
#define FORTI_PIHOLE_ALLOC_RENDER_HPP

#include "plan.hpp"

#include <nlohmann/json.hpp>

#include <span>

namespace fph::alloc {

    nlohmann::json to_json(const Proposal& proposal);
    nlohmann::json to_json(std::span<const Conflict> conflicts);
    nlohmann::json to_json(const Utilization& utilization);

}  // namespace fph::alloc

#endif  // FORTI_PIHOLE_ALLOC_RENDER_HPP
