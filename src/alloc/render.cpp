#include "render.hpp"

namespace fph::alloc {

    using nlohmann::json;

    namespace {

        json usage_json(const Usage& usage) {
            return {{"used", usage.used}, {"total", usage.total}, {"free", usage.free}};
        }

        json conflict_json(const Conflict& conflict) {
            json out = {{"kind", conflict_kind_name(conflict.kind)},
                        {"group", conflict.slice.group},
                        {"slice", conflict.slice.cidr.str()},
                        {"detail", conflict.detail}};
            if (conflict.range) out["range"] = conflict.range->str();
            if (conflict.ip) out["ip"] = format_ipv4(*conflict.ip);
            if (conflict.use) out["use"] = use_name(*conflict.use);
            if (!conflict.label.empty()) out["label"] = conflict.label;
            if (!conflict.mac.empty()) out["mac"] = conflict.mac;
            if (conflict.other) out["other"] = conflict.other->str();
            return out;
        }

        json pool_change_json(const PoolChange& change) {
            return {{"kind", change.kind == PoolChange::Kind::shrink ? "shrink" : "exclude"},
                    {"pool", change.pool_id},
                    {"range", change.pool.str()},
                    {change.kind == PoolChange::Kind::shrink ? "new_range" : "exclude_range", change.result.str()},
                    {"frees", change.frees.str()},
                    {"detail", change.detail}};
        }

        json blocks_json(const std::vector<Cidr>& blocks) {
            json out = json::array();
            for (const auto& block: blocks) out.push_back(block.str());
            return out;
        }

    }  // namespace

    json to_json(std::span<const Conflict> conflicts) {
        json out = json::array();
        for (const auto& conflict: conflicts) out.push_back(conflict_json(conflict));
        return out;
    }

    json to_json(const Utilization& utilization) {
        json slices = json::array();
        for (const auto& entry: utilization.slices) {
            json item = usage_json(entry.usage);
            item["group"] = entry.slice.group;
            item["slice"] = entry.slice.cidr.str();
            slices.push_back(std::move(item));
        }
        return {{"slices", std::move(slices)}, {"overall", usage_json(utilization.overall)}};
    }

    json to_json(const Proposal& proposal) {
        json slices = json::array();
        for (std::size_t i = 0; i < proposal.slices.size(); ++i) {
            const auto& slice = proposal.slices[i];
            json item = {{"group", slice.group},
                         {"cidr", slice.cidr.str()},
                         {"origin", slice.retained ? "retained" : "new"},
                         {"first", format_ipv4(slice.cidr.first())},
                         {"last", format_ipv4(slice.cidr.last())}};
            // utilization() keeps the order of the slices it is given.
            if (i < proposal.utilization.slices.size()) item["usage"] = usage_json(proposal.utilization.slices[i].usage);
            slices.push_back(std::move(item));
        }
        json dropped = json::array();
        for (const auto& slice: proposal.dropped) dropped.push_back({{"group", slice.group}, {"cidr", slice.cidr.str()}});
        json changes = json::array();
        for (const auto& change: proposal.pool_changes) changes.push_back(pool_change_json(change));
        json groups = json::array();
        for (const auto& group: proposal.groups) {
            json alternatives = json::array();
            for (const auto& alt: group.alternatives) {
                json item = {{"kind", alternative_kind_name(alt.kind)},
                             {"detail", alt.detail},
                             {"slices", blocks_json(alt.slices)},
                             {"disturbed", alt.disturbed}};
                if (alt.pool_change) item["pool_change"] = pool_change_json(*alt.pool_change);
                alternatives.push_back(std::move(item));
            }
            groups.push_back({{"group", group.group},
                              {"expected", group.expected},
                              {"needed", group.needed},
                              {"capacity", group.capacity},
                              {"missing", group.missing},
                              {"alternatives", std::move(alternatives)}});
        }
        return {{"network", proposal.network.str()},
                {"complete", proposal.complete()},
                {"slices", std::move(slices)},
                {"dropped", std::move(dropped)},
                {"pool_changes", std::move(changes)},
                {"groups", std::move(groups)},
                {"conflicts", to_json(proposal.conflicts)},
                {"utilization", usage_json(proposal.utilization.overall)}};
    }

}  // namespace fph::alloc
