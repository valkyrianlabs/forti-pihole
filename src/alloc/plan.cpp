#include "plan.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <functional>
#include <set>
#include <stdexcept>
#include <tuple>

namespace fph::alloc {

    namespace {

        constexpr int smallest_slice_prefix = 30;   // the sizing rule's floor (plan.hpp)

        std::uint64_t needed_for(const Request& request) {
            // The epsilon keeps 10 * 1.1 (11.000000000000002 in binary) from becoming 12.
            double scaled = static_cast<double>(request.expected) * std::max(request.headroom, 1.0);
            auto need = static_cast<std::uint64_t>(std::ceil(scaled - 1e-9));
            return std::max<std::uint64_t>({need, request.expected, 1});
        }

        struct Bounds {
            int largest = 0;    // smallest prefix length allowed
            int smallest = 0;   // largest prefix length allowed
        };

        // The prefix of the smallest block of at least max(4, count) addresses, within `bounds`.
        int prefix_for(std::uint64_t count, const Bounds& bounds) {
            std::uint64_t size = std::bit_ceil(std::max<std::uint64_t>(count, 4));
            int prefix = 32 - std::countr_zero(size);
            return std::clamp(prefix, bounds.largest, bounds.smallest);
        }

        std::string pool_label(int id) {
            return "pool " + std::to_string(id);
        }

        // A pool is named by id and current range together: FortiOS ids are unique per server, but
        // the planner never assumes the input is well formed.
        void apply_change(std::vector<Pool>& pools, std::vector<Range>& excludes, const PoolChange& change) {
            if (change.kind == PoolChange::Kind::exclude) {
                excludes.push_back(change.result);
                return;
            }
            for (auto& pool: pools)
                if (pool.id == change.pool_id && pool.range == change.pool) pool.range = change.result;
        }

        std::vector<Range> dynamic_ranges(const std::vector<Pool>& pools, const std::vector<Range>& excludes) {
            std::vector<Range> ranges;
            for (const auto& pool: pools) ranges.push_back(pool.range);
            return subtract(std::move(ranges), excludes);
        }

        // The planner's working view: the input's facts plus what the plan has added so far.
        struct State {
            const PlanInput* input = nullptr;
            std::vector<Occupant> occupants;   // effective occupancy sorted by address
            std::vector<Pool> pools;
            std::vector<Range> excludes;
            std::vector<Slice> slices;

            [[nodiscard]] const Cidr& network() const { return input->network; }

            [[nodiscard]] std::span<const Occupant> occupants_in(const Range& range) const {
                auto lo = std::lower_bound(occupants.begin(), occupants.end(), range.lo,
                                           [](const Occupant& o, Ipv4 ip) { return o.ip < ip; });
                auto hi = std::upper_bound(lo, occupants.end(), range.hi, [](Ipv4 ip, const Occupant& o) { return ip < o.ip; });
                return {lo, hi};
            }

            [[nodiscard]] std::vector<Range> dynamic() const { return dynamic_ranges(pools, excludes); }

            [[nodiscard]] bool reserved(Ipv4 ip) const {
                for (const auto& o: occupants_in(Range::single(ip)))
                    if (o.use == Use::reservation) return true;
                return false;
            }

            // Addresses a slice of `group` may not cover: interface IPs and everyone else's addresses.
            [[nodiscard]] std::vector<Range> blockers(const std::string& group) const {
                std::vector<Range> out;
                for (const auto& o: occupants)
                    if (o.use == Use::interface_ip || o.group != group) out.push_back(Range::single(o.ip));
                return out;
            }

            // Free space for a new slice of `group`: inside the network, outside every dynamic range
            // and every slice, holding no one else's address.
            [[nodiscard]] std::vector<Range> free_for(const std::string& group) const {
                auto blocked = dynamic();
                for (const auto& slice: slices) blocked.push_back(slice.cidr.range());
                auto points = blockers(group);
                blocked.insert(blocked.end(), points.begin(), points.end());
                return subtract({network().range()}, std::move(blocked));
            }

            // What the group's slices offer: their usable addresses, less other groups' overlapping
            // slices, interface IPs and addresses someone else holds.
            [[nodiscard]] std::uint64_t capacity_of(const std::string& group) const {
                std::vector<Range> mine;
                std::vector<Range> theirs;
                for (const auto& slice: slices) {
                    if (slice.group != group) {
                        theirs.push_back(slice.cidr.range());
                    } else if (auto usable = slice.cidr.usable(network())) {
                        mine.push_back(*usable);
                    }
                }
                auto points = blockers(group);
                theirs.insert(theirs.end(), points.begin(), points.end());
                std::uint64_t total = 0;
                for (const auto& range: subtract(std::move(mine), std::move(theirs))) total += range.size();
                return total;
            }

            void apply(const PoolChange& change) { apply_change(pools, excludes, change); }
        };

        // Best fit: among the maximal free CIDR blocks that can hold a block of `prefix`, the
        // smallest (then the lowest), and in it the lowest aligned block with at least `min_usable`
        // usable addresses. Taking the snuggest container keeps large free blocks whole for later.
        std::optional<Cidr> best_fit(const State& state, const std::string& group, int prefix, std::uint64_t min_usable) {
            std::vector<Cidr> containers;
            for (const auto& range: state.free_for(group))
                for (const auto& block: cover(range))
                    if (block.prefix <= prefix) containers.push_back(block);
            std::sort(containers.begin(), containers.end(), [](const Cidr& a, const Cidr& b) {
                return std::tie(b.prefix, a.network) < std::tie(a.prefix, b.network);
            });
            const std::uint64_t step = std::uint64_t{1} << (32 - prefix);
            for (const auto& container: containers) {
                for (std::uint64_t at = container.first(); at <= container.last(); at += step) {
                    Cidr candidate{static_cast<Ipv4>(at), prefix};
                    // Only the blocks at the parent's edges lose an address, so this ends quickly.
                    if (candidate.usable_count(state.network()) >= min_usable) return candidate;
                }
            }
            return std::nullopt;
        }

        // A slice for `deficit` more addresses: the sizing rule's block, or a larger one (within the
        // bounds) when only blocks at the network's edges, which lose an address, are free.
        std::optional<Cidr> fit_deficit(const State& state, const std::string& group, std::uint64_t deficit, const Bounds& bounds) {
            int prefix = prefix_for(deficit, bounds);
            bool capped = (std::uint64_t{1} << (32 - prefix)) < deficit;
            if (capped) return best_fit(state, group, prefix, 1);
            for (int p = prefix; p >= bounds.largest; --p)
                if (auto found = best_fit(state, group, p, deficit)) return found;
            return std::nullopt;
        }

        // Fills the whole deficit with slices of the sizing rule, or nothing. Mutates `state`.
        std::optional<std::vector<Cidr>> fill(State& state, const std::string& group, std::uint64_t need, const Bounds& bounds) {
            std::vector<Cidr> added;
            for (auto capacity = state.capacity_of(group); capacity < need; capacity = state.capacity_of(group)) {
                auto found = fit_deficit(state, group, need - capacity, bounds);
                if (!found) return std::nullopt;
                state.slices.push_back({group, *found, false});
                added.push_back(*found);
            }
            return added;
        }

        struct Candidate {
            PoolChange change;
            std::vector<std::string> disturbed;
        };

        // Whether `block` would be a clean new slice of `group` once `change` is made, and which
        // current dynamic leases the change would displace. Leases are the only occupants a pool
        // change may displace: everything else (reservations, VIPs, objects, static devices) is
        // someone's configured address and is never renumbered.
        std::optional<Candidate> evaluate(const State& state, const std::string& group, const Cidr& block, std::uint64_t min_usable,
                                          const PoolChange& change, const Range& freed) {
            if (!state.network().contains(block) || block.usable_count(state.network()) < min_usable) return std::nullopt;
            for (const auto& slice: state.slices)
                if (slice.cidr.overlaps(block)) return std::nullopt;
            for (const auto& o: state.occupants_in(block.range()))
                if (o.use == Use::interface_ip || (o.use != Use::lease && o.group != group)) return std::nullopt;
            auto pools = state.pools;
            auto excludes = state.excludes;
            apply_change(pools, excludes, change);
            for (const auto& range: dynamic_ranges(pools, excludes))
                if (range.overlaps(block.range())) return std::nullopt;

            Candidate candidate{change, {}};
            std::set<Ipv4> seen;
            auto consider = [&](const Range& range) {
                for (const auto& o: state.occupants_in(range)) {
                    if (o.use != Use::lease || state.reserved(o.ip)) continue;
                    if (o.group == group && block.contains(o.ip)) continue;   // already where it belongs
                    if (seen.insert(o.ip).second) candidate.disturbed.push_back(o.label.empty() ? format_ipv4(o.ip) : o.label);
                }
            };
            consider(freed);
            consider(block.range());
            return candidate;
        }

        std::string frees_detail(const Cidr& block, std::size_t disturbed) {
            std::string out = "free " + block.str();
            if (disturbed > 0) out += ", moving " + std::to_string(disturbed) + " dynamic lease" + (disturbed == 1 ? "" : "s");
            return out;
        }

        // The best pool change per pool and kind that frees a block of `prefix`: shrinking the
        // pool from the top or from the bottom (as little as possible), or one exclude-range.
        std::vector<Candidate> pool_candidates(const State& state, const std::string& group, int prefix, std::uint64_t min_usable) {
            std::vector<Candidate> out;
            const std::uint64_t size = std::uint64_t{1} << (32 - prefix);
            auto align_down = [&](std::uint64_t ip) { return ip / size * size; };
            std::vector<Pool> pools = state.pools;
            std::sort(pools.begin(), pools.end(), [](const Pool& a, const Pool& b) { return std::tie(a.id, a.range) < std::tie(b.id, b.range); });
            for (const auto& pool: pools) {
                const std::uint64_t lo = pool.range.lo;
                const std::uint64_t hi = pool.range.hi;

                // Shrink from the top: the pool ends just below the block. Highest block first, so the
                // first that works gives back the fewest addresses.
                for (std::uint64_t at = align_down(hi); at > lo; at -= size) {
                    Cidr block{static_cast<Ipv4>(at), prefix};
                    PoolChange change{PoolChange::Kind::shrink, pool.id, pool.range, {pool.range.lo, static_cast<Ipv4>(at - 1)}, block, {}};
                    if (auto c = evaluate(state, group, block, min_usable, change, {static_cast<Ipv4>(at), pool.range.hi})) {
                        out.push_back(std::move(*c));
                        break;
                    }
                }

                // Shrink from the bottom: the pool starts just above the block.
                for (std::uint64_t at = align_down(lo); at + size - 1 < hi; at += size) {
                    Cidr block{static_cast<Ipv4>(at), prefix};
                    PoolChange change{PoolChange::Kind::shrink, pool.id, pool.range, {static_cast<Ipv4>(at + size), pool.range.hi}, block, {}};
                    if (auto c = evaluate(state, group, block, min_usable, change, {pool.range.lo, block.last()})) {
                        out.push_back(std::move(*c));
                        break;
                    }
                }

                // One exclude-range over the block's part of the pool: fewest displaced leases, then
                // the highest block (FortiOS hands out pool addresses from the bottom, so the top of a
                // pool is the part least likely to be in use).
                std::optional<Candidate> best;
                for (std::uint64_t at = align_down(lo); at <= hi; at += size) {
                    Cidr block{static_cast<Ipv4>(at), prefix};
                    auto part = intersect(block.range(), pool.range);
                    PoolChange change{PoolChange::Kind::exclude, pool.id, pool.range, *part, block, {}};
                    if (auto c = evaluate(state, group, block, min_usable, change, *part))
                        if (!best || c->disturbed.size() <= best->disturbed.size()) best = std::move(c);
                }
                if (best) out.push_back(std::move(*best));
            }
            for (auto& c: out) {
                auto& change = c.change;
                if (change.kind == PoolChange::Kind::shrink)
                    change.detail = "shrink " + pool_label(change.pool_id) + " from " + change.pool.str() + " to " + change.result.str() +
                                    " to " + frees_detail(change.frees, c.disturbed.size());
                else
                    change.detail = "add exclude-range " + change.result.str() + " to " + pool_label(change.pool_id) + " to " +
                                    frees_detail(change.frees, c.disturbed.size());
            }
            return out;
        }

        Alternative::Kind kind_of(const PoolChange& change) {
            return change.kind == PoolChange::Kind::shrink ? Alternative::Kind::shrink_pool : Alternative::Kind::exclude_range;
        }

        // Addresses a pool change takes away from the dynamic pool: between two changes that disturb
        // nobody, the one leaving the pool larger wins.
        std::uint64_t pool_cost(const PoolChange& change) {
            return change.kind == PoolChange::Kind::exclude ? change.result.size() : change.pool.size() - change.result.size();
        }

        std::uint64_t pool_cost(const Alternative& alt) {
            return alt.pool_change ? pool_cost(*alt.pool_change) : 0;
        }

        void rank(std::vector<Alternative>& alternatives) {
            std::stable_sort(alternatives.begin(), alternatives.end(), [](const Alternative& a, const Alternative& b) {
                return std::make_tuple(a.disturbed.size(), a.kind, pool_cost(a), std::cref(a.detail)) <
                       std::make_tuple(b.disturbed.size(), b.kind, pool_cost(b), std::cref(b.detail));
            });
        }

        std::string join(const std::vector<Cidr>& blocks) {
            std::string out;
            for (const auto& block: blocks) out += (out.empty() ? "" : " + ") + block.str();
            return out;
        }

        // Ways to meet a shortfall, none of which renumbers a configured address.
        std::vector<Alternative> alternatives_for(const State& state, const Request& request, std::uint64_t need, const Bounds& bounds) {
            std::vector<Alternative> out;
            const std::string& group = request.group;
            const std::uint64_t capacity = state.capacity_of(group);
            const std::uint64_t missing = need - capacity;

            // Less headroom: room for the expected devices only.
            const std::uint64_t bare = std::max<std::uint64_t>(request.expected, 1);
            if (bare < need) {
                State trial = state;
                if (auto added = fill(trial, group, bare, bounds)) {
                    Alternative alt{Alternative::Kind::reduce_headroom, {}, *added, std::nullopt, {}};
                    alt.detail = "use headroom 1 (room for " + std::to_string(bare) + " instead of " + std::to_string(need) + "): " +
                                 (added->empty() ? std::string("the current slices suffice") : "add " + join(*added));
                    out.push_back(std::move(alt));
                }
            }

            // Several smaller slices out of fragmented free space: the largest free blocks first,
            // until one block of the sizing rule fits the rest.
            {
                State trial = state;
                std::vector<Cidr> added;
                for (int round = 0; round < 32; ++round) {
                    auto have = trial.capacity_of(group);
                    if (have >= need) break;
                    if (auto found = fit_deficit(trial, group, need - have, bounds)) {
                        added.push_back(*found);
                        trial.slices.push_back({group, *found, false});
                        continue;
                    }
                    std::optional<Cidr> largest;
                    for (const auto& range: trial.free_for(group))
                        for (const auto& block: cover(range))
                            if (block.prefix <= bounds.smallest && block.usable_count(trial.network()) > 0 &&
                                (!largest || block.prefix < largest->prefix))
                                largest = block;
                    if (!largest) break;
                    Cidr piece{largest->network, std::max(largest->prefix, bounds.largest)};
                    added.push_back(piece);
                    trial.slices.push_back({group, piece, false});
                }
                if (trial.capacity_of(group) >= need && added.size() > 1) {
                    std::sort(added.begin(), added.end());
                    out.push_back({Alternative::Kind::split, "split the need over " + join(added), added, std::nullopt, {}});
                }
            }

            // A pool change that frees one block for the rest.
            int prefix = prefix_for(missing, bounds);
            bool capped = (std::uint64_t{1} << (32 - prefix)) < missing;
            for (auto& candidate: pool_candidates(state, group, prefix, capped ? 1 : missing)) {
                Alternative alt{kind_of(candidate.change), candidate.change.detail, {candidate.change.frees}, candidate.change,
                                std::move(candidate.disturbed)};
                out.push_back(std::move(alt));
            }
            rank(out);
            return out;
        }

        Bounds bounds_of(const Request& request, const Cidr& network) {
            Bounds bounds{network.prefix, smallest_slice_prefix};
            if (request.min_prefix) bounds.largest = *request.min_prefix;
            if (request.max_prefix) bounds.smallest = *request.max_prefix;
            return bounds;
        }

        void validate(const PlanInput& input) {
            std::set<std::string> groups;
            for (const auto& request: input.requests) {
                if (request.group.empty()) throw std::invalid_argument("a slice request has no group");
                if (!groups.insert(request.group).second) throw std::invalid_argument("group " + request.group + " is requested twice");
                if (!std::isfinite(request.headroom) || request.headroom < 1.0)
                    throw std::invalid_argument("group " + request.group + ": headroom must be at least 1");
                auto bounds = bounds_of(request, input.network);
                auto in_range = [&](int prefix) { return prefix >= input.network.prefix && prefix <= smallest_slice_prefix; };
                if (!in_range(bounds.largest) || !in_range(bounds.smallest) || bounds.largest > bounds.smallest)
                    throw std::invalid_argument("group " + request.group + ": prefix bounds must lie within /" +
                                                std::to_string(input.network.prefix) + "../" + std::to_string(smallest_slice_prefix) +
                                                " with min_prefix <= max_prefix");
            }
        }

        bool by_address(const Slice& a, const Slice& b) {
            return std::tie(a.cidr, a.group, a.retained) < std::tie(b.cidr, b.group, b.retained);
        }

        Conflict conflict(ConflictKind kind, const Slice& slice, const Occupant* occupant = nullptr) {
            Conflict c;
            c.kind = kind;
            c.slice = slice;
            if (occupant) {
                c.ip = occupant->ip;
                c.use = occupant->use;
                c.label = occupant->label;
                c.mac = occupant->mac;
            }
            return c;
        }

        std::string occupant_name(const Occupant& o) {
            return o.label.empty() ? format_ipv4(o.ip) : o.label + " (" + format_ipv4(o.ip) + ")";
        }

    }  // namespace

    std::vector<const Occupant*> Occupancy::at(Ipv4 ip) const {
        return within(Range::single(ip));
    }

    std::vector<const Occupant*> Occupancy::within(const Range& range) const {
        std::vector<const Occupant*> out;
        for (const auto& entry: entries)
            if (range.contains(entry.ip)) out.push_back(&entry);
        return out;
    }

    Occupancy PlanInput::effective_occupancy() const {
        Occupancy out = occupancy;
        for (auto ip: interface_ips) {
            bool listed = std::any_of(occupancy.entries.begin(), occupancy.entries.end(),
                                      [&](const Occupant& o) { return o.ip == ip && o.use == Use::interface_ip; });
            if (!listed) out.add({ip, Use::interface_ip, "interface", {}, {}});
        }
        return out;
    }

    std::vector<Conflict> check(const PlanInput& input, std::span<const Slice> given) {
        std::vector<Slice> slices(given.begin(), given.end());
        std::sort(slices.begin(), slices.end(), by_address);
        auto occupancy = input.effective_occupancy();
        std::vector<Conflict> out;
        for (std::size_t i = 0; i < slices.size(); ++i) {
            const auto& slice = slices[i];
            const auto range = slice.cidr.range();
            if (!input.network.contains(slice.cidr)) {
                auto c = conflict(ConflictKind::outside_network, slice);
                c.detail = slice.cidr.str() + " is not inside " + input.network.str();
                out.push_back(std::move(c));
            }
            for (const auto& pool: input.pools) {
                for (const auto& part: subtract({pool.range}, input.excludes)) {
                    auto overlap = intersect(part, range);
                    if (!overlap) continue;
                    auto c = conflict(ConflictKind::dynamic_pool, slice);
                    c.range = overlap;
                    c.label = pool_label(pool.id);
                    c.detail = slice.cidr.str() + " overlaps dynamic " + c.label + " (" + pool.range.str() + ") at " + overlap->str() +
                               ", which no exclude-range covers";
                    out.push_back(std::move(c));
                }
            }
            for (std::size_t j = i + 1; j < slices.size(); ++j) {
                auto overlap = intersect(range, slices[j].cidr.range());
                if (!overlap) continue;
                auto c = conflict(ConflictKind::slice_overlap, slice);
                c.range = overlap;
                c.label = slices[j].group;
                c.other = slices[j].cidr;
                c.detail = slice.cidr.str() + " (" + slice.group + ") overlaps " + slices[j].cidr.str() + " (" + slices[j].group + ")";
                out.push_back(std::move(c));
            }
            std::set<Ipv4> interfaces;
            for (const auto* o: occupancy.within(range)) {
                if (o->use == Use::interface_ip) {
                    if (!interfaces.insert(o->ip).second) continue;
                    auto c = conflict(ConflictKind::interface_ip, slice, o);
                    c.detail = slice.cidr.str() + " contains interface address " + format_ipv4(o->ip);
                    out.push_back(std::move(c));
                } else if (o->group != slice.group) {
                    auto c = conflict(ConflictKind::foreign_occupant, slice, o);
                    c.detail = slice.cidr.str() + " (" + slice.group + ") contains " + std::string(use_name(o->use)) + " " + occupant_name(*o) +
                               (o->group.empty() ? std::string(" of no group") : " of group " + o->group);
                    out.push_back(std::move(c));
                }
            }
        }
        std::stable_sort(out.begin(), out.end(), [](const Conflict& a, const Conflict& b) {
            auto key = [](const Conflict& c) {
                Ipv4 at = c.ip ? *c.ip : c.range ? c.range->lo : c.slice.cidr.network;
                return std::make_tuple(c.slice.cidr, std::cref(c.slice.group), c.kind, at, std::cref(c.label));
            };
            return key(a) < key(b);
        });
        return out;
    }

    PlanInput with_pool_changes(PlanInput input, std::span<const PoolChange> changes) {
        for (const auto& change: changes) apply_change(input.pools, input.excludes, change);
        return input;
    }

    Utilization utilization(const PlanInput& input, std::span<const Slice> slices) {
        Utilization out;
        auto occupancy = input.effective_occupancy();
        for (const auto& slice: slices) {
            SliceUsage entry{slice, {}};
            if (auto usable = slice.cidr.usable(input.network)) {
                std::set<Ipv4> interfaces;
                std::set<Ipv4> used;
                for (const auto* o: occupancy.within(*usable)) (o->use == Use::interface_ip ? interfaces : used).insert(o->ip);
                for (auto ip: interfaces) used.erase(ip);
                entry.usage.total = usable->size() - interfaces.size();
                entry.usage.used = used.size();
                entry.usage.free = entry.usage.total - entry.usage.used;
            }
            out.overall.total += entry.usage.total;
            out.overall.used += entry.usage.used;
            out.overall.free += entry.usage.free;
            out.slices.push_back(std::move(entry));
        }
        return out;
    }

    bool Proposal::complete() const {
        return std::all_of(groups.begin(), groups.end(), [](const GroupPlan& g) { return g.missing == 0; });
    }

    Proposal propose(const PlanInput& input) {
        validate(input);
        State state;
        state.input = &input;
        state.occupants = input.effective_occupancy().entries;
        std::stable_sort(state.occupants.begin(), state.occupants.end(), [](const Occupant& a, const Occupant& b) { return a.ip < b.ip; });
        state.pools = input.pools;
        state.excludes = input.excludes;

        Proposal proposal;
        proposal.network = input.network;

        // Existing slices stay where they are: their devices hold reservations there. One outside
        // the network cannot hold anything and is dropped (reported).
        for (const auto& [group, cidrs]: input.existing) {
            std::set<Cidr> unique(cidrs.begin(), cidrs.end());
            for (const auto& cidr: unique) {
                Slice slice{group, cidr, true};
                (input.network.contains(cidr) ? state.slices : proposal.dropped).push_back(slice);
            }
        }
        {
            std::vector<Slice> reported = state.slices;
            reported.insert(reported.end(), proposal.dropped.begin(), proposal.dropped.end());
            proposal.conflicts = check(input, reported);
        }

        // Largest new block first, so small requests do not fragment the space a big one needs;
        // ties by group name for a stable order.
        struct Work {
            const Request* request;
            std::uint64_t need;
            int prefix;   // of the first new block, 33 when none is needed
        };
        std::vector<Work> work;
        for (const auto& request: input.requests) {
            auto need = needed_for(request);
            auto capacity = state.capacity_of(request.group);
            int prefix = capacity >= need ? 33 : prefix_for(need - capacity, bounds_of(request, input.network));
            work.push_back({&request, need, prefix});
        }
        std::sort(work.begin(), work.end(), [](const Work& a, const Work& b) {
            return std::tie(a.prefix, a.request->group) < std::tie(b.prefix, b.request->group);
        });

        // First every request from space outside the pools; only then, for what is still missing and
        // when the policy allows it, pool changes. A large request served first must not push the
        // small ones into a pool change they would not have needed.
        auto serve = [&](const Work& item, bool pool_changes) {
            const auto& request = *item.request;
            const auto bounds = bounds_of(request, input.network);
            for (auto capacity = state.capacity_of(request.group); capacity < item.need; capacity = state.capacity_of(request.group)) {
                const auto deficit = item.need - capacity;
                auto found = fit_deficit(state, request.group, deficit, bounds);
                if (!found && pool_changes) {
                    // Only a change that displaces no current dynamic lease goes into the plan itself.
                    int prefix = prefix_for(deficit, bounds);
                    bool capped = (std::uint64_t{1} << (32 - prefix)) < deficit;
                    auto candidates = pool_candidates(state, request.group, prefix, capped ? 1 : deficit);
                    std::erase_if(candidates, [](const Candidate& c) { return !c.disturbed.empty(); });
                    // A shrink keeps the pool one contiguous range, which is easier to read and undo
                    // than a hole; then whichever takes fewer addresses from the pool.
                    std::stable_sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
                        return std::make_tuple(kind_of(a.change), pool_cost(a.change)) < std::make_tuple(kind_of(b.change), pool_cost(b.change));
                    });
                    if (!candidates.empty()) {
                        state.apply(candidates.front().change);
                        proposal.pool_changes.push_back(candidates.front().change);
                        found = candidates.front().change.frees;
                    }
                }
                if (!found) break;
                state.slices.push_back({request.group, *found, false});
            }
        };
        for (const auto& item: work) serve(item, false);
        if (input.policy.allow_pool_changes)
            for (const auto& item: work) serve(item, true);

        // Shortfalls are judged against the finished plan, so an alternative never offers space a
        // later request has taken.
        for (const auto& item: work) {
            const auto& request = *item.request;
            GroupPlan plan{request.group, request.expected, item.need, state.capacity_of(request.group), 0, {}};
            if (plan.capacity < plan.needed) {
                plan.missing = plan.needed - plan.capacity;
                plan.alternatives = alternatives_for(state, request, item.need, bounds_of(request, input.network));
            }
            proposal.groups.push_back(std::move(plan));
        }

        std::sort(proposal.groups.begin(), proposal.groups.end(), [](const GroupPlan& a, const GroupPlan& b) { return a.group < b.group; });
        proposal.slices = state.slices;
        std::sort(proposal.slices.begin(), proposal.slices.end(), by_address);
        proposal.utilization = utilization(input, proposal.slices);
        return proposal;
    }

    std::optional<Ipv4> pick_address(const Cidr& parent, const Cidr& slice, const Occupancy& occupancy, std::optional<Ipv4> preferred,
                                     std::string_view mac) {
        auto usable = slice.usable(parent);
        if (!usable) return std::nullopt;
        std::set<Ipv4> taken;
        for (const auto* o: occupancy.within(*usable))
            if (o->use == Use::interface_ip || mac.empty() || o->mac != mac) taken.insert(o->ip);
        if (preferred && usable->contains(*preferred) && !taken.contains(*preferred)) return preferred;
        // Lowest free address: walk the taken set in order instead of probing every address.
        std::uint64_t candidate = usable->lo;
        for (auto ip: taken) {
            if (ip > candidate) break;
            if (ip == candidate) ++candidate;
        }
        if (candidate > usable->hi) return std::nullopt;
        return static_cast<Ipv4>(candidate);
    }

    std::string_view use_name(Use use) {
        switch (use) {
            case Use::interface_ip: return "interface-ip";
            case Use::reservation: return "reservation";
            case Use::lease: return "lease";
            case Use::vip: return "vip";
            case Use::address_object: return "address-object";
            case Use::static_device: return "static-device";
        }
        return "unknown";
    }

    std::string_view conflict_kind_name(ConflictKind kind) {
        switch (kind) {
            case ConflictKind::outside_network: return "outside-network";
            case ConflictKind::dynamic_pool: return "dynamic-pool";
            case ConflictKind::slice_overlap: return "slice-overlap";
            case ConflictKind::interface_ip: return "interface-ip";
            case ConflictKind::foreign_occupant: return "foreign-occupant";
        }
        return "unknown";
    }

    std::string_view alternative_kind_name(Alternative::Kind kind) {
        switch (kind) {
            case Alternative::Kind::reduce_headroom: return "reduce-headroom";
            case Alternative::Kind::split: return "split";
            case Alternative::Kind::shrink_pool: return "shrink-pool";
            case Alternative::Kind::exclude_range: return "exclude-range";
        }
        return "unknown";
    }

}  // namespace fph::alloc
