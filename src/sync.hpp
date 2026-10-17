//
// One synchronization run, shared by `forti-pihole plan`, `forti-pihole sync` and forti-piholed.
//
// Read (always): the FortiGate snapshot, classification, reassociation candidates, the managed
// FortiGate objects' changeset, the Pi-hole plan, the slicing plan and the migrations it implies.
//
// Write (only when asked, the configuration is enabled and sync is not paused), in this order, each
// stage isolated so one failing does not undo or block the reporting of the others:
//   1. FortiGate objects   device objects and group membership (engine plan/apply; a guarded
//                          profile's earlier plan waiting for approval goes first)
//   2. Pi-hole             managed CIDR client entries
//   3. reservations        devices already inside their slice without a reservation get one at the
//                          address they hold (no address change, no lease touched)
//   4. migrations          open operations resume (a device that has since renewed completes)
//   5. new migrations      at most max_migrations per run, only on networks with manage_reservations,
//                          only with the operator's adoptions where the move needs them
//
// Writes go through the engine and the Pi-hole client only; every FortiGate write outside the managed
// objects runs under exactly the permits it needs.
//

#ifndef FORTI_PIHOLE_SYNC_HPP
#define FORTI_PIHOLE_SYNC_HPP

#include "classify.hpp"
#include "config.hpp"
#include "gateway.hpp"
#include "guard.hpp"
#include "inventory.hpp"
#include "migrate.hpp"
#include "operation.hpp"
#include "pihole_link.hpp"
#include "pihole_sync.hpp"
#include "reconcile.hpp"
#include "slicing.hpp"
#include "state.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace fph {

    struct SyncContext {
        const Config& config;
        Gateway& gateway;
        std::shared_ptr<WritePermits> permits;
        // Connects on first use; returns null when Pi-hole is not configured. May throw PiholeLinkError.
        std::function<PiholeApi*()> pihole;
        Home home;
        std::function<std::int64_t()> clock;
        std::function<void(int)> sleep;
    };

    struct SyncOptions {
        bool apply = false;
        bool prune = false;          // delete managed Pi-hole entries no network implies any more
        int max_changes = 50;
        int max_migrations = 1;
        bool migrations = true;      // stages 4 and 5
        bool paused = false;
    };

    struct StageResult {
        std::string stage, status;   // status: skipped | in-sync | applied | waiting | failed
        std::string detail;
        std::string plan_id, rollback_plan;
    };

    struct SyncResult {
        Snapshot snapshot;
        Classification classification;
        std::vector<Candidate> candidates, found;
        Changeset objects;
        std::optional<PiholePlan> pihole;
        std::string pihole_error;
        SlicingPlan slicing;
        std::vector<MigrationPlan> migrations;     // planned moves, including refused ones
        std::vector<std::string> operations;       // ids of migrations run or resumed this time
        std::vector<StageResult> stages;
        nlohmann::json written = nlohmann::json::array();   // [{"resource", "name"}] for the daemon's loop guard
        std::string status = "planned";            // planned | applied | waiting | paused | disabled | failed
        int exit_code = 0;
    };

    // `state` is loaded by the caller (who holds the run lock) and saved by it afterwards.
    SyncResult run_sync(SyncContext& context, State& state, const SyncOptions& options);

    nlohmann::json sync_json(const SyncResult& result, const Config& config, std::int64_t now);
    std::string sync_text(const SyncResult& result, const Config& config, std::int64_t now, bool verbose);

}  // namespace fph

#endif  // FORTI_PIHOLE_SYNC_HPP
