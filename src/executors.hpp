//
// Step executors for migrations (operation.hpp, migrate.hpp): each step's forward action, the check
// that tells whether it already took effect (crash recovery), and its compensation.
//
//   pihole       ensure the slice's managed CIDR entry -> group; undo deletes it only if this step created it
//   reservation  engine plan+apply of the child operation; undo applies the engine's rollback plan, then
//   objects      revokes the device's new lease so it renews into the old address
//   revoke       engine action monitor/system/dhcp/revoke for the old address only
//   observe      polls the lease table until the device holds the new address (bounded; then "waiting")
//   verify       fresh reads: lease and inventory, firewall reach, Pi-hole resolution
//
// Every engine write runs inside a PermitScope granting exactly what that step needs, so the guard
// transport refuses anything else even if a plan were wrong. In a guarded profile the apply waits for
// a person's approval: the step reports "waiting" with the `forti approve` command and retries that
// same plan on the next run.
//

#ifndef FORTI_PIHOLE_EXECUTORS_HPP
#define FORTI_PIHOLE_EXECUTORS_HPP

#include "config.hpp"
#include "gateway.hpp"
#include "guard.hpp"
#include "operation.hpp"
#include "pihole_link.hpp"

#include <functional>
#include <memory>

namespace fph {

    struct Runtime {
        Gateway& gateway;
        std::shared_ptr<WritePermits> permits;
        PiholeApi* pihole = nullptr;   // null: Pi-hole steps fail (not configured)
        const Config& config;
        std::function<std::int64_t()> clock;
        std::function<void(int seconds)> sleep;
    };

    class MigrationExecutors {
        Runtime& rt_;
        StepExecutor pihole_, engine_, revoke_, observe_, verify_;

    public:
        explicit MigrationExecutors(Runtime& runtime);
        const StepExecutor* operator()(const Step& step) const;
    };

    // Plans and applies `operations` under `granted` permits. Result: {"plan_id", "rollback_plan",
    // "record"}; waiting when the profile is guarded and the plan is not approved yet (the plan id is
    // kept so the next attempt applies the same plan).
    StepOutcome engine_apply(Runtime& rt, const nlohmann::json& operations, const WritePermits& granted, const nlohmann::json& previous);

    // The permits a list of engine operations needs (server ids, reservation ids, adopted objects, revoke IPs).
    WritePermits permits_for(const nlohmann::json& operations);

}  // namespace fph

#endif  // FORTI_PIHOLE_EXECUTORS_HPP
