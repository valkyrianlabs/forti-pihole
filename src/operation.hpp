//
// Durable multi-step operations (address migrations). The FortiGate and Pi-hole cannot change in
// one transaction, and a device renews its lease when it wants to, so a migration is a sequence of
// steps, each with a forward action, a check that tells whether it already took effect, and a
// compensation. The journal is written before and after every step:
//
//   $FORTI_HOME/pihole/operations/<id>.json   0600, atomic replace
//
// A run that dies mid-way leaves the step "running"; `resume` re-checks it (the check decides
// whether to redo it) and continues; `rollback` compensates completed steps in reverse order.
// Success means the final verification step passed, never merely that the APIs returned 200.
//

#ifndef FORTI_PIHOLE_OPERATION_HPP
#define FORTI_PIHOLE_OPERATION_HPP

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace fph {

    struct Step {
        std::string id;            // stable within the operation: "pihole", "reservation", "objects", "revoke", ...
        std::string description;   // one line for humans
        std::string status = "pending";   // pending | running | done | failed | waiting | skipped | compensated | compensation-failed
        nlohmann::json forward = nlohmann::json::object();      // what to do (executor-specific)
        nlohmann::json compensate = nlohmann::json::object();   // how to undo it (filled from the result when needed)
        nlohmann::json result = nlohmann::json::object();       // plan ids, rollback plan ids, observations
        std::string error;
        std::int64_t started = 0, finished = 0;
    };

    struct Operation {
        std::string id;      // op-YYYYMMDD-HHMMSS-xxxxxx
        std::string kind;    // migrate
        std::string status = "planned";   // planned | running | waiting | done | failed | rolling-back | rolled-back | rollback-failed
        nlohmann::json subject = nlohmann::json::object();   // device, addresses, group, slice (for reports)
        std::vector<Step> steps;
        std::vector<std::string> log;   // timestamped notes: observations, retries, decisions
        std::int64_t created = 0, updated = 0;

        static Operation from_json(const nlohmann::json& json);
        [[nodiscard]] nlohmann::json to_json() const;
        [[nodiscard]] Step* step(std::string_view id);
        [[nodiscard]] bool finished() const;   // done, rolled-back (terminal and clean)
    };

    // What a step's executor reports.
    struct StepOutcome {
        enum class Kind { done, failed, waiting };   // waiting: needs time or a person (a device that has not renewed)
        Kind kind = Kind::done;
        nlohmann::json result = nlohmann::json::object();
        nlohmann::json compensate;   // set to replace the step's compensation (e.g. a rollback plan id)
        std::string message;
    };

    // Executes one kind of step. `already` reports whether the forward effect is in place (used to
    // resume safely after a crash: a step found running is re-checked, not blindly repeated).
    struct StepExecutor {
        std::function<StepOutcome(const Step&)> forward;
        std::function<StepOutcome(const Step&)> compensate;
        std::function<bool(const Step&)> already;
    };

    class Journal {
        std::filesystem::path dir_;

    public:
        explicit Journal(std::filesystem::path dir) : dir_(std::move(dir)) {}
        [[nodiscard]] std::filesystem::path path(std::string_view id) const;
        void save(Operation& op, std::int64_t now) const;   // stamps updated, atomic write
        [[nodiscard]] std::optional<Operation> load(std::string_view id) const;
        [[nodiscard]] std::vector<Operation> list() const;   // newest first
        // Operations not in a terminal state: at most one per device may be open.
        [[nodiscard]] std::vector<Operation> open() const;
    };

    std::string new_operation_id(std::int64_t now);

    using Executors = std::function<const StepExecutor*(const Step&)>;

    // Runs pending (and re-checks running) steps in order, saving after every change. Stops at the
    // first failed or waiting step. Returns the operation's new status.
    std::string run_operation(Operation& op, const Journal& journal, const Executors& executors,
                              const std::function<std::int64_t()>& clock);

    // Compensates done (and failed/waiting, whose effect may be partial) steps in reverse order.
    std::string rollback_operation(Operation& op, const Journal& journal, const Executors& executors,
                                   const std::function<std::int64_t()>& clock);

}  // namespace fph

#endif  // FORTI_PIHOLE_OPERATION_HPP
