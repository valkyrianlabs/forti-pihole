#include "operation.hpp"

#include "state.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <random>
#include <sstream>

namespace fph {

    using json = nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        std::string str(const json& j, const char* key) {
            auto it = j.find(key);
            return it != j.end() && it->is_string() ? it->get<std::string>() : std::string();
        }

        std::int64_t num(const json& j, const char* key) {
            auto it = j.find(key);
            return it != j.end() && it->is_number_integer() ? it->get<std::int64_t>() : 0;
        }

        bool valid_id(std::string_view id) {
            if (id.size() < 8 || id.size() > 48) return false;
            return std::ranges::all_of(id, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'; });
        }

        void note(Operation& op, std::int64_t now, std::string text) {
            op.log.push_back(std::format("{} {}", now, std::move(text)));
            // Bounded: an operation that keeps waiting must not grow without limit.
            if (op.log.size() > 200) op.log.erase(op.log.begin(), op.log.begin() + static_cast<std::ptrdiff_t>(op.log.size() - 200));
        }

    }  // namespace

    Operation Operation::from_json(const json& j) {
        Operation op;
        op.id = str(j, "id");
        op.kind = str(j, "kind");
        op.status = str(j, "status");
        op.subject = j.value("subject", json::object());
        op.created = num(j, "created");
        op.updated = num(j, "updated");
        for (const auto& line: j.value("log", json::array()))
            if (line.is_string()) op.log.push_back(line.get<std::string>());
        for (const auto& s: j.value("steps", json::array())) {
            Step step;
            step.id = str(s, "id");
            step.description = str(s, "description");
            step.status = str(s, "status");
            step.forward = s.value("forward", json::object());
            step.compensate = s.value("compensate", json::object());
            step.result = s.value("result", json::object());
            step.error = str(s, "error");
            step.started = num(s, "started");
            step.finished = num(s, "finished");
            op.steps.push_back(std::move(step));
        }
        return op;
    }

    json Operation::to_json() const {
        json steps_json = json::array();
        for (const auto& s: steps)
            steps_json.push_back({{"id", s.id}, {"description", s.description}, {"status", s.status}, {"forward", s.forward},
                                  {"compensate", s.compensate}, {"result", s.result}, {"error", s.error}, {"started", s.started},
                                  {"finished", s.finished}});
        return {{"version", 1}, {"id", id}, {"kind", kind}, {"status", status}, {"subject", subject}, {"steps", steps_json},
                {"log", log}, {"created", created}, {"updated", updated}};
    }

    Step* Operation::step(std::string_view wanted) {
        for (auto& s: steps)
            if (s.id == wanted) return &s;
        return nullptr;
    }

    bool Operation::finished() const { return status == "done" || status == "rolled-back"; }

    fs::path Journal::path(std::string_view id) const { return dir_ / (std::string(id) + ".json"); }

    void Journal::save(Operation& op, std::int64_t now) const {
        if (!valid_id(op.id)) throw StateError("operation id \"" + op.id + "\" is not valid");
        op.updated = now;
        write_private(path(op.id), op.to_json().dump(2) + "\n");
    }

    std::optional<Operation> Journal::load(std::string_view id) const {
        if (!valid_id(id)) return std::nullopt;
        std::ifstream in(path(id));
        if (!in) return std::nullopt;
        std::stringstream buffer;
        buffer << in.rdbuf();
        auto parsed = json::parse(buffer.str(), nullptr, false);
        if (parsed.is_discarded()) throw StateError(std::format("{} is not valid JSON", path(id).string()));
        return Operation::from_json(parsed);
    }

    std::vector<Operation> Journal::list() const {
        std::vector<Operation> out;
        std::error_code error;
        for (const auto& entry: fs::directory_iterator(dir_, error)) {
            if (entry.path().extension() != ".json") continue;
            if (auto op = load(entry.path().stem().string())) out.push_back(std::move(*op));
        }
        std::ranges::sort(out, [](const auto& a, const auto& b) { return a.created > b.created; });
        return out;
    }

    std::vector<Operation> Journal::open() const {
        auto all = list();
        std::erase_if(all, [](const Operation& op) {
            return op.finished() || op.status == "planned";
        });
        return all;
    }

    std::string new_operation_id(std::int64_t now) {
        auto tp = std::chrono::sys_seconds(std::chrono::seconds(now));
        std::random_device device;
        return std::format("op-{:%Y%m%d-%H%M%S}-{:06x}", tp, device() & 0xffffff);
    }

    std::string run_operation(Operation& op, const Journal& journal, const Executors& executors,
                              const std::function<std::int64_t()>& clock) {
        if (op.finished()) return op.status;
        op.status = "running";
        journal.save(op, clock());
        for (auto& step: op.steps) {
            if (step.status == "done" || step.status == "skipped") continue;
            const StepExecutor* executor = executors(step);
            if (!executor) {
                step.status = "failed";
                step.error = "no executor for step " + step.id;
                op.status = "failed";
                journal.save(op, clock());
                return op.status;
            }
            // A step left running by a crash, or waiting from an earlier run: maybe it took effect.
            if ((step.status == "running" || step.status == "waiting") && executor->already && executor->already(step)) {
                step.status = "done";
                step.finished = clock();
                note(op, clock(), step.id + ": found in effect after a restart");
                journal.save(op, clock());
                continue;
            }
            step.status = "running";
            step.started = clock();
            step.error.clear();
            journal.save(op, clock());   // checkpoint before acting: a crash now is recoverable

            StepOutcome outcome;
            try {
                outcome = executor->forward(step);
            } catch (const std::exception& e) {
                outcome = {StepOutcome::Kind::failed, json::object(), json(), e.what()};
            }
            if (!outcome.result.is_null() && !outcome.result.empty()) step.result = outcome.result;
            if (!outcome.compensate.is_null()) step.compensate = outcome.compensate;
            step.finished = clock();
            if (!outcome.message.empty()) note(op, clock(), step.id + ": " + outcome.message);
            if (outcome.kind == StepOutcome::Kind::done) {
                step.status = "done";
                journal.save(op, clock());
                continue;
            }
            step.status = outcome.kind == StepOutcome::Kind::waiting ? "waiting" : "failed";
            step.error = outcome.message;
            op.status = outcome.kind == StepOutcome::Kind::waiting ? "waiting" : "failed";
            journal.save(op, clock());
            return op.status;
        }
        op.status = "done";
        journal.save(op, clock());
        return op.status;
    }

    std::string rollback_operation(Operation& op, const Journal& journal, const Executors& executors,
                                   const std::function<std::int64_t()>& clock) {
        if (op.status == "rolled-back") return op.status;
        op.status = "rolling-back";
        journal.save(op, clock());
        bool clean = true;
        for (auto it = op.steps.rbegin(); it != op.steps.rend(); ++it) {
            auto& step = *it;
            // Pending steps never ran; skipped ones changed nothing. A failed or waiting step may have
            // taken partial effect, so it is compensated too (compensations are idempotent).
            if (step.status == "pending" || step.status == "skipped" || step.status == "compensated") continue;
            const StepExecutor* executor = executors(step);
            if (!executor || !executor->compensate || step.compensate.empty()) {
                if (step.compensate.empty()) {
                    step.status = "compensated";   // nothing to undo (a check, an observation)
                    journal.save(op, clock());
                    continue;
                }
                step.status = "compensation-failed";
                step.error = "no compensation available for " + step.id;
                clean = false;
                journal.save(op, clock());
                continue;
            }
            StepOutcome outcome;
            try {
                outcome = executor->compensate(step);
            } catch (const std::exception& e) {
                outcome = {StepOutcome::Kind::failed, json::object(), json(), e.what()};
            }
            if (!outcome.message.empty()) note(op, clock(), step.id + " (rollback): " + outcome.message);
            if (outcome.kind == StepOutcome::Kind::done) step.status = "compensated";
            else {
                step.status = "compensation-failed";
                step.error = outcome.message;
                clean = false;
            }
            journal.save(op, clock());
        }
        // A failed compensation leaves the operation open: rollback can be retried, and the report
        // lists exactly which step still needs attention.
        op.status = clean ? "rolled-back" : "rollback-failed";
        journal.save(op, clock());
        return op.status;
    }

}  // namespace fph
