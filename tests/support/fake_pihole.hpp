//
// An in-memory Pi-hole behind PiholeApi, resolving clients with the real FTL rules
// (pihole::effective_groups).
//

#ifndef FORTI_PIHOLE_TESTS_FAKE_PIHOLE_HPP
#define FORTI_PIHOLE_TESTS_FAKE_PIHOLE_HPP

#include <pihole/model.hpp>
#include <pihole/resolve.hpp>
#include <pihole_link.hpp>

namespace fph::test {

    class FakePihole final : public PiholeApi {
    public:
        PiholeView state;
        int next_id = 100;
        std::vector<PiholeChange> applied;

        FakePihole() {
            state.groups = {{0, "Default", true}, {1, "Work", true}, {2, "TV", true}, {4, "Owner", true}, {5, "IOT", true}};
        }

        std::string version() override { return "FTL v6.7.1"; }
        PiholeView view() override { return state; }

        std::vector<PiholeApplied> apply(const std::vector<PiholeChange>& changes) override {
            std::vector<PiholeApplied> out;
            for (const auto& c: changes) {
                applied.push_back(c);
                PiholeApplied r{c.kind, c.cidr, c.client_id, true, {}};
                if (c.kind == "create") {
                    r.client_id = next_id++;
                    state.clients.push_back({r.client_id, c.cidr, c.comment, c.group_ids});
                } else if (c.kind == "update") {
                    for (auto& e: state.clients)
                        if (e.client == c.cidr) e.groups = c.group_ids;
                } else if (c.kind == "delete") {
                    std::erase_if(state.clients, [&](const PiholeClientInfo& e) { return e.client == c.cidr && e.managed(); });
                }
                out.push_back(r);
            }
            return out;
        }

        std::vector<int> effective_groups(const std::string& ip) override {
            std::vector<pihole::ClientEntry> entries;
            for (const auto& c: state.clients) {
                pihole::ClientEntry e;
                e.id = c.id;
                e.client = c.client;
                e.comment = c.comment;
                e.groups = c.groups;
                entries.push_back(e);
            }
            return pihole::effective_groups(entries, ip);
        }
    };

}  // namespace fph::test

#endif  // FORTI_PIHOLE_TESTS_FAKE_PIHOLE_HPP
