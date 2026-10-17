//
// The write allowlist (AGENTS.md rule 2), enforced twice:
//
//   check_operations  before planning: every operation is create/update/delete on firewall/address or
//                     firewall/addrgrp, names start with the prefix, updates and deletes only touch
//                     objects that carry the ownership marker, creates carry it.
//   GuardTransport    under the engine: any POST/PUT/DELETE that is not to one of those two collections
//                     with a prefixed name is refused before it is sent. A bug in the planner, or a
//                     change in what the engine sends, still cannot reach anything else.
//

#ifndef FORTI_VLAN_MAC_GUARD_HPP
#define FORTI_VLAN_MAC_GUARD_HPP

#include "config.hpp"
#include "inventory.hpp"

#include <forti_api/client.hpp>

#include <memory>
#include <stdexcept>
#include <string>

namespace fvm {

    class GuardViolation : public std::logic_error {
    public:
        using std::logic_error::logic_error;
    };

    // Throws GuardViolation naming the first offending operation.
    void check_operations(const nlohmann::json& operations, const Snapshot& snapshot, const Config& config);

    // Empty when the request may be sent; otherwise why not.
    std::string refuse_write(fortiapi::Method method, std::string_view url, std::string_view body, std::string_view prefix);

    class GuardTransport final : public fortiapi::Transport {
        std::shared_ptr<fortiapi::Transport> inner_;
        std::string prefix_;

    public:
        GuardTransport(std::shared_ptr<fortiapi::Transport> inner, std::string prefix)
                : inner_(std::move(inner)), prefix_(std::move(prefix)) {}

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override;
    };

}  // namespace fvm

#endif  // FORTI_VLAN_MAC_GUARD_HPP
