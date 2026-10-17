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

#ifndef FORTI_PIHOLE_GUARD_HPP
#define FORTI_PIHOLE_GUARD_HPP

#include "config.hpp"
#include "inventory.hpp"

#include <forti_api/client.hpp>

#include <cstdint>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>

namespace fph {

    class GuardViolation : public std::logic_error {
    public:
        using std::logic_error::logic_error;
    };

    // Writes beyond the managed objects, granted for one apply at a time (a migration step, or
    // reservations a sync adds at addresses devices already hold) and withdrawn right after:
    //   dhcp_servers      single reserved-address entries on these servers (child paths only, never the
    //                     whole list); creates must carry the marker, updates/deletes only these ids:
    //   reservations      (server id, entry id) pairs: managed entries, or an adopted one
    //   address_objects   administrator host objects explicitly adopted to follow a moved device
    //   revoke_ips        leases that may be revoked (monitor/system/dhcp/revoke)
    //   automation        the event webhook's trigger, action and stitch (<prefix>* names, marker in the
    //                     description), only inside `forti-pihole events install|remove`
    struct WritePermits {
        std::set<std::uint64_t> dhcp_servers;
        std::set<std::pair<std::uint64_t, std::uint64_t>> reservations;
        std::set<std::string> address_objects;
        std::set<std::string> revoke_ips;
        bool automation = false;

        [[nodiscard]] bool empty() const {
            return dhcp_servers.empty() && reservations.empty() && address_objects.empty() && revoke_ips.empty() && !automation;
        }
    };

    // Grants permits for the lifetime of the object (an apply), then withdraws them.
    class PermitScope {
        std::shared_ptr<WritePermits> permits_;

    public:
        PermitScope(std::shared_ptr<WritePermits> permits, WritePermits granted) : permits_(std::move(permits)) { *permits_ = std::move(granted); }
        ~PermitScope() { *permits_ = {}; }
        PermitScope(const PermitScope&) = delete;
        PermitScope& operator=(const PermitScope&) = delete;
    };

    // Throws GuardViolation naming the first offending operation.
    void check_operations(const nlohmann::json& operations, const Snapshot& snapshot, const Config& config,
                          const WritePermits& permits = {});

    // Empty when the request may be sent; otherwise why not.
    std::string refuse_write(fortiapi::Method method, std::string_view url, std::string_view body, std::string_view prefix,
                             const WritePermits& permits = {});

    class GuardTransport final : public fortiapi::Transport {
        std::shared_ptr<fortiapi::Transport> inner_;
        std::string prefix_;
        std::shared_ptr<WritePermits> permits_;

    public:
        GuardTransport(std::shared_ptr<fortiapi::Transport> inner, std::string prefix,
                       std::shared_ptr<WritePermits> permits = std::make_shared<WritePermits>())
                : inner_(std::move(inner)), prefix_(std::move(prefix)), permits_(std::move(permits)) {}

        fortiapi::HttpResponse perform(const fortiapi::HttpRequest& request) override;
    };

}  // namespace fph

#endif  // FORTI_PIHOLE_GUARD_HPP
