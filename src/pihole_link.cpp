#include "pihole_link.hpp"

#include "pihole/client.hpp"
#include "pihole/error.hpp"
#include "pihole/resolve.hpp"
#include "pihole/transport.hpp"

#include <forti/engine/error.hpp>
#include <forti/engine/profile.hpp>

#include <format>

namespace fph {

    namespace {

        class Link final : public PiholeApi {
            std::unique_ptr<pihole::Client> client_;
            std::string version_;

        public:
            explicit Link(std::unique_ptr<pihole::Client> client) : client_(std::move(client)) {}

            std::string version() override {
                if (version_.empty()) {
                    auto info = client_->require_supported_version();
                    version_ = info.ftl.empty() ? "FTL (unknown)" : "FTL " + info.ftl;
                }
                return version_;
            }

            PiholeView view() override {
                PiholeView out;
                for (const auto& g: client_->groups()) out.groups.push_back({g.id, g.name, g.enabled});
                for (const auto& c: client_->clients()) out.clients.push_back({c.id, c.client, c.comment.value_or(""), c.groups});
                return out;
            }

            std::vector<PiholeApplied> apply(const std::vector<PiholeChange>& changes) override {
                std::vector<PiholeApplied> done;
                for (const auto& change: changes) {
                    PiholeApplied result{change.kind, change.cidr, change.client_id, false, {}};
                    try {
                        if (change.kind == "create") result.client_id = client_->create_client({change.cidr, change.comment, change.group_ids, false}).id;
                        else if (change.kind == "update") client_->update_client({change.cidr, change.comment, change.group_ids, false});
                        else if (change.kind == "delete") client_->delete_client(change.cidr);
                        result.ok = true;
                    } catch (const std::exception& e) {
                        result.error = e.what();
                        done.push_back(result);
                        break;
                    }
                    done.push_back(result);
                }
                return done;
            }

            std::vector<int> effective_groups(const std::string& ip) override {
                auto clients = client_->clients();
                return pihole::effective_groups(clients, ip);
            }
        };

        std::unique_ptr<PiholeApi> connect(const PiholeConfig& pihole, const std::string& password) {
            if (pihole.url.empty()) throw PiholeLinkError("Pi-hole is not configured (config.pihole.url); run forti-pihole setup");
            try {
                pihole::Endpoint endpoint;
                endpoint.url = pihole.url;
                if (!pihole.ca_bundle.empty()) endpoint.ca_bundle = pihole.ca_bundle;
                endpoint.timeout_ms = pihole.timeout_ms;
                auto client = std::make_unique<pihole::Client>(std::make_shared<pihole::CurlTransport>(endpoint));
                client->login(password);
                auto link = std::make_unique<Link>(std::move(client));
                link->version();
                return link;
            } catch (const pihole::Error& e) {
                throw PiholeLinkError(std::format("Pi-hole at {}: {}", pihole.url, e.what()));
            }
        }

    }  // namespace

    std::string pihole_account(const PiholeConfig& pihole) { return "pihole/" + pihole.name + "/password"; }

    std::string pihole_binding(const PiholeConfig& pihole) {
        // scheme://host[:port][/...] -> host:port, with the scheme's default port.
        std::string_view url = pihole.url;
        bool https = url.starts_with("https://");
        url.remove_prefix(url.find("://") == std::string_view::npos ? 0 : url.find("://") + 3);
        url = url.substr(0, url.find('/'));
        if (url.find(':') == std::string_view::npos) return std::format("{}:{}", url, https ? 443 : 80);
        return std::string(url);
    }

    std::unique_ptr<PiholeApi> pihole_connect(const PiholeConfig& pihole, const std::string& password) { return connect(pihole, password); }

    std::unique_ptr<PiholeApi> pihole_connect(const Config& config, forti::engine::SecretStore& store) {
        if (config.pihole.url.empty()) throw PiholeLinkError("Pi-hole is not configured (config.pihole.url); run forti-pihole setup");
        std::optional<forti::engine::StoredSecret> secret;
        try {
            secret = store.get(pihole_account(config.pihole));
        } catch (const forti::engine::Failure& e) {
            throw PiholeLinkError(std::string("cannot read the Pi-hole password from forti's secret store: ") + e.what());
        }
        if (!secret) throw PiholeLinkError("no Pi-hole password stored for " + config.pihole.name + "; run forti-pihole setup");
        if (secret->binding != pihole_binding(config.pihole))
            throw PiholeLinkError(std::format("the stored Pi-hole password belongs to {}, not {}; run forti-pihole setup",
                                              secret->binding.empty() ? "an unbound entry" : secret->binding, pihole_binding(config.pihole)));
        return connect(config.pihole, secret->secret);
    }

}  // namespace fph
