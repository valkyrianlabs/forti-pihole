#include "guard.hpp"

#include <array>
#include <format>

namespace fvm {

    using json = nlohmann::json;

    namespace {

        constexpr std::array writable = {std::string_view("firewall/address"), std::string_view("firewall/addrgrp")};

        bool is_writable(std::string_view resource) {
            if (resource.starts_with("cmdb/")) resource.remove_prefix(5);
            for (auto w: writable)
                if (resource == w) return true;
            return false;
        }

        std::string percent_decode(std::string_view text) {
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            std::string out;
            for (std::size_t i = 0; i < text.size(); ++i) {
                if (text[i] == '%' && i + 2 < text.size() && hex(text[i + 1]) >= 0 && hex(text[i + 2]) >= 0) {
                    out += static_cast<char>(hex(text[i + 1]) * 16 + hex(text[i + 2]));
                    i += 2;
                } else out += text[i];
            }
            return out;
        }

        bool has_marker(const json& object) {
            auto it = object.find("comment");
            return it != object.end() && it->is_string() && it->get<std::string>().find(marker) != std::string::npos;
        }

    }  // namespace

    void check_operations(const json& operations, const Snapshot& snapshot, const Config& config) {
        if (!operations.is_array()) throw GuardViolation("operations must be an array");
        for (std::size_t i = 0; i < operations.size(); ++i) {
            const auto& op = operations[i];
            auto where = std::format("operation {}", i);
            auto kind = op.value("op", std::string());
            auto resource = op.value("resource", std::string());
            if (!is_writable(resource)) throw GuardViolation(std::format("{}: {} is not a resource forti-vlan-mac may write", where, resource));
            bool group = resource.ends_with("addrgrp");
            if (kind == "create") {
                const auto& object = op.value("object", json::object());
                auto name = object.value("name", std::string());
                if (!name.starts_with(config.prefix)) throw GuardViolation(std::format("{}: {} lacks the prefix {}", where, name, config.prefix));
                if (!has_marker(object)) throw GuardViolation(std::format("{}: {} is created without the ownership marker", where, name));
                if (group ? snapshot.group(name) != nullptr : snapshot.address(name) != nullptr)
                    throw GuardViolation(std::format("{}: {} already exists", where, name));
            } else if (kind == "update" || kind == "delete") {
                auto key = op.value("key", std::string());
                if (!key.starts_with(config.prefix)) throw GuardViolation(std::format("{}: {} lacks the prefix {}", where, key, config.prefix));
                bool managed = group ? (snapshot.group(key) && snapshot.group(key)->managed())
                                     : (snapshot.address(key) && snapshot.address(key)->managed());
                if (!managed) throw GuardViolation(std::format("{}: {} does not carry the ownership marker", where, key));
                if (kind == "update") {
                    // The marker must survive: a comment change has to keep it, and nothing may clear it.
                    const auto& set = op.value("set", json::object());
                    if (set.contains("comment") && !has_marker(set))
                        throw GuardViolation(std::format("{}: update would remove the ownership marker from {}", where, key));
                    for (const auto& cleared: op.value("clear", json::array()))
                        if (cleared == "comment" || cleared == "name")
                            throw GuardViolation(std::format("{}: may not clear {} on {}", where, cleared.get<std::string>(), key));
                    if (set.contains("name")) throw GuardViolation(std::format("{}: renames are not allowed ({})", where, key));
                }
            } else throw GuardViolation(std::format("{}: operation \"{}\" is not allowed", where, kind));
        }
    }

    std::string refuse_write(fortiapi::Method method, std::string_view url, std::string_view body, std::string_view prefix) {
        if (method == fortiapi::Method::Get) return {};
        auto api = url.find("/api/v2/");
        if (api == std::string_view::npos) return "not a FortiOS API URL";
        auto path = url.substr(api + 8);
        path = path.substr(0, path.find('?'));
        for (auto w: writable) {
            std::string collection = "cmdb/" + std::string(w);
            if (path == collection) {
                // A create names the object in its body.
                if (method != fortiapi::Method::Post) return std::format("{} on the whole collection {}", fortiapi::to_string(method), collection);
                auto parsed = json::parse(body, nullptr, false);
                auto name = parsed.is_object() ? parsed.value("name", std::string()) : std::string();
                if (!name.starts_with(prefix)) return std::format("create of \"{}\" in {} (not {}*)", name, collection, prefix);
                return {};
            }
            if (path.starts_with(collection + "/")) {
                auto rest = path.substr(collection.size() + 1);
                // Exactly one more segment: the object. Child-table paths are not allowed.
                if (rest.find('/') != std::string_view::npos) return std::format("nested path {}", path);
                auto name = percent_decode(rest);
                if (!name.starts_with(prefix)) return std::format("{} of \"{}\" (not {}*)", fortiapi::to_string(method), name, prefix);
                if (method == fortiapi::Method::Post) return std::format("POST to an object path {}", path);
                return {};
            }
        }
        return std::format("{} {} is outside forti-vlan-mac's write allowlist", fortiapi::to_string(method), path);
    }

    fortiapi::HttpResponse GuardTransport::perform(const fortiapi::HttpRequest& request) {
        if (auto why = refuse_write(request.method, request.url, request.body, prefix_); !why.empty())
            // Thrown before the inner transport sees the request: nothing reaches the device.
            throw GuardViolation("write guard refused a request: " + why);
        return inner_->perform(request);
    }

}  // namespace fvm
