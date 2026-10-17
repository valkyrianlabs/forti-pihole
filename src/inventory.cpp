#include "inventory.hpp"

#include "mac.hpp"

#include <algorithm>
#include <format>

namespace fvm {

    using json = nlohmann::json;

    namespace {

        std::string str(const json& object, const char* key) {
            auto it = object.find(key);
            if (it == object.end() || it->is_null()) return {};
            if (it->is_string()) return it->get<std::string>();
            if (it->is_number() || it->is_boolean()) return it->dump();
            return {};
        }

        bool flag(const json& object, const char* key) {
            auto it = object.find(key);
            if (it == object.end()) return false;
            if (it->is_boolean()) return it->get<bool>();
            if (it->is_string()) return it->get<std::string>() == "enable";
            return false;
        }

        std::int64_t number(const json& object, const char* key) {
            auto it = object.find(key);
            return it != object.end() && it->is_number_integer() ? it->get<std::int64_t>() : 0;
        }

        // FortiOS table attributes: [{"name": "x", "q_origin_key": "x"}, ...]
        std::vector<std::string> names(const json& object, const char* key, const char* field = "name") {
            std::vector<std::string> out;
            auto it = object.find(key);
            if (it == object.end() || !it->is_array()) return out;
            for (const auto& entry: *it) {
                if (entry.is_string()) out.push_back(entry.get<std::string>());
                else if (entry.is_object()) {
                    auto value = str(entry, field);
                    if (!value.empty()) out.push_back(value);
                }
            }
            return out;
        }

        const json& array_or_empty(const json& value) {
            static const json empty = json::array();
            return value.is_array() ? value : empty;
        }

        bool contains(const std::vector<std::string>& list, std::string_view value) {
            return std::ranges::find(list, value) != list.end();
        }

    }  // namespace

    std::string Device::label() const {
        if (!hostname.empty()) return hostname;
        std::string text = vendor;
        if (!family.empty()) text += (text.empty() ? "" : " ") + family;
        return text.empty() ? mac : text;
    }

    bool Address::managed() const { return comment.find(marker) != std::string::npos; }
    bool Group::managed() const { return comment.find(marker) != std::string::npos; }

    const Device* Snapshot::device(std::string_view mac) const {
        for (const auto& d: devices)
            if (d.mac == mac) return &d;
        return nullptr;
    }

    const Address* Snapshot::address(std::string_view name) const {
        auto it = addresses.find(std::string(name));
        return it == addresses.end() ? nullptr : &it->second;
    }

    const Group* Snapshot::group(std::string_view name) const {
        auto it = groups.find(std::string(name));
        return it == groups.end() ? nullptr : &it->second;
    }

    Snapshot build_snapshot(const RawReads& raw, const Config& config, std::int64_t now) {
        Snapshot snapshot;
        snapshot.taken_at = now;

        // DHCP leases fill in what the inventory lacks (hostname, vendor class, reservation).
        struct Lease {
            std::string hostname, vci, ip;
            bool reserved = false;
        };
        std::map<std::string, Lease> leases;
        for (const auto& lease: array_or_empty(raw.leases)) {
            auto mac = normalize_mac(str(lease, "mac"));
            if (!mac) continue;
            leases[*mac] = {str(lease, "hostname"), str(lease, "vci"), str(lease, "ip"), flag(lease, "reserved")};
        }

        for (const auto& item: array_or_empty(raw.devices)) {
            auto mac = normalize_mac(str(item, "mac"));
            if (!mac) continue;
            Device device;
            device.mac = *mac;
            device.interface = str(item, "detected_interface");
            if (device.interface.empty()) {
                auto online = names(item, "online_interfaces");
                if (!online.empty()) device.interface = online.front();
            }
            // Only the interfaces the operator listed are managed: servers, DMZ and the WAN never are.
            if (!contains(config.interfaces, device.interface)) continue;
            device.ip = str(item, "ipv4_address");
            device.hostname = str(item, "hostname");
            device.vendor = str(item, "hardware_vendor");
            device.family = str(item, "hardware_family");
            device.type = str(item, "hardware_type");
            device.model = str(item, "hardware_version");
            device.os = str(item, "os_name");
            device.os_version = str(item, "os_version");
            device.firewall_address = str(item, "mac_firewall_address");
            device.last_seen = number(item, "last_seen");
            // FortiOS keeps is_online true for inventory entries it last saw days ago (observed on
            // 7.4.8), so online also needs a recent last_seen.
            device.online = flag(item, "is_online") && (device.last_seen == 0 || now - device.last_seen <= online_window);
            device.reserved = flag(item, "dhcp_lease_reserved");
            device.randomized = locally_administered(device.mac);
            if (auto lease = leases.find(device.mac); lease != leases.end()) {
                if (device.hostname.empty()) device.hostname = lease->second.hostname;
                if (device.ip.empty()) device.ip = lease->second.ip;
                device.vci = lease->second.vci;
                device.reserved = device.reserved || lease->second.reserved;
            }
            // FortiOS reports DNS-derived names like "192-168-1-36" for some devices; they say
            // nothing about the device and would make reassociation match on an address.
            if (device.hostname.find_first_not_of("0123456789-.") == std::string::npos || device.hostname == "none")
                device.hostname.clear();
            snapshot.devices.push_back(std::move(device));
        }
        std::ranges::sort(snapshot.devices, {}, &Device::mac);

        for (const auto& item: array_or_empty(raw.addresses)) {
            Address address;
            address.name = str(item, "name");
            if (address.name.empty()) continue;
            address.type = str(item, "type");
            address.sub_type = str(item, "sub-type");
            address.comment = str(item, "comment");
            address.macs = names(item, "macaddr", "macaddr");
            address.subnet = str(item, "subnet");
            address.start_ip = str(item, "start-ip");
            address.end_ip = str(item, "end-ip");
            address.hw_vendor = str(item, "hw-vendor");
            address.hw_model = str(item, "hw-model");
            address.os = str(item, "os");
            address.sw_version = str(item, "sw-version");
            if (auto dynamic = raw.dynamic.find(address.name); dynamic != raw.dynamic.end())
                for (const auto& value: array_or_empty(dynamic->second.value("addrs", json::array())))
                    if (value.is_string()) {
                        auto mac = normalize_mac(value.get<std::string>());
                        address.resolved.push_back(mac ? *mac : value.get<std::string>());
                    }
            snapshot.addresses.emplace(address.name, std::move(address));
        }

        for (const auto& item: array_or_empty(raw.groups)) {
            Group group;
            group.name = str(item, "name");
            if (group.name.empty()) continue;
            group.comment = str(item, "comment");
            group.members = names(item, "member");
            group.exclude = flag(item, "exclude");
            group.exclude_members = names(item, "exclude-member");
            snapshot.groups.emplace(group.name, std::move(group));
        }

        for (const auto& item: array_or_empty(raw.policies)) {
            Policy policy;
            policy.id = static_cast<std::uint64_t>(number(item, "policyid"));
            policy.name = str(item, "name");
            policy.enabled = str(item, "status") != "disable";
            policy.action = str(item, "action");
            policy.srcintf = names(item, "srcintf");
            policy.dstintf = names(item, "dstintf");
            policy.srcaddr = names(item, "srcaddr");
            policy.dstaddr = names(item, "dstaddr");
            policy.service = names(item, "service");
            policy.srcaddr_negate = flag(item, "srcaddr-negate");
            policy.dstaddr_negate = flag(item, "dstaddr-negate");
            policy.service_negate = flag(item, "service-negate");
            policy.internet_service = flag(item, "internet-service");
            policy.needs_auth = !names(item, "users").empty() || !names(item, "groups").empty();
            snapshot.policies.push_back(std::move(policy));
        }

        for (const auto& item: array_or_empty(raw.services)) {
            Service service;
            service.name = str(item, "name");
            service.protocol = str(item, "protocol");
            service.tcp = str(item, "tcp-portrange");
            service.udp = str(item, "udp-portrange");
            snapshot.services.emplace(service.name, std::move(service));
        }
        for (const auto& item: array_or_empty(raw.service_groups)) {
            Service service;
            service.name = str(item, "name");
            service.group = true;
            service.members = names(item, "member");
            snapshot.services.emplace(service.name, std::move(service));
        }

        for (const auto& item: array_or_empty(raw.interfaces)) {
            Interface interface;
            interface.name = str(item, "name");
            interface.role = str(item, "role");
            interface.ip = str(item, "ip");
            for (const auto& secondary: array_or_empty(item.value("secondaryip", json::array())))
                interface.secondary.push_back(str(secondary, "ip"));
            snapshot.interfaces.emplace(interface.name, std::move(interface));
        }

        for (const auto& item: array_or_empty(raw.dhcp)) {
            DhcpServer server;
            server.id = static_cast<std::uint64_t>(number(item, "id"));
            server.interface = str(item, "interface");
            server.gateway = str(item, "default-gateway");
            server.netmask = str(item, "netmask");
            if (str(item, "dns-service") == "specify") server.dns1 = str(item, "dns-server1");
            snapshot.dhcp.push_back(std::move(server));
        }
        return snapshot;
    }

    Snapshot collect(Gateway& gateway, const Config& config, std::int64_t now) {
        auto base = [&](std::string resource) {
            json request = {{"resource", std::move(resource)}};
            if (!config.profile.empty()) request["profile"] = config.profile;
            if (!config.vdom.empty()) request["vdom"] = config.vdom;
            return request;
        };
        auto with_fields = [&](std::string resource, std::vector<std::string> fields) {
            auto request = base(std::move(resource));
            request["fields"] = std::move(fields);
            return request;
        };

        RawReads raw;
        raw.devices = read_all(gateway, base("monitor/user/device/query"));
        raw.leases = read_all(gateway, base("monitor/system/dhcp"));
        raw.addresses = read_all(gateway, with_fields("firewall/address",
                {"name", "type", "sub-type", "comment", "macaddr", "subnet", "start-ip", "end-ip", "hw-vendor", "hw-model",
                 "os", "sw-version"}));
        raw.groups = read_all(gateway, with_fields("firewall/addrgrp", {"name", "comment", "member", "exclude", "exclude-member"}));
        raw.policies = read_all(gateway, with_fields("firewall/policy",
                {"policyid", "name", "status", "action", "srcintf", "dstintf", "srcaddr", "dstaddr", "service",
                 "srcaddr-negate", "dstaddr-negate", "service-negate", "internet-service", "users", "groups"}));
        raw.services = read_all(gateway, with_fields("firewall.service/custom", {"name", "protocol", "tcp-portrange", "udp-portrange"}));
        raw.service_groups = read_all(gateway, with_fields("firewall.service/group", {"name", "member"}));
        raw.interfaces = read_all(gateway, with_fields("system/interface", {"name", "role", "ip", "secondaryip"}));
        raw.dhcp = read_all(gateway, with_fields("system.dhcp/server",
                {"id", "interface", "default-gateway", "netmask", "dns-service", "dns-server1"}));

        // Dynamic objects resolve per object: the monitor answers for one mkey reliably, while a bare
        // listing can omit objects nothing references yet (observed on 7.4.8). Rule objects are
        // classification inputs; other device-identification objects matter to the connectivity check.
        for (const auto& item: array_or_empty(raw.addresses)) {
            if (str(item, "type") != "dynamic" || str(item, "sub-type") != "device-identification") continue;
            auto name = str(item, "name");
            auto request = base("monitor/firewall/address-dynamic");
            request["params"] = {{"mkey", name}};
            auto result = gateway.read(request);
            if (!result.value("ok", false)) throw GatewayError(result.value("error", json::object()));
            const auto& data = result["data"];
            if (data.is_object() && data.contains(name)) raw.dynamic[name] = data[name];
        }
        return build_snapshot(raw, config, now);
    }

    json read_all(Gateway& gateway, json request) {
        json items = json::array();
        request["count"] = 1000;
        std::size_t start = 0;
        for (int guard = 0; guard < 1000; ++guard) {
            request["start"] = start;
            auto result = gateway.read(request);
            if (!result.value("ok", false)) throw GatewayError(result.value("error", json::object()));
            const auto& data = result["data"];
            if (!data.is_array()) return data;   // singletons and keyed monitor replies come back whole
            for (const auto& item: data) items.push_back(item);
            const auto& meta = result.value("meta", json::object());
            if (!meta.contains("next_start")) return items;
            auto next = meta["next_start"].get<std::size_t>();
            if (next <= start) return items;
            start = next;
        }
        return items;
    }

}  // namespace fvm
