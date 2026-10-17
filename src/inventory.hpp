//
// One consistent read of everything classification and reconciliation need: the FortiGate's device
// inventory (with its own fingerprinting), DHCP leases and servers, address objects and groups, the
// resolution of dynamic device-identification rule objects, and the policy/service tables the
// connectivity check simulates. Read-only.
//

#ifndef FORTI_PIHOLE_INVENTORY_HPP
#define FORTI_PIHOLE_INVENTORY_HPP

#include "config.hpp"
#include "gateway.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace fph {

    // A device counts as online when FortiOS says so and saw it within this many seconds.
    inline constexpr std::int64_t online_window = 3600;

    struct Device {
        std::string mac;               // normalized
        std::string ip;
        std::string interface;         // detected interface
        std::string hostname;          // inventory hostname, else the DHCP lease's
        std::string vendor, family, type, model, os, os_version;   // FortiGate fingerprint
        std::string vci;               // DHCP vendor class
        std::string firewall_address;  // inventory mac_firewall_address (an object FortiOS links to it)
        bool online = false;
        bool randomized = false;       // locally administered MAC
        bool reserved = false;         // has a DHCP reservation
        std::int64_t last_seen = 0;    // epoch seconds

        // "Alexs-iPhone", else "Apple iPhone", else the MAC.
        [[nodiscard]] std::string label() const;
    };

    struct Address {
        std::string name, type, sub_type, comment;
        std::vector<std::string> macs;   // type mac: entries (single or "lo-hi")
        std::string subnet;              // ipmask / interface-subnet: "a.b.c.d m.m.m.m"
        std::string start_ip, end_ip;    // iprange
        std::string hw_vendor, hw_model, os, sw_version;   // dynamic device-identification filters
        std::vector<std::string> resolved;                  // dynamic: what FortiOS resolved it to (MACs or IPs)

        [[nodiscard]] bool managed() const;   // carries the ownership marker
    };

    struct AddrGroup {
        std::string name, comment;
        std::vector<std::string> members;
        bool exclude = false;
        std::vector<std::string> exclude_members;

        [[nodiscard]] bool managed() const;
    };

    struct Policy {
        std::uint64_t id = 0;
        std::string name;
        bool enabled = true;
        std::string action;   // accept | deny
        std::vector<std::string> srcintf, dstintf, srcaddr, dstaddr, service;
        bool srcaddr_negate = false, dstaddr_negate = false, service_negate = false;
        bool internet_service = false;
        bool needs_auth = false;   // users or groups set
    };

    struct Service {
        std::string name, protocol;
        std::string tcp, udp;   // FortiOS portrange strings
        std::vector<std::string> members;   // groups
        bool group = false;
    };

    struct Interface {
        std::string name, alias, type, role, ip;   // ip: "a.b.c.d m.m.m.m"
        std::string parent;                        // VLAN / EMAC VLAN: the underlying interface
        unsigned vlanid = 0;
        bool up = true;
        std::vector<std::string> secondary;
    };

    struct Reservation {
        std::uint64_t id = 0;
        std::string ip, mac, action, description;   // action: reserved | assign | block
        [[nodiscard]] bool managed() const;         // description carries the ownership marker
    };

    struct IpRange {
        std::string start, end;
    };

    struct DhcpServer {
        std::uint64_t id = 0;
        std::string interface;
        bool enabled = true;
        std::string dns1;   // empty when DNS is the FortiGate itself (dns-service default/local)
        std::string gateway, netmask;
        std::vector<IpRange> ranges;     // dynamic pools
        std::vector<IpRange> excludes;   // never handed out dynamically
        std::vector<Reservation> reservations;
        std::string mac_acl_default = "assign";
    };

    struct Lease {
        std::string ip, mac, hostname, interface;
        bool reserved = false;
        std::int64_t expires = 0;
    };

    struct Vip {
        std::string name, extintf;
        std::vector<std::string> mapped;   // mapped IPs or "lo-hi" ranges
    };

    struct Snapshot {
        std::vector<Device> devices;               // managed interfaces only, online or recently seen
        std::map<std::string, Address> addresses;  // every address (names are unique)
        std::map<std::string, AddrGroup> addrgrps;   // firewall address groups
        std::vector<Policy> policies;              // in evaluation order
        std::map<std::string, Service> services;
        std::map<std::string, Interface> interfaces;
        std::vector<DhcpServer> dhcp;
        std::vector<Lease> leases;
        std::vector<Vip> vips;
        std::int64_t taken_at = 0;

        [[nodiscard]] const Interface* interface(std::string_view name) const;
        [[nodiscard]] const DhcpServer* dhcp_for(std::string_view interface) const;   // the enabled server on it

        [[nodiscard]] const Device* device(std::string_view mac) const;
        [[nodiscard]] const Address* address(std::string_view name) const;
        [[nodiscard]] const AddrGroup* addrgrp(std::string_view name) const;
    };

    // Reads everything (several requests; each listing fully paged). Throws GatewayError.
    Snapshot collect(Gateway& gateway, const Config& config, std::int64_t now);

    // Turns raw engine reads into a Snapshot; separate so tests can feed recorded device JSON.
    struct RawReads {
        nlohmann::json devices, leases, addresses, addrgrps, policies, services, service_groups, interfaces, dhcp, vips;
        std::map<std::string, nlohmann::json> dynamic;   // address name -> monitor/firewall/address-dynamic entry
    };
    Snapshot build_snapshot(const RawReads& raw, const Config& config, std::int64_t now);

}  // namespace fph

#endif  // FORTI_PIHOLE_INVENTORY_HPP
