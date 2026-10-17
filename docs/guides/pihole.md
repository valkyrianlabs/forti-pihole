---
title: Pi-hole
description: What forti-pihole writes in Pi-hole and what it leaves alone, how Pi-hole resolves a client's groups, the original-source-IP requirement, IPv6, DNS bypass, and the app password.
order: 70
status: published
tags:
  - guides
---

# Pi-hole

forti-pihole talks to Pi-hole v6 (FTL 6.7.0 or newer) through its REST API. It reads Pi-hole's groups and
client entries, and keeps only the client entries it created. Everything else in Pi-hole is yours.

:::toc[On this page]{depth="2" theme="compact"}
:::

## What forti-pihole owns

| Pi-hole object | forti-pihole |
|---|---|
| Client entries whose comment contains `managed by forti-pihole` | Creates, updates and deletes them |
| Every other client entry (yours) | Reads and reports; never changes or deletes it |
| Groups | Maps device groups to them **by name** (case-sensitive, as Pi-hole compares); never creates, renames, disables or deletes one during a sync |
| Adlists, domains, regexes, settings | Never touches them; no request for them exists in its client |

The client checks every request against an allowlist (login and logout, version, groups, client
entries) before sending it, as the guard transport does for the FortiGate. A managed entry is updated or
deleted only after a fresh read shows it still carries the marker, and every update keeps the marker in
its comment.

### The entries a sync writes

| Network mode | Entry | Comment |
|---|---|---|
| `subnet` | Each interface subnet (primary and secondary) → the network group's Pi-hole group | `managed by forti-pihole: <interface> subnet` |
| `slices` | Each slice → its group's Pi-hole group | `managed by forti-pihole: <interface> slice <group>` |
| `hybrid` | Each slice, plus each subnet → the network group's Pi-hole group | as above |
| `observe` | Nothing | |

A group without a `pihole_group` produces no entry: its addresses stay with Pi-hole's Default group, as
any address with no entry does. When a configured Pi-hole group does not exist, the entry is not written
and `plan` reports `missing-group`: create the group in Pi-hole, or map another.

When a network's subnet or slices change, its old managed entries are replaced in the same sync. A
managed entry for a network that is no longer configured is reported as `stale-managed` and deleted only
by `forti-pihole sync --prune`.

## How Pi-hole picks a client's groups

No Pi-hole API reports which groups apply to a client, so forti-pihole models FTL's own resolution
(`get_client_groupids()` in FTL's `src/database/gravity-db.c`, FTL v6.7.1) in
`src/pihole/resolve.hpp`, and uses it to check that each managed range resolves as intended. FTL
resolves per client IP and stops at the first step that finds an entry:

1. **IP and subnet entries, longest prefix first.** Each entry is scored by FTL's `subnet_match()`: its
   prefix length when the address falls inside it (a bare address counts as `/32`), else 0. The highest
   score wins; among entries with the same score FTL takes the most recently added (highest id) and logs
   a "subnet" warning. *"So an exact address beats any subnet, a /28 beats the /24 around it, and two
   entries of the same length that both match are an ambiguity Pi-hole resolves by row id."*
2. **The MAC address** FTL knows for the IP, when `resolver.macNames` is on (the default), compared as
   text, case-insensitively.
3. **The hostname** FTL resolved for the IP, compared the same way.
4. **The interface** the query arrived on (an entry written `:eth0`).
5. **No entry**: the Default group only.

The entry found applies with exactly its groups; the Default group is not added. Disabled groups stay in
the set, but their lists do not apply.

Consequences for your own entries (from the same header):

- *"Overlapping subnets of different lengths are well defined (longest prefix wins), so a VLAN subnet
  entry plus narrower slice or per-device address entries inside it is a valid design."* This is what
  makes `hybrid` work.
- *"Any address or subnet row that covers a device shadows that device's MAC, hostname and interface
  rows entirely. Inside a managed subnet, per-device exceptions must be address rows."*
- *"IPv4 rows say nothing about the same device's IPv6 queries."*

### What plan reports about your entries

| Note | Meaning |
|---|---|
| `unmanaged-shadow` | One of your IP or narrower-CIDR entries lies inside a managed range: it decides those addresses, not the managed entry. A device keeps those groups whatever slice it moves to; remove the entry once its new address is verified |
| `unmanaged-overlap` | You already have an entry for exactly that CIDR, with other groups. Yours wins and is left as it is |
| `mac-client` | You identify a client by MAC. For clients routed through the FortiGate Pi-hole cannot see their MAC, so the entry may never match |
| `resolution` | Pi-hole currently resolves the first address of a managed range to other groups than intended (an entry of yours shadows it) |
| `missing-group`, `stale-managed`, `new-network` | A mapped group that does not exist; a managed entry nothing implies; an interface with DHCP that no network lists yet |

## Pi-hole must see the real client address

Pi-hole can only tell devices apart when queries reach it **from the devices' own addresses**:

- **Hand out Pi-hole as the DNS server** in each DHCP server (the `dns-server` settings), not the
  FortiGate. When clients query the FortiGate's DNS proxy, the FortiGate forwards their queries from its
  own address, and Pi-hole sees one client for the whole network.
- **No source NAT** on the policy from the clients to Pi-hole. When Pi-hole is on another interface, the
  policy that allows DNS from the clients to it must have NAT disabled; with NAT, every query appears to
  come from the FortiGate.
- With Pi-hole's `dns.EDNS0ECS` on (the default), an EDNS client subnet in a query replaces the source
  address. Forwarders that add one decide what Pi-hole sees.

forti-pihole's connectivity check simulates each device's DNS reach (UDP/53 to the DNS server its DHCP
server hands out) before it changes anything, so a change that would cut a device off from Pi-hole is
refused for that device.

## IPv6

forti-pihole writes IPv4 entries. A device's IPv6 queries resolve independently, against IPv6 entries
only; FTL never maps an IPv4-mapped address (`::ffff:192.168.1.5`) onto an IPv4 entry, and IPv4 entries
say nothing about IPv6 queries. On a network without IPv6 there is nothing to do. On a network with
IPv6, either add your own IPv6 CIDR entries in Pi-hole for each prefix (forti-pihole leaves them alone),
or keep DNS for that network on IPv4 only, for example by not advertising an IPv6 DNS server.

## DNS that bypasses Pi-hole

Pi-hole filters only the queries that reach it. Any of these bypass DNS filtering entirely, whatever
forti-pihole configures:

- DNS over HTTPS or TLS in browsers and apps, and Apple's iCloud Private Relay;
- devices or apps with a hard-coded resolver (`8.8.8.8`, `1.1.1.1`);
- VPNs.

Stopping that is a FortiGate policy decision. A DNS redirect (a VIP that maps UDP/TCP 53 to Pi-hole)
only takes effect through a firewall policy that uses it; blocking DoH and DoT needs policies or
application control for those services as well. forti-pihole never writes VIPs or policies.

## The app password

`forti-pihole setup` asks for the app password once (input hidden; `--password-stdin` reads it from
standard input), verifies it against Pi-hole, and stores it in **forti's secret store**: the macOS login
Keychain (service `forti`), or elsewhere the engine's `0600` file store in the forti home. The account is
`pihole/<name>/password` (`name` is `pihole.name`, default `default`), bound to the Pi-hole URL's
host and port: a configuration pointing somewhere else cannot obtain it. It never appears in
`config.json`, output, logs or errors.

Use an app password (**Settings → Web interface / API → Configure app password**), not the admin
password: it skips two-factor authentication, which a periodic job cannot answer, and you can revoke it
without touching the admin password.

Each run logs in once and always logs out: FTL has a fixed number of API sessions
(`webserver.api.max_sessions`, default 16). A wrong password is final for that run; forti-pihole never
retries a login (FTL rate-limits them). To change the password or the Pi-hole URL, run
`forti-pihole setup` again.

### TLS

TLS certificate and host verification are always on. `pihole.ca_bundle` adds a private CA (a PEM file);
it never turns verification off. Plain `http://` is accepted only for a loopback Pi-hole. Redirects are
never followed, so a credential can never be replayed to another host.
