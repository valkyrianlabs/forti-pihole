---
title: forti-pihole
description: Unified FortiGate network identity and Pi-hole DNS policy synchronization.
order: 0
status: published
tags:
  - overview
---

# forti-pihole

**Unified FortiGate network identity and Pi-hole DNS policy synchronization.**

forti-pihole is a companion for a FortiGate and a Pi-hole. The FortiGate already knows your networks
and your devices; Pi-hole already knows how each filtering group should be treated. forti-pihole owns
the relationship between the two and keeps it true: device groups on the FortiGate map to Pi-hole
groups, and networks (or address slices of a network) map to Pi-hole client entries, so every device
gets the DNS policy of the group it belongs to.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Who owns what

| System | Owns | forti-pihole's role |
|---|---|---|
| FortiGate | Interfaces and VLANs, routing, DHCP, device identification, address objects and groups, firewall policies | Reads all of it; keeps the device groups (`fp-grp-<group>`) and their per-device MAC objects (`fp-dev-*`); adds DHCP reservations only where you turn that on |
| Pi-hole | Filtering groups, blocklists, allow and deny lists, filtering behaviour | Reads groups and client entries; keeps only the client entries it created (comment `managed by forti-pihole`) |
| forti-pihole | The mapping: device group ↔ Pi-hole group, network ↔ CIDR client entries | Plans, reports and reconciles it; journals address moves |

Your firewall policies reference the `fp-grp-*` address groups like any other address group. Your
Pi-hole groups keep their own blocklists and settings: forti-pihole never creates, renames or deletes a
Pi-hole group during a sync, and never touches an adlist or a domain entry.

## Never in the traffic path

forti-pihole is a command-line program (`forti-pihole`) and an optional service (`forti-piholed`) that
run beside the network, not in it. If either stops, the FortiGate keeps routing and serving DHCP with
what it has, and Pi-hole keeps filtering with its last configuration. Nothing is written until you set
`"enabled": true`, and `forti-pihole pause` stops all writes at any time.

## Two strategies, one engine

Each FortiGate interface you list in the configuration has an allocation strategy, chosen per network:

:::cards{
  columns="2"
  cardTheme="muted"
}

:::card[Subnet: native VLANs]{
  href="/guides/strategies#subnet"
  linkScope="title"
}
The interface subnet maps to one Pi-hole group as a CIDR client entry. Every device on the VLAN gets
that group's filtering. Nothing on the FortiGate changes.
:::

:::card[Slices: DHCP address slicing]{
  href="/guides/address-slicing"
  linkScope="title"
}
On a flat network, members of a group get DHCP reservations inside a CIDR slice that maps to their
Pi-hole group. Devices keep the interface's real mask and gateway.
:::

:::

**Hybrid** combines them: slices inside a real VLAN, with the rest of the VLAN mapped to the network
group's Pi-hole group. This works because Pi-hole resolves a client by its longest matching prefix.
**Observe** reads and reports a network without mapping anything. See
[Allocation strategies](/guides/strategies).

:::callout[A slice is not a subnet]{variant="warning"}
An address slice is a DHCP allocation and DNS classification unit. It is not a routed subnet and not
Layer-2 isolation: devices in a slice keep the interface's mask and gateway, and can still reach every
other device on the same network without passing the FortiGate.
:::

## What it is not

- **Not VLAN tagging.** forti-pihole never creates or changes interfaces. Creating a VLAN interface on
  the FortiGate does not make an access point or a switch tag anyone's traffic: tagging is configured
  on the AP and the switch, and a device lands on a VLAN only when they put it there.
- **No RADIUS, no 802.1X, no dynamic VLAN assignment.** It never configures switches,
  switch-controller or authentication.
- **No Layer-2 isolation.** Groups on one network share its broadcast domain, whatever their slice.
- **Not a DNS enforcement point.** Pi-hole filters only queries that reach it. DNS over HTTPS, iCloud
  Private Relay and devices with a hard-coded resolver bypass any DNS filtering unless your FortiGate
  policies stop them. See [Pi-hole](/guides/pihole#dns-that-bypasses-pi-hole).

## How a sync works

A sync reads the FortiGate (inventory, DHCP leases and servers, address objects and groups, VIPs,
policies) and Pi-hole (groups and client entries), classifies every device, and plans everything. The
inspecting commands stop there. `forti-pihole sync` (and `forti-piholed`, which runs the same sync)
then writes, in this order:

1. **FortiGate objects**: the device groups and device objects, through the forti engine's plan and
   apply (validated, verified, audited, with a rollback plan; a guarded profile waits for approval).
2. **Pi-hole**: the managed CIDR client entries.
3. **Reservations**: devices already inside their slice get a reservation at the address they hold.
4. **Migrations**: open address moves resume; then at most `--max-migrations` new ones start.

Step 3 and new migrations only happen on networks with `"manage_reservations": true`. The other
writing commands are explicit, one-off requests: `migrate`, `operations resume|rollback` and
`events install|remove`. See [Safety](/guides/safety) for the full model.

## Where to go next

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[Install]{
  href="/getting-started/install"
  linkScope="title"
}
Homebrew, APT, or from source; forti-cli profiles and a Pi-hole v6 app password.
:::

:::card[Onboarding]{
  href="/getting-started/onboarding"
  linkScope="title"
}
From `forti configure` to a first sync, step by step.
:::

:::card[Safety]{
  href="/guides/safety"
  linkScope="title"
}
What forti-pihole may write, what it never touches, and how to stop it.
:::

:::
