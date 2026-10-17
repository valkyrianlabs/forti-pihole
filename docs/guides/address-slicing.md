---
title: Address slicing
description: How DHCP address slicing works on a flat network, why slices must lie outside the dynamic pools, the sizing rule, reservations, capacity and what slices --propose suggests.
order: 50
status: published
tags:
  - guides
---

# Address slicing

On a flat network, Pi-hole can only tell devices apart by their addresses. **Address slicing** gives
each Pi-hole mapped device group its own CIDR-aligned block of the subnet, a **slice**, and moves the
group's members into it with DHCP reservations. Pi-hole then needs one client entry per slice, not one
per device.

:::toc[On this page]{depth="2" theme="compact"}
:::

:::callout[What a slice is, and is not]{variant="warning"}
A slice is a DHCP allocation and DNS classification unit. It is **not** a routed subnet: a device in
`192.168.1.200/29` keeps the interface's mask (`/24`) and gateway (`192.168.1.1`), and its traffic is
routed exactly as before. It is **not** Layer-2 isolation: every device on the network still reaches
every other directly. Use FortiGate policies with the `fp-grp-*` groups, or real VLANs, for isolation.
:::

## Pools and slices

A FortiGate DHCP server has dynamic **ip-ranges** (pools) that it hands to any device that asks, and
**reservations** that tie one address to one MAC. A slice is only exclusive when the DHCP server can
never hand one of its addresses to another device, so **a slice must lie outside every dynamic pool**,
or inside an exclude-range. A reservation inside a pool protects that one address, not the rest of the
slice: the next unknown device could get the address next to it and inherit the slice's Pi-hole group.

`forti-pihole slices` and `plan` report every slice that breaks this, along with the other conflicts
(in `plan` as `note (conflict): <kind> <slice>: ...`):

| Conflict | Meaning |
|---|---|
| `outside-network` | The slice is not inside the interface subnet |
| `dynamic-pool` | It overlaps a dynamic pool not covered by an exclude-range |
| `slice-overlap` | It overlaps another slice |
| `interface-ip` | It contains the gateway or another interface address |
| `foreign-occupant` | It holds a reservation, lease, VIP, host address object or static device of another group |

A configured slice with conflicts is reported, never moved: moving it would renumber its devices.

## Who goes where

For every device on a `slices` or `hybrid` network whose group has a slice there:

| Situation | Action |
|---|---|
| Its address is in its slice and reserved there | `in-place`: nothing to do |
| Its address is in its slice, not reserved | `reserve`: a reservation at the address it already has (no address change, no lease touched) |
| Its address is elsewhere | `move`: a [migration](/guides/migrations) picks the lowest free address in the slice and moves it safely |

Devices whose group has no slice on that network belong in the shared range and are left alone. A device
holding an address inside **another** group's slice (a static address, a stale lease) is reported as
`foreign-in-slice`, never moved automatically: its own group has no target there. Protected devices are
never touched.

When a slice is full, the device is reported as `slice-full` and waits.

### Reservations

forti-pihole writes **single reservation entries** through the DHCP server's `reserved-address` child
table, never the whole list. Each one it creates carries the marker in its description:
`managed by forti-pihole: <label> in <group> (<slice>)`. It changes a reservation it did not create
only after you [adopt](/guides/migrations#adopting-administrator-objects) it, and it never changes a
reservation's MAC.

Nothing is reserved until the network has `"manage_reservations": true`. With it off, `plan` still
shows every action, so you can review the moves first.

## Sizing

The planner sizes a slice for a group from the number of its members detected on that network,
with a headroom of 1.5:

- A group expecting `N` devices needs `ceil(N × 1.5)` addresses, at least 1.
- A new slice is the smallest block of `2^k` addresses that is at least `max(4, need)`. A slice is never
  smaller than a `/30`: one or two addresses would leave no room for the next device and multiply the
  Pi-hole entries.
- A slice's first and last addresses are ordinary hosts (it is not a subnet). Only the parent subnet's
  own network and broadcast addresses are lost, so a block at the edge of the subnet is accepted only
  when what is left still covers the need. Interface addresses never count as usable.

| Members | Need | Slice |
|---|---|---|
| 1-2 | 2-3 | `/30` (4) |
| 3-5 | 5-8 | `/29` (8) |
| 6-10 | 9-15 | `/28` (16) |
| 11-21 | 17-32 | `/27` (32) |

Only groups with a `pihole_group` get a slice: without one, Pi-hole has nothing to tell apart. The
network's own `group` never needs a slice on its own network.

## Placement

The planner keeps every configured slice inside the network, then gives each group whose slices do not
cover its need another **best-fit** slice: among the free blocks (inside the subnet, outside every
dynamic pool and every other slice, holding nobody else's address) it takes the smallest that fits,
then the lowest, which keeps large free blocks whole for later. Groups are served largest block first,
then by name, so the same input always gives the same proposal.

## slices --propose

```bash
forti-pihole slices              # slice networks: configured slices, utilization, conflicts
forti-pihole slices --propose    # every network: what the planner would add for the current members
forti-pihole slices --json
```

Each slice is listed as `configured` or `proposed`, with its utilization (`used N/M`: occupied
addresses of its usable ones, whoever holds them). The proposal is advice: nothing is written, and you
copy the slices you accept into the network's `slices` in `config.json`.

### When there is not enough room

When the free space cannot cover a group's need, the output says how many addresses are missing and
lists the options, ranked by how many current dynamic leases they would displace (fewest first):

| Option | What it means |
|---|---|
| `reduce-headroom` | Room for exactly the current members instead of `N × 1.5` |
| `split` | Several smaller slices out of fragmented free space |
| `shrink-pool` | Shrink a dynamic pool from its top (FortiOS hands out pool addresses from the bottom, so the top is least likely to be in use) |
| `exclude-range` | Add an exclude-range to a pool over the block |

No option ever moves a reservation, VIP, address object or static device. forti-pihole never changes a
pool or an exclude-range itself: a pool change is a suggestion for you to make on the FortiGate.

### Other ways to get capacity

- Shrink the dynamic pool yourself, in the FortiGate GUI, to make room above or below it.
- Use a real VLAN for a large group (`subnet` mode), and keep slices for the few devices that need them.
- Put a group in the shared range on purpose: without a slice its members keep Pi-hole's Default group,
  unless you map them in Pi-hole yourself.
