---
title: Device groups and rules
navTitle: Groups and rules
description: The FortiGate objects forti-pihole keeps, how a device is classified into a group, rule objects made in the GUI, privileged groups, GUI moves and overlaps.
order: 40
status: published
tags:
  - guides
redirectFrom:
  - /guides/segments-and-rules
---

# Device groups and rules

A **device group** is a named set of devices, such as `tvs`, `iot_untrusted` or `trusted`. On the
FortiGate it is an address group your policies can reference; in Pi-hole it is (optionally) a filtering
group. forti-pihole classifies every device it sees into exactly one group and keeps both sides in step.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The FortiGate objects

| Object | Name | Written by |
|---|---|---|
| Address group per device group | `fp-grp-<group>` | forti-pihole (comment `managed by forti-pihole: group <group>`) |
| MAC address object per device | `fp-dev-<label>-<last 6 hex digits of the MAC>` | forti-pihole (comment `managed by forti-pihole: <label> (<vendor family>)`) |
| Dynamic device-identification address (a rule) | `fp-rule-<group>-<label>` | you, in the FortiGate GUI; forti-pihole only reads it |

`fp-` is the configured `prefix`. Your own policies reference `fp-grp-*` groups like any other address
group. A device object's label comes from the device's hostname, else its vendor and family, else its
MAC; names are cut to FortiOS's 79-character limit and made unique.

When a single-MAC address object for the device already exists (yours, without the marker),
forti-pihole references it as the group member instead of creating a duplicate, as long as
`adopt_existing` is `true` (the default). It never modifies or deletes that object.

An existing address group named `fp-grp-<group>` **without** the marker is an administrator's object
with a clashing name: that group is left alone entirely, reported as `NOT MANAGED: name clash`, and its
devices go to the default group until you rename one of them.

## Which devices are classified

Devices are taken from the FortiGate's device inventory (its own fingerprinting: vendor, family, type,
OS) and DHCP leases, on the interfaces in `interfaces`, which default to every configured network's
interface. Servers, a DMZ and the WAN are never classified unless you list them.

## Precedence

For every device, the first of these that applies decides its group:

| # | Source | Set by | Notes |
|---|---|---|---|
| 1 | **protected** | `protected` in `config.json` | Never classified, moved or touched in any way |
| 2 | **assignment** | `assignments` in `config.json` | Explicit; may name a privileged group |
| 3 | **pin** | `forti-pihole assign`, `forti-pihole confirm`, or a move in the FortiGate GUI | Explicit; may name a privileged group |
| 4 | **rule** | `rules` in `config.json` and `fp-rule-*` objects | Presumptive: the highest priority wins |
| 5 | **default** | `default_group` | Unknown devices, and ambiguous matches |

`forti-pihole devices -v` shows the source and the reasons for each decision.

### Privileged groups

A group marked `"privileged": true` (trusted users, work machines) is only ever entered by an explicit
decision: an assignment, a pin or a confirmed reassociation. The configuration refuses a rule that
targets one, `fp-rule-*` objects naming one are ignored with a warning, and the default group can never
be privileged. A spoofed hostname or vendor string can therefore never put a device in a group that
grants trust.

### Rules

```json
{"name": "fire-tv", "group": "tvs", "priority": 100, "match": {"vendor": "Amazon", "family": "Fire TV*"}}
```

Every set field of `match` must match (AND). Strings compare case-insensitively and accept the globs `*`
and `?`; `mac_prefix` is an OUI or longer prefix (`5c:e9:31`). The fields are `vendor`, `family`,
`type`, `os`, `hostname` (inventory or DHCP), `vci` (DHCP vendor class) and `mac_prefix`.

The highest `priority` wins (default 100). When matches of the same top priority name different groups
the device is **ambiguous**: it goes to the default group and the report lists it until a priority or an
assignment decides.

### Rule objects made in the GUI

A dynamic address of sub-type **device-identification** named `fp-rule-<group>-<label>` is a rule: the
FortiGate resolves it to a set of MACs, and forti-pihole puts those devices in `<group>` with priority
`native_rule_priority` (default 50, below the config rules' default of 100). Group names never contain
`-`, so the first `-` after `fp-rule-` ends the group name. Objects with that prefix of another type, or
naming an unknown or privileged group, are ignored with a warning.

### Pins and GUI moves

`forti-pihole assign MAC GROUP` pins a device; `forti-pihole assign MAC auto` removes the pin so rules
decide again. Pins take effect at the next sync.

The FortiGate GUI is a first-class way to decide too. forti-pihole remembers what it wrote, so it can
tell your changes from its own:

- **Moved to another `fp-grp-*` group** (any member that covers the device): pinned to that group
  (source `gui`). With several such placements, the earliest group in `groups` wins.
- **Taken out of every group, object kept**: pinned to the default group.
- **Its `fp-dev-*` object deleted**: a GUI pin is dropped and classification is automatic again.
- **A managed object re-pointed at another MAC**: reported, never "fixed".

A plan forti-pihole made but has not applied yet (waiting for approval) counts as its own, so a
half-applied change is never mistaken for a GUI move.

### Overlaps

A device covered by members of several `fp-grp-*` groups is an **overlap**. The report lists it with the
group that wins and why. Until the extra placements are gone, your FortiGate policies match whichever
group's policy comes first. When forti-pihole places a device it removes the device's single-device
members (its MAC object, or a `/32` host object of its address) from the other groups; members that also
cover other devices (ranges, subnets, dynamic objects) are never removed on one device's behalf.

## What a sync changes

- Missing `fp-grp-*` groups and `fp-dev-*` objects are created with the marker.
- A device that changes group leaves the other groups and joins its own, unless a member there already
  covers it.
- Before applying, every online device's internet (TCP/443 to `1.1.1.1` out of a WAN interface) and DNS
  (UDP/53 to the DNS server its DHCP server hands out) reach is simulated against your policies, before
  and after. A device that would lose either keeps its current placement and is reported as blocked.
- At most `max_changes` devices (default 50, `sync --max-changes N`) change per run; the rest wait.
- A device not seen for `retire_after_days` (default 30), or replaced by a confirmed reassociation,
  loses its `fp-dev-*` object, unless something outside the `fp-grp-*` groups uses it. An adopted
  administrator object only loses forti-pihole's reference. Nothing is retired when the inventory comes
  back empty.
- A `fp-grp-*` group whose device group left the configuration is reported, never deleted.

Devices that come back with a new randomized MAC are covered in [Randomized MACs](/guides/reassociation).
