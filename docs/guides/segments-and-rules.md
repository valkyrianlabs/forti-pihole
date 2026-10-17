---
title: Segments and rules
description: The FortiOS objects forti-pihole keeps, the rule objects you create in the GUI, and the precedence that puts a device in a segment.
order: 30
status: published
tags:
  - guides
---

# Segments and rules

A **segment** is a named group of devices, such as `iot`, `guest` or `trusted`. forti-pihole keeps
every device the FortiGate has seen in exactly one segment, and keeps that membership in native FortiOS
objects that your policies can use.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The objects

| Object | FortiOS type | Name | Who writes it |
|---|---|---|---|
| Device | `firewall/address`, type MAC | `fp-dev-*` | forti-pihole |
| Segment | `firewall/addrgrp` | `fp-seg-<segment>` | forti-pihole |
| Rule | `firewall/address`, type dynamic, sub-type device identification | `fp-rule-<segment>-<label>` | You, in the GUI |

`fp-` is the default prefix (`prefix` in [Configuration](/reference/configuration)). Every device
and segment object forti-pihole writes carries the comment `managed by forti-pihole`; that marker,
together with the prefix, is what lets it change an object at all ([Safety](/guides/safety)).

- **Device objects** hold one device's MAC address. Each is a member of exactly one segment group.
- **Segment groups** are ordinary address groups. Reference them in policies like any other group.
- **Rule objects** are yours. forti-pihole reads them and never changes or deletes them.

## Rule objects from the GUI

FortiOS can describe devices by what it has identified about them: a dynamic address with the sub-type
**device identification** matches on hardware vendor, hardware model, operating system and software
version. forti-pihole uses such addresses as rules when their name follows the pattern:

```text
fp-rule-<segment>-<label>
```

- `<segment>` names the segment the rule assigns to; it must be one of your configured segments.
- `<label>` is free text that tells your rules apart, for example `fp-rule-iot-cameras`.

Create them in the FortiGate GUI (**Policy & Objects → Addresses**, a new dynamic address with the
device identification sub-type). You can also write rules in `config.json` (`rules`, matching on
`vendor`, `family`, `type`, `os`, `hostname`, `vci` and `mac_prefix`); both kinds take part in the same
precedence. A rule object whose `<segment>` is not configured, or is privileged, is ignored with a
warning.

## Which segment a device is in

For each device the FortiGate detected on a managed interface (`interfaces`), the first of these that
applies decides its segment:

:::steps

### Protected

A device listed in `protected` is never classified or moved by forti-pihole, whatever else says.

### A fixed assignment

An entry in `assignments` in `config.json` (MAC address to segment).

### A pin

An explicit decision of yours: `forti-pihole assign MAC SEGMENT`, a confirmed reassociation, or
moving the device's object to another `fp-seg-*` group in the GUI. The next run notices a placement
it did not write and keeps it. `forti-pihole assign MAC auto` hands the device back to the rules.

### A rule

A rule in `config.json` or a rule object from the GUI that matches the device. The highest priority
wins; GUI rule objects count at `native_rule_priority` (default 50), configuration rules at their own
`priority` (default 100).

### The default segment

`default_segment`, for unknown devices and ambiguous matches.

:::

### Privileged segments are never inferred

A segment marked `privileged` (for example the segment your policies let reach management interfaces)
is entered only through a fixed assignment or a pin. A configuration rule that targets a privileged
segment is refused when the configuration is loaded, and a GUI rule object that names one is ignored
with a warning. Being identified as a laptop of some vendor is not a reason to trust a device.

### Ambiguity goes to the default

When the highest-priority matching rules name different segments, the match is ambiguous and the
device goes to the default segment. `report -v` shows which rules matched, so you can tighten them or
assign the device yourself.

:::callout[Choose a cautious default]{variant="tip"}
Every new or ambiguous device lands in the default segment, so make it the one with the least access,
such as a segment that your policies allow only to reach the internet.
:::

### One device in two groups

If you put one device into two segment groups, the segment listed first in `segments` wins and the
overlap is reported. Your own members of a segment group (objects you added by hand) stay where you
put them.

## Devices that disappear

A device forti-pihole has not seen for `retire_after_days` (default 30) is retired: its managed
`fp-dev-*` object is removed, unless something outside the segment groups still uses it. Until then
a device that is briefly offline keeps its object and its segment. An empty inventory read (a failed or
partial read) never retires anything ([Safety](/guides/safety)).

A segment you remove from the configuration keeps its group on the FortiGate: it is reported, never
deleted, so a policy that references it keeps working until you change it.

Devices that come back with a new, randomized MAC address are handled separately:
[Randomized MACs](/guides/reassociation).
