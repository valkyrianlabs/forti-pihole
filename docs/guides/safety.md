---
title: Safety
description: Fail-static operation, the write allowlist and ownership marker, the connectivity check, and everything forti-pihole never touches.
order: 50
status: published
tags:
  - guides
---

# Safety

forti-pihole changes a firewall unattended, every 15 minutes, so it is built to do as little as
possible and to do nothing when in doubt. This page covers what it may write, what it never touches,
and what happens when something goes wrong.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Fail-static

**Nothing on the network depends on forti-pihole running.** It is not in the traffic path: the
FortiGate enforces your policies with the address objects and groups it holds, whether or not the
program ever runs again.

- A failed run, a stopped timer or an uninstalled package leaves every object as it is. Devices stay in
  the segments they were in; new devices simply are not sorted until the next successful run.
- An empty inventory (a failed or partial read) never leads to anything destructive. A device is
  retired only after it has gone unseen for `retire_after_days`.
- At most `max_changes` devices (default 50, `apply --max-changes N`) change in one run; the rest wait
  for the next one. A surprise, such as a wrong rule or an inventory that suddenly looks different,
  cannot rewrite every segment in one go.
- A segment group whose segment left the configuration is reported, never deleted.

## The write allowlist

forti-pihole may create, update or delete exactly two kinds of object:

| Resource | Only when |
|---|---|
| `firewall/address` | the name starts with the prefix (default `fp-`) **and** the object carries the comment `managed by forti-pihole` |
| `firewall/addrgrp` | the name starts with the prefix **and** the object carries the comment `managed by forti-pihole` |

The allowlist is enforced twice. Before planning, every operation is checked: create, update or
delete on these two collections only, prefixed names, updates and deletes only of objects that carry
the marker, and every created object carries it. Then every request to the FortiGate passes through a
**guard transport** underneath the forti engine, which refuses any write that is not to one of these
two collections with a prefixed name before it is sent. A bug in the classification or the planner, or
a change in what the engine sends, can at worst produce a wrong change to a `fp-` object; it cannot
reach anything else.

### The ownership marker

forti-pihole writes a comment starting with `managed by forti-pihole` on every object it creates
(followed by the device's label or the segment's name), and changes or deletes only objects that carry
it. Names alone are not trusted. An object without the marker is yours, even if its name starts with
the prefix:

- It is never modified or deleted. Your `fp-rule-*` rule objects are read, never written.
- It may be *referenced*: with `adopt_existing` (the default), your address object for a single
  device's MAC becomes that device's member of its segment group, unchanged.
- Members you add to a segment group by hand stay in it.

Do not copy the marker into objects you want to keep to yourself: forti-pihole treats any object with
the prefix and the marker as its own.

## What it never touches

| Never written | Including |
|---|---|
| Interfaces and VLANs | VLAN creation, interface settings, device detection settings |
| Firewall policies | Policies, policy order, schedules, services |
| Routing | Static routes, SD-WAN, dynamic routing |
| DHCP | Servers, ranges, reservations. Assigning segments their own DHCP ranges is **not yet available: under evaluation** |
| Accounts | Administrators, API users, local users and groups |
| Switching and access control | switch-controller, FortiSwitch ports, 802.1X, RADIUS |
| System settings | Anything under `system/` |

It reads the device inventory, DHCP data, interfaces, firewall policies and address objects and groups
(the policies for the [connectivity check](#the-connectivity-check)); it writes only the two collections
above.

## The connectivity check

Moving a device between segment groups changes which of your policies match its traffic. Before a run
moves anything, forti-pihole checks that **no device loses its route**. For every online managed
device it simulates FortiOS's first-match policy lookup for two probes, with the groups as they are and
as they would be:

| Probe | Traffic |
|---|---|
| internet | TCP 443 to `1.1.1.1`, out of an interface with the WAN role |
| dns | UDP 53 to the DNS server the device's DHCP server hands out (skipped when that is the FortiGate itself, which local-in policy governs) |

A change that would turn a device's accept into a deny, or into no match, is refused for that device:
it keeps its current placement and is reported as blocked. The simulation ignores schedules, and treats
policies it cannot evaluate offline (users and groups, internet services, FQDN or tag addresses) as not
matching. These blind spots are the same before and after, so a change that matters still shows; the
check is a guard against cutting devices off, not a full policy verdict.

Writes then go through the forti engine's apply, which re-checks the device, verifies each change by
reading it back and records it in the audit log with a rollback plan. When the FortiGate cannot be
reached or a read fails, the run writes nothing and the next timer run tries again.

## The FortiOS account is the boundary

The API account in the device profile is what the FortiGate actually enforces. Give it an admin
profile that allows writing firewall addresses and address groups and reading the rest it needs, and
nothing more, and restrict its trusted hosts to the machine that runs the timer. The allowlist above
holds for forti-pihole; the account's permissions hold for anything that has its token.

:::callout[Recovery]{variant="info"}
Because forti-pihole writes only its own address objects and groups, undoing it is ordinary object
work: disable the timer, then delete the `fp-dev-*` objects and `fp-seg-*` groups (after removing
them from your policies). Your policies, interfaces and rule objects were never changed.
:::
