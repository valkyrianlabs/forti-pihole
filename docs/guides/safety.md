---
title: Safety
description: The full safety model: fail-static operation, enabled and pause, the two-layer write allowlist and its permits, ownership and adoption, migrations, Pi-hole ownership, limits and secrets.
order: 90
status: published
tags:
  - guides
---

# Safety

forti-pihole changes a firewall and a DNS filter unattended, so it is built to do as little as possible,
only what it can prove is its own, and nothing at all when in doubt.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Fail-static

Nothing on the network depends on forti-pihole running. It is never in the traffic path: the FortiGate
routes and serves DHCP, and Pi-hole filters, with whatever configuration they have. A failed, skipped or
stopped run leaves both as they are. No object is removed because a read failed, a device was briefly
absent or the inventory came back empty.

## Nothing is written until you say so

| Control | Effect |
|---|---|
| `"enabled": false` (the default after install) | `sync` plans and reports, writes nothing to the FortiGate or Pi-hole, and exits `7`; `migrate`, `operations resume` and `rollback` refuse; `forti-piholed` runs do nothing |
| `forti-pihole pause` | `sync` plans and reports, writes nothing to the FortiGate or Pi-hole, and exits `0`; `migrate` refuses; `forti-piholed` postpones its runs until `resume` |
| `"manage_reservations": false` (the default, per network) | No reservation is added and no migration starts on its own on that network; the plan still shows them |
| A `read-only` forti profile | Every FortiGate apply is refused by the engine (`policy_denied`) |

The inspecting commands (`discover`, `devices`, `groups`, `networks`, `slices`, `plan`, `references`,
`status`, `history`, `operations`, `operations show`) never write anything, not even forti-pihole's own
state. `sync` records what it observed in `state.json` even when it writes nothing else. `assign`,
`adopt` and `confirm` change only `state.json`; `setup` only `config.json` and the
Pi-hole password in forti's secret store.

Two commands write to the FortiGate without `"enabled": true`, because you run them explicitly for that
purpose: `events install` and `events remove` (the automation stitch, nothing else).

## The forti profile mode still applies

Every FortiGate write is a plan and an apply through the forti engine, the same engine as the `forti`
CLI: validated against the schema and the device, verified after the apply, recorded in forti's audit
log with a rollback plan, and subject to the profile's mode. A `guarded` profile waits for
`forti approve <plan id>`; forti-pihole never approves anything itself.

## The write allowlist

What forti-pihole may write on the FortiGate is enforced twice:

1. **Before planning**, every operation is checked against the allowlist (`check_operations`).
2. **Under the engine**, a guard transport refuses every `POST`, `PUT` or `DELETE` that is not on the
   allowlist **before it is sent**. A bug in the planner, or a change in what the engine sends, still
   cannot reach anything else. A guard refusal is an internal error (exit `1`, `nothing was sent`).

| May write | Only when |
|---|---|
| `firewall/address` and `firewall/addrgrp` objects named `fp-*` | Created with the ownership marker; updated or deleted only when the live object carries it; never renamed, never with the marker removed |
| Single DHCP reservation entries (`system.dhcp/server/<id>/reserved-address/<entry>`) | Granted for one apply (a reservation stage or a migration step), on that server only. New entries carry the marker in their description; updates and deletes only of the permitted entries (managed, or adopted); never the whole list; never a MAC change |
| Adopted administrator host objects | Only those you adopted for that device, only their `subnet`, only inside that device's migration |
| `monitor/system/dhcp/revoke` | Only the listed addresses: the moving device's old lease (or its new one, in a rollback) |
| `system/automation-trigger`, `-action`, `-stitch` named `fp-*` | Only inside `forti-pihole events install` and `remove`; created with the marker in the description; create and delete only |

Every permit is granted for one apply and withdrawn right after. forti-pihole never writes interfaces,
VLANs, firewall policies, VIPs, routing, DHCP server settings or pools, admin or API-user accounts,
system settings, users, switch-controller or 802.1X.

## Administrator objects

An object without the marker `managed by forti-pihole` is an administrator's, including one whose name
starts with `fp-`, such as your `fp-rule-*` rule objects. It is never modified or deleted:

- an existing single-MAC address object for a device is **referenced** as its group member
  (`adopt_existing`), never edited;
- an `fp-grp-<group>` address group without the marker makes that group unmanaged;
- an administrator's DHCP reservation or host object changes only after you run
  `forti-pihole adopt MAC --reservation` or `forti-pihole adopt MAC --object NAME`, and then only in
  that device's migration.

## Migrations

An address move is a journaled operation with a verified end ([Migrations](/guides/migrations)):

- **Refused** when the target address is in use, a VIP maps the old address, the device's reservation is
  an administrator's and not adopted, or a host object on the old address is a policy source and not
  adopted.
- **Ordered** so the old address never keeps privileges: Pi-hole entry, reservation, adopted objects
  updated **before** the old lease is revoked, then observe and verify.
- **Patient**: only the device's own old lease is revoked, once. A device that does not renew leaves
  the operation waiting; nothing is revoked again.
- **Verified**: the lease and the inventory show the new address, internet and DNS reach through the
  firewall are unchanged, and Pi-hole resolves the new address to the intended group.
- **Resumable and reversible**: `operations resume` and `operations rollback`. A failed operation waits
  for a person.

## Limits on every run

- At most `max_changes` devices (default 50) change group per run; the rest wait for the next one. The
  same budget bounds the reservations a sync adds.
- At most `--max-migrations` (default 1) new migrations start per run, one open migration per device.
- Retirement waits `retire_after_days` (default 30) and never happens on an empty inventory.
- **No device loses its route**: every online device's internet and DNS reach is simulated against the
  policies before and after a change; a device that would lose either keeps its current placement.
- One run at a time: a lock file serializes the timer, the service and manual runs.

## Classification

- Protected devices are never classified or moved.
- Privileged groups are only entered by explicit decisions: no rule, `fp-rule-*` object or reassociation
  guess can put a device there.
- Equal-priority rules that disagree send the device to the default group, which can never be privileged.
- A device that reappears with a new MAC is only linked after `forti-pihole confirm`.

## Pi-hole

- Only client entries whose comment carries `managed by forti-pihole` are created, updated or deleted;
  an update or delete first re-reads the entry and refuses without the marker.
- Your entries are read and reported, never changed: an exact-IP entry inside a managed range shadows
  it; a MAC entry never matches clients routed through the FortiGate.
- Groups are mapped by name; a sync never creates, renames, disables or deletes a group, and no request
  touching adlists or domains exists in the client.
- Every request is checked against an allowlist before it is sent. TLS verification is always on; plain
  HTTP only to a loopback Pi-hole; redirects are never followed.

## Secrets

The FortiGate API key, the Pi-hole app password and the webhook token live in forti's secret store
(the macOS Keychain, or a `0600` file store), each bound to its host and port. They never appear in
arguments, configuration files, state, history, the event log, output or error messages, and core dumps
are disabled. Device data (hostnames, comments, vendor strings, event fields) is untrusted: it is
sanitized before it is written into object comments or logs.

## What it is not

forti-pihole is not VLAN tagging, RADIUS or 802.1X, and not Layer-2 isolation. Groups on one network
share its broadcast domain whatever their slice, and a slice is not a routed subnet. Isolation is the job
of your FortiGate policies (with the `fp-grp-*` groups) and of real VLANs.

## Stopping it

```bash
forti-pihole pause                                   # stop all writes now
systemctl --user disable --now forti-pihole.timer    # or forti-piholed.service
forti-pihole events remove --url http://HOST:PORT    # remove the automation stitch
```

The FortiGate keeps the objects, reservations and groups it has, and Pi-hole keeps its entries. To undo a
FortiGate change, apply its rollback plan with `forti apply <rollback plan>` (the `sync` output and
`forti-pihole history --json` name it); to undo a migration, `forti-pihole operations rollback ID`.
