---
title: Migrations
description: How forti-pihole moves a device into its slice as a journaled, resumable operation, when it refuses, how to adopt administrator objects, and how to resume or roll back.
order: 60
status: published
tags:
  - guides
---

# Migrations

A **migration** moves one device to a new reserved address inside its group's slice. The FortiGate and
Pi-hole cannot change in one transaction, and a device renews its lease when it wants to, so a
migration is a sequence of steps, journaled before and after each one, that can be resumed after a crash
and rolled back. Success means the final verification passed, never merely that an API answered `200`.

:::toc[On this page]{depth="2" theme="compact"}
:::

## When a migration runs

- **`forti-pihole migrate MAC`** moves one device now. It needs `"enabled": true` and sync not paused.
  `--dry-run` shows the steps without writing (with `--json`, the whole operation).
- **`forti-pihole sync`** resumes open migrations, then starts at most `--max-migrations` new ones
  (default `1`, `0` to `50`), only on networks with `"manage_reservations": true`. `--no-migrations`
  skips both. `forti-piholed` runs the same sync.

A device has at most one open migration; while it has one, no other move is planned for it.

## When it is refused

A migration is planned only when all of these hold. Otherwise no operation is created, and the refusal
says what would make it possible (`plan` lists refusals too):

| Rule | Why |
|---|---|
| The target address is free: no lease, reservation, VIP, host object or static device | Two devices must never share an address |
| No VIP maps the old address | A port forward follows the address, not the device |
| The device's current reservation carries forti-pihole's marker, or you adopted it | Administrator objects are never changed implicitly |
| Every host object (`/32`, or a one-address range) on the old address that an enabled policy uses as a **source** is adopted | Otherwise that policy would keep granting the device's privileges to whoever gets the old address next |

Host objects used only as a destination, and ranges or subnets that contain the old address, do not
block a move. Host objects that do not follow the device and address ranges are listed as notes
(`<kind> <name> (...) still contains <old address> afterwards`): they keep covering the old address.

## Adopting administrator objects

```bash
forti-pihole adopt MAC --object NAME [--object NAME]...   # host objects that follow the device
forti-pihole adopt MAC --reservation                       # its own administrator reservation
forti-pihole adopt MAC --clear                             # forget this device's adoptions
```

An adoption is your explicit permission, recorded in `state.json`, for a migration of **that device**
to change exactly those objects. An adopted host object follows the device: only its `subnet` changes,
from the old address to the new one. An adopted reservation is updated in place (address, `reserved`
action and a description with the marker); its MAC never changes. Nothing is adopted implicitly, and
adoptions move with a confirmed reassociation and are forgotten when the device is retired.

`forti-pihole references IP` shows everything on the FortiGate that refers to an address, with the
policies that reach each object directly or through nested groups, as source or destination.

## The steps

| Step | What it does | Undone by rollback |
|---|---|---|
| `pihole` | Ensures the slice's managed CIDR entry exists and maps to the group's Pi-hole group (an operator entry for the same CIDR is left as it is) | The entry is deleted, only if this step created it |
| `reservation` | Creates the reservation, or updates the adopted or managed one: a single `reserved-address` entry, never the whole list | The engine's rollback plan restores it, and the new lease is revoked so the device renews |
| `objects` | Adopted host objects: old address → new address | The engine's rollback plan points them back |
| `revoke` | Revokes **only** the device's old lease (`monitor/system/dhcp/revoke` for that one address) | Nothing to undo |
| `observe` | Waits for the device to take the new address: polls the lease table every 5 s for up to 180 s | Nothing to undo |
| `verify` | Fresh reads: the lease and the inventory show the new address; internet and DNS reach through the firewall are what they were; Pi-hole resolves the new address to the intended group | Nothing to undo |

The order matters. The objects are updated **before** the old lease is revoked, so the old address never
stays privileged while it is free for someone else. There are no repeated revokes: once the old lease is
revoked, the device decides when it renews.

Every FortiGate write of a step runs under exactly the permits that step needs (that DHCP server, that
reservation entry, those adopted objects, that one address to revoke), and the guard transport refuses
anything else. With a `guarded` profile a step waits for `forti approve <plan id>`; the same plan is
retried on the next run.

## Example: a TV moves into its slice

`LivingRoom-TV` (`5c:e9:31:aa:bb:cc`) is classified into `tvs`. It holds the dynamic lease
`192.168.1.137`; the `tvs` slice on `internal` is `192.168.1.200/29`, mapped to Pi-hole's `TVs`. Years
ago you made a host object `tv-livingroom` for its address and used it in policy 12.

:::steps

### See what refers to the old address

```bash
forti-pihole references 192.168.1.137
```

```text
host         tv-livingroom  192.168.1.137 255.255.255.255
             policy 12 "TV to streaming" source
subnet       LAN  192.168.1.0 255.255.255.0
             policy 3 "LAN to WAN" source
lease        lease  5c:e9:31:aa:bb:cc
```

### Try a dry run

```bash
forti-pihole migrate 5c:e9:31:aa:bb:cc --dry-run
```

```text
forti-pihole: migration refused: 192.168.1.137 is privileged by address: the objects below would keep those privileges on 192.168.1.137 for whoever gets it next
  needs: forti-pihole adopt 5c:e9:31:aa:bb:cc --object "tv-livingroom"   (source of policy 12 "TV to streaming")
```

The exit status is `7`: a decision is needed, nothing went wrong.

### Adopt the object

```bash
forti-pihole adopt 5c:e9:31:aa:bb:cc --object tv-livingroom
forti-pihole migrate 5c:e9:31:aa:bb:cc --dry-run
```

```text
migration op-20261017-101500-3fa2c1: LivingRoom-TV 192.168.1.137 -> 192.168.1.200 (192.168.1.200/29)
  pihole: Pi-hole: 192.168.1.200/29 -> group "TVs"
  reservation: DHCP reservation for 5c:e9:31:aa:bb:cc: 192.168.1.200
  objects: address objects tv-livingroom: 192.168.1.137 -> 192.168.1.200
  revoke: revoke the lease on 192.168.1.137 (only this device's)
  observe: wait for LivingRoom-TV to take 192.168.1.200
  verify: verify lease, firewall reach and Pi-hole group
```

### Run it

```bash
forti-pihole migrate 5c:e9:31:aa:bb:cc
```

The operation is journaled to `$FORTI_HOME/pihole/operations/<id>.json` and run. When the TV renews
within three minutes, the output ends with `op-20261017-... done` and the exit status is `0`.

### Check the result

```bash
forti-pihole operations
forti-pihole operations show op-20261017-101500-3fa2c1
```

`show` lists every step with its status and error, and the operation's log (observations, retries,
decisions).

:::

## When the device does not renew

Revoking a lease on the FortiGate does not reach the device: it keeps using its old address until it
next talks to the DHCP server (a renewal, a reconnect, a reboot), and then it receives its new reserved
address. When that has not happened within 180 seconds, the `observe` step ends **waiting**:

```text
op-20261017-101500-3fa2c1 waiting
  observe: the device has not taken 192.168.1.200 (it has 192.168.1.137); reconnect its Wi-Fi or power-cycle it, then run forti-pihole operations resume
```

`migrate` exits `7`. Until the device renews, it still works at its old address, with what that address
grants now: adopted objects already point to the new one, and Pi-hole applies whatever covers the old
address (the Default group, in a pool). Then either:

- reconnect the device (Wi-Fi off and on, or a power cycle), and run
  `forti-pihole operations resume <id>`, or wait for the next sync, which resumes waiting operations
  and finds the new lease; or
- `forti-pihole operations rollback <id>` to put everything back.

No revoke is ever repeated: forti-pihole does not knock a device off the network to hurry it.

## Resume and rollback

```bash
forti-pihole operations                    # every operation, newest first
forti-pihole operations show ID
forti-pihole operations resume ID          # continue from the first step not done
forti-pihole operations rollback ID        # compensate completed steps in reverse order
```

Both `resume` and `rollback` need `"enabled": true`. A step found `running` (a crash) or `waiting` is
checked first: when its effect is already in place it is marked done instead of being repeated. A
FortiGate step is re-applied from its stored plan, which the engine refuses if it already ran or the
device changed meanwhile (`stale_plan`), so nothing is applied twice.

A **failed** operation (for example, `verify` found the device lost DNS reach) waits for a person: sync
never resumes it on its own. Read `operations show`, fix the cause, then `resume` (the failed step runs
again) or `rollback`.

Rollback compensates in reverse: adopted objects back to the old address; the reservation restored
from the engine's rollback plan and the new lease revoked, so the device renews; the Pi-hole entry the
operation created removed. A step whose compensation fails leaves the operation `rollback-failed` with
that step marked; `rollback` can be run again.

| Exit status | `migrate`, `operations resume`, `operations rollback` |
|---|---|
| `0` | `done` (or `rolled-back`); also a dry run, or a device that only needs a reservation |
| `2` | No move is planned for that MAC (`migrate`), or a usage error |
| `3` | The configuration is not enabled, or sync is paused (`migrate`) |
| `7` | Refused, or waiting (for the device, or for `forti approve`) |
| `8` | Failed, or rollback failed |
