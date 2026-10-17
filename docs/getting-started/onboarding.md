---
title: Onboarding
description: From a forti profile to a first sync: setup, reviewing networks and groups, slice proposals, the plan, enabling, and the optional service.
order: 20
status: published
tags:
  - getting-started
redirectFrom:
  - /getting-started/quick-start
---

# Onboarding

This guide takes an installed forti-pihole to a FortiGate and a Pi-hole that stay in step. Every step
before **Enable** is read-only on both systems: you can stop, change your mind and start again at any
point. Plan on reviewing the output of each step before moving on.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Before you start

- forti-pihole is [installed](/getting-started/install), and `forti` (forti-cli) is available for
  `forti configure`.
- Pi-hole v6 with FTL 6.7.0 or newer, reachable over HTTPS, and an **app password**
  (**Settings → Web interface / API → Configure app password**).
- The **Pi-hole groups** you want devices to land in already exist in Pi-hole, with their blocklists.
  forti-pihole maps device groups to Pi-hole groups by name; it never creates them during a sync.

:::steps

### Connect the FortiGate

```bash
forti configure
forti-pihole status
```

`forti configure` creates the device profile and stores its API key. `status` shows the profile and its
mode, and says `NOT enabled: plans only` until you enable the configuration. Prefer a `guarded` profile
while you onboard: every FortiGate change then waits for your `forti approve`.

### Run setup

```bash
forti-pihole setup --pihole-url https://pihole.example.net
```

`setup` writes a starting configuration to `$FORTI_HOME/pihole/config.json` when there is none (the
same one `forti-pihole init` writes), then:

- reads the FortiGate's identity, FortiOS version and the profile's mode;
- logs in to Pi-hole. When no password is stored yet, it asks for the app password (input hidden; or
  pipe it with `--password-stdin`), verifies it, and stores it in forti's secret store as
  `pihole/<name>/password`, bound to the Pi-hole's host and port;
- lists every LAN-side interface with an address and suggests a strategy: `subnet` for a VLAN,
  `slices` for a flat network with a DHCP server, `observe` otherwise. Interfaces with a DHCP server that
  the configuration does not list yet are added in `observe` mode;
- suggests a Pi-hole group for every device group without one: an unambiguous, case-insensitive match
  of the names (`tvs` → `TVs`). Suggestions are written to the configuration and marked `[suggested]`;
  names that do not exist in Pi-hole are marked `[missing in Pi-hole]`.

```text
FortiGate
  FortiGate 60F (fw01), FortiOS v7.4.8, profile fw01 in guarded mode

Pi-hole
  stored the password in forti's secret store (keychain) as pihole/default/password
  FTL v6.7.1 at https://pihole.example.net
  groups: Default, TVs, IoT
  client entries: 1

Networks
  internal       192.168.1.0/24     hard-switch  suggested: slices (a flat network with DHCP: slice it per group)

Group mappings
  trusted          -> (Default)
  work             -> (Default)
  tvs              -> TVs  [suggested]
  iot_trusted      -> (Default)
  iot_untrusted    -> IoT  [suggested]
  default          -> (Default)

updated /home/you/.forti/pihole/config.json
nothing was written to the FortiGate or Pi-hole. Review the networks (mode, slices) and groups, then:
  forti-pihole slices --propose   forti-pihole plan   and set "enabled": true when the plan looks right
```

Run `setup` again whenever you like: it keeps what you configured and only adds what is missing.

### Review networks and groups

```bash
forti-pihole networks
forti-pihole groups
forti-pihole devices -v
```

`networks` lists every non-WAN interface with its subnet, VLAN id, configured strategy, DHCP pools and
device count. `groups` shows each device group, its FortiGate address group (`fp-grp-<group>`), its
member count and its Pi-hole group. `devices -v` shows every device, the group it is classified into
and why.

Now edit `config.json`:

- **Networks**: give each network its `mode` and `group`. A VLAN whose whole subnet should get one
  filtering policy is `subnet`; a flat network is `slices`; a VLAN with a few groups carved out of it
  is `hybrid`. See [Allocation strategies](/guides/strategies).
- **Groups**: set `pihole_group` where the suggestion is wrong or missing. Mark the groups that grant
  trust (`trusted`, `work`) `"privileged": true`: no rule can ever put a device there.
- **Rules**: adjust the example rules (vendor, family, type, OS, hostname, DHCP vendor class, MAC
  prefix). See [Device groups and rules](/guides/device-groups-and-rules).
- **Pins**: put the devices you know into their group with `forti-pihole assign MAC GROUP`, or move them
  in the FortiGate GUI later. Devices that must never be touched go in `protected`.

### Propose slices

For `slices` and `hybrid` networks, let the allocation planner size and place a slice for every Pi-hole
mapped group with members there:

```bash
forti-pihole slices --propose
```

```text
internal  192.168.1.0/24  (slices)
  192.168.1.200/29   tvs              proposed
  192.168.1.208/28   iot_untrusted    proposed
  192.168.1.200/29   used 0/8
  192.168.1.208/28   used 0/16
```

Here the DHCP pool is `192.168.1.10-192.168.1.199`, three TVs need a `/29` and eight smart plugs a
`/28`. Nothing is written: copy the slices you accept into the network's `slices` in `config.json`.
Slices are placed outside the DHCP pools; when there is not enough room, the planner says how many
addresses are missing and lists options. See [Address slicing](/guides/address-slicing).

### Read the plan

```bash
forti-pihole plan
```

`plan` shows everything a sync would do, on both systems: device objects and group membership on the
FortiGate, Pi-hole client entries to create or update, notes about Pi-hole entries that shadow the
managed ones, address-slice actions, and migrations (with the reason when one would be refused). It
writes nothing, not even forti-pihole's own state. `plan --json` gives the same as JSON.

Iterate on the configuration until the plan is what you want.

### Enable and sync

Set `"enabled": true` in `config.json`, then:

```bash
forti-pihole sync
```

The FortiGate objects are planned and applied through the forti engine. With a `guarded` profile the
output says `waiting for approval: forti approve <plan id>` and exits `7`; approve it with
`forti approve <plan id>` and run `forti-pihole sync` again, which applies the approved plan. Pi-hole's
managed client entries are written in the same run.

The output ends with an `Applied` section: one line per stage, with `(rollback: forti apply <plan>)`
after every FortiGate apply; that command undoes it. `forti-pihole history` lists every write stage
later (`--json` includes the rollback plans).

### Turn on reservations, one network at a time

Until you set `"manage_reservations": true` on a slice network, forti-pihole only plans address
changes there. Before you do, move one device by hand and watch it end to end:

```bash
forti-pihole migrate 5c:e9:31:aa:bb:cc --dry-run
forti-pihole migrate 5c:e9:31:aa:bb:cc
```

[Migrations](/guides/migrations) walks through a complete move, including the administrator objects
you may need to `adopt` first. With `manage_reservations` on, every `sync` adds reservations for
devices already inside their slice and starts at most one new migration (`--max-migrations N`).

### Keep it running

Pick one:

- **The timer** (Linux): `systemctl --user enable --now forti-pihole.timer` runs a sync every 15 minutes.
- **The service**: `forti-piholed` runs a sync promptly after every FortiGate configuration change and
  a full one every 15 minutes. Configure `daemon.json`, start it
  (`systemctl --user enable --now forti-piholed.service`, or `brew services start forti-pihole`), then
  let the FortiGate notify it:

```bash
forti-pihole events install --url http://192.0.2.10:8735
```

See [Runtime](/guides/runtime). `forti-pihole pause` stops both from writing at any time;
`forti-pihole resume` lets them continue.

:::

## When something looks wrong

- Nothing changes: the configuration is not enabled, or sync is paused (`forti-pihole status`).
- A Pi-hole mapping does not take effect: an operator client entry for the same address or a narrower
  range decides instead. `plan` reports it as a note.
- A device keeps its old address: it has not renewed its lease yet. See
  [Troubleshooting](/reference/troubleshooting).
