---
title: Command line
description: Every forti-pihole command, option and exit status, the environment and the files it uses.
order: 100
status: published
tags:
  - reference
---

# Command line

```text
forti-pihole <command> [options]
```

forti-pihole is one executable with subcommands. Options may appear anywhere on the line. Commands that
inspect never write anything; commands that change something say so below.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Options

| Option | Meaning |
|---|---|
| `-p, --profile NAME` | The forti profile (default: the configuration's `profile`, else forti's default profile) |
| `--config PATH` | The configuration file (default `$FORTI_HOME/pihole/config.json`) |
| `--json` | Machine-readable output |
| `-q, --quiet` | `sync` prints nothing when everything applied; problems still go to standard error |
| `-v, --verbose` | Offline devices and the reasons for every decision (`devices`, `plan`, `sync`, `discover`) |
| `--version` | `forti-pihole <version> (engine forti-cli <revision>, forti-api <version>)` |
| `-h, --help` | The command summary |

Command-specific options are listed with each command. A value-taking option without its value, a
number outside its range, or an unknown option exits `2`.

## Getting started

### setup

```text
forti-pihole setup [--pihole-url URL] [--password-stdin]
```

Connects to the FortiGate and Pi-hole, discovers networks and groups, and writes a starting
configuration. When `config.json` does not exist it is created first (as `init` does). Then:

- the FortiGate's model, hostname, FortiOS version, and the profile and its mode are shown;
- `--pihole-url URL` sets `pihole.url`;
- with a Pi-hole URL, setup logs in with the stored app password. When there is none (or it is bound to
  another host), it asks for one (input hidden at a terminal; `--password-stdin` reads one line from
  standard input), verifies it, and stores it as `pihole/<name>/password` in forti's secret store;
- every LAN-side interface with an address is listed with a suggested strategy; interfaces with a DHCP
  server that the configuration does not list are added in `observe` mode;
- device groups without a `pihole_group` get an unambiguous case-insensitive match of the Pi-hole group
  names, when there is one.

Writes only `config.json` and the secret store entry; nothing on the FortiGate or Pi-hole. An empty
password exits `2`; a Pi-hole that cannot be reached, refuses the password or runs an FTL older than
6.7.0 exits `4`.

### init

```text
forti-pihole init
```

Writes the starting configuration (`packaging/config.example.json`, also installed to
`share/forti-pihole/`) to the configuration path, `0600`. Refuses (exit `3`) when the file exists.

### discover

```text
forti-pihole discover [--json]
```

Networks, groups and Pi-hole at a glance: the `networks` table followed by the full plan. Read-only.
`--json` prints `{"networks": [...], "sync": {...}}`.

## Inspecting (read-only)

### devices

```text
forti-pihole devices [-v] [--json]
```

The inventory, classified: groups with device counts, every online device with its group, source
(`protected`, `assignment`, `pin`, `rule`, `default`, `ambiguous`) and fingerprint, overlaps, ambiguous
devices, reassociation candidates (with their `confirm` commands) and warnings. `-v` adds offline devices
and the reasons for each decision. `report` is an alias.

### groups

```text
forti-pihole groups [--json]
```

Each device group, its address group (`fp-grp-<group>`), its member count, its Pi-hole group (and its id
in `--json`), and whether it is privileged. A mapped Pi-hole group that does not exist is marked
`[missing in Pi-hole]`.

### networks

```text
forti-pihole networks [--json]
```

Every non-WAN interface with an address: subnet, VLAN id (or interface type), configured mode
(`unconfigured` when no network lists it), DHCP pools and device count.

### slices

```text
forti-pihole slices [--propose] [--json]
```

For each `slices` and `hybrid` network: its slices (`configured`, or `proposed` by the allocation
planner), utilization, conflicts, and groups short of addresses with the options for them.
`--propose` includes every network, so you can see what the planner would carve out of any of them.
Nothing is written. See [Address slicing](/guides/address-slicing).

### plan

```text
forti-pihole plan [-v] [--json]
```

Everything `sync` would do: the device report, pending FortiGate changes (creates, moves, retirements,
devices blocked by the connectivity check, devices deferred by `max_changes`), Pi-hole client entry
changes and notes, address-slice actions, and migrations (refused ones with their reasons and what
would make them possible). Writes nothing, not even `state.json`.

`--json` has the keys `taken_at`, `groups`, `devices`, `overlaps`, `candidates`, `warnings`, `pending`
(`changes`, `operations`, `blocked`, `deferred`, `notes`), `status`, `pihole` (`desired`, `changes`,
`findings`, `error`), `slicing` (`actions`, `findings`), `migrations`, `stages` and `operations`.

### references

```text
forti-pihole references IP [--json]
```

Everything on the FortiGate that refers to an IPv4 address: host objects, ranges and subnets that contain
it, VIPs that map it, reservations and leases, each with the policies that reach it (directly or through
nested groups, as source or destination, and whether they are enabled). Prints
`nothing refers to IP` when nothing does.

### status

```text
forti-pihole status [--json]
```

The configuration path and whether it is enabled or paused, the profile and its mode, the Pi-hole URL,
the last sync, a plan waiting for approval, counts of known devices, pins, adoptions and reassociation
candidates, and open operations. Exits `0` even when the FortiGate cannot be reached (`device_error` in
`--json`).

### history

```text
forti-pihole history [--count N] [--json]
```

The last `N` (default 20, `1`-`10000`) write stages from `history.jsonl`: time, stage (`objects`,
`pihole`, `reservations`, `migrations`), status, plan id and summary. `--json` includes rollback plans
and operation ids.

## Changing

### sync

```text
forti-pihole sync [--prune] [--max-changes N] [--max-migrations N] [--no-migrations] [-q] [-v] [--json]
```

Plans, then applies, in stages: FortiGate objects (a plan waiting for approval from an earlier run goes
first), Pi-hole client entries, reservations at addresses devices already hold, open migrations, new
migrations. Needs `"enabled": true` (else it plans, writes nothing to the FortiGate or Pi-hole, and
exits `7`); while paused it plans, writes nothing to them and exits `0`. It records what it observed in
`state.json` either way. `apply` is an alias.

| Option | Meaning |
|---|---|
| `--prune` | Also delete managed Pi-hole entries that no configured network implies any more |
| `--max-changes N` | At most `N` devices change group, and at most `N` reservations are added, this run (`1`-`1000`; default the configuration's `max_changes`) |
| `--max-migrations N` | At most `N` new migrations start (`0`-`50`, default `1`), on networks with `manage_reservations` |
| `--no-migrations` | Neither resume open migrations nor start new ones |

Stages that wait for a person or fail are also printed to standard error, as is a Pi-hole connection
error. A Pi-hole that cannot be reached skips the Pi-hole stage without failing the FortiGate stages.

### pause, resume

```text
forti-pihole pause
forti-pihole resume
```

Sets or clears the pause flag in `daemon-state.json`. While paused, `sync` and `forti-piholed` write
nothing and `migrate` refuses. Takes effect at once, also for a running `forti-piholed`.

### assign

```text
forti-pihole assign MAC GROUP|auto
```

Pins a device to a group, a privileged one included; `auto` removes the pin so rules decide again.
Changes only `state.json`; takes effect at the next sync. `GROUP` must be listed in the configuration.

### confirm

```text
forti-pihole confirm ID [--reject]
```

Accepts a reassociation candidate (from `devices`): the new MAC is pinned to the old device's group, the
old device's adoptions carry over, and the old entry is retired at the next sync. `--reject` records that
they are different devices; the pair is never proposed again. See
[Randomized MACs](/guides/reassociation).

### adopt

```text
forti-pihole adopt MAC [--object NAME]... [--reservation]
forti-pihole adopt MAC --clear
```

Lets a migration of this device change administrator objects: each `--object NAME` (a host address
object that follows the device to its new address), and with `--reservation` its own administrator DHCP
reservation. Repeat `adopt` to add more; `--clear` forgets them all. Changes only `state.json`. See
[Migrations](/guides/migrations#adopting-administrator-objects).

### migrate

```text
forti-pihole migrate MAC [--dry-run] [--json]
```

Moves one device into its group's slice now, as a journaled operation, regardless of the network's
`manage_reservations`. `--dry-run` prints the steps (with `--json`, the operation) and writes nothing.
Running it needs `"enabled": true` and sync not paused (else exit `3`).

| Exit | Meaning |
|---|---|
| `0` | Done; a dry run; or the device only needs a reservation, or none (`reserve` / `in-place` is printed) |
| `2` | No move is planned for that MAC (not on a slice network, no slice for its group, or already moving) |
| `7` | Refused (the reason and what it needs are printed), or waiting for the device or an approval |
| `8` | Failed |

### operations

```text
forti-pihole operations [--json]
forti-pihole operations show ID [--json]
forti-pihole operations resume ID
forti-pihole operations rollback ID
```

Lists every migration (newest first), shows one with its steps, errors and log, resumes it from the
first step not done, or compensates its completed steps in reverse order. `resume` and `rollback` need
`"enabled": true`. Exit: `0` done or rolled back, `7` waiting, `8` failed or rollback failed.

### events

```text
forti-pihole events plan|install|remove --url http://HOST:PORT
```

The FortiGate automation stitch that notifies `forti-piholed` of config changes. `plan` prints the
engine operations (the token as a placeholder); `install` generates the webhook token (stored as
`pihole/<profile>/webhook-token`, bound to the FortiGate) when there is none, and creates
`fp-sync-event`, `fp-sync-webhook` and `fp-sync`; `remove` deletes them. `--url` is required for every
verb and must start with `http://` or `https://`; without a port, `8735`. Writes to the FortiGate whether
or not the configuration is enabled. Exit: `0` done, `7` waiting for approval, `6` failed. See
[Runtime](/guides/runtime#notifying-the-service-the-automation-stitch).

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success, including a paused `sync` |
| `1` | Internal error, including a write refused by the guard transport (a bug: nothing was sent) |
| `2` | Usage: unknown command or option, bad argument, a MAC that is not one, an unknown group |
| `3` | Configuration or state: no or invalid `config.json`, no forti profile, a corrupt `state.json`, another run holding the lock, `init` over an existing file, not enabled or paused (`migrate`, `operations`) |
| `4` | Connection or authentication: the FortiGate, or Pi-hole where a command needs it (`setup`, `migrate`, `operations`) |
| `5` | The FortiGate has no such object or resource |
| `6` | A device or API error; a failed `sync` stage |
| `7` | A decision is needed: waiting for `forti approve`, a read-only profile, a stale plan, a `sync` while not enabled, a refused or waiting migration |
| `8` | Partial or unknown outcome; a failed migration |

Reading the FortiGate fails before anything is written: the message ends with `nothing was changed`.

## Environment

| Variable | Meaning |
|---|---|
| `FORTI_HOME` | The forti home (default `~/.forti`); forti-pihole's files are in `$FORTI_HOME/pihole` |
| `FORTI_SECRET_STORE` | `file` or `keychain`: the engine's secret store (default: the Keychain on macOS, the file store elsewhere) |

## Files

| Path | What |
|---|---|
| `$FORTI_HOME/pihole/config.json` | The configuration ([Configuration](/reference/configuration)) |
| `$FORTI_HOME/pihole/state.json` | Devices seen, pins, adoptions, candidates, a pending plan |
| `$FORTI_HOME/pihole/history.jsonl` | One line per write stage |
| `$FORTI_HOME/pihole/operations/<id>.json` | Migration journals |
| `$FORTI_HOME/pihole/lock` | The run lock |
| `$FORTI_HOME/pihole/daemon.json`, `daemon-state.json`, `events.jsonl` | `forti-piholed` ([Runtime](/guides/runtime)) |
