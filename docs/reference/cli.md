---
title: Command line
description: forti-vlan-mac's subcommands, options, exit statuses, environment and files.
order: 90
status: published
tags:
  - reference
---

# Command line

forti-vlan-mac is one executable with subcommands. `report`, `plan`, `status` and `history` never
write to the FortiGate; `apply` does; `init`, `assign` and `confirm` change only local files.

:::toc[On this page]{depth="2" theme="compact"}
:::

```text
forti-vlan-mac init
forti-vlan-mac report [-v]
forti-vlan-mac plan
forti-vlan-mac apply [--max-changes N]
forti-vlan-mac assign MAC SEGMENT
forti-vlan-mac assign MAC auto
forti-vlan-mac confirm ID [--reject]
forti-vlan-mac status
forti-vlan-mac history [--count N]
forti-vlan-mac --version
forti-vlan-mac --help
```

## Options

| Option | Meaning |
|---|---|
| `-p`, `--profile NAME` | The forti device profile to connect with. Default: the configuration's `profile`, else forti's default profile |
| `--config PATH` | The configuration file. Default `$FORTI_HOME/vlan-mac/config.json` |
| `--json` | Machine-readable output |
| `-q`, `--quiet` | Print only problems. The timer's service uses it |
| `-v`, `--verbose` | `report`: also offline devices, and the reason for every decision |
| `--version` | The version and what it was built from: `forti-vlan-mac 0.1.0 (engine forti-cli 468f9e1, forti-api 1.1.1)` |
| `-h`, `--help` | The usage |

## Subcommands

### init

Writes a starting configuration to `$FORTI_HOME/vlan-mac/config.json` (or `--config PATH`). It never
overwrites an existing file. [Configuration](/reference/configuration) describes every key.

### report

Classifies the inventory and shows each device's segment, the decision behind it (protected,
assignment, rule or default) and what would change. With `-v` it also lists offline devices and the
reason for every decision. Reassociation candidates appear here with their ids. Read-only.

### plan

Makes a forti engine plan for the pending changes and shows it with its id, summary and risk. Planning
reads the device and never writes to it; the plan is stored like any forti plan.

### apply

Plans the pending changes and applies them through the forti engine, as the device profile's mode
allows. The timer runs `forti-vlan-mac apply --quiet`.

| Option | Meaning |
|---|---|
| `--max-changes N` | At most `N` devices change in this run (1 to 1000); the rest wait for the next run. Default: `max_changes` in the configuration (50) |

| Profile mode | What `apply` does |
|---|---|
| `read-only` | Nothing is applied; the plan id is printed so you can look at the change |
| `guarded` | The plan waits for your approval: run `forti approve <plan_id>`. The next `apply`, by hand or from the timer, applies the approved plan first (within a day of planning) |
| `autonomous` | Applies at once |

A successful apply prints the forti rollback plan; `forti apply <rollback_id>` undoes the run.

### assign

```text
forti-vlan-mac assign MAC SEGMENT
forti-vlan-mac assign MAC auto
```

Pins a device to a segment, privileged segments included. A pin outranks every rule. `auto` drops
the pin, and rules classify the device again. It takes effect at the next `apply`. Moving the device's
object to another segment group in the GUI pins it the same way
([Segments and rules](/guides/segments-and-rules#which-segment-a-device-is-in)).

### confirm

```text
forti-vlan-mac confirm ID
forti-vlan-mac confirm ID --reject
```

Accepts a reassociation candidate (the id from `report`): the new MAC address takes over the old
device's segment, and the old entry is retired at the next `apply`. `--reject` keeps the two as
separate devices and never proposes the pair again ([Randomized MACs](/guides/reassociation)).

### status

Shows the configuration, the profile's mode, the last apply and a plan that is waiting for approval.

### history

Shows the last applies (default 20; `--count N` for more), from `$FORTI_HOME/vlan-mac/history.jsonl`:
time, status, plan id and summary.

## Exit status

| Status | Meaning |
|---|---|
| `0` | Success |
| `2` | Usage error: an unknown option, command or argument |
| `3` | Configuration error: a missing or invalid configuration file, or a missing profile |
| `7` | Nothing applied: the plan waits for approval (`guarded`) or the profile is `read-only` |
| others | The forti engine's statuses, as for `forti`: `4` connection or authentication, `5` not found, `6` validation or FortiOS error, `8` an apply that stopped part-way or whose outcome is unknown. The next run reads the FortiGate again and plans from what it finds |

## Environment and files

| Name | Meaning |
|---|---|
| `FORTI_HOME` | The forti home; default `~/.forti` |
| `$FORTI_HOME/vlan-mac/config.json` | The configuration |
| `$FORTI_HOME/vlan-mac/state.json` | What forti-vlan-mac has learned about each device between runs: pins, candidates, a pending plan |
| `$FORTI_HOME/vlan-mac/history.jsonl` | One JSON object per apply |

Device profiles, credentials, plans and the engine's audit log are the forti home's, as for `forti`
and forti-mcp.
