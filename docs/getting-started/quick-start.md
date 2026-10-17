---
title: Quick start
description: A device profile, a first configuration, report and plan, one apply by hand, then the timer.
order: 20
status: published
tags:
  - getting-started
---

# Quick start

From an installed `forti-vlan-mac` to a FortiGate whose device inventory stays sorted into segments.
The first four steps write nothing to the device.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Before you start

- forti-vlan-mac and forti are installed ([Install](/getting-started/install)).
- The FortiGate has seen your devices: its device inventory (**Dashboard → Assets & Identities**, or
  the device list on older releases) shows them, with device detection enabled on the interfaces you
  care about.
- You can create a REST API administrator on the FortiGate.

:::callout[Scope the API account]{variant="tip"}
forti-vlan-mac needs to read the device inventory and DHCP data, and to write firewall addresses and
address groups. Give its API administrator an admin profile that allows exactly that, and restrict its
trusted hosts to the machine that runs the timer. The program refuses every other write itself
([Safety](/guides/safety)), but the FortiOS account is the boundary that holds even if a program
misbehaves.
:::

## Set it up

:::steps

### Create a device profile

```bash
forti configure --profile home
```

`forti configure` asks for the host, the API token and the profile's mode, and stores the token in the
forti home's secret store. `apply` writes through the forti engine, so the profile's mode applies to
it: `read-only` applies nothing, `guarded` waits for your `forti approve` of each plan, `autonomous`
applies at once ([Command line](/reference/cli#apply)). `report` and `plan` work in every mode.

### Write the configuration

Write a starting configuration, then describe your segments and rules in it:

```bash
forti-vlan-mac init        # writes ~/.forti/vlan-mac/config.json; never overwrites one
```

```json
{
  "profile": "home",
  "default_segment": "unsorted",
  "segments": [
    {"name": "trusted", "description": "Our laptops and phones", "privileged": true},
    {"name": "iot", "description": "Smart home devices"},
    {"name": "unsorted", "description": "Not classified yet"}
  ],
  "rules": [
    {"segment": "iot", "priority": 100, "match": {"vendor": "Espressif"}}
  ],
  "protected": [],
  "retire_after_days": 30
}
```

`trusted` is privileged: no rule can put a device there, only you can
([Segments and rules](/guides/segments-and-rules)). Every key is described in
[Configuration](/reference/configuration).

### Look at the inventory

```bash
forti-vlan-mac report
```

`report` reads the device inventory and DHCP data and shows each device with its segment and why
(protected, your assignment, which rule, or the default), and what would change. `report -v` adds
offline devices and the reasons for every decision. It writes nothing.

### See the changes

```bash
forti-vlan-mac plan
```

`plan` makes a forti engine plan of the changes the next `apply` would make: objects to create,
devices to move between segment groups. It writes nothing to the device either. Adjust rules until the
plan is what you expect.

### Apply once by hand

```bash
forti-vlan-mac apply --max-changes 50
```

The first run creates the `mvlan-seg-*` groups and the `mvlan-dev-*` objects. At most 50 devices change
per run (`--max-changes`, or `max_changes` in the configuration); the rest follow in later runs. With a
`guarded` profile, approve the plan with `forti approve <plan_id>`; the next `apply` applies it.

### Turn on the timer

```bash
systemctl --user enable --now forti-vlan-mac.timer
loginctl enable-linger "$USER"     # optional: keep running while you are logged out
```

The timer runs `forti-vlan-mac apply --quiet` every 15 minutes, as you, with your forti home. With a
`guarded` profile each run that finds changes waits for your approval, and the run after you approve
applies them.

:::

## Use the segments

Reference the `mvlan-seg-*` groups as sources or destinations in your own firewall policies, for
example a policy that lets `mvlan-seg-iot` reach the internet but not your LAN. forti-vlan-mac never
creates or changes policies: what a segment may do is your decision.

## Keep an eye on it

```bash
forti-vlan-mac status                   # the profile's mode, the last apply, a plan waiting for approval
forti-vlan-mac history                  # the last applies
journalctl --user -u forti-vlan-mac     # what the timer runs printed
```

To move a device, move its `mvlan-dev-*` object to another `mvlan-seg-*` group in the GUI, or run
`forti-vlan-mac assign MAC SEGMENT`. Both pin the device, which outranks every rule.

## Next

:::buttons{align="left" gap="md"}
::button[Segments and rules]{href="/guides/segments-and-rules" variant="primary"}
::button[Safety]{href="/guides/safety" variant="secondary"}
:::
