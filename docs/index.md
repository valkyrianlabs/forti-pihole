---
title: forti-pihole
description: Keep a FortiGate's device inventory classified into logical segments, in native FortiOS address objects and groups.
order: 0
status: published
tags:
  - overview
---

# forti-pihole

forti-pihole is a FortiGate companion that keeps your device inventory sorted into **logical
segments**, using FortiOS's own objects. It reads the FortiGate's device inventory and DHCP data
through the FortiOS REST API, classifies each device by MAC address with rules you write, and keeps a
MAC address object per device in the address group of its segment. Your firewall policies reference
those groups.

:::badges{align="left" gap="sm"}
::badge[Release]{
  type="github"
  target="release"
  repo="valkyrianlabs/forti-pihole"
  href="https://github.com/valkyrianlabs/forti-pihole/releases"
}
::badge[CI]{
  type="github"
  target="workflow"
  repo="valkyrianlabs/forti-pihole"
  workflow="ci.yml"
  href="https://github.com/valkyrianlabs/forti-pihole/actions/workflows/ci.yml"
}
::badge[License]{
  type="github"
  target="license"
  repo="valkyrianlabs/forti-pihole"
}
:::

```bash
forti configure                                   # a device profile in ~/.forti
forti-pihole report                             # the inventory, classified; writes nothing
forti-pihole plan                               # what apply would change; writes nothing
systemctl --user enable --now forti-pihole.timer   # keep it current every 15 minutes
```

It is **never in the traffic path**. It is a command-line program that a systemd user timer runs
periodically; there is no daemon and no listener, and nothing on the network depends on it running.

:::buttons{align="left" stack="mobile" gap="md"}
::button[Install]{href="/getting-started/install" variant="primary"}
::button[Quick start]{href="/getting-started/quick-start" variant="secondary"}
::button[GitHub]{href="https://github.com/valkyrianlabs/forti-pihole" variant="outline" newTab=true}
:::

## What it keeps on the FortiGate

| Object | Name | Who writes it |
|---|---|---|
| MAC address object, one per device | `fp-dev-*` | forti-pihole |
| Address group, one per segment | `fp-seg-<segment>` | forti-pihole |
| Dynamic device-identification address, read as a rule | `fp-rule-<segment>-<label>` | You, in the FortiGate GUI |

`fp-` is the default prefix. Every object forti-pihole writes carries the comment
`managed by forti-pihole`, and it never changes an object without that marker.
[Segments and rules](/guides/segments-and-rules) explains how a device ends up in a segment.

## What you get

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[Native objects]{eyebrow="FortiOS"}
Segments are ordinary address groups, so policies, logs and the GUI work with them as with any
other group. Nothing proprietary sits between your devices and the firewall.
:::

:::card[You stay in charge]{eyebrow="Precedence"}
Protected devices first, then your own assignments (a move in the GUI, or `forti-pihole assign`),
then rules, then the default segment. Privileged segments are never inferred from a rule.
:::

:::card[Look before it writes]{eyebrow="Workflow"}
`report` and `plan` change nothing. `apply` makes the planned changes through the forti engine, with
validation, verification, an audit record and a rollback plan, and `--max-changes` bounds a run.
:::

:::card[Fail-static]{eyebrow="Safety"}
If a run fails or the timer stops, the FortiGate keeps the objects it has. A failed read never
deletes anything.
:::

:::card[A narrow write surface]{eyebrow="Safety"}
Only prefixed address objects and groups that carry the ownership marker are ever written. Every
other write is refused in code before it is sent.
:::

:::card[Randomized MACs]{eyebrow="Devices"}
Phones and laptops that come back with a new private MAC are offered as candidates; you link them with
`forti-pihole confirm`.
:::

:::

## What it is not

:::callout[Not a network segmentation product]{variant="warning"}
- **Not VLAN tagging.** It does not create VLAN interfaces or move ports or devices between VLANs.
  A segment is an address group; what it means on the wire is decided by your policies.
- **No RADIUS, no 802.1X, no dynamic VLAN assignment.** It never configures switches,
  switch-controller or authentication.
- **No layer-2 isolation.** Devices in different segments on the same VLAN can still reach each other
  without passing through the FortiGate.
- **No DHCP changes.** Giving segments their own DHCP ranges is not yet available: it is under
  evaluation, and forti-pihole never writes DHCP settings today.
:::

## How it relates to forti-cli

forti-pihole compiles in the command engine of [forti-cli](https://github.com/valkyrianlabs/forti-cli),
the `forti` command-line tool, which is built on the
[forti-api](https://github.com/valkyrianlabs/forti-api) SDK. The engine owns device profiles,
credentials, validation, plans, modes and the audit log; forti-pihole decides which objects should
exist and hands the changes to the engine. It never runs the `forti` executable, but you use `forti
configure` to create the device profile it connects with, and both use the same forti home
(`~/.forti`).

## Where to go next

:::cards{
  columns="2"
  cardTheme="glass"
}

:::card[Install]{
  href="/getting-started/install"
  eyebrow="Getting started"
}
Install forti-pihole from the APT repository or Homebrew, or build it from source.
:::

:::card[Quick start]{
  href="/getting-started/quick-start"
  eyebrow="Getting started"
}
A profile, a first configuration, `report`, `plan`, one `apply` and the timer.
:::

:::card[Segments and rules]{
  href="/guides/segments-and-rules"
  eyebrow="Guide"
}
The objects, the rule objects you create in the GUI, and the precedence that decides a segment.
:::

:::card[Randomized MACs]{
  href="/guides/reassociation"
  eyebrow="Guide"
}
Why a device can come back as a stranger, and how `confirm` links it.
:::

:::card[Safety]{
  href="/guides/safety"
  eyebrow="Guide"
}
Fail-static operation, the write allowlist, the ownership marker and what is never touched.
:::

:::card[Command line]{
  href="/reference/cli"
  eyebrow="Reference"
}
Every subcommand and option.
:::

:::card[Configuration]{
  href="/reference/configuration"
  eyebrow="Reference"
}
`config.json`: segments, rules, protected devices and retirement.
:::

:::card[Testing]{
  href="/development/testing"
  eyebrow="Development"
}
Building, the test suites, CI and the live-device rule.
:::

:::
