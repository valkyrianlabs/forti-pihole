---
title: Configuration
description: Every key of $FORTI_HOME/vlan-mac/config.json, with an example.
order: 95
status: published
tags:
  - reference
---

# Configuration

forti-vlan-mac reads one JSON file, `$FORTI_HOME/vlan-mac/config.json` (by default
`~/.forti/vlan-mac/config.json`), or the file `--config PATH` names. `forti-vlan-mac init` writes a
starting one, and the package installs an example at `/usr/share/forti-vlan-mac/config.example.json`.
Device profiles and credentials are not in this file: they are the forti home's, managed with
`forti configure`.

The configuration holds classification policy only. Which segment a device is in lives on the
FortiGate, in the segment groups, so the GUI stays the source of truth. Unknown keys are refused, and
an invalid file names the offending key.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Example

```json
{
  "profile": "home",
  "prefix": "mvlan-",
  "interfaces": ["internal"],
  "default_segment": "default",
  "segments": [
    {"name": "trusted", "description": "Our laptops and phones", "privileged": true},
    {"name": "tvs", "description": "TVs and streaming sticks"},
    {"name": "iot", "description": "Commodity IoT (plugs, bulbs)"},
    {"name": "default", "description": "Everything not yet classified"}
  ],
  "rules": [
    {"name": "kasa-plugs", "segment": "iot", "priority": 200, "match": {"vendor": "TP-Link"}},
    {"name": "fire-tv", "segment": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}},
    {"name": "smart-tvs", "segment": "tvs", "match": {"type": "Television"}}
  ],
  "protected": [],
  "assignments": {},
  "retire_after_days": 30,
  "adopt_existing": true,
  "max_changes": 50
}
```

## Connection

| Key | Default | Meaning |
|---|---|---|
| `profile` | the forti home's default profile | The forti device profile to connect with. `--profile` overrides it |
| `vdom` | the profile's VDOM | The VDOM whose inventory and objects are managed |

## Objects

| Key | Default | Meaning |
|---|---|---|
| `prefix` | `mvlan-` | The name prefix of every managed object: device objects `<prefix>dev-*`, segment groups `<prefix>seg-<segment>`, rule objects `<prefix>rule-<segment>-<label>` |
| `adopt_existing` | `true` | When you already have an address object for exactly one device's MAC, use it as the device's member of its segment group instead of creating a `<prefix>dev-*` object. Your object is referenced, never modified ([Safety](/guides/safety#the-ownership-marker)) |

## Devices

| Key | Default | Meaning |
|---|---|---|
| `interfaces` | `["internal"]` | Only devices the FortiGate detected on these interfaces are managed |
| `protected` | `[]` | MAC addresses forti-vlan-mac never classifies or moves |
| `assignments` | `{}` | Fixed assignments, MAC address to segment, for example `{"00:11:22:33:44:55": "trusted"}`. They outrank `forti-vlan-mac assign`, GUI moves and rules |
| `retire_after_days` | `30` | How long a device may go unseen before its managed object is retired (1 to 3650) |
| `max_changes` | `50` | At most this many devices change per `apply`; the rest wait for the next run (1 to 1000). `apply --max-changes` overrides it |

## Segments

`segments` lists every segment, **in priority order**: when you put one device into two segment
groups, the segment listed first wins, and the overlap is reported. Each segment becomes an address
group `<prefix>seg-<name>`.

| Key | Meaning |
|---|---|
| `name` | Lower-case letters, digits and `_`, at most 32 characters. Used in the group name and in rules |
| `description` | Free text, shown in reports |
| `privileged` | `true` for a segment that only an explicit decision may put a device into: an entry in `assignments`, `forti-vlan-mac assign`, a confirmed reassociation or a move in the GUI. A configuration rule that targets a privileged segment is refused; a GUI rule object that names one is ignored with a warning |
| `subnet` | Documentation only, such as `"192.168.30.0/24"`: the subnet you intend for the segment. It is not acted on (see [Not yet available](#not-yet-available)) |

`default_segment` (default `default`) names the segment for every device nothing else placed,
including every ambiguous match. It must be one of `segments`; give it little access.

## Rules

`rules` lists the rules written in this file. Rule objects you create in the GUI
(`<prefix>rule-<segment>-<label>`) take part as well, at priority `native_rule_priority` (default
`50`) ([Segments and rules](/guides/segments-and-rules#rule-objects-from-the-gui)).

| Key | Default | Meaning |
|---|---|---|
| `name` | `<segment>#<index>` | Shown in reports |
| `segment` | | The segment the rule assigns to. Never a privileged one |
| `priority` | `100` | The highest-priority matching rule wins. Matching rules for different segments at the same priority are ambiguous, and the device goes to `default_segment` |
| `match` | | What the device must look like (below). At least one field |

Every field given in `match` must match (AND). Text compares case-insensitively and accepts the
wildcards `*` and `?`; fields left out are not checked.

| `match` key | Compared with | Example |
|---|---|---|
| `vendor` | The hardware vendor the FortiGate identified | `"TP-Link"` |
| `family` | The hardware family | `"Fire TV*"` |
| `type` | The hardware type | `"Television"` |
| `os` | The operating system name | `"Fire OS"` |
| `hostname` | The host name from the inventory or DHCP | `"amazon-*"` |
| `vci` | The DHCP vendor class identifier | `"udhcp*"` |
| `mac_prefix` | The start of the MAC address, such as a manufacturer's prefix | `"5c:e9:31"` |

A `mac_prefix` never matches a randomized address ([Randomized MACs](/guides/reassociation)).
The full precedence between protected devices, assignments, rules and the default is in
[Which segment a device is in](/guides/segments-and-rules#which-segment-a-device-is-in).

## Not yet available

:::callout[DHCP subnet assignment]{variant="info"}
Giving each segment its own DHCP range or subnet is **not yet available: under evaluation**. A
segment's `subnet` only documents your intent; forti-vlan-mac never writes DHCP settings.
:::
