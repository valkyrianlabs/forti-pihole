---
title: Configuration
description: Every key of config.json and daemon.json, with defaults and validation.
order: 110
status: published
tags:
  - reference
---

# Configuration

forti-pihole reads `$FORTI_HOME/pihole/config.json` (default `~/.forti/pihole/config.json`; `--config PATH`
for another), and `forti-piholed` also reads `$FORTI_HOME/pihole/daemon.json`. Both are JSON, validated
strictly: an unknown key, a wrong type or a value out of range is refused with the offending key named
(exit `3` for `forti-pihole`). A `$comment` key is allowed at the top level of each and ignored.

`forti-pihole init` writes the starting `config.json` below; `forti-pihole setup` writes it too when there
is none, and adds networks and Pi-hole mappings to it.

:::toc[On this page]{depth="3" theme="compact"}
:::

## config.json

### Top level

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `enabled` | boolean | `false` | Nothing is written to the FortiGate or Pi-hole until `true` |
| `profile` | string | `""` | The forti profile; empty: forti's default profile. `--profile` overrides it |
| `vdom` | string | `""` | The VDOM; empty: the profile's |
| `prefix` | string | `"fp-"` | 2-24 characters of `[A-Za-z0-9_-]`. Every managed FortiGate object's name starts with it |
| `interfaces` | array of strings | every network's `interface` | Devices detected on these interfaces are classified. At least one network or interface is required |
| `networks` | array | `[]` | How each interface maps to Pi-hole ([networks](#networks)) |
| `pihole` | object | | The Pi-hole connection ([pihole](#pihole)) |
| `daemon` | object | `{}` | Accepted (must be an object) and kept, but not read: `forti-piholed`'s settings are in `daemon.json` |
| `default_group` | string | `"default"` | Must be a listed group, and not privileged. Unknown and ambiguous devices go here |
| `groups` | array | | Required, at least one ([groups](#groups)). Listed in priority order |
| `rules` | array | `[]` | Presumptive classification ([rules](#rules)) |
| `protected` | array of MACs | `[]` | Devices never classified, moved or touched |
| `assignments` | object, MAC → group | `{}` | Explicit placements; any listed group, privileged ones included |
| `retire_after_days` | integer | `30` | `1`-`3650`. A device's managed object is retired after it has not been seen this long |
| `native_rule_priority` | integer | `50` | `0`-`10000`. The priority of `fp-rule-*` objects made in the GUI |
| `adopt_existing` | boolean | `true` | Reference an administrator's existing single-MAC address object as a device's group member instead of creating one (it is never modified) |
| `max_changes` | integer | `50` | `1`-`1000`. Devices that change group, and reservations added, per run |

MACs (here and on the command line) are accepted in any letter case with `:` or `-` separators or
none (`AA-BB-CC-DD-EE-FF`, `aabbccddeeff`) and normalized to `aa:bb:cc:dd:ee:ff`.

### groups

```json
{"name": "tvs", "description": "TVs and streaming sticks", "privileged": false, "pihole_group": "TVs"}
```

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `name` | string | | Required. 1-32 characters of `[a-z0-9_]`, unique. The FortiGate address group is `<prefix>grp-<name>` |
| `description` | string | `""` | Written into the address group's comment |
| `privileged` | boolean | `false` | Only explicit assignments, pins and confirmed reassociations can put a device here; rules naming it are refused |
| `pihole_group` | string | `""` | The Pi-hole group, by name, its addresses resolve to. Empty: not mapped (Pi-hole's Default group applies) |

When one device is in several groups' address groups, the earlier group in this list wins.

### rules

```json
{"name": "kasa-plugs", "group": "iot_untrusted", "priority": 200, "match": {"vendor": "TP-Link"}}
```

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `name` | string | `"<group>#<index>"` | Shown in reports |
| `group` | string | | Required. A listed group that is **not** privileged |
| `priority` | integer | `100` | `0`-`10000`. Higher wins; equal-priority matches in different groups are ambiguous |
| `match` | object | | Required, at least one field set |

`match` fields, all optional; every set field must match. Strings compare case-insensitively and accept
`*` and `?`:

| Field | Compared with |
|---|---|
| `vendor` | The FortiGate's `hardware_vendor` (`TP-Link`) |
| `family` | `hardware_family` (`Plug`, `Fire TV*`) |
| `type` | `hardware_type` (`IoT`, `Television`) |
| `os` | `os_name` (`Fire OS`) |
| `hostname` | The inventory hostname, else the DHCP hostname (`amazon-*`) |
| `vci` | The DHCP vendor class identifier (`udhcp*`) |
| `mac_prefix` | An OUI or longer prefix, `aa:bb:cc` (or with `-`); a prefix match, no globs |

### networks

```json
{
  "interface": "internal",
  "mode": "slices",
  "group": "default",
  "slices": [{"group": "tvs", "cidr": "192.168.1.200/29"}],
  "manage_reservations": false
}
```

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `interface` | string | | Required, unique. The FortiGate interface name |
| `mode` | string | `"observe"` | `subnet`, `slices`, `hybrid` or `observe` ([strategies](/guides/strategies)) |
| `group` | string | `default_group` | A listed group. In `subnet` and `hybrid`, the subnet maps to its Pi-hole group; its members need no slice here |
| `slices` | array | `[]` | `{"group", "cidr"}` pairs |
| `manage_reservations` | boolean | `false` | May sync add reservations and start migrations on this network |

Each slice's `group` must be a listed group; its `cidr` an IPv4 CIDR (`a.b.c.d/n`) with the host bits
zero, not overlapping another slice of the same network. Further rules:

- `subnet` mode takes no slices (use `hybrid`).
- In `slices` mode the rest of the subnet stays with Pi-hole's Default group, so the network's `group`
  must not have a `pihole_group` (use `hybrid`).
- Whether a slice lies inside the interface subnet and outside the DHCP pools is checked against the
  FortiGate by `slices` and `plan`, which report conflicts.

### pihole

```json
{"url": "https://pihole.example.net", "name": "default", "timeout_ms": 10000}
```

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `url` | string | `""` | Empty: Pi-hole sync is off. Must start with `https://`; `http://` is accepted only for a loopback host. A trailing `/` (and `/api`) is dropped; a path prefix behind a reverse proxy is kept. No credentials, query or fragment |
| `ca_bundle` | string | `""` | A PEM file of extra trusted CAs; verification is never turned off |
| `name` | string | `"default"` | 2-24 characters of `[A-Za-z0-9_-]`. Names the stored password: `pihole/<name>/password` |
| `timeout_ms` | integer | `10000` | `1000`-`120000`. The whole request; connecting takes at most 10 s of it |

### The starting configuration

`forti-pihole init` writes exactly this (also installed as
`share/forti-pihole/config.example.json`):

```json
{
  "$comment": "forti-pihole configuration. Groups are FortiGate address groups <prefix>grp-<name> (edit membership in the FortiGate GUI) mapped to Pi-hole groups. Nothing is written until enabled is true.",
  "adopt_existing": true,
  "assignments": {},
  "default_group": "default",
  "enabled": false,
  "groups": [
    {"description": "The operator's own devices", "name": "trusted", "privileged": true},
    {"description": "Work computers", "name": "work", "privileged": true},
    {"description": "TVs and streaming sticks", "name": "tvs"},
    {"description": "IoT devices with a known, needed cloud", "name": "iot_trusted"},
    {"description": "Commodity IoT (plugs, bulbs)", "name": "iot_untrusted"},
    {"description": "Everything not yet classified", "name": "default"}
  ],
  "max_changes": 50,
  "networks": [
    {"group": "default", "interface": "internal", "manage_reservations": false, "mode": "observe", "slices": []}
  ],
  "pihole": {"name": "default", "url": ""},
  "prefix": "fp-",
  "profile": "",
  "protected": [],
  "retire_after_days": 30,
  "rules": [
    {"group": "iot_untrusted", "match": {"vendor": "TP-Link"}, "name": "kasa-plugs", "priority": 200},
    {"group": "iot_untrusted", "match": {"family": "Hue", "vendor": "Philips"}, "name": "hue"},
    {"group": "tvs", "match": {"family": "Fire TV*", "vendor": "Amazon"}, "name": "fire-tv"},
    {"group": "tvs", "match": {"type": "Television"}, "name": "smart-tvs"},
    {"group": "iot_trusted", "match": {"vendor": "Ring"}, "name": "ring"},
    {"group": "iot_trusted", "match": {"vendor": "Rain Bird"}, "name": "rain-bird"},
    {"group": "iot_trusted", "match": {"vendor": "Chamberlain"}, "name": "myq"}
  ]
}
```

## daemon.json

`$FORTI_HOME/pihole/daemon.json`, read by `forti-piholed` at start and on `SIGHUP`. Absent: every
default. It holds no secret. `forti-piholed --check-config` validates it and prints the effective
settings.

| Key | Type | Default | Validation and meaning |
|---|---|---|---|
| `profile` | string | `""` | 1-64 characters of `[A-Za-z0-9_-]`; empty: forti's default profile. `--profile` overrides it. Gives the FortiGate's address (the default allowlist) and the token's binding |
| `listen.address` | string | `"127.0.0.1"` | An IPv4 or IPv6 address literal, never a name. IPv6 sockets are v6-only |
| `listen.port` | integer | `8735` | `1`-`65535` |
| `allow_sources` | array of strings | `[]` | Addresses or CIDR blocks (host bits zero) allowed to send events. Empty: the profile FortiGate's resolved address |
| `limits.max_header_bytes` | integer | `8192` | `1024`-`65536` |
| `limits.max_body_bytes` | integer | `65536` | `1024`-`1048576` |
| `limits.read_timeout_ms` | integer | `5000` | `100`-`60000`. The whole life of a connection, accept to last byte |
| `limits.max_connections` | integer | `16` | `1`-`256` |
| `rate_limit.burst` | integer | `30` | `1`-`10000`, per source address |
| `rate_limit.per_minute` | integer | `120` | `1`-`60000`, per source address |
| `schedule.debounce_seconds` | integer | `10` | `1`-`3600`. Quiet time after an event before a run |
| `schedule.max_delay_seconds` | integer | `60` | `1`-`86400`, at least `debounce_seconds`. The longest a burst of events delays a run |
| `schedule.full_reconcile_minutes` | integer | `15` | `1`-`10080`. A full sync this long after the last run |
| `schedule.backoff_initial_seconds` | integer | `10` | `1`-`3600`. The first retry delay after a failure |
| `schedule.backoff_max_seconds` | integer | `900` | `1`-`86400`, at least `backoff_initial_seconds` |
| `schedule.suppression_seconds` | integer | `60` | `0`-`3600`. How long events naming objects a run wrote are treated as its echo |
| `event_log.max_mib` | integer | `4` | `1`-`1024`. `events.jsonl` rotates to `events.jsonl.1` at this size |
| `token_account` | string | `""` | A secret-store account name (segments of `[A-Za-z0-9_.-]`, at most 128 characters). Empty: `pihole/<profile>/webhook-token`, where `events install` stores it |

```json
{
  "$comment": "forti-piholed settings; copy to $FORTI_HOME/pihole/daemon.json. Plain HTTP: bind to the management interface only. The webhook token lives in forti's secret store, never here.",
  "profile": "",
  "listen": {"address": "127.0.0.1", "port": 8735},
  "allow_sources": [],
  "limits": {"max_header_bytes": 8192, "max_body_bytes": 65536, "read_timeout_ms": 5000, "max_connections": 16},
  "rate_limit": {"burst": 30, "per_minute": 120},
  "schedule": {
    "debounce_seconds": 10,
    "max_delay_seconds": 60,
    "full_reconcile_minutes": 15,
    "backoff_initial_seconds": 10,
    "backoff_max_seconds": 900,
    "suppression_seconds": 60
  },
  "event_log": {"max_mib": 4},
  "token_account": ""
}
```

That is `share/forti-pihole/daemon.example.json`: every key with its default.
