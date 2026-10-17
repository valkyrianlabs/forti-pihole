---
title: Allocation strategies
navTitle: Strategies
description: The subnet, slices, hybrid and observe strategies, how each maps addresses to Pi-hole groups, with a VLAN example and a flat-network example.
order: 30
status: published
tags:
  - guides
---

# Allocation strategies

Pi-hole decides a client's filtering groups by its **source address**. forti-pihole's job is to make
sure the address a device uses tells Pi-hole the right group. Each network in `config.json` picks how
that happens: its **mode**.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The four modes

| Mode | Addresses and DHCP | Pi-hole client entries | Use it for |
|---|---|---|---|
| `subnet` | Nothing changes | One per interface subnet (primary and secondary) → the network group's Pi-hole group | Native VLANs: the VLAN is the group |
| `slices` | DHCP reservations inside each slice (with `manage_reservations`) | One per slice → the slice group's Pi-hole group; the rest of the subnet has no entry, so Pi-hole's Default group applies | A flat network shared by many kinds of devices |
| `hybrid` | As `slices` | One per slice, plus the whole subnet → the network group's Pi-hole group | A real VLAN with a few groups carved out of it |
| `observe` | Nothing changes | None | Inventory and reports only (the default) |

Device groups are network-independent. On every listed network, whatever its mode, each device is
classified and kept as a MAC object in its `fp-grp-<group>` address group on the FortiGate; the mode
only decides how the network's addresses map to Pi-hole, and whether devices get reservations.

A network's `group` has two roles: in `subnet` and `hybrid` it is the group whose Pi-hole group the
subnet maps to, and members of that group need no slice on that network.

## Subnet

A `subnet` network maps its whole interface subnet, and every secondary subnet, to the Pi-hole group of
the network's `group`. Nothing on the FortiGate is written for it: no reservation, no address change.
When that group has no `pihole_group`, nothing is written to Pi-hole either.

### Example: one VLAN per group

A FortiGate with four VLANs, each already carried to the right devices by the access points and
switches:

| VLAN | Interface | Subnet | Device group | Pi-hole group |
|---|---|---|---|---|
| 20 | `work` | `192.168.20.0/24` | `work` (privileged) | `Work` |
| 30 | `iot` | `192.168.30.0/24` | `iot` | `IoT` |
| 40 | `tvs` | `192.168.40.0/24` | `tvs` | `TVs` |
| 50 | `trusted` | `192.168.50.0/24` | `trusted` (privileged) | `Trusted` |

An excerpt of `config.json`:

```json
{
  "networks": [
    {"interface": "work",    "mode": "subnet", "group": "work"},
    {"interface": "iot",     "mode": "subnet", "group": "iot"},
    {"interface": "tvs",     "mode": "subnet", "group": "tvs"},
    {"interface": "trusted", "mode": "subnet", "group": "trusted"}
  ],
  "groups": [
    {"name": "trusted", "privileged": true, "pihole_group": "Trusted"},
    {"name": "work",    "privileged": true, "pihole_group": "Work"},
    {"name": "tvs",     "pihole_group": "TVs"},
    {"name": "iot",     "pihole_group": "IoT"},
    {"name": "default"}
  ]
}
```

Pi-hole gets four managed entries, `192.168.20.0/24 → Work`, `192.168.30.0/24 → IoT`,
`192.168.40.0/24 → TVs` and `192.168.50.0/24 → Trusted`, each with the comment
`managed by forti-pihole: <interface> subnet`.

:::callout[A VLAN interface is not a VLAN]{variant="warning"}
Creating a VLAN interface on the FortiGate does not make an access point or a switch tag anyone's
traffic. A device is on VLAN 40 only when the AP's SSID or the switch port puts it there. forti-pihole
never configures tagging, switches, SSIDs or 802.1X; it maps the subnets the network already has.
:::

## Slices

A `slices` network is one flat subnet that many kinds of devices share. Each Pi-hole mapped group gets
one or more **slices**: CIDR blocks inside the subnet, outside the DHCP pools. Members of the group get
a DHCP reservation inside their slice, and Pi-hole maps each slice to the group's Pi-hole group.
Everything else on the subnet has no client entry, so Pi-hole applies its Default group.

Devices in a slice keep the interface's mask and gateway: `192.168.1.204` is still on
`192.168.1.0/24` with gateway `192.168.1.1`. A slice is an allocation and DNS classification unit, not
a routed subnet, and not Layer-2 isolation.

Because the rest of the subnet stays with Default, the network's own `group` must not map to a Pi-hole
group in `slices` mode; the configuration refuses it and suggests `hybrid`.

### Example: a flat home network

`internal` is `192.168.1.0/24`, gateway `192.168.1.1`, with the DHCP pool
`192.168.1.10-192.168.1.199`:

| Device group | Slice | Addresses | Pi-hole group |
|---|---|---|---|
| `tvs` | `192.168.1.200/29` | `.200-.207` | `TVs` |
| `iot_untrusted` | `192.168.1.208/28` | `.208-.223` | `IoT` |
| `iot_trusted` | `192.168.1.224/28` | `.224-.239` | `IoT-Cloud` |
| `default`, everything else | the pool and the rest | | Default (no entry) |

```json
{
  "networks": [
    {
      "interface": "internal",
      "mode": "slices",
      "group": "default",
      "manage_reservations": false,
      "slices": [
        {"group": "tvs",           "cidr": "192.168.1.200/29"},
        {"group": "iot_untrusted", "cidr": "192.168.1.208/28"},
        {"group": "iot_trusted",   "cidr": "192.168.1.224/28"}
      ]
    }
  ]
}
```

Pi-hole gets three managed entries, one per slice, with the comment
`managed by forti-pihole: internal slice <group>`. With `manage_reservations` off the plan shows each
device's move; turn it on when the plan looks right. [Address slicing](/guides/address-slicing)
covers sizing and placement; [Migrations](/guides/migrations) covers how a device moves into its slice.

## Hybrid

A `hybrid` network is a real VLAN with slices carved out of it. The slices map as in `slices`, and the
whole subnet maps to the network group's Pi-hole group as well.

This is well defined because Pi-hole resolves a client by its **longest matching prefix**: an address
inside a `/28` slice entry matches the slice before the `/24` subnet entry around it
([how Pi-hole resolves clients](/guides/pihole#how-pi-hole-picks-a-clients-groups)).

### Example: a VLAN with a trusted corner

VLAN 30 (`iot`, `192.168.30.0/24`) maps to `IoT`, but the cameras that need their cloud get a slice
with laxer filtering:

```json
{
  "interface": "iot",
  "mode": "hybrid",
  "group": "iot",
  "manage_reservations": true,
  "slices": [{"group": "iot_trusted", "cidr": "192.168.30.192/27"}]
}
```

| Pi-hole entry | Group | Matches |
|---|---|---|
| `192.168.30.192/27` | `IoT-Cloud` | `.192-.223` (longest prefix wins) |
| `192.168.30.0/24` | `IoT` | everything else on the VLAN |

## Observe

`observe` networks are read and reported. Their devices are classified and kept in the `fp-grp-*`
address groups like any other, but no Pi-hole entry and no reservation is ever written for them.
`setup` adds new networks in this mode.

## Choosing

:::cards{
  columns="3"
  cardTheme="muted"
}

:::card[You have VLANs]{
  href="#subnet"
  linkScope="title"
}
Use `subnet`. Nothing on the FortiGate changes, and one Pi-hole entry per VLAN does the work.
:::

:::card[One flat network]{
  href="#slices"
  linkScope="title"
}
Use `slices`. Plan the slices with `forti-pihole slices --propose`, then let devices move in.
:::

:::card[VLANs, but mixed]{
  href="#hybrid"
  linkScope="title"
}
Use `hybrid` for the VLAN that holds a few devices needing a different policy.
:::

:::
