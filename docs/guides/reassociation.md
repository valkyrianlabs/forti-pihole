---
title: Randomized MACs
navTitle: Randomized MACs
description: Why a device can come back with a new MAC address, how forti-vlan-mac offers it as a candidate, and how confirm links it.
order: 40
status: published
tags:
  - guides
---

# Randomized MACs

forti-vlan-mac identifies devices by MAC address. Most current phones, tablets and laptops do not keep
one: they use a **private (randomized) MAC address** per network, and some change it from time to time.
When that happens the FortiGate sees a new device, and the segment you gave the old one does not follow
on its own.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Recognising a randomized address

A randomized MAC address is a *locally administered* address: the second hexadecimal digit of its first
byte is `2`, `6`, `A` or `E` (for example `da:a1:19:…`). Addresses burned in by the manufacturer start
with the vendor's prefix instead, which is why `mac_prefix` rules work only for
those.

## Candidates

When a new MAC address appears that resembles a device forti-vlan-mac already placed (or you pinned),
and that old device is offline, forti-vlan-mac records a **reassociation candidate**: "this may be the
same device as before". (Offline means the FortiGate has not seen it for an hour: FortiOS keeps
`is_online` set on inventory entries it last saw days ago, so that flag alone is not trusted.) The
evidence is scored:

| Evidence | Points |
|---|---|
| The same distinctive hostname | 3 |
| The same hardware family | 1 |
| The same operating system | 1 |
| The same OS version | 1 |
| The same vendor | 1 |

A candidate needs the hostname match and at least 4 points. Generic hostnames (`iPhone`, `Watch`,
`MacBook-Air` and the like, and any name more than one current device carries) are not evidence.

A candidate is only a suggestion. Until you confirm it, the new address is classified on its own
merits (protected, assignments, pins, rules or the default segment), and the old device keeps its
object until it is retired. `forti-vlan-mac report` lists open candidates with their ids.

## Confirming

```bash
forti-vlan-mac report                  # open candidates, with their ids
forti-vlan-mac confirm 1a2b3c4d        # the new address takes over the old device's segment
forti-vlan-mac confirm 1a2b3c4d --reject   # they are different devices; never propose the pair again
```

Confirming pins the new address to the old device's segment, including a privileged one, and retires
the old entry at the next `apply`. [Command line](/reference/cli#confirm) has the details.

:::callout[Why nothing is linked automatically]{variant="warning"}
A hostname or a device type is trivially spoofed, and the old device may sit in a privileged segment.
Linking addresses on a guess could move an unknown device into the segment of one you trust, so
forti-vlan-mac only proposes; a person decides.
:::

## Avoiding the problem

Where you control the device, turn off the private address for your own network: on iOS and iPadOS,
**Private Wi-Fi Address** in the network's settings; on Android, **MAC address type → Device MAC**;
on Windows, **Random hardware addresses**; on macOS, **Private Wi-Fi address**. The device then keeps
one address on that network, and its segment stays put.
