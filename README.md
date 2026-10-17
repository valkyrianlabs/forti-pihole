# forti-pihole

**Unified FortiGate network identity and Pi-hole DNS policy synchronization.**

The FortiGate owns your networks, DHCP, device identification, address objects and policies. Pi-hole
owns your filtering groups, blocklists and filtering behaviour. forti-pihole owns the relationship
between them, and keeps it true:

- **device groups ↔ Pi-hole groups**: every device the FortiGate sees is classified into a device group,
  kept on the FortiGate as an address group `fp-grp-<group>` (one MAC object `fp-dev-*` per device)
  that your own policies can reference, and mapped to a Pi-hole group;
- **networks ↔ CIDR client entries**: each network's addresses map to Pi-hole client entries, so every
  device gets its group's DNS filtering.

It is **never in the traffic path**: if it stops, the FortiGate keeps routing and serving DHCP, and
Pi-hole keeps its last configuration. It links the same command engine as the `forti` CLI
([forti-cli](https://github.com/valkyrianlabs/forti-cli)), built on the
[forti-api](https://github.com/valkyrianlabs/forti-api) SDK.

## Two strategies, one engine

Chosen per network:

| Strategy | For | How Pi-hole tells devices apart | FortiGate changes |
|---|---|---|---|
| **subnet** | Native VLANs | The interface subnet → the network group's Pi-hole group | None |
| **slices** | A flat network | Group members get DHCP reservations inside CIDR slices; each slice → its group's Pi-hole group | Single DHCP reservations, only with `manage_reservations` |

**hybrid** puts slices inside a real VLAN and maps the rest of the VLAN to the network group's Pi-hole
group (valid because Pi-hole resolves the longest matching prefix). **observe** only reads and reports.

A slice is a DHCP allocation and DNS classification unit: devices keep the interface's real mask and
gateway. It is **not** a routed subnet and **not** Layer-2 isolation.

## What it is not

- **Not VLAN tagging.** It never creates or changes interfaces. Creating a VLAN interface on the
  FortiGate does not make an access point or a switch tag anyone's traffic.
- **No RADIUS, no 802.1X, no dynamic VLAN assignment**, and no switch configuration.
- **No Layer-2 isolation.** Devices on one network reach each other directly, whatever their group.
- **Not DNS enforcement.** DNS over HTTPS, Private Relay and hard-coded resolvers bypass any DNS filter
  unless your FortiGate policies stop them.

## Install

```sh
brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-pihole     # macOS, Linuxbrew
sudo apt install forti-pihole                                               # Debian/Ubuntu amd64, from apt.valkyrianlabs.com
```

Requirements: a forti profile for the FortiGate (`forti configure`, from forti-cli), and Pi-hole v6 with
FTL 6.7.0 or newer and an **app password**. [Install](docs/getting-started/install.md) has the APT
repository setup and the source build.

## Quick start

```sh
forti configure                                            # the FortiGate profile
forti-pihole setup --pihole-url https://pihole.example.net # discover, store the app password, write config.json
forti-pihole networks                                      # review: strategy per network
forti-pihole groups                                        # review: device group -> Pi-hole group
forti-pihole slices --propose                              # flat networks: proposed slices
forti-pihole plan                                          # everything a sync would do (writes nothing)
# set "enabled": true in ~/.forti/pihole/config.json
forti-pihole sync
```

Then keep it running with the systemd user timer (`systemctl --user enable --now forti-pihole.timer`) or
the optional service `forti-piholed`, which reacts to FortiGate changes
(`forti-pihole events install --url http://HOST:8735`). The full walkthrough is
[Onboarding](docs/getting-started/onboarding.md).

## Safety

- **Nothing is written until `"enabled": true`.** `forti-pihole pause` stops all writes at any time;
  reservations and address moves are off per network until `"manage_reservations": true`.
- **A two-layer write allowlist**, checked before planning and again by a guard transport under the
  engine before any request is sent: managed `fp-*` address objects and groups; single DHCP reservation
  entries (never the whole list); host objects you adopted; lease revokes of the listed addresses; the
  automation stitch only inside `events install|remove`.
- **Administrator objects are never modified** unless you adopt them for one device
  (`forti-pihole adopt MAC --object NAME --reservation`).
- **Migrations are journaled, resumable and reversible.** Objects are updated before the old lease is
  revoked, so an old address never keeps privileges; only that device's lease is revoked, once; the end
  is verified (lease, firewall reach, Pi-hole group).
- **Pi-hole:** only client entries with the comment `managed by forti-pihole` are written; your entries
  are read and reported; groups are mapped, never created by a sync.
- **Every FortiGate write goes through the forti engine** (validation, verification, audit, rollback
  plan) and honours the profile's mode: a `guarded` profile waits for `forti approve`.
- **Secrets stay in forti's secret store**, never in files, output or logs.

[Safety](docs/guides/safety.md) has the full model.

## Documentation

| | |
|---|---|
| [Overview](docs/index.md) | Ownership, strategies, how a sync works |
| [Install](docs/getting-started/install.md), [Onboarding](docs/getting-started/onboarding.md) | Getting started |
| [Strategies](docs/guides/strategies.md), [Address slicing](docs/guides/address-slicing.md), [Migrations](docs/guides/migrations.md) | Mapping networks |
| [Device groups and rules](docs/guides/device-groups-and-rules.md), [Pi-hole](docs/guides/pihole.md), [Runtime](docs/guides/runtime.md) | The rest of the guides |
| [Command line](docs/reference/cli.md), [Configuration](docs/reference/configuration.md), [Troubleshooting](docs/reference/troubleshooting.md) | Reference |
| [Building and testing](docs/development/testing.md) | Development |

An agent skill for operating forti-pihole on a user's behalf is in [skill/forti-pihole](skill/forti-pihole/SKILL.md).

## License

MIT
