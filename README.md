# forti-vlan-mac

A FortiGate companion that keeps your device inventory sorted into **logical segments**, using
FortiOS's own objects. It reads the FortiGate's device inventory and DHCP data through the FortiOS
REST API, classifies each device by MAC address with rules you write, and keeps these objects in step:

| Object | Name | Written by |
|---|---|---|
| MAC address object per device | `mvlan-dev-*` | forti-vlan-mac |
| Address group per segment | `mvlan-seg-<segment>` | forti-vlan-mac |
| Dynamic device-identification address (a rule) | `mvlan-rule-<segment>-<label>` | you, in the FortiGate GUI; forti-vlan-mac only reads it |

Your firewall policies reference the `mvlan-seg-*` groups. Move a device to another segment in the GUI,
or with `forti-vlan-mac assign`, and the next run keeps it there.

It is **never in the traffic path**: a command-line program that a systemd user timer runs every 15
minutes. There is no daemon and no listener, and nothing on the network depends on it running. It links
the same command engine as the `forti` CLI ([forti-cli](https://github.com/valkyrianlabs/forti-cli)),
built on the [forti-api](https://github.com/valkyrianlabs/forti-api) SDK.

Full documentation: [docs/](docs/index.md).

## What it is not

- **Not VLAN tagging.** It does not create VLAN interfaces or move ports or devices between VLANs.
  Segments are address groups; what they mean on the wire is up to your policies.
- **No RADIUS, no 802.1X, no dynamic VLAN assignment.** It never configures switches or
  authentication.
- **No layer-2 isolation.** Devices in different segments on the same VLAN can still reach each other
  without passing through the FortiGate.
- **No DHCP changes.** Assigning segments their own DHCP ranges is not yet available: it is under
  evaluation, and the program never writes DHCP settings today.

## Install

**Debian / Ubuntu (amd64)**, from the ValkyrianLabs APT repository:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://apt.valkyrianlabs.com/pubkey.gpg | sudo tee /etc/apt/keyrings/valkyrianlabs.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/valkyrianlabs.gpg] https://apt.valkyrianlabs.com stable main" \
  | sudo tee /etc/apt/sources.list.d/valkyrianlabs.list
sudo apt update && sudo apt install forti-vlan-mac
```

The package recommends `forti-cli` (for `forti configure`) and `valkyrianlabs-archive-keyring`, which
keeps the repository key current through upgrades.

**macOS (Homebrew)**:

```sh
brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-vlan-mac
```

macOS has no systemd: run `forti-vlan-mac apply` yourself, or from your own scheduler.

**From source**: see [Building](#building).

`forti-vlan-mac --version` names what it was built from, e.g.
`forti-vlan-mac 0.1.0 (engine forti-cli 468f9e1, forti-api 1.1.1)`.

## Quick start

1. Create a device profile with the forti CLI: `forti configure` (host, API token, mode). The profile's
   API account needs read access to the device inventory and DHCP, and write access to firewall
   addresses and address groups.
2. Write a starting configuration with `forti-vlan-mac init` (`~/.forti/vlan-mac/config.json`; never
   overwrites one) and describe your segments and rules in it.
3. See what it would do. Neither command writes anything:
   ```sh
   forti-vlan-mac report      # the inventory, classified into segments
   forti-vlan-mac plan        # the changes the next apply would make
   ```
4. Apply once by hand, then let the timer keep it current:
   ```sh
   forti-vlan-mac apply                    # at most 50 devices per run (--max-changes N)
   systemctl --user enable --now forti-vlan-mac.timer
   loginctl enable-linger "$USER"   # optional: run while you are logged out
   ```

## Files

| Path | What |
|---|---|
| `$FORTI_HOME/vlan-mac/config.json` | Your configuration (segments, rules, protected devices) |
| `$FORTI_HOME/vlan-mac/state.json` | What forti-vlan-mac has learned about each device between runs |
| `$FORTI_HOME/vlan-mac/history.jsonl` | One line per apply (`forti-vlan-mac history`) |

`FORTI_HOME` defaults to `~/.forti`, the forti home that forti and forti-mcp also use. Device profiles
and credentials stay where `forti configure` put them.

## Safety model

- **Fail-static.** Nothing on the network depends on forti-vlan-mac. If it stops, the FortiGate keeps
  the objects it has; a failed read never deletes anything.
- **Write allowlist.** It writes only `firewall/address` and `firewall/addrgrp` objects whose name
  starts with its prefix (default `mvlan-`) and that carry the marker comment
  `managed by forti-vlan-mac`. Every other write is refused in code before it is sent. It never touches
  interfaces, policies, routing, DHCP, users, admins, switches or system settings.
- **Your objects are yours.** Objects without the marker are never changed or deleted, even when their
  name has the prefix.
- **Conservative classification.** Precedence is protected > your assignment (`assignments` in the
  configuration, `assign`, a move in the GUI) > rule > default. Privileged segments are never inferred
  from a rule, and an ambiguous match goes to the default segment. A device that seems to have come
  back with a new randomized MAC is linked only after you `confirm` it.
- **No device loses its route.** Before moving devices, it simulates your policies for each device's
  internet and DNS traffic and keeps a device where it is when a move would cut it off. At most
  `max_changes` devices (default 50) change per run.
- **Every change goes through the engine's plan and apply** (validation, drift check, verification,
  audit record, rollback plan), within the profile's mode: a `read-only` profile can `report` and
  `plan`, but `apply` is refused.

## Building

```sh
meson setup build -Dtests=enabled
meson compile -C build -j "$(ci/build-jobs)"
meson test -C build
sudo meson install -C build --skip-subprojects    # /usr/local/bin/forti-vlan-mac
```

Needs a C++23 compiler (GCC 13+ or a recent clang), Meson ≥ 1.3, libcurl and (for tests) GoogleTest.
The engine comes from forti-cli's source as the Meson subproject `subprojects/forti-cli`, pinned to one
commit by `subprojects/forti-cli.wrap` and fetched at configure time. forti-api (header-only) comes from
a system install (`libforti-api-dev`, the `forti-api` formula) when present, else from its wrap. On
Linux, `meson install` also installs the user units into `<prefix>/lib/systemd/user`; their
`ExecStart` names `/usr/bin/forti-vlan-mac`, so a `/usr/local` install needs
`systemctl --user edit forti-vlan-mac.service`. Tests never contact a device.

## License

MIT
