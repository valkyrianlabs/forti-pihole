---
title: Install
description: Install forti-pihole from the APT repository or Homebrew, or build it from source.
order: 10
status: published
tags:
  - getting-started
---

# Install

forti-pihole is a single executable, `forti-pihole`. libcurl is its only runtime dependency. On
Linux the package also ships a systemd user service and timer, which you enable yourself. Install it
from the ValkyrianLabs APT repository, from Homebrew, or build it from source, then check the version
it reports.

:::callout[Install forti as well]{variant="info"}
forti-pihole connects to the FortiGate with a device profile from the forti home (`~/.forti`). You
create that profile, and its credentials, with `forti configure` from the forti-cli package. The APT
package recommends `forti-cli`, so APT installs it by default.
:::

## Install

:::tabs{
  default="apt"
  theme="glass"
  tabTheme="muted"
}

:::tab[Debian and Ubuntu (APT)]{value="apt"}
`forti-pihole` is published to the ValkyrianLabs APT repository (amd64):

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://apt.valkyrianlabs.com/pubkey.gpg \
  -o /etc/apt/keyrings/valkyrianlabs.gpg
sudo chmod 0644 /etc/apt/keyrings/valkyrianlabs.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/valkyrianlabs.gpg] https://apt.valkyrianlabs.com stable main" | \
  sudo tee /etc/apt/sources.list.d/valkyrianlabs.list > /dev/null

sudo apt update
sudo apt install -y forti-pihole
```

The package recommends `forti-cli` and `valkyrianlabs-archive-keyring`. The keyring package keeps the
repository key at `/usr/share/keyrings/valkyrianlabs.gpg` current through normal upgrades. Signing key
fingerprint: `494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`.

The package installs:

| Path | What |
|---|---|
| `/usr/bin/forti-pihole` | The program |
| `/usr/lib/systemd/user/forti-pihole.service` | One `apply --quiet` run |
| `/usr/lib/systemd/user/forti-pihole.timer` | Starts the service every 15 minutes, once you enable it |
| `/usr/share/forti-pihole/config.example.json` | A starting point for your configuration |

Installing the package never enables the timer for anyone.
:::

:::tab[Homebrew (macOS)]{value="homebrew"}
```bash
brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-pihole
```

Recent Homebrew versions ask you to trust a third-party tap first (`brew trust valkyrianlabs/tap`).

macOS has no systemd, so no timer is installed. Run `forti-pihole apply` yourself or from a
scheduler you already use. The example configuration is in
`$(brew --prefix)/share/forti-pihole/config.example.json`.
:::

:::tab[From source]{value="source"}
```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev
# macOS:  brew install meson ninja       (libcurl comes with the SDK)
meson setup build
meson compile -C build -j 4
meson install -C build --skip-subprojects
```

A C++23 compiler (GCC 13 or newer, or a recent Clang) and Meson 1.3 or newer are required.

Meson fetches the engine at configure time: forti-cli's source at the commit
`subprojects/forti-cli.wrap` pins. forti-api comes from a system install (`libforti-api-dev`, or the
`forti-api` formula) when one is present, else from its own wrap.

On Linux, `meson install` also installs the user units into `<prefix>/lib/systemd/user`. Their
`ExecStart` names `/usr/bin/forti-pihole`; with another prefix, point it at your binary with
`systemctl --user edit forti-pihole.service`.
:::

:::

## Check the installation

```bash
forti-pihole --version
```

```text
forti-pihole 0.1.0 (engine forti-cli 468f9e1, forti-api 1.1.1)
```

The version line names what the binary was built from: the forti-cli engine revision and the
forti-api version. A build from a modified engine checkout shows the revision with `-dirty`.

## Where it keeps its files

forti-pihole uses the **forti home**: `~/.forti`, or the directory `$FORTI_HOME` names. Device
profiles and credentials are the ones `forti configure` manages there. Its own files live in
`pihole/` inside the home:

| Path | What |
|---|---|
| `$FORTI_HOME/pihole/config.json` | Your configuration ([Configuration](/reference/configuration)) |
| `$FORTI_HOME/pihole/state.json` | What it has learned about each device between runs |
| `$FORTI_HOME/pihole/history.jsonl` | One line per apply (`forti-pihole history`) |

`--config PATH` reads another configuration file ([Command line](/reference/cli)).

## Next

:::buttons{align="left" gap="md"}
::button[Quick start]{href="/getting-started/quick-start" variant="primary"}
::button[Safety]{href="/guides/safety" variant="secondary"}
:::
