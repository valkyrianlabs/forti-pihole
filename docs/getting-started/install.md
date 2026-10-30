---
title: Install
description: Install forti-pihole with Homebrew or APT, or build it from source, and prepare the FortiGate profile and the Pi-hole app password it needs.
order: 10
status: published
tags:
  - getting-started
---

# Install

forti-pihole ships two executables: `forti-pihole`, the command-line program, and `forti-piholed`, the
optional service that reacts to FortiGate changes. libcurl is the only runtime dependency. Install them
with Homebrew or APT, or build from source, then check the prerequisites below.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Prerequisites

| You need | Why |
|---|---|
| A FortiGate reachable over its REST API, with a **forti profile** | forti-pihole talks to the FortiGate through the forti engine, with a device profile and API key that `forti configure` (from [forti-cli](https://github.com/valkyrianlabs/forti-cli)) creates in the forti home. Developed against FortiOS 7.4 |
| **Pi-hole v6**, FTL **6.7.0 or newer** | forti-pihole uses the Pi-hole v6 REST API and refuses older FTL versions, and versions it cannot read |
| A Pi-hole **app password** | A periodic job cannot answer two-factor prompts. Create one in Pi-hole under **Settings → Web interface / API → Configure app password**; `forti-pihole setup` asks for it once |
| HTTPS to Pi-hole | Plain `http://` is accepted only for a loopback Pi-hole (`localhost`, `127.x.x.x`, `[::1]`); anywhere else the password and session would cross the network in clear |

The forti profile's **mode** decides how writes happen, exactly as for `forti` itself: `read-only`
applies nothing, `guarded` waits for your `forti approve`, `autonomous` applies directly. See
[Safety](/guides/safety#the-forti-profile-mode-still-applies).

## Install the packages

:::tabs{
  default="homebrew"
  theme="glass"
  tabTheme="muted"
}

:::tab[Homebrew (macOS, Linux)]{value="homebrew"}
```bash
brew install valkyrianlabs/tap/forti-cli valkyrianlabs/tap/forti-pihole
```

No `brew tap` or `brew trust` step: Homebrew trusts the formulae named in full on the command line.
`forti-cli` provides `forti configure`; forti-pihole has the engine compiled in and does not need it at
run time.

The example configurations are in `$(brew --prefix)/share/forti-pihole/`. The optional service runs
under `brew services start forti-pihole` ([Runtime](/guides/runtime#homebrew-services)).
:::

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

The package recommends `forti-cli` and `valkyrianlabs-archive-keyring`, so APT installs both by
default. Signing key fingerprint: `494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`.

| Path | What |
|---|---|
| `/usr/bin/forti-pihole` | The program |
| `/usr/bin/forti-piholed` | The optional event receiver and scheduler |
| `/usr/lib/systemd/user/forti-pihole.service` | One `apply --quiet` run (a sync) |
| `/usr/lib/systemd/user/forti-pihole.timer` | Starts that service every 15 minutes, once you enable it |
| `/usr/lib/systemd/user/forti-piholed.service` | The service, once you enable it |
| `/usr/share/forti-pihole/config.example.json` | The starting configuration `forti-pihole init` also writes |
| `/usr/share/forti-pihole/daemon.example.json` | Every `forti-piholed` setting with its default |

Installing the package never enables a unit for anyone.
:::

:::tab[From source]{value="source"}
```bash
# Ubuntu: sudo apt install meson ninja-build g++ pkgconf libcurl4-openssl-dev
# macOS:  brew install meson ninja       (libcurl comes with the SDK)
meson setup build
meson compile -C build -j 4
meson install -C build --skip-subprojects
```

A C++23 compiler (GCC 13 or newer, or a recent Clang) and Meson 1.3 or newer are required. Meson
fetches the engine at configure time: forti-cli's source at the commit `subprojects/forti-cli.wrap`
pins. forti-api comes from a system install (`libforti-api-dev`, or the `forti-api` formula) when one is
present, else from its own wrap.

On Linux, `meson install` also installs the three user units into `<prefix>/lib/systemd/user`. Their
`ExecStart` names `/usr/bin/...`; with another prefix, point them at your binaries with
`systemctl --user edit forti-pihole.service` (and `forti-piholed.service`).
:::

:::

## Check the installation

```bash
forti-pihole --version
forti-piholed --version
```

```text
forti-pihole 0.1.0 (engine forti-cli 468f9e1, forti-api 1.1.1)
forti-piholed 0.1.0 (engine forti-cli 468f9e1, forti-api 1.1.1)
```

The version line names what the binary was built from: the forti-cli engine revision and the forti-api
version. A build from a modified engine checkout shows the revision with `-dirty`.

## Create the FortiGate profile

```bash
forti configure
```

`forti configure` asks for the FortiGate's address, an API key and the profile's mode, and stores the
key in forti's secret store. forti-pihole uses the default profile unless the configuration's
`profile`, or `--profile NAME`, names another.

:::callout[macOS Keychain prompts]{variant="info"}
On macOS the API key, the Pi-hole app password and the webhook token live in the login Keychain
(service `forti`). Each item belongs to the binary that created it, so the first time `forti-pihole`
or `forti-piholed` (and every newly installed or upgraded build of either) reads one, macOS asks.
Choose **Always Allow**. See [Troubleshooting](/reference/troubleshooting#macos-asks-for-the-keychain-again).
:::

## Where it keeps its files

forti-pihole uses the **forti home**: `~/.forti`, or the directory `$FORTI_HOME` names. Profiles and
credentials are the ones `forti configure` manages there. Its own files live in `pihole/`:

| Path | Written by | What |
|---|---|---|
| `pihole/config.json` | you, `init`, `setup` | The configuration ([Configuration](/reference/configuration)) |
| `pihole/state.json` | `sync`, `assign`, `adopt`, `confirm` | Devices seen, pins, adoptions, reassociation candidates, a pending plan |
| `pihole/history.jsonl` | `sync` | One line per write stage (`forti-pihole history`) |
| `pihole/operations/<id>.json` | `migrate`, `sync` | The journal of each address migration |
| `pihole/lock` | every run | One run at a time (a timer, the service and you never overlap) |
| `pihole/daemon.json` | you | `forti-piholed` settings ([Configuration](/reference/configuration#daemonjson)) |
| `pihole/daemon-state.json`, `daemon-state.lock` | `forti-piholed`, `pause`, `resume` | The service's last event and run, backoff, and the pause flag |
| `pihole/events.jsonl` | `forti-piholed` | Accepted events and finished runs; rotates to `events.jsonl.1` |

Every file forti-pihole and forti-piholed create is `0600`, in a `0700` directory. No secret is ever
written to any of them: the API key, the Pi-hole app password and the webhook token stay in forti's
secret store.

## Next

:::buttons{align="left" gap="md"}
::button[Onboarding]{href="/getting-started/onboarding" variant="primary"}
::button[Safety]{href="/guides/safety" variant="secondary"}
:::
