---
title: Troubleshooting
description: Nothing happens, Keychain prompts, Pi-hole login and version errors, approvals and stale plans, devices that do not renew, shadowing Pi-hole entries, DNS bypass and forti-piholed refusals.
order: 120
status: published
tags:
  - reference
---

# Troubleshooting

Start with `forti-pihole status` (enabled, paused, profile and mode, a plan waiting for approval, open
operations) and `forti-pihole plan` (what a sync would do, and the notes that explain why something does
not). Every error names what failed; none contains a secret.

:::toc[On this page]{depth="2" theme="compact"}
:::

## Nothing happens

| Symptom | Cause | Fix |
|---|---|---|
| `sync` ends with `nothing written: the configuration is not enabled` and exits `7` | `"enabled": false` | Review `plan`, then set `"enabled": true` |
| `nothing written: sync is paused (forti-pihole resume)` | `forti-pihole pause` | `forti-pihole resume` |
| Moves appear in `plan` but no reservation is ever added | `"manage_reservations": false` on that network | Set it to `true`, or move one device with `forti-pihole migrate MAC` |
| `forti-piholed` logs runs but nothing changes | Not enabled or paused (it reads both before every run) | As above |
| A device is never classified | Its interface is not in `interfaces` (by default: the networks' interfaces) | Add the network |
| `another forti-pihole run is in progress` (exit `3`) | The timer, the service or another shell holds the run lock | Wait; runs are short |
| A group shows `[NOT MANAGED: name clash]` | An address group `fp-grp-<group>` exists without the marker | Rename your object, or the group |

## macOS asks for the Keychain again

Each Keychain item belongs to the binary that created it. The first time another binary reads it, and
after every upgrade of `forti-pihole` or `forti-piholed` (a new binary), macOS asks whether it may.
Choose **Always Allow**. `forti-pihole` and `forti-piholed` are two binaries, so each asks once per item
(the FortiGate API key, the Pi-hole app password, the webhook token).

Without a GUI session (SSH, `brew services`, launchd) macOS cannot show that prompt, and the run fails
with a configuration error. Run the program once in a terminal after installing or upgrading
(`forti-pihole plan`, and `forti-piholed` until its first run has finished, then Ctrl-C), or unlock the
keychain (`security unlock-keychain`). `FORTI_SECRET_STORE=file` selects the engine's file store
instead; every secret must then be stored there (`forti configure`, `forti-pihole setup`,
`forti-pihole events install`, run with the same setting).

## Pi-hole login and version errors

Errors read `Pi-hole at <url>: ...`. The common ones:

| Message contains | Meaning | Fix |
|---|---|---|
| `no Pi-hole password stored for <name>; run forti-pihole setup` | No app password in the secret store | `forti-pihole setup` |
| `the stored Pi-hole password belongs to <host:port>, not <host:port>` | `pihole.url` now points elsewhere than when the password was stored | `forti-pihole setup` stores one for the new URL |
| `password incorrect; check the app password (no retry: FTL rate-limits logins)` | Wrong or revoked app password | Create a new app password, then `forti-pihole setup` |
| `2FA is enabled: configure an app password instead` | The admin password was used, and two-factor authentication is on | Use an app password |
| HTTP `429` | FTL's login rate limit, or no free API session (`webserver.api.max_sessions`, default 16) | Wait; check for other API clients holding sessions |
| `FTL <version> is older than 6.7.0` | An FTL older than forti-pihole supports | Update Pi-hole |
| `cannot tell the FTL version` | A development or custom build reports no usable version | Run a released FTL |
| `plain http:// is accepted for loopback hosts only` | An `http://` URL to another host | Use `https://` |
| A TLS verification error | Pi-hole's certificate is not trusted | Point `pihole.ca_bundle` at your CA's PEM file |

During a `sync`, a Pi-hole error skips the Pi-hole stage (reported on standard error as `pihole: ...`)
and the FortiGate stages still run.

## Waiting for approval

A `guarded` forti profile applies nothing until you approve the exact plan:

```text
objects       waiting   waiting for approval: forti approve 20261017-101500-ab12cd
```

The exit status is `7`. Run `forti approve <plan id>` (it shows the change and asks), then:

- **FortiGate objects** (`objects` stage): run `forti-pihole sync` again; it applies the approved plan
  first. A pending plan older than a day is planned again from fresh reads.
- **A migration step**: `forti-pihole operations resume ID`, or the next sync, applies the same plan.
- **`events install`**: `forti apply <plan id>`.

`the forti profile is read-only: nothing applied` means the profile's mode forbids changes; changing the
mode is a decision for `forti`, not for forti-pihole.

## stale_plan

`stale_plan` means the FortiGate changed between planning and applying, so the engine refused the plan
rather than apply it to a configuration it was not made for. For the FortiGate objects, the next sync
simply plans again. For a migration step that failed with `stale_plan`, roll the operation back
(`forti-pihole operations rollback ID`); the next sync, or `forti-pihole migrate MAC`, plans a fresh
migration from current reads.

## A device does not move into its slice

| Output | Meaning |
|---|---|
| `observe: the device has not taken <new> (it has <old>)` | It has not renewed its lease. Reconnect its Wi-Fi or power-cycle it, then `forti-pihole operations resume ID` (or wait for the next sync) |
| `migration refused: ... is privileged by address` | A host object on the old address is a policy source: `forti-pihole adopt MAC --object NAME` |
| `migration refused: ...'s reservation <id> is an administrator's` | `forti-pihole adopt MAC --reservation` |
| `migration refused: VIP <name> forwards to <old>` | A port forward follows the address: move or remove the VIP first |
| `migration refused: target <ip> is in use` | Something holds the chosen address; `forti-pihole references <ip>` shows what |
| `note (slice-full)` | No free address in the group's slices: see [capacity](/guides/address-slicing#when-there-is-not-enough-room) |
| `note (no-address)` | No current address known; it waits for a lease |
| `verify` failed: `lost DNS reach` or `lost internet reach` | Your policies treat the new address differently. Fix the policy, then `operations resume ID`, or `operations rollback ID` |
| `verify` failed: `Pi-hole resolves <ip> to groups [...]` | An entry of yours decides that address (below) |

A device with a randomized MAC that rotates gets a new identity, and its reservation stays with the old
one: see [Randomized MACs](/guides/reassociation).

## Pi-hole applies the wrong group

Pi-hole uses the **most specific** entry that matches an address: an exact-IP entry beats every CIDR, and
a narrower CIDR beats a wider one ([how Pi-hole resolves clients](/guides/pihole#how-pi-hole-picks-a-clients-groups)).
`plan` reports what decides instead:

- `note (unmanaged-shadow)`: one of your IP or narrower-CIDR entries lies inside a managed range. Once the
  device's new address is verified, remove your entry (forti-pihole never removes it).
- `note (resolution)`: Pi-hole resolves the managed range to other groups than intended.
- `note (mac-client)`: an entry by MAC. Pi-hole cannot see the MAC of clients routed through the
  FortiGate, and any address or subnet entry covering the device takes precedence over it anyway.
- `note (missing-group)`: the mapped Pi-hole group does not exist; create it in Pi-hole.

If Pi-hole's query log shows the FortiGate (or a single address) as the client for everything, Pi-hole
cannot tell devices apart at all: the clients use the FortiGate's DNS proxy, or the policy to Pi-hole
applies source NAT. See [Pi-hole must see the real client address](/guides/pihole#pi-hole-must-see-the-real-client-address).

## A device is not filtered at all

Its queries do not reach Pi-hole: DNS over HTTPS or TLS, iCloud Private Relay, a hard-coded resolver or a
VPN. That is outside what DNS filtering can see; block it with FortiGate policies. A DNS redirect VIP to
Pi-hole only takes effect through a policy that uses it. See
[DNS that bypasses Pi-hole](/guides/pihole#dns-that-bypasses-pi-hole).

## forti-piholed refuses events

`forti-piholed --check-config` shows the listener, the allowlist and whether a token is stored.

| Answer | Cause |
|---|---|
| `403` | The sender is not in `allow_sources` (by default the profile FortiGate's resolved address) |
| `503` | No webhook token stored: run `forti-pihole events install` |
| `401` | The token in the FortiGate's webhook action is not the stored one (for example, `token_account` names another account) |
| `429` | The per-source rate limit |
| No connection at all | It listens on `127.0.0.1`: set `listen.address` to the management address |
