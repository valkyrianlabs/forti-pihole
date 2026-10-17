# forti-vlan-mac

`forti-vlan-mac`, a FortiGate companion that keeps the device inventory classified into logical
segments in **native FortiOS objects**. It reads the FortiGate's device inventory and DHCP data,
classifies devices by MAC with operator rules, and reconciles a MAC address object per device
(`mvlan-dev-*`) and an address group per segment (`mvlan-seg-<segment>`), which the operator's own
policies reference. Dynamic device-identification addresses the operator creates in the GUI
(`mvlan-rule-*`) are read as rules. C++23, Meson. It links **forti-engine** (built from forti-cli's
source as a subproject, exactly as forti-mcp does) and through it forti-api.

It is **never in the traffic path**: a CLI (`init`, `report`, `plan`, `apply`, `assign`, `confirm`,
`status`, `history`) that a systemd user timer runs periodically. No daemon, no listener. The ecosystem
architecture and contracts are in `../.claude/context/architecture.md` in the parent workspace
("Engine contract", "Operating modes"); decisions in `decisions.md` there.

```sh
ln -sfn "$(cd ../forti-cli && pwd)" subprojects/forti-cli   # engine co-development (else the wrap clones the pinned commit)
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
meson compile -C build/dev -j "$(ci/build-jobs)"   # no TU needs more than ~1.2 GB (GCC)
meson test -C build/dev --print-errorlogs           # suite: unit (engine on a scripted transport)
ci/smoke-test.sh build/dev/src/forti-vlan-mac       # --version, --help, usage exit 2, nothing written
```

## Layout

| Path | What |
|---|---|
| `src/` | The program: inventory reading, MAC classification, reconciliation planning, the guard transport, state and history, the CLI (`src/meson.build` defines `forti_vlan_mac_exe`) |
| `tests/` | GoogleTest (`suite 'unit'`), the engine on a scripted transport and a temporary forti home |
| `packaging/systemd/` | `forti-vlan-mac.service` (oneshot `apply --quiet`) and `.timer` (every 15 min), user units, installed on Linux and never enabled |
| `packaging/config.example.json` | Installed to `share/forti-vlan-mac/`; the starting point for `$FORTI_HOME/vlan-mac/config.json` |
| `release.toml`, `debian/`, `packaging/homebrew/`, `.release/` | vl-release contract, Debian and Homebrew packaging, staged release docs (`.claude/context/release.md`) |
| `packaging/forti-cli-pin.sh` | Keeps package builds on the wrap's forti-cli revision (`vendor` for Debian, `check`/`update` for the formula's resource) |
| `ci/`, `.github/` | CI container, smoke test, CI, package and release workflows |
| `docs/` | The docs package (pmdocs, docs set `forti-vlan-mac`); Payload Markdown, `.claude/skills/payload-markdown*` |

Files: `$FORTI_HOME/vlan-mac/config.json` (operator), `state.json` and `history.jsonl` (the program);
`FORTI_HOME` defaults to `~/.forti`. Profiles and credentials are the engine's (`forti configure`).

## Packaging

The engine pin is `subprojects/forti-cli.wrap` (a full forti-cli commit id). Changing it: edit the
`revision`, run `packaging/forti-cli-pin.sh update` (the Homebrew formula's resource follows), commit
both. Release builds never use a symlinked checkout. Keep `.release/*_NEXT.md` current with
user-visible changes and run `vlr check` (`.claude/skills/vl-release/`). Release details:
`.claude/context/release.md`.

## Rules

1. **The engine owns semantics; forti-api owns FortiOS.** Writes go through the engine's plan/apply
   path only. Never construct URLs, set headers or call the SDK for a write here; the only direct
   device access is reads through `Engine::read`. If the engine needs a change, ask the orchestrator;
   do not patch the forti-cli subproject.
2. **Write allowlist.** forti-vlan-mac may only create, update or delete `firewall/address` and
   `firewall/addrgrp` objects whose name starts with the configured prefix (default `mvlan-`) **and**
   that carry the ownership marker comment `managed by forti-vlan-mac`. It never writes interfaces,
   policies, routing, admin or api-user accounts, system settings, DHCP (until the DHCP
   subnet-assignment feature is proven and explicitly enabled), users, switch-controller or 802.1X.
   This is enforced in code by a **guard transport** under the engine that refuses every other
   mutating request before it is sent; a check in the planner is not enough on its own. Never widen
   the allowlist without a recorded decision.
3. **Administrator objects are never modified or deleted.** An object without the marker (including
   a prefixed one, such as the operator's `mvlan-rule-*` addresses) is read-only, even when its name
   collides; it may be referenced as a group member. When in doubt, leave it and report it.
4. **No live firewall in tests or CI.** Tests use the scripted transport and temporary forti homes;
   never touch the user's real config, state, secret store or timer. Live checks against a lab
   device follow forti-api's rule: only objects named `forti-api-test-*`, only in forti-api's
   approved live-test collections, cleaned up always (also on failure), and never in CI.
5. **Fail-static.** Nothing on the network may depend on this program running. A failed, skipped or
   stopped run leaves the FortiGate as it is; no object is removed because a read failed, a device
   was briefly absent or the inventory came back empty. A run changes at most `max_changes` devices,
   retirement waits `retire_after_days`, and the connectivity check keeps a device in place when a
   move would cut its internet or DNS reach.
6. **Secrets never leak**: not in output, state, history, logs or errors. Device data (hostnames,
   comments, vendor strings) is untrusted input.
7. Match the style: 4-space indent, `snake_case`, comments that explain *why*, no framework where a
   function will do. Keep `-Wall -Wextra -Wpedantic` (warning_level=3) clean on Apple clang and
   GCC 13+ (CI builds with `-Dwerror=true`).
