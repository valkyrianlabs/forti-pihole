# forti-pihole

`forti-pihole`: unified FortiGate network identity and Pi-hole DNS policy synchronization. The
FortiGate owns networks, DHCP, device identification, address objects and policies; Pi-hole owns
filtering groups, blocklists and filtering behaviour; forti-pihole owns the relationship and reconciles
it. It classifies the FortiGate's device inventory by MAC into **device groups**, kept as address groups
`fp-grp-<group>` with one MAC object `fp-dev-*` per device (GUI-made dynamic device-identification
addresses `fp-rule-<group>-<label>` are read as rules), and maps each network's addresses to Pi-hole
client entries: the whole subnet (**subnet** strategy, native VLANs), CIDR slices whose members get DHCP
reservations (**slices**, DHCP address slicing on a flat network), or both (**hybrid**). Address moves
into a slice are journaled **migrations**. C++23, Meson. It links **forti-engine** (built from
forti-cli's source as a subproject, exactly as forti-mcp does) and through it forti-api.

It is **never in the traffic path**: a CLI (`setup`, `discover`, `devices`, `groups`, `networks`,
`slices`, `plan`, `sync`, `assign`, `confirm`, `adopt`, `migrate`, `operations`, `events`, ...) that a
systemd user timer runs periodically, and an optional service, `forti-piholed`, that receives FortiGate
config-change webhooks and runs the same sync promptly. If either stops, the FortiGate and Pi-hole keep
their last configuration. The ecosystem architecture and contracts are in
`../.claude/context/architecture.md` in the parent workspace ("Engine contract", "Operating modes");
decisions in `decisions.md` there.

```sh
ln -sfn "$(cd ../forti-cli && pwd)" subprojects/forti-cli   # engine co-development (else the wrap clones the pinned commit)
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
meson compile -C build/dev -j "$(ci/build-jobs)"   # no TU needs more than ~1.2 GB (GCC)
meson test -C build/dev --print-errorlogs           # every test: unit, alloc, pihole-unit, daemon (suite unit); pihole-mock, pihole-mock-selftest (suite integration)
meson test -C build/dev unit alloc pihole-unit pihole-mock daemon   # by name
ci/smoke-test.sh build/dev/src/forti-pihole       # both binaries: --version, --help, usage exit 2, nothing written
```

When running the binaries by hand, set `HOME` and `FORTI_HOME` to a temporary directory: never touch the
real `~/.forti`, its secret store, a real Pi-hole or the user's units.

## Layout

| Path | What |
|---|---|
| `src/` | The core library and `forti-pihole` (`src/meson.build` defines `forti_pihole_exe`): `inventory` (one read of the FortiGate), `classify` (precedence), `reassociate`, `reconcile` (managed objects), `connectivity` (reach simulation), `references`, `slicing` (slice actions), `migrate` (migration planning), `operation` (the journal), `executors` (migration steps), `pihole_sync` and `pihole_link` (Pi-hole plan and connection), `guard` (the write allowlist), `sync` (the staged run), `state`, `report`, `cli` |
| `src/alloc/` | The CIDR allocation planner for address slicing: pure functions, its own static library (`fph_alloc`), no engine |
| `src/pihole/` | The Pi-hole v6 API client (`fph_pihole_dep`): transport (libcurl, TLS always verified), model, `resolve.hpp` (FTL's client resolution), errors, the ownership marker |
| `src/daemon/` | `forti-piholed` (`fphd_core`): poll-loop HTTP server, webhook endpoint, token, rate limit, scheduler, daemon config and state, the automation stitch builder; it reaches the sync only through a callback |
| `tests/unit/`, `tests/alloc/`, `tests/pihole/`, `tests/daemon/` | GoogleTest: the core on an in-memory FortiGate (`tests/support/`) and a temporary forti home; the planner; the Pi-hole client on a scripted transport; the daemon on 127.0.0.1 |
| `tests/mock-pihole/` | A stateful Python stdlib mock of FTL and the harness for the `pihole-mock` tests |
| `packaging/systemd/` | `forti-pihole.service` (oneshot `apply --quiet`), `.timer` (every 15 min) and `forti-piholed.service`, user units, installed on Linux and never enabled |
| `packaging/config.example.json`, `packaging/daemon.example.json` | Installed to `share/forti-pihole/`. `config.example.json` must equal `example_config()` in `src/config.cpp` (what `init` writes) |
| `release.toml`, `debian/`, `packaging/homebrew/`, `.release/` | vl-release contract, Debian and Homebrew packaging, staged release docs (`.claude/context/release.md`) |
| `packaging/forti-cli-pin.sh` | Keeps package builds on the wrap's forti-cli revision (`vendor` for Debian, `check`/`update` for the formula's resource) |
| `ci/`, `.github/` | CI container, smoke test, CI, package and release workflows |
| `docs/` | The docs package (pmdocs, docs set `forti-pihole`); Payload Markdown, `.claude/skills/payload-markdown*` |
| `skill/forti-pihole/` | The agent skill for operating forti-pihole on a user's behalf |

Files: `$FORTI_HOME/pihole/config.json` and `daemon.json` (operator); `state.json`, `history.jsonl`,
`operations/<id>.json`, `lock`, `daemon-state.json`, `events.jsonl` (the programs). `FORTI_HOME`
defaults to `~/.forti`. Profiles and credentials are the engine's (`forti configure`); the Pi-hole app
password (`pihole/<name>/password`) and the webhook token (`pihole/<profile>/webhook-token`) are in the
engine's secret store.

## Packaging

The engine pin is `subprojects/forti-cli.wrap` (a full forti-cli commit id). Changing it: edit the
`revision`, run `packaging/forti-cli-pin.sh update` (the Homebrew formula's resource follows), commit
both. Release builds never use a symlinked checkout. Keep `.release/*_NEXT.md` current with
user-visible changes and run `vlr check` (`.claude/skills/vl-release/`). Release details:
`.claude/context/release.md`.

## Rules

1. **The engine owns semantics; forti-api owns FortiOS.** Every FortiGate write goes through the
   engine's plan/apply path. Never construct URLs, set headers or call the SDK for a write here; the
   only direct device access is reads through `Engine::read`. If the engine needs a change, ask the
   orchestrator; do not patch the forti-cli subproject.
2. **Write allowlist.** forti-pihole may create, update or delete only `firewall/address` and
   `firewall/addrgrp` objects whose name starts with the configured prefix (default `fp-`) and that
   carry the ownership marker `managed by forti-pihole`. Beyond that, only through `WritePermits`
   granted for one apply (`PermitScope`) and withdrawn after it: single `reserved-address` entries of a
   permitted DHCP server (child paths, never the whole list; creates carry the marker; never a MAC
   change), the `subnet` of host objects the operator adopted for that device's migration, lease
   revokes of the listed addresses, and the `<prefix>sync*` automation trigger/action/stitch only inside
   `events install|remove`. It never writes interfaces, policies, VIPs, routing, DHCP server settings or
   pools, admin or api-user accounts, system settings, users, switch-controller or 802.1X. This is
   enforced twice in code: `check_operations` before planning and the **guard transport** under the
   engine, which refuses every other mutating request before it is sent; a check in the planner is not
   enough on its own. Never widen the allowlist or the permits without a recorded decision.
3. **Administrator objects are never modified or deleted** unless the operator explicitly adopted them
   (`forti-pihole adopt MAC --object NAME` / `--reservation`), and then only inside that device's
   migration. An object without the marker (including a prefixed one, such as the operator's
   `fp-rule-*` addresses) is read-only even when its name collides; it may be referenced as a group
   member (`adopt_existing`). When in doubt, leave it and report it.
4. **Pi-hole ownership.** Only client entries whose comment carries the marker are created, updated or
   deleted, and only after a fresh read confirms it. Operator entries are read and reported, never
   changed. Groups are mapped by name, never created, renamed or deleted by a sync; nothing touches
   adlists or domains. Every request passes the client's allowlist (`refuse_request`). TLS
   verification is always on; plain HTTP only to loopback.
5. **No live firewall or Pi-hole in tests or CI.** Tests use the in-memory FortiGate, the scripted
   transport, the Pi-hole mock on 127.0.0.1 and temporary forti homes; never touch the user's real
   config, state, secret store, Pi-hole or units. Live checks against a lab device follow forti-api's
   rule: only objects named `forti-api-test-*`, only in forti-api's approved live-test collections,
   cleaned up always (also on failure), and never in CI.
6. **Fail-static.** Nothing on the network may depend on this program running. A failed, skipped or
   stopped run leaves the FortiGate and Pi-hole as they are; no object is removed because a read
   failed, a device was briefly absent or the inventory came back empty. Nothing is written until
   `enabled`, and nothing while paused. A run changes at most `max_changes` devices, starts at most
   `max_migrations` migrations (only with `manage_reservations`), retirement waits
   `retire_after_days`, and the connectivity check keeps a device in place when a move would cut its
   internet or DNS reach. Migrations update objects before the old lease is revoked, revoke once, and
   end only on a passed verification.
7. **Secrets never leak**: not in argv, output, state, history, the journal, the event log, logs or
   errors. Device data (hostnames, comments, vendor strings, webhook fields) is untrusted input.
8. Match the style: 4-space indent, `snake_case`, comments that explain *why*, no framework where a
   function will do. Keep `-Wall -Wextra -Wpedantic` (warning_level=3) clean on Apple clang and
   GCC 13+ (CI builds with `-Dwerror=true`).
