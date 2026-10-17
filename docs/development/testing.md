---
title: Building and testing
navTitle: Testing
description: Build forti-pihole, run every test suite, the pinned engine, CI, and the rule for live devices.
order: 200
status: published
tags:
  - development
---

# Building and testing

Build forti-pihole for development, run its tests, and keep package builds on the pinned engine.

```bash
meson setup build/dev -Dtests=enabled --buildtype=debugoptimized
meson compile -C build/dev -j "$(ci/build-jobs)"
meson test -C build/dev --print-errorlogs
ci/smoke-test.sh build/dev/src/forti-pihole
```

forti-pihole is C++23 built with Meson (1.3 or newer), tested with GCC 13 and newer and Apple Clang. It
needs libcurl, GoogleTest for the tests, and `python3` for the Pi-hole mock. No test contacts a
FortiGate or a Pi-hole.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The engine: a pinned subproject

forti-pihole does not implement FortiOS semantics. It compiles forti-cli's command engine (`engine/`,
Meson dependency `forti-engine`) from source, as the subproject `subprojects/forti-cli`, and links it
statically, exactly as forti-mcp does. The engine brings forti-api, the header-only SDK, with it.

`subprojects/forti-cli.wrap` is the single pin: a full forti-cli commit id in `revision`. Meson clones that
commit at configure time. forti-api comes from a system install (`libforti-api-dev`, the `forti-api`
formula) when one is found, else from `subprojects/forti-api.wrap`.

For co-development, replace the subprojects with symlinks to sibling checkouts; Meson then uses them
instead of downloading:

```bash
ln -sfn "$(cd ../forti-cli && pwd)" subprojects/forti-cli
ln -sfn "$(cd ../forti-api && pwd)" subprojects/forti-api
```

### Changing the pin

:::steps

#### Edit the wrap

Edit `revision` in `subprojects/forti-cli.wrap`.

#### Update the formula

Run `packaging/forti-cli-pin.sh update`: it points the Homebrew formula's `forti-cli` resource at the new
revision and computes its sha256.

#### Commit both files

Commit the wrap and the formula together.

:::

`packaging/forti-cli-pin.sh vendor` puts forti-cli at the pinned revision into `subprojects/forti-cli`
for the Debian build and refuses a symlinked checkout; `check --download` verifies the formula's resource
against the wrap and GitHub's archive.

## The code

| Path | What |
|---|---|
| `src/` | The core: inventory, classification, reconciliation, slicing, migrations and their executors, the Pi-hole sync, the guard transport, state, the CLI |
| `src/alloc/` | The CIDR allocation planner: pure functions, its own library |
| `src/pihole/` | The Pi-hole v6 API client: transport, model, resolution, errors |
| `src/daemon/` | `forti-piholed`: HTTP server, webhook, token, scheduler, state, the automation stitch |

## Tests

| Test | Suite | What it runs |
|---|---|---|
| `unit` | `unit` | Classification, precedence, reconciliation, the guard, slicing, migrations, the Pi-hole sync and the CLI, with the engine on an in-memory FortiGate and a temporary forti home |
| `alloc` | `unit` | The allocation planner: CIDR arithmetic, proposals, conflicts, alternatives, household scenarios |
| `pihole-unit` | `unit` | The Pi-hole client on a scripted transport: model, resolution, transport rules, client |
| `daemon` | `unit` | `forti-piholed`: HTTP parsing, authentication, scheduler, state, stitch operations, and real sockets on `127.0.0.1` only |
| `pihole-mock` | `integration` | The real libcurl transport and client against `tests/mock-pihole`, a stateful Python mock of FTL on `127.0.0.1` |
| `pihole-mock-selftest` | `integration` | Keeps the mock honest about the FTL behaviour the client depends on |

```bash
meson test -C build/dev --suite unit
meson test -C build/dev --suite integration
meson test -C build/dev unit alloc pihole-unit pihole-mock daemon
```

The mock harness also checks, across the whole run, that every Pi-hole session opened was closed, that
no request renamed, changed or deleted a group, and that no password or session id ever appeared in a
request path. The `daemon` test checks the stitch operations against forti-api's FortiOS 7.4.8 schema
when a forti-api source checkout provides it (`FPHD_SCHEMA_DIR`).

`ci/smoke-test.sh` checks a built or installed `forti-pihole` and `forti-piholed` offline: `--version`
(with the engine revision), `--help`, a bad option exiting `2`, and that nothing was written to the forti
home.

:::callout[No live state in tests]{variant="info"}
Tests never touch your real forti home, secret store, Pi-hole or systemd units. They run against an
in-memory FortiGate, a scripted or mocked Pi-hole on `127.0.0.1`, and a temporary `FORTI_HOME`. When you
run the binaries by hand during development, set `HOME` and `FORTI_HOME` to a temporary directory.
:::

## Live devices

Live checks against a lab FortiGate follow forti-api's rule, and are never part of CI:

- only objects whose names start with `forti-api-test-`,
- only in the collections forti-api approves for live tests,
- always cleaned up, also when a check fails.

Never point a development build at a production FortiGate or Pi-hole, and never run `sync` from a test.

## CI

CI (`.github/workflows/ci.yml`) runs on every push to `main` and on pull requests. Each job builds exactly
once, unoptimized (`-O0`, warnings as errors), and runs every suite against that build:

- **Linux** (Ubuntu 24.04, GCC 13, in a disposable Podman container on the self-hosted runner,
  `ci/run-ci`): shellcheck, `packaging/forti-cli-pin.sh check --download` and
  `pmdocs validate --source forti-pihole`; then the build with AddressSanitizer and
  UndefinedBehaviorSanitizer, every suite, and `ci/smoke-test.sh`. A skipped test fails the job.
- **macOS** (Apple Clang): the same build without sanitizers, the same suites and the smoke test.

The release build is a different configuration and is tested as built: `-O3`, NDEBUG, no LTO or `-g`.
`.github/workflows/package.yml` (on demand) and `.github/workflows/release.yml` (on a tag) build the
Debian package and the Homebrew formula this way, install the `.deb` into a stock Ubuntu 24.04, run the
smoke test there, and check that the systemd user units are installed and not enabled.

## Docs

The docs package (`docs/`, docs set `forti-pihole`) is validated in CI and published by the release
workflow:

```bash
pmdocs validate --source forti-pihole
python3 .claude/skills/payload-markdown/scripts/check_payload_markdown_doc.py docs/**/*.md
```
