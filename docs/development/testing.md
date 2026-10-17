---
title: Building and testing
navTitle: Testing
description: Build forti-pihole, run its tests, CI, and the rule for live-device checks.
order: 110
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

forti-pihole is C++23 built with Meson (1.3 or newer), tested with GCC 13 and newer and Apple Clang.
It needs libcurl, and GoogleTest for the tests. No test contacts a FortiGate.

:::toc[On this page]{depth="2" theme="compact"}
:::

## The engine: a pinned subproject

forti-pihole does not implement FortiOS semantics. It compiles forti-cli's command engine (`engine/`,
Meson dependency `forti-engine`) from source, as the subproject `subprojects/forti-cli`, and links it
statically, exactly as forti-mcp does. The engine brings forti-api, the header-only SDK, with it.

`subprojects/forti-cli.wrap` is the single pin: a full forti-cli commit id in `revision`. Meson clones
that commit at configure time. forti-api comes from a system install (`libforti-api-dev`, the
`forti-api` formula) when one is found, else from `subprojects/forti-api.wrap`.

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

Run `packaging/forti-cli-pin.sh update`: it points the Homebrew formula's `forti-cli` resource at the
new revision and computes its sha256.

#### Commit both files

Commit the wrap and the formula together.

:::

`packaging/forti-cli-pin.sh vendor` puts forti-cli at the pinned revision into `subprojects/forti-cli`
for the Debian build and refuses a symlinked checkout; `check --download` verifies the formula's
resource against the wrap and GitHub's archive.

## Tests

| Suite | What it runs |
|---|---|
| `unit` | GoogleTest over classification, precedence, reconciliation planning, the guard and the state files, with the engine on a scripted transport and a temporary forti home |

```bash
meson test -C build/dev --suite unit
```

`ci/smoke-test.sh` checks a built or installed binary offline: `--version` (with the engine revision),
`--help` listing every subcommand, a bad option exiting `2`, and that nothing was written to the forti
home.

:::callout[No live state in tests]{variant="info"}
Tests never touch your real forti home, secret store or systemd timer. They run against a scripted
transport and a temporary `FORTI_HOME`.
:::

## Live devices

Live checks against a lab FortiGate follow forti-api's rule, and are never part of CI:

- only objects whose names start with `forti-api-test-`,
- only in the collections forti-api approves for live tests,
- always cleaned up, also when a check fails.

Never point a development build at a production FortiGate, and never run `apply` from a test.

## CI

CI (`.github/workflows/ci.yml`) runs on every push to `main` and on pull requests. Each job builds
exactly once, unoptimized (`-O0`, warnings as errors), and runs every suite against that build:

- **Linux** (Ubuntu 24.04, GCC 13, in a disposable Podman container on the self-hosted runner,
  `ci/run-ci`): first shellcheck, `packaging/forti-cli-pin.sh check --download` and
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
```
