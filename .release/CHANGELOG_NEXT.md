<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Program
- Initial release of forti-pihole: /usr/bin/forti-pihole with the subcommands init, report,
  plan, apply, assign, confirm, status and history. It reads the FortiGate device inventory and DHCP data
  over the FortiOS REST API, classifies devices by MAC with operator rules, and reconciles MAC
  address objects (fp-dev-*) and per-segment address groups (fp-seg-*); dynamic
  device-identification addresses (fp-rule-*) are read as rules.
- Precedence protected > operator assignment (GUI move or `assign`) > rule > default; privileged
  segments are never inferred; ambiguous matches go to the default segment. Randomized-MAC
  reassociation candidates wait for `confirm`.
- Writes only prefixed firewall/address and firewall/addrgrp objects that carry the marker comment
  "managed by forti-pihole", enforced by a guard transport under the engine; never interfaces,
  policies, routing, DHCP, users, admins, switch-controller or system settings.
- Connectivity check: each device's internet (TCP/443) and DNS (UDP/53) reach is simulated against the
  policies before and after a move; a move that would cut it off is refused for that device. At most
  max_changes devices (default 50, `apply --max-changes`) change per run; empty inventories never
  retire anything.
- Configuration in $FORTI_HOME/pihole/config.json; state.json and history.jsonl beside it.
- forti-pihole --version reports the forti-cli engine revision and the forti-api version.
## Packaging
- The command engine is compiled in statically from forti-cli v0.4.2 (468f9e1), on the system
  libforti-api-dev (>= 1.1.1), with --wrap-mode=nodownload: the package build fetches nothing.
- systemd user units forti-pihole.service (oneshot apply --quiet) and forti-pihole.timer (every
  15 minutes) in /usr/lib/systemd/user, installed but never enabled; an example configuration in
  /usr/share/forti-pihole.
- Recommends forti-cli and valkyrianlabs-archive-keyring. Release build profile as forti-mcp: -O3,
  NDEBUG, no LTO or -g, section garbage collection; every test suite runs against that build unless
  nocheck. amd64 only.
