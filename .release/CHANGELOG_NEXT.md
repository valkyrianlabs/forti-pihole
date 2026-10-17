<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Program
- Initial release of forti-pihole, FortiGate and Pi-hole DNS policy synchronization:
  /usr/bin/forti-pihole with the commands setup, init, discover, devices (report), groups, networks,
  slices, plan, sync (apply), status, history, pause, resume, assign, confirm, adopt, migrate,
  operations, references and events.
- Device groups: classifies the FortiGate inventory by MAC (protected > assignment > pin > rule >
  default; privileged groups never inferred; GUI moves detected as pins) into address groups
  fp-grp-<group> with MAC objects fp-dev-*; fp-rule-* device-identification objects are read as
  rules.
- Allocation strategies per network: subnet (interface subnets as Pi-hole CIDR client entries),
  slices (DHCP reservations inside CIDR slices outside the dynamic pools), hybrid and observe; a
  CIDR allocation planner proposes slice sizes and placement (slices --propose).
- Migrations: journaled, resumable, reversible address moves in
  $FORTI_HOME/pihole/operations (Pi-hole entry, reservation, adopted objects, revoke of the old
  lease only, observe, verify); refused without the operator's adoption of administrator
  reservations and policy-source host objects, or when a VIP maps the old address.
- Pi-hole v6 client (FTL >= 6.7.0): app-password login stored in forti's secret store as
  pihole/<name>/password, TLS always verified, plain HTTP only to loopback; writes only client
  entries carrying the marker "managed by forti-pihole"; models FTL's client resolution to report
  shadowing operator entries.
- Write allowlist enforced before planning and by a guard transport under the engine: managed fp-*
  firewall/address and firewall/addrgrp objects; per-apply permits for single DHCP reserved-address
  entries, adopted host objects (subnet only), listed lease revokes, and the fp-sync automation
  stitch inside events install|remove.
- Nothing is written until "enabled": true; pause/resume; manage_reservations per network (off by
  default); max_changes, max_migrations, retire_after_days and a connectivity check bound every run.
- /usr/bin/forti-piholed: optional webhook receiver (POST /v1/fortigate/events, bearer token from
  the secret store, source allowlist, rate limit; GET /v1/health) and scheduler (debounce, periodic
  full reconcile, backoff, loop suppression); settings in $FORTI_HOME/pihole/daemon.json.
- forti-pihole --version and forti-piholed --version report the forti-cli engine revision and the
  forti-api version.
## Packaging
- The command engine is compiled in statically from forti-cli v0.5.0 (6a17b34), on the system
  libforti-api-dev (>= 1.2.0), with --wrap-mode=nodownload: the package build fetches nothing.
- systemd user units forti-pihole.service (oneshot apply --quiet), forti-pihole.timer (every 15
  minutes) and forti-piholed.service in /usr/lib/systemd/user, installed but never enabled;
  config.example.json and daemon.example.json in /usr/share/forti-pihole.
- Recommends forti-cli and valkyrianlabs-archive-keyring. Release build profile as forti-mcp: -O3,
  NDEBUG, no LTO or -g, section garbage collection; every test suite runs against that build unless
  nocheck. amd64 only.
