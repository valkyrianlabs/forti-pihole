<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# FortiGate ↔ Pi-hole synchronization: native subnets and DHCP address slicing

forti-pihole is new: unified FortiGate network identity and Pi-hole DNS policy synchronization. The
FortiGate keeps owning networks, DHCP, device identification and policies; Pi-hole keeps owning
filtering groups and blocklists; forti-pihole owns the relationship and keeps it true. It is never in
the traffic path: if it stops, both keep their last configuration.

## Device groups on both sides

- Every device the FortiGate sees is classified into a device group, kept as the address group
  `fp-grp-<group>` with one MAC object `fp-dev-*` per device, ready for your own policies, and mapped
  to a Pi-hole group by name.
- Precedence: protected, then `assignments` in the configuration, then pins (`forti-pihole assign`, a
  confirmed reassociation, or a move in the FortiGate GUI, which is detected), then rules (config
  rules and GUI-made `fp-rule-<group>-<label>` device-identification objects), then the default group.
  Privileged groups are never entered by a rule; ambiguous matches go to the default group.

## Two strategies, chosen per network

- **subnet** for native VLANs: the interface subnet maps to the network group's Pi-hole group as a
  CIDR client entry. Nothing on the FortiGate changes.
- **slices** for a flat network: members of a group get DHCP reservations inside a CIDR slice that
  maps to their Pi-hole group. Devices keep the interface's mask and gateway; a slice is an allocation
  and DNS classification unit, not a routed subnet and not Layer-2 isolation.
- **hybrid** puts slices inside a real VLAN and maps the rest of the VLAN to the network group (Pi-hole
  resolves the longest matching prefix); **observe** only reports.
- `forti-pihole slices --propose` sizes and places slices outside the DHCP pools for the current
  members, and lists ranked options when there is not enough room.

## Safe address moves

Moving a device into its slice is a journaled migration: Pi-hole entry, reservation, adopted
administrator objects updated before the old lease is revoked (so an old address never keeps
privileges), a single revoke of that device's lease, then observation and verification of the lease,
firewall reach and Pi-hole group. Moves are refused when a VIP forwards to the old address, the target
is in use, or an administrator object would need to change and is not adopted
(`forti-pihole adopt MAC --object NAME --reservation`). `migrate MAC --dry-run` shows the steps;
`operations show|resume|rollback ID` follow up. A device that does not renew leaves the move waiting,
never revoked again.

## Look before it writes

- `forti-pihole setup` connects the FortiGate and Pi-hole (it stores the Pi-hole v6 app password in
  forti's secret store), discovers networks and suggests a strategy and Pi-hole group mappings; it
  writes nothing on either system.
- `discover`, `devices`, `groups`, `networks`, `slices`, `plan` and `references` are read-only.
- Nothing is written until `"enabled": true`; `forti-pihole pause` stops all writes; reservations and
  migrations stay off per network until `"manage_reservations": true`.
- Every FortiGate write goes through the forti engine (validation, verification, audit, rollback
  plan) and honours the profile's mode: a guarded profile waits for `forti approve`.

## A narrow write surface

A guard transport under the engine refuses every FortiGate write outside the allowlist before it is
sent: managed `fp-*` address objects and groups, single DHCP reservation entries (never the whole list),
adopted host objects, lease revokes of the listed addresses, and the automation stitch inside
`events install|remove`. In Pi-hole only client entries with the comment `managed by forti-pihole` are
written; your own entries are read and reported (an exact-IP entry that shadows a managed range, a MAC
entry that cannot match routed clients), and groups are never created by a sync.

## Optional runtime service

`forti-piholed` receives FortiGate config-change webhooks (`forti-pihole events install --url
http://HOST:8735` creates the automation stitch and its bearer token) and runs a sync promptly, plus a
full one every 15 minutes, with debounce, backoff and loop prevention. It runs as a systemd user unit
or under `brew services`. It speaks plain HTTP: bind it to the management network.

Requirements: a forti profile (`forti configure`, from forti-cli) and Pi-hole v6 with FTL 6.7.0 or
newer. forti-pihole is not VLAN tagging, RADIUS or 802.1X, and creating a VLAN interface does not make
an access point or switch tag traffic.
