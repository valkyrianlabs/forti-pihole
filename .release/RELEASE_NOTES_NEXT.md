<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Device segments in native FortiOS objects

forti-vlan-mac is new: a FortiGate companion that keeps your device inventory sorted into logical
segments, as FortiOS address objects your own policies can use.

- **Segments are address groups.** Every device the FortiGate has seen gets a MAC address object
  (`mvlan-dev-*`) in the group of its segment (`mvlan-seg-<segment>`). Rules come from dynamic
  device-identification addresses you create in the GUI (`mvlan-rule-<segment>-<label>`) and from
  `config.json` (vendor, family, type, OS, hostname, MAC prefix).
- **You stay in charge.** Moving a device to another group in the GUI, or `forti-vlan-mac assign`,
  is an assignment the next run keeps. Protected devices are never moved, privileged segments are
  never inferred from a rule, and an ambiguous match goes to the default segment. A device that seems
  to be back with a new randomized MAC is linked only after `forti-vlan-mac confirm`.
- **Look before it writes.** `forti-vlan-mac init` writes a starting configuration; `report` and `plan`
  change nothing; `apply` makes the planned changes through the forti engine (validation,
  verification, audit, rollback plan), as the profile's mode allows: a guarded profile waits for
  `forti approve`.
- **No device loses its route.** Before a move, the policies are simulated for each device's internet
  and DNS traffic; a move that would cut a device off is refused for that device. At most 50 devices
  change per run by default (`--max-changes N`); the rest follow in later runs.
- **Never in the traffic path.** A systemd user timer runs `apply --quiet` every 15 minutes once you
  enable it (`systemctl --user enable --now forti-vlan-mac.timer`). If it stops, the FortiGate keeps
  what it has.
- **A narrow write surface.** Only prefixed address objects and groups that carry the marker
  `managed by forti-vlan-mac` are ever written; every other write is refused before it is sent.
  Interfaces, policies, routing, DHCP, users, admins and switches are never touched, and objects you
  created are never changed or deleted.

Not in this release: assigning segments their own DHCP ranges (under evaluation). forti-vlan-mac is
not VLAN tagging, RADIUS or layer-2 isolation.
