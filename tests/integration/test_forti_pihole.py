#!/usr/bin/env python3
"""End-to-end tests of the real `forti-pihole` (and `forti-piholed`) binaries: the real forti-engine
(plan/apply, audit, rollback plans) over libcurl and verified TLS against forti-cli's stateful mock
FortiOS, and the real Pi-hole client against tests/mock-pihole. The unit suites drive an in-memory
gateway; this one checks what actually reaches a device.

    FPH_BINARY=build/src/forti-pihole FPH_DAEMON=build/src/forti-piholed \\
    FORTI_MOCK_DIR=subprojects/forti-cli/tests/mock-fortios python3 tests/integration/test_forti_pihole.py

Every test asserts, besides its own outcome, that every write any binary sent stayed inside
forti-pihole's write allowlist, and that the API key, the Pi-hole password and the webhook token never
appear in any output or any file the binaries wrote (forti home, engine state, plans, audit, history,
operation journals).
"""

from __future__ import annotations

import json
import os
import re
import signal
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fph_world import (ADMIN_PASSWORD, API_KEY, APP_PASSWORD, MARKER, SKIP, World, device, free_port,  # noqa: E402
                       require_tools, wait_until)

BINARY = os.environ.get("FPH_BINARY", "")
DAEMON = os.environ.get("FPH_DAEMON", "")
TOKEN = "it-webhook-token-5d2c8e0a7f1b3946c0de"     # distinctive, for the leak check

STICK = "00:00:5e:00:53:03"       # an administrator's reservation and a privileged host object
STICK2 = "00:00:5e:00:53:08"      # no reservation: a migration creates one
PLUG = "00:00:5e:00:53:01"        # default group, stays put
OTHER = "00:00:5e:00:53:20"       # an unrelated administrator reservation, never touched
SLICE = "192.168.1.208/28"
CONFIG = {
    "enabled": True,
    "groups": [{"name": "tvs", "pihole_group": "TVs"}, {"name": "default"}],
    "rules": [{"name": "sticks", "group": "tvs", "match": {"vendor": "Amazon", "family": "Fire TV*"}}],
    "networks": [{"interface": "internal", "mode": "slices", "group": "default", "manage_reservations": False,
                  "slices": [{"group": "tvs", "cidr": SLICE}]}],
}

# forti-pihole's write allowlist (AGENTS.md rule 2, plus the reservation/adoption/revoke permits),
# as the paths that may see a non-GET at all.
ALLOWED_WRITES = [
    ("POST", re.compile(r"^cmdb/firewall/address$")),
    ("PUT|DELETE", re.compile(r"^cmdb/firewall/address/fp-[^/]+$")),
    ("POST", re.compile(r"^cmdb/firewall/addrgrp$")),
    ("PUT|DELETE", re.compile(r"^cmdb/firewall/addrgrp/fp-[^/]+$")),
    ("POST", re.compile(r"^cmdb/system\.dhcp/server/\d+/reserved-address$")),
    ("PUT|DELETE", re.compile(r"^cmdb/system\.dhcp/server/\d+/reserved-address/\d+$")),
    ("POST", re.compile(r"^monitor/system/dhcp/revoke$")),
]
ADOPTABLE = {"Stick IP"}     # the only administrator object a test adopts
ALL_WRITES: list[str] = []   # across every test, for the summary


def seed(w: World) -> None:
    """A flat home LAN: internal 192.168.1.0/24 with DHCP .100-.200, a WAN, a LAN-out policy."""
    w.add_row("system/interface", "internal", type="physical", role="lan", ip="192.168.1.99 255.255.255.0")
    w.add_row("system/interface", "wan1", type="physical", role="wan", ip="203.0.113.2 255.255.255.0")
    w.add_row("firewall.service/custom", "ALL", protocol="IP")
    w.add_row("firewall.service/custom", "DNS", protocol="TCP/UDP/SCTP", **{"tcp-portrange": "53", "udp-portrange": "53"})
    w.mock.add_address("all", "0.0.0.0 0.0.0.0")
    # A device-identification object the operator made: forti-pihole resolves it per mkey.
    w.mock.add_address("dyn-plugs", "0.0.0.0 0.0.0.0", type="dynamic", **{"sub-type": "device-identification", "hw-vendor": "TP-Link"})
    w.mock.dynamic["dyn-plugs"] = [PLUG]  # type: ignore[attr-defined]
    w.mock.add_policy(policyid=2, name="LAN out", action="accept", srcintf=[{"name": "internal"}], dstintf=[{"name": "wan1"}],
                      srcaddr=[{"name": "all"}], dstaddr=[{"name": "all"}], service=[{"name": "ALL"}])
    w.mock.add_dhcp_server(1, interface="internal", **{
        "default-gateway": "192.168.1.99", "netmask": "255.255.255.0",
        "ip-range": [{"id": 1, "start-ip": "192.168.1.100", "end-ip": "192.168.1.200"}],
        "reserved-address": [{"id": 40, "ip": "192.168.1.150", "mac": OTHER, "description": "printer"}]})
    for mac, ip, extra in ((PLUG, "192.168.1.101", {"hardware_vendor": "TP-Link", "hardware_family": "Plug", "hostname": "HS103"}),
                           (STICK, "192.168.1.110", {"hardware_vendor": "Amazon", "hardware_family": "Fire TV Stick"})):
        w.mock.inventory.append(device(mac, ip, **extra))  # type: ignore[attr-defined]
        w.mock.add_lease(ip, mac)
    w.pihole.state.add_group("TVs", "streaming devices", True)
    w.write_config(CONFIG)


def renew_on_revoke(w: World) -> None:
    """A revoked device asks again at once: its reservation if it has one, else back to its old address."""
    previous: dict[str, str] = {}

    def hook(ips: list[str]) -> None:
        with w.mock.lock:
            for entry in w.mock.inventory:  # type: ignore[attr-defined]
                mac = entry["mac"]
                if entry["ipv4_address"] not in ips or any(lease["mac"] == mac for lease in w.mock.device.leases):
                    continue
                reserved = next((r["ip"] for r in w.mock.reservations(1).values() if r["mac"] == mac), None)
                ip = reserved or previous.get(mac, entry["ipv4_address"])
                previous[mac] = entry["ipv4_address"]
                w.mock.add_lease(ip, mac)
                entry["ipv4_address"] = ip
    w.mock.on_revoke = hook  # type: ignore[attr-defined]


class FortiPiholeTest(unittest.TestCase):

    def setUp(self) -> None:
        self.w = World(BINARY, DAEMON).__enter__()
        self.addCleanup(self.w.__exit__, None, None, None)
        self.assertTrue(self.w.env["FORTI_HOME"].startswith(str(self.w.sb.root)))
        self.assertEqual(self.w.env["FORTI_SECRET_STORE"], "file")
        seed(self.w)
        renew_on_revoke(self.w)

    def tearDown(self) -> None:
        self.check_allowlist()
        self.check_no_secrets()

    # ---- run-wide checks (scenarios 5 and 6) ----

    def check_allowlist(self) -> None:
        for request in self.w.fortios_writes():
            line = f"{request.method} {request.api}"
            ALL_WRITES.append(line)
            self.assertTrue(request.authorized, line)
            allowed = any(re.fullmatch(methods, request.method) and pattern.match(request.api) for methods, pattern in ALLOWED_WRITES)
            if request.api.startswith("cmdb/firewall/address/") and request.method == "PUT":
                name = request.api.removeprefix("cmdb/firewall/address/")
                allowed = allowed or name.replace("%20", " ") in ADOPTABLE
            self.assertTrue(allowed, f"write outside the allowlist: {line} {request.body}")
            if request.method == "POST" and request.api in ("cmdb/firewall/address", "cmdb/firewall/addrgrp"):
                body = request.json()
                self.assertTrue(body["name"].startswith("fp-"), body)
                self.assertIn(MARKER, body.get("comment", ""), body)
            self.assertNotRegex(request.api, r"^cmdb/system\.dhcp/server(/\d+)?$", "a whole DHCP server was written")
        # Pi-hole: only managed client entries (never groups, never a batch delete).
        for request in self.w.pihole_writes():
            self.assertTrue(request["path"].startswith("/api/clients"), request)

    def check_no_secrets(self) -> None:
        texts = self.w.outputs + [self.w.sandbox_text()]
        for request in self.w.mock.requests:
            texts.append(request.path + request.body)
        for text in texts:
            for secret in (API_KEY, APP_PASSWORD, ADMIN_PASSWORD, TOKEN):
                self.assertNotIn(secret, text)

    # ---- helpers ----

    def ok(self, *args: str, code: int = 0) -> Any:
        result = self.w.run(*args)
        self.assertEqual(result.code, code, f"forti-pihole {' '.join(args)}\n{result.out}\n{result.err}")
        return result

    def writes(self) -> list[str]:
        return [f"{r.method} {r.api}" for r in self.w.fortios_writes()]

    def reservation(self, entry_id: int) -> dict[str, Any] | None:
        return self.w.mock.reservations(1).get(entry_id)

    def operation(self, op_id: str) -> dict[str, Any]:
        return self.ok("operations", "show", op_id, "--json").json()  # type: ignore[no-any-return]

    def adopt_and_migrate_stick(self) -> str:
        """Adopt the stick's reservation and host object, migrate it; returns the operation id."""
        self.ok("adopt", STICK, "--reservation", "--object", "Stick IP")
        result = self.ok("migrate", STICK)
        found = re.search(r"^(\S+) done$", result.out, re.M)
        self.assertIsNotNone(found, result.out)
        assert found
        return found.group(1)

    def privileged_stick(self) -> None:
        """The stick holds an administrator's reservation, and a host object for its address sits in a
        group that a policy grants extra access from."""
        self.w.mock.set_attr("system.dhcp/server", "1", "reserved-address", [
            *self.w.mock.device.tables["system.dhcp/server"]["1"]["reserved-address"],
            {**self.w.mock.reservations(1)[40], "id": 12, "q_origin_key": 12, "ip": "192.168.1.110", "mac": STICK,
             "description": "living room stick"}])
        self.w.mock.add_address("Stick IP", "192.168.1.110/32")
        self.w.add_row("firewall/addrgrp", "Important", member=[{"name": "Stick IP"}])
        self.w.mock.add_policy(policyid=17, name="Important Devices", action="accept", srcintf=[{"name": "internal"}],
                               dstintf=[{"name": "wan1"}], srcaddr=[{"name": "Important"}], dstaddr=[{"name": "all"}],
                               service=[{"name": "ALL"}])
        # Policy 17 must come first (FortiOS evaluates in sequence; the mock lists by insertion).
        with self.w.mock.lock:
            table = self.w.mock.device.tables["firewall/policy"]
            first = {"17": table.pop("17")}
            first.update(table)
            table.clear()
            table.update(first)

    # ---- scenario 1 ----

    def test_plan_and_devices_are_read_only(self) -> None:
        plan = self.ok("plan")
        self.assertIn("create group fp-grp-tvs", plan.out)
        self.assertIn(f"create {SLICE} -> TVs", plan.out)
        self.assertIn(f"move {STICK}", plan.out)
        self.assertIn("192.168.1.110 -> 192.168.1.208", plan.out)
        planned = self.ok("plan", "--json").json()
        self.assertEqual(planned["status"], "planned")
        self.assertEqual([c["cidr"] for c in planned["pihole"]["changes"]], [SLICE])
        devices = self.ok("devices", "-v")
        self.assertIn(STICK, devices.out)
        self.assertIn(PLUG, devices.out)
        self.ok("devices", "--json")
        self.ok("networks")
        self.ok("groups")
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.w.pihole_writes(), [])
        self.assertEqual(self.w.pihole_clients(), {})
        # The dynamic object was resolved through the monitor, one mkey at a time.
        self.assertTrue(any(r.api == "monitor/firewall/address-dynamic" and r.param("mkey") == "dyn-plugs" for r in self.w.mock.requests))
        # Inspecting records nothing either: no state, no history, no engine plan or audit entry.
        self.assertFalse((self.w.pihole_dir / "state.json").exists())
        self.assertEqual(self.w.history(), [])
        self.assertEqual(self.w.audit(), [])
        # Pi-hole sessions were all closed again.
        self.assertEqual(self.w.pihole.totals["logins"], self.w.pihole.totals["closed"])

    # ---- scenario 2 ----

    def test_sync_creates_managed_objects_then_is_idempotent(self) -> None:
        first = self.ok("sync")
        self.assertIn("objects       applied", first.out)
        addresses = self.w.mock.table("firewall/address")
        groups = self.w.mock.table("firewall/addrgrp")
        managed = sorted(n for n in addresses if n.startswith("fp-"))
        self.assertEqual(len(managed), 2, managed)         # one MAC object per device on the network
        for name in managed:
            self.assertEqual(addresses[name]["type"], "mac")
            self.assertIn(MARKER, addresses[name]["comment"])
        stick_object = next(n for n in managed if addresses[n]["macaddr"] == [{"macaddr": STICK}])
        self.assertEqual(sorted(n for n in groups if n.startswith("fp-grp-")), ["fp-grp-default", "fp-grp-tvs"])
        self.assertEqual(groups["fp-grp-tvs"]["member"], [{"name": stick_object}])
        self.assertIn(MARKER, groups["fp-grp-tvs"]["comment"])
        # Administrator objects are untouched.
        self.assertEqual(addresses["all"]["comment"], "")
        self.assertNotIn("Stick IP", addresses)
        # Writes went through the engine: a plan, an apply, an audit record, a rollback plan.
        writes = self.writes()
        self.assertTrue(writes and all(w.startswith("POST cmdb/firewall/addr") for w in writes), writes)
        audit = self.w.audit()
        self.assertTrue(audit, "the engine recorded no audit entry")
        self.assertTrue(all(entry.get("actor") == "forti-pihole" for entry in audit), audit)
        history = self.w.history()
        objects = [h for h in history if h["stage"] == "objects"]
        self.assertEqual([h["status"] for h in objects], ["applied"])
        self.assertTrue(objects[0]["plan_id"] and objects[0]["rollback_plan"], objects)
        plans = list((Path(self.w.env["FORTI_STATE_DIR"])).rglob(f"*{objects[0]['plan_id']}*"))
        self.assertTrue(plans, "the engine's plan file is not in the sandbox state directory")
        # The managed Pi-hole entry for the slice, in the TVs group, carrying the marker.
        clients = self.w.pihole_clients()
        tvs = next(g["id"] for g in self.w.pihole.state.groups if g["name"] == "TVs")
        self.assertEqual(sorted(clients), [SLICE])
        self.assertEqual(clients[SLICE]["groups"], [tvs])
        self.assertIn(MARKER, clients[SLICE]["comment"])
        # manage_reservations is false: no DHCP write, no migration.
        self.assertFalse(any("dhcp" in w for w in writes), writes)
        self.assertEqual(self.reservation(40)["description"], "printer")  # type: ignore[index]

        # A second sync finds everything in place and writes nothing anywhere.
        self.w.mock.clear_requests()
        pihole_before = len(self.w.pihole_writes())
        second = self.ok("sync", "--json").json()
        self.assertEqual(second["status"], "applied")
        self.assertEqual({s["stage"]: s["status"] for s in second["stages"]},
                         {"objects": "in-sync", "pihole": "in-sync", "reservations": "in-sync", "migrations": "in-sync"})
        self.assertEqual(self.writes(), [])
        self.assertEqual(len(self.w.pihole_writes()), pihole_before)
        self.assertEqual(len(self.w.audit()), len(audit))
        self.assertEqual(len([h for h in self.w.history() if h["stage"] == "objects"]), 1)

    # ---- scenario 3 ----

    def test_migration_through_the_engine_and_rollback(self) -> None:
        self.privileged_stick()
        self.ok("sync")   # managed objects and the slice's Pi-hole entry first (manage_reservations is off)
        self.w.mock.clear_requests()

        # Refused: the reservation is an administrator's, then the host object would keep the privileges.
        refused = self.ok("migrate", STICK, code=7)
        self.assertIn("administrator", refused.err)
        self.assertIn(f"forti-pihole adopt {STICK} --reservation", refused.err)
        self.ok("adopt", STICK, "--reservation")
        refused = self.ok("migrate", STICK, code=7)
        self.assertIn("privileged by address", refused.err)
        self.assertIn('--object "Stick IP"', refused.err)
        self.assertEqual(self.writes(), [])
        self.ok("adopt", STICK, "--object", "Stick IP")
        dry = self.ok("migrate", STICK, "--dry-run")
        self.assertIn("192.168.1.110 -> 192.168.1.208", dry.out)
        self.assertIn("objects: address objects Stick IP", dry.out)
        self.assertEqual(self.writes(), [])

        op_id = self.adopt_and_migrate_stick()   # adopting again is harmless
        writes = self.writes()
        # The reservation was changed on its CHILD path; the server itself was never written.
        self.assertIn("PUT cmdb/system.dhcp/server/1/reserved-address/12", writes)
        self.assertNotIn("PUT cmdb/system.dhcp/server/1", writes)
        self.assertIn("PUT cmdb/firewall/address/Stick%20IP", writes)
        entry = self.reservation(12)
        assert entry
        self.assertEqual((entry["ip"], entry["mac"], entry["action"]), ("192.168.1.208", STICK, "reserved"))
        self.assertIn(MARKER, entry["description"])
        self.assertEqual(self.reservation(40)["ip"], "192.168.1.150")  # type: ignore[index]
        self.assertEqual(self.w.mock.table("firewall/address")["Stick IP"]["subnet"], "192.168.1.208 255.255.255.255")
        revokes = [r.json() for r in self.w.fortios_writes() if r.api == "monitor/system/dhcp/revoke"]
        self.assertEqual(revokes, [{"ip": ["192.168.1.110"]}])
        self.assertEqual(self.w.lease_of(STICK), "192.168.1.208")
        op = self.operation(op_id)
        self.assertEqual(op["status"], "done")
        steps = {s["id"]: s for s in op["steps"]}
        self.assertEqual([s["id"] for s in op["steps"]], ["pihole", "reservation", "objects", "revoke", "observe", "verify"])
        self.assertTrue(all(s["status"] == "done" for s in op["steps"]), op["steps"])
        self.assertIn("17", steps["verify"]["result"]["reach"]["internet"])   # still via Important Devices
        self.assertEqual(steps["verify"]["result"]["lease"], "192.168.1.208")
        journal = list((self.w.pihole_dir / "operations").glob(f"{op_id}*"))
        self.assertTrue(journal, "no operation journal")
        audited = len(self.w.audit())

        # A later sync sees the stick reserved inside its slice and does nothing.
        self.w.mock.clear_requests()
        after = self.ok("sync", "--json").json()
        self.assertEqual([a["kind"] for a in after["slicing"]["actions"] if a["mac"] == STICK], ["in-place"])
        self.assertEqual(self.writes(), [])

        # Rollback: the engine's rollback plans restore the reservation and the object; the new lease
        # is revoked so the device renews into its old address.
        rolled = self.ok("operations", "rollback", op_id)
        self.assertIn("rolled-back", rolled.out)
        entry = self.reservation(12)
        assert entry
        self.assertEqual((entry["ip"], entry["mac"], entry["description"]), ("192.168.1.110", STICK, "living room stick"))
        self.assertEqual(self.w.mock.table("firewall/address")["Stick IP"]["subnet"], "192.168.1.110 255.255.255.255")
        writes = self.writes()
        self.assertIn("PUT cmdb/system.dhcp/server/1/reserved-address/12", writes)
        self.assertIn("PUT cmdb/firewall/address/Stick%20IP", writes)
        revokes = [r.json() for r in self.w.fortios_writes() if r.api == "monitor/system/dhcp/revoke"]
        self.assertEqual(revokes, [{"ip": ["192.168.1.208"]}])
        self.assertEqual(self.w.lease_of(STICK), "192.168.1.110")
        self.assertEqual(self.operation(op_id)["status"], "rolled-back")
        self.assertGreater(len(self.w.audit()), audited)
        # The Pi-hole entry existed before the migration (sync made it): the rollback leaves it.
        self.assertIn(SLICE, self.w.pihole_clients())

    # ---- scenario 4 ----

    def test_reservation_create_gets_a_device_assigned_id_and_rollback_deletes_it(self) -> None:
        self.w.mock.inventory.append(device(STICK2, "192.168.1.120", hardware_vendor="Amazon",  # type: ignore[attr-defined]
                                            hardware_family="Fire TV Stick 4K", hostname="bedroom-stick"))
        self.w.mock.add_lease("192.168.1.120", STICK2)
        result = self.ok("migrate", STICK2)
        found = re.search(r"^(\S+) done$", result.out, re.M)
        self.assertIsNotNone(found, result.out)
        assert found
        op_id = found.group(1)
        target = re.search(r"192\.168\.1\.120 -> (\S+) \(", result.out)
        assert target, result.out
        to_ip = target.group(1)
        self.assertTrue(to_ip.startswith("192.168.1.2"), to_ip)   # inside 192.168.1.208/28
        creates = [r for r in self.w.fortios_writes() if r.api == "cmdb/system.dhcp/server/1/reserved-address"]
        self.assertEqual([r.method for r in creates], ["POST"])
        self.assertEqual(creates[0].json()["mac"], STICK2)
        self.assertIn(MARKER, creates[0].json()["description"])
        new = {i: e for i, e in self.w.mock.reservations(1).items() if e["mac"] == STICK2}
        self.assertEqual(list(new), [41], "the mock assigns the highest id + 1")
        self.assertEqual(new[41]["ip"], to_ip)
        self.assertEqual(self.w.lease_of(STICK2), to_ip)
        # The migration made the slice's Pi-hole entry itself (nothing had synced yet).
        self.assertIn(SLICE, self.w.pihole_clients())

        self.w.mock.clear_requests()
        self.ok("operations", "rollback", op_id)
        writes = self.writes()
        deletes = [w for w in writes if w.startswith("DELETE ")]
        self.assertEqual(deletes, ["DELETE cmdb/system.dhcp/server/1/reserved-address/41"])
        self.assertEqual(sorted(self.w.mock.reservations(1)), [40])
        revokes = [r.json() for r in self.w.fortios_writes() if r.api == "monitor/system/dhcp/revoke"]
        self.assertEqual(revokes, [{"ip": [to_ip]}])
        self.assertEqual(self.w.lease_of(STICK2), "192.168.1.120")
        self.assertEqual(self.operation(op_id)["status"], "rolled-back")
        # The entry the migration created is gone again.
        self.assertNotIn(SLICE, self.w.pihole_clients())

    # ---- scenario 6 (the check runs after every test; this one adds the read paths) ----

    def test_secrets_stay_out_of_everything(self) -> None:
        self.ok("status")
        self.ok("status", "--json")
        self.ok("sync", "-v")
        self.ok("history", "--json")
        self.ok("operations")
        # The binaries did read the stored password: they talked to the mock Pi-hole.
        self.assertGreater(self.w.pihole.totals["logins"], 0)
        self.assertTrue(all(r["method"] != "POST" or r["path"] != "/api/auth" or APP_PASSWORD in r["body"]
                            for r in self.w.pihole.totals["requests"]))
        # A wrong binding (the password stored for another host:port) is refused without the value.
        credentials = Path(self.w.env["FORTI_CONFIG_DIR"]) / "credentials" / "pihole.default.password"
        credentials.write_text(f"binding 127.0.0.1:1\n{APP_PASSWORD}\n")
        refused = self.w.run("plan")
        self.assertEqual(refused.code, 0, refused.err)   # reported; the FortiGate side still plans
        self.assertIn("belongs to 127.0.0.1:1", refused.out + refused.err)

    # ---- scenario 7 ----

    def test_daemon_check_config_and_one_event_driven_sync(self) -> None:
        if not DAEMON or not os.access(DAEMON, os.X_OK):
            self.skipTest("FPH_DAEMON is not set")
        port = free_port()
        self.w.write_daemon_config({"listen": {"address": "127.0.0.1", "port": port}, "allow_sources": ["127.0.0.1/32"],
                                    "schedule": {"debounce_seconds": 1, "max_delay_seconds": 2, "full_reconcile_minutes": 600,
                                                 "suppression_seconds": 0}})
        self.w.store_webhook_token(TOKEN)
        check = self.w.run("--check-config", binary=DAEMON)
        self.assertEqual(check.code, 0, check.out + check.err)
        self.assertIn("configuration ok", check.out)
        self.assertIn(f"127.0.0.1:{port}", check.out)
        self.assertIn("stored as pihole/lab/webhook-token", check.out)

        proc = self.w.popen("--foreground")
        try:
            def health() -> bool:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=2) as reply:
                        return reply.status == 200
                except (urllib.error.URLError, OSError):
                    return False
            self.assertTrue(wait_until(health, 15), "forti-piholed did not come up")
            # The startup reconcile is a full sync.
            self.assertTrue(wait_until(lambda: [h for h in self.w.history() if h["stage"] == "objects"], 30),
                            "no startup sync in history")
            # A device appears; the FortiGate's automation stitch reports a config change.
            self.w.mock.inventory.append(device(STICK2, "192.168.1.120", hardware_vendor="Amazon",  # type: ignore[attr-defined]
                                                hardware_family="Fire TV Stick 4K"))
            self.w.mock.add_lease("192.168.1.120", STICK2)
            event = json.dumps({"logid": "0100044547", "eventtime": "1", "vd": "root", "user": "admin", "ui": "GUI",
                                "action": "Add", "cfgpath": "user.device", "cfgobj": "bedroom", "logdesc": "Object attribute configured"})
            unauthorized = urllib.request.Request(f"http://127.0.0.1:{port}/v1/fortigate/events", data=event.encode(), method="POST",
                                                  headers={"Content-Type": "application/json", "Authorization": "Bearer wrong-token-0000000000000000000000"})
            with self.assertRaises(urllib.error.HTTPError) as denied:
                urllib.request.urlopen(unauthorized, timeout=5)
            self.assertEqual(denied.exception.code, 401)
            request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/fortigate/events", data=event.encode(), method="POST",
                                             headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
            with urllib.request.urlopen(request, timeout=5) as reply:
                self.assertIn(reply.status, (200, 202))
            synced = wait_until(lambda: len([h for h in self.w.history() if h["stage"] == "objects" and h["status"] == "applied"]) >= 2, 30)
            self.assertTrue(synced, f"the event did not trigger a sync: {self.w.history()}")
            addresses = self.w.mock.table("firewall/address")
            self.assertTrue(any(a.get("macaddr") == [{"macaddr": STICK2}] for a in addresses.values()), "the new device has no object")
        finally:
            proc.send_signal(signal.SIGTERM)
            try:
                out, err = proc.communicate(timeout=30)
            except Exception:
                proc.kill()
                out, err = proc.communicate()
            self.w.outputs += [out, err]
        self.assertEqual(proc.returncode, 0, err)
        self.assertIn("run.finished", err)


def main() -> int:
    require_tools()
    if not BINARY or not os.access(BINARY, os.X_OK):
        print("SKIP: FPH_BINARY is not set to an executable", file=sys.stderr)
        return SKIP
    runner = unittest.main(exit=False, verbosity=2)
    ok = runner.result.wasSuccessful()
    print(f"{len(ALL_WRITES)} FortiOS write(s) across the run{', all inside the allowlist' if ok else ''}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
