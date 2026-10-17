"""Fixtures for forti-pihole's real-binary integration tests.

forti-cli's stateful mock FortiOS (FORTI_MOCK_DIR = subprojects/forti-cli/tests/mock-fortios) serves
what forti-cli and forti-mcp need. forti-pihole reads more of the device, so this module extends the
mock *from here*, without editing it:

* more cmdb tables, registered in its `TABLES` before any `MockFortiOS` is constructed (each
  `Device` builds its tables from that registry): `firewall/addrgrp`, `firewall.service/custom`,
  `firewall.service/group`, `system/interface` and `firewall/vip`;
* monitors: `user/device/query` (the device inventory, `mock.inventory`) and
  `firewall/address-dynamic?mkey=NAME` (`mock.dynamic`), through a handler subclass that the mock's
  `start()` picks up (it subclasses the module's `_Handler` by name);
* a hook after `monitor/system/dhcp/revoke` (`mock.on_revoke(ips)`), so a test can have the device
  renew into its reservation the moment its lease is revoked, the way a real client does.

`World` is one sandbox: forti-cli's `Sandbox` (temporary FORTI_HOME, FORTI_CONFIG_DIR, ... and a
running mock FortiOS; the API key only through an environment-variable reference) plus forti-pihole's
mock Pi-hole on plain HTTP 127.0.0.1, its app password in forti's *file* secret store inside the
sandbox (account pihole/<name>/password, bound to the Pi-hole's host:port), the engine profile written
directly (forti-pihole builds the engine only, never `forti`), and forti-pihole's config.json.
"""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

MOCK_DIR = os.environ.get("FORTI_MOCK_DIR", "")
PIHOLE_MOCK_DIR = os.environ.get("FPH_PIHOLE_MOCK_DIR", str(Path(__file__).resolve().parent.parent / "mock-pihole"))
SKIP = 77

if not MOCK_DIR or not os.path.isfile(os.path.join(MOCK_DIR, "harness.py")):
    print("SKIP: FORTI_MOCK_DIR does not point at forti-cli's tests/mock-fortios", file=sys.stderr)
    sys.exit(SKIP)
# Both mock directories have a harness.py; forti-cli's is the one imported here.
sys.path.insert(0, MOCK_DIR)
sys.path.append(PIHOLE_MOCK_DIR)

import mock_fortios  # noqa: E402
from harness import API_KEY, KEY_VAR, Result, Sandbox, require_tools  # noqa: E402,F401
from mock_fortios import TABLES, MockFortiOS, TableSpec  # noqa: E402
from mock_pihole import ADMIN_PASSWORD, APP_PASSWORD, MockPihole  # noqa: E402,F401

PROFILE = "lab"
MARKER = "managed by forti-pihole"


# ---- mock FortiOS extensions ----

def _unitary(name: str, kind: str, help_: str) -> dict[str, Any]:
    return {"name": name, "category": "unitary", "type": kind, "help": help_}


def _names(name: str, help_: str) -> dict[str, Any]:
    return {"name": name, "category": "table", "help": help_, "mkey": "name", "mkey_type": "string",
            "children": {"name": _unitary("name", "string", "Name.")}}


EXTRA_TABLES = {
    "firewall/addrgrp": TableSpec(
        "firewall/addrgrp", "name", False, "Configure IPv4 address groups.",
        {"name": _unitary("name", "string", "Address group name."), "member": _names("member", "Address objects contained within the group."),
         "comment": _unitary("comment", "var-string", "Comment."),
         "exclude": _unitary("exclude", "option", "Enable/disable address exclusion."),
         "exclude-member": _names("exclude-member", "Address exclusion member.")},
        lambda: {"uuid": mock_fortios.uuidlib.uuid4().__str__(), "type": "default", "category": "default", "member": [],
                 "comment": "", "exclude": "disable", "exclude-member": [], "color": 0}),
    "firewall.service/custom": TableSpec(
        "firewall.service/custom", "name", False, "Configure custom services.",
        {"name": _unitary("name", "string", "Custom service name."), "protocol": _unitary("protocol", "option", "Protocol type.")},
        lambda: {"protocol": "TCP/UDP/SCTP", "tcp-portrange": "", "udp-portrange": "", "comment": ""}),
    "firewall.service/group": TableSpec(
        "firewall.service/group", "name", False, "Configure service groups.",
        {"name": _unitary("name", "string", "Service group name."), "member": _names("member", "Service objects.")},
        lambda: {"member": [], "comment": ""}),
    "system/interface": TableSpec(
        "system/interface", "name", False, "Configure interfaces.",
        {"name": _unitary("name", "string", "Name."), "ip": _unitary("ip", "ipv4-classnet-host", "Interface IPv4 address.")},
        lambda: {"vdom": "root", "type": "physical", "role": "undefined", "ip": "0.0.0.0 0.0.0.0", "secondaryip": [],
                 "interface": "", "vlanid": 0, "status": "up", "alias": ""}),
    "firewall/vip": TableSpec(
        "firewall/vip", "name", False, "Configure virtual IP for IPv4.",
        {"name": _unitary("name", "string", "Virtual IP name."), "extintf": _unitary("extintf", "string", "Interface.")},
        lambda: {"extintf": "any", "mappedip": [], "extip": "0.0.0.0", "comment": ""}),
}
for _path, _spec in EXTRA_TABLES.items():
    TABLES.setdefault(_path, _spec)


class _PiholeHandler(mock_fortios._Handler):  # type: ignore[name-defined]
    """The mock's handler plus the monitors forti-pihole reads and the revoke hook."""

    def _monitor(self, method: str, path: str, params: dict[str, str], body: str = "") -> tuple[int, Any, str]:
        mock = self.owner
        api = "monitor/" + path
        if method == "GET" and path == "firewall/address-dynamic":
            with mock.lock:
                dynamic = copy.deepcopy(getattr(mock, "dynamic", {}))
            name = params.get("mkey")
            if name is not None:
                if name not in dynamic:
                    return 404, mock.envelope(method, api, 404, error=-3), "application/json"
                dynamic = {name: dynamic[name]}
            results = {n: {"addrs": list(addrs), "addrs_count": len(addrs)} for n, addrs in dynamic.items()}
            return 200, mock.envelope(method, api, results=results), "application/json"
        status, reply, content_type = super()._monitor(method, path, params, body)
        if method == "POST" and path == "system/dhcp/revoke" and status == 200:
            hook = getattr(mock, "on_revoke", None)
            if hook:
                hook(json.loads(body)["ip"])
        return status, reply, content_type


# MockFortiOS.start() subclasses the module's `_Handler`: from now on that is ours.
mock_fortios._Handler = _PiholeHandler


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- the sandbox ----

def device(mac: str, ip: str, **extra: Any) -> dict[str, Any]:
    """One monitor/user/device/query entry, seen just now on `internal`."""
    out = {"mac": mac, "ipv4_address": ip, "detected_interface": "internal", "is_online": True,
           "last_seen": int(time.time()), "online_interfaces": ["internal"]}
    out.update(extra)
    return out


class World:
    """A Sandbox, the mock Pi-hole, forti-pihole's binaries and their configuration."""

    def __init__(self, binary: str, daemon: str | None = None) -> None:
        self.bin = binary
        self.daemon_bin = daemon
        self.sb = Sandbox()
        self.pihole = MockPihole()
        self.outputs: list[str] = []    # every stdout/stderr, for the leak check
        self._starts: list[int] = []

    def __enter__(self) -> "World":
        self.sb.__enter__()
        self.pihole.start()
        self.mock: MockFortiOS = self.sb.mock
        self.mock.inventory = []          # type: ignore[attr-defined]
        self.mock.dynamic = {}            # type: ignore[attr-defined]
        self.mock.on_revoke = None        # type: ignore[attr-defined]
        self.mock.monitors["user/device/query"] = lambda: copy.deepcopy(self.mock.inventory)  # type: ignore[attr-defined]
        self.env = dict(self.sb.env)
        self.home = Path(self.env["FORTI_HOME"])
        self.pihole_dir = self.home / "pihole"
        self.write_profile()
        self.store_pihole_password()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.pihole.stop()
        self.sb.__exit__(*exc)

    # ---- configuration ----

    def write_profile(self, mode: str = "autonomous") -> None:
        """The engine's config.json, as `forti configure --api-key-env` writes it."""
        config = Path(self.env["FORTI_CONFIG_DIR"])
        config.mkdir(mode=0o700, parents=True, exist_ok=True)
        profile = {"host": "localhost", "port": self.mock.port, "mode": mode, "ca_bundle": str(self.mock.ca_path),
                   "api_key": {"source": "env", "env": KEY_VAR}}
        self._private(config / "config.json", json.dumps({"version": 1, "default_profile": PROFILE, "profiles": {PROFILE: profile}}))

    def store_pihole_password(self, name: str = "default") -> None:
        """forti's file secret store: <config>/credentials/<account with / -> .>, 'binding host:port' first."""
        credentials = Path(self.env["FORTI_CONFIG_DIR"]) / "credentials"
        credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private(credentials / f"pihole.{name}.password", f"binding 127.0.0.1:{self.pihole.port}\n{APP_PASSWORD}\n")

    def store_webhook_token(self, token: str) -> None:
        credentials = Path(self.env["FORTI_CONFIG_DIR"]) / "credentials"
        credentials.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private(credentials / f"pihole.{PROFILE}.webhook-token", f"binding localhost:{self.mock.port}\n{token}\n")

    def write_config(self, config: dict[str, Any]) -> None:
        self.pihole_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        config = dict(config)
        config.setdefault("pihole", {"url": self.pihole.url, "name": "default"})
        self._private(self.pihole_dir / "config.json", json.dumps(config, indent=2))

    def write_daemon_config(self, config: dict[str, Any]) -> None:
        self.pihole_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._private(self.pihole_dir / "daemon.json", json.dumps(config, indent=2))

    @staticmethod
    def _private(path: Path, text: str) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(path, 0o600)

    # ---- the device ----

    def add_row(self, path: str, key: str, **attrs: Any) -> None:
        """One object in a cmdb table, with that table's defaults (an administrator's object)."""
        with self.mock.lock:
            spec = TABLES[path]
            row = spec.defaults()
            row.update(attrs)
            row.update({spec.mkey: key, "q_origin_key": key})
            self.mock.device.tables[path][key] = row
            self.mock.device.bump()

    def set_device_ip(self, mac: str, ip: str) -> None:
        with self.mock.lock:
            for entry in self.mock.inventory:  # type: ignore[attr-defined]
                if entry["mac"] == mac:
                    entry["ipv4_address"] = ip

    def lease_of(self, mac: str) -> str | None:
        with self.mock.lock:
            return next((lease["ip"] for lease in self.mock.device.leases if lease["mac"] == mac), None)

    # ---- running ----

    def run(self, *args: str, timeout: float = 120, binary: str | None = None) -> Result:
        self._pace()
        proc = subprocess.run([binary or self.bin, *args], capture_output=True, text=True, env=self.env, timeout=timeout)
        self.outputs += [proc.stdout, proc.stderr]
        return Result(proc.returncode, proc.stdout, proc.stderr)

    def _pace(self) -> None:
        """FTL (and the mock) refuse more than three password checks in one wall-clock second, and every
        run logs in once: a test that runs the CLI back to back waits for the next second, as a person or
        the timer always would."""
        now = int(time.time())
        if len([t for t in self._starts if t == now]) >= 3:
            time.sleep(now + 1 - time.time() + 0.01)
        self._starts = [t for t in self._starts if t >= now] + [int(time.time())]

    def popen(self, *args: str) -> subprocess.Popen:  # type: ignore[type-arg]
        assert self.daemon_bin
        return subprocess.Popen([self.daemon_bin, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)

    # ---- inspection ----

    def fortios_writes(self) -> list[Any]:
        return self.mock.writes()

    def pihole_writes(self) -> list[dict[str, Any]]:
        return [r for r in self.pihole.state.requests if r["method"] != "GET" and r["path"] != "/api/auth"]

    def pihole_clients(self) -> dict[str, dict[str, Any]]:
        state = self.pihole.state
        with self.pihole.lock:
            return {row["client"]: state.client_json(row) for row in state.clients}

    def history(self) -> list[dict[str, Any]]:
        path = self.pihole_dir / "history.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []

    def audit(self) -> list[dict[str, Any]]:
        return self.sb.audit()

    def sandbox_text(self) -> str:
        """Every file the binaries could have written (forti home, config, state, cache, HOME), minus the
        credentials the test itself put into the secret store and the mocks' PKI."""
        chunks = []
        credentials = Path(self.env["FORTI_CONFIG_DIR"]) / "credentials"
        for path in sorted(self.sb.root.rglob("*")):
            if not path.is_file() or credentials in path.parents or (self.sb.root / "mock") in path.parents:
                continue
            chunks.append(f"== {path}\n" + path.read_text(errors="replace"))
        return "\n".join(chunks)


def wait_until(predicate: Callable[[], Any], timeout: float = 20.0, step: float = 0.1) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return None
