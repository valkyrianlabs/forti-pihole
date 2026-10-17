#!/usr/bin/env python3
"""A small, stateful mock of the Pi-hole v6 REST API (FTL v6.7), for end-to-end tests of forti-pihole's
Pi-hole client through libcurl. Python 3 standard library only; plain HTTP on 127.0.0.1 and an
ephemeral port (the client accepts http:// for loopback hosts only).

What it models, after FTL's OpenAPI specification (src/api/docs/content/specs/{auth,clients,groups,
info}.yaml) and the code behind it (src/api/auth.c, src/api/list.c, src/database/gravity-db.c,
advanced/Templates/gravity.db.sql in pi-hole/pi-hole):

* Sessions: `POST /api/auth {"password"}` with the admin or the app password answers a session with a
  random SID; requests authenticate with the `X-FTL-SID` (or `sid`) header; `DELETE /api/auth` ends
  it (204). A wrong password is 401 with the *session* object ("password incorrect"); more than three
  password checks in one second are 429 `rate_limiting`; no free slot (max_sessions) is 429
  `api_seats_exceeded`; with 2FA enabled the admin password without "totp" is 400 (the app password
  needs none). Every other endpoint answers 401 `unauthorized` without a valid SID.
* `GET /api/info/version` in the specification's shape.
* Groups (`GET`, `POST`, `PUT`, `DELETE /api/groups[/{name}]`): the Default group (id 0) always
  exists; names are UNIQUE.
* Clients (`GET`, `POST /api/clients`, `GET`/`PUT`/`DELETE /api/clients/{client}`): the `client`
  column is UNIQUE byte for byte; an insert joins group 0 (trigger tr_client_add); a "groups" array
  then replaces the memberships the way gravityDB_edit_groups() does it: all deleted first, then each
  id inserted, outside a transaction, so an unknown id (FOREIGN KEY) or a repeated id (PRIMARY KEY)
  fails half-way and leaves what was done. PUT is an upsert and stores the comment it is given (null
  when missing or empty). A POST or PUT reply lists only the last item, with "processed"; when every
  item failed the reply is 400 `database_error`. Items with spaces, tabs, CR or LF are 400.

Test control lives outside /api: `POST /_mock/reset` (state and settings), `GET /_mock/state`
(sessions, groups, clients, the request log), `POST /_mock/fault` (answer the next matching request
with a given status and body), `POST /_mock/expire` (end every session, as a timeout would).
Counters that span resets (`totals`) let a harness check that every login was paired with a logout.

Used in-process (`MockPihole().start()`) or standalone (`python3 mock_pihole.py`), which prints one
JSON line with the port and URL and serves until stdin closes or SIGTERM.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import secrets
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

APP_PASSWORD = "mock-app-password-4b8e1f0d"
ADMIN_PASSWORD = "mock-admin-password-91c3"
MAX_PASSWORD_ATTEMPTS_PER_SECOND = 3     # FTL src/config/password.h
DUPLICATE = "The item is already present"


def _now() -> int:
    return int(time.time())


class State:
    """Everything the mock Pi-hole knows; replaced wholesale by /_mock/reset."""

    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        s = settings or {}
        self.app_password: str | None = s.get("app_password", APP_PASSWORD)
        self.admin_password: str | None = s.get("admin_password", ADMIN_PASSWORD)
        self.no_password: bool = bool(s.get("no_password", False))
        self.totp: bool = bool(s.get("totp", False))
        self.max_sessions: int = int(s.get("max_sessions", 16))
        self.session_timeout: int = int(s.get("session_timeout", 1800))
        versions = s.get("versions", {})
        self.versions = {"core": versions.get("core", "v6.4.3"), "web": versions.get("web", "v6.6"),
                         "ftl": versions.get("ftl", "v6.7.1")}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.attempt_second = 0
        self.attempt_count = 0
        t = _now()
        self.groups: list[dict[str, Any]] = [
            {"id": 0, "name": "Default", "comment": "The default group", "enabled": True,
             "date_added": t, "date_modified": t}]
        self.next_group_id = 1
        self.clients: list[dict[str, Any]] = []
        self.client_by_group: set[tuple[int, int]] = set()
        self.next_client_id = 1
        self.hostnames: dict[str, str] = dict(s.get("hostnames", {}))   # client -> "name" field
        self.faults: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []
        for group in s.get("groups", []):
            self.add_group(group["name"], group.get("comment"), group.get("enabled", True), group.get("id"))
        for client in s.get("clients", []):
            row = self.insert_client(client["client"], client.get("comment"))
            assert isinstance(row, dict), row
            if "groups" in client:
                self.edit_groups(row["id"], client["groups"])

    # ---- gravity.db ----

    def add_group(self, name: str, comment: str | None, enabled: bool, gid: int | None = None) -> dict[str, Any] | str:
        if any(g["name"] == name for g in self.groups):
            return DUPLICATE
        if gid is None:
            gid = self.next_group_id
        self.next_group_id = max(self.next_group_id, gid + 1)
        t = _now()
        row = {"id": gid, "name": name, "comment": comment, "enabled": enabled, "date_added": t, "date_modified": t}
        self.groups.append(row)
        return row

    def insert_client(self, item: str, comment: str | None) -> dict[str, Any] | str:
        if any(c["client"] == item for c in self.clients):       # UNIQUE, BINARY collation
            return DUPLICATE
        t = _now()
        row = {"id": self.next_client_id, "client": item, "comment": comment, "date_added": t, "date_modified": t}
        self.next_client_id += 1
        self.clients.append(row)
        self.client_by_group.add((row["id"], 0))                    # trigger tr_client_add
        return row

    def edit_groups(self, client_id: int, groups: Any) -> str | None:
        """gravityDB_edit_groups(): delete all memberships, then insert each number. None on success."""
        self.client_by_group = {(c, g) for (c, g) in self.client_by_group if c != client_id}
        if not isinstance(groups, list):
            return None
        for gid in groups:
            if isinstance(gid, bool) or not isinstance(gid, (int, float)):
                continue                                            # cJSON_IsNumber() only
            gid = int(gid)
            if not any(g["id"] == gid for g in self.groups):
                return "FOREIGN KEY constraint failed"
            if (client_id, gid) in self.client_by_group:
                return "UNIQUE constraint failed: client_by_group.client_id, client_by_group.group_id"
            self.client_by_group.add((client_id, gid))
        return None

    def client_json(self, row: dict[str, Any]) -> dict[str, Any]:
        groups = sorted(g for (c, g) in self.client_by_group if c == row["id"])
        return {"client": row["client"], "name": self.hostnames.get(row["client"], ""), "comment": row["comment"],
                "groups": groups, "id": row["id"], "date_added": row["date_added"],
                "date_modified": row["date_modified"]}

    def active_sessions(self) -> int:
        t = _now()
        return sum(1 for s in self.sessions.values() if s["valid_until"] >= t)


class MockPihole:
    def __init__(self, settings: dict[str, Any] | None = None) -> None:
        self.lock = threading.RLock()
        self.state = State(settings)
        # Across resets. "closed" counts logouts and sessions ended by /_mock/expire.
        self.totals = {"logins": 0, "closed": 0, "requests": []}
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        assert self.server
        return self.server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "MockPihole":
        mock = self

        class Handler(_Handler):
            pass

        Handler.mock = mock
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def __enter__(self) -> "MockPihole":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


class _Handler(BaseHTTPRequestHandler):
    mock: MockPihole
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:     # quiet
        pass

    # ---- plumbing ----

    def _send(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _error(self, status: int, key: str, message: str, hint: str | None = None) -> None:
        self._send(status, {"error": {"key": key, "message": message, "hint": hint}, "took": 0.001})

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _sid(self) -> str | None:
        return self.headers.get("X-FTL-SID") or self.headers.get("sid")

    def _session(self, state: State) -> dict[str, Any] | None:
        sid = self._sid()
        if not sid:
            return None
        session = state.sessions.get(sid)
        if not session or session["valid_until"] < _now():
            return None
        session["valid_until"] = _now() + state.session_timeout   # any authenticated request extends it
        return session

    def _session_object(self, state: State, sid: str | None, message: str | None, valid: bool) -> dict[str, Any]:
        obj: dict[str, Any] = {"valid": valid, "totp": state.totp, "sid": sid, "validity": -1, "message": message}
        if sid:
            obj["csrf"] = state.sessions[sid]["csrf"]
            obj["validity"] = state.sessions[sid]["valid_until"] - _now()
        return {"session": obj, "took": 0.001}

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def _dispatch(self, method: str) -> None:
        raw = self._body()
        split = urlsplit(self.path)
        path = unquote(split.path)                  # civetweb decodes the URI before FTL routes it
        mock = self.mock
        with mock.lock:
            state = mock.state
            if not split.path.startswith("/_mock/"):
                record = {"method": method, "path": self.path, "has_sid": bool(self._sid()),
                          "body": raw.decode(errors="replace")}
                state.requests.append(record)
                mock.totals["requests"].append(record)
                for fault in list(state.faults):
                    if fault["method"] == method and fault["path"] == split.path:
                        state.faults.remove(fault)
                        self._send(fault["status"], fault.get("body"), fault.get("headers"))
                        return
            try:
                payload = json.loads(raw) if raw else None
            except ValueError:
                payload = ValueError
            self._route(method, path, split.query, payload, state)

    # ---- routes ----

    def _route(self, method: str, path: str, query: str, payload: Any, state: State) -> None:
        mock = self.mock
        if path.startswith("/_mock/"):
            return self._control(method, path, payload)
        if path == "/api/auth":
            return self._auth(method, payload, state)
        if path == "/api/docs":
            return self._send(200, {"docs": "mock"})
        if not state.no_password and self._session(state) is None:
            return self._error(401, "unauthorized", "Unauthorized")
        if path == "/api/info/version" and method == "GET":
            v = state.versions
            return self._send(200, {"version": {
                "core": {"local": {"branch": "master", "version": v["core"], "hash": "a1b2c3d4"},
                         "remote": {"version": v["core"], "hash": "a1b2c3d4"}},
                "web": {"local": {"branch": "master", "version": v["web"], "hash": "e5f6a7b8"},
                        "remote": {"version": v["web"], "hash": "e5f6a7b8"}},
                "ftl": {"local": {"branch": "master", "version": v["ftl"], "hash": "c9d0e1f2",
                                  "date": "2026-09-19 10:00:00 +0000"},
                        "remote": {"version": v["ftl"], "hash": "c9d0e1f2"}},
                "docker": {"local": None, "remote": None}}, "took": 0.001})
        for base, kind in (("/api/groups", "groups"), ("/api/clients", "clients")):
            if path == base or path.startswith(base + "/"):
                item = path[len(base) + 1:] if path != base else ""
                return self._list(method, kind, item, payload, state)
            if path == base + ":batchDelete":
                return self._batch_delete(method, kind, payload, state)
        _ = mock
        return self._error(404, "not_found", "Not found", path)

    def _control(self, method: str, path: str, payload: Any) -> None:
        mock = self.mock
        if path == "/_mock/reset" and method == "POST":
            mock.state = State(payload if isinstance(payload, dict) else None)
            return self._send(200, {"ok": True})
        if path == "/_mock/state" and method == "GET":
            s = mock.state
            return self._send(200, {
                "active_sessions": s.active_sessions(), "groups": copy.deepcopy(s.groups),
                "clients": [s.client_json(r) for r in s.clients], "requests": s.requests,
                "totals": {"logins": mock.totals["logins"], "closed": mock.totals["closed"]}})
        if path == "/_mock/fault" and method == "POST":
            mock.state.faults.append(payload)
            return self._send(200, {"ok": True})
        if path == "/_mock/expire" and method == "POST":
            mock.totals["closed"] += len(mock.state.sessions)
            mock.state.sessions.clear()
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "no such control endpoint"})

    def _auth(self, method: str, payload: Any, state: State) -> None:
        mock = self.mock
        session = self._session(state)
        if method == "GET":
            if state.no_password:
                return self._send(200, self._session_object(state, None, "no password set", True))
            if session:
                return self._send(200, self._session_object(state, self._sid(), None, True))
            return self._send(401, self._session_object(state, None, "no SID provided", False))
        if method == "DELETE":
            if session:
                sid = self._sid()
                assert sid
                del state.sessions[sid]
                mock.totals["closed"] += 1
                return self._send(204)
            return self._send(401, self._session_object(state, None, "no SID provided", False))
        if method != "POST":
            return self._error(404, "not_found", "Not found")

        if payload is ValueError or not isinstance(payload, dict):
            return self._error(400, "bad_request", "No valid JSON payload found")
        if "password" not in payload:
            return self._error(400, "bad_request", "No password found in JSON payload")
        password = payload["password"]
        if not isinstance(password, str):
            return self._error(400, "bad_request", "Field password has to be of type 'string'")
        if session and not password:
            return self._send(200, self._session_object(state, self._sid(), None, True))
        if state.no_password:
            if not password:
                return self._send(200, self._session_object(state, None, "no password set", True))
            return self._send(401, self._session_object(state, None, "password incorrect", False))

        # verify_password(): more than three checks within one second are rate-limited
        t = _now()
        if state.attempt_second == t:
            state.attempt_count += 1
            if state.attempt_count > MAX_PASSWORD_ATTEMPTS_PER_SECOND:
                return self._error(429, "rate_limiting", "Rate-limiting login attempts")
        else:
            state.attempt_second, state.attempt_count = t, 1

        app = state.app_password is not None and password == state.app_password
        admin = state.admin_password is not None and password == state.admin_password
        if not (app or admin):
            return self._send(401, self._session_object(state, None, "password incorrect", False))
        if admin and state.totp:
            if "totp" not in payload:
                return self._error(400, "bad_request", "No 2FA token found in JSON payload")
            return self._error(401, "unauthorized", "Invalid 2FA token")
        if state.active_sessions() >= state.max_sessions:
            return self._error(429, "api_seats_exceeded", "API seats exceeded", "increase webserver.api.max_sessions")
        sid = base64.b64encode(secrets.token_bytes(16)).decode()
        csrf = base64.b64encode(secrets.token_bytes(16)).decode()
        state.sessions[sid] = {"csrf": csrf, "valid_until": t + state.session_timeout, "app": app}
        mock.totals["logins"] += 1
        return self._send(200, self._session_object(state, sid, "app-password correct" if app else "password correct", True))

    def _items(self, kind: str, payload: Any) -> list[str] | str:
        field = "name" if kind == "groups" else "client"
        value = payload.get(field) if isinstance(payload, dict) else None
        if isinstance(value, str) and value:
            return [value]
        if isinstance(value, list) and value:
            return value
        return f'Invalid request: No valid "{field}" in payload (must be either string or array)'

    def _validate(self, kind: str, items: list[Any]) -> tuple[str, str | None] | None:
        for item in items:
            if not isinstance(item, str):
                return ("all array items must be strings", None)
        for item in items:
            if kind != "groups" and (" " in item or "\t" in item):
                return ("Spaces and tabs are not allowed in domains and URLs", item)
            if "\r" in item or "\n" in item:
                return ("Newlines and carriage returns are not allowed in any input", item)
        return None

    def _list(self, method: str, kind: str, item: str, payload: Any, state: State) -> None:
        rows = state.groups if kind == "groups" else state.clients
        key = "name" if kind == "groups" else "client"

        def render(selected: str) -> list[dict[str, Any]]:
            chosen = [r for r in rows if not selected or r[key] == selected]
            if kind == "groups":
                return copy.deepcopy(chosen)
            return [state.client_json(r) for r in chosen]

        if method == "GET":
            return self._send(200, {kind: render(item), "took": 0.001})

        if method in ("POST", "PUT"):
            if payload is ValueError or not isinstance(payload, dict):
                return self._error(400, "bad_request", "Invalid request body data (no valid JSON)")
            if method == "POST":
                if item:
                    return self._error(400, "uri_error", "Invalid request: Specify item in payload, not as URI parameter", item)
                items = self._items(kind, payload)
                if isinstance(items, str):
                    return self._error(400, "bad_request", items)
            else:
                if not item:
                    return self._error(400, "uri_error", "Invalid request: Specify item in URI")
                items = [item]
            invalid = self._validate(kind, items)
            if invalid:
                return self._error(400, "bad_request", invalid[0], invalid[1])
            comment = payload.get("comment")
            comment = comment if isinstance(comment, str) and comment else None
            enabled = payload.get("enabled")
            enabled = enabled if isinstance(enabled, bool) else True
            success, errors, message = [], [], None
            for it in items:
                if kind == "groups":
                    if method == "POST":
                        result = state.add_group(it, comment, enabled)
                    else:
                        row = next((g for g in state.groups if g["name"] == it), None)
                        new_name = payload.get("name") if isinstance(payload.get("name"), str) and payload.get("name") else None
                        if row is None and new_name is None:
                            result = state.add_group(it, comment, enabled)
                        elif row is None:
                            result = "no group with that name"
                        else:
                            if new_name:
                                row["name"] = new_name
                            row.update({"comment": comment, "enabled": enabled, "date_modified": _now()})
                            result = row
                    if isinstance(result, str):
                        errors.append({"item": it, "error": result})
                        message = result
                    else:
                        success.append({"item": it})
                    continue
                # clients
                if method == "POST":
                    result = state.insert_client(it, comment)
                else:
                    existing = next((c for c in state.clients if c["client"] == it), None)
                    if existing is None:
                        result = state.insert_client(it, comment)
                    else:
                        existing.update({"comment": comment, "date_modified": _now()})
                        result = existing
                if isinstance(result, str):
                    errors.append({"item": it, "error": result})
                    message = result
                    continue
                if "groups" in payload:
                    failure = state.edit_groups(result["id"], payload["groups"])
                    if failure:
                        errors.append({"item": it, "error": failure})
                        message = failure
                        continue
                success.append({"item": it})
            if not success and errors:
                return self._error(400, "database_error", "Could not add to gravity database", message)
            last = items[-1]
            if kind == "groups" and method == "PUT" and isinstance(payload.get("name"), str) and payload["name"]:
                last = payload["name"]
            status = 201 if method == "POST" else 200
            return self._send(status, {kind: render(last), "processed": {"errors": errors, "success": success},
                                       "took": 0.001},
                              {"Location": f"/api/{kind}/{last}"})

        if method == "DELETE":
            if not item:
                return self._error(400, "uri_error", "Invalid request: Specify item in URI")
            return self._delete(kind, [item], state)
        return self._error(404, "not_found", "Not found")

    def _delete(self, kind: str, items: list[str], state: State) -> None:
        key = "name" if kind == "groups" else "client"
        rows = state.groups if kind == "groups" else state.clients
        doomed = [r for r in rows if r[key] in items]
        for row in doomed:
            rows.remove(row)
            if kind == "clients":
                state.client_by_group = {(c, g) for (c, g) in state.client_by_group if c != row["id"]}
            else:
                state.client_by_group = {(c, g) for (c, g) in state.client_by_group if g != row["id"]}
        if kind == "groups" and not any(g["id"] == 0 for g in state.groups):
            state.add_group("Default", None, True, 0)                # trigger tr_group_zero
        if doomed:
            return self._send(204)
        return self._send(404, {"took": 0.001})

    def _batch_delete(self, method: str, kind: str, payload: Any, state: State) -> None:
        if method != "POST" or not isinstance(payload, list):
            return self._error(400, "bad_request", "Invalid request: Batch delete requires an array of objects")
        items = [p.get("item") for p in payload if isinstance(p, dict)]
        return self._delete(kind, [i for i in items if isinstance(i, str)], state)


def main() -> int:
    mock = MockPihole().start()
    print(json.dumps({"port": mock.port, "url": mock.url, "app_password": APP_PASSWORD}), flush=True)
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    mock.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
