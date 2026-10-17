#!/usr/bin/env python3
"""Self-test of the mock: the FTL behaviours the C++ client is built around are modelled (if the mock
drifted, the integration tests would prove nothing), and the harness notices a leaked session."""

from __future__ import annotations

import json
import sys
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harness import check  # noqa: E402
from mock_pihole import APP_PASSWORD, MockPihole  # noqa: E402


class MockPiholeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mock = MockPihole().start()
        self.sid: str | None = None

    def tearDown(self) -> None:
        self.mock.stop()

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.mock.url + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.sid:
            request.add_header("X-FTL-SID", self.sid)
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read()
            return error.code, json.loads(raw) if raw else None

    def login(self) -> None:
        status, reply = self.call("POST", "/api/auth", {"password": APP_PASSWORD})
        self.assertEqual(status, 200)
        self.sid = reply["session"]["sid"]

    def test_unauthenticated_requests_are_401(self) -> None:
        status, reply = self.call("GET", "/api/clients")
        self.assertEqual(status, 401)
        self.assertEqual(reply["error"]["key"], "unauthorized")
        status, reply = self.call("POST", "/api/auth", {"password": "wrong"})
        self.assertEqual(status, 401)
        self.assertEqual(reply["session"]["message"], "password incorrect")

    def test_login_rate_limit(self) -> None:
        codes = [self.call("POST", "/api/auth", {"password": "wrong"})[0] for _ in range(5)]
        self.assertIn(429, codes)

    def test_new_client_joins_default_and_groups_replace_it(self) -> None:
        self.login()
        self.call("POST", "/api/groups", {"name": "iot"})
        status, reply = self.call("POST", "/api/clients", {"client": "10.0.0.5"})
        self.assertEqual(status, 201)
        self.assertEqual(reply["clients"][0]["groups"], [0])
        status, reply = self.call("POST", "/api/clients", {"client": "10.0.0.6", "groups": [1]})
        self.assertEqual(reply["clients"][0]["groups"], [1])
        status, reply = self.call("POST", "/api/clients", {"client": "10.0.0.7", "groups": []})
        self.assertEqual(reply["clients"][0]["groups"], [])
        status, reply = self.call("POST", "/api/clients", {"client": "10.0.0.5"})
        self.assertEqual(status, 400)
        self.assertEqual(reply["error"]["hint"], "The item is already present")
        self.call("DELETE", "/api/auth")

    def test_unknown_group_fails_half_way(self) -> None:
        self.login()
        self.call("POST", "/api/groups", {"name": "iot"})
        self.call("POST", "/api/clients", {"client": "10.0.0.5", "groups": [0, 1]})
        status, reply = self.call("PUT", "/api/clients/10.0.0.5", {"comment": "x", "groups": [1, 42]})
        self.assertEqual(status, 400)
        self.assertEqual(reply["error"]["hint"], "FOREIGN KEY constraint failed")
        _, reply = self.call("GET", "/api/clients/10.0.0.5")
        self.assertEqual(reply["clients"][0]["groups"], [1])          # 0 was dropped before the failure
        self.call("DELETE", "/api/auth")

    def test_put_is_an_upsert_and_replaces_the_comment(self) -> None:
        self.login()
        status, reply = self.call("PUT", "/api/clients/10.9.0.0%2F16", {"comment": "managed"})
        self.assertEqual(status, 200)
        self.assertEqual(reply["clients"][0]["client"], "10.9.0.0/16")   # created
        _, reply = self.call("PUT", "/api/clients/10.9.0.0%2F16", {"groups": [0]})
        self.assertIsNone(reply["clients"][0]["comment"])                 # no comment sent: null
        self.assertEqual(self.call("DELETE", "/api/clients/10.9.0.0%2F16")[0], 204)
        self.assertEqual(self.call("DELETE", "/api/clients/10.9.0.0%2F16")[0], 404)
        self.call("DELETE", "/api/auth")

    def test_client_text_is_unique_byte_for_byte(self) -> None:
        self.login()
        self.assertEqual(self.call("POST", "/api/clients", {"client": "aa:bb:cc:dd:ee:ff"})[0], 201)
        self.assertEqual(self.call("POST", "/api/clients", {"client": "AA:BB:CC:DD:EE:FF"})[0], 201)
        self.assertEqual(self.call("POST", "/api/clients", {"client": "10.0.0.1 "})[0], 400)
        self.call("DELETE", "/api/auth")

    def test_harness_notices_a_leaked_session(self) -> None:
        self.login()
        self.assertTrue(any("left open" in p for p in check(self.mock)))
        self.call("DELETE", "/api/auth")
        self.assertEqual(check(self.mock), [])

    def test_harness_notices_forbidden_requests(self) -> None:
        self.login()
        self.call("PUT", "/api/groups/Default", {"name": "Default", "enabled": False})
        self.call("DELETE", "/api/auth")
        self.assertTrue(any("forbidden group write" in p for p in check(self.mock)))


if __name__ == "__main__":
    unittest.main()
