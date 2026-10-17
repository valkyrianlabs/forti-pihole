#!/usr/bin/env python3
"""Runs the Pi-hole client's integration tests (a GoogleTest binary) against a running MockPihole.

    python3 harness.py --binary build/tests/pihole/piholeIntegrationTests [-- gtest args]

The mock serves on 127.0.0.1; the binary finds it through PIHOLE_MOCK_URL and its credentials through
PIHOLE_MOCK_APP_PASSWORD / PIHOLE_MOCK_ADMIN_PASSWORD, and resets it per test (POST /_mock/reset).
After the binary exits the harness checks what no single test can see, across the whole run:

  * every session that was opened was closed again (by a logout, or by /_mock/expire in a test that
    simulates a timeout): FTL's session slots are few;
  * no request ever renamed, changed or deleted a group, or used a batch delete;
  * no password or session ID ever appeared in a request path (they belong in the body and header).

Exit status: the binary's, or 1 when a check fails; 77 (Meson's "skipped") without a binary.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mock_pihole import ADMIN_PASSWORD, APP_PASSWORD, MockPihole  # noqa: E402

SKIP = 77


def check(mock: MockPihole) -> list[str]:
    problems: list[str] = []
    totals = mock.totals
    if totals["logins"] != totals["closed"]:
        problems.append(f"{totals['logins']} logins but {totals['closed']} sessions closed: sessions were left open")
    for request in totals["requests"]:
        method, path = request["method"], request["path"]
        if path.startswith("/api/groups/") and method in ("PUT", "DELETE"):
            problems.append(f"forbidden group write: {method} {path}")
        if ":batchDelete" in path:
            problems.append(f"forbidden batch delete: {method} {path}")
        for secret in (APP_PASSWORD, ADMIN_PASSWORD):
            if secret in path:
                problems.append(f"a password appeared in a request path: {method} ...")
        if "sid=" in path:
            problems.append(f"a session ID was sent in the URL: {method} ...")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("rest", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not os.access(args.binary, os.X_OK):
        print(f"SKIP: {args.binary} is not executable", file=sys.stderr)
        return SKIP

    with MockPihole() as mock:
        env = {**os.environ, "PIHOLE_MOCK_URL": mock.url, "PIHOLE_MOCK_APP_PASSWORD": APP_PASSWORD,
               "PIHOLE_MOCK_ADMIN_PASSWORD": ADMIN_PASSWORD}
        extra = [a for a in args.rest if a != "--"]
        code = subprocess.run([args.binary, *extra], env=env, check=False).returncode
        problems = check(mock)

    for problem in problems:
        print(f"harness: {problem}", file=sys.stderr)
    if code != 0:
        return code
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
