#!/usr/bin/env python3
"""
NetConverter — Cisco FMC API connectivity check (read-only).

Verifies host reachability, credentials, and returns FMC version + domain UUID.
No configuration is exported.

Usage:
    python fmc_test_auth.py --host 10.1.1.100 --user api_readonly
    python fmc_test_auth.py --host fmc.example.com --user admin --password 'secret'
    python fmc_test_auth.py --host 192.168.1.50 --user ro --insecure

License: MIT
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from getpass import getpass


def normalize_host(host: str) -> str:
    host = host.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix) :]
    return host.rstrip("/").split("/")[0]


def main() -> int:
    p = argparse.ArgumentParser(description="FMC API connectivity check (token only)")
    p.add_argument("--host", required=True, help="FMC IP address or hostname (no https://)")
    p.add_argument("--user", required=True, help="API username")
    p.add_argument("--password", help="Password (or FMC_PASSWORD env, else prompted)")
    p.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification (lab only)")
    args = p.parse_args()

    host = normalize_host(args.host)
    password = args.password or os.environ.get("FMC_PASSWORD") or getpass("FMC password: ")

    ctx = ssl.create_default_context()
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
    req = urllib.request.Request(url, method="POST", data=b"")
    creds = base64.b64encode(f"{args.user}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")

    # The sandbox/lab token endpoint returns transient 401/429/timeouts; keep trying.
    status = domain = token = None
    for attempt in range(1, 7):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                status = resp.status
                domain = resp.headers.get("DOMAIN_UUID", "")
                token = resp.headers.get("X-auth-access-token", "")
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")[:400]
            transient = exc.code in (401, 429) or exc.code >= 500
            if transient and attempt < 6:
                wait = 5 * attempt
                print(
                    f"  auth {exc.code} (often transient on sandbox) — "
                    f"retry in {wait}s ({attempt}/6) …",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            print(f"FAIL: HTTP {exc.code} — {body}", file=sys.stderr)
            return 1
        except Exception as exc:  # noqa: BLE001
            if attempt < 6:
                wait = 5 * attempt
                print(
                    f"  auth attempt {attempt}/6 failed ({exc.__class__.__name__}) — "
                    f"retry in {wait}s …",
                    file=sys.stderr,
                )
                time.sleep(wait)
                continue
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1

    print(f"OK: authentication succeeded (HTTP {status})")
    print(f"Host: {host}")
    print(f"Domain UUID: {domain or '(not returned)'}")
    if token:
        print(f"Token: {token[:24]}…")

    if token:
        vr = urllib.request.Request(
            f"https://{host}/api/fmc_platform/v1/info/serverversion",
            headers={"X-auth-access-token": token},
        )
        try:
            with urllib.request.urlopen(vr, context=ctx, timeout=30) as vrsp:
                data = json.loads(vrsp.read())
                ver = (data.get("items") or [{}])[0].get("serverVersion", "?")
                print(f"FMC version: {ver}")
        except Exception as exc:  # noqa: BLE001
            print(f"WARN: could not read server version: {exc}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
