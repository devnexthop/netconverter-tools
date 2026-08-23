#!/usr/bin/env python3
"""
ValeronLabs / NetConverter — Check Point GATEWAY ROUTING collector
==================================================================

The Check Point *Management* API does NOT return gateway routing tables — routes
live in Gaia on each gateway. This companion script collects routing per gateway
over SSH (Gaia clish) so NetConverter has the routing picture for audit/migration.

It is READ-ONLY: it only runs `show route` / `show configuration` style clish
commands. It changes nothing.

Two ways to tell it which gateways to hit:
  A) --run-dir <run-YYYYMMDD-HHMMSS>   reuse the mgmt collector's
     gateways-and-servers.json to discover gateway IPs automatically, then use a
     shared --username/--password (or --key).
  B) --gateways-file gateways.csv      a CSV with columns: name,host,username,password
     (password optional if --key is given). One row per gateway.

Usage:
    pip install paramiko
    # discover gateways from a prior mgmt pull, one shared SSH cred:
    python checkpoint_collect_routing.py --run-dir run-20260602-173505 \
        --username admin --password 'SECRET' --output routing

    # or an explicit gateway list:
    python checkpoint_collect_routing.py --gateways-file gateways.csv --output routing

    # SSH key instead of password:
    python checkpoint_collect_routing.py --gateways-file gateways.csv --key ~/.ssh/id_rsa

    # if you can't run Python on the gateways, print the manual clish steps:
    python checkpoint_collect_routing.py --mop

Output (drops into the run-* bundle so the viewer can show it):
    routing/<gateway>.json          parsed routes [{code,dest,nexthop,interface,raw}]
    routing/<gateway>.show-route.txt   raw clish output (evidence)
    routing/_routing-summary.csv    one row per gateway: status, route count
"""
from __future__ import print_function

import argparse
import csv
import json
import re
import sys
from pathlib import Path

BANNER = "ValeronLabs — Check Point Gaia routing collector (read-only, SSH/clish)\n"

# clish commands run on each gateway (read-only). Output saved verbatim + parsed.
CLISH_COMMANDS = [
    "show route",
    "show route static",
    "show ipv6 route",
    "show configuration static-route",
]

MOP = """\
==================================================================
 MANUAL ROUTING COLLECTION (Method of Procedure) — per gateway
==================================================================
If you cannot run this Python script, collect routing by hand:

1. SSH to each Check Point gateway (Gaia) as a read-only admin.
2. Enter clish (you are usually in clish by default):
       clish
3. Run and capture the output of:
       show route
       show route static
       show ipv6 route
       show configuration static-route
   Optional (skip if the command is unknown):
       show arp
       show vpn tunnels
4. Save each gateway's output to a text file named:
       routing/<gateway-name>.show-route.txt
5. Send the routing/ folder back to ValeronLabs (or drop it inside the
   run-* export folder before zipping).

Notes:
 - 'show route' is the live routing table (Connected/Static/BGP/OSPF).
 - 'show ipv6 route' — skip only if the gateway has no IPv6.
 - 'show configuration static-route' is the persistent static config.
 - These are read-only display commands — they change nothing.
==================================================================
"""

# Parse a Gaia 'show route' line, e.g.:
#   S    0.0.0.0/0        via 10.0.0.1, eth0, cost 0, age 12345
#   C    10.0.0.0/24      is directly connected, eth0
ROUTE_RE = re.compile(
    r"^\s*([A-Z])\*?\s+"                       # code (C/S/B/O/...)
    r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+"    # dest prefix
    r"(.*)$"                                    # remainder (via / connected)
)
VIA_RE = re.compile(r"via\s+(\d{1,3}(?:\.\d{1,3}){3})")
IFACE_RE = re.compile(r"(?:connected,\s*|,\s*)([A-Za-z][\w.\-]*\d[\w.\-]*)")


def parse_show_route(text):
    routes = []
    for line in (text or "").splitlines():
        m = ROUTE_RE.match(line)
        if not m:
            continue
        code, dest, rest = m.group(1), m.group(2), m.group(3)
        via = VIA_RE.search(rest)
        iface = IFACE_RE.search(rest)
        routes.append({
            "code": code,
            "dest": dest,
            "nexthop": via.group(1) if via else ("connected" if "connected" in rest else ""),
            "interface": iface.group(1) if iface else "",
            "raw": line.strip(),
        })
    return routes


def gateways_from_run_dir(run_dir, username, password):
    path = Path(run_dir) / "gateways-and-servers.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        print("  Could not read {}".format(path))
        return []
    out = []
    for gw in (data if isinstance(data, list) else []):
        if not isinstance(gw, dict):
            continue
        if gw.get("type") not in ("simple-gateway", "simple-cluster", "CpmiGatewayCluster",
                                   "CpmiVsClusterNetobj", "CpmiVsxClusterNetobj"):
            continue
        ip = gw.get("ipv4-address")
        if not ip:
            continue
        out.append({"name": gw.get("name", ip), "host": ip,
                    "username": username, "password": password})
    return out


def gateways_from_csv(path):
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row.get("host"):
                out.append({k: (row.get(k) or "").strip() for k in
                            ("name", "host", "username", "password")})
    return out


def collect_one(gw, key_path, out_dir, timeout=25):
    try:
        import paramiko
    except ImportError:
        print("\nThis script needs paramiko for SSH. Install it once:\n    pip install paramiko\n")
        sys.exit(1)
    name = gw.get("name") or gw.get("host")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs = {"hostname": gw["host"], "username": gw.get("username") or "admin",
                      "timeout": timeout, "allow_agent": False, "look_for_keys": False}
    if key_path:
        connect_kwargs["key_filename"] = str(Path(key_path).expanduser())
    else:
        connect_kwargs["password"] = gw.get("password") or ""
    try:
        client.connect(**connect_kwargs)
    except Exception as exc:
        print("  {}  SSH FAILED: {}".format(name, exc))
        return {"name": name, "host": gw["host"], "status": "ssh-failed",
                "note": str(exc)[:160], "routes": 0}
    raw_parts = []
    routes = []
    try:
        for cmd in CLISH_COMMANDS:
            # clish -c runs one command non-interactively
            stdin, stdout, stderr = client.exec_command("clish -c '{}'".format(cmd), timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            raw_parts.append("# === {} ===\n{}".format(cmd, out))
            if cmd == "show route":
                routes = parse_show_route(out)
    finally:
        client.close()
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w\-.]+", "_", name)
    (out_dir / "{}.show-route.txt".format(safe)).write_text("\n\n".join(raw_parts), encoding="utf-8")
    (out_dir / "{}.json".format(safe)).write_text(
        json.dumps({"name": name, "host": gw["host"], "routes": routes}, indent=2), encoding="utf-8")
    print("  {}  OK — {} routes".format(name, len(routes)))
    return {"name": name, "host": gw["host"], "status": "ok",
            "note": "", "routes": len(routes)}


def main():
    p = argparse.ArgumentParser(description="Check Point Gaia routing collector (read-only)")
    p.add_argument("--run-dir", help="A mgmt collector run-* folder; discover gateway IPs from it")
    p.add_argument("--gateways-file", help="CSV: name,host,username,password")
    p.add_argument("--username", help="Shared SSH username (with --run-dir)")
    p.add_argument("--password", help="Shared SSH password (with --run-dir)")
    p.add_argument("--key", help="SSH private key file (instead of password)")
    p.add_argument("--output", default="routing", help="Output folder (default: routing)")
    p.add_argument("--mop", action="store_true", help="Print the manual clish steps and exit")
    args = p.parse_args()

    if args.mop:
        print(MOP)
        return 0

    print(BANNER)
    if args.gateways_file:
        gws = gateways_from_csv(args.gateways_file)
    elif args.run_dir:
        if not (args.username and (args.password or args.key)):
            print("With --run-dir, also pass --username and --password (or --key).")
            return 2
        gws = gateways_from_run_dir(args.run_dir, args.username, args.password)
    else:
        print("Provide --gateways-file OR --run-dir (+ --username/--password). See --help / --mop.")
        return 2

    if not gws:
        print("No gateways to process.")
        return 1

    out_dir = Path(args.output)
    print("Collecting routing from {} gateway(s) -> {}/\n".format(len(gws), out_dir))
    summary = [collect_one(gw, args.key, out_dir) for gw in gws]

    with (out_dir / "_routing-summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["name", "host", "status", "routes", "note"])
        w.writeheader()
        w.writerows(summary)
    ok = sum(1 for s in summary if s["status"] == "ok")
    print("\nDone. {}/{} gateways collected. Summary: {}/_routing-summary.csv".format(
        ok, len(gws), out_dir))
    print("Tip: drop the {}/ folder into the run-* export folder before zipping.".format(out_dir))
    return 0


if __name__ == "__main__":
    main()
