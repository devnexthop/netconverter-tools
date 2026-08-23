#!/usr/bin/env python3
"""
FortiManager read-only config browser (NetConverter).

Reads a run-YYYYMMDD-HHMMSS bundle produced by fortimanager_collect.py and
generates a self-contained static HTML site under <run>/html_view/ using the
shared NetConverter chrome with the Fortinet (red) accent.

Pages: dashboard, managed devices, interfaces (IP addressing), static routes,
policy packages, firewall policies, address/service objects and groups, VIPs,
IP pools, IPsec phase 1/2 tunnels, SSL VPN, and raw JSON.

Usage:
    python build_html.py --input run-YYYYMMDD-HHMMSS
    python build_html.py --input run-... --output /some/path/html_view
"""

from __future__ import annotations

__version__ = "1.3.0"

# Nav pages omitted from the customer browse-only HTML (see --analysis).
_ANALYSIS_NAV = frozenset({"compliance.html", "risk.html"})

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.cve_intel import cpe_for_version, device_cve_status, fetch_cve_intel  # noqa: E402
from core.cve_intel import has_patch as _has_patch  # noqa: E402
from core.html_site import SiteBuilder, esc, sev_badge  # noqa: E402
from fortigate_config import find_local_configs_dir, merge_run_local_configs  # noqa: E402

# Navigation (grouped). ("group", "Label") renders a section heading.
NAV = [
    ("group", "Overview"),
    ("index.html", "Dashboard"),
    ("audit.html", "Audit (by Device)"),
    ("revisions.html", "Revisions & Changes"),
    ("optimization.html", "Optimization"),
    ("simplify.html", "Simplify & Merge"),
    ("relationships.html", "Relationships (Where-Used)"),
    ("compliance.html", "Compliance (NIST/CIS)"),
    ("risk.html", "Versions & CVE"),
    ("group", "Inventory"),
    ("devices.html", "Managed Devices"),
    ("appliances.html", "Physical Appliances"),
    ("interfaces.html", "Interfaces / IPs"),
    ("zones.html", "Zones"),
    ("routes.html", "Static Routes"),
    ("dhcp.html", "DHCP Servers"),
    ("dhcp_leases.html", "DHCP Leases"),
    ("admins.html", "Administrators"),
    ("group", "Live State"),
    ("policy_hits.html", "Policy Hit Counters"),
    ("ha_status.html", "HA / Cluster Sync"),
    ("sessions.html", "Resource Usage"),
    ("routes_live.html", "Live Routes (FIB)"),
    ("group", "Policy"),
    ("packages.html", "Policy Packages"),
    ("policies.html", "Firewall Policies"),
    ("central_snat.html", "Central SNAT"),
    ("group", "Objects"),
    ("addresses.html", "Addresses"),
    ("address_groups.html", "Address Groups"),
    ("services.html", "Services"),
    ("service_groups.html", "Service Groups"),
    ("schedules.html", "Schedules"),
    ("vips.html", "Virtual IPs"),
    ("ippools.html", "IP Pools"),
    ("profiles.html", "Security Profiles"),
    ("users.html", "Users & Groups"),
    ("group", "VPN"),
    ("vpn_map.html", "VPN Map"),
    ("vpn_matrix.html", "VPN Matrix"),
    ("vpn_phase1.html", "IPsec Phase 1"),
    ("vpn_phase2.html", "IPsec Phase 2"),
    ("vpn_ssl.html", "SSL VPN"),
    ("group", "Data"),
    ("coverage.html", "Collection Coverage"),
    ("raw.json.html", "Raw JSON"),
]

# Table page definitions: file, title, snapshot key, table id, columns.
TABLES = [
    ("devices.html", "Managed Devices", "devices", "dev",
     [("ADOM", "adom"), ("Name", "name"), ("Serial", "sn"), ("Mgmt IP", "ip"),
      ("Platform", "platform"), ("OS", "os_ver"), ("HA", "ha_mode"),
      ("VDOMs", "vdoms"), ("Conn", "conn_status"), ("Local Cfg Rev", "config_revision"),
      ("Device Revisions", "revision_info"), ("Description", "desc")]),
    ("routes.html", "Static Routes", "routes", "rt",
     [("Device", "device"), ("VDOM", "vdom"), ("Seq", "seq"), ("Destination", "dst"),
      ("Gateway", "gateway"), ("Egress Intf", "interface"), ("Distance", "distance"),
      ("Priority", "priority"), ("Status", "status"), ("Blackhole", "blackhole"),
      ("Comment", "comment")]),
    ("packages.html", "Policy Packages", "packages", "pkg",
     [("ADOM", "adom"), ("Name", "name"), ("Type", "type"), ("Scope (devices)", "scope")]),
    ("central_snat.html", "Central SNAT Rules", "central_snat", "csnat",
     [("ADOM", "adom"), ("Package", "package"), ("ID", "policyid"),
      ("Src Intf", "srcintf"), ("Dst Intf", "dstintf"), ("Orig Addr", "orig_addr"),
      ("Dest Addr", "dst_addr"), ("NAT Pool", "nat_ippool"), ("Protocol", "protocol"),
      ("Orig Port", "orig_port"), ("NAT Port", "nat_port"), ("Status", "status"),
      ("Comments", "comments")]),
    ("zones.html", "Security Zones", "zones", "zn",
     [("Device", "device"), ("VDOM", "vdom"), ("Zone", "name"),
      ("Interfaces", "interfaces"), ("Intrazone", "intrazone")]),
    ("dhcp.html", "DHCP Servers", "dhcp_servers", "dhcp",
     [("Device", "device"), ("VDOM", "vdom"), ("ID", "id"), ("Interface", "interface"),
      ("Range", "range"), ("Netmask", "netmask"), ("Gateway", "gateway"),
      ("DNS", "dns"), ("Domain", "domain"), ("Lease (s)", "lease")]),
    ("dhcp_leases.html", "DHCP Leases (at collection time)", "dhcp_leases", "dhl",
     [("Device", "device"), ("IP", "ip"), ("MAC", "mac"), ("Hostname", "hostname"),
      ("Interface", "interface"), ("Status", "status"), ("Expires", "expires"),
      ("Reserved", "reserved"), ("Vendor (VCI)", "vci"), ("Server ID", "server_id")]),
    ("policy_hits.html", "Policy Hit Counters (live at collection)", "policy_hits", "phits",
     [("Device", "device"), ("ADOM", "adom"), ("VDOM", "vdom"), ("Policy ID", "policyid"),
      ("Name", "name"), ("Bytes", "bytes"), ("Packets", "packets"),
      ("Active Sess", "active_sessions"), ("Hit Count", "hit_count"),
      ("First Used", "first_used"), ("Last Used", "last_used")]),
    ("ha_status.html", "HA / Cluster Sync (live)", "ha_status_flat", "ha",
     [("Device", "device"), ("ADOM", "adom"), ("Peers", "peers_summary"),
      ("Checksum", "checksum_summary"), ("Statistics", "statistics_summary")]),
    ("sessions.html", "Resource Usage (live)", "sessions_flat", "sess",
     [("Device", "device"), ("ADOM", "adom"), ("CPU %", "cpu"),
      ("Memory %", "memory"), ("Sessions", "session_count"),
      ("Session Setup Rate", "session_setup_rate"), ("Detail", "detail")]),
    ("routes_live.html", "Live Routes / FIB (at collection)", "routes_live", "rlive",
     [("Device", "device"), ("ADOM", "adom"), ("VDOM", "vdom"), ("Destination", "dst"),
      ("Gateway", "gateway"), ("Interface", "interface"), ("Type", "type"),
      ("Distance", "distance"), ("Metric", "metric")]),
    ("schedules.html", "Schedules", "schedules", "sched",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Kind", "kind"),
      ("Window", "value"), ("Members", "member"), ("Comment", "comment")]),
    ("profiles.html", "Security (UTM) Profiles", "sec_profiles", "prof",
     [("ADOM", "adom"), ("Type", "type"), ("Name", "name"), ("Comment", "comment")]),
    ("addresses.html", "Address Objects", "addresses", "addr",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Type", "type"),
      ("Value", "value"), ("Interface", "interface"), ("Comment", "comment")]),
    ("address_groups.html", "Address Groups", "address_groups", "addrgrp",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Members", "member"),
      ("Comment", "comment")]),
    ("services.html", "Service Objects", "services", "svc",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Protocol", "protocol"),
      ("Ports", "ports"), ("Category", "category"), ("Comment", "comment")]),
    ("service_groups.html", "Service Groups", "service_groups", "svcgrp",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Members", "member"),
      ("Comment", "comment")]),
    ("vips.html", "Virtual IPs (DNAT)", "vips", "vip",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Ext IP", "extip"),
      ("Mapped IP", "mappedip"), ("Ext Port", "extport"), ("Mapped Port", "mappedport"),
      ("Protocol", "protocol"), ("Comment", "comment")]),
    ("ippools.html", "IP Pools (SNAT)", "ippools", "pool",
     [("ADOM", "adom"), ("Device(s)", "device"), ("Name", "name"), ("Type", "type"),
      ("Start IP", "startip"), ("End IP", "endip"), ("Comment", "comment")]),
    ("vpn_phase1.html", "IPsec VPN — Phase 1", "vpn_phase1", "p1",
     [("Device", "device"), ("VDOM", "vdom"), ("Name", "name"), ("Interface", "interface"),
      ("Remote GW", "remote_gw"), ("Local GW", "local_gw"), ("IKE", "ike"), ("Mode", "mode"),
      ("Proposal", "proposal"), ("DH", "dhgrp"), ("Key Life", "keylife"), ("PSK", "psk"),
      ("Comments", "comments")]),
    ("vpn_phase2.html", "IPsec VPN — Phase 2", "vpn_phase2", "p2",
     [("Device", "device"), ("VDOM", "vdom"), ("Name", "name"), ("Phase 1", "phase1"),
      ("Proposal", "proposal"), ("Source Subnet", "src_subnet"), ("Dest Subnet", "dst_subnet"),
      ("PFS", "pfs"), ("Key Life (s)", "keylife_sec"), ("Comments", "comments")]),
    ("vpn_ssl.html", "SSL VPN Portals", "vpn_ssl", "ssl",
     [("Device", "device"), ("VDOM", "vdom"), ("Status", "status"), ("Port", "port"),
      ("Source Intf", "source_interface"), ("Tunnel Pools", "tunnel_ip_pools"),
      ("Server Cert", "servercert")]),
]


def load_snapshot(run: Path) -> dict:
    path = run / "fortimanager_snapshot.json"
    if not path.is_file():
        print(f"Error: snapshot not found: {path}")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


# ===================== analysis engine =====================

def _tokens(value) -> list[str]:
    """Split a joined member/field string into individual object-name tokens."""
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            out.extend(_tokens(v))
        return out
    return [t for t in re.split(r"[\s,]+", str(value)) if t and t not in ("-",)]


def _bare_ip(value: str) -> str:
    return str(value or "").split("/")[0].strip()


def _has_real_ip(value: str) -> bool:
    """An assigned, routable interface address (tunnel placeholders like 0.0.0.0/0 don't count)."""
    bare = _bare_ip(value)
    return bool(bare) and bare != "0.0.0.0"


def _network_of(ip_mask: str) -> str:
    """'10.0.0.221/22' -> '10.0.0.0/22' (best-effort, no external deps)."""
    s = str(ip_mask or "").strip()
    if "/" not in s:
        return ""
    addr, _, bits = s.partition("/")
    try:
        b = int(bits)
        octets = [int(x) for x in addr.split(".")]
        if len(octets) != 4:
            return ""
        val = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        mask = (0xFFFFFFFF << (32 - b)) & 0xFFFFFFFF if b else 0
        net = val & mask
        return f"{(net >> 24) & 255}.{(net >> 16) & 255}.{(net >> 8) & 255}.{net & 255}/{b}"
    except (ValueError, TypeError):
        return ""


WAN_HINTS = ("wan", "ppp", "sdwan", "internet", "external", "outside", "untrust")
CLEARTEXT_ACCESS = ("telnet", "http")          # http (not https) + telnet
MGMT_ACCESS = ("telnet", "http", "https", "ssh", "snmp")
WEAK_DH = {"1", "2", "5"}


def _is_wan(iface: dict) -> bool:
    n = str(iface.get("name", "")).lower()
    a = str(iface.get("alias", "")).lower()
    d = str(iface.get("description", "")).lower()
    return (any(n.startswith(h) for h in WAN_HINTS)
            or any(h in a for h in WAN_HINTS)
            or "external" in d or "internet" in d)


def _access_tokens(iface: dict) -> list[str]:
    return [t for t in re.split(r"[\s,]+", str(iface.get("allowaccess", "")).lower())
            if t and not t.startswith("0x")]


def _proposal_weak(value: str) -> bool:
    s = str(value or "").lower()
    return ("des" in s) or ("md5" in s)        # des/3des/md5 are weak


def analyze(snap: dict) -> dict:
    addresses = [a for a in snap.get("addresses", []) if isinstance(a, dict)]
    services = [s for s in snap.get("services", []) if isinstance(s, dict)]
    addr_groups = [g for g in snap.get("address_groups", []) if isinstance(g, dict)]
    svc_groups = [g for g in snap.get("service_groups", []) if isinstance(g, dict)]
    vips = [v for v in snap.get("vips", []) if isinstance(v, dict)]
    policies = [p for p in snap.get("policies", []) if isinstance(p, dict)]
    interfaces = [i for i in snap.get("interfaces", []) if isinstance(i, dict)]
    routes = [r for r in snap.get("routes", []) if isinstance(r, dict)]
    p1 = [p for p in snap.get("vpn_phase1", []) if isinstance(p, dict)]
    p2 = [p for p in snap.get("vpn_phase2", []) if isinstance(p, dict)]
    ssl = [s for s in snap.get("vpn_ssl", []) if isinstance(s, dict)]

    # ---- cross-reference (where-used) ----
    ref_by: dict[str, list[str]] = defaultdict(list)
    for g in addr_groups:
        for m in _tokens(g.get("member")):
            ref_by[m].append(f"address-group ▸ {g.get('name', '')}")
    for g in svc_groups:
        for m in _tokens(g.get("member")):
            ref_by[m].append(f"service-group ▸ {g.get('name', '')}")
    for p in policies:
        loc = f"{p.get('package', '')} #{p.get('policyid', '')}"
        for f in ("srcaddr", "dstaddr"):
            for m in _tokens(p.get(f)):
                ref_by[m].append(f"policy {loc} ({f})")
        for m in _tokens(p.get("service")):
            ref_by[m].append(f"policy {loc} (service)")
    ref_count = Counter({k: len(v) for k, v in ref_by.items()})

    def _addr_value(a: dict) -> str:
        return str(a.get("value", "") or "")

    def _svc_value(s: dict) -> str:
        return f"{s.get('protocol', '')} {s.get('ports', '')}".strip()

    # ---- duplicates ----
    by_addr_val: dict[str, list[str]] = defaultdict(list)
    for a in addresses:
        v = _addr_value(a)
        if v:
            by_addr_val[v].append(a.get("name", ""))
    dup_addr = sorted([(v, ns) for v, ns in by_addr_val.items() if len(ns) > 1],
                      key=lambda x: -len(x[1]))
    by_svc_val: dict[str, list[str]] = defaultdict(list)
    for s in services:
        v = _svc_value(s)
        if v:
            by_svc_val[v].append(s.get("name", ""))
    dup_svc = sorted([(v, ns) for v, ns in by_svc_val.items() if len(ns) > 1],
                     key=lambda x: -len(x[1]))

    # ---- usage closure (for unused detection) ----
    # Group membership only makes an object "used" when the group itself is
    # used. Seed the used-set from objects a pushed policy references directly,
    # then propagate through group membership to a fixpoint so members of nested
    # groups are covered. (Mirrors the Check Point unused logic for parity.)
    addr_group_members = {g.get("name", ""): set(_tokens(g.get("member"))) for g in addr_groups}
    svc_group_members = {g.get("name", ""): set(_tokens(g.get("member"))) for g in svc_groups}

    def _usage_closure(seeds: set, group_members: dict) -> set:
        used = set(seeds)
        changed = True
        while changed:
            changed = False
            for gname, members in group_members.items():
                if gname in used:
                    new = members - used
                    if new:
                        used |= new
                        changed = True
        return used

    addr_seeds: set[str] = set()
    svc_seeds: set[str] = set()
    for p in policies:
        for f in ("srcaddr", "dstaddr"):
            addr_seeds.update(_tokens(p.get(f)))
        svc_seeds.update(_tokens(p.get("service")))
    used_addr_names = _usage_closure(addr_seeds, addr_group_members)
    used_svc_names = _usage_closure(svc_seeds, svc_group_members)

    # ---- unused / empty ----
    BUILTIN = {"all", "none", "any"}
    unused_addr = [a for a in addresses
                   if a.get("name") not in used_addr_names and str(a.get("name", "")).lower() not in BUILTIN]
    unused_svc = [s for s in services
                  if s.get("name") not in used_svc_names and str(s.get("name", "")).lower() not in BUILTIN]
    unused_addrgrp = [g for g in addr_groups if g.get("name") not in used_addr_names]
    unused_svcgrp = [g for g in svc_groups if g.get("name") not in used_svc_names]
    empty_groups = ([dict(g, kind="address-group") for g in addr_groups if not _tokens(g.get("member"))]
                    + [dict(g, kind="service-group") for g in svc_groups if not _tokens(g.get("member"))])

    # ---- policy hygiene (degrades gracefully when 0 policies) ----
    def _is_any(v: str) -> bool:
        return any(t.lower() == "all" for t in _tokens(v)) or not _tokens(v)
    permissive, no_log, disabled, no_comment = [], [], [], []
    for p in policies:
        action = str(p.get("action", "")).lower()
        loc = {"package": p.get("package", ""), "id": p.get("policyid", ""), "name": p.get("name", "")}
        if str(p.get("status", "")).lower() in ("disable", "0", "down"):
            disabled.append(loc)
            continue
        if action in ("accept", "1") and _is_any(p.get("srcaddr")) and _is_any(p.get("dstaddr")) and _is_any(p.get("service")):
            permissive.append(loc)
        if action in ("accept", "1") and str(p.get("logtraffic", "")).lower() in ("disable", "", "0"):
            no_log.append(loc)
        if not str(p.get("comments", "")).strip():
            no_comment.append(loc)

    # ---- interface / management-plane exposure ----
    p1_ifaces = {(t.get("device"), _tokens(t.get("interface"))[0])
                 for t in p1 if _tokens(t.get("interface"))}
    mgmt_cleartext, mgmt_wan, ifaces_no_ip, ifaces_down = [], [], [], []
    for i in interfaces:
        toks = _access_tokens(i)
        wan = _is_wan(i) or (i.get("device"), i.get("name")) in p1_ifaces
        row = {"device": i.get("device", ""), "name": i.get("name", ""), "alias": i.get("alias", ""),
               "ip": i.get("ip", ""), "access": i.get("allowaccess", ""), "wan": wan}
        if any(t in CLEARTEXT_ACCESS for t in toks):
            mgmt_cleartext.append(row)
        if wan and any(t in MGMT_ACCESS for t in toks):
            mgmt_wan.append(row)
        if not _has_real_ip(i.get("ip")):
            ifaces_no_ip.append(i)
        if str(i.get("status", "")).lower() == "down":
            ifaces_down.append(i)
    default_routes = [r for r in routes if str(r.get("dst", "")).startswith("0.0.0.0")]

    # ---- VPN crypto hygiene ----
    ike_aggressive = [t for t in p1 if str(t.get("mode", "")).lower() == "aggressive"]
    weak_dh = [t for t in p1 if set(_tokens(t.get("dhgrp"))) & WEAK_DH]
    weak_proposal = ([dict(t, _ph="P1") for t in p1 if _proposal_weak(t.get("proposal"))]
                     + [dict(t, _ph="P2") for t in p2 if _proposal_weak(t.get("proposal"))])
    ssl_enabled = [s for s in ssl if "enable" in str(s.get("status", "")).lower()]
    ssl_devices = sorted({s.get("device") for s in ssl_enabled if s.get("device")})

    return {
        "counts": {"addresses": len(addresses), "services": len(services),
                   "addr_groups": len(addr_groups), "svc_groups": len(svc_groups),
                   "policies": len(policies), "interfaces": len(interfaces)},
        "dup_addr": dup_addr, "dup_svc": dup_svc,
        "unused_addr": unused_addr, "unused_svc": unused_svc,
        "unused_addrgrp": unused_addrgrp, "unused_svcgrp": unused_svcgrp,
        "empty_groups": empty_groups,
        "permissive": permissive, "no_log": no_log, "disabled": disabled, "no_comment": no_comment,
        "mgmt_cleartext": mgmt_cleartext, "mgmt_wan": mgmt_wan,
        "ifaces_no_ip": ifaces_no_ip, "ifaces_down": ifaces_down, "default_routes": default_routes,
        "ike_aggressive": ike_aggressive, "weak_dh": weak_dh, "weak_proposal": weak_proposal,
        "ssl_enabled": ssl_enabled, "ssl_devices": ssl_devices,
        "ref_by": ref_by, "ref_count": ref_count,
        "addresses": addresses, "services": services,
        "addr_groups": addr_groups, "svc_groups": svc_groups,
        "_addr_value": _addr_value, "_svc_value": _svc_value,
    }


# Curated FortiOS advisories. The `fixed` map (major-train -> first fixed build) lets us
# do *exact* version-range matching when the collector captured the patch level, so a device
# is only flagged when its train is affected AND (build known) it is below the fixed build.
# Always verify the exact build against the Fortinet PSIRT advisory + NVD.
KNOWN_CVES = [
    {"cve": "CVE-2024-55591", "sev": "Critical (CVSS 9.6)", "cond": "all", "feature": "admin/HTTPS plane",
     "summary": "FortiOS/FortiProxy authentication bypass via crafted Node.js websocket — "
                "remote attacker gains super-admin (exploited in the wild, Jan 2025).",
     "affected": "FortiOS 7.0.0–7.0.16 (fixed 7.0.17), FortiProxy 7.0/7.2.",
     "fixed": {"7.0": "7.0.17"},
     "action": "Restrict admin/HTTPS access to mgmt interfaces; confirm fixed build; review admins."},
    {"cve": "CVE-2024-23113", "sev": "Critical (CVSS 9.8)", "cond": "all", "feature": "FGFM (mgmt)",
     "summary": "fgfmd (FortiGate-to-FortiManager) format-string flaw allowing remote code execution.",
     "affected": "FortiOS 7.4<7.4.3, 7.2<7.2.7, 7.0<7.0.13, 6.4<6.4.15.",
     "fixed": {"7.4": "7.4.3", "7.2": "7.2.7", "7.0": "7.0.13", "6.4": "6.4.15"},
     "action": "All FortiManager-managed gateways use FGFM — patch/verify fixed build; "
               "restrict FGFM (TCP 541) to the FortiManager."},
    {"cve": "CVE-2024-21762", "sev": "Critical (CVSS 9.8)", "cond": "ssl", "feature": "SSL-VPN",
     "summary": "SSL-VPN out-of-bounds write enabling pre-auth remote code execution.",
     "affected": "FortiOS 7.4<7.4.3, 7.2<7.2.7, 7.0<7.0.14, 6.4<6.4.15, 6.2<6.2.16.",
     "fixed": {"7.4": "7.4.3", "7.2": "7.2.7", "7.0": "7.0.14", "6.4": "6.4.15", "6.2": "6.2.16"},
     "action": "Applies where SSL-VPN is enabled — patch, or disable SSL-VPN if unused."},
    {"cve": "CVE-2023-27997", "sev": "Critical (CVSS 9.8)", "cond": "ssl", "feature": "SSL-VPN",
     "summary": "XORtigate — SSL-VPN heap overflow allowing pre-auth remote code execution.",
     "affected": "FortiOS 7.2<7.2.5, 7.0<7.0.12, 6.4<6.4.13, 6.2<6.2.15, 6.0<6.0.17.",
     "fixed": {"7.2": "7.2.5", "7.0": "7.0.12", "6.4": "6.4.13", "6.2": "6.2.15", "6.0": "6.0.17"},
     "action": "Applies where SSL-VPN is enabled — confirm fixed build."},
    {"cve": "CVE-2022-42475", "sev": "Critical (CVSS 9.8)", "cond": "ssl", "feature": "SSL-VPN",
     "summary": "SSL-VPN heap buffer overflow allowing pre-auth remote code execution (exploited).",
     "affected": "FortiOS 7.2<7.2.3, 7.0<7.0.9, 6.4<6.4.12, 6.2<6.2.12, 6.0<6.0.16.",
     "fixed": {"7.2": "7.2.3", "7.0": "7.0.9", "6.4": "6.4.12", "6.2": "6.2.12", "6.0": "6.0.16"},
     "action": "Applies where SSL-VPN is enabled — confirm fixed build."},
]


def analyze_versions(snap: dict, ssl_devices: list[str]) -> dict:
    devices = [d for d in snap.get("devices", []) if isinstance(d, dict)]
    by_version: Counter = Counter()
    rows = []
    ssl_set = set(ssl_devices)
    for d in devices:
        ver = str(d.get("os_ver") or "unknown")
        by_version[ver] += 1
        major = ver.split(".")[0] if ver and ver[0].isdigit() else ""
        eol = major in ("5", "6")
        rows.append({"name": d.get("name", ""), "platform": d.get("platform", ""),
                     "version": ver, "serial": d.get("sn", ""), "eol": eol,
                     "ssl": d.get("name") in ssl_set})
    return {"by_version": dict(sorted(by_version.items())),
            "devices": sorted(rows, key=lambda r: str(r["name"])),
            "ssl_devices": ssl_devices}


def _kpi(site: SiteBuilder, items) -> str:
    return site.cards(items)


def build_optimization(site: SiteBuilder, snap: dict, A: dict) -> None:
    unused_total = (len(A["unused_addr"]) + len(A["unused_svc"])
                    + len(A["unused_addrgrp"]) + len(A["unused_svcgrp"]))
    body = ["<h2>Optimization &amp; Hygiene</h2>",
            '<div class="meta">Heuristic findings from the read-only snapshot — review before any change.</div>']
    body.append(site.cards([
        (str(len(A["dup_addr"]) + len(A["dup_svc"])), "Duplicate Values", "warn" if (A["dup_addr"] or A["dup_svc"]) else ""),
        (str(unused_total), "Unreferenced Objects", "warn" if unused_total else ""),
        (str(len(A["empty_groups"])), "Empty Groups", "warn" if A["empty_groups"] else ""),
        (str(len(A["permissive"])), "Any/Any/Any Accept", "bad" if A["permissive"] else ""),
        (str(len(A["ifaces_no_ip"])), "Interfaces w/o IP", ""),
        (str(len(A["ifaces_down"])), "Interfaces Down", "warn" if A["ifaces_down"] else ""),
    ]))
    if A["counts"]["policies"] == 0:
        body.append('<div class="note warnbox">This FortiManager pushes <strong>0</strong> firewall '
                    'policies for these devices (policies are managed locally), so rule-based checks '
                    'below show no findings. Object hygiene still applies. Re-run the collector if ADOM '
                    'policy packages are later populated.</div>')

    # Duplicate addresses
    body.append(f'<div class="section-title" id="dup">Duplicate Address Objects (same value) '
                f'<span class="count">{len(A["dup_addr"])}</span></div>')
    body.append('<table><thead><tr><th>Value</th><th>#</th><th>Object names</th></tr></thead><tbody>')
    for val, names in A["dup_addr"][:400]:
        body.append(f"<tr><td class='mono'>{esc(val)}</td><td>{len(names)}</td>"
                    f"<td>{esc(', '.join(names))}</td></tr>")
    body.append('</tbody></table>')
    # Duplicate services
    body.append(f'<div class="section-title" id="dupsvc">Duplicate Service Objects '
                f'<span class="count">{len(A["dup_svc"])}</span></div>')
    body.append('<table><thead><tr><th>Protocol / Ports</th><th>#</th><th>Object names</th></tr></thead><tbody>')
    for val, names in A["dup_svc"][:400]:
        body.append(f"<tr><td class='mono'>{esc(val)}</td><td>{len(names)}</td>"
                    f"<td>{esc(', '.join(names))}</td></tr>")
    body.append('</tbody></table>')

    # Unreferenced
    body.append(f'<div class="section-title" id="unused">Unreferenced Objects '
                f'<span class="count">{unused_total}</span></div>')
    body.append('<div class="note warnbox">Not referenced by any pushed policy, and not a member of '
                'any <em>used</em> group (group membership resolved transitively, including nested '
                'groups). Because policies are managed locally on these FortiGates, an object used '
                'only in a local policy can still appear here — verify before deleting.</div>')
    body.append(site.searchbox("untbl", "uncnt"))
    body.append('<div class="meta"><span id="uncnt"></span></div>')
    body.append('<table id="untbl"><thead><tr><th>Name</th><th>Category</th><th>Value</th></tr></thead><tbody>')
    for a in A["unused_addr"]:
        body.append(f"<tr><td class='mono'>{esc(a.get('name'))}</td><td>address</td>"
                    f"<td class='mono'>{esc(A['_addr_value'](a))}</td></tr>")
    for s in A["unused_svc"]:
        body.append(f"<tr><td class='mono'>{esc(s.get('name'))}</td><td>service</td>"
                    f"<td class='mono'>{esc(A['_svc_value'](s))}</td></tr>")
    for g in A["unused_addrgrp"]:
        body.append(f"<tr><td class='mono'>{esc(g.get('name'))}</td><td>address-group</td><td></td></tr>")
    for g in A["unused_svcgrp"]:
        body.append(f"<tr><td class='mono'>{esc(g.get('name'))}</td><td>service-group</td><td></td></tr>")
    body.append('</tbody></table>')

    # Empty groups
    body.append(f'<div class="section-title" id="empty">Empty Groups '
                f'<span class="count">{len(A["empty_groups"])}</span></div>')
    body.append('<table><thead><tr><th>Name</th><th>Type</th></tr></thead><tbody>')
    for g in A["empty_groups"]:
        body.append(f"<tr><td class='mono'>{esc(g.get('name'))}</td><td>{esc(g.get('kind'))}</td></tr>")
    body.append('</tbody></table>')
    site.page("optimization.html", "Optimization", "".join(body))


def build_simplify(site: SiteBuilder, snap: dict, A: dict) -> None:
    body = ['<h2>Simplify &amp; Merge</h2>',
            '<div class="note">Consolidation candidates — multiple objects describing the same thing, '
            'or groups that overlap. Confirm intent before merging.</div>']
    body.append(site.cards([
        (str(len(A["dup_addr"])), "Mergeable Address Sets", "warn" if A["dup_addr"] else ""),
        (str(len(A["dup_svc"])), "Mergeable Service Sets", "warn" if A["dup_svc"] else ""),
        (str(len(A["empty_groups"])), "Empty Groups to Remove", ""),
    ]))
    body.append('<div class="section-title" id="merge">Address objects to merge (identical value)'
                f' <span class="count">{len(A["dup_addr"])}</span></div>')
    body.append('<div class="note">Keep one canonical object per value and re-point members/rules to it.</div>')
    body.append('<table><thead><tr><th>Canonical value</th><th>#Objects</th><th>Keep one of</th>'
                '</tr></thead><tbody>')
    for val, names in A["dup_addr"][:400]:
        body.append(f"<tr><td class='mono'>{esc(val)}</td><td>{len(names)}</td>"
                    f"<td>{esc(', '.join(names))}</td></tr>")
    body.append('</tbody></table>')
    body.append('<div class="section-title" id="mergesvc">Service objects to merge'
                f' <span class="count">{len(A["dup_svc"])}</span></div>')
    body.append('<table><thead><tr><th>Protocol / Ports</th><th>#Objects</th><th>Keep one of</th>'
                '</tr></thead><tbody>')
    for val, names in A["dup_svc"][:400]:
        body.append(f"<tr><td class='mono'>{esc(val)}</td><td>{len(names)}</td>"
                    f"<td>{esc(', '.join(names))}</td></tr>")
    body.append('</tbody></table>')
    site.page("simplify.html", "Simplify", "".join(body))


def build_relationships(site: SiteBuilder, snap: dict, A: dict) -> None:
    addr_by = {a.get("name"): a for a in A["addresses"]}
    svc_by = {s.get("name"): s for s in A["services"]}
    grp_names = {g.get("name") for g in A["addr_groups"]} | {g.get("name") for g in A["svc_groups"]}
    rows = []
    for name, refs in sorted(A["ref_by"].items(), key=lambda kv: -len(kv[1])):
        if name in addr_by:
            typ, val = "address", A["_addr_value"](addr_by[name])
        elif name in svc_by:
            typ, val = "service", A["_svc_value"](svc_by[name])
        elif name in grp_names:
            typ, val = "group", ""
        else:
            typ, val = "object", ""
        shown = refs[:8]
        more = f" … +{len(refs) - 8} more" if len(refs) > 8 else ""
        rows.append(f"<tr><td class='mono'>{esc(name)}</td><td>{esc(typ)}</td>"
                    f"<td class='mono'>{esc(val)}</td><td>{len(refs)}</td>"
                    f"<td style='font-size:11px;color:var(--muted)'>{esc('; '.join(shown))}{esc(more)}</td></tr>")
    body = ['<h2>Relationships <span class="count">(Where-Used)</span></h2>',
            '<div class="note">Every object and the groups and policies that reference it, most-used '
            'first. Objects with <strong>0</strong> references are on '
            '<a href="optimization.html#unused">Optimization → Unreferenced</a>.</div>']
    body.append(site.cards([(str(len(rows)), "Referenced Objects", ""),
                            (str(sum(len(v) for v in A["ref_by"].values())), "Total References", "")]))
    body.append(site.searchbox("rel", "relcnt"))
    body.append('<div class="meta"><span id="relcnt"></span></div>')
    body.append('<table id="rel"><thead><tr><th>Object</th><th>Type</th><th>Value</th>'
                '<th>#Refs</th><th>Referenced By</th></tr></thead><tbody>')
    body.extend(rows)
    body.append('</tbody></table>')
    site.page("relationships.html", "Relationships", "".join(body))


def build_compliance(site: SiteBuilder, snap: dict, A: dict, intel: dict | None = None) -> None:
    intel = intel or {"kev": set(), "nvd": {}, "source": "curated"}
    kev = intel.get("kev", set())
    # Advisories that apply to this fleet AND are on the CISA KEV (actively-exploited) list.
    ssl_set = set(A["ssl_devices"])
    kev_hits = []
    for c in KNOWN_CVES:
        if c["cve"] not in kev:
            continue
        applies = (c["cond"] == "all") or (c["cond"] == "ssl" and ssl_set)
        if applies:
            kev_hits.append(c["cve"])
    unused_total = (len(A["unused_addr"]) + len(A["unused_svc"])
                    + len(A["unused_addrgrp"]) + len(A["unused_svcgrp"]))
    controls = [
        {"id": "AC-17 / SC-7", "csf": "PR.AC-3, PR.PT-4", "cis": "CIS 4.x", "sev": "high",
         "title": "Cleartext management access (HTTP/Telnet) on interfaces",
         "count": len(A["mgmt_cleartext"]), "page": "interfaces.html", "anchor": "mgmt",
         "why": "Telnet/HTTP expose admin credentials in cleartext — use HTTPS/SSH only."},
        {"id": "AC-17 / SC-7", "csf": "PR.AC-5", "cis": "CIS 4.x", "sev": "high",
         "title": "Management access on internet-facing (WAN) interfaces",
         "count": len(A["mgmt_wan"]), "page": "interfaces.html", "anchor": "mgmt",
         "why": "Admin planes reachable from untrusted networks should be removed or restricted by trusted hosts."},
        {"id": "SC-8 / SC-13", "csf": "PR.DS-2", "cis": "CIS 9.x", "sev": "high",
         "title": "Weak IPsec proposals (DES/3DES/MD5)",
         "count": len(A["weak_proposal"]), "page": "vpn_phase1.html", "anchor": "",
         "why": "Deprecated ciphers/hashes are cryptographically broken — use AES-GCM/SHA-256+."},
        {"id": "SC-12", "csf": "PR.DS-2", "cis": "CIS 9.x", "sev": "medium",
         "title": "Weak Diffie-Hellman groups (1/2/5) on IPsec",
         "count": len(A["weak_dh"]), "page": "vpn_phase1.html", "anchor": "",
         "why": "DH groups 1/2/5 are too small — use group 14+ (or ECP)."},
        {"id": "IA-2 / SC-8", "csf": "PR.AC-7", "cis": "CIS 9.x", "sev": "medium",
         "title": "IKE aggressive mode in use",
         "count": len(A["ike_aggressive"]), "page": "vpn_phase1.html", "anchor": "",
         "why": "Aggressive mode exposes identities/PSK hashes — prefer main mode / IKEv2."},
        {"id": "CM-7 / RA-5", "csf": "PR.IP-12", "cis": "CIS 12.x", "sev": "high",
         "title": "SSL-VPN enabled (attack-surface / CVE exposure)",
         "count": len(A["ssl_enabled"]), "page": "risk.html", "anchor": "",
         "why": "SSL-VPN is a frequent RCE target — patch promptly and restrict, or disable if unused."},
        {"id": "AC-4 / SC-7", "csf": "PR.AC-5", "cis": "CIS 4.x", "sev": "high",
         "title": "Overly permissive Any/Any/Any Accept policies",
         "count": len(A["permissive"]), "page": "policies.html", "anchor": "",
         "why": "Any-source/dest/service Accept defeats least-privilege segmentation."},
        {"id": "AU-2 / AU-12", "csf": "DE.AE-3", "cis": "CIS 8.x", "sev": "medium",
         "title": "Accept policies without logging",
         "count": len(A["no_log"]), "page": "policies.html", "anchor": "",
         "why": "Permitted traffic must be logged for detection and audit."},
        {"id": "CM-8", "csf": "ID.AM-1, ID.AM-2", "cis": "CIS 1.x", "sev": "medium",
         "title": "Unreferenced objects (inventory hygiene)",
         "count": unused_total, "page": "optimization.html", "anchor": "unused",
         "why": "Stale objects bloat the database and obscure real exposure."},
        {"id": "CM-8", "csf": "ID.AM-1", "cis": "CIS 1.x", "sev": "low",
         "title": "Duplicate objects (same value)",
         "count": len(A["dup_addr"]) + len(A["dup_svc"]), "page": "optimization.html", "anchor": "dup",
         "why": "One canonical object per value prevents inconsistent edits."},
        {"id": "SI-2 / CM-2", "csf": "ID.RA-1", "cis": "CIS 2.x", "sev": "high",
         "title": "End-of-support FortiOS versions",
         "count": sum(1 for d in snap.get("devices", []) if str(d.get("os_ver", ""))[:1] in ("5", "6")),
         "page": "risk.html", "anchor": "", "why": "Unsupported firmware no longer receives security fixes."},
        {"id": "RA-5 / SI-2", "csf": "ID.RA-1, RS.MI-3", "cis": "CIS 7.x", "sev": "high",
         "title": "Advisories on the CISA KEV (actively exploited in the wild)",
         "count": len(kev_hits), "page": "risk.html", "anchor": "",
         "why": "These CVEs apply to this platform and are confirmed exploited in the wild — "
                "verify the fixed build/patch on every affected device as top priority."},
    ]
    body = ['<h2>Compliance Mapping <span class="count">(NIST 800-53 · NIST CSF · CIS)</span></h2>',
            '<div class="note">Heuristic, data-driven mapping of configuration findings to common control '
            'families. An audit starting point, not a certification. Counts link to the underlying items.</div>']
    body.append('<table><thead><tr><th>Sev</th><th>NIST 800-53</th><th>NIST CSF</th><th>CIS</th>'
                '<th>Finding</th><th>Count</th><th>Rationale</th></tr></thead><tbody>')
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    for c in sorted(controls, key=lambda x: (sev_rank.get(x["sev"], 9), -x["count"])):
        anchor = f"#{c['anchor']}" if c["anchor"] else ""
        body.append(f'<tr><td>{sev_badge(c["sev"])}</td><td class="mono">{esc(c["id"])}</td>'
                    f'<td class="mono">{esc(c["csf"])}</td><td class="mono">{esc(c["cis"])}</td>'
                    f'<td><a href="{c["page"]}{anchor}">{esc(c["title"])}</a></td>'
                    f'<td>{c["count"]}</td><td>{esc(c["why"])}</td></tr>')
    body.append('</tbody></table>')
    site.page("compliance.html", "Compliance", "".join(body))


def build_risk(site: SiteBuilder, snap: dict, A: dict, intel: dict | None = None) -> None:
    intel = intel or {"kev": set(), "nvd": {}, "source": "curated"}
    kev = intel.get("kev", set())
    nvd = intel.get("nvd", {})
    epss = intel.get("epss", {}) or {}
    discovered = intel.get("discovered", {}) or {}

    def _epss_of(cid) -> float:
        try:
            return float(epss.get(cid) or 0)
        except (TypeError, ValueError):
            return 0.0

    def _cvss_of(cid) -> float:
        try:
            return float(nvd.get(cid, {}).get("cvss") or 0)
        except (TypeError, ValueError):
            return 0.0
    V = analyze_versions(snap, A["ssl_devices"])
    ssl_set = set(A["ssl_devices"])
    devices = V["devices"]
    builds_known = sum(1 for d in devices if _has_patch(d["version"]))

    # Evaluate every device against every applicable advisory.
    status_rank = {"vulnerable": 0, "verify": 1, "patched": 2, "na": 3}
    dev_overall: dict[str, str] = {}
    cve_breakdown: dict[str, dict] = {}
    for c in KNOWN_CVES:
        cve_breakdown[c["cve"]] = {"vulnerable": [], "verify": [], "patched": []}
    for d in devices:
        worst = "na"
        for c in KNOWN_CVES:
            applies = (c["cond"] == "all") or (c["cond"] == "ssl" and d["name"] in ssl_set)
            if not applies:
                continue
            st = device_cve_status(d["version"], c["fixed"])
            if st in ("vulnerable", "verify", "patched"):
                cve_breakdown[c["cve"]][st].append(d["name"])
            if status_rank[st] < status_rank[worst]:
                worst = st
        dev_overall[d["name"]] = worst

    n_vuln = sum(1 for v in dev_overall.values() if v == "vulnerable")
    n_verify = sum(1 for v in dev_overall.values() if v == "verify")
    n_clear = sum(1 for v in dev_overall.values() if v in ("patched", "na"))

    def _stbadge(st: str) -> str:
        return {
            "vulnerable": '<span class="badge b-red">vulnerable</span>',
            "verify": '<span class="badge b-amber">verify build</span>',
            "patched": '<span class="badge b-blue">patched</span>',
            "na": '<span class="muted">not applicable</span>',
        }[st]

    body = ['<h2>Software Versions &amp; CVE Awareness</h2>']
    src = esc(intel.get("source", "curated"))
    if builds_known:
        body.append('<div class="note">Devices are matched to advisories by <strong>exact build</strong> '
                     'where FortiManager reported the patch level, and by major train otherwise. '
                     f'Threat-intel source: <strong>{src}</strong> '
                     '(CISA KEV = actively exploited; NVD = live CVSS). Findings are conservative — '
                     'a device is only flagged when its train is affected; unknown builds are marked '
                     '<em>verify</em>, never vulnerable.</div>')
    else:
        body.append('<div class="note warnbox">FortiManager did not report exact build numbers in this '
                     'snapshot, so devices show as <strong>verify</strong> for any advisory affecting their '
                     'train (no false positives). Re-run the collector to capture <code>patch</code>/'
                     '<code>build</code> for exact Vulnerable/Patched results. '
                     f'Threat-intel source: <strong>{src}</strong>.</div>')

    # Summary cards
    body.append(site.cards([
        (str(len(devices)), "Devices", ""),
        (str(builds_known), "Exact build known", "" if builds_known else "warn"),
        (str(n_vuln), "Likely vulnerable", "bad" if n_vuln else ""),
        (str(n_verify), "To verify", "warn" if n_verify else ""),
        (str(n_clear), "Patched / N/A", "good" if n_clear else ""),
    ]))

    # Version inventory
    body.append('<div class="section-title">FortiOS version inventory</div>')
    body.append('<table><thead><tr><th>Version</th><th>Devices</th><th>Status</th></tr></thead><tbody>')
    for ver, n in V["by_version"].items():
        eol = str(ver)[:1] in ("5", "6")
        if eol:
            status = sev_badge("high") + " EOL — verify lifecycle"
        elif _has_patch(ver):
            status = '<span class="badge b-blue">exact build</span>'
        else:
            status = '<span class="pill">train only (verify build)</span>'
        body.append(f"<tr><td class='mono'>{esc(ver)}</td><td>{n}</td><td>{status}</td></tr>")
    body.append('</tbody></table>')

    # Per-advisory detail with live severity + exploitation status
    # Priority order: KEV (exploited) first, then EPSS, then CVSS.
    ordered = sorted(KNOWN_CVES, key=lambda c: (
        c["cve"] in kev, _epss_of(c["cve"]), _cvss_of(c["cve"])), reverse=True)
    body.append('<div class="section-title">FortiOS advisories — matched to your fleet</div>')
    for c in ordered:
        bd = cve_breakdown[c["cve"]]
        meta = nvd.get(c["cve"], {})
        sev_txt = c["sev"]
        if meta.get("cvss"):
            sev_lbl = meta.get("sev") or ""
            sev_txt = f"CVSS {meta['cvss']}" + (f" {sev_lbl}" if sev_lbl else "")
        kev_badge = (' <span class="badge b-red">CISA KEV — exploited</span>'
                     if c["cve"] in kev else "")
        ep = _epss_of(c["cve"])
        if ep:
            kev_badge += f' <span class="pill">EPSS {ep:.1%}</span>'
        link = meta.get("url", f"https://nvd.nist.gov/vuln/detail/{c['cve']}")
        if c["cond"] == "ssl":
            scope = "SSL-VPN-enabled devices"
        else:
            scope = "all FortiManager-managed FortiGates (FGFM/admin plane)"
        nv, nver, npat = len(bd["vulnerable"]), len(bd["verify"]), len(bd["patched"])
        if nv:
            tally = f'<span class="badge b-red">{nv} vulnerable</span>'
        elif nver:
            tally = f'<span class="badge b-amber">{nver} to verify</span>'
        elif npat:
            tally = f'<span class="badge b-blue">{npat} patched</span>'
        else:
            tally = '<span class="muted">no devices on an affected train</span>'
        detail = ""
        if bd["vulnerable"]:
            detail += f'<br><em>Vulnerable:</em> <span class="mono">{esc(", ".join(sorted(bd["vulnerable"])))}</span>'
        if bd["verify"]:
            detail += f'<br><em>Verify build:</em> <span class="mono">{esc(", ".join(sorted(bd["verify"])))}</span>'
        body.append(
            f'<div class="note"><strong><a href="{esc(link)}" target="_blank" rel="noopener">{esc(c["cve"])}</a></strong>'
            f' — {esc(c["summary"])}{kev_badge}<br>'
            f'<span class="pill">{esc(sev_txt)}</span> &nbsp; {tally}<br>'
            f'<em>Affected:</em> {esc(c["affected"])}<br>'
            f'<em>Scope:</em> {esc(scope)}.<br>'
            f'<em>Action:</em> {esc(c["action"])}{detail}</div>')

    # Tier 2 — NVD CPE discovery (informational only; never drives compliance)
    curated_ids = {c["cve"] for c in KNOWN_CVES}
    if discovered:
        body.append('<div class="section-title">Discovered via NVD CPE — informational</div>')
        body.append('<div class="note">Everything NVD matches to the exact FortiOS builds in this '
                    'snapshot (beyond the curated advisories above). <strong>Informational only — '
                    'verify applicability</strong>; these never affect compliance findings. '
                    'Sorted by KEV, then EPSS, then CVSS.</div>')
    for cpe, entries in sorted(discovered.items()):
        extra = [e for e in entries if e.get("cve") not in curated_ids]
        label = f"{cpe} — {len(entries)} CVEs ({len(extra)} beyond curated)"
        rows = []
        for e in sorted(extra, key=lambda e: (
                e.get("cve") in kev, _epss_of(e.get("cve")),
                float(e.get("cvss") or 0)), reverse=True):
            kevb = ' <span class="badge b-red">KEV</span>' if e.get("cve") in kev else ""
            ep = _epss_of(e.get("cve"))
            rows.append(
                f"<tr><td class='mono'><a href='{esc(e.get('url', ''))}' target='_blank' "
                f"rel='noopener'>{esc(e.get('cve', ''))}</a>{kevb}</td>"
                f"<td>{esc(str(e.get('cvss', '') or '—'))}</td>"
                f"<td>{esc(e.get('severity', '') or '—')}</td>"
                f"<td>{'{:.1%}'.format(ep) if ep else '—'}</td>"
                f"<td>{esc((e.get('summary') or '')[:220])}</td></tr>")
        if not rows:
            rows.append("<tr><td colspan='5' class='muted'>No CVEs beyond the curated set.</td></tr>")
        body.append(
            f'<details><summary class="mono">{esc(label)}</summary>'
            '<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th>'
            f'<th>Summary</th></tr></thead><tbody>{"".join(rows)}</tbody></table></details>')

    # All devices with overall status
    body.append('<div class="section-title">All devices</div>')
    body.append(site.searchbox("vertbl", "vercnt"))
    body.append('<table id="vertbl"><thead><tr><th>Device</th><th>Platform</th><th>Version</th>'
                '<th>Serial</th><th>Features</th><th>Status</th></tr></thead><tbody>')
    for d in V["devices"]:
        feats = []
        if d["eol"]:
            feats.append(sev_badge("high") + " EOL")
        if d["ssl"]:
            feats.append('<span class="badge b-amber">SSL-VPN</span>')
        feats.append('<span class="badge b-blue">FGFM</span>')
        if _has_patch(d["version"]):
            ver_disp = esc(d["version"])
        else:
            ver_disp = f"{esc(d['version'])} <span class='muted'>(train)</span>"
        body.append(f"<tr><td>{esc(d['name'])}</td><td>{esc(d['platform'])}</td>"
                    f"<td class='mono'>{ver_disp}</td>"
                    f"<td class='mono'>{esc(d['serial'])}</td>"
                    f"<td>{' '.join(feats)}</td><td>{_stbadge(dev_overall[d['name']])}</td></tr>")
    body.append('</tbody></table>')
    site.page("risk.html", "Versions & CVE", "".join(body))


INTERFACE_FILTER_JS = r"""<script>
(function(){
  var tbl=document.getElementById('iftbl'); if(!tbl) return;
  var q=document.getElementById('iffilter');
  var st=document.getElementById('ifstatus');
  var ip=document.getElementById('ifhasip');
  var mg=document.getElementById('ifmgmt');
  var cnt=document.getElementById('ifcnt');
  var rows=tbl.tBodies[0].rows;
  function apply(){
    var text=((q&&q.value)||'').toLowerCase();
    var sv=st?st.value:'all';
    var ipOnly=ip&&ip.checked;
    var mgOnly=mg&&mg.checked;
    var shown=0;
    for(var i=0;i<rows.length;i++){
      var r=rows[i], ok=true;
      if(text && r.innerText.toLowerCase().indexOf(text)<0) ok=false;
      if(ok && sv!=='all' && r.getAttribute('data-status')!==sv) ok=false;
      if(ok && ipOnly && r.getAttribute('data-ip')!=='1') ok=false;
      if(ok && mgOnly && r.getAttribute('data-mgmt')!=='1') ok=false;
      r.style.display=ok?'':'none';
      if(ok) shown++;
    }
    if(cnt) cnt.textContent=shown+' shown';
  }
  if(q) q.addEventListener('input',apply);
  [st,ip,mg].forEach(function(e){ if(e) e.addEventListener('change',apply); });
  apply();
})();
</script>"""


def build_interfaces(site: SiteBuilder, snap: dict, A: dict) -> None:
    interfaces = [i for i in snap.get("interfaces", []) if isinstance(i, dict)]
    cleartext_keys = {(r["device"], r["name"]) for r in A["mgmt_cleartext"]}
    wan_mgmt_keys = {(r["device"], r["name"]) for r in A["mgmt_wan"]}
    with_ip = [i for i in interfaces if _has_real_ip(i.get("ip"))]
    body = ['<h2>Interfaces &amp; IP Addressing</h2>',
            '<div class="note">Every managed interface with its IP/mask, the connected network, role, '
            'and administrative access — insecure or internet-facing management is flagged. Use the '
            'filters to hide unassigned ports or show only up/down interfaces.</div>']
    body.append(site.cards([
        (str(len(interfaces)), "Interfaces", ""),
        (str(len(with_ip)), "With IP", ""),
        (str(len(A["ifaces_no_ip"])), "Without IP", ""),
        (str(len(A["ifaces_down"])), "Down", "warn" if A["ifaces_down"] else ""),
        (str(len(A["mgmt_cleartext"])), "Cleartext Mgmt", "bad" if A["mgmt_cleartext"] else ""),
        (str(len(A["mgmt_wan"])), "WAN Mgmt", "bad" if A["mgmt_wan"] else ""),
    ]))
    body.append(
        '<div class="filterbar" id="mgmt">'
        '<input id="iffilter" class="search" type="search" placeholder="Filter interfaces…">'
        '<label for="ifstatus">Status'
        '<select id="ifstatus"><option value="all">All</option>'
        '<option value="up">Up / enabled</option><option value="down">Down / disabled</option>'
        '</select></label>'
        '<label><input type="checkbox" id="ifhasip"> Hide ports without IP</label>'
        '<label><input type="checkbox" id="ifmgmt"> Management-exposed only</label>'
        '<button class="vbtn" onclick="exportTableCSV(\'iftbl\',\'interfaces.csv\')">Export Excel / CSV</button>'
        '</div>'
    )
    body.append('<div class="meta"><span id="ifcnt"></span> of '
                f'{len(interfaces)} interfaces · rows in red/amber expose a management plane</div>')
    body.append('<div class="table-wrap"><table id="iftbl"><thead><tr><th>Device</th><th>Interface</th>'
                '<th>Alias</th><th>IP / Mask</th><th>Connected Network</th><th>Status</th><th>Role</th>'
                '<th>Admin Access</th><th>VLAN</th><th>Description</th></tr></thead><tbody>')
    for i in sorted(interfaces, key=lambda x: (str(x.get("device")), str(x.get("name")))):
        key = (i.get("device"), i.get("name"))
        access = esc(i.get("allowaccess", ""))
        mgmt = "0"
        flag = ""
        if key in cleartext_keys:
            access = f'<span class="badge b-red">cleartext</span> {access}'
            flag = ' style="background:rgba(239,68,68,.06)"'
            mgmt = "1"
        elif key in wan_mgmt_keys:
            access = f'<span class="badge b-amber">wan-mgmt</span> {access}'
            flag = ' style="background:rgba(234,179,8,.05)"'
            mgmt = "1"
        status = i.get("status", "")
        slow = str(status).lower()
        st = (f'<span class="tag t-accept">{esc(status)}</span>' if slow == "up"
              else f'<span class="tag t-drop">{esc(status)}</span>' if slow == "down"
              else esc(status))
        role = "WAN" if _is_wan(i) else ("VLAN" if i.get("vlanid") else "LAN")
        real_ip = _has_real_ip(i.get("ip"))
        net = _network_of(i.get("ip", "")) if real_ip else ""
        has_ip = "1" if real_ip else "0"
        body.append(
            f'<tr{flag} data-status="{esc(slow)}" data-ip="{has_ip}" data-mgmt="{mgmt}">'
            f"<td>{esc(i.get('device'))}</td><td class='mono'>{esc(i.get('name'))}</td>"
            f"<td>{esc(i.get('alias'))}</td><td class='mono'>{esc(i.get('ip'))}</td>"
            f"<td class='mono'>{esc(net)}</td><td>{st}</td><td>{esc(role)}</td>"
            f"<td>{access}</td><td>{esc(i.get('vlanid'))}</td><td>{esc(i.get('description'))}</td></tr>")
    body.append('</tbody></table></div>')
    body.append(INTERFACE_FILTER_JS)
    site.page("interfaces.html", "Interfaces", "".join(body))


VPN_MAP_CSS = """<style>
.vpn-toolbar{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin:14px 0 10px;}
.vpn-check{display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--muted);cursor:pointer;}
.vpn-check input{accent-color:var(--accent);width:15px;height:15px;}
.vbtn{background:var(--panel2);border:1px solid var(--line-soft);color:var(--txt);font-size:12px;
  font-weight:600;padding:7px 13px;border-radius:var(--radius);cursor:pointer;transition:all .15s;}
.vbtn:hover{border-color:var(--accent);color:var(--accent);}
.vpn-sep{width:1px;height:20px;background:var(--line);margin:0 2px;}
.vpn-legend{display:flex;gap:18px;flex-wrap:wrap;font-size:11.5px;color:var(--muted);margin:4px 0 12px;}
.vpn-legend span{display:flex;align-items:center;gap:7px;}
.vpn-legend .lg{width:13px;height:13px;border-radius:4px;display:inline-block;}
.lg-dev{background:rgba(238,49,36,.22);border:1.5px solid var(--vendor-forti);}
.lg-peer{background:rgba(46,134,214,.22);border:1.5px solid var(--vendor-forti-navy);border-radius:50%;}
.lg-lnet{background:rgba(34,197,94,.2);border:1.5px solid var(--good);border-radius:50%;}
.lg-rnet{background:rgba(234,179,8,.2);border:1.5px solid var(--warn);border-radius:50%;}
.lg-tun{width:16px;height:0;border:none;border-top:2px solid var(--vendor-forti);border-radius:0;}
#vpnwrap{position:relative;height:74vh;min-height:480px;border:1px solid var(--line);
  border-radius:var(--radius-lg);overflow:hidden;box-shadow:var(--shadow-sm);
  background:radial-gradient(ellipse 70% 60% at 30% 0%,rgba(238,49,36,.06),transparent 55%),
    radial-gradient(ellipse 60% 60% at 90% 100%,rgba(46,134,214,.07),transparent 55%),var(--bg2);}
#vpnsvg{width:100%;height:100%;display:block;cursor:grab;touch-action:none;}
#vpnsvg.grabbing{cursor:grabbing;}
.vlink{stroke-linecap:round;}
.vlink-tun{stroke:rgba(238,49,36,.55);stroke-width:1.6;}
.vlink-net{stroke:rgba(140,150,160,.35);stroke-width:1;stroke-dasharray:3 4;}
.vlink.sel{stroke:#ff6a5c;stroke-width:2.6;}
.vlink.dim{opacity:.12;}
.vnode{cursor:pointer;}
.vnode .vshape{transition:stroke-width .12s,filter .12s;}
.v-device .vshape{fill:rgba(238,49,36,.16);stroke:var(--vendor-forti);stroke-width:1.8;}
.v-peer .vshape{fill:rgba(46,134,214,.16);stroke:var(--vendor-forti-navy);stroke-width:1.6;}
.v-lnet .vshape{fill:rgba(34,197,94,.16);stroke:var(--good);stroke-width:1.4;}
.v-rnet .vshape{fill:rgba(234,179,8,.16);stroke:var(--warn);stroke-width:1.4;}
.vlabel{fill:var(--txt);font-family:var(--sans);font-size:11px;font-weight:600;
  paint-order:stroke;stroke:rgba(10,10,11,.85);stroke-width:3px;pointer-events:none;}
.v-lnet .vlabel,.v-rnet .vlabel{font-family:var(--mono);font-size:9.5px;font-weight:500;fill:var(--muted);}
.vnode.sel .vshape{stroke-width:3;filter:drop-shadow(0 0 8px var(--accent-glow));}
.vnode.dim{opacity:.22;}
.vnode.hit .vshape{stroke:var(--accent);stroke-width:3;filter:drop-shadow(0 0 10px var(--accent-glow));}
#vppanel{display:none;position:absolute;top:14px;right:14px;width:288px;max-height:88%;overflow-y:auto;
  background:rgba(20,20,21,.97);backdrop-filter:blur(18px);border:1px solid var(--line-soft);
  border-radius:var(--radius-lg);padding:16px 18px;box-shadow:var(--shadow-md);}
#vppanel .vptitle{font-size:14px;font-weight:700;color:var(--txt);margin:0 22px 3px 0;word-break:break-all;}
#vppanel .vptype{font-size:11px;color:var(--accent);font-family:var(--mono);margin-bottom:11px;}
#vppanel .vrow{display:flex;gap:10px;border-bottom:1px solid var(--line);padding:5px 0;font-size:12px;}
#vppanel .vk{color:var(--dim);min-width:84px;flex-shrink:0;font-weight:500;}
#vppanel .vv{color:#d4d4d8;font-family:var(--mono);font-size:11.5px;word-break:break-all;}
#vppanel .vphdr{font-size:10px;color:var(--dim);margin:11px 0 4px;font-weight:600;
  text-transform:uppercase;letter-spacing:.06em;}
#vppanel .vpmem{font-family:var(--mono);font-size:11px;color:var(--muted);padding:3px 0;
  border-bottom:1px solid var(--line);}
#vppanel .vpclose{position:absolute;top:12px;right:14px;cursor:pointer;color:var(--dim);font-size:18px;line-height:1;}
#vppanel .vpclose:hover{color:var(--bad);}
#vphint{position:absolute;left:14px;bottom:12px;font-size:11px;color:var(--dim);
  font-family:var(--mono);pointer-events:none;background:rgba(10,10,11,.5);padding:4px 9px;border-radius:6px;}
</style>"""

VPN_MAP_JS = r"""
(function(){
  var GRAPH = VPN_GRAPH;
  var svg = document.getElementById('vpnsvg');
  var vp = document.getElementById('vpvp');
  var glink = document.getElementById('vplinks');
  var gnode = document.getElementById('vpnodes');
  var panel = document.getElementById('vppanel');
  if(!svg || !GRAPH) return;
  var NS = 'http://www.w3.org/2000/svg';
  function W(){ return svg.clientWidth || 900; }
  function H(){ return svg.clientHeight || 600; }
  function esc(s){ var d=document.createElement('div'); d.textContent=(s==null?'':String(s)); return d.innerHTML; }

  var nodes = GRAPH.nodes, links = GRAPH.links;
  var byId = {}; nodes.forEach(function(n){ byId[n.id]=n; });
  links.forEach(function(l){ l.s=byId[l.source]; l.t=byId[l.target]; });
  // subnets and tunnel-less firewalls hidden by default
  nodes.forEach(function(n){
    if(n.type==='lnet'||n.type==='rnet') n.hidden=true;
    if(n.type==='device'&&n.notun) n.hidden=true;
  });

  nodes.forEach(function(n,i){
    var a=i*2.3999632; var r=Math.min(W(),H())*0.36*Math.sqrt((i+1)/nodes.length);
    n.x=W()/2+r*Math.cos(a); n.y=H()/2+r*Math.sin(a); n.vx=0; n.vy=0;
    n.rad = n.type==='device'?20:(n.type==='peer'?14:7);
  });

  links.forEach(function(l){
    var line=document.createElementNS(NS,'line');
    line.setAttribute('class','vlink '+(l.kind==='subnet'?'vlink-net':'vlink-tun'));
    if(l.kind==='tunnel') line.addEventListener('click',function(e){ e.stopPropagation(); selectLink(l); });
    glink.appendChild(line); l.el=line;
  });
  nodes.forEach(function(n){
    var g=document.createElementNS(NS,'g'); g.setAttribute('class','vnode v-'+n.type);
    var shp;
    if(n.type==='device'){ shp=document.createElementNS(NS,'rect');
      shp.setAttribute('width',n.rad*2); shp.setAttribute('height',n.rad*2);
      shp.setAttribute('x',-n.rad); shp.setAttribute('y',-n.rad); shp.setAttribute('rx',6);
    } else { shp=document.createElementNS(NS,'circle'); shp.setAttribute('r',n.rad); }
    shp.setAttribute('class','vshape'); g.appendChild(shp);
    var t=document.createElementNS(NS,'text'); t.setAttribute('class','vlabel');
    t.setAttribute('text-anchor','middle'); t.setAttribute('y',n.rad+13); t.textContent=n.label;
    g.appendChild(t); n.g=g;
    addDrag(n,g);
    g.addEventListener('click',function(e){ e.stopPropagation(); selectNode(n); });
    gnode.appendChild(g);
  });

  function render(){
    links.forEach(function(l){
      if(!l.s||!l.t) return;
      var hid=l.s.hidden||l.t.hidden;
      l.el.style.display=hid?'none':'';
      if(hid) return;
      l.el.setAttribute('x1',l.s.x); l.el.setAttribute('y1',l.s.y);
      l.el.setAttribute('x2',l.t.x); l.el.setAttribute('y2',l.t.y);
    });
    nodes.forEach(function(n){
      n.g.style.display=n.hidden?'none':'';
      if(!n.hidden) n.g.setAttribute('transform','translate('+n.x+','+n.y+')');
    });
  }

  var alpha=1;
  function tick(){
    var cx=W()/2, cy=H()/2, i, j;
    for(i=0;i<nodes.length;i++){ var a=nodes[i]; if(a.hidden) continue;
      for(j=i+1;j<nodes.length;j++){ var b=nodes[j]; if(b.hidden) continue;
        var dx=a.x-b.x, dy=a.y-b.y, d2=dx*dx+dy*dy; if(d2<0.01) d2=0.01;
        var d=Math.sqrt(d2), rep=3200/d2, fx=dx/d*rep, fy=dy/d*rep;
        a.vx+=fx; a.vy+=fy; b.vx-=fx; b.vy-=fy; } }
    links.forEach(function(l){
      if(!l.s||!l.t||l.s.hidden||l.t.hidden) return;
      var dx=l.t.x-l.s.x, dy=l.t.y-l.s.y, d=Math.sqrt(dx*dx+dy*dy)||0.01;
      var tgt=l.kind==='subnet'?60:165, k=(d-tgt)*0.03, fx=dx/d*k, fy=dy/d*k;
      l.s.vx+=fx; l.s.vy+=fy; l.t.vx-=fx; l.t.vy-=fy; });
    nodes.forEach(function(n){
      if(n.hidden) return;
      n.vx+=(cx-n.x)*0.004; n.vy+=(cy-n.y)*0.004;
      if(n.fixed){ n.vx=0; n.vy=0; return; }
      n.x+=Math.max(-16,Math.min(16,n.vx*alpha)); n.y+=Math.max(-16,Math.min(16,n.vy*alpha));
      n.vx*=0.8; n.vy*=0.8; });
  }
  var raf, animate=true;
  function loop(){ tick(); render(); alpha*=0.99; if(alpha>0.015){ raf=requestAnimationFrame(loop); } }
  function settle(iters){ for(var k=0;k<iters;k++){ alpha=1; tick(); } alpha=0; render(); }
  function reheat(){ cancelAnimationFrame(raf); if(animate){ alpha=1; loop(); } else { settle(260); } }

  var tx=0, ty=0, scale=1;
  function applyVP(){ vp.setAttribute('transform','translate('+tx+','+ty+') scale('+scale+')'); }
  svg.addEventListener('wheel',function(e){
    e.preventDefault();
    var rc=svg.getBoundingClientRect(), mx=e.clientX-rc.left, my=e.clientY-rc.top;
    var ns=Math.max(0.25,Math.min(3,scale*(e.deltaY<0?1.1:0.9)));
    tx=mx-(mx-tx)*(ns/scale); ty=my-(my-ty)*(ns/scale); scale=ns; applyVP();
  },{passive:false});
  var panning=false, px, py;
  svg.addEventListener('pointerdown',function(e){
    if(e.target.closest && e.target.closest('.vnode')) return;
    panning=true; px=e.clientX; py=e.clientY; svg.classList.add('grabbing');
  });
  window.addEventListener('pointermove',function(e){
    if(!panning) return; tx+=e.clientX-px; ty+=e.clientY-py; px=e.clientX; py=e.clientY; applyVP();
  });
  window.addEventListener('pointerup',function(){ panning=false; svg.classList.remove('grabbing'); });
  svg.addEventListener('click',function(e){ if(e.target===svg||e.target===vp) clearSel(); });

  function addDrag(n,g){
    g.addEventListener('pointerdown',function(e){
      e.stopPropagation(); g.setPointerCapture(e.pointerId);
      var rc=svg.getBoundingClientRect();
      function mv(ev){ n.x=(ev.clientX-rc.left-tx)/scale; n.y=(ev.clientY-rc.top-ty)/scale; n.fixed=true; reheat(); }
      function up(){ g.removeEventListener('pointermove',mv); g.removeEventListener('pointerup',up); }
      g.addEventListener('pointermove',mv); g.addEventListener('pointerup',up);
    });
  }

  function clearSel(){
    nodes.forEach(function(n){ n.g.classList.remove('sel','dim'); });
    links.forEach(function(l){ l.el.classList.remove('sel','dim'); });
    panel.style.display='none';
  }
  function selectNode(n){
    var adj={}; adj[n.id]=true;
    links.forEach(function(l){ if(l.source===n.id) adj[l.target]=true; if(l.target===n.id) adj[l.source]=true; });
    nodes.forEach(function(m){ m.g.classList.toggle('sel',m.id===n.id); m.g.classList.toggle('dim',!adj[m.id]&&!m.hidden); });
    links.forEach(function(l){ var on=l.source===n.id||l.target===n.id; l.el.classList.toggle('sel',on); l.el.classList.toggle('dim',!on); });
    showNodePanel(n);
  }
  function selectLink(l){
    nodes.forEach(function(m){ var on=m.id===l.source||m.id===l.target; m.g.classList.toggle('sel',on); m.g.classList.toggle('dim',!on&&!m.hidden); });
    links.forEach(function(x){ x.el.classList.toggle('sel',x===l); x.el.classList.toggle('dim',x!==l); });
    showLinkPanel(l);
  }
  function row(k,v){ return '<div class="vrow"><span class="vk">'+k+'</span><span class="vv">'+v+'</span></div>'; }
  var TYPE={device:'Managed FortiGate',peer:'Remote VPN gateway',lnet:'Local network',rnet:'Remote network'};
  function openPanel(html){
    panel.innerHTML='<span class="vpclose">&#10005;</span>'+html; panel.style.display='block';
    panel.querySelector('.vpclose').addEventListener('click',clearSel);
  }
  function showNodePanel(n){
    var tuns=links.filter(function(l){ return l.kind==='tunnel'&&(l.source===n.id||l.target===n.id); });
    var h='<div class="vptitle">'+esc(n.label)+'</div><div class="vptype">'+(TYPE[n.type]||n.type)+'</div>';
    if(n.ip) h+=row('IP', esc(n.ip));
    if(n.remote_fw) h+=row('Resolved FW', esc(n.remote_fw));
    if(n.platform) h+=row('Platform', esc(n.platform));
    h+=row('Tunnels', tuns.length);
    if(tuns.length){ h+='<div class="vphdr">IPsec tunnels</div>';
      tuns.forEach(function(l){ var o=l.source===n.id?byId[l.target]:byId[l.source];
        h+='<div class="vpmem">'+esc(l.label)+' &rarr; '+esc(o?o.label:'')+'</div>'; }); }
    openPanel(h);
  }
  function showLinkPanel(l){
    var h='<div class="vptitle">'+esc(l.label)+'</div><div class="vptype">IPsec tunnel</div>';
    h+=row('FortiGate', esc(byId[l.source].label));
    if(l.intf) h+=row('Egress intf', esc(l.intf));
    if(l.init_ip) h+=row('Initiating IP', esc(l.init_ip));
    h+=row('Remote GW', esc(byId[l.target].label));
    h+=row('Remote FW', esc(l.remote_fw||'(external)'));
    if(l.ike) h+=row('IKE', esc(l.ike));
    if(l.mode) h+=row('Mode', esc(l.mode));
    if(l.local&&l.local.length){ h+='<div class="vphdr">Local networks</div>';
      l.local.forEach(function(s){ h+='<div class="vpmem">'+esc(s)+'</div>'; }); }
    if(l.remote&&l.remote.length){ h+='<div class="vphdr">Remote networks</div>';
      l.remote.forEach(function(s){ h+='<div class="vpmem">'+esc(s)+'</div>'; }); }
    openPanel(h);
  }

  var tog=document.getElementById('vptognet');
  if(tog) tog.addEventListener('change',function(e){
    var show=e.target.checked;
    nodes.forEach(function(n){ if(n.type==='lnet'||n.type==='rnet') n.hidden=!show; });
    reheat();
  });
  function applyVisibility(){
    nodes.forEach(function(n){
      if(n.type==='lnet') n.hidden=!showLocal;
      else if(n.type==='rnet') n.hidden=!showRemote;
      else if(n.type==='device' && n.notun) n.hidden=!showAll;
    });
  }
  var showLocal=false, showRemote=false, showAll=false;
  var tl=document.getElementById('vptoglocal');
  if(tl) tl.addEventListener('change',function(e){ showLocal=e.target.checked; applyVisibility(); reheat(); });
  var tr=document.getElementById('vptogremote');
  if(tr) tr.addEventListener('change',function(e){ showRemote=e.target.checked; applyVisibility(); reheat(); });
  var ta=document.getElementById('vptogall');
  if(ta) ta.addEventListener('change',function(e){ showAll=e.target.checked; applyVisibility(); reheat(); });
  var an=document.getElementById('vpanimate');
  if(an) an.addEventListener('change',function(e){ animate=e.target.checked; if(animate) reheat(); });
  var sb=document.getElementById('vpsearch');
  if(sb) sb.addEventListener('input',function(e){
    var q=e.target.value.toLowerCase();
    nodes.forEach(function(n){ n.g.classList.toggle('hit', !!q && n.label.toLowerCase().indexOf(q)>-1); });
  });
  var rl=document.getElementById('vprelayout');
  if(rl) rl.addEventListener('click',function(){ nodes.forEach(function(n){ n.fixed=false; }); reheat(); });
  var rv=document.getElementById('vpreset');
  if(rv) rv.addEventListener('click',function(){ tx=0; ty=0; scale=1; applyVP(); });
  window.addEventListener('resize',function(){ reheat(); });

  // ---- export (PNG / JPEG / PDF) ----
  // Drawing an SVG image onto canvas ignores external CSS, so embed literal colours.
  var EXPORT_STYLE = ".vlink{stroke-linecap:round}"
    + ".vlink-tun{stroke:rgba(238,49,36,.7);stroke-width:1.6}"
    + ".vlink-net{stroke:rgba(140,150,160,.5);stroke-width:1;stroke-dasharray:3 4}"
    + ".v-device .vshape{fill:rgba(238,49,36,.22);stroke:#ee3124;stroke-width:1.8}"
    + ".v-peer .vshape{fill:rgba(46,134,214,.22);stroke:#2e86d6;stroke-width:1.6}"
    + ".v-lnet .vshape{fill:rgba(34,197,94,.22);stroke:#22c55e;stroke-width:1.4}"
    + ".v-rnet .vshape{fill:rgba(234,179,8,.22);stroke:#eab308;stroke-width:1.4}"
    + ".vlabel{fill:#ececec;font-family:'Inter',Arial,sans-serif;font-size:11px;font-weight:600}"
    + ".v-lnet .vlabel,.v-rnet .vlabel{fill:#9aa0a6;font-family:monospace;font-size:9.5px}";
  function buildSVG(){
    var bb=vp.getBBox(), pad=36;
    var bx=bb.x-pad, by=bb.y-pad, bw=Math.max(bb.width+pad*2,10), bh=Math.max(bb.height+pad*2,10);
    var clone=vp.cloneNode(true); clone.removeAttribute('transform');
    var out=document.createElementNS(NS,'svg');
    out.setAttribute('xmlns',NS);
    out.setAttribute('viewBox',bx+' '+by+' '+bw+' '+bh);
    out.setAttribute('width',Math.round(bw)); out.setAttribute('height',Math.round(bh));
    var st=document.createElementNS(NS,'style'); st.textContent=EXPORT_STYLE;
    var bg=document.createElementNS(NS,'rect');
    bg.setAttribute('x',bx); bg.setAttribute('y',by);
    bg.setAttribute('width',bw); bg.setAttribute('height',bh); bg.setAttribute('fill','#0a0a0b');
    out.appendChild(st); out.appendChild(bg); out.appendChild(clone);
    return {svg:out, w:Math.round(bw), h:Math.round(bh)};
  }
  function rasterize(cb,scale){
    var o=buildSVG(); scale=scale||2;
    var data=new XMLSerializer().serializeToString(o.svg);
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'); c.width=o.w*scale; c.height=o.h*scale;
      var ctx=c.getContext('2d'); ctx.fillStyle='#0a0a0b'; ctx.fillRect(0,0,c.width,c.height);
      ctx.drawImage(img,0,0,c.width,c.height); cb(c);
    };
    img.onerror=function(){ alert('Export failed to render the SVG.'); };
    img.src='data:image/svg+xml;base64,'+btoa(unescape(encodeURIComponent(data)));
  }
  function dl(name,url){ var a=document.createElement('a'); a.href=url; a.download=name; document.body.appendChild(a); a.click(); a.remove(); }
  function exportImg(type){ rasterize(function(c){ dl('vpn-map.'+(type==='jpeg'?'jpg':'png'), c.toDataURL('image/'+type,0.95)); }); }
  function exportPDF(){ rasterize(function(c){
    var url=c.toDataURL('image/jpeg',0.95);
    var w=window.open('','_blank');
    if(!w){ alert('Allow pop-ups to print/save as PDF.'); return; }
    w.document.write('<html><head><title>VPN Map</title><style>@page{size:landscape;margin:8mm}'
      +'html,body{margin:0;background:#0a0a0b}img{width:100%;display:block}</style></head>'
      +'<body><img src="'+url+'"></body></html>');
    w.document.close(); w.focus(); setTimeout(function(){ w.print(); },350);
  }); }
  var bpng=document.getElementById('vppng'); if(bpng) bpng.addEventListener('click',function(){ exportImg('png'); });
  var bjpg=document.getElementById('vpjpg'); if(bjpg) bjpg.addEventListener('click',function(){ exportImg('jpeg'); });
  var bpdf=document.getElementById('vppdf'); if(bpdf) bpdf.addEventListener('click',exportPDF);

  applyVisibility();
  applyVP(); reheat();
})();
"""


def table_rows(items: list, columns: list[tuple[str, str]]) -> list[str]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cells = "".join(f"<td>{esc(item.get(key, ''))}</td>" for _, key in columns)
        rows.append(f"<tr>{cells}</tr>")
    return rows


def _short_json(value: object, limit: int = 120) -> str:
    """Compact one-line summary of nested live-state payloads for table cells."""
    if value is None or value == "":
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        text = json.dumps(value, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _usage_field(usage: object, *keys: str) -> str:
    if not isinstance(usage, dict):
        return ""
    for key in keys:
        if key in usage and usage[key] not in (None, ""):
            return str(usage[key])
    # FortiOS sometimes nests under cpu / mem / session keys
    for nest_key, nested_keys in (
        ("cpu", ("current", "cpu", "usage")),
        ("mem", ("current", "used", "usage", "memory")),
        ("session", ("current", "count", "setup_rate")),
    ):
        nested = usage.get(nest_key)
        if isinstance(nested, dict):
            for nk in nested_keys:
                if nk in nested and nested[nk] not in (None, ""):
                    return str(nested[nk])
        elif nested not in (None, "") and nest_key in keys:
            return str(nested)
    return ""


def normalize_live_state(snap: dict) -> None:
    """Flatten nested ha_status / sessions for table pages (mutates snap)."""
    ha_flat = []
    for row in snap.get("ha_status") or []:
        if not isinstance(row, dict):
            continue
        ha = row.get("ha") if isinstance(row.get("ha"), dict) else {}
        ha_flat.append({
            "device": row.get("device", ""),
            "adom": row.get("adom", ""),
            "peers_summary": _short_json(ha.get("peers")),
            "checksum_summary": _short_json(ha.get("checksum")),
            "statistics_summary": _short_json(ha.get("statistics")),
        })
    snap["ha_status_flat"] = ha_flat

    sess_flat = []
    for row in snap.get("sessions") or []:
        if not isinstance(row, dict):
            continue
        usage = row.get("usage")
        sess_flat.append({
            "device": row.get("device", ""),
            "adom": row.get("adom", ""),
            "cpu": _usage_field(usage, "cpu", "cpu_usage", "cpuusage"),
            "memory": _usage_field(usage, "memory", "mem", "mem_usage"),
            "session_count": _usage_field(
                usage, "session_count", "sessions", "session", "npu_session"),
            "session_setup_rate": _usage_field(
                usage, "session_setup_rate", "setup_rate", "session_rate"),
            "detail": _short_json(usage, limit=160),
        })
    snap["sessions_flat"] = sess_flat


def build_dashboard(site: SiteBuilder, snap: dict) -> None:
    def n(key: str) -> int:
        v = snap.get(key)
        return len(v) if isinstance(v, list) else 0

    interfaces = snap.get("interfaces", [])
    routes = snap.get("routes", [])
    vpn_devices = sorted({v.get("device") for v in snap.get("vpn_phase1", []) if v.get("device")})
    ifaces_no_ip = [i for i in interfaces if not _has_real_ip(i.get("ip"))]
    ifaces_down = [i for i in interfaces if i.get("status") == "down"]
    default_routes = [r for r in routes if str(r.get("dst", "")).startswith("0.0.0.0")]

    header = (
        f"<h2>{esc(snap.get('hostname') or snap.get('host', 'FortiManager'))} "
        "<span class='vendor-chip'>FortiManager</span></h2>"
        '<div class="note">Read-only inventory exported from the FortiManager JSON-RPC API. '
        "Theme matches NetConverter with the Fortinet accent. Upload the full bundle to "
        "NetConverter.local for interactive analysis.</div>"
    )
    meta = (
        '<p class="meta">'
        f"Host: <span class='mono'>{esc(snap.get('host', '—'))}</span> &nbsp;·&nbsp; "
        f"Platform: <span class='mono'>{esc(snap.get('platform', '—'))}</span> &nbsp;·&nbsp; "
        f"Version: <span class='mono'>{esc(snap.get('version', '—'))}</span> &nbsp;·&nbsp; "
        f"Serial: <span class='mono'>{esc(snap.get('serial', '—'))}</span> &nbsp;·&nbsp; "
        f"ADOM mode: <span class='mono'>{esc(snap.get('adom_mode', '—'))}</span> &nbsp;·&nbsp; "
        f"ADOMs: <span class='mono'>{esc(', '.join(snap.get('adoms', [])) or '—')}</span>"
        "</p>"
    )

    lc = snap.get("local_configs")
    if isinstance(lc, dict) and lc.get("devices"):
        with_local = len([d for d in snap.get("devices", [])
                          if isinstance(d, dict) and d.get("has_local_config")])
        meta += (
            '<div class="note">'
            f"Merged <strong>{esc(lc.get('devices'))}</strong> local device "
            f"<span class='mono'>.conf</span> backup(s) from "
            f"<span class='mono'>{esc(lc.get('dir', 'Local Configs'))}</span> — "
            f"device-local firewall policies and objects (not pushed centrally by "
            f"FortiManager) are now included. {esc(with_local)} of "
            f"{esc(n('devices'))} managed devices have a local config."
            "</div>"
        )

    inventory_cards = site.cards([
        (str(n("devices")), "Managed Devices", ""),
        (str(n("interfaces")), "Interfaces", ""),
        (str(n("routes")), "Static Routes", ""),
        (str(n("packages")), "Policy Packages", ""),
        (str(n("policies")), "Firewall Policies", ""),
    ])
    object_cards = site.cards([
        (str(n("addresses")), "Addresses", ""),
        (str(n("address_groups")), "Address Groups", ""),
        (str(n("services")), "Services", ""),
        (str(n("service_groups")), "Service Groups", ""),
        (str(n("vips") + n("ippools")), "NAT Objects (VIP+Pool)", ""),
    ])
    vpn_cards = site.cards([
        (str(n("vpn_phase1")), "IPsec Phase 1", ""),
        (str(n("vpn_phase2")), "IPsec Phase 2", ""),
        (str(len(vpn_devices)), "Devices with VPN", ""),
        (str(n("vpn_ssl")), "SSL VPN Portals", ""),
    ])
    health_cards = site.cards([
        (str(len(ifaces_no_ip)), "Interfaces without IP", "warn" if ifaces_no_ip else ""),
        (str(len(ifaces_down)), "Interfaces down", "warn" if ifaces_down else ""),
        (str(len(default_routes)), "Default routes", ""),
        (str(n("policies")), "Firewall rules", "warn" if n("policies") == 0 else ""),
    ])
    with_local = len([d for d in snap.get("devices", [])
                      if isinstance(d, dict) and d.get("has_local_config")])
    change_cards = site.cards([
        (str(n("adom_revisions")), "ADOM Revisions", "" if n("adom_revisions") else "warn"),
        (str(n("device_revisions")), "Device Config Revisions", ""),
        (str(with_local), "Local .conf Backups", "good" if with_local else "warn"),
        (str(n("fmg_admins") + n("device_admins")), "Admin Accounts", ""),
    ])
    live_cards = site.cards([
        (str(n("policy_hits")), "Policy Hit Rows",
         "good" if n("policy_hits") else "warn"),
        (str(n("ha_status")), "HA Status Devices", ""),
        (str(n("sessions")), "Resource Snapshots", ""),
        (str(n("routes_live")), "Live FIB Routes", ""),
    ])

    body = (
        header + meta
        + "<h3>Inventory</h3>" + inventory_cards
        + "<h3>Objects</h3>" + object_cards
        + "<h3>VPN</h3>" + vpn_cards
        + "<h3>Health</h3>" + health_cards
        + "<h3>Live State (perishable)</h3>" + live_cards
        + '<p class="meta">Live datasets are from collection time only — see '
        '<a href="policy_hits.html">Policy Hit Counters</a>, '
        '<a href="ha_status.html">HA / Cluster Sync</a>, '
        '<a href="sessions.html">Resource Usage</a>, and '
        '<a href="routes_live.html">Live Routes</a>.</p>'
        + "<h3>Change Tracking</h3>" + change_cards
        + '<p class="meta">See <a href="revisions.html">Revisions &amp; Changes</a> for '
        'ADOM/device revision history and <a href="coverage.html">Collection Coverage</a> '
        'for dataset completeness.</p>'
    )
    site.page("index.html", "Dashboard", body)


def build_vpn_graph(snap: dict) -> dict:
    """Build a node/link topology of FortiGates, remote gateways, tunnels and subnets."""
    devices = {d.get("name"): d for d in snap.get("devices", []) if isinstance(d, dict)}
    phase1 = [p for p in snap.get("vpn_phase1", []) if isinstance(p, dict)]
    phase2 = [p for p in snap.get("vpn_phase2", []) if isinstance(p, dict)]
    interfaces = [i for i in snap.get("interfaces", []) if isinstance(i, dict)]

    # interface IP lookup + reverse index (managed IP -> device) for remote-FW resolution
    iface_ip: dict[tuple, str] = {}
    ip_to_dev: dict[str, str] = {}
    for i in interfaces:
        bip = _bare_ip(i.get("ip", ""))
        if i.get("device") and i.get("name") and bip:
            iface_ip[(i.get("device"), i.get("name"))] = bip
            ip_to_dev.setdefault(bip, i.get("device"))
    for name, d in devices.items():
        bip = _bare_ip(d.get("ip", ""))
        if bip:
            ip_to_dev.setdefault(bip, name)

    # phase 2 selectors grouped by (device, phase1 name)
    sel_by_p1: dict[tuple, list] = {}
    for s in phase2:
        sel_by_p1.setdefault((s.get("device"), s.get("phase1")), []).append(s)

    nodes: list[dict] = []
    links: list[dict] = []
    seen: set[str] = set()

    def add_node(nid: str, **kw) -> None:
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, **kw})

    tunnel_devs = {p.get("device") for p in phase1 if p.get("device")}
    # device nodes — tunnel devices are visible, the rest carry notun=1 (hidden until "Show all")
    for dev in sorted(devices):
        d = devices.get(dev, {})
        add_node(f"dev:{dev}", label=dev, type="device", ip=d.get("ip", ""),
                 platform=d.get("platform", ""), notun=0 if dev in tunnel_devs else 1)

    local_by_dev: dict[str, set] = {}
    remote_by_peer: dict[str, set] = {}

    for t in phase1:
        dev = t.get("device")
        name = t.get("name")
        if not dev or not name:
            continue
        gw = (t.get("remote_gw") or "").strip()
        dev_id = f"dev:{dev}"
        # dynamic / dial-up peers fan out per tunnel; static peers dedupe by gateway IP
        if gw and gw not in ("0.0.0.0", "0.0.0.0/0"):
            peer_id = f"peer:{gw}"
            peer_label = gw
        else:
            peer_id = f"peer:{dev}:{name}"
            peer_label = "dial-up / dynamic"
        # resolve remote gateway IP to a managed FortiGate where possible
        remote_fw = ip_to_dev.get(_bare_ip(gw), "") if gw else ""
        if remote_fw == dev:
            remote_fw = ""
        add_node(peer_id, label=peer_label, type="peer", ip=gw or "dynamic", remote_fw=remote_fw)

        # initiating IP: explicit local-gw, else the egress interface address
        intf = (_tokens(t.get("interface")) or [""])[0]
        init_ip = _bare_ip(t.get("local_gw", ""))
        if not init_ip or init_ip == "0.0.0.0":
            init_ip = iface_ip.get((dev, intf), "")

        sels = sel_by_p1.get((dev, name), [])
        local = sorted({s.get("src_subnet") for s in sels if s.get("src_subnet")})
        remote = sorted({s.get("dst_subnet") for s in sels if s.get("dst_subnet")})
        local_by_dev.setdefault(dev_id, set()).update(local)
        remote_by_peer.setdefault(peer_id, set()).update(remote)

        links.append({
            "source": dev_id, "target": peer_id, "kind": "tunnel",
            "label": name, "intf": t.get("interface", ""), "ike": t.get("ike", ""),
            "mode": t.get("mode", ""), "local": local, "remote": remote,
            "init_ip": init_ip, "remote_fw": remote_fw,
        })

    # local network nodes (toggleable)
    for dev_id, subs in local_by_dev.items():
        for sub in sorted(subs):
            nid = f"lnet:{dev_id}:{sub}"
            add_node(nid, label=sub, type="lnet")
            links.append({"source": dev_id, "target": nid, "kind": "subnet"})
    # remote network nodes (toggleable)
    for peer_id, subs in remote_by_peer.items():
        for sub in sorted(subs):
            nid = f"rnet:{peer_id}:{sub}"
            add_node(nid, label=sub, type="rnet")
            links.append({"source": peer_id, "target": nid, "kind": "subnet"})

    return {"nodes": nodes, "links": links}


def build_vpn_map(site: SiteBuilder, snap: dict) -> None:
    graph = build_vpn_graph(snap)
    n_dev = sum(1 for n in graph["nodes"] if n["type"] == "device" and not n.get("notun"))
    n_all = sum(1 for n in graph["nodes"] if n["type"] == "device")
    n_peer = sum(1 for n in graph["nodes"] if n["type"] == "peer")
    n_tun = sum(1 for l in graph["links"] if l["kind"] == "tunnel")
    n_net = sum(1 for n in graph["nodes"] if n["type"] in ("lnet", "rnet"))

    header = (
        "<h2>VPN Map <span class='vendor-chip'>FortiManager</span></h2>"
        '<div class="note">Interactive IPsec topology built from the read-only snapshot. '
        "Drag nodes, scroll to zoom, drag the background to pan. Click a FortiGate, "
        "gateway or tunnel for details. Toggle subnets to overlay local &amp; remote networks.</div>"
    )
    meta = (
        f'<p class="meta"><span class="mono">{n_dev}</span> FortiGates with IPsec '
        f'(<span class="mono">{n_all}</span> managed — enable “All firewalls”) &nbsp;&middot;&nbsp; '
        f'<span class="mono">{n_peer}</span> remote gateways &nbsp;&middot;&nbsp; '
        f'<span class="mono">{n_tun}</span> IPsec tunnels &nbsp;&middot;&nbsp; '
        f'<span class="mono">{n_net}</span> VPN networks</p>'
    )
    toolbar = (
        '<div class="vpn-toolbar">'
        '<input id="vpsearch" class="search" placeholder="Find device / gateway…" '
        'style="max-width:220px;margin:0">'
        '<label class="vpn-check"><input type="checkbox" id="vptoglocal"> Local subnets</label>'
        '<label class="vpn-check"><input type="checkbox" id="vptogremote"> Remote subnets</label>'
        '<label class="vpn-check"><input type="checkbox" id="vptogall"> All firewalls</label>'
        '<label class="vpn-check"><input type="checkbox" id="vpanimate" checked> Animate</label>'
        '<button class="vbtn" id="vprelayout">Re-run layout</button>'
        '<button class="vbtn" id="vpreset">Reset view</button>'
        '<span class="vpn-sep"></span>'
        '<button class="vbtn" id="vppng">PNG</button>'
        '<button class="vbtn" id="vpjpg">JPEG</button>'
        '<button class="vbtn" id="vppdf">PDF / Print</button>'
        '</div>'
    )
    legend = (
        '<div class="vpn-legend">'
        '<span><i class="lg lg-dev"></i> FortiGate</span>'
        '<span><i class="lg lg-peer"></i> Remote gateway</span>'
        '<span><i class="lg lg-lnet"></i> Local network</span>'
        '<span><i class="lg lg-rnet"></i> Remote network</span>'
        '<span><i class="lg lg-tun"></i> IPsec tunnel</span>'
        '</div>'
    )
    canvas = (
        '<div id="vpnwrap">'
        '<svg id="vpnsvg"><g id="vpvp"><g id="vplinks"></g><g id="vpnodes"></g></g></svg>'
        '<div id="vppanel"></div>'
        '<div id="vphint">Click a node or tunnel for details</div>'
        '</div>'
    )
    script = (
        "<script>var VPN_GRAPH = "
        + json.dumps(graph)
        + ";</script>\n<script>"
        + VPN_MAP_JS
        + "</script>"
    )
    if n_tun == 0:
        body = header + "<div class='note warnbox'>No IPsec tunnels found in this snapshot.</div>"
    else:
        body = (header + meta + VPN_MAP_CSS + toolbar + legend + canvas + script)
    site.page("vpn_map.html", "VPN Map", body)


def build_vpn_matrix(site: SiteBuilder, snap: dict) -> None:
    """Whole-view table: every firewall, its tunnels, initiating IPs, local/remote nets & peer FW."""
    graph = build_vpn_graph(snap)
    byid = {n["id"]: n for n in graph["nodes"]}
    devices = sorted(d.get("name") for d in snap.get("devices", []) if isinstance(d, dict) and d.get("name"))
    tunnels = [l for l in graph["links"] if l["kind"] == "tunnel"]
    p1_by = {}
    for p in snap.get("vpn_phase1", []):
        if isinstance(p, dict):
            p1_by[(p.get("device"), p.get("name"))] = p

    rows = []
    devs_with = set()
    for l in sorted(tunnels, key=lambda x: (byid[x["source"]]["label"], x["label"])):
        dev = byid[l["source"]]["label"]
        devs_with.add(dev)
        p1 = p1_by.get((dev, l["label"]), {})
        peer = byid[l["target"]]
        remote_fw = l.get("remote_fw") or '<span class="muted">(external)</span>'
        local = "<br>".join(esc(s) for s in l.get("local", [])) or '<span class="muted">—</span>'
        remote = "<br>".join(esc(s) for s in l.get("remote", [])) or '<span class="muted">—</span>'
        rows.append(
            f"<tr><td>{esc(dev)}</td><td class='mono'>{esc(p1.get('vdom', ''))}</td>"
            f"<td class='mono'>{esc(l['label'])}</td><td class='mono'>{esc(l.get('intf', ''))}</td>"
            f"<td class='mono'>{esc(l.get('init_ip') or '—')}</td><td class='mono'>{local}</td>"
            f"<td class='mono'>{esc(peer['label'])}</td><td>{remote_fw}</td>"
            f"<td class='mono'>{remote}</td><td>{esc(l.get('ike', ''))}</td>"
            f"<td>{esc(l.get('mode', ''))}</td></tr>")

    no_tun = [d for d in devices if d not in devs_with]
    body = ['<h2>VPN Matrix <span class="vendor-chip">FortiManager</span></h2>',
            '<div class="note">Whole-view table of every IPsec tunnel — the initiating firewall and IP, '
            'local networks, the remote gateway (resolved to a managed FortiGate where its IP matches one) '
            'and the remote networks. Use the export button for Excel/CSV.</div>']
    body.append(site.cards([
        (str(len(devices)), "Managed Firewalls", ""),
        (str(len(devs_with)), "With IPsec", ""),
        (str(len(no_tun)), "Without IPsec", "warn" if no_tun else ""),
        (str(len(tunnels)), "Tunnels", ""),
    ]))
    body.append(site.searchbox("vpmtx", "vpmtxcnt"))
    body.append('<div class="meta"><span id="vpmtxcnt"></span> of '
                f'{len(tunnels)} tunnels &nbsp;·&nbsp; '
                '<button class="vbtn" onclick="exportTableCSV(\'vpmtx\',\'vpn-matrix.csv\')">'
                'Export Excel / CSV</button></div>')
    body.append('<div class="table-wrap"><table id="vpmtx"><thead><tr><th>Firewall</th><th>VDOM</th>'
                '<th>Tunnel</th><th>Egress</th><th>Initiating IP</th><th>Local networks</th>'
                '<th>Remote GW</th><th>Remote FW</th><th>Remote networks</th><th>IKE</th><th>Mode</th>'
                '</tr></thead><tbody>')
    body.extend(rows or ['<tr><td colspan="11" class="muted">No IPsec tunnels found.</td></tr>'])
    body.append('</tbody></table></div>')
    if no_tun:
        body.append('<div class="section-title">Firewalls without IPsec tunnels '
                    f'<span class="count">{len(no_tun)}</span></div>')
        body.append('<table><thead><tr><th>Firewall</th></tr></thead><tbody>')
        body.extend(f"<tr><td>{esc(d)}</td></tr>" for d in no_tun)
        body.append('</tbody></table>')
    site.page("vpn_matrix.html", "VPN Matrix", "".join(body))


def _action_tag(action: str) -> str:
    a = str(action or "").strip().lower()
    if a in ("accept", "allow", "1"):
        cls, label = "t-accept", "ACCEPT"
    elif a in ("deny", "drop", "0", "block"):
        cls, label = "t-drop", "DENY"
    elif a in ("reject",):
        cls, label = "t-reject", "REJECT"
    elif a in ("ipsec", "ssl-vpn", "tunnel"):
        cls, label = "t-inner", a.upper()
    else:
        cls, label = "t-other", (str(action) or "—")
    return f'<span class="tag {cls}">{esc(label)}</span>'


def _nat_tag(nat: str) -> str:
    n = str(nat or "").strip().lower()
    if n in ("enable", "1", "on", "yes"):
        return '<span class="tag t-inner">NAT</span>'
    return '<span class="tag t-other">—</span>'


def _status_tag(status: str) -> str:
    s = str(status or "").strip().lower()
    if s in ("disable", "0", "down", "disabled"):
        return '<span class="tag t-drop">DISABLED</span>'
    return '<span class="tag t-accept">ENABLED</span>'


def _log_tag(log: str) -> str:
    l = str(log or "").strip().lower()
    if l in ("all", "enable", "utm"):
        return f'<span class="tag t-accept">{esc(l)}</span>'
    if l in ("", "disable", "0"):
        return '<span class="tag t-reject">no-log</span>'
    return f'<span class="tag t-other">{esc(l)}</span>'


def build_policies(site: SiteBuilder, snap: dict) -> None:
    pols = [p for p in snap.get("policies", []) if isinstance(p, dict)]

    def _is_disabled(p: dict) -> bool:
        return str(p.get("status", "")).strip().lower() in ("disable", "0", "down", "disabled")

    def _act(p: dict) -> str:
        return str(p.get("action", "")).strip().lower()

    n_accept = sum(1 for p in pols if _act(p) in ("accept", "allow", "1") and not _is_disabled(p))
    n_deny = sum(1 for p in pols if _act(p) in ("deny", "drop", "0", "block"))
    n_disabled = sum(1 for p in pols if _is_disabled(p))
    n_nat = sum(1 for p in pols if str(p.get("nat", "")).strip().lower() in ("enable", "1", "on", "yes"))
    n_nolog = sum(1 for p in pols if str(p.get("logtraffic", "")).strip().lower() in ("", "disable", "0")
                  and not _is_disabled(p))

    headers = ["Device", "ID", "Name", "Src Intf", "Dst Intf", "Source",
               "Destination", "Service", "Action", "NAT", "Log", "Status", "Comments"]
    rows = []
    for p in pols:
        tr_cls = ' class="disabled"' if _is_disabled(p) else ""
        cells = [
            f'<td class="mono">{esc(p.get("device", ""))}</td>',
            f'<td class="mono">{esc(p.get("policyid", ""))}</td>',
            f'<td>{esc(p.get("name", ""))}</td>',
            f'<td class="mono">{esc(p.get("srcintf", ""))}</td>',
            f'<td class="mono">{esc(p.get("dstintf", ""))}</td>',
            f'<td class="mono">{esc(p.get("srcaddr", ""))}</td>',
            f'<td class="mono">{esc(p.get("dstaddr", ""))}</td>',
            f'<td class="mono">{esc(p.get("service", ""))}</td>',
            f'<td>{_action_tag(p.get("action"))}</td>',
            f'<td>{_nat_tag(p.get("nat"))}</td>',
            f'<td>{_log_tag(p.get("logtraffic"))}</td>',
            f'<td>{_status_tag(p.get("status"))}</td>',
            f'<td>{esc(p.get("comments", ""))}</td>',
        ]
        rows.append(f"<tr{tr_cls}>{''.join(cells)}</tr>")

    legend = (
        '<div class="meta" style="margin-bottom:12px">Legend: '
        '<span class="tag t-accept">ACCEPT</span> allow &nbsp; '
        '<span class="tag t-drop">DENY</span> drop/deny &nbsp; '
        '<span class="tag t-reject">REJECT</span> reject &nbsp; '
        '<span class="tag t-inner">NAT</span> source-NAT &nbsp; '
        '<span class="tag t-drop">DISABLED</span> rule off (row dimmed)</div>'
    )
    body = (
        "<h2>Firewall Policies</h2>"
        + site.cards([
            (str(len(pols)), "Total Rules", ""),
            (str(n_accept), "Accept (active)", "good" if n_accept else ""),
            (str(n_deny), "Deny / Drop", "bad" if n_deny else ""),
            (str(n_disabled), "Disabled", "warn" if n_disabled else ""),
            (str(n_nat), "Source-NAT", ""),
            (str(n_nolog), "Accept w/o Log", "warn" if n_nolog else ""),
        ])
        + legend
        + site.searchbox("pol", "pol_cnt")
        + f'<div class="meta"><span id="pol_cnt"></span> of {len(pols)} total'
        + ' &nbsp;·&nbsp; <button class="vbtn" onclick="exportTableCSV(\'pol\',\'policies.csv\')">'
        + 'Export Excel / CSV</button></div>'
        + site.table("pol", headers, rows)
    )
    site.page("policies.html", "Firewall Policies", body)


def build_audit(site: SiteBuilder, snap: dict, A: dict) -> None:
    """Per-device security posture — cross-references policies, interfaces, VPN,
    routing and firmware so each FortiGate can be understood and audited on one row."""
    devices = [d for d in snap.get("devices", []) if isinstance(d, dict)]
    policies = [p for p in snap.get("policies", []) if isinstance(p, dict)]
    interfaces = [i for i in snap.get("interfaces", []) if isinstance(i, dict)]
    routes = [r for r in snap.get("routes", []) if isinstance(r, dict)]
    p1 = [t for t in snap.get("vpn_phase1", []) if isinstance(t, dict)]
    ssl = [s for s in snap.get("vpn_ssl", []) if isinstance(s, dict)]

    def _is_any(v) -> bool:
        toks = _tokens(v)
        return (not toks) or any(t.lower() == "all" for t in toks)

    # Seed one record per known device (and any device that only appears in a dataset).
    names = {str(d.get("name", "")) for d in devices if d.get("name")}
    for coll in (policies, interfaces, routes, p1, ssl):
        names.update(str(x.get("device", "")) for x in coll if x.get("device"))
    names.discard("")

    dev_meta = {str(d.get("name", "")): d for d in devices}
    rec: dict[str, dict] = {n: {
        "rules": 0, "accept": 0, "deny": 0, "disabled": 0, "permissive": 0,
        "nolog": 0, "intf": 0, "cleartext": 0, "wan_mgmt": 0, "tunnels": 0,
        "ssl": False, "default_route": False,
    } for n in sorted(names)}

    for p in policies:
        r = rec.get(str(p.get("device", "")))
        if r is None:
            continue
        r["rules"] += 1
        act = str(p.get("action", "")).strip().lower()
        disabled = str(p.get("status", "")).strip().lower() in ("disable", "0", "down", "disabled")
        if disabled:
            r["disabled"] += 1
            continue
        if act in ("accept", "allow", "1"):
            r["accept"] += 1
            if _is_any(p.get("srcaddr")) and _is_any(p.get("dstaddr")) and _is_any(p.get("service")):
                r["permissive"] += 1
            if str(p.get("logtraffic", "")).strip().lower() in ("", "disable", "0"):
                r["nolog"] += 1
        elif act in ("deny", "drop", "0", "block"):
            r["deny"] += 1

    p1_ifaces = {(t.get("device"), _tokens(t.get("interface"))[0])
                 for t in p1 if _tokens(t.get("interface"))}
    for i in interfaces:
        r = rec.get(str(i.get("device", "")))
        if r is None:
            continue
        r["intf"] += 1
        toks = _access_tokens(i)
        if any(t in CLEARTEXT_ACCESS for t in toks):
            r["cleartext"] += 1
        wan = _is_wan(i) or (i.get("device"), i.get("name")) in p1_ifaces
        if wan and any(t in MGMT_ACCESS for t in toks):
            r["wan_mgmt"] += 1
    for r in routes:
        rr = rec.get(str(r.get("device", "")))
        if rr is not None and str(r.get("dst", "")).startswith("0.0.0.0"):
            rr["default_route"] = True
    for t in p1:
        rr = rec.get(str(t.get("device", "")))
        if rr is not None:
            rr["tunnels"] += 1
    for s in ssl:
        rr = rec.get(str(s.get("device", "")))
        if rr is not None and "enable" in str(s.get("status", "")).lower():
            rr["ssl"] = True

    def _num(v, cls):
        return f'<td><span class="tag {cls}">{v}</span></td>' if v else '<td><span class="tag t-other">0</span></td>'

    def _eol(ver: str) -> bool:
        return str(ver or "")[:1] in ("5", "6")

    rows = []
    n_permissive = n_cleartext = n_nolog = n_ssl = n_nolocal = 0
    for name in sorted(rec):
        r = rec[name]
        meta = dev_meta.get(name, {})
        ver = str(meta.get("os_ver", "") or "")
        has_local = bool(meta.get("has_local_config"))
        if not has_local:
            n_nolocal += 1
        if r["permissive"]:
            n_permissive += 1
        if r["cleartext"] or r["wan_mgmt"]:
            n_cleartext += 1
        if r["nolog"]:
            n_nolog += 1
        if r["ssl"]:
            n_ssl += 1
        ver_cell = (f'<span class="tag t-drop">{esc(ver) or "?"} (EOL)</span>'
                    if _eol(ver) else f'<span class="mono">{esc(ver) or "—"}</span>')
        local_cell = ('<span class="tag t-accept">yes</span>' if has_local
                      else '<span class="tag t-reject">no</span>')
        ssl_cell = ('<span class="tag t-reject">enabled</span>' if r["ssl"]
                    else '<span class="tag t-other">off</span>')
        rows.append(
            "<tr>"
            f'<td class="mono">{esc(name)}</td>'
            f"<td>{ver_cell}</td>"
            f"<td>{local_cell}</td>"
            f'<td><span class="tag t-other">{r["rules"]}</span></td>'
            f'<td><span class="tag t-accept">{r["accept"]}</span></td>'
            f'<td><span class="tag t-drop">{r["deny"]}</span></td>'
            + _num(r["disabled"], "t-reject")
            + _num(r["permissive"], "t-drop")
            + _num(r["nolog"], "t-reject")
            + _num(r["cleartext"], "t-drop")
            + _num(r["wan_mgmt"], "t-drop")
            + f'<td><span class="tag t-inner">{r["tunnels"]}</span></td>'
            + f"<td>{ssl_cell}</td>"
            + ('<td><span class="tag t-accept">yes</span></td>' if r["default_route"]
               else '<td><span class="tag t-other">no</span></td>')
            + "</tr>"
        )

    headers = ["Device", "FortiOS", "Local Cfg", "Rules", "Accept", "Deny",
               "Disabled", "Any/Any Accept", "Accept No-Log", "Cleartext Mgmt",
               "WAN Mgmt", "IPsec Tunnels", "SSL-VPN", "Default Rt"]
    body = (
        "<h2>Audit &mdash; Security Posture by Device</h2>"
        '<div class="note">One row per FortiGate, cross-referencing firewall rules, '
        'interfaces, VPN, routing and firmware from the central pull <em>and</em> the '
        'merged local device configs. Red cells are review-worthy; click a page in the '
        'nav for the underlying detail.</div>'
        + site.cards([
            (str(len(rec)), "Firewalls Audited", ""),
            (str(n_nolocal), "Missing Local Config", "warn" if n_nolocal else "good"),
            (str(n_permissive), "Devices w/ Any/Any Accept", "bad" if n_permissive else "good"),
            (str(n_cleartext), "Devices w/ Cleartext/WAN Mgmt", "bad" if n_cleartext else "good"),
            (str(n_nolog), "Devices w/ Unlogged Accept", "warn" if n_nolog else "good"),
            (str(n_ssl), "Devices w/ SSL-VPN", "warn" if n_ssl else ""),
        ])
        + site.searchbox("aud", "aud_cnt")
        + f'<div class="meta"><span id="aud_cnt"></span> of {len(rec)} firewalls'
        + ' &nbsp;·&nbsp; <button class="vbtn" onclick="exportTableCSV(\'aud\',\'audit_by_device.csv\')">'
        + 'Export Excel / CSV</button></div>'
        + site.table("aud", headers, rows)
    )
    site.page("audit.html", "Audit", body)


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))


def build_appliances(site: SiteBuilder, snap: dict, run: Path, out: Path) -> None:
    """Physical appliance inventory (Check Point parity) — one row per FortiGate
    with hardware/OS/HA detail and a click-through to the unit's actual running
    config (the .conf backup pulled from the device at collection time)."""
    devices = [d for d in snap.get("devices", []) if isinstance(d, dict)]
    cfg_dir = find_local_configs_dir(run)
    conf_files: dict[str, Path] = {}
    if cfg_dir and cfg_dir.is_dir():
        for f in sorted(cfg_dir.glob("*.conf")):
            conf_files[f.stem.lower()] = f

    dest = out / "configs"
    viewer_for: dict[str, tuple[str, str, int]] = {}  # device -> (viewer, raw, bytes)
    for d in devices:
        name = str(d.get("name", ""))
        f = conf_files.get(name.lower()) or conf_files.get(_safe_name(name).lower())
        if not f:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        dest.mkdir(parents=True, exist_ok=True)
        raw_rel = f"configs/{f.name}"
        (out / "configs" / f.name).write_text(text, encoding="utf-8")
        viewer = f"config_{_safe_name(name)}.html"
        n_lines = text.count("\n") + 1
        vbody = (
            f"<h2>{esc(name)} — running configuration</h2>"
            f'<div class="meta">Source: <span class="mono">{esc(f.name)}</span>'
            f' &nbsp;·&nbsp; {len(text):,} bytes &nbsp;·&nbsp; {n_lines:,} lines'
            f' &nbsp;·&nbsp; local rev <span class="mono">{esc(d.get("config_revision", "") or "—")}</span>'
            f' &nbsp;·&nbsp; <a href="{esc(raw_rel)}" download>Download .conf</a>'
            f' &nbsp;·&nbsp; <a href="appliances.html">← back to appliances</a></div>'
            '<div class="note">Exact text backup pulled read-only from the FortiGate via the '
            'FortiManager proxy at collection time — what the device was actually running.</div>'
            f'<pre class="mono" style="white-space:pre-wrap;overflow-x:auto">{esc(text)}</pre>'
        )
        site.page(viewer, f"{name} config", vbody)
        viewer_for[name] = (viewer, raw_rel, len(text))

    body = ['<h2>Physical Appliances '
            f'<span class="count">({len(devices)})</span></h2>',
            '<div class="note">Every FortiGate enforcement unit managed by this FortiManager. '
            'Click <strong>view</strong> to read the exact running configuration pulled from '
            'the device, or download the raw <span class="mono">.conf</span> backup.</div>']
    body.append(site.cards([
        (str(len(devices)), "Appliances", ""),
        (str(len(viewer_for)), "Running Configs Captured",
         "good" if len(viewer_for) == len(devices) else "warn"),
        (str(len({d.get('platform') for d in devices if d.get('platform')})), "Hardware Models", ""),
        (str(len({d.get('os_ver') for d in devices if d.get('os_ver')})), "FortiOS Versions", ""),
    ]))
    body.append(site.searchbox("appl", "applcnt"))
    body.append(f'<div class="meta"><span id="applcnt"></span> of {len(devices)} appliances</div>')
    body.append('<table id="appl"><thead><tr><th>Appliance</th><th>Platform</th><th>Serial</th>'
                '<th>FortiOS</th><th>HA</th><th>Mgmt IP</th><th>VDOMs</th><th>Conn</th>'
                '<th>Revisions</th><th>Running Config</th></tr></thead><tbody>')
    for d in sorted(devices, key=lambda x: str(x.get("name"))):
        name = str(d.get("name", ""))
        conn = str(d.get("conn_status", ""))
        conn_cell = (f'<span class="tag t-accept">{esc(conn)}</span>'
                     if conn.lower() in ("up", "1", "connected")
                     else f'<span class="tag t-other">{esc(conn or "—")}</span>')
        v = viewer_for.get(name)
        cfg_cell = (f'<a href="{esc(v[0])}">view</a> · <a href="{esc(v[1])}" download>.conf</a>'
                    f' <span class="muted">({v[2] // 1024} KB)</span>'
                    if v else '<span class="badge b-amber">not captured</span>')
        body.append(
            f"<tr><td class='mono'>{esc(name)}</td><td>{esc(d.get('platform'))}</td>"
            f"<td class='mono'>{esc(d.get('sn'))}</td><td class='mono'>{esc(d.get('os_ver'))}</td>"
            f"<td>{esc(d.get('ha_mode'))}</td><td class='mono'>{esc(d.get('ip'))}</td>"
            f"<td class='mono'>{esc(d.get('vdoms'))}</td><td>{conn_cell}</td>"
            f"<td>{esc(d.get('revision_info', ''))}</td><td>{cfg_cell}</td></tr>"
        )
    body.append('</tbody></table>')
    site.page("appliances.html", "Physical Appliances", "".join(body))


def build_revisions(site: SiteBuilder, snap: dict) -> None:
    """Change tracking — ADOM database revisions on the FortiManager plus the
    config revision history stored on each FortiGate, and the local .conf
    backups merged into this bundle."""
    adom_revs = [r for r in snap.get("adom_revisions", []) if isinstance(r, dict)]
    dev_revs = [r for r in snap.get("device_revisions", []) if isinstance(r, dict)]
    devices = [d for d in snap.get("devices", []) if isinstance(d, dict)]
    with_local = [d for d in devices if d.get("has_local_config")]
    dev_rev_count = Counter(str(r.get("device", "")) for r in dev_revs)

    body = ['<h2>Revisions &amp; Change Tracking</h2>',
            '<div class="note">Configuration history from three sources: '
            '<strong>ADOM revisions</strong> (database snapshots taken on the FortiManager), '
            '<strong>device config revisions</strong> (the revision list each FortiGate keeps '
            'locally, read via the proxied monitor API), and the <strong>local .conf backups</strong> '
            'bundled in this run. Re-run the collector periodically to maintain a fresh baseline; '
            'each run is a timestamped, diff-able snapshot.</div>']
    body.append(site.cards([
        (str(len(adom_revs)), "ADOM Revisions", "" if adom_revs else "warn"),
        (str(len(dev_revs)), "Device Config Revisions", ""),
        (str(len(dev_rev_count)), "Devices w/ Revision History", ""),
        (str(len(with_local)), "Local .conf Backups in Bundle", "good" if with_local else "warn"),
    ]))

    body.append(f'<div class="section-title">ADOM revisions (FortiManager database) '
                f'<span class="count">{len(adom_revs)}</span></div>')
    if adom_revs:
        body.append('<table><thead><tr><th>ADOM</th><th>Version</th><th>Name</th>'
                    '<th>Created</th><th>By</th><th>Locked</th><th>Description</th></tr></thead><tbody>')
        for r in sorted(adom_revs, key=lambda x: str(x.get("created_time", "")), reverse=True):
            body.append(f"<tr><td>{esc(r.get('adom'))}</td><td class='mono'>{esc(r.get('version'))}</td>"
                        f"<td>{esc(r.get('name'))}</td><td class='mono'>{esc(r.get('created_time'))}</td>"
                        f"<td>{esc(r.get('created_by'))}</td><td>{esc(r.get('locked'))}</td>"
                        f"<td>{esc(r.get('desc'))}</td></tr>")
        body.append('</tbody></table>')
    else:
        body.append('<div class="note warnbox">No ADOM revisions found — none have been created on '
                    'this FortiManager (System Settings → Advanced → ADOM Revisions), or the API '
                    'account cannot read <span class="mono">/dvmdb/adom/&lt;adom&gt;/revision</span>. '
                    'Creating a revision before/after change windows gives you restorable, '
                    'auditable checkpoints.</div>')

    body.append(f'<div class="section-title">Device config revisions (stored on each FortiGate) '
                f'<span class="count">{len(dev_revs)}</span></div>')
    if dev_revs:
        body.append(site.searchbox("drev", "drevcnt"))
        body.append('<div class="meta"><span id="drevcnt"></span> of '
                    f'{len(dev_revs)} revisions &nbsp;·&nbsp; '
                    '<button class="vbtn" onclick="exportTableCSV(\'drev\',\'device-revisions.csv\')">'
                    'Export Excel / CSV</button></div>')
        body.append('<table id="drev"><thead><tr><th>Device</th><th>Rev ID</th><th>Time</th>'
                    '<th>Admin</th><th>Comment</th></tr></thead><tbody>')
        for r in sorted(dev_revs, key=lambda x: (str(x.get("device")), str(x.get("time"))),
                        reverse=False):
            body.append(f"<tr><td>{esc(r.get('device'))}</td><td class='mono'>{esc(r.get('id'))}</td>"
                        f"<td class='mono'>{esc(r.get('time'))}</td><td>{esc(r.get('admin'))}</td>"
                        f"<td>{esc(r.get('comment'))}</td></tr>")
        body.append('</tbody></table>')
    else:
        body.append('<div class="note">No device revision history was readable (devices offline, '
                    'or configuration revisions not enabled on the FortiGates). The bundled '
                    '<span class="mono">Local Configs/*.conf</span> backups below still capture '
                    'the running config at collection time.</div>')

    body.append(f'<div class="section-title">Local config backups in this bundle '
                f'<span class="count">{len(with_local)}</span></div>')
    body.append('<table><thead><tr><th>Device</th><th>Config File</th><th>Rev</th>'
                '<th>FortiOS</th><th>Serial</th></tr></thead><tbody>')
    for d in sorted(with_local, key=lambda x: str(x.get("name"))):
        body.append(f"<tr><td>{esc(d.get('name'))}</td>"
                    f"<td class='mono'>{esc(d.get('config_file', ''))}</td>"
                    f"<td class='mono'>{esc(d.get('config_revision', ''))}</td>"
                    f"<td class='mono'>{esc(d.get('os_ver', ''))}</td>"
                    f"<td class='mono'>{esc(d.get('sn', ''))}</td></tr>")
    if not with_local:
        body.append('<tr><td colspan="5" class="muted">No local .conf backups merged.</td></tr>')
    body.append('</tbody></table>')
    site.page("revisions.html", "Revisions", "".join(body))


def build_users(site: SiteBuilder, snap: dict) -> None:
    users = [u for u in snap.get("users", []) if isinstance(u, dict)]
    groups = [g for g in snap.get("user_groups", []) if isinstance(g, dict)]
    auth = [a for a in snap.get("auth_servers", []) if isinstance(a, dict)]
    body = ['<h2>Users, Groups &amp; Authentication</h2>',
            '<div class="note">Identity objects referenced by identity-aware policies, plus the '
            'external authentication servers (RADIUS/LDAP/TACACS+/SAML) they resolve against.</div>']
    body.append(site.cards([
        (str(len(users)), "Local Users", ""),
        (str(len(groups)), "User Groups", ""),
        (str(len(auth)), "Auth Servers", ""),
    ]))
    body.append(f'<div class="section-title">Local users <span class="count">{len(users)}</span></div>')
    body.append('<table><thead><tr><th>ADOM</th><th>Name</th><th>Type</th><th>Email</th>'
                '<th>Status</th></tr></thead><tbody>')
    for u in users:
        body.append(f"<tr><td>{esc(u.get('adom'))}</td><td class='mono'>{esc(u.get('name'))}</td>"
                    f"<td>{esc(u.get('type'))}</td><td>{esc(u.get('email'))}</td>"
                    f"<td>{esc(u.get('status'))}</td></tr>")
    if not users:
        body.append('<tr><td colspan="5" class="muted">No local users defined centrally.</td></tr>')
    body.append('</tbody></table>')
    body.append(f'<div class="section-title">User groups <span class="count">{len(groups)}</span></div>')
    body.append('<table><thead><tr><th>ADOM</th><th>Name</th><th>Type</th><th>Members</th>'
                '</tr></thead><tbody>')
    for g in groups:
        body.append(f"<tr><td>{esc(g.get('adom'))}</td><td class='mono'>{esc(g.get('name'))}</td>"
                    f"<td>{esc(g.get('group_type'))}</td><td class='mono'>{esc(g.get('member'))}</td></tr>")
    if not groups:
        body.append('<tr><td colspan="4" class="muted">No user groups defined centrally.</td></tr>')
    body.append('</tbody></table>')
    body.append(f'<div class="section-title">Authentication servers <span class="count">{len(auth)}</span></div>')
    body.append('<table><thead><tr><th>ADOM</th><th>Type</th><th>Name</th><th>Server</th>'
                '<th>Port</th></tr></thead><tbody>')
    for a in auth:
        body.append(f"<tr><td>{esc(a.get('adom'))}</td><td>{esc(a.get('type'))}</td>"
                    f"<td class='mono'>{esc(a.get('name'))}</td><td class='mono'>{esc(a.get('server'))}</td>"
                    f"<td class='mono'>{esc(a.get('port'))}</td></tr>")
    if not auth:
        body.append('<tr><td colspan="5" class="muted">No external auth servers defined centrally.</td></tr>')
    body.append('</tbody></table>')
    site.page("users.html", "Users & Groups", "".join(body))


def build_admins(site: SiteBuilder, snap: dict) -> None:
    fmg = [a for a in snap.get("fmg_admins", []) if isinstance(a, dict)]
    dev = [a for a in snap.get("device_admins", []) if isinstance(a, dict)]
    open_trust = [a for a in dev if not str(a.get("trusthosts", "")).strip()]
    no_2fa = [a for a in dev if str(a.get("two_factor", "disable")).lower() in ("disable", "", "0")]
    body = ['<h2>Administrators</h2>',
            '<div class="note">Who can change this environment: FortiManager administrator '
            'accounts, and the local admin accounts on each FortiGate (from the central pull '
            'and merged local configs). Admins without trusted-host restrictions or two-factor '
            'are highlighted.</div>']
    body.append(site.cards([
        (str(len(fmg)), "FortiManager Admins", ""),
        (str(len(dev)), "Device Admin Accounts", ""),
        (str(len(open_trust)), "No Trusted Hosts", "warn" if open_trust else "good"),
        (str(len(no_2fa)), "No Two-Factor", "warn" if no_2fa else "good"),
    ]))
    body.append(f'<div class="section-title">FortiManager administrators '
                f'<span class="count">{len(fmg)}</span></div>')
    body.append('<table><thead><tr><th>User</th><th>Profile</th><th>Type</th><th>ADOMs</th>'
                '<th>Description</th></tr></thead><tbody>')
    for a in fmg:
        body.append(f"<tr><td class='mono'>{esc(a.get('userid'))}</td><td>{esc(a.get('profile'))}</td>"
                    f"<td>{esc(a.get('type'))}</td><td>{esc(a.get('adoms'))}</td>"
                    f"<td>{esc(a.get('description'))}</td></tr>")
    if not fmg:
        body.append('<tr><td colspan="5" class="muted">Not readable with this API account.</td></tr>')
    body.append('</tbody></table>')
    body.append(f'<div class="section-title">Device administrator accounts '
                f'<span class="count">{len(dev)}</span></div>')
    body.append(site.searchbox("dadm", "dadmcnt"))
    body.append(f'<div class="meta"><span id="dadmcnt"></span> of {len(dev)} accounts</div>')
    body.append('<table id="dadm"><thead><tr><th>Device</th><th>Account</th><th>Profile</th>'
                '<th>Trusted Hosts</th><th>VDOMs</th><th>Two-Factor</th></tr></thead><tbody>')
    for a in sorted(dev, key=lambda x: (str(x.get("device")), str(x.get("name")))):
        trust = a.get("trusthosts", "")
        tcell = (f"<span class='mono'>{esc(trust)}</span>" if trust
                 else '<span class="badge b-amber">any source</span>')
        tf = str(a.get("two_factor", "disable"))
        tfcell = (f'<span class="tag t-accept">{esc(tf)}</span>'
                  if tf.lower() not in ("disable", "", "0")
                  else '<span class="tag t-reject">off</span>')
        body.append(f"<tr><td>{esc(a.get('device'))}</td><td class='mono'>{esc(a.get('name'))}</td>"
                    f"<td>{esc(a.get('profile'))}</td><td>{tcell}</td>"
                    f"<td class='mono'>{esc(a.get('vdoms'))}</td><td>{tfcell}</td></tr>")
    if not dev:
        body.append('<tr><td colspan="6" class="muted">No device admin accounts collected.</td></tr>')
    body.append('</tbody></table>')
    site.page("admins.html", "Administrators", "".join(body))


def build_coverage(site: SiteBuilder, snap: dict, run: Path) -> None:
    """Collection coverage — what this bundle contains and what is empty/missing."""
    rows = []
    csv_path = run / "collection-summary.csv"
    if csv_path.is_file():
        try:
            with csv_path.open(newline="", encoding="utf-8") as fh:
                rows = [r for r in csv.DictReader(fh)]
        except Exception:
            rows = []
    if not rows:
        rows = [{"dataset": k, "rows": str(len(v)), "status": "ok" if v else "empty", "note": ""}
                for k, v in snap.items() if isinstance(v, list) and k != "adoms"]

    manifest = {}
    mpath = run / "manifest.json"
    if mpath.is_file():
        try:
            manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except Exception:
            manifest = {}

    n_ok = sum(1 for r in rows if r.get("status") == "ok")
    n_empty = sum(1 for r in rows if r.get("status") == "empty")
    n_err = sum(1 for r in rows if r.get("status") == "error")
    body = ['<h2>Collection Coverage</h2>',
            '<div class="note">Every dataset the collector attempted, with row counts — the '
            'quickest way to spot gaps before analysis. Empty datasets are often legitimate '
            '(e.g. no central policies when FortiGates are managed locally); errors are listed '
            'verbatim from the collection run.</div>']
    body.append(site.cards([
        (str(n_ok), "Datasets Populated", "good" if n_ok else ""),
        (str(n_empty), "Empty", "warn" if n_empty else ""),
        (str(n_err), "Errors", "bad" if n_err else "good"),
    ]))
    if manifest:
        body.append('<div class="section-title">Run manifest</div>')
        body.append('<table><tbody>')
        for k in ("vendor", "collector", "collector_version", "host", "created_at"):
            if manifest.get(k):
                body.append(f"<tr><td>{esc(k)}</td><td class='mono'>{esc(manifest[k])}</td></tr>")
        extra = manifest.get("extra", manifest)
        for k in ("adoms", "duration_sec", "status", "device_configs_pulled"):
            if extra.get(k) not in (None, ""):
                body.append(f"<tr><td>{esc(k)}</td><td class='mono'>{esc(extra[k])}</td></tr>")
        body.append('</tbody></table>')
    body.append('<div class="section-title">Datasets</div>')
    body.append('<table><thead><tr><th>Dataset</th><th>Rows</th><th>Status</th><th>Note</th>'
                '</tr></thead><tbody>')
    for r in rows:
        st = r.get("status", "")
        badge = ('<span class="tag t-accept">ok</span>' if st == "ok"
                 else '<span class="tag t-reject">error</span>' if st == "error"
                 else '<span class="tag t-other">empty</span>')
        body.append(f"<tr><td class='mono'>{esc(r.get('dataset'))}</td>"
                    f"<td>{esc(r.get('rows'))}</td><td>{badge}</td>"
                    f"<td>{esc(r.get('note'))}</td></tr>")
    body.append('</tbody></table>')
    site.page("coverage.html", "Coverage", "".join(body))


def build_table_page(site: SiteBuilder, snap: dict, file: str, title: str,
                     key: str, tid: str, columns: list[tuple[str, str]]) -> None:
    items = snap.get(key, [])
    if not isinstance(items, list):
        items = []
    body = (
        f"<h2>{esc(title)}</h2>"
        + site.searchbox(tid, f"{tid}_cnt")
        + f'<div class="meta"><span id="{tid}_cnt"></span> of {len(items)} total'
        + f' &nbsp;·&nbsp; <button class="vbtn" onclick="exportTableCSV(\'{tid}\',\'{tid}.csv\')">'
        + 'Export Excel / CSV</button></div>'
        + site.table(tid, [h for h, _ in columns], table_rows(items, columns))
    )
    site.page(file, title, body)


def build_site(out: Path, run: Path, snap: dict, offline: bool = False,
               nvd_api_key: str | None = None, analysis: bool = False) -> None:
    nav = NAV if analysis else [n for n in NAV if n[0] not in _ANALYSIS_NAV]
    site = SiteBuilder(out, "fortinet", run.name, nav, viewer_version=__version__)
    site.write_assets()
    normalize_live_state(snap)

    # Enrich devices with revision history summary (count + latest timestamp)
    dev_revs = [r for r in snap.get("device_revisions", []) if isinstance(r, dict)]
    by_dev: dict[str, list] = defaultdict(list)
    for r in dev_revs:
        by_dev[str(r.get("device", ""))].append(r)
    for d in snap.get("devices", []):
        if not isinstance(d, dict):
            continue
        revs = by_dev.get(str(d.get("name", "")), [])
        if revs:
            latest = max(str(r.get("time", "")) for r in revs)
            d["revision_info"] = f"{len(revs)} (latest {latest})" if latest else str(len(revs))

    A = analyze(snap)
    if analysis:
        cve_ids = [c["cve"] for c in KNOWN_CVES]
        if offline:
            print("  [intel] offline mode — using cache/curated data only.")
        else:
            print("  [intel] fetching CISA KEV + NVD (this may take ~30s on first run)...")
        cpes = sorted({cpe_for_version("fortinet", d.get("os_ver"))
                       for d in snap.get("devices", []) if isinstance(d, dict)} - {""})
        intel = fetch_cve_intel(cve_ids, run / "_cve_intel_cache.json", offline,
                                cpes=cpes, nvd_api_key=nvd_api_key)
    else:
        # Browse-only bundle: drop stale analysis pages from earlier builds.
        for name in _ANALYSIS_NAV:
            try:
                (out / name).unlink()
            except OSError:
                pass
    build_dashboard(site, snap)
    build_audit(site, snap, A)
    build_optimization(site, snap, A)
    build_simplify(site, snap, A)
    build_relationships(site, snap, A)
    if analysis:
        build_compliance(site, snap, A, intel)
        build_risk(site, snap, A, intel)
    build_interfaces(site, snap, A)
    build_vpn_map(site, snap)
    build_vpn_matrix(site, snap)
    build_policies(site, snap)
    build_appliances(site, snap, run, out)
    build_revisions(site, snap)
    build_users(site, snap)
    build_admins(site, snap)
    build_coverage(site, snap, run)
    for file, title, key, tid, columns in TABLES:
        build_table_page(site, snap, file, title, key, tid, columns)
    site.write_json_embed("raw.json.html", "Raw JSON", snap)


def main() -> int:
    p = argparse.ArgumentParser(description="Build FortiManager HTML browser from collector bundle")
    p.add_argument("--input", required=True)
    p.add_argument("--output", default=None)
    p.add_argument("--analysis", action="store_true",
                   help="Include the Compliance and Versions & CVE analysis pages "
                        "(omitted from the customer browse-only HTML by default).")
    p.add_argument("--offline", action="store_true",
                   help="Skip live CISA KEV / NVD lookups; use cached or curated data only.")
    p.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                   help="Optional NVD API key (or NVD_API_KEY env) — raises the NVD "
                        "rate limit from 5 to 50 requests/30s.")
    p.add_argument("--local-configs", default=None,
                   help="Folder of per-device FortiGate .conf backups to merge "
                        "(default: auto-detect a 'Local Configs' folder in the run).")
    p.add_argument("--no-local-configs", action="store_true",
                   help="Do not merge any local device .conf backups.")
    args = p.parse_args()
    run = Path(args.input)
    if not run.is_dir():
        print(f"Error: folder not found: {run}")
        return 1
    out = Path(args.output) if args.output else run / "html_view"
    snap = load_snapshot(run)
    if not args.no_local_configs:
        override = Path(args.local_configs) if args.local_configs else None
        merge_run_local_configs(snap, run, override=override, log=print)
    build_site(out, run, snap, offline=args.offline,
               nvd_api_key=args.nvd_api_key or None, analysis=args.analysis)
    print(f"Done. Open:\n  {(out / 'index.html').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
