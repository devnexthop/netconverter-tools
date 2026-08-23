#!/usr/bin/env python3
"""
Check Point configuration browser (read-only).

Reads a run-YYYYMMDD-HHMMSS export folder (from checkpoint_collect_data.py) and
generates a self-contained static HTML site under <run>/html_view/ for local
browsing (open index.html in a browser).

Optional ``--analysis`` adds Optimization, Simplify & Merge, Compliance, and
CVE pages — intended for the NetConverter.local engagement workflow, not the
customer collector bundle.

Usage:
    python build_html.py --input run-YYYYMMDD-HHMMSS
    python build_html.py --input run-... --analysis   # NetConverter.local only
"""
from __future__ import print_function

import argparse
import csv
import html
import json
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import sys
_script_dir = Path(__file__).resolve().parent
_repo_root = _script_dir.parents[1]  # smartconsole/ → checkpoint/ → repo root
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
if str(_script_dir) not in sys.path:
    sys.path.insert(0, str(_script_dir))
from core.cve_intel import cpe_for_version, fetch_cve_intel
from core.html_theme import CSS, JS, vendor

__version__ = "1.5.6"

# Nav pages omitted from the customer browse-only HTML (see --analysis).
_ANALYSIS_NAV = frozenset({
    "optimization.html", "simplify.html", "compliance.html", "risk.html",
})

try:
    from export_quality_audit import audit_run as audit_export_run
except ImportError:
    audit_export_run = None

try:
    from collection_remediation import (
        ROUTING_COLLECTOR,
        build_recollect_command,
        format_remediation_html,
        remediation_for_flag,
    )
except ImportError:
    ROUTING_COLLECTOR = ""
    build_recollect_command = None  # type: ignore[assignment,misc]
    format_remediation_html = None  # type: ignore[assignment,misc]
    remediation_for_flag = None  # type: ignore[assignment,misc]

ANY_UID = "97aeb369-9aea-11d5-bd16-0090272ccb30"
SMC_DOMAIN = "SMC User"
BUILTIN_APP_DOMAINS = frozenset({"APPI Data", "Check Point Data"})

# Check Point built-in/system objects carry fixed UIDs that are NOT returned by
# the object-list commands, so they never land in by_uid. NAT/threat rules lean on
# them heavily ("Original", "Policy Targets", threat profiles). UIDs are stable
# across installations (CheckMates / show-generic-object). Embedded object
# dictionaries in rulebase exports also carry many of these — see _harvest_embedded.
SYSTEM_UID_NAMES = {
  # --- global match / install targets ---
    "97aeb368-9aea-11d5-bd16-0090272ccb30": "All",
    "97aeb369-9aea-11d5-bd16-0090272ccb30": "Any",
    "97aeb36a-9aea-11d5-bd16-0090272ccb30": "None",
    "85c0f50f-6d8a-4528-88ab-5fb11d8fe16c": "Original",
    "6c488338-8eec-4103-ad21-cd461ac2c476": "Policy Targets",
    "6c488338-8eec-4103-ad21-cd461ac2c477": "Log",
    "6c488338-8eec-4103-ad21-cd461ac2c472": "Accept",
    "6c488338-8eec-4103-ad21-cd461ac2c473": "Drop",
    "6c488338-8eec-4103-ad21-cd461ac2c474": "Reject",
    "ea28da66-c5ed-11e2-bc66-aa5c6188709b": "Inner Layer",
    "213f0a22-49da-4719-94b3-f2d74623f3fb": "Policy HTTPS Targets",
    "97aeb36a-9aeb-11d5-bd16-0090272ccb30": "All Users",
    "97aeb36a-9aed-11d5-bd16-0090272ccb30": "All_GwToGw",
  # --- common built-in services referenced in threat/NAT ---
    "97aeb3d9-9aea-11d5-bd16-0090272ccb30": "smtp",
    "97aeb443-9aea-11d5-bd16-0090272ccb30": "https",
  # --- default threat-prevention profiles (out-of-box; names fixed, UIDs stable) ---
    "eb39a60d-c454-49f5-a28c-a89aa5bd2e09": "Basic",
    "caf8b711-d762-4c1e-82d5-6af2549b2869": "Strict",
    "64f86e35-7c16-4b8d-8127-61652a3416c0": "Optimized",
    "715c3bd0-fdf5-46fb-b1d1-229c61720e53": "Optimized",
  # --- org / blade-specific profiles (Mercury export; from show-threat-profile) ---
    "fa1aa324-a8cc-4dbd-bc04-f31fdb8abf61": "MyOrganization",
    "ef06dbef-ed88-4730-b620-03309900a1ed": "Threat Emulation",
    "e9d0e49d-bebb-416f-beb5-2749df0206be": "Inactive",
}

# Object json files -> logical category
OBJECT_FILES = {
    "objects-hosts.json": "host",
    "objects-networks.json": "network",
    "objects-address-ranges.json": "address-range",
    "objects-multicast-ranges.json": "multicast-address-range",
    "objects-groups.json": "group",
    "objects-service-groups.json": "service-group",
    "objects-application-sites.json": "application-site",
    "objects-application-site-groups.json": "application-site-group",
    "objects-user-groups.json": "user-group",
    "objects-services-tcp.json": "service-tcp",
    "objects-services-udp.json": "service-udp",
    "objects-services-icmp.json": "service-icmp",
    "objects-services-icmp6.json": "service-icmp6",
    "objects-services-other.json": "service-other",
    "objects-services-dce-rpc.json": "service-dce-rpc",
    "objects-services-rpc.json": "service-rpc",
    "objects-services-gtp.json": "service-gtp",
    "objects-times.json": "time",
    "objects-access-roles.json": "access-role",
    "objects-dynamic.json": "dynamic-object",
    "objects-dns-domains.json": "dns-domain",
    "objects-groups-with-exclusion.json": "group-with-exclusion",
    "objects-security-zones.json": "security-zone",
    "objects-wildcards.json": "wildcard",
    "objects-updatable.json": "updatable-object",
    "objects-services-sctp.json": "service-sctp",
    "objects-application-site-categories.json": "application-site-category",
    "objects-checkpoint-hosts.json": "checkpoint-host",
    "objects-time-groups.json": "time-group",
    "objects-data-types.json": "data-type",
    "objects-tags.json": "tag",
    "objects-users.json": "user",
    "objects-threat-profiles.json": "threat-profile",
    "objects-threat-exception-groups.json": "threat-exception-group",
    "objects-simple-gateways.json": "simple-gateway",
    "objects-simple-clusters.json": "simple-cluster",
    "objects-referenced.json": "referenced-object",
}

# Every service object category the collector exports. Used for the dashboard
# count, the Services page, and hygiene analysis so no service type is dropped.
SERVICE_CATS = (
    "service-tcp", "service-udp", "service-icmp", "service-icmp6",
    "service-other", "service-dce-rpc", "service-rpc", "service-gtp",
)

# Implied ("hidden") firewall rules from global-properties.json -> firewall.
# These permit traffic that never appears in the explicit rulebase, so a migration
# to Palo Alto / Fortinet MUST reproduce every ENABLED one as an explicit rule.
# Maps the boolean key -> (human label, why it matters). The matching
# "<key>-position" field says where the implied rule sits (first / before last / last).
IMPLIED_RULE_LABELS = {
    "accept-control-connections":
        ("Accept control connections", "SIC, policy install, logging between CP components"),
    "accept-remote-access-control-connections":
        ("Accept Remote Access control connections", "Client-to-site VPN control traffic"),
    "accept-smart-update-connections":
        ("Accept SmartUpdate connections", "License / package management"),
    "accept-ips1-management-connections":
        ("Accept IPS-1 management connections", "IPS management channel"),
    "accept-outgoing-packets-originating-from-gw":
        ("Accept outgoing packets from gateway", "Gateway-sourced traffic (updates, DNS, NTP)"),
    "accept-outgoing-packets-originating-from-connectra-gw":
        ("Accept outgoing packets from Connectra gateway", "Mobile Access gateway egress"),
    "accept-outgoing-packets-to-cp-online-services":
        ("Accept outgoing packets to Check Point online services", "ThreatCloud / update services"),
    "accept-rip":
        ("Accept RIP", "Dynamic routing protocol RIP"),
    "accept-domain-name-over-udp":
        ("Accept DNS over UDP", "DNS name resolution (UDP/53)"),
    "accept-domain-name-over-tcp":
        ("Accept DNS over TCP", "DNS zone transfer (TCP/53)"),
    "accept-icmp-requests":
        ("Accept ICMP requests", "Ping / ICMP to and through the gateway"),
    "accept-web-and-ssh-connections-for-gw-administration":
        ("Accept web & SSH for gateway administration", "HTTPS/SSH management to the gateway"),
    "accept-incoming-traffic-to-dhcp-and-dns-services-of-gws":
        ("Accept incoming DHCP & DNS to gateways", "Gateway-hosted DHCP/DNS services"),
    "accept-dynamic-addr-modules-outgoing-internet-connections":
        ("Accept DAIP dynamic-address gateway egress", "DAIP gateway internet connections"),
    "accept-vrrp-packets-originating-from-cluster-members":
        ("Accept VRRP from cluster members", "Nokia/Gaia VRRP cluster heartbeat"),
    "accept-identity-awareness-control-connections":
        ("Accept Identity Awareness control connections", "PDP/PEP identity sharing"),
}


def esc(value):
    return html.escape("" if value is None else str(value))


def safe_name(name):
    return re.sub(r"[^\w\-.]+", "_", str(name)).strip("_") or "unnamed"


def _mask_len(iface):
    """Prefix length from explicit field or a dotted netmask (handles both CP schemas)."""
    ml = iface.get("ipv4-mask-length")
    if ml in (None, ""):
        ml = iface.get("mask-length4")
    if ml not in (None, ""):
        return str(ml)
    dotted = iface.get("ipv4-network-mask") or ""
    try:
        return str(sum(bin(int(o)).count("1") for o in dotted.split("."))) if dotted else ""
    except (ValueError, TypeError):
        return ""


def _cidr_network(ip, masklen):
    """'10.0.5.3' + 24 -> '10.0.5.0/24' (best-effort, IPv4 only)."""
    try:
        bits = int(masklen)
        octets = [int(x) for x in str(ip).split(".")]
        if len(octets) != 4 or not 0 <= bits <= 32:
            return ""
        val = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
        net = val & mask
        return "{}.{}.{}.{}/{}".format((net >> 24) & 255, (net >> 16) & 255,
                                       (net >> 8) & 255, net & 255, bits)
    except (ValueError, TypeError):
        return ""


def _is_epoch_time_endpoint(endpoint):
    if not isinstance(endpoint, dict):
        return False
    if endpoint.get("posix") == 0:
        return True
    return str(endpoint.get("iso-8601", "")).startswith("1970-01-01")


def format_time_point(endpoint, *, start_now=False, end_never=False):
    """Human-readable start/end for a Check Point time object."""
    if end_never:
        return "Never"
    if start_now and _is_epoch_time_endpoint(endpoint):
        return "Now"
    if not isinstance(endpoint, dict):
        return "—"
    if _is_epoch_time_endpoint(endpoint):
        clock = (endpoint.get("time") or "").strip()
        return clock if clock else "—"
    date = (endpoint.get("date") or "").strip()
    clock = (endpoint.get("time") or "").strip()
    if date and clock:
        return "{} {}".format(date, clock)
    return date or clock or str(endpoint.get("iso-8601", ""))[:19] or "—"


def format_time_recurrence(recurrence, hours_ranges=None):
    """Turn recurrence dict (+ optional hours-ranges) into readable schedule text."""
    parts = []
    if isinstance(recurrence, dict):
        pattern = (recurrence.get("pattern") or "").strip()
        weekdays = [w for w in (recurrence.get("weekdays") or []) if w]
        days = [str(d) for d in (recurrence.get("days") or []) if d not in (None, "")]
        month = recurrence.get("month")
        if pattern == "Daily":
            parts.append("Daily")
        elif pattern == "Weekly":
            parts.append("Weekly" + (": " + ", ".join(weekdays) if weekdays else ""))
        elif pattern == "Monthly":
            detail = []
            if month and str(month) != "Any":
                detail.append("month {}".format(month))
            if days:
                detail.append("day(s) " + ", ".join(days))
            parts.append("Monthly" + (": " + "; ".join(detail) if detail else ""))
        elif pattern:
            parts.append(pattern)
    elif recurrence:
        parts.append(str(recurrence))

    if isinstance(hours_ranges, list):
        windows = []
        for slot in hours_ranges:
            if not isinstance(slot, dict) or not slot.get("enabled"):
                continue
            frm, to = slot.get("from", ""), slot.get("to", "")
            if frm or to:
                windows.append("{}–{}".format(frm, to))
        if windows:
            parts.append("Hours: " + ", ".join(windows))

    return "; ".join(parts) if parts else "—"


def format_time_daily_window(obj):
    """Clock window inside each recurrence period (when not using hours-ranges)."""
    if obj.get("hours-ranges"):
        return "—"
    start = obj.get("start") if isinstance(obj.get("start"), dict) else {}
    end = obj.get("end") if isinstance(obj.get("end"), dict) else {}
    st, en = (start.get("time") or "").strip(), (end.get("time") or "").strip()
    if not st and not en:
        return "—"
    if st == "00:00" and en in ("00:00", "23:59", ""):
        return "All day"
    if st and en:
        return "{}–{}".format(st, en)
    return st or en or "—"

UID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def is_uid(value):
    return bool(UID_RE.match(str(value or "")))


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def nat_settings_summary(obj):
    """One-line object-level NAT summary when --full-objects was used."""
    ns = obj.get("nat-settings")
    if not isinstance(ns, dict) or not ns:
        return ""
    method = ns.get("method") or ns.get("auto-rule") or ""
    if method in ("", None, False):
        if ns.get("ipv4-address") or ns.get("ipv4-network"):
            return "configured"
        return ""
    return str(method)


def is_custom_application(obj):
    domain = (obj.get("domain") or {}).get("name", "")
    return domain not in BUILTIN_APP_DOMAINS


def threat_blade_summary(profile, blade_key):
    """Human-readable IPS / Anti-Bot / Anti-Virus / TE summary from a threat profile.

    Check Point profile JSON varies by version: blade block may be a dict with
    ``active`` + confidence actions, a nested settings object, or absent.
    """
    if not isinstance(profile, dict):
        return "—"
    block = profile.get(blade_key)
    if block is None:
        # Alternate key spellings seen in older exports
        alts = {
            "anti-bot": ("antibot", "anti_bot"),
            "anti-virus": ("antivirus", "anti_virus"),
            "threat-emulation": ("threat_emulation", "te"),
        }
        for alt in alts.get(blade_key, ()):
            if profile.get(alt) is not None:
                block = profile.get(alt)
                break
    if block is None:
        return "—"
    if isinstance(block, bool):
        return "On" if block else "Off"
    if not isinstance(block, dict):
        return str(block)
    if block.get("active") is False:
        return "Inactive"
    parts = []
    if block.get("active") is True:
        parts.append("Active")
    # Confidence / severity action fields (Anti-Bot / AV)
    for label, keys in (
        ("High", ("confidence-level-high", "high", "high-confidence")),
        ("Med", ("confidence-level-medium", "medium", "medium-confidence")),
        ("Low", ("confidence-level-low", "low", "low-confidence")),
    ):
        for k in keys:
            if k in block and block[k] not in (None, ""):
                parts.append("{}={}".format(label, block[k]))
                break
    # IPS often exposes performance / protection mode instead of confidence
    for k in ("protection-mode", "performance-impact", "severity-level",
              "ips-mode", "mode"):
        if block.get(k) not in (None, ""):
            parts.append("{}={}".format(k, block[k]))
            break
    if not parts:
        # Non-empty dict with no known keys — still prove the blade block exists
        return "Configured"
    return ", ".join(parts)


def threat_profile_has_blade_detail(obj):
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in (
        "ips", "anti-bot", "anti-virus", "threat-emulation",
        "active-protections-configuration",
    ))


class CheckpointModel:
    """Loads objects + rulebases and builds cross-reference indexes."""

    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.by_uid = {}            # uid -> object (merged)
        self.objects = defaultdict(list)  # category -> [objects] (from object files)
        self.gateways = []
        self.packages = []
        self.access_layers = []     # list of dicts: {package, layer, file, rules(flat), raw}
        self.nat_layers = []        # list of dicts: {package, file, rules}
        self.https_layers = []      # list of dicts: {package, layer, file, rules}
        self.threat_layers = []     # list of dicts: {package, layer, file, rules}
        self.threat_exceptions = []  # list of dicts from threat-exceptions-*.json
        self.used_uids = set()
        self.member_index = defaultdict(set)  # group uid -> member uids (if available)
        self.where_used = defaultdict(list)   # object uid -> [reference dicts]
        self.member_of = defaultdict(set)     # member uid -> {group uids it belongs to}
        self.vpn_meshed = []
        self.vpn_star = []
        self.vpn_remote = []
        self.export_audit = {"flags": [], "summary": {}}
        self.uses_native_where_used = False
        self.has_object_nat = False
        self.threat_action_hints = {}  # unresolved threat-profile uid -> install-on gateway names
        self.threat_action_layer_hints = {}  # uid -> threat layer names (Policy Targets rules)
        self.zone_interfaces = defaultdict(list)  # zone uid -> gateway iface assignments
        self.global_properties = {}   # global-properties.json (implied rules, NAT, stateful, VPN)
        self.package_meta = {}        # package name -> package.json (install targets, HTTPS layers)

    # ---------- loading ----------
    def load(self):
        self._load_objects()
        self._load_gateways()
        self._load_global_properties()
        self._load_package_meta()
        self._build_zone_interface_index()
        self._load_vpn()
        self._merge_dictionaries_and_rules()
        self._harvest_embedded_objects()
        self._harvest_stub_objects()
        self._load_nat()
        self._load_https()
        self._load_threat()
        self._build_threat_action_hints()
        self._compute_used()
        self._build_where_used()
        self._merge_native_where_used()
        self._assess_export()

    def _index_obj(self, obj):
        uid = obj.get("uid")
        if not uid:
            return
        existing = self.by_uid.get(uid)
        if existing is None:
            self.by_uid[uid] = obj
        else:
            # keep the richer record (more keys)
            if len(obj) > len(existing):
                self.by_uid[uid] = obj
        members = obj.get("members")
        if isinstance(members, list):
            for m in members:
                muid = m.get("uid") if isinstance(m, dict) else m
                if muid:
                    self.member_index[uid].add(muid)
                    if isinstance(m, dict):
                        self._index_obj(m)

    def _expand_object_records(self, obj, category):
        """Normalize collector object shapes (notably updatable-object wrappers)."""
        if not isinstance(obj, dict):
            return []
        if category != "updatable-object":
            return [obj]
        out = []
        nested = obj.get("updatable-object")
        if isinstance(nested, dict) and nested.get("uid"):
            out.append(dict(nested))
        repo_uid = obj.get("uid-in-updatable-objects-repository")
        if repo_uid:
            rec = dict(obj)
            rec["uid"] = repo_uid
            rec.setdefault("type", "updatable-object")
            if not rec.get("name") and rec.get("name-in-updatable-objects-repository"):
                rec["name"] = rec["name-in-updatable-objects-repository"]
            if not any(r.get("uid") == repo_uid for r in out):
                out.append(rec)
        if not out and obj.get("uid"):
            out.append(obj)
        return out

    def _load_objects(self):
        for fname, category in OBJECT_FILES.items():
            data = load_json(self.run_dir / fname)
            if not isinstance(data, list):
                continue
            for obj in data:
                for rec in self._expand_object_records(obj, category):
                    rec["_category"] = category
                    self.objects[category].append(rec)
                    self._index_obj(rec)

    def _load_gateways(self):
        data = load_json(self.run_dir / "gateways-and-servers.json")
        if isinstance(data, list):
            self.gateways = data
            for gw in data:
                if isinstance(gw, dict):
                    self._index_obj(gw)

    def _load_global_properties(self):
        """Load global-properties.json (implied rules, global NAT, stateful inspection,
        VPN, remote-access, hit-count, log-and-alert). This is real config that permits
        traffic outside the explicit rulebase — previously not surfaced anywhere."""
        data = load_json(self.run_dir / "global-properties.json")
        if isinstance(data, dict):
            self.global_properties = data
        elif isinstance(data, list) and data and isinstance(data[0], dict):
            # some exports wrap the single object in a list
            self.global_properties = data[0]

    def _load_package_meta(self):
        """Load each policy-by-package/<pkg>/package.json for install targets and the
        HTTPS-inspection layer wiring (not carried in the top-level packages.json)."""
        policy_dir = self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            return
        for pkg_json in sorted(policy_dir.rglob("package.json")):
            doc = load_json(pkg_json)
            if isinstance(doc, dict) and doc.get("name"):
                self.package_meta[doc["name"]] = doc

    def _build_zone_interface_index(self):
        """Map security-zone uid -> gateway interfaces with that zone in topology."""
        self.zone_interfaces = defaultdict(list)
        for gw in self.gateways:
            if not isinstance(gw, dict):
                continue
            gwname = gw.get("name", "")
            for iface in gw.get("interfaces") or []:
                if not isinstance(iface, dict):
                    continue
                topo = iface.get("topology") or iface.get("topology-settings") or {}
                if not isinstance(topo, dict):
                    continue
                sz = topo.get("security-zone")
                if not isinstance(sz, dict) or not sz.get("uid"):
                    continue
                self.zone_interfaces[sz["uid"]].append({
                    "gateway": gwname,
                    "interface": iface.get("interface-name") or iface.get("name", "?"),
                    "ip": iface.get("ipv4-address", ""),
                    "internet": bool(topo.get("leads-to-internet")),
                    "dmz": bool(topo.get("leads-to-dmz")),
                })

    @staticmethod
    def zone_role_label(name):
        """Human hint for built-in Check Point security zone names."""
        roles = {
            "ExternalZone": "External / Internet-facing",
            "InternalZone": "Internal / trusted",
            "DMZZone": "DMZ",
            "WirelessZone": "Wireless",
        }
        return roles.get(name or "", "Custom zone")

    def _load_vpn(self):
        meshed = load_json(self.run_dir / "vpn-communities-meshed.json")
        if isinstance(meshed, list):
            self.vpn_meshed = meshed
        star = load_json(self.run_dir / "vpn-communities-star.json")
        if isinstance(star, list):
            self.vpn_star = star
        remote = load_json(self.run_dir / "vpn-communities-remote-access.json")
        if isinstance(remote, list):
            self.vpn_remote = remote

    def _flatten_rules(self, rulebase):
        """Yield access-rule dicts in order, recursing into access-section."""
        out = []
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            etype = entry.get("type")
            if etype == "access-section":
                out.extend(self._flatten_rules(entry.get("rulebase", [])))
            else:
                out.append(entry)
        return out

    @staticmethod
    def _shared_export_score(path, rules):
        """Prefer human-readable export filenames over bare UID stems."""
        stem = path.stem.replace("access-rulebase-", "")
        score = len(rules)
        if not is_uid(stem):
            score += 100000
        return score

    def _merge_dictionaries_and_rules(self):
        pkgs = load_json(self.run_dir / "packages.json")
        if isinstance(pkgs, list):
            self.packages = pkgs

        rb_files = []
        policy_dir = self.run_dir / "policy-by-package"
        if policy_dir.is_dir():
            for p in sorted(policy_dir.rglob("access-rulebase-*.json")):
                rb_files.append(("package", p))
        shared_dir = self.run_dir / "access-layers-shared"
        if shared_dir.is_dir():
            for p in sorted(shared_dir.glob("access-rulebase-*.json")):
                rb_files.append(("shared", p))

        shared_best = {}
        package_layers = []
        for origin, path in rb_files:
            doc = load_json(path)
            if not isinstance(doc, dict):
                continue
            for key in ("object_dictionary", "objects-dictionary"):
                for obj in doc.get(key) or []:
                    if isinstance(obj, dict):
                        self._index_obj(obj)
            rules = self._flatten_rules(doc.get("rulebase", []))
            layer_name = doc.get("layer", path.stem)
            layer_uid = layer_name if is_uid(layer_name) else ""
            # inner layers were fetched by UID; resolve to a friendly name if known
            if is_uid(layer_name):
                resolved = self.by_uid.get(layer_name, {}).get("name")
                if resolved:
                    layer_name = resolved
            entry = {
                "origin": origin,
                "package": doc.get("package", ""),
                "layer": layer_name,
                "layer_uid": layer_uid,
                "file": path,
                "rules": rules,
                "total": doc.get("total"),
                "fetched": doc.get("fetched"),
            }
            if origin == "shared":
                key = str(layer_name)
                cur = shared_best.get(key)
                if cur is None or self._shared_export_score(path, rules) > self._shared_export_score(
                        cur["file"], cur["rules"]):
                    shared_best[key] = entry
            else:
                package_layers.append(entry)
        self.access_layers = package_layers + list(shared_best.values())

    def _load_nat(self):
        policy_dir = self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            return
        for p in sorted(policy_dir.rglob("nat-rulebase.json")):
            doc = load_json(p)
            if not isinstance(doc, dict):
                continue
            # index the NAT object-dictionary if present (Rev 2 collects it) so
            # source/destination/service UIDs resolve to names
            for obj in (doc.get("objects-dictionary") or doc.get("object_dictionary") or []):
                if isinstance(obj, dict):
                    self._index_obj(obj)
            pkg = p.parent.name
            # show-nat-rulebase returns rules grouped under nat-section headers
            # (e.g. "Automatic Generated Rules : Network Hide NAT"). The nested
            # rules live in each section's own "rulebase" array, so a flat read
            # of the top level only sees the section headers + any ungrouped
            # rule. Flatten so every nat-rule (manual + auto-generated) is
            # captured, tagging each with its section for context.
            rules = self._flatten_nat_rules(doc.get("rulebase", []))
            self.nat_layers.append({"package": pkg, "file": p, "rules": rules})

    @staticmethod
    def _flatten_nat_rules(rulebase, section=None):
        """Recursively flatten a NAT rulebase, descending into nat-section
        entries to collect every nat-rule. Each rule is annotated with the
        name of the section it came from (under "_section")."""
        out = []
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            etype = entry.get("type")
            if etype == "nat-section":
                sec_name = entry.get("name") or section
                out.extend(CheckpointModel._flatten_nat_rules(entry.get("rulebase", []), sec_name))
            elif etype == "nat-rule":
                if section and "_section" not in entry:
                    entry = dict(entry)
                    entry["_section"] = section
                out.append(entry)
            else:
                # Unknown wrapper that still nests rules — descend defensively.
                if isinstance(entry.get("rulebase"), list):
                    out.extend(CheckpointModel._flatten_nat_rules(entry.get("rulebase"), section))
                else:
                    out.append(entry)
        return out

    def _load_https(self):
        policy_dir = self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            return
        for p in sorted(policy_dir.rglob("https-rulebase-*.json")):
            doc = load_json(p)
            if not isinstance(doc, dict):
                continue
            # index the HTTPS object-dictionary so source/dest/service/site UIDs
            # resolve to names
            for obj in (doc.get("objects-dictionary") or doc.get("object_dictionary") or []):
                if isinstance(obj, dict):
                    self._index_obj(obj)
            pkg = p.parent.name
            rules = self._flatten_https(doc.get("rulebase", []))
            self.https_layers.append({
                "package": pkg,
                "layer": doc.get("layer", p.stem),
                "file": p,
                "rules": rules,
                "total": doc.get("total"),
            })

    def _flatten_https(self, rulebase):
        """Yield https-rule dicts in order, recursing into https-section."""
        out = []
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "https-section":
                out.extend(self._flatten_https(entry.get("rulebase", [])))
            else:
                out.append(entry)
        return out

    def _load_threat(self):
        policy_dir = self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            return
        for p in sorted(policy_dir.rglob("threat-rulebase-*.json")):
            doc = load_json(p)
            if not isinstance(doc, dict):
                continue
            for obj in (doc.get("objects-dictionary") or doc.get("object_dictionary") or []):
                if isinstance(obj, dict):
                    self._index_obj(obj)
                    # Stub profiles from rulebase dictionaries when bulk
                    # show-threat-profiles returned empty (pre-1.5.3 exports).
                    if obj.get("type") == "threat-profile" and obj.get("uid"):
                        stubs = self.objects["threat-profile"]
                        if not any(s.get("uid") == obj["uid"] for s in stubs):
                            stubs.append(obj)
            pkg = p.parent.name
            layer = doc.get("layer", p.stem.replace("threat-rulebase-", ""))
            rules = self._flatten_threat(doc.get("rulebase", []))
            self.threat_layers.append({
                "package": pkg,
                "layer": layer,
                "file": p,
                "rules": rules,
                "total": doc.get("total"),
            })
        for p in sorted(policy_dir.rglob("threat-exceptions-*.json")):
            doc = load_json(p)
            if not isinstance(doc, dict):
                continue
            for obj in (doc.get("objects-dictionary") or doc.get("object_dictionary") or []):
                if isinstance(obj, dict):
                    self._index_obj(obj)
            self.threat_exceptions.append({
                "package": doc.get("package") or p.parent.name,
                "layer": doc.get("layer") or "",
                "rule_uid": doc.get("rule-uid") or "",
                "rule_name": doc.get("rule-name") or p.stem,
                "rule_number": doc.get("rule-number"),
                "file": p,
                "rules": self._flatten_threat(doc.get("rulebase", [])),
                "total": doc.get("total"),
            })

    def _flatten_threat(self, rulebase):
        """Yield threat-rule dicts in order, recursing into threat-section."""
        out = []
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "threat-section":
                out.extend(self._flatten_threat(entry.get("rulebase", [])))
            else:
                out.append(entry)
        return out

    def exceptions_for_rule(self, rule_uid, package=None, rule_name=None):
        """Match exported exception rulebase docs to a parent threat rule."""
        hits = []
        for exc in self.threat_exceptions:
            if rule_uid and exc.get("rule_uid") == rule_uid:
                hits.append(exc)
                continue
            if (package and rule_name
                    and exc.get("package") == package
                    and exc.get("rule_name") == rule_name):
                hits.append(exc)
        return hits

    def threat_profiles_with_blade_detail(self):
        """Profiles that include IPS/AV/Anti-Bot/TE settings (full enrich)."""
        out = []
        for o in self.objects.get("threat-profile", []):
            if any(k in o for k in ("ips", "anti-bot", "anti-virus", "threat-emulation",
                                    "active-protections-configuration")):
                out.append(o)
        return out

    def _harvest_embedded_objects(self):
        """Index uid+name pairs from object dictionaries embedded in rulebase exports."""
        for sub in ("policy-by-package", "access-layers-shared"):
            base = self.run_dir / sub
            if not base.is_dir():
                continue
            for path in sorted(base.rglob("*.json")):
                doc = load_json(path)
                if not isinstance(doc, dict):
                    continue
                for key in ("objects-dictionary", "object_dictionary"):
                    for obj in doc.get(key) or []:
                        if isinstance(obj, dict):
                            self._index_obj(obj)

    def _harvest_stub_objects(self):
        """Index uid+name pairs nested in gateway/policy JSON (fills export gaps)."""
        paths = [self.run_dir / "gateways-and-servers.json"]
        for sub in ("policy-by-package", "access-layers-shared"):
            base = self.run_dir / sub
            if base.is_dir():
                paths.extend(sorted(base.rglob("*.json")))
        for path in paths:
            self._walk_index_stubs(load_json(path))

    def _walk_index_stubs(self, node):
        if isinstance(node, dict):
            uid, name = node.get("uid"), node.get("name")
            if (
                uid and name
                and isinstance(uid, str) and isinstance(name, str)
                and is_uid(uid)
            ):
                existing = self.by_uid.get(uid)
                if existing is None:
                    self._index_obj({
                        "uid": uid,
                        "name": name,
                        "type": node.get("type", ""),
                    })
                elif not existing.get("name"):
                    existing["name"] = name
            for value in node.values():
                self._walk_index_stubs(value)
        elif isinstance(node, list):
            for item in node:
                self._walk_index_stubs(item)

    def _build_threat_action_hints(self):
        """For custom IPS/TP profiles missing from export, annotate by install-on / layer."""
        policy_targets = "6c488338-8eec-4103-ad21-cd461ac2c476"
        hints = {}
        layer_hints = {}
        for layer in self.threat_layers:
            layer_label = layer.get("layer") or ""
            for rule in layer.get("rules") or []:
                act = rule.get("action")
                if not isinstance(act, str) or not is_uid(act):
                    continue
                if act in SYSTEM_UID_NAMES or self.by_uid.get(act, {}).get("name"):
                    continue
                installs = list(rule.get("install-on") or [])
                gw_names = [
                    self.name_of(u) for u in installs
                    if u and u != policy_targets
                ]
                if gw_names:
                    hints.setdefault(act, set()).update(gw_names)
                elif installs == [policy_targets] or installs == []:
                    layer_hints.setdefault(act, set()).add(layer_label)
        self.threat_action_hints = hints
        self.threat_action_layer_hints = layer_hints

    def _merge_native_where_used(self):
        """Augment inferred where-used with Check Point native where-used when collected."""
        data = load_json(self.run_dir / "objects-where-used.json")
        if not isinstance(data, dict) or not data:
            return
        self.uses_native_where_used = True
        for uid, entry in data.items():
            if not isinstance(entry, dict):
                continue
            for bucket, kind in (("used-directly", "native-direct"), ("used-indirectly", "native-indirect")):
                block = entry.get(bucket) or {}
                for obj in (block.get("objects") or []):
                    if not isinstance(obj, dict):
                        continue
                    ref_name = obj.get("name") or obj.get("type") or "reference"
                    self.where_used[uid].append({
                        "kind": kind,
                        "package": obj.get("domain", {}).get("name", "") if isinstance(obj.get("domain"), dict) else "",
                        "layer": ref_name,
                        "num": obj.get("rule-number", ""),
                        "name": obj.get("type", ""),
                        "field": bucket,
                    })

    def _assess_export(self):
        if audit_export_run is None:
            self.export_audit = {"flags": [], "summary": {}}
            return
        flags, summary = audit_export_run(self.run_dir)
        self.export_audit = {"flags": flags, "summary": summary}
        self.has_object_nat = bool(summary.get("object_nat_present"))

    def _add_used(self, value):
        if isinstance(value, str):
            self.used_uids.add(value)
        elif isinstance(value, list):
            for v in value:
                if isinstance(v, str):
                    self.used_uids.add(v)

    def _compute_used(self):
        rule_fields = ("source", "destination", "service", "vpn", "content", "time", "install-on")
        for layer in self.access_layers:
            for rule in layer["rules"]:
                for fld in rule_fields:
                    self._add_used(rule.get(fld))
                self._add_used(rule.get("action"))
        nat_fields = (
            "original-source",
            "original-destination",
            "original-service",
            "translated-source",
            "translated-destination",
            "translated-service",
            "install-on",
        )
        for nat in self.nat_layers:
            for rule in nat["rules"]:
                for fld in nat_fields:
                    self._add_used(rule.get(fld))
        # Members of a used group are themselves used. Resolve transitively so
        # objects referenced only through a nested group (group-in-group) are not
        # falsely flagged as unreferenced. Iterate to a fixpoint.
        changed = True
        while changed:
            changed = False
            for guid, members in self.member_index.items():
                if guid in self.used_uids:
                    for m in members:
                        if m not in self.used_uids:
                            self.used_uids.add(m)
                            changed = True

    def _build_where_used(self):
        """Reverse-reference index: object uid -> every place it is referenced.
        Each ref: {kind, package, layer, num, name, field}. Covers access rules
        (object-dictionary UIDs), inline NAT rules (uid-or-dict), and group
        membership edges so an object shows the groups that contain it."""
        access_fields = ("source", "destination", "service", "vpn", "content",
                         "time", "install-on")

        def uid_of(val):
            if isinstance(val, str):
                return val
            if isinstance(val, dict):
                return val.get("uid")
            return None

        for layer in self.access_layers:
            pkg = layer.get("package") or ""
            lname = layer.get("layer") or ""
            for rule in layer["rules"]:
                if rule.get("type") != "access-rule":
                    continue
                num = rule.get("rule-number", "")
                rname = rule.get("name", "") or ""
                for fld in access_fields:
                    for v in (rule.get(fld) or []):
                        uid = uid_of(v)
                        if uid:
                            self.where_used[uid].append(
                                {"kind": "access", "package": pkg, "layer": lname,
                                 "num": num, "name": rname, "field": fld})
                act = rule.get("action")
                if isinstance(act, str):
                    self.where_used[act].append(
                        {"kind": "access", "package": pkg, "layer": lname,
                         "num": num, "name": rname, "field": "action"})

        nat_fields = ("original-source", "original-destination", "original-service",
                      "translated-source", "translated-destination",
                      "translated-service", "install-on")
        for nat in self.nat_layers:
            pkg = nat.get("package") or ""
            for i, rule in enumerate(nat["rules"], 1):
                num = rule.get("rule-number", i)
                for fld in nat_fields:
                    val = rule.get(fld)
                    vals = val if isinstance(val, list) else ([val] if val else [])
                    for v in vals:
                        uid = uid_of(v)
                        if uid:
                            self.where_used[uid].append(
                                {"kind": "nat", "package": pkg, "layer": "NAT",
                                 "num": num, "name": "", "field": fld})

        # group membership edges (object -> groups that contain it)
        for guid, members in self.member_index.items():
            for muid in members:
                self.member_of[muid].add(guid)
                self.where_used[muid].append(
                    {"kind": "member", "package": "", "layer": "",
                     "num": "", "name": self.name_of(guid), "field": "group-member"})

    def ref_count(self, uid):
        """Number of rule/NAT/native references (excludes pure membership edges)."""
        return sum(1 for r in self.where_used.get(uid, [])
                   if r["kind"] in ("access", "nat", "native-direct", "native-indirect"))

    # ---------- helpers ----------
    @staticmethod
    def _uid_of(ref):
        if ref is None:
            return None
        if isinstance(ref, dict):
            return ref.get("uid")
        if is_uid(ref):
            return ref
        return None

    def name_of(self, uid):
        if isinstance(uid, dict):
            if uid.get("name"):
                return str(uid["name"]).strip()
            uid = uid.get("uid")
        if not uid:
            return "Any"
        obj = self.by_uid.get(uid)
        if obj:
            return str(obj.get("name", uid)).strip()
        if uid in SYSTEM_UID_NAMES:
            return SYSTEM_UID_NAMES[uid]
        hints = self.threat_action_hints.get(uid)
        if hints:
            return "Threat profile ({})".format(", ".join(sorted(hints)[:4]))
        layer_hints = getattr(self, "threat_action_layer_hints", {}).get(uid)
        if layer_hints:
            return "Threat profile ({})".format(", ".join(sorted(layer_hints)[:2]))
        if is_uid(uid):
            return "⟨{}… not in export⟩".format(uid[:8])
        return str(uid)

    def obj_addr_hint(self, uid):
        """Best-effort IP/CIDR/range for address objects (NAT column enrichment)."""
        uid = self._uid_of(uid)
        if not uid:
            return ""
        obj = self.by_uid.get(uid)
        if not obj:
            return ""
        if obj.get("ipv4-address"):
            return str(obj["ipv4-address"])
        if obj.get("subnet4") is not None:
            ml = obj.get("mask-length4", "")
            return "{}/{}".format(obj.get("subnet4"), ml) if ml != "" else str(obj.get("subnet4"))
        first = obj.get("ipv4-address-first")
        if first:
            last = obj.get("ipv4-address-last", "")
            return "{}-{}".format(first, last) if last else str(first)
        return ""

    @staticmethod
    def nat_translated_addrs(rule, model):
        """Resolved IPv4/CIDR for translated source/destination when available."""
        parts = []
        for label, field in (("src", "translated-source"), ("dst", "translated-destination")):
            hint = model.obj_addr_hint(rule.get(field))
            if hint:
                parts.append("{} {}".format(label, hint))
        return "; ".join(parts)

    @staticmethod
    def nat_rule_brief(rule, model):
        """One-line human summary of what a NAT rule does."""
        meth = (rule.get("method") or "").lower()
        orig = model.name_of(rule.get("original-source"))
        odest = model.name_of(rule.get("original-destination"))
        tsrc = model.name_of(rule.get("translated-source"))
        tdst = model.name_of(rule.get("translated-destination"))
        osvc = model.name_of(rule.get("original-service"))
        tsvc = model.name_of(rule.get("translated-service"))
        orig_is_any = rule.get("original-source") in (None, "", ANY_UID)
        odest_is_any = rule.get("original-destination") in (None, "", ANY_UID)
        svc_note = ""
        if (
            rule.get("original-service") != rule.get("translated-service")
            and tsvc not in ("Original", "Any")
            and osvc not in ("Any",)
        ):
            svc_note = "; svc {}→{}".format(osvc, tsvc)
        addr_note = CheckpointModel.nat_translated_addrs(rule, model)
        if addr_note:
            addr_note = "; " + addr_note
        if meth == "hide":
            if not orig_is_any and odest_is_any:
                return "Hide {} behind {}{}{}".format(orig, tsrc, svc_note, addr_note)
            if orig_is_any and not odest_is_any:
                return "Hide behind {} for dst {}{}{}".format(tsrc, odest, svc_note, addr_note)
            return "Hide NAT{}{}".format(svc_note, addr_note)
        if meth == "static":
            parts = []
            if rule.get("original-source") != rule.get("translated-source"):
                if tsrc not in ("Original", "Any") and orig not in ("Any",):
                    parts.append("src {}→{}".format(orig, tsrc))
            if rule.get("original-destination") != rule.get("translated-destination"):
                if tdst not in ("Original", "Any") and odest not in ("Any",):
                    parts.append("dst {}→{}".format(odest, tdst))
            return "Static NAT" + (": " + "; ".join(parts) if parts else "") + svc_note + addr_note
        if meth == "automatic":
            return "Automatic NAT{}{}".format(svc_note, addr_note)
        return (meth or "NAT") + svc_note + addr_note

    def format_access_role_field(self, value, limit=8):
        """Render users / networks / machines on an access-role (list, sentinel string, or object)."""
        if value is None or value == "":
            return "—"
        if isinstance(value, str):
            low = value.strip().lower()
            if low == "any":
                return "Any"
            if low == "all identified":
                return "All Identified"
            if low == "all unidentified":
                return "All Unidentified"
            if is_uid(value):
                return self.name_of(value)
            return value.strip()
        if isinstance(value, dict):
            return str(value.get("name") or value.get("display-name") or "?")
        if isinstance(value, list):
            parts = []
            for item in value[:limit]:
                if isinstance(item, dict):
                    parts.append(str(item.get("name") or item.get("display-name") or "?"))
                elif isinstance(item, str):
                    parts.append(
                        self.format_access_role_field(item, limit=1)
                        if is_uid(item) else item
                    )
                else:
                    parts.append(str(item))
            if len(value) > limit:
                parts.append("…+{}".format(len(value) - limit))
            return ", ".join(parts) if parts else "—"
        return str(value)

    def names_of(self, uids):
        if not uids:
            return "Any"
        out = [self.name_of(u) for u in uids]
        return ", ".join(out) if out else "Any"

    def is_any(self, uids):
        if not uids:
            return True
        for u in uids:
            if u == ANY_UID:
                return True
            obj = self.by_uid.get(u)
            if obj and (obj.get("type") == "CpmiAnyObject" or obj.get("name") == "Any"):
                return True
        return False

    def layers_by_name(self):
        """One representative layer per logical name (package binding wins over shared copy)."""
        by_name = {}
        for layer in self.access_layers:
            key = str(layer["layer"])
            cur = by_name.get(key)
            if cur is None:
                by_name[key] = layer
            elif layer.get("origin") == "package" and cur.get("origin") != "package":
                by_name[key] = layer
            elif len(layer.get("rules") or []) > len(cur.get("rules") or []):
                by_name[key] = layer
        return list(by_name.values())

    def layers_for_analysis(self):
        """Layers used for shadow/merge/compliance scans — no duplicate shared exports."""
        return self.layers_by_name()

    def catalog_layer_count(self):
        catalog = load_json(self.run_dir / "access-layers.json")
        if isinstance(catalog, list) and catalog:
            return len(catalog)
        return len(self.layers_by_name())

    def unique_access_rule_count(self):
        uids = set()
        for layer in self.layers_by_name():
            for rule in layer.get("rules") or []:
                if rule.get("type") != "access-rule":
                    continue
                uid = rule.get("uid")
                if uid:
                    uids.add(uid)
        if uids:
            return len(uids)
        return sum(
            1 for layer in self.layers_by_name()
            for rule in (layer.get("rules") or [])
            if rule.get("type") == "access-rule"
        )

    def custom_application_count(self):
        return sum(1 for o in self.objects.get("application-site", []) if is_custom_application(o))

    def threat_rule_count(self):
        return sum(len(t["rules"]) for t in self.threat_layers)

    def raw_export_layer_count(self):
        return len(self.access_layers)


# ===================== optimization analysis =====================
def object_value_key(obj):
    t = obj.get("type")
    if t in ("host", "CpmiHostCkp") or (t and t.startswith("Cpmi") and obj.get("ipv4-address")):
        ip = obj.get("ipv4-address")
        return ("ip", ip) if ip else None
    if t == "network":
        if obj.get("subnet4") is not None:
            return ("network", obj.get("subnet4"), obj.get("mask-length4"))
    if t == "address-range":
        f, l = obj.get("ipv4-address-first"), obj.get("ipv4-address-last")
        return ("range", f, l) if f else None
    if t == "service-tcp":
        return ("tcp", obj.get("port"))
    if t == "service-udp":
        return ("udp", obj.get("port"))
    if t == "service-icmp":
        return ("icmp", obj.get("icmp-type"), obj.get("icmp-code"))
    return None


def analyze_duplicates(model):
    buckets = defaultdict(list)
    cats = ("host", "network", "address-range") + SERVICE_CATS
    for cat in cats:
        for obj in model.objects.get(cat, []):
            if (obj.get("domain") or {}).get("name") != SMC_DOMAIN:
                continue
            key = object_value_key(obj)
            if key:
                buckets[key].append(obj)
    dups = []
    for key, objs in buckets.items():
        if len(objs) > 1:
            dups.append((key, sorted(objs, key=lambda o: o.get("name", ""))))
    dups.sort(key=lambda kv: (-len(kv[1]), str(kv[0])))
    return dups


def analyze_unused(model):
    cats = (
        "host", "network", "address-range",
    ) + SERVICE_CATS + (
        "group", "service-group",
    )
    unused = defaultdict(list)
    for cat in cats:
        for obj in model.objects.get(cat, []):
            if (obj.get("domain") or {}).get("name") != SMC_DOMAIN:
                continue
            uid = obj.get("uid")
            if uid and uid not in model.used_uids:
                unused[cat].append(obj)
    for cat in unused:
        unused[cat].sort(key=lambda o: o.get("name", ""))
    return unused


def _field_set(model, rule, field):
    """Return ('ANY',) or frozenset(uids); None if negated (skip)."""
    if rule.get(field + "-negate"):
        return None
    uids = rule.get(field) or []
    if model.is_any(uids):
        return ("ANY",)
    return frozenset(uids)


def _covers(earlier, later):
    if earlier is None or later is None:
        return False
    if earlier == ("ANY",):
        return True
    if later == ("ANY",):
        return False
    return earlier >= later  # superset


def analyze_shadows(model):
    """Per layer: find rules made unreachable/redundant by an earlier rule."""
    findings = []
    for layer in model.layers_for_analysis():
        enabled = []
        for rule in layer["rules"]:
            if rule.get("type") != "access-rule":
                continue
            if not rule.get("enabled", True):
                continue
            src = _field_set(model, rule, "source")
            dst = _field_set(model, rule, "destination")
            svc = _field_set(model, rule, "service")
            action = model.name_of(rule.get("action")) if isinstance(rule.get("action"), str) else "?"
            enabled.append((rule, src, dst, svc, action))

        for i in range(len(enabled)):
            later_rule, lsrc, ldst, lsvc, laction = enabled[i]
            if None in (lsrc, ldst, lsvc):
                continue
            for j in range(i):
                e_rule, esrc, edst, esvc, eaction = enabled[j]
                if None in (esrc, edst, esvc):
                    continue
                if _covers(esrc, lsrc) and _covers(edst, ldst) and _covers(esvc, lsvc):
                    if eaction == laction:
                        kind = "REDUNDANT"
                    else:
                        kind = "SHADOWED"
                    findings.append(
                        {
                            "package": layer["package"],
                            "layer": layer["layer"],
                            "later_no": later_rule.get("rule-number"),
                            "later_name": later_rule.get("name", ""),
                            "later_action": laction,
                            "earlier_no": e_rule.get("rule-number"),
                            "earlier_name": e_rule.get("name", ""),
                            "earlier_action": eaction,
                            "kind": kind,
                        }
                    )
                    break
    findings.sort(key=lambda f: (f["package"], str(f["layer"]), f["later_no"] or 0))
    return findings


def analyze_permissive(model):
    """Any/Any/Any Accept rules and Accept rules with no logging."""
    permissive = []
    no_log = []
    for layer in model.layers_for_analysis():
        for rule in layer["rules"]:
            if rule.get("type") != "access-rule":
                continue
            action = model.name_of(rule.get("action")) if isinstance(rule.get("action"), str) else ""
            if action != "Accept":
                continue
            any_src = model.is_any(rule.get("source"))
            any_dst = model.is_any(rule.get("destination"))
            any_svc = model.is_any(rule.get("service"))
            row = {
                "package": layer["package"],
                "layer": layer["layer"],
                "no": rule.get("rule-number"),
                "name": rule.get("name", ""),
                "enabled": rule.get("enabled", True),
            }
            if any_src and any_dst and any_svc:
                permissive.append(row)
            track = rule.get("track") or {}
            track_type = model.name_of(track.get("type")) if isinstance(track.get("type"), str) else ""
            if track_type in ("None", "", "none"):
                no_log.append(row)
    return permissive, no_log


def _field_repr(model, rule, field):
    """Hashable representation of a rule field incl. negation; 'ANY' aware."""
    neg = bool(rule.get(field + "-negate"))
    uids = rule.get(field) or []
    if model.is_any(uids) and not neg:
        base = "ANY"
    else:
        base = frozenset(uids)
    return (neg, base)


def _action_name(model, rule):
    a = rule.get("action")
    return model.name_of(a) if isinstance(a, str) else "?"


def _is_simple_action(name):
    return (name or "").lower() in ("accept", "drop", "reject")


def analyze_merge(model):
    """
    Find rules that can be consolidated: identical except for ONE dimension.
      - same source+dest+action  -> merge SERVICES
      - same source+service+action -> merge DESTINATIONS
      - same dest+service+action   -> merge SOURCES
    Only enabled simple-action (Accept/Drop/Reject) rules within the same layer.
    """
    results = {"service": [], "destination": [], "source": []}
    dims = (
        ("service", ("source", "destination")),
        ("destination", ("source", "service")),
        ("source", ("destination", "service")),
    )
    for layer in model.layers_for_analysis():
        rules = [r for r in layer["rules"]
                 if r.get("type") == "access-rule" and r.get("enabled", True)
                 and _is_simple_action(_action_name(model, r))]
        for vary, fixed in dims:
            groups = defaultdict(list)
            for r in rules:
                action = _action_name(model, r)
                track = (r.get("track") or {}).get("type")
                key = (
                    _field_repr(model, r, fixed[0]),
                    _field_repr(model, r, fixed[1]),
                    action,
                )
                groups[key].append(r)
            for key, grp in groups.items():
                if len(grp) < 2:
                    continue
                # ensure the varying dimension actually differs
                variants = {_field_repr(model, r, vary) for r in grp}
                if len(variants) < 2:
                    continue
                results[vary].append(
                    {
                        "package": layer["package"],
                        "layer": layer["layer"],
                        "origin": layer["origin"],
                        "action": key[2],
                        "rule_numbers": [r.get("rule-number") for r in grp],
                        "count": len(grp),
                        "fixed": fixed,
                        "sample_fixed": {
                            fixed[0]: model.names_of(grp[0].get(fixed[0])),
                            fixed[1]: model.names_of(grp[0].get(fixed[1])),
                        },
                    }
                )
    for k in results:
        results[k].sort(key=lambda x: (-x["count"], x["package"], str(x["layer"])))
    return results


def _ts_years_ago(posix_ms):
    try:
        return (datetime.now() - datetime.fromtimestamp(posix_ms / 1000.0)).days / 365.25
    except (TypeError, ValueError, OSError):
        return None


def analyze_compliance(model, dup, unused, shadows, permissive, no_log, merge):
    """Map data-driven checks to NIST 800-53, NIST CSF, and CIS control families."""
    # extra checks
    any_service_accept = []
    no_comment = []
    stale = []
    disabled = []
    for layer in model.layers_for_analysis():
        for r in layer["rules"]:
            if r.get("type") != "access-rule":
                continue
            action = _action_name(model, r)
            loc = {"package": layer["package"], "layer": layer["layer"],
                   "no": r.get("rule-number"), "name": r.get("name", "")}
            if not r.get("enabled", True):
                disabled.append(loc)
                continue
            if action == "Accept" and model.is_any(r.get("service")):
                any_service_accept.append(loc)
            if not (r.get("comments") or "").strip():
                no_comment.append(loc)
            mt = ((r.get("meta-info") or {}).get("last-modify-time") or {}).get("posix")
            yrs = _ts_years_ago(mt)
            if yrs is not None and yrs >= 3:
                stale.append(dict(loc, years=round(yrs, 1)))

    unused_total = sum(len(v) for v in unused.values())
    merge_total = sum(len(v) for v in merge.values())
    shadowed = [s for s in shadows if s["kind"] == "SHADOWED"]

    controls = [
        {
            "id": "AC-4 / SC-7", "csf": "PR.AC-5, PR.PT-4", "cis": "CIS CP 3.x",
            "sev": "high", "title": "Overly permissive Any/Any/Any Accept rules",
            "count": len(permissive), "anchor": "permissive", "page": "optimization.html",
            "why": "Any-source/Any-dest/Any-service Accept defeats least-privilege segmentation.",
        },
        {
            "id": "CM-7", "csf": "PR.IP-1, PR.PT-3", "cis": "CIS CP 3.x",
            "sev": "high", "title": "Accept rules permitting Any service",
            "count": len(any_service_accept), "anchor": "anysvc", "page": "compliance.html",
            "why": "Least functionality: restrict to required ports/services.",
        },
        {
            "id": "AU-2 / AU-12", "csf": "DE.AE-3, PR.PT-1", "cis": "CIS CP 5.x",
            "sev": "medium", "title": "Accept rules without logging/tracking",
            "count": len(no_log), "anchor": "nolog", "page": "compliance.html",
            "why": "Permitted traffic must be logged for detection and audit.",
        },
        {
            "id": "CM-6 / SC-7", "csf": "PR.IP-1", "cis": "CIS CP 3.x",
            "sev": "high", "title": "Shadowed (unreachable) rules",
            "count": len(shadowed), "anchor": "shadow", "page": "optimization.html",
            "why": "Dead rules hide intent and cause policy drift; remove or reorder.",
        },
        {
            "id": "CM-7 / CM-6", "csf": "PR.IP-1", "cis": "CIS CP 3.x",
            "sev": "low", "title": "Redundant / mergeable rules",
            "count": merge_total, "anchor": "merge", "page": "simplify.html",
            "why": "Consolidating reduces rulebase size and review burden.",
        },
        {
            "id": "CM-8", "csf": "ID.AM-1, ID.AM-2", "cis": "CIS CP 1.x",
            "sev": "medium", "title": "Unreferenced objects (inventory hygiene)",
            "count": unused_total, "anchor": "unused", "page": "optimization.html",
            "why": "Stale objects bloat the database and obscure real exposure.",
        },
        {
            "id": "CM-8", "csf": "ID.AM-1", "cis": "CIS CP 1.x",
            "sev": "low", "title": "Duplicate objects (same value)",
            "count": len(dup), "anchor": "dup", "page": "optimization.html",
            "why": "One canonical object per value prevents inconsistent edits.",
        },
        {
            "id": "CM-3", "csf": "PR.IP-3", "cis": "CIS CP 1.x",
            "sev": "low", "title": "Rules without change documentation (no comment)",
            "count": len(no_comment), "anchor": "nocomment", "page": "compliance.html",
            "why": "Each rule should reference a change/owner for auditability.",
        },
        {
            "id": "CM-2 / SI-2", "csf": "PR.IP-1", "cis": "CIS CP 1.x",
            "sev": "low", "title": "Stale rules (not modified in 3+ years)",
            "count": len(stale), "anchor": "stale", "page": "compliance.html",
            "why": "Long-unchanged rules should be re-validated against current need.",
        },
        {
            "id": "AC-3", "csf": "PR.AC-4", "cis": "CIS CP 3.x",
            "sev": "low", "title": "Disabled rules left in policy",
            "count": len(disabled), "anchor": "disabled", "page": "compliance.html",
            "why": "Remove disabled rules once obsolete to keep policy clean.",
        },
    ]
    detail = {
        "anysvc": any_service_accept,
        "nolog": no_log,
        "nocomment": no_comment,
        "stale": stale,
        "disabled": disabled,
    }
    return controls, detail


# Curated, high-profile Check Point advisories. Live severity (CVSS) and the
# actively-exploited flag come from NVD + CISA KEV at build time; the curated `sev`
# is only a fallback when we are offline. We cannot read the exact Jumbo Hotfix from
# a management export, so per-gateway status is reported as "verify" (never an
# unbacked "vulnerable") for gateways that meet the advisory's condition.
KNOWN_CVES = [
    {
        "cve": "CVE-2024-24919", "sev": "High (CVSS 7.5/8.6)", "cond": "ra",
        "summary": "Quantum Security Gateway information disclosure — arbitrary file read "
                   "on gateways with IPsec VPN, Remote Access VPN, or Mobile Access enabled.",
        "affected": "R80.40, R81, R81.10, R81.20, R82 (fixed via Jumbo HF / hotfix, May 2024).",
        "action": "Confirm the May-2024 hotfix/JHF is installed on every internet-facing "
                  "gateway running Remote Access / Mobile Access (e.g. Secure_Remote VS).",
    },
    {
        "cve": "CVE-2023-28461", "sev": "High (CVSS 9.8)", "cond": "ra",
        "summary": "Security Gateway RCE via SSL Network Extender / Mobile Access portal.",
        "affected": "R80.20.x–R81.10 with Mobile Access/SNX. Fixed via hotfix.",
        "action": "Verify Mobile Access portals are patched; restrict portal exposure.",
    },
]

# Versions past or near end-of-support (verify on Check Point lifecycle page).
EOL_VERSIONS = {"R77", "R77.10", "R77.20", "R77.30", "R80.10", "R80.20", "R80.30"}


def analyze_versions(model):
    by_version = defaultdict(int)
    gw_rows = []
    cve_review = []
    gw_types = ("simple-gateway", "simple-cluster")
    for gw in model.gateways:
        if not isinstance(gw, dict):
            continue
        t = gw.get("type", "")
        is_gw = ("gateway" in t.lower() or "cluster" in t.lower()
                 or "vsx" in t.lower() or "vs" in t.lower())
        ver = gw.get("version") or "unknown"
        if is_gw and gw.get("version"):
            by_version[ver] += 1
        pol = (gw.get("policy") or {}).get("access-policy-name", "")
        blades = gw.get("network-security-blades") or {}
        vpn_like = any(k for k, v in blades.items()
                       if v and ("vpn" in k.lower() or "mobile" in k.lower()))
        remote_access = pol == "Secure_Remote" or vpn_like
        eol = ver in EOL_VERSIONS
        if is_gw:
            gw_rows.append({
                "name": gw.get("name"), "type": t, "version": ver,
                "policy": pol, "eol": eol, "remote_access": remote_access,
            })
        if remote_access:
            cve_review.append({"name": gw.get("name"), "version": ver, "policy": pol})
    return {
        "by_version": dict(sorted(by_version.items())),
        "gateways": sorted(gw_rows, key=lambda r: str(r["name"])),
        "cve_review": sorted(cve_review, key=lambda r: str(r["name"])),
    }


# HTML rendering — shared theme in core/html_theme.py


def action_tag(name, href=None):
    n = (name or "").lower()
    if n == "accept":
        cls = "t-accept"
    elif n == "drop":
        cls = "t-drop"
    elif n in ("reject",):
        cls = "t-reject"
    elif "layer" in n:
        cls = "t-inner"
    else:
        cls = "t-other"
    tag = '<span class="tag {}">{}</span>'.format(cls, esc(name or "?"))
    if href:
        return '<a href="{}" style="text-decoration:none">{} <span style="font-size:10px;opacity:.7">↗</span></a>'.format(href, tag)
    return tag


def sev_badge(sev):
    cls = {"high": "b-red", "medium": "b-amber", "low": "b-blue"}.get(sev, "b-blue")
    return '<span class="badge {}">{}</span>'.format(cls, esc((sev or "").upper()))


def vpn_anchor(name):
    return "vpn-" + safe_name(name)


def vpn_ike_summary(vpn):
    parts = []
    em = vpn.get("encryption-method")
    if em:
        parts.append(str(em))
    p1 = vpn.get("ike-phase-1") or {}
    if isinstance(p1, dict):
        alg = p1.get("encryption-algorithm")
        dh = p1.get("diffie-hellman-group")
        integrity = p1.get("data-integrity")
        if alg:
            chunk = "P1 {} / {}".format(alg, dh or "?")
            if integrity:
                chunk += " / {}".format(integrity)
            parts.append(chunk)
    p2 = vpn.get("ike-phase-2") or {}
    if isinstance(p2, dict) and p2.get("encryption-algorithm"):
        parts.append("P2 {}".format(p2.get("encryption-algorithm")))
    return " · ".join(parts)


def vpn_peer_kind_label(gw_type):
    """Short device label for VPN member tables."""
    labels = {
        "CpmiVsNetobj": "VSX",
        "CpmiVsClusterNetobj": "VSX cluster",
        "simple-gateway": "Gateway",
        "simple-cluster": "Cluster",
        "interoperable-device": "3rd-party peer",
    }
    return labels.get(gw_type or "", gw_type or "—")


def vpn_routing_label(vpn):
    raw = vpn.get("routing-mode") or vpn.get("vpn-routing")
    if isinstance(raw, dict):
        raw = raw.get("routing-mode") or raw.get("vpn-routing") or ""
    text = str(raw or "").strip()
    mapping = {
        "domain_based": "Domain-based",
        "to center only": "To hub only (star)",
        "center_only": "To hub only (star)",
    }
    return mapping.get(text, text) if text else "—"


def vpn_nat_label(vpn):
    val = vpn.get("disable-nat-on")
    if isinstance(val, dict):
        center = val.get("disable-nat-on-center-gateway")
        sat = val.get("disable-nat-on-satellite-gateway")
        if center and sat:
            return "Disabled on hub + spoke"
        if center:
            return "Disabled on hub"
        if sat:
            return "Disabled on spoke"
        return "—"
    text = str(val or "").strip()
    mapping = {
        "both center and satellite gateways": "Disabled on hub + spoke",
        "center gateways only": "Disabled on hub",
        "satellite gateways only": "Disabled on spoke",
        "none": "NAT enabled",
    }
    return mapping.get(text.lower(), text) if text else "—"


def vpn_permanent_tunnels_label(vpn):
    pt = vpn.get("permanent-tunnels")
    if isinstance(pt, dict):
        raw = str(pt.get("set-permanent-tunnels") or "").strip()
    else:
        raw = str(pt or "").strip()
    mapping = {
        "off": "Off",
        "on all tunnels in the community": "On (all tunnels)",
        "on": "On",
    }
    return mapping.get(raw.lower(), raw) if raw else "—"


def vpn_collect_peers(vpn, topology):
    """Yield (role, gateway dict) for a community."""
    if topology == "meshed":
        for gw in vpn.get("gateways") or []:
            if isinstance(gw, dict):
                yield ("Member", gw)
    elif topology == "star":
        for gw in vpn.get("center-gateways") or []:
            if isinstance(gw, dict):
                yield ("Hub", gw)
        for gw in vpn.get("satellite-gateways") or []:
            if isinstance(gw, dict):
                yield ("Spoke", gw)
    elif topology == "remote":
        for gw in vpn.get("gateways") or []:
            if isinstance(gw, dict):
                yield ("RA gateway", gw)


def vpn_user_groups_label(vpn):
    groups = vpn.get("user-groups") or []
    names = [g.get("name", "?") for g in groups if isinstance(g, dict) and g.get("name")]
    return ", ".join(names) if names else "—"


def build_gateway_topology_index(gateways):
    """Derive cluster / VSX parent relationships from gateways-and-servers.json."""
    vsx_hosts = set()
    for gw in gateways or []:
        if not isinstance(gw, dict):
            continue
        name = gw.get("name")
        if not name:
            continue
        if gw.get("type") in ("CpmiVsxNetobj", "CpmiVsxClusterNetobj"):
            vsx_hosts.add(name)

    child_to_cluster = {}
    cluster_members = {}
    for gw in gateways or []:
        if not isinstance(gw, dict):
            continue
        cname = gw.get("name")
        members = gw.get("cluster-member-names") or []
        if not cname or not members:
            continue
        cluster_members[cname] = list(members)
        for member in members:
            child_to_cluster[member] = cname

    def infer_vsx_parent(gw_name):
        for parent in sorted(vsx_hosts, key=len, reverse=True):
            if gw_name == parent:
                return None
            if gw_name.startswith(parent + "-") or gw_name.startswith(parent + "_"):
                return parent
        return None

    return {
        "vsx_hosts": vsx_hosts,
        "child_to_cluster": child_to_cluster,
        "cluster_members": cluster_members,
        "infer_vsx_parent": infer_vsx_parent,
    }


def gw_deployment_role(gw):
    """Human deployment role from Check Point gateway type."""
    labels = {
        "CpmiGatewayCluster": "Cluster",
        "simple-cluster": "Cluster",
        "cluster-member": "Cluster member",
        "CpmiVsxClusterNetobj": "VSX cluster",
        "CpmiVsxClusterMember": "VSX cluster member",
        "CpmiVsxNetobj": "VSX host",
        "CpmiVsClusterNetobj": "VS cluster",
        "CpmiVsNetobj": "Virtual System",
        "simple-gateway": "Gateway",
        "checkpoint-host": "Mgmt / server",
    }
    return labels.get(gw.get("type", ""), gw.get("type", "") or "—")


def gw_role_badge(role):
    cls = {
        "VSX host": "b-amber",
        "VSX cluster": "b-amber",
        "VSX cluster member": "b-amber",
        "Virtual System": "b-blue",
        "VS cluster": "b-blue",
        "Cluster": "b-red",
        "Cluster member": "b-red",
        "Gateway": "",
    }.get(role, "")
    if cls:
        return '<span class="badge {}">{}</span>'.format(cls, esc(role))
    return esc(role)


def gw_ha_label(gw, topo):
    """HA / virtualization context for one gateway row."""
    t = gw.get("type", "")
    name = gw.get("name", "")
    if t in ("CpmiGatewayCluster", "CpmiVsxClusterNetobj", "simple-cluster", "CpmiVsClusterNetobj"):
        n = len(gw.get("cluster-member-names") or [])
        return "HA cluster ({})".format(n) if n else "HA cluster"
    if t in ("cluster-member", "CpmiVsxClusterMember"):
        return "HA member"
    if t == "CpmiVsNetobj":
        return "VS on VSX"
    if t == "CpmiVsClusterNetobj":
        n = len(gw.get("cluster-member-names") or [])
        return "VS HA ({})".format(n) if n else "VS HA"
    if topo["child_to_cluster"].get(name):
        return "HA member"
    if t == "simple-gateway":
        return "Standalone"
    return "—"


def gw_parent_name(gw, topo):
    """Parent cluster or VSX host name (plain text)."""
    name = gw.get("name", "")
    t = gw.get("type", "")
    parent = topo["child_to_cluster"].get(name)
    if parent:
        return parent
    if t in ("CpmiVsNetobj", "CpmiVsClusterNetobj"):
        return resolve_vsx_platform(gw, topo) or ""
    return ""


def gw_parse_interface(iface, owner=""):
    """Rich interface fields for gateway detail / sign-off (zone, anti-spoof, topology)."""
    if not isinstance(iface, dict):
        return None
    name = iface.get("interface-name") or iface.get("name") or "?"
    ip = (iface.get("ipv4-address") or "").strip()
    topo = iface.get("topology") or iface.get("topology-settings") or {}
    topo_str = ""
    if isinstance(topo, str):
        topo_str = topo.lower()
        topo = {}
    if not isinstance(topo, dict):
        topo = {}
    masklen = _mask_len(iface)
    net = _cidr_network(ip, masklen) if (ip and masklen) else ""
    behind = str(topo.get("ip-address-behind-this-interface") or "").strip()
    if topo.get("leads-to-internet") or topo_str in ("internet", "external"):
        role, topology = "External (Internet)", "Internet"
    elif topo.get("leads-to-dmz") or topo_str == "dmz":
        role, topology = "DMZ", "DMZ"
    else:
        role = "Internal"
        topology = behind if behind else "Internal"
        if behind and behind.lower() in ("not defined", "not-defined"):
            topology = "not defined"
    sz = topo.get("security-zone")
    if isinstance(sz, dict):
        zone = sz.get("name", "") or ""
    elif iface.get("security-zone") is True:
        zone = "enabled"
    else:
        zone = ""
    asp = iface.get("anti-spoofing")
    if asp is None:
        asp = topo.get("anti-spoofing")
    if asp is True:
        anti = "on"
    elif asp is False:
        anti = "off"
    else:
        anti = "—"
    return {
        "owner": owner,
        "name": name,
        "ip": ip,
        "mask": masklen,
        "network": net,
        "role": role,
        "topology": topology,
        "zone": zone,
        "anti_spoofing": anti,
    }


def format_layer_summary(ordered_count, inner_count):
    """Human-readable policy layer count for firewall table."""
    if inner_count:
        return "{} ordered · {} inline".format(ordered_count, inner_count)
    if ordered_count == 1:
        return "1 layer"
    return "{} layers".format(ordered_count)


def gateway_topology_stats(gateways):
    """Aggregate VSX / VS / HA counts for dashboard and firewall summary cards."""
    counts = defaultdict(int)
    for gw in gateways or []:
        if isinstance(gw, dict):
            counts[gw.get("type", "")] += 1
    vsx_hosts = counts["CpmiVsxNetobj"]
    vsx_clusters = counts["CpmiVsxClusterNetobj"]
    vs_instances = counts["CpmiVsNetobj"]
    vs_clusters = counts["CpmiVsClusterNetobj"]
    phy_clusters = counts["CpmiGatewayCluster"] + counts["simple-cluster"]
    ha_members = counts["CpmiVsxClusterMember"] + counts["cluster-member"]
    ha_clusters = phy_clusters + vsx_clusters + vs_clusters
    physical_boxes = (
        counts["CpmiVsxNetobj"] + counts["CpmiVsxClusterMember"]
        + counts["cluster-member"] + counts["simple-gateway"]
    )
    return {
        "vsx_appliances": vsx_hosts + vsx_clusters,
        "vsx_hosts": vsx_hosts,
        "vsx_clusters": vsx_clusters,
        "vsx_platforms": vsx_hosts + vsx_clusters,
        "virtual_systems": vs_instances + vs_clusters,
        "vs_instances": vs_instances,
        "vs_ha_clusters": vs_clusters,
        "phy_clusters": phy_clusters,
        "ha_clusters": ha_clusters,
        "ha_members": ha_members,
        "standalone": counts["simple-gateway"],
        "mgmt_servers": counts["checkpoint-host"],
        "physical_boxes": physical_boxes,
    }


PHYSICAL_GATEWAY_TYPES = frozenset({
    "CpmiVsxNetobj", "CpmiVsxClusterMember", "cluster-member", "simple-gateway",
})

PHYSICAL_ROLE_LABELS = {
    "CpmiVsxNetobj": "VSX appliance (single node)",
    "CpmiVsxClusterMember": "VSX HA cluster member",
    "cluster-member": "HA cluster member",
    "simple-gateway": "Standalone gateway",
}


def resolve_vsx_platform(gw, topo):
    """VSX platform hosting a Virtual System (name prefix or cluster-member-names)."""
    if not isinstance(gw, dict):
        return ""
    if gw.get("type") not in ("CpmiVsNetobj", "CpmiVsClusterNetobj"):
        return ""
    name = gw.get("name", "")
    parent = topo["infer_vsx_parent"](name)
    if parent:
        return parent
    for cm in gw.get("cluster-member-names") or []:
        member = cm.split("_", 1)[0] if "_" in cm else cm
        plat = topo["child_to_cluster"].get(member)
        if plat:
            return plat
    return ""


def build_vs_children_index(gateways, topo):
    """Map VSX platform name -> list of Virtual System object names."""
    idx = defaultdict(list)
    for gw in gateways or []:
        if not isinstance(gw, dict):
            continue
        if gw.get("type") not in ("CpmiVsNetobj", "CpmiVsClusterNetobj"):
            continue
        vname = gw.get("name", "")
        parent = resolve_vsx_platform(gw, topo)
        if parent:
            idx[parent].append(vname)
    for key in idx:
        idx[key] = sorted(set(idx[key]))
    return dict(idx)


def build_physical_inventory(gateways, topo):
    """Physical enforcement nodes only — excludes Virtual Systems and cluster objects."""
    gws = [g for g in (gateways or []) if isinstance(g, dict)]
    vs_children = build_vs_children_index(gws, topo)

    physical_rows = []
    platform_rows = []
    mgmt_rows = []

    for g in sorted(gws, key=lambda x: x.get("name", "").lower()):
        t = g.get("type", "")
        name = g.get("name", "?")
        if t in PHYSICAL_GATEWAY_TYPES:
            ha_parent = topo["child_to_cluster"].get(name, "")
            if t == "CpmiVsxNetobj":
                vsx_platform = name
            elif t == "CpmiVsxClusterMember":
                vsx_platform = ha_parent  # e.g. hq-fw-cluster
            else:
                vsx_platform = ""
            vs_list = vs_children.get(vsx_platform, []) if vsx_platform else []
            physical_rows.append({
                "name": name,
                "type": t,
                "role": PHYSICAL_ROLE_LABELS.get(t, t),
                "ha_cluster": ha_parent if ha_parent and t != "CpmiVsxNetobj" else "",
                "vsx_platform": vsx_platform,
                "vs_count": len(vs_list),
                "hardware": g.get("hardware", ""),
                "version": g.get("version", ""),
                "ip": g.get("ipv4-address", ""),
                "sic": g.get("sic-name", ""),
            })
        elif t == "CpmiVsxClusterNetobj":
            members = list(g.get("cluster-member-names") or [])
            platform_rows.append({
                "name": name,
                "kind": "VSX HA cluster",
                "physical_nodes": members,
                "node_count": len(members),
                "vs_count": len(vs_children.get(name, [])),
                "vs_names": vs_children.get(name, []),
                "hardware": g.get("hardware", ""),
                "version": g.get("version", ""),
            })
        elif t == "CpmiVsxNetobj":
            pass  # already in physical_rows
        elif t == "CpmiGatewayCluster":
            members = list(g.get("cluster-member-names") or [])
            platform_rows.append({
                "name": name,
                "kind": "Physical HA cluster (non-VSX)",
                "physical_nodes": members,
                "node_count": len(members),
                "vs_count": 0,
                "vs_names": [],
                "hardware": g.get("hardware", ""),
                "version": g.get("version", ""),
            })
        elif t == "checkpoint-host":
            mgmt_rows.append({
                "name": name,
                "version": g.get("version", ""),
                "ip": g.get("ipv4-address", ""),
                "sic": g.get("sic-name", ""),
                "hardware": g.get("hardware", ""),
            })

    # Single-node VSX platforms (not already in platform_rows as HA)
    for g in gws:
        if g.get("type") != "CpmiVsxNetobj":
            continue
        name = g.get("name", "?")
        platform_rows.append({
            "name": name,
            "kind": "VSX appliance (single node)",
            "physical_nodes": [name],
            "node_count": 1,
            "vs_count": len(vs_children.get(name, [])),
            "vs_names": vs_children.get(name, []),
            "hardware": g.get("hardware", ""),
            "version": g.get("version", ""),
        })

    platform_rows.sort(key=lambda r: r["name"].lower())
    serial_present = sum(1 for r in physical_rows + mgmt_rows if r.get("sic"))

    return {
        "physical_rows": physical_rows,
        "platform_rows": platform_rows,
        "mgmt_rows": mgmt_rows,
        "vs_children": vs_children,
        "stats": {
            "physical_boxes": len(physical_rows),
            "vsx_platforms": sum(1 for r in platform_rows if "VSX" in r["kind"]),
            "vs_total": sum(len(v) for v in vs_children.values()),
            "mgmt_servers": len(mgmt_rows),
            "serial_present": serial_present,
        },
    }


def gw_policy_name(gw):
    """Access policy package installed on a gateway or VS."""
    if not isinstance(gw, dict):
        return ""
    return (gw.get("policy") or {}).get("access-policy-name", "") or ""


def vs_function_hint(vs_name):
    """Human role for a Virtual System name (heuristic from naming convention)."""
    n = (vs_name or "").lower()
    if "switch" in n:
        return "Internal switching (no firewall policy)"
    if "external" in n:
        return "Internet / DMZ face"
    if "internal" in n:
        return "Internal network"
    if "labs" in n or "-lab" in n:
        return "Lab environment"
    if "production" in n or "-prod" in n:
        return "Production"
    if "oci" in n:
        return "OCI cloud"
    if "securecloud" in n or (n.endswith("-sc") and "switch" not in n):
        return "Engineering / secure cloud"
    if "vpn" in n:
        return "Remote access / VPN"
    if "intrazone" in n:
        return "Intra-zone policy"
    return ""


def _vs_tree_sort_key(name):
    """Policy VS objects first; L2 switch VS objects last."""
    return (1 if "switch" in (name or "").lower() else 0, (name or "").lower())


def _platform_tree_sort_key(tree):
    kind = tree.get("kind", "")
    if kind == "VSX HA cluster":
        return (0, tree["name"].lower())
    if kind == "VSX appliance (single node)":
        return (1, tree["name"].lower())
    return (2, tree["name"].lower())


def build_platform_trees(gateways, inv):
    """Enrich platform_rows into physical → virtual tree structures for HTML."""
    by_name = {
        g.get("name"): g for g in (gateways or [])
        if isinstance(g, dict) and g.get("name")
    }
    trees = []
    for row in inv.get("platform_rows") or []:
        plat_gw = by_name.get(row["name"], {})
        physical = []
        for pname in row.get("physical_nodes") or []:
            pg = by_name.get(pname, {})
            physical.append({
                "name": pname,
                "ip": pg.get("ipv4-address", ""),
                "policy": gw_policy_name(pg),
                "hardware": pg.get("hardware", ""),
                "version": pg.get("version", ""),
            })
        virtual = []
        for vname in sorted(row.get("vs_names") or [], key=_vs_tree_sort_key):
            vg = by_name.get(vname, {})
            pol = gw_policy_name(vg)
            hint = vs_function_hint(vname)
            if not pol and hint.startswith("Internal switching"):
                pol_display = "— (no access policy)"
            else:
                pol_display = pol or "—"
            vs_ha = vg.get("type") == "CpmiVsClusterNetobj"
            virtual.append({
                "name": vname,
                "ip": vg.get("ipv4-address", ""),
                "policy": pol,
                "policy_display": pol_display,
                "hint": hint,
                "vs_ha": vs_ha,
                "member_count": len(vg.get("cluster-member-names") or []) if vs_ha else 0,
            })
        trees.append({
            "name": row["name"],
            "kind": row["kind"],
            "hardware": row.get("hardware") or plat_gw.get("hardware", ""),
            "version": row.get("version") or plat_gw.get("version", ""),
            "cluster_ip": plat_gw.get("ipv4-address", ""),
            "platform_policy": gw_policy_name(plat_gw),
            "physical": physical,
            "virtual": virtual,
            "vs_count": len(virtual),
            "is_vsx": "VSX" in row.get("kind", ""),
        })
    trees.sort(key=_platform_tree_sort_key)
    standalone = [r for r in inv.get("physical_rows") or [] if r.get("type") == "simple-gateway"]
    return trees, standalone


def rule_install_on_names(rule, model):
    """Resolve install-on column to display names and UIDs."""
    names = []
    uids = set()
    for ref in rule.get("install-on") or []:
        uid = model._uid_of(ref)
        if uid:
            uids.add(uid)
        names.append(model.name_of(ref))
    return names, uids


def rule_applies_to_gateway(rule, gw, pkg_name, model, topo=None):
    """True when rule installs on this gateway (direct, cluster parent, or Policy Targets)."""
    if not isinstance(gw, dict) or not gw.get("name"):
        return False
    gw_name = gw["name"].lower()
    gw_uid = gw.get("uid") or ""
    names, uids = rule_install_on_names(rule, model)
    if gw_uid and gw_uid in uids:
        return True
    for n in names:
        nl = (n or "").lower()
        if nl == gw_name:
            return True
        if nl == "policy targets" and pkg_name:
            return True
    if topo:
        parent = (topo.get("child_to_cluster") or {}).get(gw.get("name", ""))
        if parent and parent.lower() in {(n or "").lower() for n in names}:
            return True
    return False


def count_applicable_access_rules(layers, inner_layers, gw, pkg_name, model, topo):
    """Count access rules in a package that apply to one gateway."""
    total = 0
    applicable = 0
    for layer in layers + inner_layers:
        for rule in layer.get("rules") or []:
            if rule.get("type") != "access-rule":
                continue
            total += 1
            if rule_applies_to_gateway(rule, gw, pkg_name, model, topo):
                applicable += 1
    return applicable, total


def filter_access_layers_for_gateway(layers, inner_layers, gw, pkg_name, model, topo):
    """Split package layers into applicable vs other-target rule lists."""
    app_layers = []
    other_layers = []
    for layer, is_inner in [(l, False) for l in layers] + [(l, True) for l in inner_layers]:
        app_rules = []
        oth_rules = []
        for rule in layer.get("rules") or []:
            if rule.get("type") != "access-rule":
                continue
            if rule_applies_to_gateway(rule, gw, pkg_name, model, topo):
                app_rules.append(rule)
            else:
                oth_rules.append(rule)
        if app_rules:
            app_layers.append(({**layer, "rules": app_rules}, is_inner))
        if oth_rules:
            other_layers.append(({**layer, "rules": oth_rules}, is_inner))
    return app_layers, other_layers


def filter_nat_rules_for_gateway(nat_rules, gw, pkg_name, model, topo):
    """NAT rules that install on this gateway."""
    app, other = [], []
    for rule in nat_rules or []:
        if rule.get("type") != "nat-rule":
            continue
        if rule_applies_to_gateway(rule, gw, pkg_name, model, topo):
            app.append(rule)
        else:
            other.append(rule)
    return app, other


class HtmlSite:
    def __init__(self, model, out_dir, browse_only=True):
        self.model = model
        self.out = Path(out_dir)
        self.browse_only = browse_only
        self.nav_links = []
        self._layer_url_map = None

    # ---------- object popup helpers ----------

    def _gateway_topology(self):
        if not hasattr(self, "_gw_topo_cache"):
            self._gw_topo_cache = build_gateway_topology_index(self.model.gateways)
        return self._gw_topo_cache

    def _gw_parent_link(self, gw):
        topo = self._gateway_topology()
        parent = gw_parent_name(gw, topo)
        if parent:
            return self._gw_link(parent)
        return '<span class="muted">—</span>'

    def _gw_topology_detail_html(self, gw):
        """Deployment stack note for per-gateway detail pages."""
        topo = self._gateway_topology()
        role = gw_deployment_role(gw)
        ha = gw_ha_label(gw, topo)
        parent = gw_parent_name(gw, topo)
        members = gw.get("cluster-member-names") or []
        lines = ['<b>Role</b>: {} · <b>HA</b>: {}'.format(esc(role), esc(ha))]
        if parent:
            lines.append('<b>Parent</b>: {}'.format(self._gw_link(parent)))
        hw = gw.get("hardware")
        if hw:
            lines.append('<b>Hardware</b>: {}'.format(esc(str(hw))))
        if members:
            shown = ", ".join(esc(m) for m in members[:6])
            if len(members) > 6:
                shown += " … +{}".format(len(members) - 6)
            lines.append('<b>Cluster / VS members</b>: <span class="mono">{}</span>'.format(shown))
        return "<br>".join(lines)

    def _get_layer_url_map(self):
        """uid of an access-layer → URL relative to html_view root."""
        if self._layer_url_map is not None:
            return self._layer_url_map
        m = self.model
        name_to_layer = {}
        for l in m.access_layers:
            name = str(l["layer"])
            if name not in name_to_layer:
                name_to_layer[name] = l
        result = {}
        for uid, obj in m.by_uid.items():
            if not isinstance(obj, dict) or obj.get("type") != "access-layer":
                continue
            lname = obj.get("name", "")
            l = name_to_layer.get(lname)
            if not l:
                continue
            if l["origin"] == "package":
                url = "layers/{}__{}.html".format(safe_name(l["package"]), safe_name(lname))
            else:
                url = "layers/shared__{}.html".format(safe_name(lname))
            result[uid] = url
        self._layer_url_map = result
        return result

    def _reachable_inner_layers(self, layers):
        """Every distinct inner/inline layer reachable from `layers`, resolved
        recursively. A rule's `inline-layer` is a UID -> resolve via by_uid to a
        layer name -> match a loaded layer. This is what makes a 1-ordered-layer
        package actually show its 10 inner layers."""
        m = self.model
        name_to_layer = {}
        for l in m.access_layers:
            key = str(l["layer"])
            cur = name_to_layer.get(key)
            if cur is None:
                name_to_layer[key] = l
            elif l.get("origin") == "package" and cur.get("origin") != "package":
                name_to_layer[key] = l
            elif len(l.get("rules") or []) > len(cur.get("rules") or []):
                name_to_layer[key] = l
        seen = {str(l["layer"]) for l in layers}
        out = []
        queue = list(layers)
        while queue:
            cur = queue.pop(0)
            for rule in cur.get("rules", []):
                if not isinstance(rule, dict):
                    continue
                uid = rule.get("inline-layer")
                if not uid:
                    continue
                obj = m.by_uid.get(uid)
                lname = obj.get("name") if isinstance(obj, dict) else None
                if not lname and not is_uid(uid):
                    lname = uid  # some exports store the name directly
                target = name_to_layer.get(lname) if lname else None
                if not target or str(target["layer"]) in seen:
                    continue
                seen.add(str(target["layer"]))
                out.append(target)
                queue.append(target)
        return out

    def _inline_href(self, rule, page_subdir):
        """Return an href for an Inner Layer action's sub-layer, or None."""
        uid = rule.get("inline-layer")
        if not uid:
            return None
        url = self._get_layer_url_map().get(uid)
        if not url:
            return None
        # Convert root-relative URL to page-relative
        return os.path.relpath(url, page_subdir).replace("\\", "/")

    def _obj_entry(self, uid):
        """Serialize one object for the OBJ popup script."""
        m = self.model
        obj = m.by_uid.get(uid)
        if not obj or not isinstance(obj, dict):
            return None
        t = obj.get("type", "")
        data = {"name": obj.get("name", uid), "type": t}
        ip = obj.get("ipv4-address")
        if ip:
            data["ip"] = ip
        if t == "network":
            data["subnet"] = obj.get("subnet4", "")
            data["mask"] = obj.get("mask-length4", "")
        if t == "address-range":
            data["first"] = obj.get("ipv4-address-first", "")
            data["last"] = obj.get("ipv4-address-last", "")
        if t in ("service-tcp", "service-udp"):
            data["proto"] = "TCP" if t == "service-tcp" else "UDP"
            data["port"] = obj.get("port", "")
        if t == "service-icmp":
            data["proto"] = "ICMP"
            data["port"] = "type {}/code {}".format(
                obj.get("icmp-type", ""), obj.get("icmp-code", ""))
        members = m.member_index.get(uid, set())
        if members:
            data["members"] = sorted(m.name_of(muid) for muid in members)
        return data

    def _build_obj_data(self, rules, rule_type="access-rule"):
        """Build JSON-serialisable dict of objects referenced by a list of rules."""
        m = self.model
        all_uids = set()
        if rule_type == "access-rule":
            fields = ("source", "destination", "service", "install-on", "content", "time")
            for rule in rules:
                if rule.get("type") != "access-rule":
                    continue
                for fld in fields:
                    for uid in (rule.get(fld) or []):
                        if isinstance(uid, str):
                            all_uids.add(uid)
                action = rule.get("action")
                if isinstance(action, str):
                    all_uids.add(action)
        else:
            nat_fields = (
                "original-source", "original-destination", "original-service",
                "translated-source", "translated-destination", "translated-service",
            )
            for rule in rules:
                if rule.get("type") != "nat-rule":
                    continue
                for fld in nat_fields:
                    uid = rule.get(fld)
                    if isinstance(uid, str):
                        all_uids.add(uid)
                for uid in (rule.get("install-on") or []):
                    if isinstance(uid, str):
                        all_uids.add(uid)
        for uid in list(all_uids):
            for muid in m.member_index.get(uid, set()):
                all_uids.add(muid)

        result = {}
        for uid in all_uids:
            data = self._obj_entry(uid)
            if data:
                result[uid] = data
        return result

    def _uid_spans(self, uids, negate=False):
        """Render a list of UIDs as clickable .obj spans (or plain 'Any')."""
        ANY = "97aeb369-9aea-11d5-bd16-0090272ccb30"
        if not uids or (len(uids) == 1 and uids[0] == ANY):
            return "Any"
        parts = []
        for uid in uids:
            if uid == ANY:
                parts.append("Any")
            else:
                parts.append(self._obj_span(uid))
        text = ", ".join(parts)
        if negate:
            text = "<em>NOT</em> " + text
        return text

    def _obj_span(self, ref, show_addr=False):
        """Single clickable object reference; optional IP/CIDR hint for NAT."""
        uid = self.model._uid_of(ref)
        if not uid:
            return esc(str(ref or "Any"))
        name = self.model.name_of(uid)
        hint = self.model.obj_addr_hint(uid) if show_addr else ""
        label = esc(name)
        if hint and hint not in name:
            label += ' <span class="muted">({})</span>'.format(esc(hint))
        return '<span class="obj" onclick="showObj(\'{}\')">{}</span>'.format(uid, label)

    def _nat_field(self, ref):
        return self._obj_span(ref, show_addr=True)

    def write_assets(self):
        (self.out / "assets").mkdir(parents=True, exist_ok=True)
        (self.out / "assets" / "style.css").write_text(CSS, encoding="utf-8")
        (self.out / "assets" / "app.js").write_text(JS, encoding="utf-8")
        # Compute a version tag from the CSS/JS content hash so browsers always fetch fresh assets
        import hashlib
        self._asset_ver = hashlib.md5((CSS + JS).encode()).hexdigest()[:8]

    def page(self, rel_path, title, body, depth=0, obj_data=None):
        prefix = "../" * depth
        nav = self._nav(prefix, rel_path)
        obj_script = ""
        if obj_data is not None:
            obj_script = "<script>var OBJ={};</script>".format(json.dumps(obj_data, ensure_ascii=False))
        ver = getattr(self, "_asset_ver", "1")
        ver_badge = '<div class="viewer-version" title="HTML report builder">v{}</div>'.format(esc(__version__))
        doc = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {suffix}</title>
<link rel="stylesheet" href="{p}assets/style.css?v={ver}"></head>
<body class="{theme}">{ver_badge}<div class="layout">{nav}<div class="main">{body}</div></div>
<div id="opop"></div>
{obj_script}
<script src="{p}assets/app.js?v={ver}"></script></body></html>""".format(
            title=esc(title), suffix=esc(vendor("checkpoint")["title_suffix"]), theme=vendor("checkpoint")["theme_class"], p=prefix, nav=nav, body=body, obj_script=obj_script, ver=ver, ver_badge=ver_badge
        )
        full = self.out / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(doc, encoding="utf-8")

    def _nav(self, prefix, current):
        items = [
            ("group", "Overview"),
            ("index.html", "Dashboard"),
            ("firewall.html", "Firewall View"),
            ("physical.html", "Physical Appliances"),
            ("coverage.html", "Export Coverage"),
            ("optimization.html", "Optimization"),
            ("simplify.html", "Simplify & Merge"),
            ("relationships.html", "Relationships (Where-Used)"),
            ("compliance.html", "Compliance (NIST/CIS)"),
            ("risk.html", "Versions & CVE"),
            ("group", "Connectivity"),
            ("vpn.html", "VPN Communities"),
            ("group", "Inventory"),
            ("gateways.html", "Gateways & Servers"),
            ("interfaces.html", "Interfaces / IPs"),
            ("hosts.html", "Hosts"),
            ("networks.html", "Networks"),
            ("ranges.html", "Address Ranges"),
            ("dns-domains.html", "DNS Domains"),
            ("groups.html", "Groups"),
            ("services.html", "Services"),
            ("service-groups.html", "Service Groups"),
            ("applications.html", "Applications & URL"),
            ("access-roles.html", "Access Roles"),
            ("users.html", "Users & Groups"),
            ("times.html", "Time Objects"),
            ("zones.html", "Security Zones"),
            ("dynamic.html", "Dynamic Objects"),
            ("group", "Policy"),
            ("packages.html", "Packages & Layers"),
            ("global-properties.html", "Global Properties & Implied Rules"),
            ("nat.html", "NAT Rules"),
            ("threat.html", "Threat Prevention"),
            ("threat-profiles.html", "Threat Profiles"),
            ("https.html", "HTTPS Inspection"),
        ]
        logo = (
            '<svg class="brand-mark" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">'
            '<defs><linearGradient id="cpg" x1="0" y1="0" x2="32" y2="32" gradientUnits="userSpaceOnUse">'
            '<stop stop-color="#ff2e74"/><stop offset="1" stop-color="#e6004d"/>'
            '</linearGradient></defs>'
            '<path d="M16 3.5l10.5 4v7.1c0 6.9-4.5 11.1-10.5 13.4C10 25.7 5.5 21.5 5.5 14.6V7.5z" '
            'stroke="url(#cpg)" stroke-width="1.6" stroke-linejoin="round" fill="rgba(230,0,77,.10)"/>'
            '<path d="M10 11.5h12M10 16h12M10 20.5h12M14 11.5v4.5M18.5 11.5v4.5M12 16v4.5M16 16v4.5M20 16v4.5" '
            'stroke="url(#cpg)" stroke-width="1.5" stroke-linecap="round"/>'
            '</svg>'
        )
        out = ['<div class="nav">',
               '<div class="brand">' + logo +
               '<div><div class="brand-name">Net<span class="brand-accent">Converter</span></div>'
               '<div class="brand-tag"><span class="vendor-chip">Check Point</span> Read-only browser</div></div></div>',
               '<div class="sub">{}</div>'.format(esc(self.model.run_dir.name))]
        for href, label in items:
            if self.browse_only and href in _ANALYSIS_NAV:
                continue
            if href == "group":
                out.append('<div class="group">{}</div>'.format(esc(label)))
                continue
            active = "active" if href == current else ""
            out.append('<a class="{}" href="{}{}">{}</a>'.format(active, prefix, href, esc(label)))
        out.append('<div class="nav-foot">ValeronLabs LLC<br><a href="https://netconverter.ai/" target="_blank" rel="noopener">netconverter.ai</a></div>')
        out.append("</div>")
        return "".join(out)

    def searchbox(self, target, count_id):
        return ('<input class="search" placeholder="Filter rows…" '
                'oninput="filterTable(this)" data-target="{}" data-count="{}">'
                '<div class="meta"><span id="{}"></span></div>').format(target, count_id, count_id)

    def inventory_toolbar(self, prefix, table_id, total, csv_filename, placeholder="Filter rows…",
                          role_options=None, extra_controls="", show_hint=True):
        role_html = ""
        if role_options:
            opts = ['<option value="">All roles</option>']
            for role in role_options:
                opts.append('<option value="{}">{}</option>'.format(esc(role), esc(role)))
            role_html = (
                '<label>Role <select id="{}-role">{}</select></label>'.format(
                    prefix, "".join(opts))
            )
        hint = (
            '<p class="table-hint">Click any <b>column header</b> to sort (▲▼). '
            'Type to filter like Excel; visible rows export to CSV.</p>'
            if show_hint else ""
        )
        return (
            hint
            + '<div class="filterbar">'
            '<input class="search" id="{p}-filter" type="search" placeholder="{ph}">'
            '{role}{extra}'
            '<button type="button" class="vbtn" onclick="exportTableCSV(\'{tid}\',\'{csv}\')">'
            'Export CSV</button>'
            '<span class="meta" style="margin-left:auto"><span id="{p}-cnt">{total}</span> shown</span>'
            '</div>'
        ).format(
            p=prefix, ph=esc(placeholder), role=role_html, extra=extra_controls,
            tid=table_id, csv=esc(csv_filename), total=total,
        )

    def inventory_table_section(self, prefix, table_id, csv_filename, total, placeholder,
                                header_html, row_html_list, extra_controls="", selects=None,
                                checks=None, show_hint=True):
        """Sortable inventory table with filter bar and CSV export."""
        parts = [
            self.inventory_toolbar(
                prefix, table_id, total, csv_filename, placeholder=placeholder,
                extra_controls=extra_controls, show_hint=show_hint,
            ),
            '<div class="table-wrap"><table id="{}"><thead><tr>{}</tr></thead><tbody>'.format(
                table_id, header_html),
        ]
        parts.extend(row_html_list)
        parts.append('</tbody></table></div>')
        parts.append(self.inv_filter_script(prefix, table_id, selects=selects, checks=checks))
        return "".join(parts)

    def inv_filter_script(self, prefix, table_id, selects=None, checks=None):
        cfg = {
            "tableId": table_id,
            "filterId": "{}-filter".format(prefix),
            "countId": "{}-cnt".format(prefix),
            "selects": selects or [],
            "checks": checks or [],
        }
        return (
            '<script>window.INV_FILTERS=window.INV_FILTERS||[];'
            'INV_FILTERS.push({});</script>'
        ).format(json.dumps(cfg, ensure_ascii=False))

    def searchbox_blocks(self, target, count_id):
        return ('<input class="search" placeholder="Filter platforms…" '
                'oninput="filterBlocks(this)" data-target="{}" data-count="{}">'
                '<div class="meta"><span id="{}"></span></div>').format(target, count_id, count_id)

    def _render_platform_stack(self, tree):
        """One VSX platform or HA cluster as physical → virtual tree."""
        meta_bits = []
        if tree.get("cluster_ip"):
            meta_bits.append("Cluster IP {}".format(esc(tree["cluster_ip"])))
        if tree.get("version"):
            meta_bits.append(esc(tree["version"]))
        if tree.get("hardware"):
            meta_bits.append(esc(tree["hardware"]))
        if tree.get("platform_policy"):
            meta_bits.append("platform policy: {}".format(esc(tree["platform_policy"])))
        meta = " · ".join(meta_bits) if meta_bits else "—"

        parts = [
            '<div class="plat-stack">',
            '<div class="plat-head">',
            '<div class="plat-title">{} <span class="badge b-amber">{}</span></div>'.format(
                self._gw_link(tree["name"]), esc(tree["kind"])),
            '<div class="plat-meta">{}</div>'.format(meta),
            '</div><div class="plat-body">',
        ]

        if tree.get("physical"):
            parts.append('<div class="plat-section-label">Physical</div>')
            for node in tree["physical"]:
                ip = esc(node.get("ip") or "—")
                parts.append(
                    '<div class="plat-row physical">'
                    '<div class="plat-row-name">{}</div>'
                    '<div class="plat-row-ip">{}</div>'
                    '</div>'.format(self._gw_link(node["name"]), ip)
                )

        if tree.get("virtual"):
            parts.append('<div class="plat-section-label">Virtual (policy enforcement)</div>')
            for vs in tree["virtual"]:
                name_cell = self._gw_link(vs["name"])
                if vs.get("vs_ha") and vs.get("member_count"):
                    name_cell += ' <span class="badge b-blue">VS HA ({})</span>'.format(
                        vs["member_count"])
                pol = esc(vs.get("policy_display") or "—")
                hint = esc(vs.get("hint") or "")
                ip = esc(vs.get("ip") or "—")
                name_cell += '<span class="plat-arrow">→</span> {}'.format(pol)
                parts.append(
                    '<div class="plat-row virtual">'
                    '<div class="plat-row-name">{}</div>'
                    '<div class="plat-row-ip">{}</div>'
                    '<div class="plat-row-hint">{}</div>'
                    '</div>'.format(name_cell, ip, hint)
                )
        elif not tree.get("is_vsx") and tree.get("platform_policy"):
            parts.append(
                '<div class="plat-section-label">Policy</div>'
                '<div class="plat-row">'
                '<div class="plat-row-name">Cluster policy <span class="plat-arrow">→</span> {}</div>'
                '<div class="plat-row-hint">No VSX — policy on cluster</div>'
                '</div>'.format(esc(tree["platform_policy"]))
            )

        parts.append('</div></div>')
        return "".join(parts)

    def _gateway_names(self):
        if not hasattr(self, "_gw_name_cache"):
            self._gw_name_cache = {g.get("name") for g in self.model.gateways if isinstance(g, dict)}
        return self._gw_name_cache

    def _gw_link(self, name, depth=0):
        prefix = "../" * depth
        if name in self._gateway_names():
            return '<a href="{}{}">{}</a>'.format(prefix, "gateways/{}.html".format(safe_name(name)), esc(name))
        return esc(name)

    def _gw_member_line(self, gw, depth=0):
        if not isinstance(gw, dict):
            return esc(str(gw))
        name = gw.get("name", "?")
        ip = gw.get("ipv4-address", "")
        typ = gw.get("type", "")
        line = self._gw_link(name, depth)
        if ip:
            line += " <span class='mono'>({})</span>".format(esc(ip))
        if typ:
            line += " <span class='mono'>[{}]</span>".format(esc(typ))
        return line

    def _gw_iface_sublist(self, gw):
        rows = []
        for iface in gw.get("interfaces") or []:
            if not isinstance(iface, dict):
                continue
            iname = iface.get("interface-name") or iface.get("name", "")
            ip = iface.get("ipv4-address", "")
            if iname or ip:
                rows.append("<li><span class='mono'>{}</span> ({})</li>".format(
                    esc(iname or "?"), esc(ip or "?")))
        return rows

    def _gw_by_name(self):
        if not hasattr(self, "_gw_by_name_cache"):
            self._gw_by_name_cache = {
                g.get("name"): g for g in self.model.gateways
                if isinstance(g, dict) and g.get("name")
            }
        return self._gw_by_name_cache

    def _gw_policy_counts(self, gw, pkg_layers, topo):
        """Applicable vs total access rules for one gateway's installed package."""
        pol = (gw.get("policy") or {}).get("access-policy-name", "")
        if not pol:
            return 0, 0, pol, [], []
        layers = pkg_layers.get(pol, [])
        inner = self._reachable_inner_layers(layers)
        app, total = count_applicable_access_rules(
            layers, inner, gw, pol, self.model, topo)
        return app, total, pol, layers, inner

    def _render_access_layers_tables(self, layer_pairs, page_subdir, id_prefix):
        """Render access layer rule tables from [(layer_dict, is_inner), ...]."""
        m = self.model
        parts = []
        for layer, is_inner in layer_pairs:
            ly_id = "{}_{}".format(id_prefix, safe_name(layer["layer"]))
            tag = ' <span class="tag t-inner">inner layer</span>' if is_inner else ''
            parts.append(
                '<div style="margin:14px 0 4px;font-size:13px;font-weight:600;color:#9aa7c0">'
                '{}{} <span class="count">({} rules)</span></div>'.format(
                    esc(layer["layer"]), tag, len(layer["rules"])))
            parts.append(self.searchbox(ly_id, ly_id + "_cnt"))
            parts.append(
                '<table id="{}"><thead><tr><th>#</th><th>Name</th><th>Source</th>'
                '<th>Destination</th><th>Service</th><th>Action</th>'
                '<th>Track</th><th>Install On</th><th>Comments</th>'
                '</tr></thead><tbody>'.format(ly_id))
            for rule in layer["rules"]:
                if rule.get("type") != "access-rule":
                    continue
                enabled = rule.get("enabled", True)
                action = m.name_of(rule.get("action")) if isinstance(rule.get("action"), str) else "?"
                track = rule.get("track") or {}
                track_name = m.name_of(track.get("type")) if isinstance(track.get("type"), str) else ""
                ihref = self._inline_href(rule, page_subdir)
                cls = "" if enabled else " class='disabled'"
                parts.append(
                    "<tr{cls}><td>{n}</td><td>{nm}</td><td>{src}</td><td>{dst}</td>"
                    "<td>{svc}</td><td>{act}</td><td>{trk}</td><td>{ion}</td>"
                    "<td>{cmt}</td></tr>".format(
                        cls=cls, n=esc(rule.get("rule-number", "")), nm=esc(rule.get("name", "")),
                        src=self._uid_spans(rule.get("source"), rule.get("source-negate")),
                        dst=self._uid_spans(rule.get("destination"), rule.get("destination-negate")),
                        svc=self._uid_spans(rule.get("service"), rule.get("service-negate")),
                        act=action_tag(action, href=ihref), trk=esc(track_name),
                        ion=self._uid_spans(rule.get("install-on")),
                        cmt=esc((rule.get("comments") or "")[:120]),
                    )
                )
            parts.append('</tbody></table>')
        return "".join(parts)

    def _render_fw_hierarchy_node(self, gw, pkg_layers, topo, level_label):
        """One hierarchy level: interfaces, package, rule counts, drill-down link."""
        if not gw:
            return ""
        app, total, pkg, _layers, _inner = self._gw_policy_counts(gw, pkg_layers, topo)
        ifaces = gw.get("interfaces") or []
        rel = "gateways/{}.html".format(safe_name(gw.get("name", "")))
        rule_txt = (
            "<span class='good'>{} applicable</span> / {} in package".format(app, total)
            if pkg and total else ("<span class='muted'>no access policy</span>" if not pkg else "—")
        )
        iface_items = self._gw_iface_sublist(gw)
        iface_block = (
            "<ul style='margin:6px 0 0 16px;padding:0'>{}</ul>".format("".join(iface_items[:8]))
            if iface_items else "<span class='muted'>—</span>"
        )
        if len(iface_items) > 8:
            iface_block += " <span class='muted'>… +{} more on detail page</span>".format(
                len(iface_items) - 8)
        return (
            '<div class="fw-node">'
            '<div><span class="fw-lbl">{}</span>{}</div>'.format(
                esc(level_label), self._gw_link(gw.get("name", ""), depth=0))
            + '<div class="fw-node-meta">'
            + "Package: <span class='mono'>{}</span> · Interfaces: {} · Rules: {}".format(
                esc(pkg or "—"), len(ifaces), rule_txt)
            + '</div>'
            + '<div class="fw-node-meta">{}</div>'.format(iface_block)
            + '<div class="fw-node-actions"><a href="{}">Open full detail →</a></div>'
            + '</div>'
        )

    def _render_firewall_hierarchy(self, trees, pkg_layers, topo):
        """Top-down firewall tree: cluster → physical → VSX0 → virtual."""
        by_name = self._gw_by_name()
        parts = ['<div class="fw-hierarchies" id="fw-hierarchies">']
        for tree in trees:
            plat_id = "fw-plat-{}".format(safe_name(tree["name"]))
            plat_gw = by_name.get(tree["name"], {})
            vs_count = len(tree.get("virtual") or [])
            phys_count = len(tree.get("physical") or [])
            summary = "{} · {} physical · {} virtual".format(
                tree.get("kind", ""), phys_count, vs_count)
            parts.append(
                '<details class="fw-platform" id="{}" open>'.format(plat_id)
                + '<summary>{} <span class="badge b-amber">{}</span></summary>'.format(
                    esc(tree["name"]), esc(summary))
                + '<div class="fw-platform-body">'
            )
            # L1 — Cluster / platform object
            if plat_gw:
                parts.append('<details class="fw-level" open>')
                parts.append(
                    '<summary>L1 · Cluster / VSX platform — '
                    '<span class="mono">{}</span></summary>'.format(esc(tree["name"])))
                parts.append('<div class="fw-level-body">')
                parts.append(self._render_fw_hierarchy_node(
                    plat_gw, pkg_layers, topo, "Cluster"))
                if tree.get("is_vsx"):
                    parts.append(
                        '<div class="note" style="margin-top:8px">Mgmt + HA sync interfaces. '
                        'Platform policy (often <span class="mono">vsx0-firewalls</span>) governs '
                        'traffic <i>to</i> the firewalls themselves.</div>')
                else:
                    parts.append(
                        '<div class="note" style="margin-top:8px">Cluster VIP and data-plane interfaces. '
                        'Policy installs on this cluster object (Install On = this gateway or '
                        '<b>Policy Targets</b>). Not a VSX platform.</div>')
                parts.append('</div></details>')
            # L2 — Physical members
            if tree.get("physical"):
                parts.append('<details class="fw-level">')
                parts.append(
                    '<summary>L2 · Physical members ({})</summary>'.format(phys_count))
                parts.append('<div class="fw-level-body">')
                for node in tree["physical"]:
                    pgw = by_name.get(node["name"], {})
                    if pgw:
                        parts.append(self._render_fw_hierarchy_node(
                            pgw, pkg_layers, topo, "Physical"))
                if tree.get("is_vsx"):
                    parts.append(
                        '<div class="note" style="margin-top:8px">Per-node Mgmt/Sync — not data-plane VLANs. '
                        'Data interfaces are owned by Virtual Systems below.</div>')
                else:
                    parts.append(
                        '<div class="note" style="margin-top:8px">Per-node member IPs, HA sync, and '
                        'interfaces without a cluster VIP. Not Virtual Systems — this is a physical HA pair.</div>')
                parts.append('</div></details>')
            # L3 — VSX0 platform context (when VSX)
            if tree.get("is_vsx") and tree.get("platform_policy"):
                plat_app, plat_total, plat_pkg, _, _ = self._gw_policy_counts(
                    plat_gw, pkg_layers, topo) if plat_gw else (0, 0, "", [], [])
                parts.append('<details class="fw-level">')
                parts.append(
                    '<summary>L3 · VSX0 platform context — '
                    '<span class="mono">{}</span> · {} / {} rules</summary>'.format(
                        esc(tree["platform_policy"]), plat_app, plat_total))
                parts.append('<div class="fw-level-body">')
                parts.append(
                    '<div class="fw-node">'
                    '<div><span class="fw-lbl">VSX0</span>Platform kernel context</div>'
                    '<div class="fw-node-meta">Package <span class="mono">{}</span> installed on '
                    'cluster + members. Rules use <b>Policy Targets</b> or explicit install-on for '
                    'firewall management traffic (SNMP, IA, geo on mgmt, etc.).</div>'.format(
                        esc(tree["platform_policy"]))
                    + '<div class="fw-node-actions"><a href="gateways/{}.html">'
                    'View on {} →</a></div></div>'.format(
                        safe_name(tree["name"]), esc(tree["name"]))
                )
                parts.append('</div></details>')
            # L4 — Virtual systems
            if tree.get("virtual"):
                parts.append('<details class="fw-level" open>')
                parts.append(
                    '<summary>L4 · Virtual Systems ({}) — policy enforcement</summary>'.format(
                        vs_count))
                parts.append('<div class="fw-level-body">')
                for vs in tree["virtual"]:
                    vgw = by_name.get(vs["name"], {})
                    if not vgw:
                        continue
                    app, total, pkg, _, _ = self._gw_policy_counts(vgw, pkg_layers, topo)
                    ifaces_n = len(vgw.get("interfaces") or [])
                    hint = vs.get("hint") or ""
                    pol_disp = vs.get("policy_display") or "—"
                    badge = ""
                    if vs.get("vs_ha") and vs.get("member_count"):
                        badge = ' <span class="badge b-blue">VS HA ({})</span>'.format(
                            vs["member_count"])
                    parts.append(
                        '<div class="fw-node">'
                        '<div><span class="fw-lbl">Virtual</span>{}{}'
                        '<span class="plat-arrow">→</span> <span class="mono">{}</span></div>'.format(
                            self._gw_link(vs["name"], depth=0), badge, esc(pol_disp))
                        + '<div class="fw-node-meta">{} · {} interfaces · '
                        '<span class="good">{} applicable</span> / {} rules in package</div>'.format(
                            esc(hint) if hint else "Virtual System",
                            ifaces_n, app, total)
                        + '<div class="fw-node-actions"><a href="gateways/{}.html">'
                        'Open {} (filtered rules) →</a></div></div>'.format(
                            safe_name(vs["name"]), esc(vs["name"]))
                    )
                parts.append('</div></details>')
            elif not tree.get("is_vsx") and tree.get("platform_policy"):
                parts.append(
                    '<div class="note">Non-VSX HA cluster — policy enforced at cluster level; '
                    'no Virtual Systems in this export.</div>')
            parts.append('</div></details>')
        parts.append('</div>')
        return "".join(parts)

    # ---------- pages ----------
    def build(self, analysis, extra):
        self.write_assets()
        if self.browse_only:
            for name in _ANALYSIS_NAV:
                stale = self.out / name
                if stale.is_file():
                    stale.unlink()
        self.page_dashboard(analysis, extra)
        self.page_physical()
        self.page_coverage()
        self.page_gateways()
        self.page_interfaces()
        self.page_hosts()
        self.page_networks()
        self.page_ranges()
        self.page_dns_domains()
        self.page_groups()
        self.page_services()
        self.page_service_groups()
        self.page_applications()
        self.page_access_roles()
        self.page_users()
        self.page_times()
        self.page_zones()
        self.page_dynamic()
        self.page_packages()
        self.page_global_properties()
        self.page_nat()
        self.page_threat()
        self.page_threat_profiles()
        self.page_https()
        self.page_firewall()
        self.page_vpn()
        if not self.browse_only:
            self.page_optimization(analysis)
            self.page_simplify(extra["merge"])
            self.page_compliance(extra["controls"], extra["detail"], extra.get("intel"))
            self.page_risk(extra["versions"], extra.get("intel"))
        self.page_relationships()

    def _cards(self, items):
        """(number, label, optional class warn|bad|good) -> matches the shared card markup."""
        parts = ['<div class="cards">']
        for n, label, *rest in items:
            cls = " " + rest[0] if rest and rest[0] else ""
            parts.append('<div class="card{}"><div class="n">{}</div><div class="l">{}</div></div>'.format(
                cls, esc(str(n)), esc(label)))
        parts.append('</div>')
        return "".join(parts)

    def page_dashboard(self, analysis, extra):
        m = self.model
        n_layers = m.catalog_layer_count()
        n_rules = m.unique_access_rule_count()
        total_nat = sum(len(n["rules"]) for n in m.nat_layers)
        n_comm = len(m.vpn_meshed) + len(m.vpn_star) + len(m.vpn_remote)

        browse_note = (
            'Start with <a href="firewall.html"><b>Firewall View</b></a> for gateways, VSX/HA roles, '
            'and per-device policy drill-down. Tables sort on header click; filter in the search box.'
        )
        if not self.browse_only:
            browse_note += ' Cleanup candidates: <a href="optimization.html">Optimization</a>.'
        header = (
            '<h2>Configuration Dashboard <span class="vendor-chip">Check Point</span></h2>'
            '<div class="note">Read-only inventory exported from the Check Point Management API. '
            + browse_note + '</div>'
        )
        meta = (
            '<p class="meta">'
            'Source export: <span class="mono">{}</span> &nbsp;·&nbsp; '
            'Generated: <span class="mono">{}</span>'
            '</p>'.format(esc(m.run_dir), datetime.now().strftime("%Y-%m-%d %H:%M"))
        )

        inventory_cards = self._cards([
            (len(m.gateways), "Gateways/Servers", "good"),
            (len(m.objects.get("host", [])), "Hosts", ""),
            (len(m.objects.get("network", [])), "Networks", ""),
            (len(m.objects.get("group", [])), "Groups", ""),
            (sum(len(m.objects.get(c, [])) for c in SERVICE_CATS), "Services", ""),
        ])
        policy_cards = self._cards([
            (len(m.packages), "Policy Packages", ""),
            (n_layers, "Access Layers", ""),
            (n_rules, "Access Rules", ""),
            (total_nat, "NAT Rules", ""),
            (m.threat_rule_count(), "Threat Rules", ""),
        ])
        policy_note = (
            '<p class="meta">Layer and rule totals are deduplicated across shared-layer exports '
            '({} raw rulebase files in this bundle).</p>'.format(m.raw_export_layer_count())
        )
        vpn_cards = self._cards([
            (n_comm, "VPN Communities", ""),
            (len(m.vpn_meshed), "Meshed", ""),
            (len(m.vpn_star), "Star", ""),
            (len(m.vpn_remote), "Remote Access", ""),
        ])
        topo_stats = gateway_topology_stats(m.gateways)
        phy_inv = build_physical_inventory(m.gateways, build_gateway_topology_index(m.gateways))
        topology_cards = self._cards([
            (phy_inv["stats"]["physical_boxes"], "Physical boxes", "good"),
            (topo_stats["vsx_platforms"], "VSX platforms", ""),
            (topo_stats["virtual_systems"], "Virtual Systems", ""),
            (topo_stats["ha_clusters"], "HA cluster objects", "warn"),
            (topo_stats["standalone"], "Standalone gateways", ""),
        ])
        topology_note = (
            '<p class="meta">'
            '<b>Physical box</b> = real enforcement node (VSX appliance, HA member, or standalone gateway) — '
            '<b>not</b> a Virtual System. '
            'Typical stack: optional <b>HA cluster</b> → <b>VSX platform</b> → many <b>Virtual Systems</b> '
            '(like PA multi-vsys). '
            'This export: <b>{}</b> physical boxes across <b>{}</b> VSX platforms hosting '
            '<b>{}</b> virtual systems. '
            '<a href="physical.html">Physical Appliances</a> · '
            '<a href="firewall.html">Firewall View</a> (all objects).'
            '</p>'.format(
                phy_inv["stats"]["physical_boxes"],
                phy_inv["stats"]["vsx_platforms"],
                phy_inv["stats"]["vs_total"],
            )
        )
        audit = m.export_audit.get("summary") or {}
        coverage_banner = ""
        crit = audit.get("critical_flags", 0)
        warn = audit.get("warning_flags", 0)
        if crit or warn:
            coverage_banner = (
                '<div class="note warnbox">Export coverage: <strong>{} critical</strong>, '
                '<strong>{} warning</strong> flag(s). See '
                '<a href="coverage.html">Export Coverage</a> for what is missing and how to re-collect.</div>'
            ).format(crit, warn)

        body = [
            header, meta, coverage_banner,
            "<h3>Inventory</h3>", inventory_cards,
            "<h3>Gateway topology</h3>", topology_cards, topology_note,
            "<h3>Policy</h3>", policy_cards, policy_note,
            "<h3>VPN</h3>", vpn_cards,
        ]
        self.page("index.html", "Dashboard", "".join(body), depth=0)

    def page_physical(self):
        """Physical enforcement appliances — platform stacks (physical → virtual)."""
        m = self.model
        topo = self._gateway_topology()
        inv = build_physical_inventory(m.gateways, topo)
        stats = inv["stats"]
        trees, standalone = build_platform_trees(m.gateways, inv)

        body = [
            '<h2>Physical Appliances <span class="count">({})</span></h2>'.format(
                stats["physical_boxes"]),
            '<div class="note">'
            '<b>How to read this page</b> — each <b>platform stack</b> is one row in SmartConsole '
            '(VSX HA pair, single VSX box, or non-VSX HA cluster):<br>'
            '① <b>Physical</b> — Gaia boxes (<span class="mono">hq-fw1</span>, '
            '<span class="mono">hq-fw2</span>) sharing one VSX kernel.<br>'
            '② <b>Virtual</b> — policy enforcement contexts (<span class="mono">hq-fw-external</span> → '
            '<span class="mono">External_HQ</span>, etc.). '
            '<span class="mono">Switch_*</span> VS objects are L2-only (no access policy).'
            '</div>',
            '<div class="cards">'
            '<div class="card good"><div class="num">{}</div><div class="lbl">Physical boxes</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">VSX platforms</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Virtual Systems</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Mgmt servers</div></div>'
            '</div>'.format(
                stats["physical_boxes"], stats["vsx_platforms"],
                stats["vs_total"], stats["mgmt_servers"]),
        ]
        if stats["serial_present"] == 0:
            body.append(
                '<div class="note warnbox">'
                '<b>Serial numbers / SIC names</b> are largely absent in this export '
                '(only management <span class="mono">checkpoint-host</span> objects include '
                '<span class="mono">sic-name</span>). Gateway serials require a future collector '
                'enhancement (<span class="mono">show-simple-gateway</span> / '
                '<span class="mono">show-vsx</span> full detail).'
                '</div>'
            )
        else:
            body.append(
                '<div class="meta">SIC / serial present on {} object(s) in this export.</div>'.format(
                    stats["serial_present"]))

        body.append(
            '<div class="section-title">Platform stacks <span class="count">({})</span></div>'.format(
                len(trees)))
        body.append(
            '<div class="note">VSX HA example: <span class="mono">hq-fw-cluster</span> — '
            'physical <span class="mono">hq-fw1</span> + <span class="mono">hq-fw2</span> host '
            'virtual systems <span class="mono">hq-fw-external</span>, '
            '<span class="mono">hq-fw-internal</span>, <span class="mono">hq-fw-labs</span>, …'
            '</div>'
        )
        body.append(self.searchbox_blocks("plat-stacks", "plat-cnt"))
        body.append('<div id="plat-stacks" class="plat-stacks">')
        for tree in trees:
            body.append(self._render_platform_stack(tree))
        body.append('</div>')

        if standalone:
            by_name = {
                g.get("name"): g for g in m.gateways
                if isinstance(g, dict) and g.get("name")
            }
            body.append(
                '<div class="section-title">Standalone gateways <span class="count">({})</span></div>'.format(
                    len(standalone)))
            body.append(
                '<div class="note">Not on a VSX platform — each box enforces its own policy '
                '(e.g. <span class="mono">hq-fw1-vpn</span> for Secure Remote).</div>'
            )
            body.append(self.searchbox("standalone-gw", "standalone-cnt"))
            body.append(
                '<table id="standalone-gw"><thead><tr>'
                '<th>Gateway</th><th>IP</th><th>Policy package</th><th>Hardware</th><th>Version</th>'
                '</tr></thead><tbody>'
            )
            for row in standalone:
                gw = by_name.get(row["name"], {})
                pol = gw_policy_name(gw) or "—"
                body.append(
                    "<tr><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
                    "<td>{}</td><td>{}</td></tr>".format(
                        self._gw_link(row["name"]),
                        esc(row.get("ip") or "—"),
                        esc(pol),
                        esc(row.get("hardware") or "—"),
                        esc(row.get("version") or "—"),
                    )
                )
            body.append('</tbody></table>')

        body.append('<div class="section-title">All physical nodes (flat) <span class="count">({})</span></div>'.format(
            len(inv["physical_rows"])))
        body.append(self.searchbox("phys-boxes", "phys-cnt"))
        body.append(
            '<table id="phys-boxes"><thead><tr>'
            '<th>Node</th><th>Role</th><th>HA / VSX cluster</th><th>VSX platform</th>'
            '<th># VS</th><th>Hardware</th><th>Version</th><th>IP</th><th>SIC / serial</th>'
            '</tr></thead><tbody>'
        )
        for row in inv["physical_rows"]:
            name = row["name"]
            body.append(
                "<tr><td>{}</td><td>{}</td><td class='mono'>{}</td><td>{}</td>"
                "<td>{}</td><td>{}</td><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td></tr>".format(
                    self._gw_link(name),
                    esc(row["role"]),
                    esc(row["ha_cluster"] or "—"),
                    self._gw_link(row["vsx_platform"]) if row["vsx_platform"] else "—",
                    row["vs_count"] if row["vs_count"] else "—",
                    esc(row.get("hardware") or "—"),
                    esc(row.get("version") or "—"),
                    esc(row.get("ip") or "—"),
                    esc(row.get("sic") or "—"),
                )
            )
        body.append('</tbody></table>')

        if inv["mgmt_rows"]:
            body.append('<div class="section-title">Management servers <span class="count">({})</span></div>'.format(
                len(inv["mgmt_rows"])))
            body.append('<table><thead><tr><th>Name</th><th>Version</th><th>IP</th>'
                        '<th>SIC name</th><th>Hardware</th></tr></thead><tbody>')
            for row in inv["mgmt_rows"]:
                body.append(
                    "<tr><td>{}</td><td>{}</td><td class='mono'>{}</td>"
                    "<td class='mono'>{}</td><td>{}</td></tr>".format(
                        self._gw_link(row["name"]),
                        esc(row.get("version") or "—"),
                        esc(row.get("ip") or "—"),
                        esc(row.get("sic") or "—"),
                        esc(row.get("hardware") or "—"),
                    )
                )
            body.append('</tbody></table>')

        self.page("physical.html", "Physical Appliances", "".join(body))

    def page_coverage(self):
        """Export quality audit — mirrors export_quality_audit.py flags in the HTML browser."""
        m = self.model
        flags = m.export_audit.get("flags") or []
        summary = m.export_audit.get("summary") or {}
        body = ['<h2>Export Coverage <span class="vendor-chip">Data Quality</span></h2>']
        body.append('<div class="note">Read-only audit of this export folder. Each flag below '
                    'includes <b>Collector (Python)</b> steps when the Management API can supply '
                    'the data, and <b>Manual / Gaia / SmartConsole</b> steps when it cannot.</div>')
        body.append(self._cards([
            (summary.get("critical_flags", 0), "Critical flags", "bad" if summary.get("critical_flags") else "good"),
            (summary.get("warning_flags", 0), "Warnings", "warn" if summary.get("warning_flags") else ""),
            (summary.get("info_flags", 0), "Info", ""),
            (summary.get("access_rulebases_checked", 0), "Access layers checked", ""),
        ]))
        recollect = (
            build_recollect_command(flags) if build_recollect_command else
            "python checkpoint_collect_data.py \\\n"
            "  --mgmt-ip <IP> --username <USER> --password <PASS> \\\n"
            "  --full-objects --where-used --verify-export --output ."
        )
        body.append('<div class="section-title">Recommended re-collect command (Management API)</div>')
        body.append('<pre class="mono" style="white-space:pre-wrap;padding:12px;background:#1a1f2e;border-radius:8px">'
                    '{}</pre>'.format(esc(recollect)))
        if ROUTING_COLLECTOR and not summary.get("routing_present"):
            body.append('<div class="section-title">Routing companion (Gaia SSH — not Management API)</div>')
            body.append('<div class="note">Live routing tables are <b>not</b> available via SmartCenter API. '
                        'Use the companion script from a host that can SSH to each gateway, or collect manually.</div>')
            body.append('<pre class="mono" style="white-space:pre-wrap;padding:12px;background:#1a1f2e;border-radius:8px">'
                        '{}</pre>'.format(esc(ROUTING_COLLECTOR)))
            body.append('<div class="muted">Manual only: <span class="mono">python checkpoint_collect_routing.py --mop</span> '
                        'prints Gaia clish steps per gateway.</div>')
        body.append('<table><thead><tr><th>Severity</th><th>Category</th><th>Detail</th>'
                    '<th>How to fix</th></tr></thead><tbody>')
        if not flags:
            body.append('<tr><td colspan="4" class="muted">No audit flags (export_quality_audit not available).</td></tr>')
        for f in flags:
            sev = f.get("severity", "")
            badge = sev_badge(sev) if sev in ("high", "medium", "low") else (
                '<span class="badge b-red">critical</span>' if sev == "critical"
                else '<span class="badge b-amber">warning</span>' if sev == "warning"
                else '<span class="badge">info</span>')
            rem = f.get("remediation") or (remediation_for_flag(f) if remediation_for_flag else {})
            hint = format_remediation_html(rem) if format_remediation_html and rem else esc(f.get("detail", ""))
            body.append('<tr><td>{}</td><td class="mono">{}</td><td>{}</td><td>{}</td></tr>'.format(
                badge, esc(f.get("category", "")),
                esc("{} — expected {}, got {}. {}".format(
                    f.get("layer_or_object", ""), f.get("expected", ""), f.get("actual", ""), f.get("detail", ""))),
                hint))
        body.append('</tbody></table>')
        cap = m.run_dir / "collection-capability.csv"
        if cap.exists():
            body.append('<div class="section-title">Management API capability matrix</div>')
            body.append('<div class="note">What Check Point exposes via API vs. what requires Gaia SSH.</div>')
            body.append('<table><thead><tr><th>Item</th><th>Via API</th><th>Note</th></tr></thead><tbody>')
            with cap.open(newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    body.append('<tr><td>{}</td><td>{}</td><td class="mono">{}</td></tr>'.format(
                        esc(row.get("item", "")), esc(row.get("available_via_management_api", "")),
                        esc(row.get("note", ""))))
            body.append('</tbody></table>')
        self.page("coverage.html", "Export Coverage", "".join(body))

    def page_gateways(self):
        topo = self._gateway_topology()
        rows = []
        roles_seen = set()
        for gw in self.model.gateways:
            if not isinstance(gw, dict):
                continue
            pol = gw.get("policy") or {}
            ifaces = gw.get("interfaces") or []
            iface_str = ", ".join(
                "{}={}".format(i.get("interface-name") or i.get("name", "?"), i.get("ipv4-address", ""))
                for i in ifaces if isinstance(i, dict)
            )
            role = gw_deployment_role(gw)
            roles_seen.add(role)
            rows.append(
                "<tr data-role='{}'><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                "<td class='mono'>{}</td><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                    esc(role),
                    esc(gw.get("name")),
                    gw_role_badge(role),
                    esc(gw_ha_label(gw, topo)),
                    self._gw_parent_link(gw),
                    esc(gw.get("version", "")),
                    esc(gw.get("ipv4-address", "")),
                    esc(pol.get("access-policy-name", "")),
                    len(ifaces), esc(iface_str[:160]),
                )
            )
        total = len(rows)
        body = [
            '<h2>Gateways &amp; Servers <span class="count">({})</span></h2>'.format(total),
            '<div class="note">See <a href="firewall.html">Firewall View</a> for the same '
            'deployment roles with policy rule counts.</div>',
        ]
        body.append(self.inventory_toolbar(
            "cpgw", "cpgwtbl", total, "gateways.csv",
            placeholder="Filter gateways (name, IP, policy, version…)",
            role_options=sorted(roles_seen),
        ))
        body.append('<div class="table-wrap"><table id="cpgwtbl"><thead><tr><th>Name</th><th>Role</th>'
                    '<th>HA / layout</th><th>Parent</th><th>Version</th><th>IP</th>'
                    '<th>Access Policy</th><th>#Ifaces</th><th>Interfaces</th>'
                    '</tr></thead><tbody>')
        body.extend(rows)
        body.append('</tbody></table></div>')
        body.append(self.inv_filter_script(
            "cpgw", "cpgwtbl",
            selects=[{"id": "cpgw-role", "attr": "data-role"}],
        ))
        self.page("gateways.html", "Gateways", "".join(body))

    def page_interfaces(self):
        rows = []
        n_ip = n_inet = n_dmz = n_internal = n_noasp = 0
        for gw in self.model.gateways:
            if not isinstance(gw, dict):
                continue
            gwname = gw.get("name", "")
            for iface in gw.get("interfaces") or []:
                if not isinstance(iface, dict):
                    continue
                name = iface.get("interface-name") or iface.get("name") or "?"
                ip = (iface.get("ipv4-address") or "").strip()
                topo = iface.get("topology") or iface.get("topology-settings") or {}
                topo_str = ""
                if isinstance(topo, str):
                    topo_str = topo.lower()
                    topo = {}
                masklen = _mask_len(iface)
                net = _cidr_network(ip, masklen) if (ip and masklen) else ""
                has_ip = bool(ip) and ip != "0.0.0.0"
                dynamic = bool(iface.get("dynamic-ip"))

                if topo.get("leads-to-internet") or topo_str in ("internet", "external"):
                    role, rkey, rbadge = "External (Internet)", "external", "b-red"
                    n_inet += 1
                elif topo.get("leads-to-dmz") or topo_str == "dmz":
                    role, rkey, rbadge = "DMZ", "dmz", "b-amber"
                    n_dmz += 1
                else:
                    role, rkey, rbadge = "Internal", "internal", "b-blue"
                    n_internal += 1

                sz = topo.get("security-zone")
                if isinstance(sz, dict):
                    zone = sz.get("name", "")
                elif iface.get("security-zone") is True:
                    zone = "enabled"
                else:
                    zone = ""

                asp = iface.get("anti-spoofing")
                if asp is None:
                    asp = topo.get("anti-spoofing")
                if asp is True:
                    asp_cell, asp_key = '<span class="badge b-blue">on</span>', "1"
                elif asp is False:
                    asp_cell, asp_key = '<span class="badge b-amber">off</span>', "0"
                    n_noasp += 1
                else:
                    asp_cell, asp_key = '<span class="muted">—</span>', "-"

                if has_ip:
                    n_ip += 1
                    ip_cell = "<td class='mono'>{}</td>".format(esc(ip))
                elif ip == "0.0.0.0":
                    ip_cell = "<td><span class='muted'>0.0.0.0</span></td>"
                elif dynamic:
                    ip_cell = "<td><span class='muted'>dynamic</span></td>"
                else:
                    ip_cell = "<td><span class='muted'>—</span></td>"

                rows.append(
                    "<tr data-role='{rkey}' data-ip='{hip}' data-inet='{inet}' data-asp='{asp}'>"
                    "<td>{gw}</td><td class='mono'>{name}</td>{ipc}"
                    "<td class='mono'>{ml}</td><td class='mono'>{net}</td>"
                    "<td><span class='badge {rb}'>{role}</span></td>"
                    "<td>{zone}</td><td>{aspc}</td><td>{dyn}</td></tr>".format(
                        rkey=rkey, hip="1" if has_ip else "0",
                        inet="1" if rkey == "external" else "0", asp=asp_key,
                        gw=esc(gwname), name=esc(name), ipc=ip_cell,
                        ml=("/" + masklen) if masklen else "",
                        net=esc(net), rb=rbadge, role=esc(role),
                        zone=esc(zone) if zone else "<span class='muted'>—</span>",
                        aspc=asp_cell, dyn="yes" if dynamic else "",
                    )
                )

        total = len(rows)
        cards = (
            '<div class="cards">'
            '<div class="card"><div class="num">{tot}</div><div class="lbl">Interfaces</div></div>'
            '<div class="card good"><div class="num">{ip}</div><div class="lbl">With IP</div></div>'
            '<div class="card"><div class="num">{ni}</div><div class="lbl">Without IP</div></div>'
            '<div class="card warn"><div class="num">{inet}</div><div class="lbl">Internet-facing</div></div>'
            '<div class="card"><div class="num">{dmz}</div><div class="lbl">DMZ</div></div>'
            '<div class="card{aspc}"><div class="num">{noasp}</div><div class="lbl">Anti-spoof off</div></div>'
            '</div>'.format(
                tot=total, ip=n_ip, ni=total - n_ip, inet=n_inet, dmz=n_dmz,
                noasp=n_noasp, aspc=" bad" if n_noasp else "",
            )
        )

        body = ['<h2>Interfaces / IPs <span class="count">({})</span></h2>'.format(total)]
        body.append('<div class="note">Aggregated interface inventory across all gateways and cluster members. '
                    'Empty or <span class="mono">0.0.0.0</span> addresses are treated as &ldquo;no IP&rdquo;.</div>')
        body.append(cards)
        extra_controls = (
            '<label>Topology '
            '<select id="cpif-topo"><option value="">All</option>'
            '<option value="external">External (Internet)</option>'
            '<option value="dmz">DMZ</option>'
            '<option value="internal">Internal</option></select></label>'
            '<label><input type="checkbox" id="cpif-hasip"> Hide without IP</label>'
            '<label><input type="checkbox" id="cpif-inet"> Internet-facing only</label>'
            '<label><input type="checkbox" id="cpif-asp"> Anti-spoof off only</label>'
        )
        body.append(self.inventory_toolbar(
            "cpif", "cpiftbl", total, "interfaces.csv",
            placeholder="Filter interfaces (gateway, name, IP, network…)",
            extra_controls=extra_controls,
        ))
        body.append('<div class="table-wrap"><table id="cpiftbl"><thead><tr>'
                    '<th>Gateway</th><th>Interface</th><th>IPv4</th><th>Mask</th>'
                    '<th>Network</th><th>Topology</th><th>Security Zone</th>'
                    '<th>Anti-Spoofing</th><th>Dynamic</th></tr></thead><tbody>')
        body.extend(rows)
        body.append('</tbody></table></div>')
        body.append(self.inv_filter_script(
            "cpif", "cpiftbl",
            selects=[{"id": "cpif-topo", "attr": "data-role"}],
            checks=[
                {"id": "cpif-hasip", "attr": "data-ip", "val": "1"},
                {"id": "cpif-inet", "attr": "data-inet", "val": "1"},
                {"id": "cpif-asp", "attr": "data-asp", "val": "0"},
            ],
        ))
        self.page("interfaces.html", "Interfaces / IPs", "".join(body))

    def page_simple_objects(self, fname, title, category, columns):
        objs = self.model.objects.get(category, [])
        prefix = "inv-{}".format(fname.replace(".html", "").replace("-", "")[:12])
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            cells = "".join("<td class='mono'>{}</td>".format(esc(obj.get(c[1], ""))) for c in columns)
            rows.append("<tr>{}</tr>".format(cells))
        head = "".join("<th>{}</th>".format(esc(c[0])) for c in columns)
        body = ['<h2>{} <span class="count">({})</span></h2>'.format(esc(title), len(objs))]
        body.append(self.inventory_table_section(
            prefix, prefix + "tbl", fname.replace(".html", ".csv"), len(objs),
            "Filter {}…".format(title.lower()), head, rows,
        ))
        self.page(fname, title, "".join(body))

    def page_hosts(self):
        objs = self.model.objects.get("host", [])
        m = self.model
        body = ['<h2>Hosts <span class="count">({})</span></h2>'.format(len(objs))]
        if not m.has_object_nat:
            body.append('<div class="note warnbox">Object-level NAT not in this export. Re-collect with '
                        '<span class="mono">--full-objects</span> to see NAT method per host.</div>')
        head = '<th>Name</th><th>IP Address</th><th>Color</th>'
        if m.has_object_nat:
            head += '<th>Object NAT</th>'
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            row = '<td class="mono">{}</td><td class="mono">{}</td><td>{}</td>'.format(
                esc(obj.get("name", "")), esc(obj.get("ipv4-address", "")), esc(obj.get("color", "")))
            if m.has_object_nat:
                ns = nat_settings_summary(obj)
                row += '<td class="mono">{}</td>'.format(esc(ns) if ns else "—")
            rows.append("<tr>{}</tr>".format(row))
        body.append(self.inventory_table_section(
            "inv-host", "inv-host-tbl", "hosts.csv", len(objs),
            "Filter hosts (name, IP, NAT…)", head, rows,
        ))
        self.page("hosts.html", "Hosts", "".join(body))

    def page_ranges(self):
        objs = self.model.objects.get("address-range", [])
        m = self.model
        body = ['<h2>Address Ranges <span class="count">({})</span></h2>'.format(len(objs))]
        if not m.has_object_nat:
            body.append('<div class="note warnbox">Object-level NAT not captured — use '
                        '<span class="mono">--full-objects</span> on re-collect.</div>')
        head = '<th>Name</th><th>First</th><th>Last</th>'
        if m.has_object_nat:
            head += '<th>Object NAT</th>'
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            row = '<td class="mono">{}</td><td class="mono">{}</td><td class="mono">{}</td>'.format(
                esc(obj.get("name", "")), esc(obj.get("ipv4-address-first", "")),
                esc(obj.get("ipv4-address-last", "")))
            if m.has_object_nat:
                ns = nat_settings_summary(obj)
                row += '<td class="mono">{}</td>'.format(esc(ns) if ns else "—")
            rows.append("<tr>{}</tr>".format(row))
        body.append(self.inventory_table_section(
            "inv-range", "inv-range-tbl", "address-ranges.csv", len(objs),
            "Filter address ranges…", head, rows,
        ))
        self.page("ranges.html", "Address Ranges", "".join(body))

    def page_dns_domains(self):
        objs = self.model.objects.get("dns-domain", [])
        body = ['<h2>DNS Domains (FQDN) <span class="count">({})</span></h2>'.format(len(objs))]
        body.append(
            '<div class="note">Check Point <span class="mono">dns-domain</span> objects '
            '(FQDN / domain patterns). The name field holds the match pattern '
            '(e.g. <span class="mono">.dropbox.com</span>). Map to Palo Alto FQDN address objects on migration.</div>'
        )
        head = '<th>Name / FQDN</th><th>Color</th><th>Comments</th>'
        rows = []
        for obj in sorted(objs, key=lambda o: (o.get("name") or "").lower()):
            rows.append(
                "<tr><td class='mono'>{}</td><td>{}</td><td>{}</td></tr>".format(
                    esc(obj.get("name", "")),
                    esc(obj.get("color", "")),
                    esc(obj.get("comments", "") or ""),
                )
            )
        if not rows:
            body.append('<div class="note">No DNS domain objects in this export.</div>')
        else:
            body.append(self.inventory_table_section(
                "inv-dns", "inv-dns-tbl", "dns-domains.csv", len(objs),
                "Filter DNS domains…", head, rows,
            ))
        self.page("dns-domains.html", "DNS Domains", "".join(body))

    def page_networks(self):
        objs = self.model.objects.get("network", [])
        m = self.model
        body = ['<h2>Networks <span class="count">({})</span></h2>'.format(len(objs))]
        if not m.has_object_nat:
            body.append('<div class="note warnbox">Object-level NAT not captured — use '
                        '<span class="mono">--full-objects</span> on re-collect.</div>')
        head = '<th>Name</th><th>Subnet</th><th>Mask</th><th>CIDR</th>'
        if m.has_object_nat:
            head += '<th>Object NAT</th>'
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            cells = [
                esc(obj.get("name")), esc(obj.get("subnet4", "")),
                esc(obj.get("subnet-mask", "")), "/" + esc(str(obj.get("mask-length4", ""))),
            ]
            if m.has_object_nat:
                ns = nat_settings_summary(obj)
                cells.append(esc(ns) if ns else "—")
            rows.append("<tr>" + "".join("<td class='mono'>{}</td>".format(c) for c in cells) + "</tr>")
        body.append(self.inventory_table_section(
            "inv-net", "inv-net-tbl", "networks.csv", len(objs),
            "Filter networks (name, subnet, CIDR…)", head, rows,
        ))
        self.page("networks.html", "Networks", "".join(body))

    def page_groups(self):
        objs = self.model.objects.get("group", [])
        body = ['<h2>Network Groups <span class="count">({})</span></h2>'.format(len(objs))]
        has_members = any(self.model.member_index.get(o.get("uid")) for o in objs)
        if not has_members:
            body.append('<div class="note warnbox">Group membership was not captured in this export '
                        '(collected at standard detail). Re-run the collector (updated to use full '
                        'detail) to see members and improve unused-object accuracy.</div>')
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            members = self.model.member_index.get(obj.get("uid"), set())
            mnames = ", ".join(sorted(self.model.name_of(u) for u in members))
            rows.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                esc(obj.get("name")), len(members), esc(mnames[:300])))
        body.append(self.inventory_table_section(
            "inv-grp", "inv-grp-tbl", "groups.csv", len(objs),
            "Filter groups (name, members…)", '<th>Name</th><th>#Members</th><th>Members</th>', rows,
        ))
        self.page("groups.html", "Groups", "".join(body))

    def page_services(self):
        proto_label = {
            "service-tcp": "TCP", "service-udp": "UDP", "service-icmp": "ICMP",
            "service-icmp6": "ICMPv6", "service-other": "Other",
            "service-dce-rpc": "DCE-RPC", "service-rpc": "RPC", "service-gtp": "GTP",
        }
        rows = []
        for cat in SERVICE_CATS:
            proto = proto_label.get(cat, cat)
            for obj in self.model.objects.get(cat, []):
                if cat in ("service-icmp", "service-icmp6"):
                    port = "type {}/{}".format(obj.get("icmp-type", ""), obj.get("icmp-code", ""))
                elif cat == "service-other":
                    proto_num = obj.get("ip-protocol")
                    port = "ip-proto {}".format(proto_num) if proto_num not in (None, "") else ""
                elif cat in ("service-dce-rpc", "service-rpc"):
                    port = obj.get("interface-uuid") or obj.get("program-number") or ""
                else:
                    port = obj.get("port", "")
                rows.append((obj.get("name", ""), proto, str(port)))
        body = ['<h2>Services <span class="count">({})</span></h2>'.format(len(rows))]
        svc_rows = []
        for name, proto, port in sorted(rows):
            svc_rows.append("<tr><td class='mono'>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                esc(name), proto, esc(port)))
        body.append(self.inventory_table_section(
            "inv-svc", "inv-svc-tbl", "services.csv", len(rows),
            "Filter services (name, protocol, port…)",
            '<th>Name</th><th>Protocol</th><th>Port</th>', svc_rows,
        ))
        self.page("services.html", "Services", "".join(body))

    def page_service_groups(self):
        objs = self.model.objects.get("service-group", [])
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            members = self.model.member_index.get(obj.get("uid"), set())
            mnames = ", ".join(sorted(self.model.name_of(u) for u in members))
            rows.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                esc(obj.get("name")), len(members), esc(mnames[:300])))
        body = ['<h2>Service Groups <span class="count">({})</span></h2>'.format(len(objs))]
        body.append(self.inventory_table_section(
            "inv-svcg", "inv-svcg-tbl", "service-groups.csv", len(objs),
            "Filter service groups…", '<th>Name</th><th>#Members</th><th>Members</th>', rows,
        ))
        self.page("service-groups.html", "Service Groups", "".join(body))

    def page_applications(self):
        """Application & URL-filtering objects.

        Customer-defined application-sites are the audit-relevant ones: the
        collector enriches them to full detail so url-list / primary-category /
        risk are present here. Built-in Check Point apps (the AppWiki database)
        are listed too, but only custom apps carry a URL definition worth review.
        Each custom app is cross-referenced to the access rules that apply it
        (directly, or via an application-site group).
        """
        BUILTIN_DOMS = ("APPI Data", "Check Point Data")

        def dom_name(o):
            d = o.get("domain")
            return d.get("name") if isinstance(d, dict) else d

        def is_custom(o):
            return o.get("user-defined") is True or (dom_name(o) not in BUILTIN_DOMS)

        sites = self.model.objects.get("application-site", [])
        groups = self.model.objects.get("application-site-group", [])
        custom = [o for o in sites if is_custom(o)]
        with_url = [o for o in custom if o.get("url-list")]

        # cross-reference each custom app to where it is applied in policy
        usage = {o.get("uid"): self._app_usage(o.get("uid")) for o in custom}
        unused = [o for o in custom
                  if not usage[o.get("uid")][0] and not usage[o.get("uid")][1]]

        body = ['<h2>Applications &amp; URL Filtering <span class="count">({})</span></h2>'.format(len(sites))]
        body.append('<div class="note">On Check Point Access layers, Application Control / URL Filtering '
                    'matches live in the <b>Service</b> column (application-site / category objects) — '
                    'not a separate policy package. Identity-aware allow/block uses <b>Access Roles</b> '
                    'in Source (see <a href="access-roles.html">Access Roles</a>). '
                    'The Content column is often left as Any.</div>')
        body.append(self._cards([
            (len(sites), "Application sites", ""),
            (len(custom), "Custom (user-defined)", "warn" if custom else ""),
            (len(with_url), "With URL definition", ""),
            (len(unused), "Custom, not applied", "bad" if unused else "good"),
            (len(groups), "Application groups", ""),
        ]))

        # ----- custom application-sites (the ones worth auditing) -----
        body.append('<h3 id="custom">Custom application-sites</h3>')
        if not custom:
            body.append('<div class="note">No customer-defined application-sites were found in this export.</div>')
        else:
            if not with_url:
                body.append('<div class="note warnbox">Custom apps were captured by name only (no URL list). '
                            'Re-run the collector (updated to enrich custom apps to full detail) to see their '
                            'URL/category/risk definitions here.</div>')
            body.append('<div class="note">The <strong>Where applied</strong> column cross-references each '
                        'app to the access rules that use it — directly, or <em>via</em> an application-site '
                        'group. Apps with no reference are flagged <span class="pill bad">not applied</span> '
                        'and are candidates for cleanup.</div>')
            app_rows = []
            for o in sorted(custom, key=lambda o: o.get("name", "").lower()):
                urls = o.get("url-list") or []
                url_txt = ", ".join(str(u) for u in urls) if urls else ""
                cat = o.get("primary-category", "")
                risk = o.get("risk", "")
                desc = o.get("description", "")
                direct, via = usage[o.get("uid")]
                applied = self._fmt_app_usage(direct, via)
                app_rows.append("<tr><td>{}</td><td>{}</td><td>{}</td><td class='mono'>{}</td>"
                                "<td>{}</td><td>{}</td></tr>".format(
                                    esc(o.get("name", "")), esc(cat), esc(risk), esc(url_txt),
                                    applied, esc(desc[:300])))
            body.append(self.inventory_table_section(
                "inv-app", "inv-app-tbl", "applications-custom.csv", len(custom),
                "Filter custom applications…",
                '<th>Name</th><th>Primary Category</th><th>Risk</th><th>URLs / patterns</th>'
                '<th>Where applied</th><th>Description</th>',
                app_rows,
            ))

        # ----- application-site groups -----
        if groups:
            body.append('<h3 id="groups">Application groups <span class="count">({})</span></h3>'.format(len(groups)))
            grp_rows = []
            for o in sorted(groups, key=lambda o: o.get("name", "").lower()):
                members = self.model.member_index.get(o.get("uid"), set())
                mnames = ", ".join(sorted(self.model.name_of(u) for u in members))
                grp_rows.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                    esc(o.get("name", "")), len(members), esc(mnames[:300])))
            body.append(self.inventory_table_section(
                "inv-appgrp", "inv-appgrp-tbl", "application-groups.csv", len(groups),
                "Filter application groups…", '<th>Name</th><th>#Members</th><th>Members</th>',
                grp_rows, show_hint=False,
            ))

        # ----- built-in apps referenced (collapsed list for completeness) -----
        builtin = [o for o in sites if not is_custom(o)]
        if builtin:
            body.append('<h3 id="builtin">Built-in Check Point apps in use '
                        '<span class="count">({})</span></h3>'.format(len(builtin)))
            body.append('<div class="note">These come from the Check Point AppWiki database; '
                        'they are referenced by policy but defined by Check Point, not the customer.</div>')
            bi_rows = []
            for o in sorted(builtin, key=lambda o: o.get("name", "").lower()):
                bi_rows.append("<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    esc(o.get("name", "")), esc(o.get("primary-category", "")), esc(o.get("risk", ""))))
            body.append(self.inventory_table_section(
                "inv-appbi", "inv-appbi-tbl", "applications-builtin.csv", len(builtin),
                "Filter built-in applications…",
                '<th>Name</th><th>Primary Category</th><th>Risk</th>',
                bi_rows, show_hint=False,
            ))

        self.page("applications.html", "Applications & URL Filtering", "".join(body))

    def page_access_roles(self):
        m = self.model
        objs = m.objects.get("access-role", [])
        body = ['<h2>Access Roles <span class="count">({})</span></h2>'.format(len(objs))]
        body.append('<div class="note">Check Point <b>Access Roles</b> bind <b>Users</b>, '
                    '<b>Networks</b>, and <b>Machines</b> for identity-aware policy. '
                    '<span class="mono">Any</span> = all networks/machines; '
                    '<span class="mono">All Identified</span> = any user authenticated via Identity Awareness.</div>')
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            rows.append("<tr><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
                        "<td class='mono'>{}</td></tr>".format(
                            esc(obj.get("name", "")),
                            esc(m.format_access_role_field(obj.get("users"))),
                            esc(m.format_access_role_field(obj.get("networks"))),
                            esc(m.format_access_role_field(obj.get("machines")))))
        body.append(self.inventory_table_section(
            "inv-arole", "inv-arole-tbl", "access-roles.csv", len(objs),
            "Filter access roles…",
            '<th>Name</th><th>Users</th><th>Networks</th><th>Machines</th>', rows,
        ))
        self.page("access-roles.html", "Access Roles", "".join(body))

    def page_users(self):
        users = self.model.objects.get("user", [])
        groups = self.model.objects.get("user-group", [])
        body = ['<h2>Users &amp; Groups <span class="count">({} users · {} groups)</span></h2>'.format(
            len(users), len(groups))]
        body.append('<h3>Users</h3>')
        user_rows = []
        for obj in sorted(users, key=lambda o: o.get("name", "")):
            user_rows.append("<tr><td>{}</td><td class='mono'>{}</td></tr>".format(
                esc(obj.get("name", "")), esc(obj.get("type", ""))))
        body.append(self.inventory_table_section(
            "inv-user", "inv-user-tbl", "users.csv", len(users),
            "Filter users…", '<th>Name</th><th>Type</th>', user_rows,
        ))
        if groups:
            body.append('<h3>User Groups</h3>')
            grp_rows = []
            for obj in sorted(groups, key=lambda o: o.get("name", "")):
                members = self.model.member_index.get(obj.get("uid"), set())
                mnames = ", ".join(sorted(self.model.name_of(u) for u in members))
                grp_rows.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                    esc(obj.get("name", "")), len(members), esc(mnames[:300])))
            body.append(self.inventory_table_section(
                "inv-ugrp", "inv-ugrp-tbl", "user-groups.csv", len(groups),
                "Filter user groups…", '<th>Name</th><th>#Members</th><th>Members</th>',
                grp_rows, show_hint=False,
            ))
        self.page("users.html", "Users & Groups", "".join(body))

    def page_times(self):
        times = self.model.objects.get("time", [])
        tgroups = self.model.objects.get("time-group", [])
        body = ['<h2>Time Objects <span class="count">({} · {} groups)</span></h2>'.format(
            len(times), len(tgroups))]
        body.append('<div class="note">Schedule objects used in the <b>Time</b> column of access rules. '
                    '<span class="mono">1970-01-01</span> dates are Check Point placeholders for '
                    '&ldquo;no fixed calendar bound&rdquo;. '
                    '<b>Used in</b> is inferred from exported rulebases'
                    + (' (merged with native <span class="mono">where-used</span>).' if self.model.uses_native_where_used
                       else ' — this export did not collect native <span class="mono">where-used</span>; '
                            'see <a href="relationships.html">Relationships</a> for all objects.')
                    + '</div>')
        time_rows = []
        for obj in sorted(times, key=lambda o: o.get("name", "")):
            start = format_time_point(
                obj.get("start"),
                start_now=bool(obj.get("start-now")),
            )
            end = format_time_point(
                obj.get("end"),
                end_never=bool(obj.get("end-never")),
            )
            window = format_time_daily_window(obj)
            schedule = format_time_recurrence(
                obj.get("recurrence"),
                obj.get("hours-ranges") or obj.get("hours"),
            )
            used = self._fmt_time_usage(obj.get("uid"))
            cmt = (obj.get("comments") or "")[:80]
            time_rows.append("<tr><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
                             "<td class='mono'>{}</td><td>{}</td><td style='font-size:11px'>{}</td>"
                             "<td class='muted'>{}</td></tr>".format(
                                 esc(obj.get("name", "")), esc(start), esc(end),
                                 esc(window), esc(schedule), used, esc(cmt)))
        body.append(self.inventory_table_section(
            "inv-time", "inv-time-tbl", "time-objects.csv", len(times),
            "Filter time objects…",
            '<th>Name</th><th>Active From</th><th>Active Until</th><th>Daily Window</th>'
            '<th>Schedule</th><th>Used in</th><th>Comments</th>',
            time_rows,
        ))
        if tgroups:
            body.append('<h3>Time Groups</h3>')
            tg_rows = []
            for obj in sorted(tgroups, key=lambda o: o.get("name", "")):
                members = self.model.member_index.get(obj.get("uid"), set())
                mnames = ", ".join(sorted(self.model.name_of(u) for u in members))
                tg_rows.append("<tr><td>{}</td><td class='mono'>{}</td></tr>".format(
                    esc(obj.get("name", "")), esc(mnames[:300])))
            body.append(self.inventory_table_section(
                "inv-tgrp", "inv-tgrp-tbl", "time-groups.csv", len(tgroups),
                "Filter time groups…", '<th>Name</th><th>Members</th>',
                tg_rows, show_hint=False,
            ))
        self.page("times.html", "Time Objects", "".join(body))

    def page_zones(self):
        m = self.model
        objs = m.objects.get("security-zone", [])
        assigned = sum(1 for z in objs if m.zone_interfaces.get(z.get("uid")))
        total_ifaces = sum(len(v) for v in m.zone_interfaces.values())
        body = ['<h2>Security Zones <span class="count">({})</span></h2>'.format(len(objs))]
        body.append('<div class="note">Check Point <b>security zones</b> classify gateway interfaces in '
                    '<b>topology</b> (External / Internal / DMZ / Wireless). They drive anti-spoofing and '
                    'zone-based policy — zones are assigned per interface on each gateway, not in access-rule '
                    'source/destination columns. See also '
                    '<a href="interfaces.html">Interfaces / IPs</a> (Security Zone column).'
                    + (' Native <span class="mono">where-used</span> was not collected for this export.'
                       if not m.uses_native_where_used else '')
                    + '</div>')
        body.append(
            '<div class="cards">'
            '<div class="card"><div class="num">{}</div><div class="lbl">Zone objects</div></div>'
            '<div class="card good"><div class="num">{}</div><div class="lbl">Zones with gateway ifaces</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Interface assignments</div></div>'
            '</div>'.format(len(objs), assigned, total_ifaces)
        )
        zone_rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            uid = obj.get("uid")
            domain = (obj.get("domain") or {}).get("name", "") if isinstance(obj.get("domain"), dict) else ""
            nif = len(m.zone_interfaces.get(uid, []))
            ifaces = self._fmt_zone_iface_usage(uid)
            rules = self._fmt_time_usage(uid)
            zone_rows.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td><td>{}</td>"
                             "<td style='font-size:11px'>{}</td><td style='font-size:11px'>{}</td></tr>".format(
                                 esc(obj.get("name", "")),
                                 esc(m.zone_role_label(obj.get("name"))),
                                 esc(domain), nif, ifaces, rules))
        body.append(self.inventory_table_section(
            "inv-zone", "inv-zone-tbl", "security-zones.csv", len(objs),
            "Filter security zones…",
            '<th>Name</th><th>Role</th><th>Domain</th><th># Ifaces</th>'
            '<th>Assigned on gateways</th><th>Used in rules</th>',
            zone_rows,
        ))
        if total_ifaces:
            body.append('<h3>Interface assignments <span class="count">({})</span></h3>'.format(total_ifaces))
            body.append('<div class="note">Flat view of every gateway interface with an explicit security zone '
                        'in topology (from <span class="mono">gateways-and-servers.json</span>).</div>')
            zif_rows = []
            for obj in sorted(objs, key=lambda o: o.get("name", "")):
                zname = obj.get("name", "")
                for row in m.zone_interfaces.get(obj.get("uid"), []):
                    if row.get("internet"):
                        topo = '<span class="badge b-red">Internet</span>'
                    elif row.get("dmz"):
                        topo = '<span class="badge b-amber">DMZ</span>'
                    else:
                        topo = '<span class="badge b-blue">Internal</span>'
                    zif_rows.append((zname, row["gateway"], row["interface"], row.get("ip", ""), topo))
            zif_html = []
            for zname, gw, iface, ip, topo in sorted(zif_rows, key=lambda r: (r[0].lower(), r[1].lower(), r[2])):
                zif_html.append("<tr><td>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
                                "<td class='mono'>{}</td><td>{}</td></tr>".format(
                                    esc(zname), esc(gw), esc(iface), esc(ip), topo))
            body.append(self.inventory_table_section(
                "inv-zif", "inv-zif-tbl", "zone-interfaces.csv", len(zif_html),
                "Filter zone interface assignments…",
                '<th>Zone</th><th>Gateway</th><th>Interface</th><th>IPv4</th><th>Topology</th>',
                zif_html, show_hint=False,
            ))
        self.page("zones.html", "Security Zones", "".join(body))

    def page_dynamic(self):
        objs = self.model.objects.get("dynamic-object", [])
        rows = []
        for obj in sorted(objs, key=lambda o: o.get("name", "")):
            rows.append("<tr><td>{}</td><td>{}</td></tr>".format(
                esc(obj.get("name", "")), esc(obj.get("comments", ""))))
        body = ['<h2>Dynamic Objects <span class="count">({})</span></h2>'.format(len(objs))]
        body.append(self.inventory_table_section(
            "inv-dyn", "inv-dyn-tbl", "dynamic-objects.csv", len(objs),
            "Filter dynamic objects…", '<th>Name</th><th>Comment</th>', rows,
        ))
        self.page("dynamic.html", "Dynamic Objects", "".join(body))

    def _app_usage(self, uid):
        """Cross-reference an application-site to the rules that apply it.

        Returns (direct, via): 'direct' is a sorted list of 'pkg · layer #n'
        locations where the app is referenced straight in a rule (typically the
        Application/URL 'content' column); 'via' is a list of (group-name, [locs])
        for rules that reference an application-site group the app belongs to.
        """
        m = self.model

        def loc(r):
            if r["kind"] == "nat":
                return "NAT" + ((" · " + r["package"]) if r["package"] else "") + " #" + str(r["num"])
            head = (r["package"] + " · ") if r["package"] else ""
            return head + (r["layer"] or "?") + " #" + str(r["num"])

        direct = sorted({loc(r) for r in m.where_used.get(uid, [])
                         if r["kind"] in ("access", "nat")})
        via = []
        for guid in sorted(m.member_of.get(uid, set()), key=lambda g: m.name_of(g).lower()):
            glocs = sorted({loc(r) for r in m.where_used.get(guid, [])
                            if r["kind"] in ("access", "nat")})
            if glocs:
                via.append((m.name_of(guid), glocs))
        return direct, via

    def _fmt_app_usage(self, direct, via):
        if not direct and not via:
            return '<span class="pill bad">not applied</span>'
        parts = []
        if direct:
            parts.append("<span class='mono'>{}</span>".format(esc(", ".join(direct))))
        for gname, glocs in via:
            parts.append("via <strong>{}</strong>: <span class='mono'>{}</span>".format(
                esc(gname), esc(", ".join(glocs))))
        return "<br>".join(parts)

    def _rule_ref_loc(self, r):
        """One-line location string for a where-used reference."""
        if r["kind"] == "nat":
            return "NAT · {} #{}".format(r["package"], r["num"])
        if r["kind"] in ("native-direct", "native-indirect"):
            return "CP where-used · {} ({})".format(r["layer"], r["field"])
        head = (r["package"] + " · ") if r["package"] else ""
        rule = r.get("name") or ""
        extra = (" — " + rule) if rule else ""
        return head + (r["layer"] or "?") + " #" + str(r["num"]) + extra

    def _fmt_time_usage(self, uid):
        """Access/NAT rules (and time groups) that reference this time object."""
        m = self.model
        refs = [r for r in m.where_used.get(uid, [])
                if r["kind"] in ("access", "nat", "native-direct", "native-indirect")]
        locs = []
        for r in refs:
            loc = self._rule_ref_loc(r)
            if loc not in locs:
                locs.append(loc)
        if locs:
            text = "; ".join(locs[:6])
            if len(locs) > 6:
                text += " … +{}".format(len(locs) - 6)
            return "<span class='mono'>{}</span>".format(esc(text))
        via = []
        for guid in sorted(m.member_of.get(uid, set()), key=lambda g: m.name_of(g).lower()):
            grefs = [r for r in m.where_used.get(guid, [])
                     if r["kind"] in ("access", "nat")]
            if grefs:
                glocs = []
                for r in grefs:
                    loc = self._rule_ref_loc(r)
                    if loc not in glocs:
                        glocs.append(loc)
                via.append((m.name_of(guid), glocs))
        if via:
            parts = []
            for gname, glocs in via:
                parts.append("via <strong>{}</strong>: <span class='mono'>{}</span>".format(
                    esc(gname), esc(", ".join(glocs))))
            return "<br>".join(parts)
        return '<span class="pill bad">not referenced in export</span>'

    def _fmt_zone_iface_usage(self, uid, limit=8):
        """Gateway interfaces assigned to this security zone (topology)."""
        items = self.model.zone_interfaces.get(uid, [])
        if not items:
            return '<span class="pill bad">no gateway assignment in export</span>'
        parts = []
        for row in items[:limit]:
            label = "{} / {}".format(row["gateway"], row["interface"])
            if row.get("ip"):
                label += " ({})".format(row["ip"])
            parts.append(label)
        text = "; ".join(parts)
        if len(items) > limit:
            text += " … +{}".format(len(items) - limit)
        return "<span class='mono'>{}</span>".format(esc(text))

    def page_packages(self):
        from package_dossier import build_package_dossiers

        dossiers = build_package_dossiers(self.model)

        # Keep generating layer detail pages (linked from dossiers)
        pkg_layers = defaultdict(list)
        shared = []
        for l in self.model.access_layers:
            if l["origin"] == "package":
                pkg_layers[l["package"]].append(l)
            else:
                shared.append(l)
        layer_href = {}
        for pkg, layers in pkg_layers.items():
            for l in layers:
                rel = "layers/{}__{}.html".format(safe_name(pkg), safe_name(l["layer"]))
                self.page_layer(l, rel)
                layer_href[(pkg, l["layer"])] = rel
        for l in shared:
            rel = "layers/shared__{}.html".format(safe_name(l["layer"]))
            self.page_layer(l, rel)
            layer_href[(l.get("package") or "shared", l["layer"])] = rel

        n_pkg = len(dossiers)
        access_total = sum(int(d.get("access_rule_total") or 0) for d in dossiers)
        with_nat = sum(1 for d in dossiers if (d.get("nat") or {}).get("present"))
        gw_names = sorted({g for d in dossiers for g in (d.get("gateways") or []) if g})

        body = [
            '<h2>Packages &amp; Access Layers <span class="count">({})</span></h2>'.format(n_pkg),
            '<div class="note">'
            'Per-package summary of access / NAT / threat / HTTPS surfaces, gateways installing '
            'the package, and object-type counts from the package rulebase dictionaries. '
            'Object counts are <b>UID-deduped</b> across access + NAT + threat + HTTPS for each package.'
            '</div>',
            '<div class="cards">'
            '<div class="card"><div class="n">{}</div><div class="l">Packages</div></div>'
            '<div class="card"><div class="n">{}</div><div class="l">Access rules</div></div>'
            '<div class="card"><div class="n">{}</div><div class="l">With NAT</div></div>'
            '<div class="card"><div class="n">{}</div><div class="l">Gateways</div></div>'
            '</div>'.format(n_pkg, access_total, with_nat, len(gw_names)),
        ]

        for d in dossiers:
            pname = d.get("name") or ""
            body.append(
                '<div class="section-title" id="pkg-{}">{} '
                '<span class="count">({} objects · {} access rules)</span></div>'.format(
                    safe_name(pname), esc(pname),
                    d.get("object_total") or 0, d.get("access_rule_total") or 0))
            if d.get("domain"):
                body.append('<div class="meta">Domain: {}</div>'.format(esc(d["domain"])))

            # Policy surfaces (same primitives as VPN / Global Properties)
            surf_rows = []
            al = d.get("access_layers") or []
            if al:
                bits = []
                for a in al:
                    href = layer_href.get((pname, a.get("name")))
                    label = esc(a.get("name") or "")
                    rc = a.get("rules")
                    suffix = " <span class='muted'>({} rules)</span>".format(rc) if rc is not None else ""
                    if href:
                        bits.append("<a href='{}'>{}</a>{}".format(href, label, suffix))
                    else:
                        bits.append("{}{}".format(label, suffix))
                surf_rows.append(("Access Policy", "<br>".join(bits)))
            else:
                surf_rows.append(("Access Policy", "<span class='muted'>—</span>"))

            nat = d.get("nat") or {}
            if nat.get("present"):
                rc = nat.get("rules")
                nat_txt = "NAT" + (" · {} rules".format(rc) if rc is not None else "")
                surf_rows.append(("NAT", esc(nat_txt)))
            else:
                surf_rows.append(("NAT", "<span class='muted'>No NAT policy</span>"))

            th = d.get("threat_layers") or []
            if th:
                bits = []
                for t in th:
                    label = esc(t.get("name") or "")
                    if t.get("rules") is not None:
                        label += " <span class='muted'>({} rules)</span>".format(t["rules"])
                    bits.append(label)
                surf_rows.append(("Threat Prevention", "<br>".join(bits)))
            else:
                surf_rows.append(("Threat Prevention", "<span class='muted'>—</span>"))

            https = d.get("https_layers") or []
            if https:
                bits = [
                    "<span class='muted'>{}:</span> {}".format(
                        esc(h.get("role") or ""), esc(h.get("name") or ""))
                    for h in https
                ]
                surf_rows.append(("HTTPS Inspection", "<br>".join(bits)))
            else:
                surf_rows.append(("HTTPS Inspection", "<span class='muted'>—</span>"))

            body.append(
                '<div class="table-wrap"><table><thead><tr>'
                '<th>Surface</th><th>Layers / detail</th></tr></thead><tbody>')
            for label, detail in surf_rows:
                body.append("<tr><td>{}</td><td>{}</td></tr>".format(esc(label), detail))
            body.append("</tbody></table></div>")

            gws = d.get("gateways") or []
            body.append(
                '<div class="section-title">Gateways running this package '
                '<span class="count">({})</span></div>'.format(len(gws)))
            if gws:
                body.append(
                    '<div class="table-wrap"><table><thead><tr><th>Gateway</th></tr></thead><tbody>')
                for g in gws:
                    body.append("<tr><td class='mono'>{}</td></tr>".format(esc(g)))
                body.append("</tbody></table></div>")
            else:
                body.append(
                    '<div class="meta">None resolved (check installation-targets / gateway policy).</div>')

            objs = d.get("objects") or []
            body.append(
                '<div class="section-title">Objects by type '
                '<span class="count">({})</span></div>'.format(d.get("object_total") or 0))
            if objs:
                body.append(
                    '<div class="table-wrap"><table><thead><tr>'
                    '<th>Type</th><th>Count</th></tr></thead><tbody>')
                for o in objs:
                    body.append(
                        "<tr><td class='mono'>{}</td><td>{}</td></tr>".format(
                            esc(o["type"]), o["count"]))
                body.append("</tbody></table></div>")
            else:
                body.append('<div class="meta">—</div>')

        if shared:
            shared_unique = sorted(shared, key=lambda x: str(x["layer"]).lower())
            body.append('<div class="section-title">Shared / Inner Access Layers '
                        '<span class="count">({})</span></div>'.format(len(shared_unique)))
            body.append(self.searchbox("shtbl", "shcnt"))
            body.append(
                '<div class="table-wrap"><table id="shtbl"><thead><tr>'
                '<th>Layer</th><th>Rules</th><th></th></tr></thead><tbody>')
            for l in shared_unique:
                rel = layer_href.get((l.get("package") or "shared", l["layer"]),
                                     "layers/shared__{}.html".format(safe_name(l["layer"])))
                body.append('<tr><td>{}</td><td>{}</td><td><a href="{}">view rules →</a></td></tr>'.format(
                    esc(l["layer"]), len(l["rules"]), rel))
            body.append('</tbody></table></div>')

        self.page("packages.html", "Packages", "".join(body))


    def page_layer(self, layer, rel):
        m = self.model
        # layers/ subdir — relative from here to html root is ".."
        page_subdir = "layers"
        obj_data = self._build_obj_data(layer["rules"])
        body = ['<h2>{} <span class="count">/ {}</span></h2>'.format(
            esc(layer["layer"]), esc(layer["package"] or "shared"))]
        body.append('<div class="meta">{} rules</div>'.format(len(layer["rules"])))
        body.append(self.searchbox("tbl", "cnt"))
        body.append('<table id="tbl"><thead><tr><th>#</th><th>Name</th><th>Source</th>'
                    '<th>Destination</th><th>Service</th><th>Action</th><th>Track</th>'
                    '<th>Comments</th></tr></thead><tbody>')
        for rule in layer["rules"]:
            if rule.get("type") != "access-rule":
                continue
            enabled = rule.get("enabled", True)
            action = m.name_of(rule.get("action")) if isinstance(rule.get("action"), str) else "?"
            track = rule.get("track") or {}
            track_name = m.name_of(track.get("type")) if isinstance(track.get("type"), str) else ""
            ihref = self._inline_href(rule, page_subdir)
            cls = "" if enabled else " class='disabled'"
            body.append(
                "<tr id='rule-{n}'{cls}><td>{n}</td><td>{name}</td><td>{src}</td><td>{dst}</td>"
                "<td>{svc}</td><td>{act}</td><td>{trk}</td><td>{cmt}</td></tr>".format(
                    cls=cls, n=esc(rule.get("rule-number", "")), name=esc(rule.get("name", "")),
                    src=self._uid_spans(rule.get("source"), rule.get("source-negate")),
                    dst=self._uid_spans(rule.get("destination"), rule.get("destination-negate")),
                    svc=self._uid_spans(rule.get("service"), rule.get("service-negate")),
                    act=action_tag(action, href=ihref), trk=esc(track_name),
                    cmt=esc((rule.get("comments") or "")[:120]),
                )
            )
        body.append('</tbody></table>')
        self.page(rel, layer["layer"], "".join(body), depth=1, obj_data=obj_data)

    def page_firewall(self):
        """Index page: list all gateways with links to per-gateway detail pages."""
        m = self.model
        topo = self._gateway_topology()
        # build package -> layers and package -> nat maps
        pkg_layers = defaultdict(list)
        for l in m.access_layers:
            if l["origin"] == "package":
                pkg_layers[l["package"]].append(l)
        pkg_nat = {}
        for nat in m.nat_layers:
            pkg_nat[nat["package"]] = nat["rules"]

        policy_rows = []
        other_rows = []
        for gw in sorted(m.gateways, key=lambda g: g.get("name", "")):
            if not isinstance(gw, dict):
                continue
            pol = gw.get("policy") or {}
            pkg_name = pol.get("access-policy-name", "")
            layers = pkg_layers.get(pkg_name, [])
            inner = self._reachable_inner_layers(layers)
            nat_rules = pkg_nat.get(pkg_name, [])
            rule_count = sum(len(l["rules"]) for l in layers + inner)
            layer_cell = format_layer_summary(len(layers), len(inner))
            rel = "gateways/{}.html".format(safe_name(gw.get("name", "unknown")))
            self.page_gateway_detail(gw, pkg_name, layers, nat_rules, rel)
            role = gw_deployment_role(gw)
            row = (
                "<tr><td><a href='{}'>{}</a></td><td>{}</td><td>{}</td><td>{}</td>"
                "<td class='mono'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    rel, esc(gw.get("name")),
                    gw_role_badge(role),
                    esc(gw_ha_label(gw, topo)),
                    self._gw_parent_link(gw),
                    esc(gw.get("version", "")),
                    esc(gw.get("ipv4-address", "")),
                    esc(pkg_name) if pkg_name else "<span class='muted'>—</span>",
                    layer_cell if pkg_name else "<span class='muted'>—</span>",
                    rule_count if pkg_name else "<span class='muted'>—</span>",
                )
            )
            if pkg_name:
                policy_rows.append(row)
            else:
                other_rows.append(row)
        rows = policy_rows + other_rows
        topo_stats = gateway_topology_stats(m.gateways)
        inv = build_physical_inventory(m.gateways, topo)
        trees, standalone_gw = build_platform_trees(m.gateways, inv)
        body = [
            '<h2>Firewall View <span class="count">({} with policy · {} other)</span></h2>'.format(
                len(policy_rows), len(other_rows)),
            '<div class="note">'
            '<b>Top-down view</b> — expand each platform: '
            '<b>L1 Cluster</b> (VSX HA object) → <b>L2 Physical</b> (mgmt/sync per box) → '
            '<b>L3 VSX0</b> (platform policy, e.g. <span class="mono">vsx0-firewalls</span>) → '
            '<b>L4 Virtual</b> (customer policy + data interfaces). '
            'Gateway detail pages show <b>applicable rules first</b> (Install On + Policy Targets); '
            'full shared package is in a collapsible section below.</div>',
            '<div class="cards">'
            '<div class="card"><div class="num">{}</div><div class="lbl">VSX appliances</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Virtual Systems</div></div>'
            '<div class="card warn"><div class="num">{}</div><div class="lbl">HA clusters</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">HA members</div></div>'
            '<div class="card good"><div class="num">{}</div><div class="lbl">With policy</div></div>'
            '</div>'.format(
                topo_stats["vsx_appliances"], topo_stats["virtual_systems"],
                topo_stats["ha_clusters"], topo_stats["ha_members"],
                len(policy_rows),
            ),
            '<div class="section-title">Platform hierarchy <span class="count">({})</span></div>'.format(
                len(trees)),
            '<div class="meta">Same tree as <a href="physical.html">Physical Appliances</a>, '
            'with package + rule counts per level. Also: '
            '<a href="physical.html">physical topology</a>.</div>',
        ]
        body.append(self.searchbox_blocks("fw-hierarchies", "fw-hier-cnt"))
        body.append(self._render_firewall_hierarchy(trees, pkg_layers, topo))
        if standalone_gw:
            body.append(
                '<div class="section-title">Standalone gateways <span class="count">({})</span></div>'.format(
                    len(standalone_gw)))
            body.append('<table><thead><tr><th>Gateway</th><th>IP</th><th>Package</th>'
                        '<th>Applicable / total rules</th></tr></thead><tbody>')
            for row in standalone_gw:
                gw = self._gw_by_name().get(row["name"], {})
                app, total, pkg, _, _ = self._gw_policy_counts(gw, pkg_layers, topo) if gw else (0, 0, "", [], [])
                body.append(
                    "<tr><td><a href='gateways/{}.html'>{}</a></td>"
                    "<td class='mono'>{}</td><td class='mono'>{}</td>"
                    "<td>{} / {}</td></tr>".format(
                        safe_name(row["name"]), esc(row["name"]),
                        esc(row.get("ip") or "—"), esc(pkg or "—"), app, total,
                    )
                )
            body.append('</tbody></table>')
        body.append(
            '<details style="margin-top:24px"><summary class="section-title" style="cursor:pointer">'
            'Flat inventory (all SMS objects)</summary>')
        body.append(
            '<div class="meta" style="margin:8px 0">Every gateway object in SmartConsole — '
            'including cluster, member, VS, mgmt server, and Switch VS.</div>')
        body.append(self.searchbox("tbl", "cnt"))
        body.append('<table id="tbl"><thead><tr><th>Gateway</th><th>Role</th><th>HA / layout</th>'
                    '<th>Parent (VSX / cluster)</th><th>Version</th>'
                    '<th>IP</th><th>Package</th><th>Policy layers</th><th>Rules</th>'
                    '</tr></thead><tbody>')
        body.extend(rows)
        body.append('</tbody></table></details>')
        self.page("firewall.html", "Firewall View", "".join(body))

    def page_gateway_detail(self, gw, pkg_name, layers, nat_rules, rel):
        """Per-gateway drill-down: info + applicable rules + full package."""
        m = self.model
        topo = self._gateway_topology()
        name = gw.get("name", "unknown")
        pol = gw.get("policy") or {}
        ifaces = gw.get("interfaces") or []
        parent_plat = gw_parent_name(gw, topo) or (
            topo.get("child_to_cluster", {}).get(name, ""))

        body = ['<h2>{}</h2>'.format(esc(name))]
        crumb = '<a href="../firewall.html">← Firewall View</a>'
        if parent_plat:
            crumb += ' · <a href="../firewall.html#fw-plat-{}">{}</a>'.format(
                safe_name(parent_plat), esc(parent_plat))
        body.append('<div class="meta">{}</div>'.format(crumb))
        body.append('<div class="note">{}</div>'.format(self._gw_topology_detail_html(gw)))

        # Info cards
        body.append('<div class="cards">')
        for lbl, val in [
            ("Role", gw_deployment_role(gw)),
            ("Version", gw.get("version", "")),
            ("IP", gw.get("ipv4-address", "")),
            ("OS", gw.get("operating-system", "")),
            ("Hardware", gw.get("hardware", "")),
            ("Package", pkg_name),
        ]:
            if val:
                body.append('<div class="card"><div class="n" style="font-size:14px;word-break:break-all">{}</div>'
                            '<div class="l">{}</div></div>'.format(esc(str(val)), esc(lbl)))
        body.append('</div>')

        # Interfaces table
        if ifaces:
            body.append('<div class="section-title">Interfaces <span class="count">({})</span></div>'.format(len(ifaces)))
            body.append('<table><thead><tr><th>Name</th><th>IPv4</th><th>Mask</th><th>Network</th>'
                        '<th>Role</th><th>Topology</th><th>Zone</th><th>Anti-spoof</th></tr></thead><tbody>')
            for iface in ifaces:
                parsed = gw_parse_interface(iface, owner=name)
                if not parsed:
                    continue
                asp = parsed["anti_spoofing"]
                if asp == "off":
                    asp_cell = '<span class="badge b-amber">off</span>'
                elif asp == "on":
                    asp_cell = '<span class="badge b-blue">on</span>'
                else:
                    asp_cell = '<span class="muted">—</span>'
                body.append(
                    "<tr><td class='mono'>{}</td><td class='mono'>{}</td><td class='mono'>{}</td>"
                    "<td class='mono'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        esc(parsed["name"]), esc(parsed["ip"]),
                        esc(("/" + str(parsed["mask"])) if parsed["mask"] else ""),
                        esc(parsed["network"]), esc(parsed["role"]),
                        esc(parsed["topology"]),
                        esc(parsed["zone"]) if parsed["zone"] else "<span class='muted'>—</span>",
                        asp_cell))
            body.append('</tbody></table>')

        inner = self._reachable_inner_layers(layers)
        app_layers, other_layers = filter_access_layers_for_gateway(
            layers, inner, gw, pkg_name, m, topo)
        app_nat, other_nat = filter_nat_rules_for_gateway(nat_rules, gw, pkg_name, m, topo)
        app_rule_count = sum(len(l["rules"]) for l, _ in app_layers)
        total_rule_count = sum(len(l["rules"]) for l in layers + inner)
        page_subdir = "gateways"
        all_rules = [r for l in layers + inner for r in l["rules"]]
        obj_data = self._build_obj_data(all_rules)
        obj_data.update(self._build_obj_data(nat_rules, rule_type="nat-rule"))

        if app_layers:
            if inner:
                count_label = "{} applicable of {} rules ({} ordered + {} inner layers)".format(
                    app_rule_count, total_rule_count, len(layers), len(inner))
            else:
                count_label = "{} applicable of {} rules".format(app_rule_count, total_rule_count)
            body.append(
                '<div class="section-title">Access Layers — this gateway '
                '<span class="count">({})</span></div>'.format(count_label))
            body.append(
                '<div class="note">Rules where <b>Install On</b> is this gateway, its cluster parent, '
                'or <b>Policy Targets</b> (package installed here). '
                'Shared multi-site packages (e.g. <span class="mono">External_HQ</span>) include '
                'rules for other firewalls — see full package below.</div>')
            body.append(self._render_access_layers_tables(
                app_layers, page_subdir, "ly_app_{}".format(safe_name(name))))
        elif layers or inner:
            body.append('<div class="note warnbox">No rules in package <strong>{}</strong> '
                        'match this gateway via Install On / Policy Targets.</div>'.format(
                            esc(pkg_name or "(none)")))
        else:
            body.append('<div class="note warnbox">No access layers found for package <strong>{}</strong>.</div>'.format(
                esc(pkg_name or "(none)")))

        if other_layers and total_rule_count > app_rule_count:
            other_count = sum(len(l["rules"]) for l, _ in other_layers)
            body.append(
                '<details style="margin-top:20px"><summary class="section-title" style="cursor:pointer">'
                'Full package <span class="mono">{}</span> — other install targets '
                '<span class="count">({} rules)</span></summary>'.format(
                    esc(pkg_name), other_count))
            body.append(
                '<div class="note warnbox">These rules are in the same policy package but install on '
                '<i>other</i> gateways (remote sites, shared objects). Not enforced on '
                '<span class="mono">{}</span> unless Install On is changed.</div>'.format(esc(name)))
            body.append(self._render_access_layers_tables(
                other_layers, page_subdir, "ly_all_{}".format(safe_name(name))))
            body.append('</details>')

        # NAT rules — applicable first
        if app_nat or other_nat:
            body.append('<div class="section-title">NAT Rules — this gateway '
                        '<span class="count">({} applicable)</span></div>'.format(len(app_nat)))
            nat_show = app_nat if app_nat else nat_rules
            body.append('<table><thead><tr><th>#</th><th>Name</th><th>Section</th><th>Summary</th>'
                        '<th>Method</th><th>Orig Src</th><th>Orig Dst</th><th>Orig Svc</th>'
                        '<th>Tr Src</th><th>Tr Dst</th><th>Tr Svc</th><th>Tr IPs</th>'
                        '<th>Install On</th><th>Auto</th><th>En</th><th>Comments</th>'
                        '</tr></thead><tbody>')
            for r in nat_show:
                if r.get("type") != "nat-rule":
                    continue
                cls = "" if r.get("enabled", True) else " class='disabled'"
                body.append(
                    "<tr{cls}><td>{n}</td><td>{name}</td><td>{sec}</td><td class='mono'>{brief}</td>"
                    "<td>{meth}</td><td>{os}</td><td>{od}</td><td>{osv}</td>"
                    "<td>{ts}</td><td>{td}</td><td>{tsv}</td><td class='mono'>{addrs}</td>"
                    "<td>{on}</td><td>{auto}</td><td>{en}</td><td>{cmt}</td></tr>".format(
                        cls=cls, n=esc(r.get("rule-number", "")),
                        name=esc(r.get("name", "")),
                        sec=esc(r.get("_section", "")),
                        brief=esc(CheckpointModel.nat_rule_brief(r, m)),
                        meth=esc(r.get("method", "")),
                        os=self._nat_field(r.get("original-source")),
                        od=self._nat_field(r.get("original-destination")),
                        osv=self._nat_field(r.get("original-service")),
                        ts=self._nat_field(r.get("translated-source")),
                        td=self._nat_field(r.get("translated-destination")),
                        tsv=self._nat_field(r.get("translated-service")),
                        addrs=esc(CheckpointModel.nat_translated_addrs(r, m)),
                        on=self._uid_spans(r.get("install-on") or []),
                        auto="yes" if r.get("auto-generated") else "",
                        en="yes" if r.get("enabled", True) else "no",
                        cmt=esc((r.get("comments") or "")[:100]),
                    )
                )
            body.append('</tbody></table>')
            if other_nat:
                body.append(
                    '<details><summary>NAT — other install targets ({} rules)</summary>'.format(
                        len(other_nat)))
                body.append('<table><thead><tr><th>#</th><th>Name</th><th>Install On</th>'
                            '<th>Summary</th></tr></thead><tbody>')
                for r in other_nat:
                    body.append(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                            esc(r.get("rule-number", "")),
                            esc(r.get("name", "")),
                            self._uid_spans(r.get("install-on") or []),
                            esc(CheckpointModel.nat_rule_brief(r, m)[:80]),
                        ))
                body.append('</tbody></table></details>')

        self.page(rel, name, "".join(body), depth=1, obj_data=obj_data)

    def _vpn_peer_row_cells(self, community, topology, role, gw):
        """HTML table row for one VPN community member."""
        name = gw.get("name", "?")
        return (
            esc(community),
            esc(topology),
            esc(role),
            self._gw_link(name),
            esc(gw.get("ipv4-address", "")),
            esc(vpn_peer_kind_label(gw.get("type", ""))),
            esc(gw.get("vsx-name") or "—"),
        )

    def page_vpn(self):
        """VPN communities — summary + flat member list (no duplicate detail blocks)."""
        m = self.model
        meshed = m.vpn_meshed or []
        star = m.vpn_star or []
        remote = m.vpn_remote or []
        communities = (
            [(v, "Meshed") for v in meshed]
            + [(v, "Star") for v in star]
            + [(v, "Remote Access") for v in remote]
        )
        total = len(communities)
        peer_total = sum(1 for v, top in communities for _ in vpn_collect_peers(v, top.lower().split()[0]))

        body = ['<h2>VPN Communities <span class="count">({})</span></h2>'.format(total)]
        body.append(
            '<div class="note">'
            '<b>Meshed</b> — every member tunnels to every other member (site-to-site mesh). '
            '<b>Star</b> — spokes connect through hub gateway(s); typical for cloud/partner VPNs. '
            '<b>Remote Access</b> — Mobile Access / SSL VPN gateways for end users. '
            'Use the <b>All VPN peers</b> table below to search by gateway name or IP.</div>'
        )
        body.append(
            '<div class="cards">'
            '<div class="card"><div class="num">{}</div><div class="lbl">Communities</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Meshed</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Star</div></div>'
            '<div class="card"><div class="num">{}</div><div class="lbl">Remote Access</div></div>'
            '<div class="card good"><div class="num">{}</div><div class="lbl">VPN peers</div></div>'
            '</div>'.format(total, len(meshed), len(star), len(remote), peer_total)
        )

        body.append('<div class="section-title">Community summary</div>')
        body.append(self.searchbox("vpn-summary", "vpn-sum-cnt"))
        body.append(
            '<table id="vpn-summary"><thead><tr>'
            '<th>Community</th><th>Type</th><th>Peers</th><th>Hubs</th><th>Spokes</th>'
            '<th>IKE / crypto</th><th>Routing</th><th>NAT</th><th>Perm. tunnels</th>'
            '<th>User groups</th><th>Comments</th>'
            '</tr></thead><tbody>'
        )
        for vpn, topo in sorted(
            communities,
            key=lambda x: (
                {"Meshed": 0, "Star": 1, "Remote Access": 2}.get(x[1], 9),
                x[0].get("name", "").lower(),
            ),
        ):
            topo_key = topo.lower().split()[0]
            hubs = len(vpn.get("center-gateways") or []) if topo_key == "star" else 0
            spokes = len(vpn.get("satellite-gateways") or []) if topo_key == "star" else 0
            if topo_key == "meshed":
                peers = len(vpn.get("gateways") or [])
            elif topo_key == "star":
                peers = hubs + spokes
            else:
                peers = len(vpn.get("gateways") or [])
            peer_cell = str(peers)
            if peers == 0:
                peer_cell = '<span class="pill bad">0</span>'
            body.append(
                "<tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                "<td class='mono' style='font-size:11px'>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                "<td>{}</td><td class='muted'>{}</td></tr>".format(
                    esc(vpn.get("name", "?")),
                    esc(topo),
                    peer_cell,
                    hubs if topo_key == "star" else "—",
                    spokes if topo_key == "star" else "—",
                    esc(vpn_ike_summary(vpn) or "—"),
                    esc(vpn_routing_label(vpn)),
                    esc(vpn_nat_label(vpn) if topo_key == "star" else "—"),
                    esc(vpn_permanent_tunnels_label(vpn) if topo_key == "star" else "—"),
                    esc(vpn_user_groups_label(vpn) if topo_key == "remote" else "—"),
                    esc((vpn.get("comments") or "")[:80]),
                )
            )
        body.append('</tbody></table>')

        body.append('<div class="section-title">All VPN peers <span class="count">({})</span></div>'.format(peer_total))
        body.append('<div class="note">One row per gateway/peer in a community. '
                    '3rd-party peers are <span class="mono">interoperable-device</span> objects (partner firewalls). '
                    'VSX members show the parent VS name.</div>')
        body.append(self.searchbox("vpn-peers", "vpn-peer-cnt"))
        body.append(
            '<div class="table-wrap"><table id="vpn-peers"><thead><tr>'
            '<th>Community</th><th>Type</th><th>Role</th><th>Gateway / peer</th>'
            '<th>VPN IP</th><th>Device</th><th>VSX parent</th>'
            '</tr></thead><tbody>'
        )
        for vpn, topo in sorted(
            communities,
            key=lambda x: (
                {"Meshed": 0, "Star": 1, "Remote Access": 2}.get(x[1], 9),
                x[0].get("name", "").lower(),
            ),
        ):
            topo_key = topo.lower().split()[0]
            cname = vpn.get("name", "?")
            for role, gw in vpn_collect_peers(vpn, topo_key):
                cells = self._vpn_peer_row_cells(cname, topo, role, gw)
                body.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                            "<td class='mono'>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(*cells))
        body.append('</tbody></table></div>')

        if not total:
            body.append('<div class="note warnbox">No VPN community exports found. '
                          'Re-collect with <span class="mono">checkpoint_collect_data.py</span>.</div>')

        self.page("vpn.html", "VPN Communities", "".join(body))

    @staticmethod
    def _fmt_gp_value(val):
        """Render a global-property scalar; flag booleans with a badge."""
        if isinstance(val, bool):
            return ('<span class="badge b-green">enabled</span>' if val
                    else '<span class="badge">disabled</span>')
        if isinstance(val, (dict, list)):
            return '<span class="muted">(nested — {} entries)</span>'.format(
                len(val) if val else 0)
        return esc(val)

    def _gp_section_table(self, section, order=None, labels=None):
        """Render one global-properties sub-dict as a 2-column table.
        Scalars only; nested dicts get a summary row so nothing is silently dropped."""
        if not isinstance(section, dict) or not section:
            return '<div class="muted">Not present in this export.</div>'
        labels = labels or {}
        keys = list(order) if order else []
        for k in section:
            if k not in keys:
                keys.append(k)
        rows = ['<table><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>']
        for k in keys:
            if k not in section:
                continue
            label = labels.get(k, k.replace("-", " ").capitalize())
            rows.append('<tr><td>{}<div class="muted mono" style="font-size:11px">{}</div></td>'
                        '<td>{}</td></tr>'.format(
                            esc(label), esc(k), self._fmt_gp_value(section[k])))
        rows.append('</tbody></table>')
        return "".join(rows)

    def page_global_properties(self):
        m = self.model
        gp = m.global_properties or {}
        body = ['<h2>Global Properties &amp; Implied Rules '
                '<span class="vendor-chip">Check Point</span></h2>']

        if not gp:
            body.append('<div class="note warnbox">No <span class="mono">global-properties.json</span> '
                        'in this export. Re-collect with the updated '
                        '<span class="mono">checkpoint_collect_data.py</span> to capture implied rules, '
                        'global NAT, and stateful-inspection settings.</div>')
            self.page("global-properties.html", "Global Properties", "".join(body))
            return

        fw = gp.get("firewall") or {}
        # Pair each implied-rule boolean with its position field; keep unknown accept-* too.
        implied = []
        seen = set()
        for key, (label, why) in IMPLIED_RULE_LABELS.items():
            if key in fw:
                implied.append((key, label, why, fw.get(key), fw.get(key + "-position")))
                seen.add(key)
        for key in fw:
            if key.endswith("-position") or key in seen:
                continue
            if isinstance(fw.get(key), bool) and key.startswith("accept"):
                label = key.replace("-", " ").capitalize()
                implied.append((key, label, "", fw.get(key), fw.get(key + "-position")))
        enabled_ct = sum(1 for *_x, val, _pos in implied if val is True)

        body.append(
            '<div class="note"><b>Implied rules permit traffic that never appears in the '
            'explicit rulebase.</b> Every <b>enabled</b> implied rule below is real, live '
            'allowed traffic on these gateways. On migration to Palo Alto / Fortinet it must be '
            'reproduced as an <b>explicit</b> rule — the target platform has no equivalent hidden '
            'ruleset. This page reads <span class="mono">global-properties.json</span>.</div>')

        body.append(self._cards([
            (enabled_ct, "Implied rules ENABLED", "warn" if enabled_ct else "good"),
            (len(implied), "Implied rules evaluated", ""),
            ("yes" if (gp.get("nat") or {}).get("allow-bi-directional-nat") else "no",
             "Bi-directional NAT", ""),
            ("on" if (gp.get("hit-count") or {}).get("enable-hit-count") else "off",
             "Hit count", ""),
        ]))

        # ---- Implied rules table ----
        body.append('<div class="section-title">Implied Rules (hidden rulebase)</div>')
        body.append('<table><thead><tr><th>Implied rule</th><th>Status</th><th>Position</th>'
                    '<th>Why it exists / migration note</th></tr></thead><tbody>')
        if not implied:
            body.append('<tr><td colspan="4" class="muted">No implied-rule flags in firewall section.</td></tr>')
        for key, label, why, val, pos in implied:
            if val is True:
                status = '<span class="badge b-green">ENABLED — permits traffic</span>'
            else:
                status = '<span class="badge">disabled</span>'
            body.append('<tr><td>{}<div class="muted mono" style="font-size:11px">{}</div></td>'
                        '<td>{}</td><td class="mono">{}</td><td>{}</td></tr>'.format(
                            esc(label), esc(key), status, esc(pos or "—"), esc(why or "")))
        body.append('</tbody></table>')

        # ---- Global NAT ----
        body.append('<div class="section-title">Global NAT settings</div>')
        body.append('<div class="note">Estate-wide NAT behavior applied on top of per-rule and '
                    'object NAT. <b>Bi-directional NAT</b> and automatic ARP affect how automatic '
                    'NAT rules expand at enforcement.</div>')
        body.append(self._gp_section_table(gp.get("nat"), labels={
            "allow-bi-directional-nat": "Allow bi-directional NAT",
            "auto-arp-conf": "Automatic ARP configuration",
            "enable-ip-pool-nat": "Enable IP Pool NAT",
        }))

        # ---- Stateful inspection ----
        body.append('<div class="section-title">Stateful Inspection</div>')
        body.append('<div class="note">Connection timeouts and out-of-state handling. These change '
                    'session behavior and should be compared to target-platform defaults during migration.</div>')
        body.append(self._gp_section_table(gp.get("stateful-inspection"), labels={
            "tcp-session-timeout": "TCP session timeout (s)",
            "udp-virtual-session-timeout": "UDP virtual session timeout (s)",
            "icmp-virtual-session-timeout": "ICMP virtual session timeout (s)",
            "drop-out-of-state-tcp-packets": "Drop out-of-state TCP",
            "drop-out-of-state-icmp-packets": "Drop out-of-state ICMP",
            "drop-out-of-state-sctp-packets": "Drop out-of-state SCTP",
        }))

        # ---- VPN + Remote Access ----
        body.append('<div class="section-title">VPN (global)</div>')
        body.append(self._gp_section_table(gp.get("vpn"), labels={
            "vpn-conf-method": "VPN configuration method",
        }))
        body.append('<div class="section-title">Remote Access (global)</div>')
        body.append(self._gp_section_table(gp.get("remote-access")))

        # ---- Hit count + logging ----
        body.append('<div class="section-title">Hit Count</div>')
        body.append(self._gp_section_table(gp.get("hit-count")))
        body.append('<div class="section-title">Log &amp; Alert</div>')
        body.append(self._gp_section_table(gp.get("log-and-alert")))

        # ---- Per-package HTTPS inspection layer wiring (from package.json) ----
        if m.package_meta:
            body.append('<div class="section-title">HTTPS Inspection layers per package</div>')
            body.append('<div class="note">From each package\'s <span class="mono">package.json</span> '
                        '(install-target and HTTPS-layer wiring not present in the top-level '
                        '<span class="mono">packages.json</span>).</div>')
            body.append('<table><thead><tr><th>Package</th><th>Domain</th>'
                        '<th>Inbound HTTPS layer</th><th>Outbound HTTPS layer</th></tr></thead><tbody>')
            for name in sorted(m.package_meta):
                doc = m.package_meta[name]
                dom = (doc.get("domain") or {}).get("name", "")
                hil = doc.get("https-inspection-layers") or {}
                inb = (hil.get("inbound-https-layer") or {}).get("name", "—")
                outb = (hil.get("outbound-https-layer") or {}).get("name", "—")
                body.append('<tr><td>{}</td><td class="mono">{}</td><td>{}</td><td>{}</td></tr>'.format(
                    esc(name), esc(dom), esc(inb), esc(outb)))
            body.append('</tbody></table>')

        self.page("global-properties.html", "Global Properties", "".join(body))

    def page_nat(self):
        m = self.model
        all_nat_rules = []
        for nat in m.nat_layers:
            all_nat_rules.extend(
                r for r in nat["rules"] if r.get("type") == "nat-rule"
            )
        total_rules = len(all_nat_rules)
        obj_data = self._build_obj_data(all_nat_rules, rule_type="nat-rule")
        body = ['<h2>NAT Rules <span class="count">({} rules · {} packages)</span></h2>'.format(
            total_rules, len(m.nat_layers))]
        body.append('<div class="note">Manual and auto-generated NAT from '
                    '<span class="mono">show-nat-rulebase</span>. '
                    '<b>Original</b> = leave field untranslated. '
                    '<b>Summary</b> interprets static/hide rules (incl. service port-map and translated IPs). '
                    'Click any object for details. '
                    'IPs in parentheses come from the per-package object dictionary.</div>')
        for nat in sorted(m.nat_layers, key=lambda n: n["package"]):
            rules = [r for r in nat["rules"] if r.get("type") == "nat-rule"]
            body.append('<div class="section-title">{} <span class="count">({} rules)</span></div>'.format(
                esc(nat["package"]), len(rules)))
            body.append('<table><thead><tr><th>#</th><th>Name</th><th>Section</th><th>Summary</th>'
                        '<th>Method</th><th>Orig Src</th><th>Orig Dst</th><th>Orig Svc</th>'
                        '<th>Tr Src</th><th>Tr Dst</th><th>Tr Svc</th><th>Tr IPs</th>'
                        '<th>Install On</th><th>Auto</th><th>En</th><th>Comments</th>'
                        '</tr></thead><tbody>')
            for r in rules:
                cls = "" if r.get("enabled", True) else " class='disabled'"
                body.append(
                    "<tr{cls}><td>{n}</td><td>{name}</td><td>{sec}</td><td class='mono'>{brief}</td>"
                    "<td>{meth}</td><td>{os}</td><td>{od}</td><td>{osv}</td>"
                    "<td>{ts}</td><td>{td}</td><td>{tsv}</td><td class='mono'>{addrs}</td>"
                    "<td>{on}</td><td>{auto}</td><td>{en}</td><td>{cmt}</td></tr>".format(
                        cls=cls, n=esc(r.get("rule-number", "")),
                        name=esc(r.get("name", "")),
                        sec=esc(r.get("_section", "")),
                        brief=esc(CheckpointModel.nat_rule_brief(r, m)),
                        meth=esc(r.get("method", "")),
                        os=self._nat_field(r.get("original-source")),
                        od=self._nat_field(r.get("original-destination")),
                        osv=self._nat_field(r.get("original-service")),
                        ts=self._nat_field(r.get("translated-source")),
                        td=self._nat_field(r.get("translated-destination")),
                        tsv=self._nat_field(r.get("translated-service")),
                        addrs=esc(CheckpointModel.nat_translated_addrs(r, m)),
                        on=self._uid_spans(r.get("install-on") or []),
                        auto="yes" if r.get("auto-generated") else "",
                        en="yes" if r.get("enabled", True) else "no",
                        cmt=esc((r.get("comments") or "")[:100]),
                    )
                )
            body.append('</tbody></table>')
        self.page("nat.html", "NAT", "".join(body), obj_data=obj_data)

    def page_threat(self):
        m = self.model
        layers = sorted(m.threat_layers, key=lambda t: (t["package"], t["layer"]))
        total_rules = sum(len(t["rules"]) for t in layers)
        exc_files = len(m.threat_exceptions)
        body = ['<h2>Threat Prevention <span class="count">({} rules · {} layers)</span></h2>'.format(
            total_rules, len(layers))]
        body.append('<div class="note">IPS / Anti-Bot / Anti-Virus / Threat Emulation are applied by '
                    'assigning a <b>threat profile</b> as the rule Action (see '
                    '<a href="threat-profiles.html">Threat Profiles</a> for blade settings). '
                    'Standalone <span class="mono">IPS</span> layers are often empty when protections '
                    'are merged into the Threat Prevention layer — that is a policy design choice, '
                    'not a missing export.</div>')
        if not layers:
            body.append('<div class="note warnbox">No threat rulebases found. Re-collect with the '
                        'current collector.</div>')
            self.page("threat.html", "Threat Prevention", "".join(body))
            return
        if total_rules and not m.threat_profiles_with_blade_detail():
            body.append('<div class="note warnbox">Threat rules reference profiles by name, but this '
                        'export has no full profile blade settings (IPS/AV/Anti-Bot confidence). '
                        'Re-collect with collector <span class="mono">v1.5.3+</span> '
                        '(per-UID <span class="mono">show-threat-profile</span>).</div>')
        if total_rules and not exc_files:
            # Count rules that declare exceptions UIDs but we have no exception files
            need_exc = sum(
                1 for t in layers for r in t["rules"]
                if (r.get("exceptions") or r.get("exceptions-layer"))
            )
            if need_exc:
                body.append('<div class="note warnbox">{} threat rule(s) declare exceptions, but '
                            'exception rulebases were not exported. Re-collect with '
                            '<span class="mono">v1.5.3+</span> to fetch '
                            '<span class="mono">show-threat-rule-exception-rulebase</span>.</div>'.format(
                                need_exc))
        for t in layers:
            body.append('<div class="section-title">{} <span class="count">({} · {} rules)</span></div>'.format(
                esc(t["package"]), esc(t["layer"]), len(t["rules"])))
            body.append('<table><thead><tr><th>#</th><th>Name</th><th>Source</th><th>Destination</th>'
                        '<th>Service</th><th>Protected Scope</th><th>Action (Profile)</th>'
                        '<th>Exceptions</th>'
                        '<th>Track</th><th>Install On</th><th>Enabled</th><th>Comments</th></tr></thead><tbody>')
            for r in t["rules"]:
                if r.get("type") not in ("threat-rule", None):
                    if r.get("type") == "threat-section":
                        continue
                cls = "" if r.get("enabled", True) else " class='disabled'"
                act = r.get("action")
                if isinstance(act, dict):
                    act_html = esc(act.get("name", ""))
                    act_uid = act.get("uid")
                else:
                    act_html = self._obj_span(act) if act else ""
                    act_uid = act if isinstance(act, str) else None
                if act_uid:
                    act_html += ' <a class="muted" href="threat-profiles.html#prof-{}">profile →</a>'.format(
                        esc(act_uid))
                trk = r.get("track")
                trk_html = self._obj_span(trk) if isinstance(trk, str) else esc(
                    (trk or {}).get("name", "") if isinstance(trk, dict) else "")
                ts = r.get("track-settings") or {}
                trk_extra = []
                if ts.get("packet-capture"):
                    trk_extra.append("pcap")
                if ts.get("forensics"):
                    trk_extra.append("forensics")
                if trk_extra:
                    trk_html += ' <span class="muted">({})</span>'.format(esc(", ".join(trk_extra)))
                # Exceptions: prefer exported exception rulebases; else UID count
                exc_docs = m.exceptions_for_rule(
                    r.get("uid"), package=t["package"], rule_name=r.get("name"))
                if exc_docs:
                    n_exc = sum(len(d.get("rules") or []) for d in exc_docs)
                    exc_html = '<a href="#exc-{}">{} exception(s)</a>'.format(
                        esc(r.get("uid") or r.get("name") or ""), n_exc)
                else:
                    n_uids = len(r.get("exceptions") or [])
                    exc_html = ("{} UID ref(s)".format(n_uids) if n_uids
                                else '<span class="muted">—</span>')
                body.append(
                    "<tr{cls}><td>{n}</td><td>{rname}</td><td>{src}</td><td>{dst}</td><td>{svc}</td>"
                    "<td>{psc}</td><td>{act}</td><td>{exc}</td><td>{trk}</td><td>{on}</td>"
                    "<td>{en}</td><td>{cmt}</td></tr>".format(
                        cls=cls, n=esc(r.get("rule-number", "")),
                        rname=esc(r.get("name", "")),
                        src=self._uid_spans(r.get("source") or []),
                        dst=self._uid_spans(r.get("destination") or []),
                        svc=self._uid_spans(r.get("service") or []),
                        psc=self._uid_spans(r.get("protected-scope") or []),
                        act=act_html,
                        exc=exc_html,
                        trk=trk_html,
                        on=self._uid_spans(r.get("install-on") or []),
                        en="yes" if r.get("enabled", True) else "no",
                        cmt=esc((r.get("comments") or "")[:120]),
                    ))
            body.append('</tbody></table>')
            # Exception detail tables for rules in this layer
            for r in t["rules"]:
                exc_docs = m.exceptions_for_rule(
                    r.get("uid"), package=t["package"], rule_name=r.get("name"))
                if not exc_docs:
                    continue
                anchor = esc(r.get("uid") or r.get("name") or "")
                body.append('<div class="section-title" id="exc-{}">Exceptions — {} '
                            '<span class="count">({} / {})</span></div>'.format(
                                anchor, esc(r.get("name") or ""),
                                esc(t["package"]), esc(t["layer"])))
                for ed in exc_docs:
                    body.append('<table><thead><tr><th>#</th><th>Name</th><th>Source</th>'
                                '<th>Destination</th><th>Service</th><th>Protected Scope</th>'
                                '<th>Protection / Site</th><th>Action</th><th>Track</th>'
                                '<th>Install On</th><th>Enabled</th><th>Comments</th>'
                                '</tr></thead><tbody>')
                    for er in ed.get("rules") or []:
                        if er.get("type") == "threat-section":
                            continue
                        ecls = "" if er.get("enabled", True) else " class='disabled'"
                        eact = er.get("action")
                        if isinstance(eact, dict):
                            eact_html = esc(eact.get("name", ""))
                        else:
                            eact_html = self._obj_span(eact) if eact else ""
                        prot = er.get("protection-or-site") or er.get("protection") or []
                        if not isinstance(prot, list):
                            prot = [prot] if prot else []
                        body.append(
                            "<tr{cls}><td>{n}</td><td>{name}</td><td>{src}</td><td>{dst}</td>"
                            "<td>{svc}</td><td>{psc}</td><td>{prot}</td><td>{act}</td>"
                            "<td>{trk}</td><td>{on}</td><td>{en}</td><td>{cmt}</td></tr>".format(
                                cls=ecls,
                                n=esc(er.get("rule-number", "")),
                                name=esc(er.get("name", "")),
                                src=self._uid_spans(er.get("source") or []),
                                dst=self._uid_spans(er.get("destination") or []),
                                svc=self._uid_spans(er.get("service") or []),
                                psc=self._uid_spans(er.get("protected-scope") or []),
                                prot=self._uid_spans(prot),
                                act=eact_html,
                                trk=self._obj_span(er.get("track")) if isinstance(er.get("track"), str)
                                else esc((er.get("track") or {}).get("name", "")
                                         if isinstance(er.get("track"), dict) else ""),
                                on=self._uid_spans(er.get("install-on") or []),
                                en="yes" if er.get("enabled", True) else "no",
                                cmt=esc((er.get("comments") or "")[:100]),
                            ))
                    body.append('</tbody></table>')
        self.page("threat.html", "Threat Prevention", "".join(body))

    def page_threat_profiles(self):
        """IPS / Anti-Bot / Anti-Virus / TE settings from threat profiles."""
        m = self.model
        profiles = sorted(
            m.objects.get("threat-profile", []),
            key=lambda o: (o.get("name") or "").lower(),
        )
        # Deduplicate by uid (stub harvest + objects file can overlap)
        seen = set()
        uniq = []
        for o in profiles:
            uid = o.get("uid")
            if uid and uid in seen:
                # Prefer richer record
                for i, existing in enumerate(uniq):
                    if existing.get("uid") == uid and len(o) > len(existing):
                        uniq[i] = o
                continue
            if uid:
                seen.add(uid)
            uniq.append(o)
        profiles = uniq
        detailed = [o for o in profiles if threat_profile_has_blade_detail(o)]

        body = ['<h2>Threat Profiles <span class="count">({})</span></h2>'.format(len(profiles))]
        body.append('<div class="note">Threat Prevention <b>profiles</b> define how IPS, Anti-Bot, '
                    'Anti-Virus, and Threat Emulation behave. Access rules assign a profile as the '
                    'Threat Prevention Action. Empty standalone IPS layers with a populated TP layer '
                    'usually means protections live here, not in a separate IPS policy.</div>')
        body.append(self._cards([
            (len(profiles), "Profiles", ""),
            (len(detailed), "With blade settings", "good" if detailed else "warn"),
            (len(profiles) - len(detailed), "Name only (need re-collect)",
             "warn" if profiles and not detailed else ""),
        ]))
        if not profiles:
            body.append('<div class="note warnbox">No threat profiles in this export. '
                        'If Threat Prevention rules exist, re-collect with collector '
                        '<span class="mono">v1.5.3+</span>.</div>')
            self.page("threat-profiles.html", "Threat Profiles", "".join(body))
            return
        if profiles and not detailed:
            body.append('<div class="note warnbox">Profile <b>names</b> were recovered from threat '
                        'rulebase dictionaries, but IPS/AV/Anti-Bot/TE settings are missing '
                        '(known <span class="mono">show-threat-profiles</span> empty-list quirk). '
                        'Re-collect with <span class="mono">v1.5.3+</span> to pull per-profile '
                        '<span class="mono">show-threat-profile</span> full detail.</div>')

        rows = []
        for o in profiles:
            uid = o.get("uid") or ""
            rows.append(
                "<tr id='prof-{uid}'><td>{name}</td><td>{ips}</td><td>{abot}</td>"
                "<td>{av}</td><td>{te}</td><td>{cmt}</td></tr>".format(
                    uid=esc(uid),
                    name=self._obj_span(uid) if uid else esc(o.get("name", "")),
                    ips=esc(threat_blade_summary(o, "ips")),
                    abot=esc(threat_blade_summary(o, "anti-bot")),
                    av=esc(threat_blade_summary(o, "anti-virus")),
                    te=esc(threat_blade_summary(o, "threat-emulation")),
                    cmt=esc((o.get("comments") or "")[:120]),
                ))
        body.append(self.inventory_table_section(
            "inv-tprof", "inv-tprof-tbl", "threat-profiles.csv", len(profiles),
            "Filter threat profiles…",
            '<th>Name</th><th>IPS</th><th>Anti-Bot</th><th>Anti-Virus</th>'
            '<th>Threat Emulation</th><th>Comments</th>',
            rows,
        ))
        # Where each profile is used as a TP rule action
        body.append('<h3>Where applied</h3>')
        body.append('<div class="note">Threat rules whose Action is this profile.</div>')
        usage_rows = []
        for o in profiles:
            uid = o.get("uid")
            locs = []
            for layer in m.threat_layers:
                for r in layer.get("rules") or []:
                    act = r.get("action")
                    act_uid = act.get("uid") if isinstance(act, dict) else act
                    if act_uid == uid:
                        locs.append("{} · {} #{} {}".format(
                            layer.get("package"), layer.get("layer"),
                            r.get("rule-number", ""), r.get("name") or ""))
            usage_rows.append("<tr><td>{}</td><td class='mono'>{}</td></tr>".format(
                esc(o.get("name") or uid),
                esc("; ".join(locs) if locs else "(not referenced in exported TP rules)")))
        body.append(self.inventory_table_section(
            "inv-tprof-use", "inv-tprof-use-tbl", "threat-profiles-usage.csv",
            len(usage_rows), "Filter profile usage…",
            '<th>Profile</th><th>Threat rules</th>', usage_rows, show_hint=False,
        ))
        self.page("threat-profiles.html", "Threat Profiles", "".join(body))

    def page_https(self):
        m = self.model
        layers = sorted(m.https_layers, key=lambda h: (h["package"], h["layer"]))
        total_rules = sum(len(h["rules"]) for h in layers)
        body = ['<h2>HTTPS Inspection <span class="count">({} rules across {} package view(s))</span></h2>'.format(
            total_rules, len(layers))]
        body.append('<div class="note">HTTPS Inspection rulebase exported via '
                    '<span class="mono">show-https-rulebase</span>. <b>Bypass</b> rules skip TLS '
                    'inspection for the matched traffic; <b>Inspect</b> rules decrypt and inspect. '
                    'Review Bypass entries to confirm only intended exclusions (e.g. banking, '
                    'healthcare, partner equipment) skip inspection.</div>')
        if not layers:
            body.append('<div class="note warnbox">No HTTPS inspection rulebase was found in this '
                        'export. If HTTPS Inspection is enabled in SmartConsole, re-run the updated '
                        'collector to capture the <span class="mono">https-rulebase-*.json</span> '
                        'files (the singular <span class="mono">https-inspection-layer</span> key is '
                        'now supported).</div>')
            self.page("https.html", "HTTPS Inspection", "".join(body))
            return
        for h in layers:
            body.append('<div class="section-title">{} <span class="count">({} · {} rules)</span></div>'.format(
                esc(h["package"]), esc(h["layer"]), len(h["rules"])))
            body.append('<table><thead><tr><th>#</th><th>Name</th><th>Source</th><th>Destination</th>'
                        '<th>Services</th><th>Site Category</th><th>Action</th><th>Track</th>'
                        '<th>Blade</th><th>Install On</th><th>Certificate</th></tr></thead><tbody>')
            for r in h["rules"]:
                if r.get("type") == "https-section":
                    continue
                cls = "" if r.get("enabled", True) else " class='disabled'"
                action = r.get("action")
                if isinstance(action, dict):
                    action_name = action.get("name", "")
                else:
                    action_name = m.name_of(action) if action else ""
                cat = r.get("site-category") or r.get("service")
                body.append(
                    "<tr{cls}><td>{n}</td><td>{name}</td><td>{src}</td><td>{dst}</td>"
                    "<td>{svc}</td><td>{cat}</td><td>{act}</td><td>{trk}</td><td>{blade}</td>"
                    "<td>{on}</td><td>{cert}</td></tr>".format(
                        cls=cls, n=esc(r.get("rule-number", "")),
                        name=esc(r.get("name", "")),
                        src=esc(m.names_of(r.get("source"))),
                        dst=esc(m.names_of(r.get("destination"))),
                        svc=esc(m.names_of(r.get("service"))),
                        cat=esc(m.names_of(cat) if isinstance(cat, list) else (m.name_of(cat) if cat else "Any")),
                        act=action_tag(action_name or ""),
                        trk=esc(self._track_name(r.get("track"), m)),
                        blade=esc(m.names_of(r.get("blade")) if r.get("blade") else ""),
                        on=esc(m.names_of(r.get("install-on"))),
                        cert=esc(m.name_of(r.get("certificate")) if r.get("certificate") else ""),
                    )
                )
            body.append('</tbody></table>')
        self.page("https.html", "HTTPS Inspection", "".join(body))

    @staticmethod
    def _track_name(track, model=None):
        if isinstance(track, dict):
            return track.get("type") or track.get("name") or ""
        if track and model is not None:
            return model.name_of(track)
        return track or ""

    def page_optimization(self, analysis):
        dup, unused, shadows, permissive, no_log = analysis
        m = self.model
        unused_total = sum(len(v) for v in unused.values())
        shadowed = [s for s in shadows if s["kind"] == "SHADOWED"]
        redundant = [s for s in shadows if s["kind"] == "REDUNDANT"]
        body = ['<h2>Optimization &amp; Hygiene</h2>',
                '<div class="meta">Heuristic findings — review before any change.</div>']
        body.append('<div class="cards">')
        for cls, n, label in (
            ("warn", len(dup), "Duplicate Values"),
            ("warn", unused_total, "Unreferenced Objects"),
            ("bad", len(shadowed), "Shadowed Rules"),
            ("warn", len(redundant), "Redundant Rules"),
            ("bad", len(permissive), "Any/Any/Any Accept"),
            ("warn", len(no_log), "Accept w/o Logging"),
        ):
            body.append('<div class="card {}"><div class="n">{}</div><div class="l">{}</div></div>'.format(
                cls, n, esc(label)))
        body.append('</div>')

        # Duplicates
        body.append('<div class="section-title" id="dup">Duplicate Objects (same value) '
                    '<span class="count">{}</span></div>'.format(len(dup)))
        body.append('<div class="note">Multiple objects share the same IP/subnet/range/port. '
                    'Consolidate to one canonical object to reduce drift.</div>')
        body.append('<table><thead><tr><th>Value</th><th>Type</th><th>#</th><th>Object names</th>'
                    '</tr></thead><tbody>')
        for key, objs in dup[:400]:
            val = " ".join(str(x) for x in key[1:])
            body.append("<tr><td class='mono'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(val), esc(key[0]), len(objs),
                esc(", ".join(o.get("name", "") for o in objs))))
        body.append('</tbody></table>')

        # Unused
        body.append('<div class="section-title" id="unused">Unreferenced Objects '
                    '<span class="count">{}</span></div>'.format(unused_total))
        has_membership = any(self.model.member_index.values())
        if has_membership:
            body.append('<div class="note warnbox">Not referenced in any access rule or NAT rule, '
                        'and not a member of any <em>used</em> group (group membership resolved '
                        'transitively, including nested groups). These are safe candidates to '
                        'review for cleanup.</div>')
        else:
            body.append('<div class="note warnbox">Not referenced in any access rule or NAT rule. '
                        'NOTE: group membership was not captured in this export, so an object used '
                        '<em>only</em> inside a group may appear here. Re-run the updated collector '
                        '(full detail) for definitive results.</div>')
        body.append(self.searchbox("untbl", "uncnt"))
        body.append('<table id="untbl"><thead><tr><th>Name</th><th>Category</th><th>Value</th>'
                    '</tr></thead><tbody>')
        for cat in sorted(unused):
            for obj in unused[cat]:
                val = obj.get("ipv4-address") or obj.get("subnet4") or obj.get("ipv4-address-first") \
                    or obj.get("port") or ""
                body.append("<tr><td class='mono'>{}</td><td>{}</td><td class='mono'>{}</td></tr>".format(
                    esc(obj.get("name")), esc(cat), esc(val)))
        body.append('</tbody></table>')

        # Shadowed
        body.append('<div class="section-title" id="shadow">Shadowed Rules (unreachable) '
                    '<span class="count">{}</span></div>'.format(len(shadowed)))
        body.append('<div class="note warnbox">An earlier enabled rule fully covers these rules with a '
                    'different action, so they never match. Containment is by object set (Any-aware); '
                    'CIDR subset across different objects is not evaluated, so verify each.</div>')
        body.append(self._shadow_table(shadowed))

        # Redundant
        body.append('<div class="section-title" id="redundant">Redundant Rules (same action) '
                    '<span class="count">{}</span></div>'.format(len(redundant)))
        body.append(self._shadow_table(redundant))

        # Permissive
        body.append('<div class="section-title" id="permissive">Any / Any / Any Accept '
                    '<span class="count">{}</span></div>'.format(len(permissive)))
        body.append('<table><thead><tr><th>Package</th><th>Layer</th><th>#</th><th>Name</th>'
                    '<th>Enabled</th></tr></thead><tbody>')
        for r in permissive:
            body.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(r["package"]), esc(r["layer"]), esc(r["no"]), esc(r["name"]),
                "yes" if r["enabled"] else "no"))
        body.append('</tbody></table>')

        self.page("optimization.html", "Optimization", "".join(body))

    def _shadow_table(self, rows):
        out = ['<table><thead><tr><th>Package</th><th>Layer</th><th>Rule #</th><th>Rule name</th>'
               '<th>Action</th><th>Covered by #</th><th>Earlier name</th><th>Earlier action</th>'
               '</tr></thead><tbody>']
        for f in rows[:1000]:
            out.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    esc(f["package"]), esc(f["layer"]), esc(f["later_no"]), esc(f["later_name"]),
                    action_tag(f["later_action"]), esc(f["earlier_no"]), esc(f["earlier_name"]),
                    action_tag(f["earlier_action"])))
        out.append('</tbody></table>')
        return "".join(out)

    def _loc_table(self, rows, extra_cols=None):
        extra_cols = extra_cols or []
        head = "".join("<th>{}</th>".format(esc(c[0])) for c in extra_cols)
        out = ['<table><thead><tr><th>Package</th><th>Layer</th><th>Rule #</th><th>Name</th>{}'
               '</tr></thead><tbody>'.format(head)]
        for r in rows[:2000]:
            extra = "".join("<td>{}</td>".format(esc(r.get(c[1], ""))) for c in extra_cols)
            out.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>{}</tr>".format(
                esc(r.get("package", "")), esc(r.get("layer", "")), esc(r.get("no", "")),
                esc(r.get("name", "")), extra))
        out.append('</tbody></table>')
        return "".join(out)

    def page_simplify(self, merge):
        total = sum(len(v) for v in merge.values())

        def layer_href(r):
            if r.get("origin") == "shared":
                return "layers/shared__{}.html".format(safe_name(r["layer"]))
            return "layers/{}__{}.html".format(safe_name(r["package"]), safe_name(r["layer"]))

        body = ['<h2>Simplify &amp; Merge <span class="count">({} groups)</span></h2>'.format(total),
                '<div class="note">Groups of enabled rules in the same layer that are identical '
                'except for one field — they can be collapsed into a single rule by combining that '
                'field. Verify intent (logging, order, install-on) before merging. '
                'The <strong>Rule numbers</strong> column lists each rule\u2019s position (sequence) '
                'in that layer — click any number to jump straight to that rule, or click the '
                '<strong>layer name</strong> to open its full rulebase.</div>']
        body.append(self._cards([
            (len(merge["service"]), "Merge SERVICES", "warn" if merge["service"] else ""),
            (len(merge["destination"]), "Merge DESTINATIONS", "warn" if merge["destination"] else ""),
            (len(merge["source"]), "Merge SOURCES", "warn" if merge["source"] else ""),
        ]))
        labels = {
            "service": ("Merge SERVICES", "same Source + Destination + Action; combine services"),
            "destination": ("Merge DESTINATIONS", "same Source + Service + Action; combine destinations"),
            "source": ("Merge SOURCES", "same Destination + Service + Action; combine sources"),
        }
        for dim in ("service", "destination", "source"):
            rows = merge[dim]
            title, desc = labels[dim]
            body.append('<div class="section-title" id="merge-{}">{} '
                        '<span class="count">{} — {}</span></div>'.format(dim, title, len(rows), esc(desc)))
            body.append('<table><thead><tr><th>Package</th><th>Layer</th><th>Action</th>'
                        '<th>#Rules</th><th>Rule numbers</th><th>Shared fields</th>'
                        '</tr></thead><tbody>')
            for r in rows[:1000]:
                shared = " · ".join("{}={}".format(k, v) for k, v in r["sample_fixed"].items())
                href = layer_href(r)
                nums = " ".join(
                    "<a class='pill' href='{}#rule-{}'>{}</a>".format(href, n, esc(str(n)))
                    for n in r["rule_numbers"])
                layer_link = "<a href='{}'>{}</a>".format(href, esc(str(r["layer"])))
                body.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                            "<td>{}</td><td class='mono'>{}</td></tr>".format(
                                esc(r["package"]), layer_link, action_tag(r["action"]),
                                r["count"], nums, esc(shared[:200])))
            body.append('</tbody></table>')
        self.page("simplify.html", "Simplify", "".join(body))

    def _obj_value_str(self, obj):
        m = self.model
        t = obj.get("type", "")
        if obj.get("ipv4-address"):
            return obj["ipv4-address"]
        if t == "network":
            return "{}/{}".format(obj.get("subnet4", ""), obj.get("mask-length4", ""))
        if t == "address-range":
            return "{}–{}".format(obj.get("ipv4-address-first", ""), obj.get("ipv4-address-last", ""))
        if t in ("service-tcp", "service-udp"):
            return "{}/{}".format("tcp" if t == "service-tcp" else "udp", obj.get("port", ""))
        if t == "service-icmp":
            return "icmp {}".format(obj.get("icmp-type", ""))
        if t in ("group", "service-group"):
            return "{} members".format(len(m.member_index.get(obj.get("uid"), ())))
        return ""

    def _ref_loc(self, r):
        if r["kind"] == "nat":
            return "NAT · {} #{} ({})".format(r["package"], r["num"], r["field"])
        if r["kind"] in ("native-direct", "native-indirect"):
            return "CP where-used · {} ({})".format(r["layer"], r["field"])
        return "{} ▸ {} #{} ({})".format(r["package"] or "?", r["layer"], r["num"], r["field"])

    def page_relationships(self):
        """Where-Used / cross-reference: every object and the rules, NAT rules,
        and groups that reference it. Most-referenced first."""
        m = self.model
        skip = {"access-layer", "RulebaseAction", "Global", "Track", "CpmiAnyObject"}
        uids = [u for u in m.where_used if m.ref_count(u) > 0]
        uids.sort(key=lambda u: -m.ref_count(u))

        rows = []
        total_refs = 0
        for uid in uids:
            obj = m.by_uid.get(uid)
            if not isinstance(obj, dict) or obj.get("type", "") in skip:
                continue
            refs = [r for r in m.where_used[uid]
                    if r["kind"] in ("access", "nat", "native-direct", "native-indirect")]
            nrefs = len(refs)
            total_refs += nrefs
            groups = sorted(m.name_of(g) for g in m.member_of.get(uid, set()))
            grp_str = ", ".join(groups[:6]) + (" +{}".format(len(groups) - 6) if len(groups) > 6 else "")
            locs = [self._ref_loc(r) for r in refs[:8]]
            ref_str = "; ".join(locs) + (" … +{} more".format(nrefs - 8) if nrefs > 8 else "")
            rows.append(
                "<tr><td>{nm}</td><td class='mono'>{ty}</td><td class='mono'>{val}</td>"
                "<td>{n}</td><td>{grp}</td><td style='font-size:11px;color:#9aa7c0'>{rf}</td></tr>".format(
                    nm=esc(obj.get("name", uid)), ty=esc(obj.get("type", "")),
                    val=esc(self._obj_value_str(obj)), n=nrefs,
                    grp=esc(grp_str), rf=esc(ref_str)))

        body = ['<h2>Relationships <span class="count">(Where-Used)</span></h2>']
        if m.uses_native_where_used:
            body.append('<div class="note goodbox">Native Check Point <span class="mono">where-used</span> '
                        'data is merged with rulebase-inferred references (collected with '
                        '<span class="mono">--where-used</span>).</div>')
        else:
            body.append('<div class="note warnbox">References are inferred from access/NAT rulebases only. '
                        'For ground-truth where-used (including indirect refs), re-collect with '
                        '<span class="mono">--where-used</span>. See '
                        '<a href="coverage.html">Export Coverage</a>.</div>')
        body.append('<div class="note">Every object and the rules, NAT rules, and groups that reference it — '
                    'the cross-reference view. Sorted by reference count (most-used first). '
                    'Click a column header to sort, type to filter.')
        if not self.browse_only:
            body[-1] += (
                ' Objects with <strong>0</strong> references are listed on '
                '<a href="optimization.html#unused">Optimization → Unused</a>.')
        body[-1] += '</div>'
        body.append('<div class="cards"><div class="card"><div class="n">{}</div>'
                    '<div class="l">Referenced objects</div></div>'
                    '<div class="card"><div class="n">{}</div><div class="l">Total references</div></div></div>'.format(
                        len(rows), total_refs))
        body.append(self.searchbox("tbl", "cnt"))
        body.append('<div class="meta"><span id="cnt"></span></div>')
        body.append('<table id="tbl"><thead><tr><th>Object</th><th>Type</th><th>Value</th>'
                    '<th>#Refs</th><th>In Groups</th><th>Referenced By</th></tr></thead><tbody>')
        body.extend(rows)
        body.append('</tbody></table>')
        self.page("relationships.html", "Relationships", "".join(body))

    def page_compliance(self, controls, detail, intel=None):
        intel = intel or {"kev": set(), "nvd": {}}
        kev = intel.get("kev", set())
        controls = list(controls)
        kev_cves = [c["cve"] for c in KNOWN_CVES if c["cve"] in kev]
        if kev_cves:
            controls.append({
                "id": "RA-5 / SI-2", "csf": "ID.RA-1, RS.MI-3", "cis": "CIS 7.x", "sev": "high",
                "title": "Advisories on the CISA KEV (actively exploited in the wild)",
                "count": len(kev_cves), "page": "risk.html", "anchor": "",
                "why": "These Check Point advisories are confirmed exploited in the wild ({}); "
                       "verify the Jumbo Hotfix on VPN/Remote-Access gateways as top priority.".format(
                           ", ".join(kev_cves)),
            })
        body = ['<h2>Compliance Mapping <span class="count">(NIST 800-53 · NIST CSF · CIS Check Point)</span></h2>',
                '<div class="note">Heuristic, data-driven mapping of configuration findings to common '
                'control families. Use as an audit starting point, not a certification. Counts link to '
                'the underlying items.</div>']
        body.append('<table><thead><tr><th>Sev</th><th>NIST 800-53</th><th>NIST CSF</th>'
                    '<th>CIS</th><th>Finding</th><th>Count</th><th>Rationale</th>'
                    '</tr></thead><tbody>')
        sev_rank = {"high": 0, "medium": 1, "low": 2}
        for c in sorted(controls, key=lambda x: (sev_rank.get(x["sev"], 9), -x["count"])):
            body.append('<tr><td>{}</td><td class="mono">{}</td><td class="mono">{}</td>'
                        '<td class="mono">{}</td><td><a href="{}#{}">{}</a></td><td>{}</td>'
                        '<td>{}</td></tr>'.format(
                            sev_badge(c["sev"]), esc(c["id"]), esc(c["csf"]), esc(c["cis"]),
                            c["page"], c["anchor"], esc(c["title"]), c["count"], esc(c["why"])))
        body.append('</tbody></table>')

        sections = [
            ("anysvc", "Accept rules permitting Any service (CM-7)", []),
            ("nolog", "Accept rules without logging (AU-2 / AU-12)", []),
            ("nocomment", "Rules without change documentation (CM-3)", []),
            ("stale", "Stale rules — not modified in 3+ years (CM-2)", [("Years", "years")]),
            ("disabled", "Disabled rules left in policy (AC-3)", []),
        ]
        for anchor, title, cols in sections:
            rows = detail.get(anchor, [])
            body.append('<div class="section-title" id="{}">{} '
                        '<span class="count">{}</span></div>'.format(anchor, esc(title), len(rows)))
            body.append(self._loc_table(rows, cols))
        self.page("compliance.html", "Compliance", "".join(body))

    def page_risk(self, versions, intel=None):
        intel = intel or {"kev": set(), "nvd": {}, "source": "curated"}
        kev = intel.get("kev", set())
        nvd = intel.get("nvd", {})
        epss = intel.get("epss", {}) or {}
        discovered = intel.get("discovered", {}) or {}
        src = esc(intel.get("source", "curated"))

        def _epss_of(cid):
            try:
                return float(epss.get(cid) or 0)
            except (TypeError, ValueError):
                return 0.0

        def _epss_badge(cid):
            s = _epss_of(cid)
            if not s:
                return ""
            return ' <span class="pill">EPSS {:.1%}</span>'.format(s)
        rev = versions["cve_review"]
        ra_names = [r["name"] for r in rev]
        body = ['<h2>Software Versions &amp; CVE Awareness</h2>',
                '<div class="note">Severity and the actively-exploited flag are pulled live from '
                f'<strong>{src}</strong> (CISA KEV = exploited in the wild; NVD = current CVSS). '
                'A management export does not expose the exact Jumbo Hotfix take, so per-gateway status '
                'is shown as <strong>verify</strong> for gateways that meet each advisory\u2019s condition '
                '\u2014 we never assert an unverifiable \u201cvulnerable\u201d.</div>']

        # Summary cards
        kev_applicable = [c["cve"] for c in KNOWN_CVES if c["cve"] in kev and (c["cond"] != "ra" or ra_names)]
        body.append(self._cards([
            (len(versions["gateways"]), "Gateways", ""),
            (len(ra_names), "VPN / Remote-Access facing", "warn" if ra_names else ""),
            (len(kev_applicable), "Exploited (CISA KEV) & applicable", "bad" if kev_applicable else ""),
            (sum(1 for g in versions["gateways"] if g["eol"]), "End-of-support train", ""),
        ]))

        # version inventory
        body.append('<div class="section-title">Gateway version inventory</div>')
        body.append('<table><thead><tr><th>Version</th><th>Gateways</th><th>Status</th></tr></thead><tbody>')
        for ver, n in versions["by_version"].items():
            status = sev_badge("high") + " EOL — verify lifecycle" if ver in EOL_VERSIONS else \
                '<span class="pill">supported (verify JHF)</span>'
            body.append("<tr><td class='mono'>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(ver), n, status))
        body.append('</tbody></table>')

        # CVE list — live severity + KEV + applicable gateways
        # Priority order: KEV (exploited) first, then EPSS, then CVSS.
        def _cvss_of(cid, fallback=0.0):
            try:
                return float(nvd.get(cid, {}).get("cvss") or fallback)
            except (TypeError, ValueError):
                return fallback

        ordered = sorted(KNOWN_CVES, key=lambda c: (
            c["cve"] in kev, _epss_of(c["cve"]), _cvss_of(c["cve"])), reverse=True)
        body.append('<div class="section-title">Check Point advisories — matched to your gateways</div>')
        for c in ordered:
            meta = nvd.get(c["cve"], {})
            if meta.get("cvss"):
                sev_lbl = meta.get("sev") or ""
                sev_txt = f"CVSS {meta['cvss']}" + (f" {sev_lbl}" if sev_lbl else "")
            else:
                sev_txt = c["sev"]
            kev_badge = (' <span class="badge b-red">CISA KEV — exploited</span>'
                         if c["cve"] in kev else "")
            link = meta.get("url", "https://nvd.nist.gov/vuln/detail/{}".format(c["cve"]))
            applies = ra_names if c["cond"] == "ra" else [g["name"] for g in versions["gateways"]]
            if applies:
                tally = '<span class="badge b-amber">{} to verify (JHF)</span>'.format(len(applies))
                detail = '<br><em>Verify JHF on:</em> <span class="mono">{}</span>'.format(
                    esc(", ".join(sorted(applies))))
            else:
                tally = '<span class="muted">no gateways meet this condition</span>'
                detail = ""
            body.append(
                '<div class="note"><strong><a href="{}" target="_blank" rel="noopener">{}</a></strong>'
                ' — {}{}<br><span class="pill">{}</span> &nbsp; {}<br>'
                '<em>Affected:</em> {}<br><em>Action:</em> {}{}</div>'.format(
                    esc(link), esc(c["cve"]), esc(c["summary"]),
                    kev_badge + _epss_badge(c["cve"]),
                    esc(sev_txt), tally, esc(c["affected"]), esc(c["action"]), detail))

        # Tier 2 — NVD CPE discovery (informational only; never drives compliance)
        curated_ids = {c["cve"] for c in KNOWN_CVES}
        if discovered:
            body.append('<div class="section-title">Discovered via NVD CPE — informational</div>')
            body.append('<div class="note">Everything NVD matches to the exact Gaia OS versions in '
                        'this export (beyond the curated advisories above). <strong>Informational '
                        'only — verify applicability</strong>; these never affect compliance '
                        'findings. Sorted by KEV, then EPSS, then CVSS.</div>')
        for cpe, entries in sorted(discovered.items()):
            extra = [e for e in entries if e.get("cve") not in curated_ids]
            label = "{} — {} CVEs ({} beyond curated)".format(cpe, len(entries), len(extra))
            rows = []
            for e in sorted(extra, key=lambda e: (
                    e.get("cve") in kev, _epss_of(e.get("cve")),
                    float(e.get("cvss") or 0)), reverse=True):
                kevb = (' <span class="badge b-red">KEV</span>'
                        if e.get("cve") in kev else "")
                ep = _epss_of(e.get("cve"))
                rows.append(
                    "<tr><td class='mono'><a href='{}' target='_blank' rel='noopener'>{}</a>{}</td>"
                    "<td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                        esc(e.get("url", "")), esc(e.get("cve", "")), kevb,
                        esc(str(e.get("cvss", "") or "—")),
                        esc(e.get("severity", "") or "—"),
                        "{:.1%}".format(ep) if ep else "—",
                        esc((e.get("summary") or "")[:220])))
            if not rows:
                rows.append("<tr><td colspan='5' class='muted'>No CVEs beyond the curated set.</td></tr>")
            body.append(
                '<details><summary class="mono">{}</summary>'
                '<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th>'
                '<th>Summary</th></tr></thead><tbody>{}</tbody></table></details>'.format(
                    esc(label), "".join(rows)))

        # full gateway version table
        body.append('<div class="section-title">All gateways</div>')
        body.append(self.searchbox("gvtbl", "gvcnt"))
        body.append('<table id="gvtbl"><thead><tr><th>Gateway</th><th>Type</th><th>Version</th>'
                    '<th>Access Policy</th><th>Flags</th></tr></thead><tbody>')
        for g in versions["gateways"]:
            flags = []
            if g["eol"]:
                flags.append(sev_badge("high") + " EOL")
            if g["remote_access"]:
                flags.append('<span class="badge b-amber">VPN/RA</span>')
            body.append("<tr><td>{}</td><td>{}</td><td class='mono'>{}</td><td>{}</td><td>{}</td></tr>".format(
                esc(g["name"]), esc(g["type"]), esc(g["version"]), esc(g["policy"]), " ".join(flags)))
        body.append('</tbody></table>')
        self.page("risk.html", "Versions & CVE", "".join(body))


def main():
    parser = argparse.ArgumentParser(description="Generate local HTML config browser (read-only)")
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(__version__))
    parser.add_argument("--input", required=True, help="run-YYYYMMDD-HHMMSS export folder")
    parser.add_argument("--output", default=None, help="output dir (default: <input>/html_view)")
    parser.add_argument("--analysis", action="store_true",
                        help="Include Optimization, Simplify & Merge, Compliance, and CVE pages "
                             "(NetConverter.local engagement workflow — not shipped to customers).")
    parser.add_argument("--offline", action="store_true",
                        help="Skip live CISA KEV / NVD lookups; use cached or curated data only.")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                        help="Optional NVD API key (or NVD_API_KEY env) — raises the NVD "
                             "rate limit from 5 to 50 requests/30s.")
    args = parser.parse_args()

    run_dir = Path(args.input)
    if not run_dir.is_dir():
        print("Error: input folder not found: {}".format(run_dir))
        return 1
    out_dir = Path(args.output) if args.output else run_dir / "html_view"

    print("Loading export: {}".format(run_dir))
    model = CheckpointModel(run_dir)
    model.load()
    print("  objects indexed : {}".format(len(model.by_uid)))
    print("  access layers   : {} unique ({} raw exports)".format(
        model.catalog_layer_count(), model.raw_export_layer_count()))
    print("  access rules    : {} unique".format(model.unique_access_rule_count()))
    print("  nat packages    : {}".format(len(model.nat_layers)))
    print("  threat layers   : {} ({} rules)".format(
        len(model.threat_layers), model.threat_rule_count()))
    audit = model.export_audit.get("summary") or {}
    if audit:
        print("  export audit    : {} critical, {} warning".format(
            audit.get("critical_flags", 0), audit.get("warning_flags", 0)))
    print("  vpn communities : {} meshed, {} star, {} remote".format(
        len(model.vpn_meshed), len(model.vpn_star), len(model.vpn_remote)))

    browse_only = not args.analysis
    if browse_only:
        print("Building browse-only HTML (no optimization/compliance/CVE pages).")
        analysis = ([], {}, [], [], [])
        extra = {
            "merge": {},
            "controls": [],
            "detail": {},
            "versions": {"gateways": [], "by_version": {}},
            "intel": {"kev": set(), "nvd": {}},
        }
    else:
        print("Analyzing...")
        analysis = (
            analyze_duplicates(model),
            analyze_unused(model),
            analyze_shadows(model),
            *analyze_permissive(model),
        )
        dup, unused, shadows, permissive, no_log = analysis
        merge = analyze_merge(model)
        controls, detail = analyze_compliance(model, dup, unused, shadows, permissive, no_log, merge)
        versions = analyze_versions(model)
        cve_ids = [c["cve"] for c in KNOWN_CVES]
        if args.offline:
            print("  [intel] offline mode — using cache/curated data only.")
        else:
            print("  [intel] fetching CISA KEV + NVD (this may take ~15s on first run)...")
        cpes = sorted({cpe_for_version("checkpoint", v)
                       for v in versions["by_version"]} - {""})
        intel = fetch_cve_intel(cve_ids, run_dir / "_cve_intel_cache.json", args.offline,
                                cpes=cpes, nvd_api_key=args.nvd_api_key or None)
        extra = {"merge": merge, "controls": controls, "detail": detail, "versions": versions,
                 "intel": intel}
        print("  duplicate values: {}".format(len(dup)))
        print("  unreferenced    : {}".format(sum(len(v) for v in unused.values())))
        print("  shadowed        : {}".format(len([s for s in shadows if s['kind'] == 'SHADOWED'])))
        print("  redundant       : {}".format(len([s for s in shadows if s['kind'] == 'REDUNDANT'])))
        print("  any/any/any acc : {}".format(len(permissive)))
        print("  merge groups    : {}".format(sum(len(v) for v in merge.values())))
        print("  compliance ctrl : {}".format(len(controls)))
        print("  gw versions     : {}".format(len(versions["by_version"])))

    print("Writing HTML to: {}".format(out_dir))
    HtmlSite(model, out_dir, browse_only=browse_only).build(analysis, extra)
    index = out_dir / "index.html"
    print("\nDone. Open in your browser:\n  {}".format(index.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
