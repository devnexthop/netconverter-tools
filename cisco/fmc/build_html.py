#!/usr/bin/env python3
"""
NetConverter — Cisco FMC read-only HTML browser (Check Point–style layout).

Reads a run-YYYYMMDD-HHMMSS bundle from fmc_collect_data.py and generates a
self-contained static HTML site under <run>/html_view/ with dashboard KPI cards,
clickable managed devices, interfaces/routes drill-down, and filterable tables.

Usage:
    python build_html.py --input run-20260606-120000
    python build_html.py --input run-... --output /some/path/html_view

License: MIT
"""

from __future__ import annotations

__version__ = "2.3.0"

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.html_site import SiteBuilder, esc  # noqa: E402
from core.html_theme import CSS  # noqa: E402

FMC_EXTRA_CSS = """
.section-title { font-size: 13px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
  color: var(--dim); margin: 28px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.section-title .count { font-weight: 400; text-transform: none; letter-spacing: 0; color: var(--muted); }
.breadcrumb { font-size: 12px; color: var(--dim); margin-bottom: 16px; }
.breadcrumb a { color: var(--accent); text-decoration: none; }
.breadcrumb a:hover { text-decoration: underline; }
.device-hero { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px;
  margin: 8px 0 24px; }
.device-hero .card .n { font-size: 1.05rem; word-break: break-word; }
h3.subhead { font-size: 14px; font-weight: 600; margin: 24px 0 10px; color: var(--txt); }
.note-warn { background: color-mix(in srgb, var(--warn) 12%, transparent); border: 1px solid color-mix(in srgb, var(--warn) 35%, transparent);
  border-radius: 8px; padding: 12px 14px; font-size: 13px; margin: 12px 0; color: var(--txt); }
.tag { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }
.tag.t-allow, .tag.t-permit { background: color-mix(in srgb, #22c55e 18%, transparent); color: #4ade80; }
.tag.t-block, .tag.t-deny { background: color-mix(in srgb, #ef4444 18%, transparent); color: #f87171; }
.tag.t-warn { background: color-mix(in srgb, #f59e0b 18%, transparent); color: #fbbf24; }
.badge.b-green { background: color-mix(in srgb, #22c55e 20%, transparent); color: #4ade80; }
.badge.b-red { background: color-mix(in srgb, #ef4444 20%, transparent); color: #f87171; }
.badge.b-amber { background: color-mix(in srgb, #f59e0b 20%, transparent); color: #fbbf24; }
.badge.b-blue { background: color-mix(in srgb, var(--accent) 20%, transparent); color: var(--accent); }
a.row-link { color: var(--accent); font-weight: 500; text-decoration: none; }
a.row-link:hover { text-decoration: underline; }
.filter-bar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 12px 0; }
.filter-bar label { font-size: 12px; color: var(--dim); display: flex; align-items: center; gap: 6px; }
.filter-bar select { background: var(--panel); border: 1px solid var(--border); color: var(--txt);
  border-radius: 6px; padding: 6px 10px; font-size: 12px; }
.table-wrap.scroll-x { overflow-x: auto; -webkit-overflow-scrolling: touch; width: 100%; }
.table-wrap.scroll-x table { min-width: 1180px; }
.table-wrap.rules-pane { max-height: 50vh; overflow: auto; margin-bottom: 0;
  border-radius: var(--radius-lg) var(--radius-lg) 0 0; border-bottom: none; }
tr.rule-row { cursor: pointer; }
tr.rule-row.row-selected td { background: color-mix(in srgb, var(--accent) 18%, transparent) !important;
  box-shadow: inset 3px 0 0 var(--accent); }
#rule-detail, #row-detail { display: none; margin: 0 0 28px; padding: 16px 18px; background: var(--panel2);
  border: 1px solid var(--line); border-top: 2px solid var(--accent);
  border-radius: 0 0 var(--radius-lg) var(--radius-lg); max-height: 36vh; overflow-y: auto; }
#rule-detail .rd-title, #row-detail .rd-title { font-size: 15px; font-weight: 600; margin: 0 0 6px; letter-spacing: -.02em; }
#rule-detail .rd-hint, #row-detail .rd-hint { color: var(--dim); font-size: 11px; margin: 0 0 12px; }
#rule-detail .rd-grid, #row-detail .rd-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px 18px; }
#rule-detail .rd-k, #row-detail .rd-k { font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--dim); font-weight: 600; }
#rule-detail .rd-v, #row-detail .rd-v { font-size: 12px; word-break: break-word; margin-top: 3px; line-height: 1.45; }
td.cell-wrap { min-width: 90px; max-width: 200px; white-space: normal; word-break: break-word; vertical-align: top; }
td.cell-narrow { white-space: nowrap; }
"""

NAV = [
    ("group", "Overview"),
    ("index.html", "Dashboard"),
    ("completeness.html", "Completeness"),
    ("group", "Inventory"),
    ("devices.html", "Managed Devices"),
    ("interfaces.html", "Interfaces"),
    ("routes.html", "Static Routes"),
    ("device_groups.html", "Device Groups"),
    ("domains.html", "Domains"),
    ("group", "Policy"),
    ("access_policies.html", "Access Policies"),
    ("access_rules.html", "Access Rules"),
    ("nat_policies.html", "NAT Policies"),
    ("nat_rules.html", "NAT Rules"),
    ("prefilter_policies.html", "Prefilter Policies"),
    ("prefilter_rules.html", "Prefilter Rules"),
    ("intrusion_policies.html", "Intrusion Policies"),
    ("file_policies.html", "File Policies"),
    ("dns_policies.html", "DNS Policies"),
    ("dns_rules.html", "DNS Rules"),
    ("group", "Objects"),
    ("apps_in_use.html", "Apps & URLs In Use"),
    ("applications.html", "Applications"),
    ("hosts.html", "Host Objects"),
    ("networks.html", "Network Objects"),
    ("network_groups.html", "Network Groups"),
    ("fqdns.html", "FQDN Objects"),
    ("urls.html", "URL Objects"),
    ("protocol_ports.html", "Protocol Ports"),
    ("port_groups.html", "Port Groups"),
    ("security_zones.html", "Security Zones"),
    ("group", "Data"),
    ("raw.json.html", "Raw JSON"),
]


def safe_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (name or "device").strip())
    return slug.strip("_")[:80] or "device"


def iter_data_roots(run: Path) -> list[Path]:
    domains = run / "domains"
    if domains.is_dir():
        subs = sorted(p for p in domains.iterdir() if p.is_dir() and (p / "fmc_snapshot.json").is_file())
        if subs:
            return subs
    return [run]


OBJECT_FILES = (
    ("objects-hosts.json", "Host"),
    ("objects-networks.json", "Network"),
    ("objects-ranges.json", "Range"),
    ("objects-networkgroups.json", "NetworkGroup"),
    ("objects-protocolports.json", "ProtocolPort"),
    ("objects-portgroups.json", "PortObjectGroup"),
    ("objects-securityzones.json", "SecurityZone"),
    ("objects-fqdns.json", "FQDN"),
    ("objects-urls.json", "Url"),
    ("objects-applications.json", "Application"),
)


class ObjectIndex:
    """Name-indexed FMC objects for clickable inspector (Check Point–style)."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}
        self._uid_for_name: dict[str, str] = {}

    def load_run(self, run: Path) -> None:
        for root in iter_data_roots(run):
            for filename, default_type in OBJECT_FILES:
                path = root / filename
                if not path.is_file():
                    continue
                data = load_json(path)
                if isinstance(data, list):
                    for obj in data:
                        if isinstance(obj, dict):
                            self._index_object(obj, default_type)

    def _uid(self, name: str) -> str:
        key = name.lower()
        if key not in self._uid_for_name:
            self._uid_for_name[key] = hashlib.md5(key.encode()).hexdigest()[:12]
        return self._uid_for_name[key]

    def _index_object(self, obj: dict, default_type: str) -> None:
        name = str(obj.get("name") or "").strip()
        if not name:
            return
        t = str(obj.get("type") or default_type)
        entry: dict[str, Any] = {"name": name, "type": t, "id": obj.get("id", "")}
        val = obj.get("value")
        if val is not None and str(val):
            entry["ip"] = str(val)
            if t == "Network":
                entry["subnet"] = str(val)
        if t == "ProtocolPort" or default_type == "ProtocolPort":
            entry["proto"] = obj.get("protocol", "")
            entry["port"] = obj.get("port", "")
        if t in ("NetworkGroup", "PortObjectGroup") or "Group" in t:
            members: list[str] = []
            for ref in obj.get("objects") or []:
                if isinstance(ref, dict):
                    members.append(str(ref.get("name") or ref.get("value") or ref.get("id") or "?"))
            for lit in obj.get("literals") or []:
                if isinstance(lit, dict):
                    members.append(str(lit.get("value") or lit.get("type") or "?"))
            if members:
                entry["members"] = members
        desc = obj.get("description")
        if desc:
            entry["description"] = str(desc)[:200]
        self._entries[name.lower()] = entry

    def to_js_dict(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for name, entry in self._entries.items():
            out[self._uid(name)] = entry
        return out

    def linkify(self, text: str) -> str:
        raw = (text or "").strip()
        if not raw or raw.lower() in ("any", "—", "-"):
            return esc(raw or "—")
        parts: list[str] = []
        for piece in raw.split(","):
            piece = piece.strip()
            if not piece:
                continue
            key = piece.lower()
            if key.startswith("cat:"):
                parts.append(esc(piece))
                continue
            if key in self._entries:
                uid = self._uid(piece)
                parts.append(f'<span class="obj" onclick="showObj(\'{uid}\')">{esc(piece)}</span>')
            else:
                parts.append(esc(piece))
        return ", ".join(parts) if parts else "—"


FMC_DETAIL_JS = """
function _escHtml(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function showDetail(rid){
  var panel=document.getElementById('row-detail')||document.getElementById('rule-detail');
  if(!panel) return;
  var r=(typeof DETAIL!=='undefined'&&DETAIL[rid])||(typeof RULES!=='undefined'&&RULES[rid]);
  if(!r){ panel.style.display='none'; return; }
  document.querySelectorAll('tr.rule-row').forEach(function(tr){ tr.classList.remove('row-selected'); });
  var row=document.querySelector('tr[data-row-id="'+rid+'"],tr[data-rule-id="'+rid+'"]');
  if(row) row.classList.add('row-selected');
  var title=r.title||r.name||rid;
  var h='<div class="rd-title">'+_escHtml(title)+'</div>';
  h+='<div class="rd-hint">Click underlined names to inspect objects/groups · Click another row to switch</div>';
  h+='<div class="rd-grid">';
  var fields=r.fields||[];
  if(!fields.length){
    for(var k in r){ if(k==='id'||k==='title'||k==='name'||k==='fields') continue;
      var v=r[k]; if(v==null||v==='') continue;
      h+='<div><div class="rd-k">'+_escHtml(k)+'</div><div class="rd-v">'+v+'</div></div>';
    }
  } else {
    fields.forEach(function(f){
      if(!f||f.html==null||f.html==='') return;
      h+='<div><div class="rd-k">'+_escHtml(f.label||'')+'</div><div class="rd-v">'+f.html+'</div></div>';
    });
  }
  h+='</div>';
  panel.innerHTML=h;
  panel.style.display='block';
  try{ panel.scrollIntoView({behavior:'smooth',block:'nearest'}); }catch(e){}
}
function filterRulesByPolicy(sel){
  var pol=sel.value;
  var tableId=sel.dataset?sel.dataset.table:'';
  var table=tableId?document.getElementById(tableId):document.querySelector('table[id]');
  if(!table||!table.tBodies[0]) return;
  var cntId=sel.dataset?sel.dataset.count:'';
  var shown=0;
  Array.prototype.forEach.call(table.tBodies[0].rows,function(tr){
    var ok=!pol||tr.dataset.policy===pol;
    tr.style.display=ok?'':'none';
    if(ok) shown++;
  });
  var c=cntId?document.getElementById(cntId):null;
  if(c) c.textContent=String(shown);
}
document.addEventListener('click',function(e){
  if(e.target.classList.contains('obj')) return;
  if(e.target.closest('a')) return;
  var tr=e.target.closest('tr.rule-row');
  if(!tr) return;
  var rid=tr.dataset.rowId||tr.dataset.ruleId;
  if(rid) showDetail(rid);
});
"""

# (header, field_key, linkify, formatter) — formatter: None | "action_tag" | "policy_link"
RuleCol = tuple[str, str, bool, str | None]

POLICY_KINDS: list[dict[str, Any]] = [
    {
        "kind": "access",
        "label": "Access",
        "policies_key": "access_policies",
        "rules_key": "access_rules",
        "rules_dir": "accesspolicies",
        "rule_json_keys": ["accessrules"],
        "policies_html": "access_policies.html",
        "rules_html": "access_rules.html",
        "url_seg": "access",
        "policy_columns": [("Default action", "default_action", "action_tag")],
        "rule_columns": [
            ("Policy", "policy", False, "policy_link"),
            ("Section", "section", False, None),
            ("Rule", "name", False, None),
            ("Action", "action", False, "action_tag"),
            ("On", "enabled", False, None),
            ("Src zones", "source_zones", True, None),
            ("Dst zones", "dest_zones", True, None),
            ("Src networks", "source_networks", True, None),
            ("Dst networks", "dest_networks", True, None),
            ("Src ports", "source_ports", True, None),
            ("Services", "services", True, None),
            ("Apps", "applications", True, None),
            ("URLs", "urls", True, None),
            ("IPS policy", "ips_policy", True, None),
            ("File policy", "file_policy", True, None),
        ],
        "raw_json_file": "policies-access.json",
    },
    {
        "kind": "nat",
        "label": "NAT",
        "policies_key": "nat_policies",
        "rules_key": "nat_rules",
        "rules_dir": "ftdnatpolicies",
        "rule_json_keys": ["autonatrules", "manualnatrules", "natrules"],
        "policies_html": "nat_policies.html",
        "rules_html": "nat_rules.html",
        "url_seg": "nat",
        "policy_columns": [],
        "rule_columns": [
            ("Policy", "policy", False, "policy_link"),
            ("Section", "section_label", False, None),
            ("Rule", "name", False, None),
            ("Type", "type", False, None),
            ("On", "enabled", False, None),
            ("Src IF", "source_zones", True, None),
            ("Dst IF", "dest_zones", True, None),
            ("Orig src", "source_networks", True, None),
            ("Orig dst", "dest_networks", True, None),
            ("Orig svc", "original_services", True, None),
            ("Trans src", "translated_source", True, None),
            ("Trans dst", "translated_dest", True, None),
            ("Trans svc", "translated_services", True, None),
        ],
        "raw_json_file": "policies-nat.json",
    },
    {
        "kind": "prefilter",
        "label": "Prefilter",
        "policies_key": "prefilter_policies",
        "rules_key": "prefilter_rules",
        "rules_dir": "prefilterpolicies",
        "rule_json_keys": ["prefilterrules"],
        "policies_html": "prefilter_policies.html",
        "rules_html": "prefilter_rules.html",
        "url_seg": "prefilter",
        "policy_columns": [],
        "rule_columns": [
            ("Policy", "policy", False, "policy_link"),
            ("#", "rule_index", False, None),
            ("Rule", "name", False, None),
            ("Action", "action", False, "action_tag"),
            ("On", "enabled", False, None),
            ("Src IF", "source_zones", True, None),
            ("Dst IF", "dest_zones", True, None),
            ("Src networks", "source_networks", True, None),
            ("Dst networks", "dest_networks", True, None),
            ("Src ports", "source_ports", True, None),
            ("Dst ports", "dest_ports", True, None),
            ("VLANs", "vlan_tags", True, None),
        ],
        "raw_json_file": "policies-prefilter.json",
    },
    {
        "kind": "dns",
        "label": "DNS",
        "policies_key": "dns_policies",
        "rules_key": "dns_rules",
        "rules_dir": "dnspolicies",
        "rule_json_keys": ["dnsrules"],
        "policies_html": "dns_policies.html",
        "rules_html": "dns_rules.html",
        "url_seg": "dns",
        "policy_columns": [],
        "rule_columns": [
            ("Policy", "policy", False, "policy_link"),
            ("#", "rule_index", False, None),
            ("Rule", "name", False, None),
            ("Action", "action", False, "action_tag"),
            ("On", "enabled", False, None),
            ("Src zones", "source_zones", True, None),
            ("Src networks", "source_networks", True, None),
            ("DNS lists", "dns_objects", True, None),
            ("URL categories", "url_categories", True, None),
            ("Sinkhole", "sinkhole", False, None),
        ],
        "raw_json_file": "policies-dns.json",
    },
]

CONTAINER_POLICY_KINDS: list[dict[str, Any]] = [
    {
        "kind": "intrusion",
        "label": "Intrusion",
        "policies_key": "intrusion_policies",
        "policies_html": "intrusion_policies.html",
        "url_seg": "intrusion",
        "raw_json_file": "policies-intrusion.json",
        "display_keys": [
            ("Inspection mode", "inspectionMode"),
            ("Base policy", "basePolicy", "ref_name"),
            ("Snort engine", "metadata", "snortEngine_nested"),
            ("Inline drop", "inlineDrop"),
            ("System defined", "isSystemDefined"),
        ],
    },
    {
        "kind": "file",
        "label": "File / Malware",
        "policies_key": "file_policies",
        "policies_html": "file_policies.html",
        "url_seg": "file",
        "raw_json_file": "policies-file.json",
        "display_keys": [
            ("Threat score", "threatScore"),
            ("Inspect archives", "inspectArchives"),
            ("Archive depth", "archiveDepth"),
            ("First-time analysis", "firstTimeFileAnalysis"),
            ("Block encrypted archives", "blockEncryptedArchives"),
            ("Clean list", "cleanList"),
        ],
    },
]

OBJECT_SPECS: list[dict[str, Any]] = [
    {
        "html": "applications.html",
        "title": "Applications",
        "table_id": "app",
        "snap_key": "applications",
        "raw_file": "objects-applications.json",
        "columns": [
            ("Name", "name", True),
            ("Type", "type", False),
            ("Risk", "risk", False),
            ("Productivity", "productivity", False),
            ("Description", "description", False),
        ],
    },
    {
        "html": "hosts.html",
        "title": "Host Objects",
        "table_id": "hst",
        "snap_key": "hosts",
        "raw_file": "objects-hosts.json",
        "columns": [("Name", "name", True), ("IP", "value", False), ("Description", "description", False), ("ID", "id", False)],
    },
    {
        "html": "networks.html",
        "title": "Network Objects",
        "table_id": "net",
        "snap_key": "networks",
        "raw_file": "objects-networks.json",
        "columns": [("Name", "name", True), ("Value", "value", False), ("Type", "type", False), ("Description", "description", False)],
    },
    {
        "html": "network_groups.html",
        "title": "Network Groups",
        "table_id": "ng",
        "snap_key": "network_groups",
        "raw_file": "objects-networkgroups.json",
        "columns": [("Name", "name", True), ("Members", "members", False), ("Description", "description", False)],
        "is_group": True,
    },
    {
        "html": "fqdns.html",
        "title": "FQDN Objects",
        "table_id": "fq",
        "snap_key": "fqdns",
        "raw_file": "objects-fqdns.json",
        "columns": [("Name", "name", True), ("Type", "type", False), ("Description", "description", False), ("ID", "id", False)],
    },
    {
        "html": "urls.html",
        "title": "URL Objects",
        "table_id": "url",
        "snap_key": "urls",
        "raw_file": "objects-urls.json",
        "columns": [("Name", "name", True), ("Type", "type", False), ("Description", "description", False), ("ID", "id", False)],
    },
    {
        "html": "protocol_ports.html",
        "title": "Protocol Port Objects",
        "table_id": "pp",
        "snap_key": "protocol_ports",
        "raw_file": "objects-protocolports.json",
        "columns": [("Name", "name", True), ("Protocol", "protocol", False), ("Port", "port", False), ("Description", "description", False)],
    },
    {
        "html": "port_groups.html",
        "title": "Port Object Groups",
        "table_id": "pg",
        "snap_key": "port_groups",
        "raw_file": "objects-portgroups.json",
        "columns": [("Name", "name", True), ("Members", "members", False), ("Description", "description", False)],
        "is_group": True,
    },
    {
        "html": "security_zones.html",
        "title": "Security Zones",
        "table_id": "sz",
        "snap_key": "security_zones",
        "raw_file": "objects-securityzones.json",
        "columns": [("Name", "name", True), ("Interface mode", "interface_mode", False), ("Description", "description", False)],
    },
]


def _policy_name(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("name") or "")
    return str(obj or "")


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def enrich_snapshot(run: Path, snap: dict) -> dict:
    """Merge device-details, raw devices.json, interfaces/routes from run folder."""
    counts = snap.setdefault("counts", {})

    if not snap.get("interfaces") and (run / "interfaces.json").is_file():
        snap["interfaces"] = load_json(run / "interfaces.json") or []
    if not snap.get("routes") and (run / "routes.json").is_file():
        snap["routes"] = load_json(run / "routes.json") or []

    details: dict[str, dict] = {}
    details_dir = run / "device-details"
    if details_dir.is_dir():
        for fp in sorted(details_dir.glob("*.json")):
            bundle = load_json(fp)
            if not isinstance(bundle, dict):
                continue
            dev = bundle.get("device") or {}
            dname = dev.get("name") or fp.stem.split("__")[0]
            details[dname] = bundle
            if not snap.get("interfaces"):
                snap.setdefault("interfaces", []).extend(bundle.get("interfaces_flat") or [])
            if not snap.get("routes"):
                snap.setdefault("routes", []).extend(bundle.get("routes_flat") or [])

    raw_devices = load_json(run / "devices.json")
    raw_by_name: dict[str, dict] = {}
    if isinstance(raw_devices, list):
        for d in raw_devices:
            if isinstance(d, dict) and d.get("name"):
                raw_by_name[d["name"]] = d

    devices_out = []
    for d in snap.get("devices") or []:
        if not isinstance(d, dict):
            continue
        name = d.get("name", "")
        raw = raw_by_name.get(name, {})
        bundle = details.get(name, {})
        dev_full = bundle.get("device") or raw or d
        slug = d.get("slug") or safe_slug(name)
        row = dict(d)
        meta = dev_full.get("metadata") or {}
        row.update(
            {
                "slug": slug,
                "hostname": row.get("hostname") or dev_full.get("hostName") or dev_full.get("hostname", ""),
                "serial": row.get("serial") or meta.get("deviceSerialNumber", ""),
                "device_group": row.get("device_group") or _policy_name(dev_full.get("deviceGroup")),
                "access_policy": row.get("access_policy") or _policy_name(dev_full.get("accessPolicy")),
                "nat_policy": row.get("nat_policy") or _policy_name(dev_full.get("natPolicy")),
                "intrusion_policy": row.get("intrusion_policy")
                or _policy_name(dev_full.get("intrusionPolicy")),
                "ftd_mode": row.get("ftd_mode") or dev_full.get("ftdMode", ""),
                "connected": dev_full.get("isConnected")
                if row.get("connected") in (None, "")
                else row.get("connected"),
                "snort": row.get("snort") or meta.get("snortVersion", ""),
                "vdb": row.get("vdb") or meta.get("vdbVersion", ""),
                "management_state": dev_full.get("managementState", ""),
                "license_caps": ", ".join(dev_full.get("license_caps") or []),
            }
        )
        ifaces = bundle.get("interfaces_flat") or []
        routes = bundle.get("routes_flat") or []
        row["iface_count"] = len(ifaces) or row.get("iface_count", 0)
        row["route_count"] = len(routes) or row.get("route_count", 0)
        row["_ifaces"] = ifaces
        row["_routes"] = routes
        row["_detail_errors"] = bundle.get("errors") or []
        devices_out.append(row)

    snap["devices"] = devices_out
    snap.setdefault("interfaces", [])
    snap.setdefault("routes", [])
    counts["interfaces"] = len(snap["interfaces"])
    counts["routes"] = len(snap["routes"])
    return snap


MERGE_LIST_KEYS = (
    "devices",
    "interfaces",
    "routes",
    "access_policies",
    "access_rules",
    "nat_policies",
    "nat_rules",
    "prefilter_policies",
    "prefilter_rules",
    "dns_policies",
    "dns_rules",
    "intrusion_policies",
    "file_policies",
    "ssl_policies",
    "device_groups",
    "applications",
    "hosts",
    "networks",
    "network_groups",
    "fqdns",
    "urls",
    "protocol_ports",
    "port_groups",
    "security_zones",
)


def _has_domain_subdirs(run: Path) -> bool:
    domains_dir = run / "domains"
    if not domains_dir.is_dir():
        return False
    return any((p / "fmc_snapshot.json").is_file() for p in domains_dir.iterdir() if p.is_dir())


def merge_domain_bundles(run: Path, root_snap: dict) -> dict:
    """Load domains/<slug>/ bundles and merge for HTML (multi-domain collects)."""
    domains_dir = run / "domains"
    merged: dict[str, Any] = dict(root_snap or {})
    merged_counts: dict[str, int] = {}
    for key in MERGE_LIST_KEYS:
        merged[key] = []

    domain_collects: list[dict] = []
    merged_domains: list[dict] = []
    seen_uuids: set[str] = set()

    for ddir in sorted(domains_dir.iterdir()):
        if not ddir.is_dir():
            continue
        snap_path = ddir / "fmc_snapshot.json"
        if not snap_path.is_file():
            continue
        dsnap = load_json(snap_path)
        if not isinstance(dsnap, dict):
            continue
        dsnap = enrich_snapshot(ddir, dsnap)
        dname = dsnap.get("domain_name") or ddir.name
        dslug = dsnap.get("domain_slug") or ddir.name
        duuid = dsnap.get("domain_uuid") or ""

        domain_collects.append(
            {
                "name": dname,
                "uuid": duuid,
                "slug": dslug,
                "path": f"domains/{dslug}",
                "counts": dsnap.get("counts") or {},
            }
        )
        for d in dsnap.get("domains") or []:
            if isinstance(d, dict):
                uid = str(d.get("uuid") or d.get("id") or "")
                if uid and uid not in seen_uuids:
                    seen_uuids.add(uid)
                    merged_domains.append(d)

        for key in MERGE_LIST_KEYS:
            for row in dsnap.get(key) or []:
                if isinstance(row, dict):
                    tagged = dict(row)
                    tagged.setdefault("domain", dname)
                    tagged.setdefault("domain_slug", dslug)
                    merged[key].append(tagged)
                else:
                    merged[key].append(row)
        for k, v in (dsnap.get("counts") or {}).items():
            merged_counts[k] = merged_counts.get(k, 0) + int(v or 0)

    merged["counts"] = merged_counts
    merged["domains"] = merged_domains or merged.get("domains") or []
    merged["domain_collects"] = domain_collects or merged.get("domain_collects") or []
    merged["all_domains"] = len(domain_collects) > 1
    return merged


def action_tag(action: str) -> str:
    a = (action or "").upper()
    if a in ("ALLOW", "PERMIT", "TRUST"):
        cls = "t-allow"
    elif a in ("BLOCK", "DENY", "DROP"):
        cls = "t-block"
    else:
        cls = "t-warn"
    return f'<span class="tag {cls}">{esc(action or "—")}</span>'


def health_badge(health: str) -> str:
    h = (health or "").lower()
    if h in ("green", "ok", "good"):
        return '<span class="badge b-green">Healthy</span>'
    if h in ("red", "critical", "bad"):
        return '<span class="badge b-red">Critical</span>'
    if h:
        return f'<span class="badge b-amber">{esc(health)}</span>'
    return '<span class="badge b-blue">—</span>'


def bool_badge(val: Any, yes: str = "Yes", no: str = "No") -> str:
    if val is True or str(val).lower() in ("true", "yes", "1", "connected"):
        return f'<span class="badge b-green">{esc(yes)}</span>'
    if val is False or str(val).lower() in ("false", "no", "0"):
        return f'<span class="badge b-amber">{esc(no)}</span>'
    return esc(val)


def deployment_badge(status: str) -> str:
    s = (status or "").upper()
    if "SUCCESS" in s or s == "DEPLOYED":
        return '<span class="badge b-green">Deployed</span>'
    if "PENDING" in s or "NEEDED" in s:
        return '<span class="badge b-amber">Pending</span>'
    if "FAIL" in s:
        return '<span class="badge b-red">Failed</span>'
    return f'<span class="badge b-blue">{esc(status or "—")}</span>'


def _ref_name(val: Any) -> str:
    if isinstance(val, dict):
        return str(val.get("name") or val.get("id") or "")
    return str(val or "")


def _extract_raw_display(raw: dict, display_keys: list) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for spec in display_keys:
        label = spec[0]
        key = spec[1]
        mode = spec[2] if len(spec) > 2 else None
        val = raw.get(key)
        if mode == "ref_name":
            text = _ref_name(val)
        elif mode == "snortEngine_nested":
            meta = raw.get("metadata") or {}
            text = str(meta.get("snortEngine") or (meta.get("mappedPolicy") or {}).get("snortEngine") or "")
        elif isinstance(val, (dict, list)):
            text = json.dumps(val, indent=2)[:800]
        else:
            text = str(val) if val is not None else ""
        if text:
            rows.append((label, text))
    usage = (raw.get("metadata") or {}).get("usage") or {}
    acps = usage.get("asscoiatedAcPolicies") or usage.get("associatedAcPolicies") or []
    if acps:
        names = ", ".join(_ref_name(p) for p in acps if isinstance(p, dict))
        if names:
            rows.append(("Used by access policies", names))
    return rows


class FMCReport:
    def __init__(self, run: Path, out: Path, snap: dict):
        self.run = run
        self.out = out
        self.snap = snap
        self.counts = snap.get("counts") or {}
        self.multi_domain = bool(
            snap.get("all_domains") or len(snap.get("domain_collects") or []) > 1
        )
        self.obj_index = ObjectIndex()
        self.obj_index.load_run(run)
        self.obj_data = self.obj_index.to_js_dict()
        self._policy_slugs: dict[str, dict[str, str]] = {}
        self._policy_meta: dict[str, dict[str, dict]] = {}
        self._raw_rules: dict[str, dict[str, dict]] = {}
        self._raw_policies: dict[str, dict[str, dict]] = {}
        self._raw_objects: dict[str, dict[str, dict]] = {}
        self._init_policy_registries()
        self.site = SiteBuilder(out, "fmc", run.name, NAV, viewer_version=__version__)
        self._device_slugs = {
            d.get("name"): d.get("slug") or safe_slug(d.get("name", ""))
            for d in snap.get("devices") or []
            if isinstance(d, dict)
        }

    def _init_policy_registries(self) -> None:
        for cfg in POLICY_KINDS + CONTAINER_POLICY_KINDS:
            kind = cfg["kind"]
            self._policy_slugs[kind] = {}
            self._policy_meta[kind] = {}
            for pol in self.snap.get(cfg["policies_key"]) or []:
                if not isinstance(pol, dict):
                    continue
                pname = pol.get("name", "")
                if not pname:
                    continue
                slug = safe_slug(pname)
                pid = str(pol.get("id") or "")
                if slug in self._policy_slugs[kind].values() and pid:
                    slug = f"{slug}_{pid[:8]}"
                self._policy_slugs[kind][pname] = slug
                self._policy_meta[kind][pname] = pol
            raw_file = cfg.get("raw_json_file")
            if raw_file:
                self._raw_policies[kind] = self._load_raw_list_file(raw_file)
            if cfg.get("rules_dir"):
                self._raw_rules[kind] = self._load_raw_rules_dir(
                    cfg["rules_dir"], cfg.get("rule_json_keys") or []
                )
        for spec in OBJECT_SPECS:
            rf = spec.get("raw_file")
            if rf:
                self._raw_objects[spec["snap_key"]] = self._load_raw_list_file(rf)

    def _load_raw_list_file(self, filename: str) -> dict[str, dict]:
        by_name: dict[str, dict] = {}
        for root in iter_data_roots(self.run):
            data = load_json(root / filename)
            if not isinstance(data, list):
                continue
            for item in data:
                if isinstance(item, dict) and item.get("name"):
                    by_name[str(item["name"])] = item
        return by_name

    def _load_raw_rules_dir(self, rules_dir: str, rule_keys: list[str]) -> dict[str, dict]:
        by_id: dict[str, dict] = {}
        for root in iter_data_roots(self.run):
            rdir = root / "policy-rules" / rules_dir
            if not rdir.is_dir():
                continue
            for fp in rdir.glob("*.json"):
                bundle = load_json(fp)
                if not isinstance(bundle, dict):
                    continue
                for key in rule_keys:
                    for rule in bundle.get(key) or []:
                        if isinstance(rule, dict) and rule.get("id"):
                            by_id[str(rule["id"])] = rule
        return by_id

    def _row_id(self, r: dict) -> str:
        rid = str(r.get("id") or "").strip()
        if rid:
            return rid
        return hashlib.md5(json.dumps(r, sort_keys=True, default=str).encode()).hexdigest()[:12]

    def _policy_href(self, kind: str, policy_name: str, depth: int) -> str:
        prefix = "../" * depth
        slug = self._policy_slugs.get(kind, {}).get(policy_name, safe_slug(policy_name))
        seg = next(c["url_seg"] for c in POLICY_KINDS + CONTAINER_POLICY_KINDS if c["kind"] == kind)
        return f"{prefix}policies/{seg}/{esc(slug)}.html"

    def _format_cell(
        self,
        r: dict,
        key: str,
        linkify: bool,
        fmt: str | None,
        *,
        kind: str = "",
        depth: int = 0,
    ) -> str:
        if fmt == "policy_link":
            pol = r.get("policy", "")
            if not pol:
                return ""
            return f'<a class="row-link" href="{self._policy_href(kind, pol, depth)}">{esc(pol)}</a>'
        val = r.get(key, "")
        if isinstance(val, dict):
            val = val.get("name") or val.get("value") or val.get("id") or ""
        elif isinstance(val, list):
            val = ", ".join(
                (v.get("name") or v.get("value") or v.get("id") or "") if isinstance(v, dict) else str(v)
                for v in val if v
            )
        if fmt == "action_tag":
            return action_tag(str(val))
        text = str(val) if val is not None else ""
        if linkify:
            return self.obj_index.linkify(text)
        if key == "name" and text:
            uid = self.obj_index._uid(text)
            if text.lower() in self.obj_index._entries:
                return f'<span class="obj" onclick="showObj(\'{uid}\')">{esc(text)}</span>'
        return esc(text)

    def _detail_entry(self, r: dict, cfg: dict) -> dict[str, Any]:
        rid = self._row_id(r)
        raw = self._raw_rules.get(cfg["kind"], {}).get(str(r.get("id") or ""), {})
        meta = raw.get("metadata") if isinstance(raw, dict) else {}
        if not isinstance(meta, dict):
            meta = {}
        fields: list[dict[str, str]] = []
        for col in cfg.get("rule_columns") or []:
            label, key, linkify, fmt = col[0], col[1], col[2], col[3] if len(col) > 3 else None
            if key == "policy" or fmt == "policy_link":
                continue
            html = self._format_cell(r, key, linkify, fmt if fmt != "policy_link" else None)
            if html:
                fields.append({"label": label, "html": html})
        if meta.get("section"):
            fields.append({"label": "Section", "html": esc(meta.get("section"))})
        if r.get("id"):
            fields.append({"label": "Rule ID", "html": f'<span class="mono">{esc(r.get("id"))}</span>'})
        return {"id": rid, "title": r.get("name") or rid, "fields": fields}

    def _object_detail_entry(self, item: dict, spec: dict) -> dict[str, Any]:
        rid = self._row_id(item)
        name = str(item.get("name") or rid)
        raw = self._raw_objects.get(spec["snap_key"], {}).get(name, {})
        fields: list[dict[str, str]] = []
        for col in spec["columns"]:
            label, key, linkify = col[0], col[1], col[2]
            html = self._format_cell(item, key, linkify, None)
            if html:
                fields.append({"label": label, "html": html})
        if spec.get("is_group") and raw:
            members: list[str] = []
            for ref in raw.get("objects") or []:
                if isinstance(ref, dict):
                    n = ref.get("name") or ref.get("value")
                    if n:
                        members.append(str(n))
            for lit in raw.get("literals") or []:
                if isinstance(lit, dict):
                    members.append(str(lit.get("value") or lit.get("type") or ""))
            if members:
                mem_html = ", ".join(
                    self.obj_index.linkify(m) if m.lower() in self.obj_index._entries else esc(m)
                    for m in members
                )
                fields.append({"label": "Members (expanded)", "html": mem_html})
        if raw.get("id"):
            fields.append({"label": "Object ID", "html": f'<span class="mono">{esc(raw.get("id"))}</span>'})
        return {"id": rid, "title": name, "fields": fields}

    def _build_rule_rows(
        self, rules: list[dict], cfg: dict, *, depth: int = 0
    ) -> tuple[list[str], dict[str, dict]]:
        kind = cfg["kind"]
        rows: list[str] = []
        detail_js: dict[str, dict] = {}
        for r in rules:
            if not isinstance(r, dict):
                continue
            rid = self._row_id(r)
            detail_js[rid] = self._detail_entry(r, cfg)
            pol = r.get("policy", "")
            cells = []
            for col in cfg["rule_columns"]:
                label, key, linkify = col[0], col[1], col[2]
                fmt = col[3] if len(col) > 3 else None
                cls = "cell-wrap" if linkify or key.endswith("networks") or key.endswith("zones") else "cell-narrow"
                cells.append(f'<td class="{cls}">{self._format_cell(r, key, linkify, fmt, kind=kind, depth=depth)}</td>')
            rows.append(
                f'<tr class="rule-row" data-row-id="{esc(rid)}" data-policy="{esc(pol)}">'
                + "".join(cells)
                + "</tr>"
            )
        return rows, detail_js

    def _interactive_table_html(
        self,
        table_id: str,
        count_id: str,
        headers: list[str],
        rows: list[str],
        *,
        policy_filter: list[str] | None = None,
        hint: str = "rows",
        csv_name: str | None = None,
    ) -> str:
        filter_html = ""
        if policy_filter:
            opts = ['<option value="">All policies</option>']
            for p in sorted(set(policy_filter)):
                opts.append(f'<option value="{esc(p)}">{esc(p)}</option>')
            filter_html = (
                '<div class="filter-bar"><label>Policy '
                f'<select data-table="{table_id}" data-count="{count_id}" '
                f'onchange="filterRulesByPolicy(this)">{"".join(opts)}</select>'
                "</label></div>"
            )
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        return (
            filter_html
            + self.site.searchbox(table_id, count_id, export_csv=csv_name)
            + f'<div class="meta"><span id="{count_id}">{len(rows)}</span> {hint} · click a row for details below</div>'
            + f'<div class="table-wrap scroll-x rules-pane"><table id="{table_id}">'
            + f"<thead><tr>{th}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
            + '<div id="row-detail"></div>'
        )

    def _detail_script(self, detail_js: dict[str, dict]) -> str:
        return (
            f"<script>var DETAIL={json.dumps(detail_js, ensure_ascii=False)};</script>"
            f"<script>{FMC_DETAIL_JS}</script>"
        )

    def page_policy_bundles(self) -> None:
        for cfg in POLICY_KINDS:
            self._page_policy_index(cfg)
            self._page_policy_rule_details(cfg)
            self._page_all_rules(cfg)
        for cfg in CONTAINER_POLICY_KINDS:
            self._page_policy_index(cfg, container=True)
            self._page_container_policy_details(cfg)

    def _page_policy_index(self, cfg: dict, *, container: bool = False) -> None:
        kind = cfg["kind"]
        rules_key = cfg.get("rules_key")
        rules = self.snap.get(rules_key) or [] if rules_key else []
        rule_counts: dict[str, int] = {}
        for r in rules:
            if isinstance(r, dict):
                pol = r.get("policy", "")
                rule_counts[pol] = rule_counts.get(pol, 0) + 1

        rows = []
        for pname, pol in self._policy_meta.get(kind, {}).items():
            slug = self._policy_slugs[kind][pname]
            cnt = rule_counts.get(pname, 0) if rules_key else "—"
            extra_cells = ""
            for col in cfg.get("policy_columns") or []:
                label, key, fmt = col[0], col[1], col[2]
                val = pol.get(key, "")
                extra_cells += f"<td>{action_tag(val) if fmt == 'action_tag' else esc(val)}</td>"
            rows.append(
                "<tr>"
                f'<td><a class="row-link" href="policies/{cfg["url_seg"]}/{esc(slug)}.html">{esc(pname)}</a></td>'
                f"<td>{cnt}</td>"
                f"{extra_cells}"
                f"<td>{esc(pol.get('description', ''))}</td>"
                f'<td class="mono">{esc(pol.get("id", ""))}</td>'
                "</tr>"
            )
        headers = ["Policy", "Rules"] + [c[0] for c in cfg.get("policy_columns") or []] + ["Description", "ID"]
        noun = "rules" if rules_key else "settings"
        body = (
            f"<h2>{esc(cfg['label'])} Policies</h2>"
            f'<div class="note">Click a policy to view its {noun} with object drill-down.</div>'
            + self.site.searchbox(f"pol_{kind}", f"pol_{kind}_cnt")
            + f'<div class="meta"><span id="pol_{kind}_cnt">{len(rows)}</span> policies</div>'
            + self.site.table(f"pol_{kind}", headers, rows)
        )
        self.site.page(cfg["policies_html"], f"{cfg['label']} Policies", body, obj_data=self.obj_data)

    def _page_policy_rule_details(self, cfg: dict) -> None:
        kind = cfg["kind"]
        rules_key = cfg["rules_key"]
        all_rules = self.snap.get(rules_key) or []
        by_policy: dict[str, list[dict]] = {}
        for r in all_rules:
            if isinstance(r, dict):
                by_policy.setdefault(r.get("policy", ""), []).append(r)

        headers = [c[0] for c in cfg["rule_columns"]]
        table_id = f"rules_{kind}"

        for pname, pol in self._policy_meta.get(kind, {}).items():
            slug = self._policy_slugs[kind][pname]
            policy_rules = by_policy.get(pname, [])
            rows, detail_js = self._build_rule_rows(policy_rules, cfg, depth=2)
            extra_cols = ""
            for col in cfg.get("policy_columns") or []:
                if col[2] == "action_tag":
                    extra_cols = f" · Default: {action_tag(pol.get(col[1], ''))}"
                    break
            body = (
                f'<div class="breadcrumb"><a href="../../{cfg["policies_html"]}">{esc(cfg["label"])} Policies</a>'
                f" → {esc(pname)}</div>"
                f"<h2>{esc(pname)}</h2>"
                f'<div class="note">{len(policy_rules)} {cfg["label"].lower()} rule(s){extra_cols}</div>'
                + self._interactive_table_html(
                    table_id, f"{table_id}_cnt", headers, rows, hint="rules"
                )
            )
            self.site.page(
                f"policies/{cfg['url_seg']}/{slug}.html",
                pname,
                body,
                depth=2,
                obj_data=self.obj_data,
                extra_script=self._detail_script(detail_js),
            )

    def _page_all_rules(self, cfg: dict) -> None:
        rules = self.snap.get(cfg["rules_key"]) or []
        if not rules and cfg["rules_key"] not in self.counts:
            return
        policy_names = sorted({r.get("policy", "") for r in rules if isinstance(r, dict) and r.get("policy")})
        rows, detail_js = self._build_rule_rows(rules, cfg)
        headers = [c[0] for c in cfg["rule_columns"]]
        table_id = f"all_{cfg['kind']}"
        body = (
            f"<h2>{esc(cfg['label'])} Rules</h2>"
            f'<div class="note">All {esc(cfg["label"].lower())} rules across policies. '
            "Click a <strong>policy</strong> name · Click a <strong>row</strong> for details · "
            'Click <span class="obj" style="cursor:default;border:none">underlined objects</span> for groups.</div>'
            + self._interactive_table_html(
                table_id,
                f"{table_id}_cnt",
                headers,
                rows,
                policy_filter=policy_names,
                hint="rules",
            )
        )
        self.site.page(
            cfg["rules_html"],
            f"{cfg['label']} Rules",
            body,
            obj_data=self.obj_data,
            extra_script=self._detail_script(detail_js),
        )

    def _page_container_policy_details(self, cfg: dict) -> None:
        kind = cfg["kind"]
        for pname, pol in self._policy_meta.get(kind, {}).items():
            slug = self._policy_slugs[kind][pname]
            raw = self._raw_policies.get(kind, {}).get(pname, pol)
            display = _extract_raw_display(raw, cfg.get("display_keys") or [])
            detail_js = {
                slug: {
                    "id": slug,
                    "title": pname,
                    "fields": [{"label": k, "html": esc(v)} for k, v in display]
                    + [{"label": "Description", "html": esc(pol.get("description", ""))}]
                    + [{"label": "Policy ID", "html": f'<span class="mono">{esc(pol.get("id", ""))}</span>'}],
                }
            }
            grid_rows = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in display)
            body = (
                f'<div class="breadcrumb"><a href="../../{cfg["policies_html"]}">{esc(cfg["label"])} Policies</a>'
                f" → {esc(pname)}</div>"
                f"<h2>{esc(pname)}</h2>"
                f'<div class="note">{esc(cfg["label"])} policy container — click summary row for full detail panel.</div>'
                + self.site.table(
                    f"meta_{kind}",
                    ["Attribute", "Value"],
                    [f'<tr class="rule-row" data-row-id="{esc(slug)}"><td>Summary</td><td>{esc(pname)}</td></tr>']
                    + [f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in display],
                )
                + '<div id="row-detail"></div>'
            )
            self.site.page(
                f"policies/{cfg['url_seg']}/{slug}.html",
                pname,
                body,
                depth=2,
                obj_data=self.obj_data,
                extra_script=self._detail_script(detail_js),
            )

    def page_object_tables(self) -> None:
        for spec in OBJECT_SPECS:
            data = self.snap.get(spec["snap_key"]) or []
            if not data and spec["snap_key"] not in self.counts:
                continue
            headers = [c[0] for c in spec["columns"]]
            rows: list[str] = []
            detail_js: dict[str, dict] = {}
            for item in data:
                if not isinstance(item, dict):
                    continue
                rid = self._row_id(item)
                detail_js[rid] = self._object_detail_entry(item, spec)
                cells = []
                for col in spec["columns"]:
                    label, key, linkify = col[0], col[1], col[2]
                    cls = "cell-wrap" if linkify or key == "description" else "cell-narrow"
                    cells.append(f'<td class="{cls}">{self._format_cell(item, key, linkify, None)}</td>')
                rows.append(f'<tr class="rule-row" data-row-id="{esc(rid)}">' + "".join(cells) + "</tr>")
            body = (
                f"<h2>{esc(spec['title'])}</h2>"
                '<div class="note">Click a row for details · Click underlined names to inspect object/group members.</div>'
                + self._interactive_table_html(
                    spec["table_id"],
                    f"{spec['table_id']}cnt",
                    headers,
                    rows,
                    hint="objects",
                    csv_name=spec["html"].rsplit(".", 1)[0] + ".csv",
                )
            )
            self.site.page(
                spec["html"],
                spec["title"],
                body,
                obj_data=self.obj_data,
                extra_script=self._detail_script(detail_js),
            )

        if self.snap.get("device_groups") or "device_groups" in self.counts:
            self.page_table(
                "device_groups.html",
                "Device Groups",
                "dg",
                self.snap.get("device_groups") or [],
                [("Name", "name"), ("Type", "type"), ("Description", "description"), ("ID", "id")],
            )

    def write_assets(self) -> None:
        self.site.write_assets()
        css_path = self.out / "assets" / "style.css"
        css_path.write_text(CSS + FMC_EXTRA_CSS, encoding="utf-8")

    def device_href(self, name: str, depth: int = 0) -> str:
        prefix = "../" * depth
        slug = self._device_slugs.get(name) or safe_slug(name)
        return f"{prefix}devices/{slug}.html"

    def device_link(self, name: str, depth: int = 0) -> str:
        if not name or name not in self._device_slugs:
            return esc(name)
        return f'<a class="row-link" href="{self.device_href(name, depth)}">{esc(name)}</a>'

    def build(self) -> None:
        self.write_assets()
        self.page_dashboard()
        self.page_completeness()
        self.page_devices()
        for dev in self.snap.get("devices") or []:
            if isinstance(dev, dict) and dev.get("name"):
                self.page_device_detail(dev)
        self.page_interfaces()
        self.page_routes()
        self.page_table(
            "domains.html",
            "Domains",
            "dom",
            self.snap.get("domains") or [],
            [("Name", "name"), ("UUID", "uuid"), ("Type", "type")],
        )
        self.page_policy_bundles()
        self.page_object_tables()
        self.page_apps_in_use()
        self.site.write_json_embed("raw.json.html", "FMC Snapshot JSON", self.snap)

    def page_completeness(self) -> None:
        """Capture-completeness audit: live FMC totals vs what this pull captured."""
        rows_data = self.snap.get("completeness") or []
        if not rows_data:
            body = (
                "<h2>Capture Completeness</h2>"
                '<div class="note">No completeness audit in this bundle. Re-run the collector '
                "(<code>fmc_collect_data.py</code> v2.3.0+) to record live-vs-captured reconciliation "
                "for every object and rule type.</div>"
            )
            self.site.page("completeness.html", "Completeness", body)
            return

        def status_badge(s: str) -> str:
            cls = {"complete": "b-blue", "captured": "b-blue",
                   "PARTIAL": "b-red", "api_blocked": "b-amber"}.get(s, "b-blue")
            return f'<span class="badge {cls}">{esc(s)}</span>'

        has_domain = bool(rows_data[0].get("domain"))
        headers = (["Domain"] if has_domain else []) + [
            "Object / Rule Type", "Live Total", "Captured", "Status", "Note",
        ]
        rows = []
        for r in rows_data:
            cells = []
            if has_domain:
                cells.append(f"<td>{esc(r.get('domain', ''))}</td>")
            cells.append(f"<td>{esc(r.get('object_type', ''))}</td>")
            cells.append(f"<td>{esc(r.get('live_total', ''))}</td>")
            cells.append(f"<td>{esc(r.get('captured', ''))}</td>")
            cells.append(f"<td>{status_badge(str(r.get('status', '')))}</td>")
            cells.append(f'<td class="cell-wrap">{esc(r.get("note", ""))}</td>')
            rows.append("<tr>" + "".join(cells) + "</tr>")

        n_partial = sum(1 for r in rows_data if r.get("status") == "PARTIAL")
        n_blocked = sum(1 for r in rows_data if r.get("status") == "api_blocked")
        n_ok = sum(1 for r in rows_data if r.get("status") in ("complete", "captured"))
        cards = self.site.cards([
            (str(len(rows_data)), "Types audited"),
            (str(n_ok), "Complete", "good"),
            (str(n_partial), "Partial", "bad" if n_partial else ""),
            (str(n_blocked), "API-blocked", "warn" if n_blocked else ""),
        ])
        note = (
            '<div class="note">Live FMC <code>paging.count</code> vs what this pull captured, per '
            'object/rule type. <b>complete</b> = nothing missing · <b>api_blocked</b> = the FMC REST '
            'API does not expose it on this version (documented limitation, not a defect) · '
            '<b>PARTIAL</b> = investigate. Use the export button for the full CSV.</div>'
        )
        body = (
            "<h2>Capture Completeness</h2>"
            + cards
            + note
            + self.site.searchbox("cmpl", "cmplcnt", export_csv="completeness.csv")
            + f'<div class="meta"><span id="cmplcnt">{len(rows)}</span> rows</div>'
            + self.site.table("cmpl", headers, rows)
        )
        self.site.page("completeness.html", "Completeness", body)

    def page_apps_in_use(self) -> None:
        """L7 objects (applications/URLs/categories) actually referenced by access rules,
        cross-referenced to the rules that use them + catalog risk/type. Migration aid for
        mapping to Palo App-ID / Fortinet application control."""
        rules = self.snap.get("access_rules") or []
        catalog: dict[str, dict] = {}
        for a in self.snap.get("applications") or []:
            if isinstance(a, dict) and a.get("name"):
                catalog[a["name"]] = a

        usage: dict[tuple[str, str], set] = {}

        def add(kind: str, joined, rule_label: str) -> None:
            for item in [s.strip() for s in str(joined or "").split(",")]:
                if item:
                    usage.setdefault((kind, item), set()).add(rule_label)

        for r in rules:
            if not isinstance(r, dict):
                continue
            rname = r.get("name", "") or f"Rule {r.get('rule_index', '')}"
            label = f"{r.get('policy', '')} / {rname}".strip(" /")
            add("Application", r.get("applications"), label)
            add("URL", r.get("urls"), label)
            add("URL Category", r.get("url_categories"), label)

        rows = []
        for (kind, name), ruleset in sorted(
            usage.items(), key=lambda kv: (kv[0][0], -len(kv[1]), kv[0][1].lower())
        ):
            detail = catalog.get(name) or catalog.get(name.replace("cat:", "")) or {}
            risk = detail.get("risk")
            risk = risk.get("name", "") if isinstance(risk, dict) else (risk or "")
            biz = detail.get("productivity")
            biz = biz.get("name", "") if isinstance(biz, dict) else (biz or "")
            rules_html = "<br>".join(esc(x) for x in sorted(ruleset))
            rows.append("<tr>" + "".join([
                f"<td>{esc(kind)}</td>",
                f"<td>{esc(name)}</td>",
                f"<td>{esc(risk)}</td>",
                f"<td>{esc(biz)}</td>",
                f"<td>{len(ruleset)}</td>",
                f'<td class="cell-wrap">{rules_html}</td>',
            ]) + "</tr>")

        headers = ["Type", "Name", "Risk", "Business Relevance", "Used by (rules)", "Rules"]
        note = (
            '<div class="note">Only the applications, URLs, and URL categories <b>actually referenced '
            'by access rules</b> — the migration-relevant L7 set (vs the full predefined catalog). '
            'Each is linked to the rules that enforce it, with catalog risk/type for mapping to '
            'Palo App-ID / Fortinet application control. Empty here means no rule uses L7 matching.</div>'
        )
        body = (
            "<h2>Applications &amp; URLs In Use</h2>"
            + self.site.cards([(str(len(rows)), "L7 objects in use")])
            + note
            + self.site.searchbox("aiu", "aiucnt", export_csv="apps_in_use.csv")
            + f'<div class="meta"><span id="aiucnt">{len(rows)}</span> rows</div>'
            + self.site.table("aiu", headers, rows)
        )
        self.site.page("apps_in_use.html", "Apps & URLs In Use", body)

    def page_dashboard(self) -> None:
        c = self.counts
        host = self.snap.get("host", "")
        ver = self.snap.get("server_version", "")
        collected = (self.snap.get("collected_at") or "")[:19].replace("T", " ")

        body = [
            f"<h2>FMC Dashboard</h2>",
            f'<div class="note">Read-only snapshot from <span class="mono">{esc(host)}</span>'
            f' · FMC {esc(ver)} · collected {esc(collected)} UTC</div>',
        ]
        if self.multi_domain:
            body.append(
                '<div class="note-warn">Multi-domain collect — tables include a '
                "<strong>Domain</strong> column; per-domain JSON lives under "
                "<code>domains/&lt;slug&gt;/</code>.</div>"
            )
        elif self.snap.get("domain_collects"):
            dc = self.snap["domain_collects"][0]
            body.append(
                f'<div class="note">Single domain bundle: '
                f'<span class="mono">{esc(dc.get("name") or dc.get("slug", ""))}</span> '
                f'(path <code>{esc(dc.get("path", ""))}</code>)</div>'
            )
        body.extend([
            '<div class="section-title">Inventory</div>',
            self.site.cards([
                (str(c.get("devices", len(self.snap.get("devices") or []))), "Managed devices", "good"),
                (str(c.get("interfaces", len(self.snap.get("interfaces") or []))), "Interfaces", ""),
                (str(c.get("routes", len(self.snap.get("routes") or []))), "Static routes", ""),
                (str(len(self.snap.get("domains") or [])), "Domains", ""),
            ]),
            '<div class="section-title">Policy</div>',
            self.site.cards([
                (str(c.get("access_policies", 0)), "Access policies", ""),
                (str(c.get("access_rules", 0)), "Access rules", "warn" if c.get("access_rules", 0) > 500 else ""),
                (str(c.get("nat_policies", 0)), "NAT policies", ""),
                (str(c.get("nat_rules", 0)), "NAT rules", ""),
            ]),
            '<div class="section-title">Objects</div>',
            self.site.cards([
                (str(c.get("applications", 0)), "Applications", ""),
                (str(c.get("hosts", 0)), "Hosts", ""),
                (str(c.get("networks", 0)), "Networks", ""),
                (str(c.get("fqdns", 0)), "FQDNs", ""),
                (str(c.get("urls", 0)), "URLs", ""),
                (str(c.get("network_groups", 0)), "Network groups", ""),
                (str(c.get("security_zones", 0)), "Security zones", ""),
            ]),
            '<div class="section-title">L4–L7 policies</div>',
            self.site.cards([
                (str(c.get("intrusion_policies", 0)), "Intrusion", ""),
                (str(c.get("file_policies", 0)), "File/Malware", ""),
                (str(c.get("prefilter_policies", 0)), "Prefilter", ""),
                (str(c.get("dns_policies", 0)), "DNS", ""),
                (str(c.get("ssl_policies", 0)), "SSL", "warn"),
            ]),
        ])

        devices = self.snap.get("devices") or []
        if devices:
            body.append('<div class="section-title">Managed devices <span class="count">(click to drill down)</span></div>')
            rows = []
            dev_cols = ["Device", "Mgmt IP", "Model", "Health", "Deployment", "Access policy", "Ifaces", "Routes"]
            if self.multi_domain:
                dev_cols.insert(1, "Domain")
            for d in devices:
                name = d.get("name", "")
                slug = d.get("slug") or safe_slug(name)
                cells = [f'<td><a class="row-link" href="devices/{esc(slug)}.html">{esc(name)}</a></td>']
                if self.multi_domain:
                    cells.append(f"<td>{esc(d.get('domain', ''))}</td>")
                cells.extend([
                    f"<td>{esc(d.get('hostname', ''))}</td>",
                    f"<td>{esc(d.get('model', ''))}</td>",
                    f"<td>{health_badge(d.get('health', ''))}</td>",
                    f"<td>{deployment_badge(d.get('deployment', ''))}</td>",
                    f"<td>{esc(d.get('access_policy') or '—')}</td>",
                    f"<td>{d.get('iface_count', 0)}</td>",
                    f"<td>{d.get('route_count', 0)}</td>",
                ])
                rows.append("<tr>" + "".join(cells) + "</tr>")
            body.append(
                self.site.table(
                    "dashdev",
                    dev_cols,
                    rows,
                )
            )

        self.site.page("index.html", "Dashboard", "".join(body))

    def page_devices(self) -> None:
        rows = []
        for d in self.snap.get("devices") or []:
            name = d.get("name", "")
            slug = d.get("slug") or safe_slug(name)
            rows.append(
                "<tr>"
                f'<td><a class="row-link" href="devices/{esc(slug)}.html">{esc(name)}</a></td>'
                f"<td>{esc(d.get('hostname', ''))}</td>"
                f"<td>{esc(d.get('model', ''))}</td>"
                f"<td>{esc(d.get('sw_version', ''))}</td>"
                f"<td>{health_badge(d.get('health', ''))}</td>"
                f"<td>{deployment_badge(d.get('deployment', ''))}</td>"
                f"<td>{esc(d.get('device_group') or '—')}</td>"
                f"<td>{esc(d.get('access_policy') or '—')}</td>"
                f"<td>{d.get('iface_count', 0)}</td>"
                f"<td>{d.get('route_count', 0)}</td>"
                "</tr>"
            )
        body = (
            "<h2>Managed Devices</h2>"
            '<div class="note">Click a device name for interfaces, static routes, and assigned policies.</div>'
            + self.site.searchbox("dev", "devcnt")
            + f'<div class="meta">Showing <span id="devcnt">{len(rows)}</span> devices</div>'
            + self.site.table(
                "dev",
                [
                    "Name",
                    "Mgmt IP",
                    "Model",
                    "Version",
                    "Health",
                    "Deployment",
                    "Device group",
                    "Access policy",
                    "Ifaces",
                    "Routes",
                ],
                rows,
            )
        )
        self.site.page("devices.html", "Managed Devices", body)

    def page_device_detail(self, dev: dict) -> None:
        name = dev.get("name", "Device")
        slug = dev.get("slug") or safe_slug(name)
        ifaces = dev.get("_ifaces") or []
        routes = dev.get("_routes") or []
        errors = dev.get("_detail_errors") or []

        body = [
            f'<div class="breadcrumb"><a href="../devices.html">Managed Devices</a> › {esc(name)}</div>',
            f"<h2>{esc(name)}</h2>",
            '<div class="device-hero">',
            f'<div class="card"><div class="n">{esc(dev.get("hostname") or "—")}</div><div class="l">Management IP</div></div>',
            f'<div class="card"><div class="n">{esc(dev.get("model") or "—")}</div><div class="l">Model</div></div>',
            f'<div class="card"><div class="n">{esc(dev.get("sw_version") or "—")}</div><div class="l">Version</div></div>',
            f'<div class="card good"><div class="n">{health_badge(dev.get("health", ""))}</div><div class="l">Health</div></div>',
            f'<div class="card"><div class="n">{deployment_badge(dev.get("deployment", ""))}</div><div class="l">Deployment</div></div>',
            f'<div class="card"><div class="n">{bool_badge(dev.get("connected"), "Connected", "Offline")}</div><div class="l">FMC link</div></div>',
            "</div>",
            '<div class="section-title">Identity &amp; policies</div>',
            self.site.table(
                "devmeta",
                ["Field", "Value"],
                [
                    f"<tr><td>Serial</td><td>{esc(dev.get('serial') or '—')}</td></tr>",
                    f"<tr><td>Performance tier</td><td>{esc(dev.get('performance') or '—')}</td></tr>",
                    f"<tr><td>FTD mode</td><td>{esc(dev.get('ftd_mode') or '—')}</td></tr>",
                    f"<tr><td>Device group</td><td>{esc(dev.get('device_group') or '—')}</td></tr>",
                    f"<tr><td>Access policy</td><td>{esc(dev.get('access_policy') or '—')}</td></tr>",
                    f"<tr><td>NAT policy</td><td>{esc(dev.get('nat_policy') or '—')}</td></tr>",
                    f"<tr><td>Intrusion policy</td><td>{esc(dev.get('intrusion_policy') or '—')}</td></tr>",
                    f"<tr><td>Snort / VDB</td><td>{esc(dev.get('snort') or '—')} · {esc(dev.get('vdb') or '—')}</td></tr>",
                    f"<tr><td>Licenses</td><td>{esc(dev.get('license_caps') or '—')}</td></tr>",
                    f"<tr><td>UUID</td><td class='mono'>{esc(dev.get('id') or '')}</td></tr>",
                ],
            ),
        ]

        if not ifaces and not routes and not dev.get("access_policy"):
            body.append(
                '<div class="note-warn">No per-device interfaces/routes in this bundle. '
                "Re-run <span class='mono'>fmc_collect_data.py</span> (full collect) so the collector "
                "can pull <span class='mono'>physicalinterfaces</span> and "
                "<span class='mono'>ipv4staticroutes</span> from FMC.</div>"
            )
        if errors:
            body.append(f'<div class="note-warn">API notes: {esc("; ".join(errors))}</div>')

        body.append(f'<div class="section-title">Interfaces <span class="count">({len(ifaces)})</span></div>')
        if ifaces:
            irows = []
            for i in ifaces:
                st = (i.get("status") or "").lower()
                st_badge = (
                    '<span class="badge b-green">up</span>'
                    if st in ("up", "true", "enabled")
                    else '<span class="badge b-amber">down</span>'
                )
                irows.append(
                    "<tr>"
                    f"<td>{esc(i.get('name', ''))}</td>"
                    f"<td class='mono'>{esc(i.get('ip', ''))}</td>"
                    f"<td>{esc(i.get('zone', ''))}</td>"
                    f"<td>{esc(i.get('mode', ''))}</td>"
                    f"<td>{st_badge}</td>"
                    f"<td>{esc(i.get('mtu', ''))}</td>"
                    "</tr>"
                )
            body.append(
                self.site.searchbox(f"if_{slug}", f"ifcnt_{slug}")
                + f'<div class="meta"><span id="ifcnt_{slug}">{len(irows)}</span> interfaces</div>'
                + self.site.table(f"if_{slug}", ["Interface", "IPv4", "Zone", "Mode", "Status", "MTU"], irows)
            )
        else:
            body.append('<div class="note">No interface records returned by FMC for this device.</div>')

        body.append(f'<div class="section-title">Static routes <span class="count">({len(routes)})</span></div>')
        if routes:
            rrows = []
            for r in routes:
                rrows.append(
                    "<tr>"
                    f"<td class='mono'>{esc(r.get('destination', ''))}</td>"
                    f"<td class='mono'>{esc(r.get('gateway', ''))}</td>"
                    f"<td>{esc(r.get('interface', ''))}</td>"
                    f"<td>{esc(r.get('metric', ''))}</td>"
                    "</tr>"
                )
            body.append(
                self.site.searchbox(f"rt_{slug}", f"rtcnt_{slug}")
                + f'<div class="meta"><span id="rtcnt_{slug}">{len(rrows)}</span> routes</div>'
                + self.site.table(f"rt_{slug}", ["Destination", "Gateway", "Interface", "Metric"], rrows)
            )
        else:
            body.append('<div class="note">No static routes returned by FMC for this device.</div>')

        ap = dev.get("access_policy")
        if ap:
            rules = [r for r in self.snap.get("access_rules") or [] if r.get("policy") == ap][:50]
            body.append(
                f'<div class="section-title">Access rules — {esc(ap)} '
                f'<span class="count">(first {len(rules)} shown)</span></div>'
            )
            if rules:
                rr = []
                for r in rules:
                    rr.append(
                        "<tr>"
                        f"<td>{esc(r.get('name', ''))}</td>"
                        f"<td>{action_tag(r.get('action', ''))}</td>"
                        f"<td>{esc(r.get('source_zones', ''))}</td>"
                        f"<td>{esc(r.get('dest_zones', ''))}</td>"
                        f"<td>{esc(r.get('source_networks', ''))}</td>"
                        f"<td>{esc(r.get('dest_networks', ''))}</td>"
                        "</tr>"
                    )
                body.append(
                    self.site.table(
                        f"rules_{slug}",
                        ["Rule", "Action", "Src zone", "Dst zone", "Src net", "Dst net"],
                        rr,
                    )
                )
                total = sum(1 for r in self.snap.get("access_rules") or [] if r.get("policy") == ap)
                if total > len(rules):
                    body.append(
                        f'<div class="note"><a href="../access_rules.html">View all access rules</a> '
                        f"({total} in policy {esc(ap)})</div>"
                    )

        self.site.page(f"devices/{slug}.html", name, "".join(body), depth=1)

    def page_interfaces(self) -> None:
        ifaces = self.snap.get("interfaces") or []
        devices = sorted({i.get("device", "") for i in ifaces if i.get("device")})
        rows = []
        for i in ifaces:
            st = (i.get("status") or "").lower()
            st_badge = (
                '<span class="badge b-green">up</span>'
                if st in ("up", "true", "enabled")
                else '<span class="badge b-amber">down</span>'
            )
            rows.append(
                f"<tr data-device='{esc(i.get('device', ''))}'>"
                f"<td>{self.device_link(i.get('device', ''), 0)}</td>"
                f"<td>{esc(i.get('name', ''))}</td>"
                f"<td class='mono'>{esc(i.get('ip', ''))}</td>"
                f"<td>{esc(i.get('zone', ''))}</td>"
                f"<td>{esc(i.get('mode', ''))}</td>"
                f"<td>{st_badge}</td>"
                "</tr>"
            )
        dev_opts = "".join(f'<option value="{esc(d)}">{esc(d)}</option>' for d in devices)
        filter_js = """
<script>
(function(){
  var tbl=document.getElementById('iftbl'); if(!tbl) return;
  var q=document.querySelector('[data-target="iftbl"]'), dev=document.getElementById('ifdev'), cnt=document.getElementById('ifcnt');
  var rows=Array.prototype.slice.call(tbl.tBodies[0].rows);
  function apply(){
    var term=(q&&q.value||'').toLowerCase(), dv=dev?dev.value:'', n=0;
    rows.forEach(function(r){
      var show=true;
      if(term && r.textContent.toLowerCase().indexOf(term)<0) show=false;
      if(show && dv && r.getAttribute('data-device')!==dv) show=false;
      r.style.display=show?'':'none'; if(show) n++;
    });
    if(cnt) cnt.textContent=n;
  }
  if(q) q.addEventListener('input',apply);
  if(dev) dev.addEventListener('change',apply);
  apply();
})();
</script>"""
        body = (
            "<h2>Interfaces</h2>"
            + self.site.searchbox("iftbl", "ifcnt")
            + '<div class="filter-bar"><label>Device <select id="ifdev"><option value="">All</option>'
            + dev_opts
            + "</select></label></div>"
            + f'<div class="meta">Showing <span id="ifcnt">{len(rows)}</span> interfaces</div>'
            + self.site.table("iftbl", ["Device", "Interface", "IPv4", "Zone", "Mode", "Status"], rows)
            + filter_js
        )
        self.site.page("interfaces.html", "Interfaces", body)

    def page_routes(self) -> None:
        routes = self.snap.get("routes") or []
        devices = sorted({r.get("device", "") for r in routes if r.get("device")})
        rows = []
        for r in routes:
            rows.append(
                f"<tr data-device='{esc(r.get('device', ''))}'>"
                f"<td>{self.device_link(r.get('device', ''), 0)}</td>"
                f"<td class='mono'>{esc(r.get('destination', ''))}</td>"
                f"<td class='mono'>{esc(r.get('gateway', ''))}</td>"
                f"<td>{esc(r.get('interface', ''))}</td>"
                f"<td>{esc(r.get('metric', ''))}</td>"
                "</tr>"
            )
        dev_opts = "".join(f'<option value="{esc(d)}">{esc(d)}</option>' for d in devices)
        filter_js = """
<script>
(function(){
  var tbl=document.getElementById('rttbl'); if(!tbl) return;
  var q=document.querySelector('[data-target="rttbl"]'), dev=document.getElementById('rtdev'), cnt=document.getElementById('rtcnt');
  var rows=Array.prototype.slice.call(tbl.tBodies[0].rows);
  function apply(){
    var term=(q&&q.value||'').toLowerCase(), dv=dev?dev.value:'', n=0;
    rows.forEach(function(r){
      var show=true;
      if(term && r.textContent.toLowerCase().indexOf(term)<0) show=false;
      if(show && dv && r.getAttribute('data-device')!==dv) show=false;
      r.style.display=show?'':'none'; if(show) n++;
    });
    if(cnt) cnt.textContent=n;
  }
  if(q) q.addEventListener('input',apply);
  if(dev) dev.addEventListener('change',apply);
  apply();
})();
</script>"""
        body = (
            "<h2>Static Routes</h2>"
            + self.site.searchbox("rttbl", "rtcnt")
            + '<div class="filter-bar"><label>Device <select id="rtdev"><option value="">All</option>'
            + dev_opts
            + "</select></label></div>"
            + f'<div class="meta">Showing <span id="rtcnt">{len(rows)}</span> routes</div>'
            + self.site.table("rttbl", ["Device", "Destination", "Gateway", "Interface", "Metric"], rows)
            + filter_js
        )
        self.site.page("routes.html", "Static Routes", body)

    def page_table(
        self,
        filename: str,
        title: str,
        table_id: str,
        rows_data: list,
        columns: list,
    ) -> None:
        rows = []
        for item in rows_data:
            if not isinstance(item, dict):
                continue
            cells = []
            for col in columns:
                if len(col) == 3:
                    label, key, fmt = col
                    cells.append(f"<td>{fmt(item.get(key, ''))}</td>")
                else:
                    label, key = col
                    cells.append(f"<td>{esc(item.get(key, ''))}</td>")
            rows.append("<tr>" + "".join(cells) + "</tr>")
        csv_name = filename.rsplit(".", 1)[0] + ".csv"
        body = (
            f"<h2>{esc(title)}</h2>"
            + self.site.searchbox(table_id, f"{table_id}cnt", export_csv=csv_name)
            + f'<div class="meta"><span id="{table_id}cnt">{len(rows)}</span> rows</div>'
            + self.site.table(table_id, [c[0] for c in columns], rows)
        )
        self.site.page(filename, title, body)


def main() -> int:
    p = argparse.ArgumentParser(description="Build FMC HTML browser from collector bundle")
    p.add_argument("--input", required=True, help="run-* folder from fmc_collect_data.py")
    p.add_argument("--output", default=None, help="Output dir (default: <input>/html_view)")
    args = p.parse_args()

    run = Path(args.input)
    if not run.is_dir():
        print(f"Error: folder not found: {run}")
        return 1
    snap_path = run / "fmc_snapshot.json"
    if not snap_path.is_file():
        print(f"Error: fmc_snapshot.json not found in {run}")
        return 1

    snap = load_json(snap_path)
    if not isinstance(snap, dict):
        print("Error: invalid fmc_snapshot.json")
        return 1

    if _has_domain_subdirs(run):
        snap = merge_domain_bundles(run, snap)
    else:
        snap = enrich_snapshot(run, snap)

    out = Path(args.output) if args.output else run / "html_view"
    FMCReport(run, out, snap).build()
    print(f"Done. Open:\n  {(out / 'index.html').resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
