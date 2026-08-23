#!/usr/bin/env python3
"""
NetConverter — FortiManager read-only config pull

Exports devices, policy packages, firewall policies and objects from a
FortiManager via its JSON-RPC API (read-only). Output drops into the same
snapshot + HTML pipeline used by the other vendor collectors.

Read-only: logs in, runs only `get` calls (plus `exec` for login/logout),
never writes to the FortiManager database.

API note: this talks to the documented FortiManager JSON-RPC endpoint
(POST https://<host>/jsonrpc). Fortinet's own `pyFMG` library is just a thin
wrapper over the same API; we use `requests` directly to keep dependencies
minimal and consistent with the other collectors in this repo.

Requirements: Python 3.8+, requests

Usage:
    python fortimanager_collect.py --host fortimanager.example.com --user api_ro \
        --adom root --output .

If --adom is omitted the collector auto-detects: when Administrative Domains
are enabled it walks every visible ADOM, otherwise it uses the implicit
`root` ADOM.

License: MIT
"""

from __future__ import annotations

__version__ = "1.3.0"

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:
    print("ERROR: pip install requests")
    sys.exit(1)

import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from core.manifest import make_run_dir, write_manifest  # noqa: E402


def prefetch_cve_intel(run: Path, snap: dict, nvd_api_key: str | None, log) -> None:
    """Bake CVE threat-intel into the bundle while we are demonstrably online:
    CISA KEV + NVD CVSS for the curated advisories, NVD CPE discovery for each
    distinct FortiOS build on the managed devices (informational tier) and EPSS
    scores. Written to _cve_intel_cache.json inside the run folder, keeping the
    analysis side fully offline. Never fatal."""
    try:
        from core.cve_intel import cpe_for_version, fetch_cve_intel
        try:
            from build_html import KNOWN_CVES  # sibling module, same curated set
            cve_ids = [c["cve"] for c in KNOWN_CVES]
        except Exception:
            cve_ids = []
        cpes = sorted({cpe_for_version("fortinet", d.get("os_ver"))
                       for d in snap.get("devices", []) if isinstance(d, dict)} - {""})
        log(f"Pre-fetching CVE intel (KEV + NVD + EPSS; {len(cve_ids)} CVEs, "
            f"{len(cpes)} CPEs) ...")
        fetch_cve_intel(cve_ids, run / "_cve_intel_cache.json", offline=False,
                        cpes=cpes, nvd_api_key=nvd_api_key)
        log("  CVE intel cached in bundle (_cve_intel_cache.json)")
    except Exception as exc:  # network/import problems must never break collection
        log(f"  CVE intel pre-fetch skipped ({exc.__class__.__name__})")

MAX_RETRIES = 3
RETRY_BACKOFF = 3


def _join(value: Any) -> str:
    """Flatten FortiManager list/dict fields into a display-friendly string."""
    if value is None:
        return ""
    if isinstance(value, list):
        parts = []
        for v in value:
            if isinstance(v, dict):
                parts.append(str(v.get("name", v)))
            else:
                parts.append(str(v))
        return ", ".join(parts)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _addr_value(obj: dict) -> str:
    """Best-effort single-string value for a firewall address object."""
    t = obj.get("type")
    subnet = obj.get("subnet")
    if isinstance(subnet, list) and len(subnet) == 2:
        subnet = f"{subnet[0]}/{subnet[1]}"
    if t in (0, "ipmask") and subnet:
        return str(subnet)
    if t in (1, "iprange") or obj.get("start-ip"):
        s, e = obj.get("start-ip"), obj.get("end-ip")
        if s or e:
            return f"{s}-{e}"
    if t in (2, "fqdn") or obj.get("fqdn"):
        return str(obj.get("fqdn", ""))
    if obj.get("country"):
        return f"geo:{obj.get('country')}"
    return str(subnet or obj.get("wildcard-fqdn") or "")


def _svc_value(obj: dict) -> str:
    proto = obj.get("protocol")
    bits = []
    for key, label in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"),
                       ("sctp-portrange", "sctp")):
        v = obj.get(key)
        if v:
            bits.append(f"{label}/{_join(v)}")
    if obj.get("protocol-number"):
        bits.append(f"ip-proto {obj.get('protocol-number')}")
    if not bits and proto is not None:
        bits.append(str(proto))
    return "; ".join(bits)


def _epoch(value: Any) -> str:
    """Render FortiManager epoch timestamps as ISO date-time (UTC); passthrough otherwise."""
    try:
        n = int(value)
        if n > 100000:
            return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError, OSError, OverflowError):
        pass
    return str(value or "")


def _ipmask(value: Any) -> str:
    """FortiManager ip fields are usually [addr, netmask]; render as addr/cidr."""
    if isinstance(value, list) and len(value) == 2 and value[0]:
        addr, mask = value
        try:
            bits = sum(bin(int(o)).count("1") for o in str(mask).split("."))
            return f"{addr}/{bits}"
        except (ValueError, TypeError):
            return f"{addr} {mask}"
    if isinstance(value, str):
        return value
    return ""


# Best-effort decode of the system interface allowaccess bitmask (low bits are
# stable across FortiOS versions; unknown high bits are shown as hex).
_ALLOWACCESS_BITS = [
    (1, "ping"), (2, "https"), (4, "ssh"), (8, "snmp"),
    (16, "http"), (32, "telnet"), (64, "fgfm"), (512, "radius-acct"),
    (1024, "probe-response"), (4096, "fabric"), (16384, "speed-test"),
]


def _allowaccess(value: Any) -> str:
    try:
        n = int(value)
    except (ValueError, TypeError):
        return _join(value)
    names = [name for bit, name in _ALLOWACCESS_BITS if n & bit]
    used = sum(bit for bit, _ in _ALLOWACCESS_BITS if n & bit)
    rest = n & ~used
    if rest:
        names.append(f"0x{rest:x}")
    return " ".join(names)


# VPN phase1/phase2 proposal enum -> label (best-effort; unknown shown as p<N>).
_PROPOSAL = {
    1: "des-md5", 2: "des-sha1", 3: "3des-md5", 4: "3des-sha1",
    9: "aes128-md5", 10: "aes128-sha1", 11: "aes192-md5", 12: "aes192-sha1",
    13: "aes256-md5", 14: "aes256-sha1", 21: "aes128-sha256", 22: "aes192-sha256",
    23: "aes256-sha256", 24: "aes128-sha384", 25: "aes256-sha384",
    26: "aes128-sha512", 27: "aes256-sha512",
}


def _proposal(value: Any) -> str:
    if not isinstance(value, list):
        value = [value] if value is not None else []
    return ", ".join(_PROPOSAL.get(v, f"p{v}") for v in value)


_IKE = {1: "IKEv1", 2: "IKEv2"}
_ONOFF = {0: "disable", 1: "enable"}


class FortiManager:
    """Minimal read-only FortiManager JSON-RPC client."""

    def __init__(self, host: str, verify: bool = False):
        self.url = f"https://{host}/jsonrpc"
        self.host = host
        self.session_id: str | None = None
        self.http = requests.Session()
        self.http.verify = verify
        self._id = 0

    def _post(self, body: dict) -> dict:
        last_err = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = self.http.post(self.url, json=body, timeout=60)
                r.raise_for_status()
                return r.json()
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BACKOFF * attempt)
        raise RuntimeError(f"request failed after {MAX_RETRIES} tries: {last_err}")

    def call(self, method: str, url: str, data: Any = None, **extra) -> dict:
        self._id += 1
        params: dict[str, Any] = {"url": url}
        if data is not None:
            params["data"] = data
        params.update(extra)
        body: dict[str, Any] = {"id": self._id, "method": method, "params": [params]}
        if self.session_id:
            body["session"] = self.session_id
        return self._post(body)

    def get(self, url: str, **extra) -> tuple[int, Any]:
        """Return (status_code, data). status code 0 == OK."""
        resp = self.call("get", url, **extra)
        res = (resp.get("result") or [{}])[0]
        code = (res.get("status") or {}).get("code", -1)
        return code, res.get("data")

    def login(self, user: str, password: str) -> None:
        resp = self.call("exec", "/sys/login/user", {"user": user, "passwd": password})
        res = (resp.get("result") or [{}])[0]
        status = res.get("status", {})
        if status.get("code") != 0:
            raise RuntimeError(f"login failed: {status.get('message', status)}")
        self.session_id = resp.get("session")

    def logout(self) -> None:
        if self.session_id:
            try:
                self.call("exec", "/sys/logout")
            except Exception:  # noqa: BLE001
                pass
            self.session_id = None

    def device_monitor(self, adom: str, device: str, resource: str) -> Any:
        """Proxy a read-only GET to a managed FortiGate's own monitor API via
        /sys/proxy/json. The device must be online and reachable from the
        FortiManager. Returns the payload (str/dict/list) or None on failure."""
        resp = self.call(
            "exec", "/sys/proxy/json",
            data={
                "target": [f"adom/{adom}/device/{device}"],
                "action": "get",
                "resource": resource,
            },
        )
        results = (resp.get("result") or [{}])[0].get("data")
        if not isinstance(results, list) or not results:
            return None
        entry = results[0] if isinstance(results[0], dict) else {}
        status = entry.get("status", {})
        if isinstance(status, dict) and status.get("code") not in (0, 200, None):
            return None
        return entry.get("response", entry.get("data"))

    def device_config_backup(self, adom: str, device: str) -> str:
        """Pull a managed FortiGate's full running config (same text as a manual
        CLI/GUI backup). Returns "" on any failure."""
        payload = self.device_monitor(
            adom, device, "/api/v2/monitor/system/config/backup?scope=global")
        if isinstance(payload, str):
            return payload
        if isinstance(payload, dict):
            # Some firmware wraps the text under .response / .data
            inner = payload.get("response") or payload.get("data")
            if isinstance(inner, str):
                return inner
        return ""

    def device_config_revisions(self, adom: str, device: str) -> list[dict]:
        """List the device-local config revision history via the monitor API
        (`/api/v2/monitor/system/config-revision`). Best-effort; [] on failure."""
        payload = self.device_monitor(
            adom, device, "/api/v2/monitor/system/config-revision")
        if isinstance(payload, dict):
            payload = payload.get("results", payload.get("revisions", payload))
        if isinstance(payload, dict):
            payload = payload.get("revisions", [])
        return payload if isinstance(payload, list) else []

    def device_dhcp_leases(self, adom: str, device: str) -> list[dict]:
        """List active DHCP leases on a managed FortiGate via the monitor API
        (`/api/v2/monitor/system/dhcp`). Best-effort; [] on failure."""
        payload = self.device_monitor(adom, device, "/api/v2/monitor/system/dhcp")
        if isinstance(payload, dict):
            payload = payload.get("results", payload)
        return payload if isinstance(payload, list) else []

    # ------------------------------------------------------------------
    # Live-only state (perishable — must be captured while the device is
    # online). Config backups do NOT contain any of this. All read-only.
    # ------------------------------------------------------------------
    def device_policy_hits(self, adom: str, device: str, vdom: str = "root") -> list[dict]:
        """Live per-policy hit counters from a managed FortiGate's monitor API
        (`/api/v2/monitor/firewall/policy` + `/policy6`). Yields
        bytes/packets/last_used/first_used per policyid — the FortiGate
        equivalent of Check Point retained hit data, used to prove a rule is
        'never matched in the window'. Best-effort; [] on failure."""
        out: list[dict] = []
        for res in (
            f"/api/v2/monitor/firewall/policy?vdom={vdom}",
            f"/api/v2/monitor/firewall/policy6?vdom={vdom}",
        ):
            payload = self.device_monitor(adom, device, res)
            if isinstance(payload, dict):
                payload = payload.get("results", payload.get("data", []))
            if isinstance(payload, list):
                out.extend(x for x in payload if isinstance(x, dict))
        return out

    def device_ha_status(self, adom: str, device: str) -> Any:
        """Live HA / cluster member + sync state (`/api/v2/monitor/system/
        ha-peer`, `ha-checksum/cluster`, `ha-statistics`). Config backups do
        not reliably show live HA health / sync. Best-effort; None on failure."""
        out: dict[str, Any] = {}
        for key, res in (
            ("peers", "/api/v2/monitor/system/ha-peer"),
            ("checksum", "/api/v2/monitor/system/ha-checksum/cluster"),
            ("statistics", "/api/v2/monitor/system/ha-statistics"),
        ):
            payload = self.device_monitor(adom, device, res)
            if payload is not None:
                out[key] = (payload.get("results", payload)
                            if isinstance(payload, dict) else payload)
        return out or None

    def device_resource_usage(self, adom: str, device: str) -> Any:
        """Live resource usage incl. session count / CPU / memory
        (`/api/v2/monitor/system/resource/usage`). Small health + session-load
        snapshot; the full session table is intentionally NOT dumped (size /
        PII). Best-effort; None on failure."""
        payload = self.device_monitor(
            adom, device, "/api/v2/monitor/system/resource/usage")
        if isinstance(payload, dict):
            return payload.get("results", payload)
        return payload

    def device_routes_live(self, adom: str, device: str, vdom: str = "root") -> list[dict]:
        """Live effective routing table / FIB (`/api/v2/monitor/router/ipv4`) —
        the routes actually installed, not just the configured statics already
        captured from config. Best-effort; [] on failure."""
        payload = self.device_monitor(
            adom, device, f"/api/v2/monitor/router/ipv4?vdom={vdom}")
        if isinstance(payload, dict):
            payload = payload.get("results", payload)
        return payload if isinstance(payload, list) else []


def flatten_packages(entries: list, prefix: str = "") -> list[dict]:
    """Walk FortiManager package tree (folders contain 'subobj') -> flat pkgs."""
    out: list[dict] = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        name = e.get("name", "")
        path = f"{prefix}{name}"
        if e.get("type") == "folder" or "subobj" in e:
            out.extend(flatten_packages(e.get("subobj") or [], prefix=f"{path}/"))
        else:
            out.append(
                {
                    "name": path,
                    "type": e.get("type", "pkg"),
                    "scope": _join(e.get("scope member")),
                    "oid": e.get("oid", ""),
                }
            )
    return out


def collect_adom(fm: FortiManager, adom: str, snap: dict, log) -> None:
    base_obj = f"/pm/config/adom/{adom}/obj/firewall"

    # devices
    _, devs = fm.get(f"/dvmdb/adom/{adom}/device")
    dev_vdoms: list[tuple[str, list[str]]] = []
    for d in devs or []:
        name = d.get("name", "")
        vdoms = [v.get("name") for v in (d.get("vdom") or []) if isinstance(v, dict) and v.get("name")]
        vdoms = vdoms or ["root"]
        dev_vdoms.append((name, vdoms))
        # Build the most precise firmware string available. FortiManager exposes the
        # major train via os_ver/mr and (often) the patch level via 'patch' plus the
        # firmware build number via 'build'. When patch is present we get e.g. 7.4.3.
        _osver = str(d.get("os_ver", "")).strip()
        _mr = str(d.get("mr", "")).strip()
        _patch = str(d.get("patch", "")).strip()
        _build = str(d.get("build", "")).strip()
        _train = ".".join(p for p in (_osver, _mr) if p != "")
        _full = ".".join(p for p in (_osver, _mr, _patch) if p != "") if _patch not in ("", "-1") else _train
        snap["devices"].append(
            {
                "adom": adom,
                "name": name,
                "sn": d.get("sn", ""),
                "ip": d.get("ip", ""),
                "platform": d.get("platform_str", d.get("os_type", "")),
                "os_ver": _full,
                "os_train": _train,
                "os_patch": _patch,
                "os_build": _build,
                "ha_mode": d.get("ha_mode", ""),
                "vdoms": ", ".join(vdoms),
                "conn_status": d.get("conn_status", ""),
                "desc": d.get("desc", ""),
            }
        )
    log(f"  [{adom}] devices: {len(devs or [])}")

    # policy packages
    _, pkgs = fm.get(f"/pm/pkg/adom/{adom}")
    flat = flatten_packages(pkgs or [])
    for p in flat:
        p["adom"] = adom
        snap["packages"].append(p)
    log(f"  [{adom}] packages: {len(flat)}")

    # firewall policies per package
    for p in flat:
        pkg = p["name"]
        code, pols = fm.get(f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy")
        if code != 0 or not pols:
            continue
        for r in pols:
            snap["policies"].append(
                {
                    "adom": adom,
                    "package": pkg,
                    "policyid": r.get("policyid", ""),
                    "name": _join(r.get("name")),
                    "srcintf": _join(r.get("srcintf")),
                    "dstintf": _join(r.get("dstintf")),
                    "srcaddr": _join(r.get("srcaddr") or r.get("srcaddr6")),
                    "dstaddr": _join(r.get("dstaddr") or r.get("dstaddr6")),
                    "service": _join(r.get("service")),
                    "schedule": _join(r.get("schedule")),
                    "action": {0: "deny", 1: "accept"}.get(r.get("action"), r.get("action")),
                    "nat": {0: "disable", 1: "enable"}.get(r.get("nat"), r.get("nat")),
                    "status": {0: "disable", 1: "enable"}.get(r.get("status"), r.get("status")),
                    "comments": _join(r.get("comments")),
                }
            )
        log(f"  [{adom}] policies in '{pkg}': {len(pols)}")

    # central SNAT rules per package (only present when central-NAT is enabled)
    for p in flat:
        pkg = p["name"]
        code, snat = fm.get(f"/pm/config/adom/{adom}/pkg/{pkg}/firewall/central-snat-map")
        if code != 0 or not snat:
            continue
        for r in snat:
            snap["central_snat"].append(
                {
                    "adom": adom,
                    "package": pkg,
                    "policyid": r.get("policyid", ""),
                    "srcintf": _join(r.get("srcintf")),
                    "dstintf": _join(r.get("dstintf")),
                    "orig_addr": _join(r.get("orig-addr")),
                    "dst_addr": _join(r.get("dst-addr")),
                    "nat_ippool": _join(r.get("nat-ippool")),
                    "protocol": _join(r.get("protocol")),
                    "orig_port": _join(r.get("orig-port")),
                    "nat_port": _join(r.get("nat-port")),
                    "nat": _ONOFF.get(r.get("nat"), r.get("nat")),
                    "status": _ONOFF.get(r.get("status"), r.get("status")),
                    "comments": _join(r.get("comments")),
                }
            )
        log(f"  [{adom}] central SNAT in '{pkg}': {len(snat)}")

    # address objects + groups
    _, addrs = fm.get(f"{base_obj}/address")
    for a in addrs or []:
        snap["addresses"].append(
            {
                "adom": adom,
                "name": a.get("name", ""),
                "type": a.get("type", ""),
                "value": _addr_value(a),
                "interface": _join(a.get("associated-interface")),
                "comment": _join(a.get("comment")),
            }
        )
    _, grps = fm.get(f"{base_obj}/addrgrp")
    for g in grps or []:
        snap["address_groups"].append(
            {
                "adom": adom,
                "name": g.get("name", ""),
                "member": _join(g.get("member")),
                "comment": _join(g.get("comment")),
            }
        )
    log(f"  [{adom}] addresses: {len(addrs or [])}, groups: {len(grps or [])}")

    # services + groups
    _, svcs = fm.get(f"{base_obj}/service/custom")
    for s in svcs or []:
        snap["services"].append(
            {
                "adom": adom,
                "name": s.get("name", ""),
                "protocol": s.get("protocol", ""),
                "ports": _svc_value(s),
                "category": _join(s.get("category")),
                "comment": _join(s.get("comment")),
            }
        )
    _, sgrps = fm.get(f"{base_obj}/service/group")
    for g in sgrps or []:
        snap["service_groups"].append(
            {
                "adom": adom,
                "name": g.get("name", ""),
                "member": _join(g.get("member")),
                "comment": _join(g.get("comment")),
            }
        )
    log(f"  [{adom}] services: {len(svcs or [])}, service groups: {len(sgrps or [])}")

    # VIPs and IP pools (NAT)
    _, vips = fm.get(f"{base_obj}/vip")
    for v in vips or []:
        snap["vips"].append(
            {
                "adom": adom,
                "name": v.get("name", ""),
                "extip": _join(v.get("extip")),
                "mappedip": _join(v.get("mappedip")),
                "extport": _join(v.get("extport")),
                "mappedport": _join(v.get("mappedport")),
                "protocol": v.get("protocol", ""),
                "comment": _join(v.get("comment")),
            }
        )
    _, pools = fm.get(f"{base_obj}/ippool")
    for p in pools or []:
        snap["ippools"].append(
            {
                "adom": adom,
                "name": p.get("name", ""),
                "type": p.get("type", ""),
                "startip": _join(p.get("startip")),
                "endip": _join(p.get("endip")),
                "comment": _join(p.get("comment")),
            }
        )
    log(f"  [{adom}] vips: {len(vips or [])}, ippools: {len(pools or [])}")

    # wildcard-FQDN + IPv6 addresses / groups (folded into the address tables)
    _, wfqdn = fm.get(f"{base_obj}/wildcard-fqdn/custom")
    for a in wfqdn or []:
        snap["addresses"].append(
            {
                "adom": adom,
                "name": a.get("name", ""),
                "type": "wildcard-fqdn",
                "value": _join(a.get("wildcard-fqdn")),
                "interface": "",
                "comment": _join(a.get("comment")),
            }
        )
    _, addr6 = fm.get(f"{base_obj}/address6")
    for a in addr6 or []:
        val = _join(a.get("ip6")) or _join(a.get("fqdn")) or (
            f"{_join(a.get('start-ip'))}-{_join(a.get('end-ip'))}"
            if a.get("start-ip") else "")
        snap["addresses"].append(
            {
                "adom": adom,
                "name": a.get("name", ""),
                "type": f"ipv6/{a.get('type', '')}",
                "value": val,
                "interface": "",
                "comment": _join(a.get("comment")),
            }
        )
    _, grp6 = fm.get(f"{base_obj}/addrgrp6")
    for g in grp6 or []:
        snap["address_groups"].append(
            {
                "adom": adom,
                "name": g.get("name", ""),
                "member": _join(g.get("member")),
                "comment": f"[ipv6] {_join(g.get('comment'))}".strip(),
            }
        )
    if wfqdn or addr6 or grp6:
        log(f"  [{adom}] wildcard-fqdn: {len(wfqdn or [])}, ipv6 addrs: {len(addr6 or [])}, "
            f"ipv6 groups: {len(grp6 or [])}")

    # schedules (recurring / onetime / groups) — referenced by every policy
    _, sch_r = fm.get(f"{base_obj}/schedule/recurring")
    for s in sch_r or []:
        days = _join(s.get("day"))
        snap["schedules"].append(
            {
                "adom": adom, "name": s.get("name", ""), "kind": "recurring",
                "value": f"{days} {_join(s.get('start'))}-{_join(s.get('end'))}".strip(),
                "member": "", "comment": _join(s.get("comment")),
            }
        )
    _, sch_o = fm.get(f"{base_obj}/schedule/onetime")
    for s in sch_o or []:
        snap["schedules"].append(
            {
                "adom": adom, "name": s.get("name", ""), "kind": "onetime",
                "value": f"{_join(s.get('start'))} → {_join(s.get('end'))}",
                "member": "", "comment": _join(s.get("comment")),
            }
        )
    _, sch_g = fm.get(f"{base_obj}/schedule/group")
    for s in sch_g or []:
        snap["schedules"].append(
            {
                "adom": adom, "name": s.get("name", ""), "kind": "group",
                "value": "", "member": _join(s.get("member")),
                "comment": _join(s.get("comment")),
            }
        )
    log(f"  [{adom}] schedules: {len(sch_r or []) + len(sch_o or []) + len(sch_g or [])}")

    # security (UTM) profiles — the FortiOS equivalent of threat profiles
    for url, ptype in (("antivirus/profile", "antivirus"),
                       ("webfilter/profile", "webfilter"),
                       ("ips/sensor", "ips"),
                       ("application/list", "app-control"),
                       ("dnsfilter/profile", "dnsfilter"),
                       ("emailfilter/profile", "emailfilter"),
                       ("firewall/ssl-ssh-profile", "ssl-ssh"),
                       ("waf/profile", "waf"),
                       ("voip/profile", "voip")):
        code, profs = fm.get(f"/pm/config/adom/{adom}/obj/{url}")
        if code != 0 or not profs:
            continue
        for pr in profs:
            snap["sec_profiles"].append(
                {
                    "adom": adom, "type": ptype, "name": pr.get("name", ""),
                    "comment": _join(pr.get("comment") or pr.get("comments")),
                }
            )
    log(f"  [{adom}] security profiles: "
        f"{sum(1 for r in snap['sec_profiles'] if r['adom'] == adom)}")

    # users, user groups and authentication servers (identity-aware policy)
    _, ulocal = fm.get(f"/pm/config/adom/{adom}/obj/user/local")
    for u in ulocal or []:
        snap["users"].append(
            {
                "adom": adom, "name": u.get("name", ""),
                "type": _join(u.get("type")),
                "email": _join(u.get("email-to")),
                "status": _ONOFF.get(u.get("status"), _join(u.get("status"))),
            }
        )
    _, ugrps = fm.get(f"/pm/config/adom/{adom}/obj/user/group")
    for g in ugrps or []:
        snap["user_groups"].append(
            {
                "adom": adom, "name": g.get("name", ""),
                "member": _join(g.get("member")),
                "group_type": _join(g.get("group-type")),
            }
        )
    for url, stype in (("user/radius", "radius"), ("user/ldap", "ldap"),
                       ("user/tacacs+", "tacacs+"), ("user/saml", "saml")):
        code, srvs = fm.get(f"/pm/config/adom/{adom}/obj/{url}")
        if code != 0 or not srvs:
            continue
        for s in srvs:
            snap["auth_servers"].append(
                {
                    "adom": adom, "type": stype, "name": s.get("name", ""),
                    "server": _join(s.get("server") or s.get("idp-entity-id")),
                    "port": _join(s.get("port")),
                }
            )
    log(f"  [{adom}] users: {len(ulocal or [])}, user groups: {len(ugrps or [])}, "
        f"auth servers: {sum(1 for r in snap['auth_servers'] if r['adom'] == adom)}")

    # ADOM revision history (database snapshots taken on the FortiManager)
    _, revs = fm.get(f"/dvmdb/adom/{adom}/revision")
    for r in revs or []:
        snap["adom_revisions"].append(
            {
                "adom": adom,
                "version": r.get("version", r.get("oid", "")),
                "name": r.get("name", ""),
                "created_time": _epoch(r.get("created_time")),
                "created_by": r.get("created_by", ""),
                "locked": r.get("locked", ""),
                "desc": _join(r.get("desc")),
            }
        )
    log(f"  [{adom}] ADOM revisions: {len(revs or [])}")

    # ADOM-level (central) VPN objects, if any are managed centrally
    _, c_p1 = fm.get(f"/pm/config/adom/{adom}/obj/vpn/ipsec/phase1-interface")
    for v in c_p1 or []:
        snap["vpn_phase1"].append(_map_phase1(adom, "(central)", "", v))
    _, c_p2 = fm.get(f"/pm/config/adom/{adom}/obj/vpn/ipsec/phase2-interface")
    for v in c_p2 or []:
        snap["vpn_phase2"].append(_map_phase2(adom, "(central)", "", v))

    # Per-device, per-vdom walk: interfaces (IP), routing, VPN tunnels
    for name, vdoms in dev_vdoms:
        collect_device(fm, adom, name, vdoms, snap, log)


def _map_phase1(adom: str, device: str, vdom: str, v: dict) -> dict:
    return {
        "adom": adom,
        "device": device,
        "vdom": vdom,
        "name": v.get("name", ""),
        "interface": _join(v.get("interface")),
        "remote_gw": v.get("remote-gw", ""),
        "local_gw": v.get("local-gw", ""),
        "ike": _IKE.get(v.get("ike-version"), v.get("ike-version")),
        "mode": {0: "aggressive", 1: "main"}.get(v.get("mode"), v.get("mode")),
        "proposal": _proposal(v.get("proposal")),
        "dhgrp": _join(v.get("dhgrp")),
        "keylife": v.get("keylife", ""),
        "peertype": v.get("peertype", ""),
        "psk": "<redacted>" if v.get("psksecret") else "",
        "comments": _join(v.get("comments")),
    }


def _map_phase2(adom: str, device: str, vdom: str, v: dict) -> dict:
    return {
        "adom": adom,
        "device": device,
        "vdom": vdom,
        "name": v.get("name", ""),
        "phase1": _join(v.get("phase1name")),
        "proposal": _proposal(v.get("proposal")),
        "src_subnet": _ipmask(v.get("src-subnet")),
        "dst_subnet": _ipmask(v.get("dst-subnet")),
        "pfs": _ONOFF.get(v.get("pfs"), v.get("pfs")),
        "keylife_sec": v.get("keylifeseconds", ""),
        "comments": _join(v.get("comments")),
    }


def collect_device(fm: FortiManager, adom: str, name: str, vdoms: list[str], snap: dict, log) -> None:
    """Walk one managed FortiGate: interfaces (all vdoms), then per-vdom routing + VPN."""
    # interfaces are returned device-wide from the global scope (each carries its vdom)
    _, ifaces = fm.get(f"/pm/config/device/{name}/global/system/interface")
    for i in ifaces or []:
        snap["interfaces"].append(
            {
                "device": name,
                "vdom": _join(i.get("vdom")),
                "name": i.get("name", ""),
                "ip": _ipmask(i.get("ip")),
                "status": {0: "down", 1: "up"}.get(i.get("status"), i.get("status")),
                "allowaccess": _allowaccess(i.get("allowaccess")),
                "vlanid": i.get("vlanid") or "",
                "parent": _join(i.get("interface")),
                "alias": i.get("alias") or "",
                "description": i.get("description") or "",
            }
        )
    n_if = len(ifaces or [])

    # device DNS (global scope, single object)
    _, dns = fm.get(f"/pm/config/device/{name}/global/system/dns")
    if isinstance(dns, dict) and (dns.get("primary") or dns.get("secondary")):
        snap["device_dns"].append(
            {
                "device": name,
                "primary": _join(dns.get("primary")),
                "secondary": _join(dns.get("secondary")),
                "domain": _join(dns.get("domain")),
            }
        )

    # device-local administrator accounts (global scope)
    _, admins = fm.get(f"/pm/config/device/{name}/global/system/admin")
    for a in admins or []:
        trust = ", ".join(
            _ipmask(a.get(k)) for k in ("trusthost1", "trusthost2", "trusthost3")
            if a.get(k) and _ipmask(a.get(k)) not in ("0.0.0.0/0", ""))
        snap["device_admins"].append(
            {
                "device": name,
                "name": a.get("name", ""),
                "profile": _join(a.get("accprofile")),
                "trusthosts": trust,
                "vdoms": _join(a.get("vdom")),
                "two_factor": _join(a.get("two-factor")) or "disable",
            }
        )

    n_rt = n_p1 = n_p2 = n_zn = n_dh = 0
    for vdom in vdoms:
        # static routes
        _, routes = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/router/static")
        for r in routes or []:
            snap["routes"].append(
                {
                    "device": name,
                    "vdom": vdom,
                    "seq": r.get("seq-num", ""),
                    "dst": _ipmask(r.get("dst")) or _join(r.get("dstaddr")) or "0.0.0.0/0",
                    "gateway": r.get("gateway", ""),
                    "interface": _join(r.get("device")),
                    "distance": r.get("distance", ""),
                    "priority": r.get("priority", ""),
                    "status": {0: "disable", 1: "enable"}.get(r.get("status"), r.get("status")),
                    "blackhole": _ONOFF.get(r.get("blackhole"), r.get("blackhole")),
                    "comment": _join(r.get("comment")),
                }
            )
        n_rt += len(routes or [])

        # VPN phase1 / phase2 (interface mode)
        _, p1 = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/vpn/ipsec/phase1-interface")
        for v in p1 or []:
            snap["vpn_phase1"].append(_map_phase1(adom, name, vdom, v))
        n_p1 += len(p1 or [])
        _, p2 = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/vpn/ipsec/phase2-interface")
        for v in p2 or []:
            snap["vpn_phase2"].append(_map_phase2(adom, name, vdom, v))
        n_p2 += len(p2 or [])

        # SSL VPN settings (single object per vdom)
        _, ssl = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/vpn/ssl/settings")
        if isinstance(ssl, dict) and ssl.get("status") not in (None, 0, "disable"):
            snap["vpn_ssl"].append(
                {
                    "device": name,
                    "vdom": vdom,
                    "status": _ONOFF.get(ssl.get("status"), ssl.get("status")),
                    "port": ssl.get("port", ""),
                    "source_interface": _join(ssl.get("source-interface")),
                    "tunnel_ip_pools": _join(ssl.get("tunnel-ip-pools")),
                    "servercert": _join(ssl.get("servercert")),
                }
            )

        # security zones (interface groupings used in policy)
        _, zones = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/system/zone")
        for z in zones or []:
            snap["zones"].append(
                {
                    "device": name,
                    "vdom": vdom,
                    "name": z.get("name", ""),
                    "interfaces": _join(z.get("interface")),
                    "intrazone": {0: "deny", 1: "allow"}.get(
                        z.get("intrazone"), _join(z.get("intrazone"))),
                }
            )
        n_zn += len(zones or [])

        # DHCP servers
        _, dhcp = fm.get(f"/pm/config/device/{name}/vdom/{vdom}/system/dhcp/server")
        for d in dhcp or []:
            ranges = d.get("ip-range")
            if isinstance(ranges, list):
                rng = ", ".join(
                    f"{_join(r.get('start-ip'))}-{_join(r.get('end-ip'))}"
                    for r in ranges if isinstance(r, dict))
            else:
                rng = ""
            dns_srv = ", ".join(
                _join(d.get(k)) for k in ("dns-server1", "dns-server2", "dns-server3")
                if d.get(k) and _join(d.get(k)) != "0.0.0.0")
            snap["dhcp_servers"].append(
                {
                    "device": name,
                    "vdom": vdom,
                    "id": d.get("id", ""),
                    "interface": _join(d.get("interface")),
                    "range": rng,
                    "netmask": _join(d.get("netmask")),
                    "gateway": _join(d.get("default-gateway")),
                    "dns": dns_srv,
                    "domain": _join(d.get("domain")),
                    "lease": _join(d.get("lease-time")),
                }
            )
        n_dh += len(dhcp or [])

    if n_if or n_rt or n_p1 or n_p2 or n_zn or n_dh:
        log(f"  [{adom}] {name}: {n_if} intf, {n_rt} routes, {n_p1} ph1, {n_p2} ph2, "
            f"{n_zn} zones, {n_dh} dhcp")


def create_zip(run: Path, log) -> Path:
    """Package a collection run folder into a single fortinet_audit_<stamp>.zip
    (alongside the run folder, mirroring the Check Point collector). Entries are
    prefixed with the run-id so the archive extracts into its own folder."""
    import zipfile

    stamp = run.name.replace("run-", "")
    zip_path = run.parent / f"fortinet_audit_{stamp}.zip"
    files = [Path(r) / f for r, _, fs in os.walk(run) for f in fs]
    log(f"Creating zip ({len(files)} files) -> {zip_path.name} ...")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for full in files:
            zf.write(full, Path(run.name) / full.relative_to(run))
    log(f"  Zip created: {zip_path.name}")
    return zip_path


def main() -> int:
    p = argparse.ArgumentParser(description="FortiManager read-only collect (NetConverter)")
    p.add_argument("--host", required=True, help="FortiManager hostname or IP")
    p.add_argument("--user", required=True, help="API username")
    p.add_argument("--password", help="Password (prompted if omitted)")
    p.add_argument("--adom", default=None, help="ADOM name (default: auto-detect / all)")
    p.add_argument("--output", default=".", help="Output parent directory")
    p.add_argument("--verify-tls", action="store_true",
                   help="Verify the FortiManager TLS certificate (default: off, self-signed)")
    p.add_argument("--insecure", action="store_true",
                   help="(Deprecated, default behaviour) Skip TLS verification")
    p.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                   help="Optional NVD API key (or NVD_API_KEY env) for the CVE-intel "
                        "pre-fetch — raises the NVD rate limit from 5 to 50 req/30s.")
    p.add_argument("--pull-device-configs", action="store_true",
                   help="(Deprecated — now the default.) Pull each managed FortiGate's "
                        "full running config via /sys/proxy/json.")
    p.add_argument("--no-live-state", action="store_true",
                   help="Skip live-only per-device state (policy hit counters, HA/"
                        "cluster sync, session load, effective routes). Live state "
                        "is captured by default via /sys/proxy/json to each online "
                        "device — it is PERISHABLE (only available while devices are "
                        "reachable) and required for behavior-preserving rule review.")
    p.add_argument("--no-device-configs", action="store_true",
                   help="Skip pulling per-device running configs and device revision "
                        "history (configs land under '<run>/Local Configs/'; they capture "
                        "device-local firewall policies/objects not managed centrally).")
    p.add_argument("--zip", action="store_true",
                   help="Package the collection bundle into a single "
                        "fortinet_audit_<timestamp>.zip in the output directory.")
    p.add_argument("--no-extract", action="store_true",
                   help="With --zip, remove the extracted run folder afterwards so only "
                        "the .zip remains. Ignored unless --zip is set.")
    args = p.parse_args()
    password = args.password or getpass("FortiManager password: ")
    pull_configs = not args.no_device_configs
    pull_live = not args.no_live_state

    progress: list[str] = []

    def log(msg: str) -> None:
        print(msg, flush=True)
        progress.append(f"{datetime.now().strftime('%H:%M:%S')} {msg}")

    print("NetConverter — FortiManager read-only collection")
    print(f"  Host: {args.host}")
    print("  Mode: READ-ONLY (get calls only)")
    if not args.verify_tls:
        print("  NOTE: TLS verification OFF (typical for self-signed FortiManager certs).")

    t0 = time.time()
    fm = FortiManager(args.host, verify=bool(args.verify_tls))
    snap: dict[str, Any] = {
        "host": args.host,
        "adoms": [],
        "devices": [],
        "packages": [],
        "policies": [],
        "central_snat": [],
        "addresses": [],
        "address_groups": [],
        "services": [],
        "service_groups": [],
        "schedules": [],
        "vips": [],
        "ippools": [],
        "sec_profiles": [],
        "users": [],
        "user_groups": [],
        "auth_servers": [],
        "interfaces": [],
        "routes": [],
        "zones": [],
        "dhcp_servers": [],
        "dhcp_leases": [],
        "device_dns": [],
        "device_admins": [],
        "fmg_admins": [],
        "adom_revisions": [],
        "device_revisions": [],
        "vpn_phase1": [],
        "vpn_phase2": [],
        "vpn_ssl": [],
        # live-only state (perishable; requires online devices)
        "policy_hits": [],
        "ha_status": [],
        "sessions": [],
        "routes_live": [],
    }
    errors: list[str] = []
    device_configs: dict[str, str] = {}
    live_raw: dict[str, dict] = {}
    try:
        log("Connecting / login ...")
        fm.login(args.user, password)
        log("  Login OK")

        _, status = fm.get("/sys/status")
        if isinstance(status, dict):
            snap["hostname"] = status.get("Hostname", "")
            snap["platform"] = status.get("Platform Full Name", "")
            snap["version"] = (
                f"{status.get('Major', '')}.{status.get('Minor', '')}.{status.get('Patch', '')}"
            )
            snap["serial"] = status.get("Serial Number", "")
            snap["adom_mode"] = status.get("Admin Domain Configuration", "")
            snap["status"] = status

        # determine ADOM list
        if args.adom:
            adom_names = [args.adom]
        else:
            _, adoms = fm.get("/dvmdb/adom", fields=["name"])
            adom_names = [a.get("name") for a in (adoms or []) if a.get("name")]
            if not adom_names:
                adom_names = ["root"]  # ADOMs disabled -> implicit root
        snap["adoms"] = adom_names
        log(f"  ADOMs to collect: {', '.join(adom_names)}")

        for adom in adom_names:
            log(f"Collecting ADOM '{adom}' ...")
            try:
                collect_adom(fm, adom, snap, log)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{adom}: {exc}")
                log(f"  ERROR in ADOM '{adom}': {exc}")

        # FortiManager administrator accounts (who can change what)
        try:
            _, fmg_admins = fm.get("/cli/global/system/admin/user")
            for a in fmg_admins or []:
                snap["fmg_admins"].append(
                    {
                        "userid": a.get("userid", ""),
                        "profile": _join(a.get("profileid")),
                        "type": _join(a.get("user_type")),
                        "adoms": _join(a.get("adom")),
                        "description": _join(a.get("description")),
                    }
                )
            log(f"FortiManager admins: {len(snap['fmg_admins'])}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"fmg-admins: {exc}")

        if pull_configs:
            log("Pulling per-device running configs, revisions + DHCP leases via /sys/proxy/json ...")
            for d in snap["devices"]:
                name = d.get("name")
                adom = d.get("adom") or (snap["adoms"][0] if snap["adoms"] else "root")
                if not name:
                    continue
                try:
                    text = fm.device_config_backup(adom, name)
                except Exception as exc:  # noqa: BLE001
                    text = ""
                    errors.append(f"config-pull {name}: {exc}")
                if text and ("config firewall" in text or "config system" in text):
                    device_configs[name] = text
                    log(f"  [{adom}] {name}: config pulled ({len(text):,} bytes)")
                else:
                    log(f"  [{adom}] {name}: config unavailable (device offline?)")
                try:
                    revs = fm.device_config_revisions(adom, name)
                except Exception as exc:  # noqa: BLE001
                    revs = []
                    errors.append(f"revisions {name}: {exc}")
                for r in revs:
                    if not isinstance(r, dict):
                        continue
                    snap["device_revisions"].append(
                        {
                            "device": name,
                            "adom": adom,
                            "id": r.get("id", r.get("revision", "")),
                            "time": _epoch(r.get("time") or r.get("created_time")),
                            "admin": _join(r.get("admin") or r.get("created_by")),
                            "comment": _join(r.get("comment") or r.get("desc")),
                        }
                    )
                if revs:
                    log(f"  [{adom}] {name}: {len(revs)} config revision(s) on device")
                try:
                    leases = fm.device_dhcp_leases(adom, name)
                except Exception as exc:  # noqa: BLE001
                    leases = []
                    errors.append(f"dhcp-leases {name}: {exc}")
                for l in leases:
                    if not isinstance(l, dict):
                        continue
                    snap["dhcp_leases"].append(
                        {
                            "device": name,
                            "adom": adom,
                            "ip": l.get("ip", ""),
                            "mac": l.get("mac", ""),
                            "hostname": _join(l.get("hostname", "")),
                            "interface": _join(l.get("interface", "")),
                            "status": _join(l.get("status", "")),
                            "expires": _epoch(l.get("expire_time") or l.get("expire")),
                            "reserved": "yes" if l.get("reserved") else "",
                            "vci": _join(l.get("vci", "")),
                            "server_id": l.get("server_mkey", ""),
                        }
                    )
                if leases:
                    log(f"  [{adom}] {name}: {len(leases)} active DHCP lease(s)")

        if pull_live:
            log("Pulling live-only state (policy hits, HA sync, session load, "
                "effective routes) via /sys/proxy/json ...")
            for d in snap["devices"]:
                name = d.get("name")
                adom = d.get("adom") or (snap["adoms"][0] if snap["adoms"] else "root")
                if not name:
                    continue
                vdoms = [v.strip() for v in str(d.get("vdoms") or "root").split(",") if v.strip()] or ["root"]

                # --- policy hit counters (per VDOM): the parity-critical dataset ---
                hit_rows = 0
                for vdom in vdoms:
                    try:
                        hits = fm.device_policy_hits(adom, name, vdom)
                    except Exception as exc:  # noqa: BLE001
                        hits = []
                        errors.append(f"policy-hits {name}/{vdom}: {exc}")
                    for r in hits:
                        snap["policy_hits"].append(
                            {
                                "device": name,
                                "adom": adom,
                                "vdom": vdom,
                                "policyid": r.get("policyid", ""),
                                "name": _join(r.get("name", "")),
                                "bytes": r.get("bytes", 0),
                                "packets": r.get("packets", 0),
                                "active_sessions": r.get(
                                    "active_sessions", r.get("session_count", 0)),
                                "hit_count": r.get("hit_count", r.get("hitcount", "")),
                                "first_used": _epoch(
                                    r.get("first_used") or r.get("first_hit")),
                                "last_used": _epoch(
                                    r.get("last_used") or r.get("last_hit")),
                            }
                        )
                        hit_rows += 1
                if hit_rows:
                    log(f"  [{adom}] {name}: {hit_rows} policy hit-counter row(s)")
                else:
                    log(f"  [{adom}] {name}: no live policy hits (device offline?)")

                # --- HA / cluster sync state ---
                try:
                    ha = fm.device_ha_status(adom, name)
                except Exception as exc:  # noqa: BLE001
                    ha = None
                    errors.append(f"ha-status {name}: {exc}")
                if ha is not None:
                    snap["ha_status"].append({"device": name, "adom": adom, "ha": ha})
                    live_raw.setdefault(name, {})["ha_status"] = ha

                # --- resource usage (session load / CPU / mem health snapshot) ---
                try:
                    usage = fm.device_resource_usage(adom, name)
                except Exception as exc:  # noqa: BLE001
                    usage = None
                    errors.append(f"resource-usage {name}: {exc}")
                if usage is not None:
                    snap["sessions"].append({"device": name, "adom": adom, "usage": usage})
                    live_raw.setdefault(name, {})["resource_usage"] = usage

                # --- effective routing table / FIB (per VDOM) ---
                route_rows = 0
                for vdom in vdoms:
                    try:
                        routes = fm.device_routes_live(adom, name, vdom)
                    except Exception as exc:  # noqa: BLE001
                        routes = []
                        errors.append(f"routes-live {name}/{vdom}: {exc}")
                    for r in routes:
                        if not isinstance(r, dict):
                            continue
                        snap["routes_live"].append(
                            {
                                "device": name,
                                "adom": adom,
                                "vdom": vdom,
                                "dst": _join(r.get("ip_mask") or r.get("network") or r.get("dst")),
                                "gateway": _join(r.get("gateway", "")),
                                "interface": _join(r.get("interface", "")),
                                "type": _join(r.get("type", "")),
                                "distance": r.get("distance", ""),
                                "metric": r.get("metric", ""),
                            }
                        )
                        route_rows += 1
                    live_raw.setdefault(name, {}).setdefault("routes_live", {})[vdom] = routes
                if route_rows:
                    log(f"  [{adom}] {name}: {route_rows} live route(s)")
    finally:
        fm.logout()

    run = make_run_dir(args.output)
    (run / "fortimanager_snapshot.json").write_text(
        json.dumps(snap, indent=2) + "\n", encoding="utf-8"
    )
    prefetch_cve_intel(run, snap, args.nvd_api_key.strip() or None, log)
    if device_configs:
        cfg_dir = run / "Local Configs"
        cfg_dir.mkdir(exist_ok=True)
        for name, text in device_configs.items():
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
            (cfg_dir / f"{safe}.conf").write_text(text, encoding="utf-8")
        print(f"  Saved {len(device_configs)} device config(s) -> {cfg_dir}")
    if live_raw:
        live_dir = run / "live-state"
        for name, payloads in live_raw.items():
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
            dev_dir = live_dir / safe
            dev_dir.mkdir(parents=True, exist_ok=True)
            for key, payload in payloads.items():
                (dev_dir / f"{key}.json").write_text(
                    json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"  Saved live-state for {len(live_raw)} device(s) -> {run / 'live-state'}")
    duration = round(time.time() - t0, 1)

    # collection-summary.csv — dataset/row-count matrix (parity with the
    # Check Point collector's export summary; quick coverage check offline).
    with (run / "collection-summary.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["dataset", "rows", "status", "note"])
        for k, v in snap.items():
            if isinstance(v, list) and k != "adoms":
                w.writerow([k, len(v), "ok" if v else "empty", ""])
        w.writerow(["device_configs", len(device_configs),
                    "ok" if device_configs else "empty",
                    "Local Configs/*.conf" if device_configs else
                    ("skipped (--no-device-configs)" if not pull_configs
                     else "devices offline / unreachable")])
        w.writerow(["live_state", len(live_raw),
                    "ok" if snap["policy_hits"] else "empty",
                    "live-state/<device>/*.json + policy_hits in snapshot"
                    if snap["policy_hits"] else
                    ("skipped (--no-live-state)" if not pull_live
                     else "devices offline / unreachable — hit counts NOT captured")])
        for e in errors:
            w.writerow(["error", "", "error", e])

    write_manifest(
        run,
        vendor="fortinet_fortimanager",
        collector="fortimanager_collect.py",
        collector_version=__version__,
        host=args.host,
        extra={
            "adoms": snap["adoms"],
            "duration_sec": duration,
            "status": "ok" if not errors else "partial",
            "errors": errors,
            "device_configs_pulled": len(device_configs),
            "counts": {k: len(v) for k, v in snap.items() if isinstance(v, list)},
        },
    )

    print()
    print(f"Done in {duration}s. Bundle: {run}")
    for k, v in snap.items():
        if isinstance(v, list) and k != "adoms":
            print(f"  {k:16} {len(v)}")
    if errors:
        print(f"  errors: {len(errors)}")
    (run / "collection-progress.log").write_text(
        "\n".join(progress) + "\n", encoding="utf-8")

    zip_path = None
    if args.zip:
        print()
        zip_path = create_zip(run, log)
        if args.no_extract:
            import shutil
            shutil.rmtree(run, ignore_errors=True)
            log(f"  Removed extracted folder; kept zip only: {zip_path.name}")

    print()
    if args.zip and args.no_extract:
        print(f"Bundle (zip only): {zip_path}")
        print("Next: build the HTML browser (build_html reads an extracted run folder)")
        print(f"  Expand-Archive '{zip_path}' -DestinationPath '{run.parent}'")
        print(f"  python build_html.py --input {run}")
    else:
        if zip_path:
            print(f"Zip: {zip_path}")
        print("Next: build the HTML browser")
        print(f"  python build_html.py --input {run}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
