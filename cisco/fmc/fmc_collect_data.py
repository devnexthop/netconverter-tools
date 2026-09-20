#!/usr/bin/env python3
"""
NetConverter — Cisco FMC read-only data collection

Pulls Cisco Secure FMC configuration via the REST API into a portable JSON bundle
for local HTML browsing and (later) NetConverter.local ingest.

Read-only: token auth + GET only — no writes to FMC.

Usage:
    python fmc_collect_data.py --host 10.1.1.100 --user api_ro --output .
    python fmc_collect_data.py --host fmc.example.com --user admin --password 'secret'
    python fmc_collect_data.py --host 192.168.1.50 --user ro --insecure --quick

License: MIT
"""

from __future__ import annotations

__version__ = "2.3.3"

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urljoin, urlsplit

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from safe_stdio import configure_stdio, safe_print  # noqa: E402

configure_stdio()

COLLECTOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    import subprocess

    safe_print("First run: installing required Python package 'requests' …")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"], stdout=subprocess.DEVNULL)
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from core.manifest import make_run_dir, write_manifest  # noqa: E402

BANNER = "NetConverter FMC Collection"


def normalize_host(host: str) -> str:
    """Accept IP, hostname, or accidental https:// prefix."""
    host = host.strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix) :]
    return host.rstrip("/").split("/")[0]
MAX_RETRIES = 3
RETRY_BACKOFF = 4
AUTH_MAX_RETRIES = 6   # token endpoint on lab/sandbox FMCs is transiently flaky (401/timeout)
AUTH_BACKOFF = 5       # seconds, multiplied by attempt number
PAGE_SIZE = 1000
MAX_PAGES = 10000
MAX_ITEMS = 1000000
TOKEN_VALIDITY_SEC = 30 * 60
TOKEN_REFRESH_BUFFER_SEC = 5 * 60

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nonnegative_int(value: Any) -> int:
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("Invalid nonnegative paging integer")
    return int(value)


def _next_offsets(endpoint: str, value: Any) -> list[int]:
    """FMC can list all future pages; validate them and retain ordered offsets."""
    if value in (None, [], ""):
        return []
    values = value if isinstance(value, list) else [value]
    if len(values) > MAX_PAGES:
        raise ValueError("Too many next-page links")
    base = urlsplit(endpoint)
    offsets = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("Invalid next-page link")
        link = urlsplit(urljoin(endpoint, value))
        if (link.scheme != "https" or link.netloc.lower() != base.netloc.lower()
                or link.path != base.path or link.username or link.password or link.fragment):
            raise ValueError("Next page must remain on the same HTTPS origin and endpoint")
        query = parse_qs(link.query, keep_blank_values=True)
        if len(query.get("offset", [])) != 1:
            raise ValueError("Next page needs one explicit offset")
        offsets.append(_nonnegative_int(query["offset"][0]))
    if len(set(offsets)) != len(offsets):
        raise ValueError("Duplicate next-page offsets")
    return sorted(offsets)


def _endpoint_evidence(client: FMCClient, path: str) -> dict:
    evidence = getattr(client, "endpoint_evidence", {})
    return evidence.get(path, {}) if isinstance(evidence, dict) else {}


def _save_evidence(client: FMCClient, run: Path, snap: dict) -> None:
    """Separate provenance; native API records above remain untouched."""
    evidence = {"schema_version": 1, "vendor": "cisco_fmc", "collector": "fmc_collect_data.py",
                "collector_version": __version__, "collector_sha256": COLLECTOR_SHA256,
                "domain_id": client.domain_uuid,
                "endpoints": copy.deepcopy(client.endpoint_evidence)}
    snap["collection_evidence"] = evidence
    _safe_json_write(run / "collection-evidence.json", evidence)


# (API path under /object/, output filename, snapshot list key)
OBJECT_EXPORTS: list[tuple[str, str, str]] = [
    ("hosts", "objects-hosts.json", "hosts"),
    ("networks", "objects-networks.json", "networks"),
    ("ranges", "objects-ranges.json", "ranges"),
    ("networkgroups", "objects-networkgroups.json", "network_groups"),
    ("protocolportobjects", "objects-protocolports.json", "protocol_ports"),
    ("portobjectgroups", "objects-portgroups.json", "port_groups"),
    ("icmpv4objects", "objects-icmpv4.json", "icmpv4"),
    ("icmpv6objects", "objects-icmpv6.json", "icmpv6"),
    ("urls", "objects-urls.json", "urls"),
    ("urlgroups", "objects-urlgroups.json", "url_groups"),
    ("urlcategories", "objects-urlcategories.json", "url_categories"),
    ("fqdns", "objects-fqdns.json", "fqdns"),
    ("securityzones", "objects-securityzones.json", "security_zones"),
    ("interfacegroups", "objects-interfacegroups.json", "interface_groups"),
    ("vlantags", "objects-vlantags.json", "vlan_tags"),
    ("vlangrouptags", "objects-vlangrouptags.json", "vlan_group_tags"),
    ("geolocations", "objects-geolocations.json", "geolocations"),
    ("applications", "objects-applications.json", "applications"),
    ("applicationfilters", "objects-applicationfilters.json", "application_filters"),
    ("applicationcategories", "objects-applicationcategories.json", "application_categories"),
    ("applicationtags", "objects-applicationtags.json", "application_tags"),
    ("variablesets", "objects-variablesets.json", "variable_sets"),
    ("realms", "objects-realms.json", "realms"),
    ("networkfeeds", "objects-networkfeeds.json", "network_feeds"),
    ("dynamicobjects", "objects-dynamicobjects.json", "dynamic_objects"),
    ("ikev1policies", "objects-ikev1policies.json", "ikev1_policies"),
    ("ikev2policies", "objects-ikev2policies.json", "ikev2_policies"),
    ("ikev1ipsecproposals", "objects-ikev1ipsecproposals.json", "ikev1_ipsec_proposals"),
    ("ikev2ipsecproposals", "objects-ikev2ipsecproposals.json", "ikev2_ipsec_proposals"),
]

# Inventory / device-management (not under /object/)
INVENTORY_EXPORTS: list[tuple[str, str, str]] = [
    ("devices/devicegrouprecords", "inventory-devicegroups.json", "device_groups"),
    ("devices/ftddevicecluster", "inventory-ftdclusters.json", "ftd_clusters"),
]

# Policy containers — optional nested rule endpoints per policy type
# (api segment, list filename, snapshot key, rule segments or None)
POLICY_EXPORTS: list[tuple[str, str, str, list[str] | None]] = [
    ("accesspolicies", "policies-access.json", "access_policies", ["accessrules"]),
    ("ftdnatpolicies", "policies-nat.json", "nat_policies", ["autonatrules", "manualnatrules", "natrules"]),
    ("prefilterpolicies", "policies-prefilter.json", "prefilter_policies", ["prefilterrules"]),
    ("intrusionpolicies", "policies-intrusion.json", "intrusion_policies", None),
    ("filepolicies", "policies-file.json", "file_policies", None),
    ("sslpolicies", "policies-ssl.json", "ssl_policies", None),
    ("dnspolicies", "policies-dns.json", "dns_policies", ["dnsrules"]),
    ("identitypolicies", "policies-identity.json", "identity_policies", None),
    ("healthpolicies", "policies-health.json", "health_policies", None),
]

# Quick-mode subsets
QUICK_OBJECT_EXPORTS = ("hosts", "networks", "securityzones", "applications")
QUICK_POLICY_EXPORTS = 2  # access + NAT only


def _ref_name(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, dict):
        if val.get("type") == "ApplicationCategory" and val.get("name"):
            return f"cat:{val['name']}"
        return str(val.get("name") or val.get("value") or val.get("id") or "")
    if isinstance(val, list):
        return ", ".join(_ref_name(v) for v in val if v)
    return str(val)


def _iter_refs(val: Any):
    """Walk FMC nested object references (objects/literals/filters)."""
    if val is None:
        return
    if isinstance(val, dict):
        if isinstance(val.get("objects"), list):
            for item in val["objects"]:
                yield from _iter_refs(item)
            return
        if isinstance(val.get("literals"), list):
            for item in val["literals"]:
                yield from _iter_refs(item)
            return
        if isinstance(val.get("inlineApplicationFilters"), list):
            for filt in val["inlineApplicationFilters"]:
                for key in ("applications", "categories", "applicationTypes", "tags"):
                    for item in filt.get(key) or []:
                        yield from _iter_refs(item)
            return
        if val.get("name") or val.get("value") or val.get("id"):
            yield val
            return
        for child in val.values():
            yield from _iter_refs(child)
    elif isinstance(val, list):
        for item in val:
            yield from _iter_refs(item)
    else:
        yield val


def _join_field(obj: dict, key: str) -> str:
    parts = [_ref_name(v) for v in _iter_refs(obj.get(key))]
    return ", ".join(p for p in parts if p)


def _nat_iface_label(r: dict, role: str) -> str:
    """Map FMC NAT object refs; handle Interface keyword placeholders."""
    flags = {
        "original_src": "interfaceInOriginalSource",
        "original_dest": "interfaceInOriginalDestination",
        "translated_src": "interfaceInTranslatedSource",
        "translated_dest": "interfaceInTranslatedDestination",
    }
    if flags.get(role) and r.get(flags[role]):
        return "Interface"
    keys = {
        "original_src": "originalSource",
        "original_dest": "originalDestination",
        "translated_src": "translatedSource",
        "translated_dest": "translatedDestination",
        "orig_net": "originalNetwork",
        "trans_net": "translatedNetwork",
    }
    return _join_field(r, keys[role])


def _nat_port_label(r: dict, key: str) -> str:
    val = r.get(key)
    if val is None or val == "" or val == 0:
        return ""
    return str(val)


def _nat_section_label(section: str) -> str:
    return {
        "BEFORE_AUTO": "NAT Rules Before",
        "AUTO": "Auto NAT Rules",
        "AFTER_AUTO": "NAT Rules After",
    }.get(section, section)


def _nat_rules_for_snapshot(pol_rules: dict) -> list[tuple[dict, str]]:
    """Prefer ordered /policy/.../natrules (FMC eval order); fallback to manual+auto."""
    ordered = pol_rules.get("natrules") or []
    if ordered:
        out: list[tuple[dict, str]] = []
        for r in ordered:
            sec = (r.get("metadata") or {}).get("section", "")
            if r.get("type") == "FTDAutoNatRule":
                kind = "autonatrules"
            elif sec in ("BEFORE_AUTO", "AFTER_AUTO"):
                kind = "manualnatrules"
            else:
                kind = "natrules"
            out.append((r, kind))
        return out
    out = []
    for seg in ("manualnatrules", "autonatrules"):
        for r in pol_rules.get(seg) or []:
            out.append((r, seg))
    return out


def flatten_nat_rule(policy_name: str, policy_id: str, r: dict, *, nat_kind: str = "") -> dict:
    meta = r.get("metadata") or {}
    section = str(meta.get("section") or "")
    rule_type = str(r.get("type") or "")
    nat_type = str(r.get("natType") or "")

    src_zones = _join_field(r, "sourceInterface")
    dst_zones = _join_field(r, "destinationInterface")

    orig_src = _nat_iface_label(r, "original_src")
    orig_dst = _nat_iface_label(r, "original_dest")
    trans_src = _nat_iface_label(r, "translated_src")
    trans_dst = _nat_iface_label(r, "translated_dest")
    orig_net = _nat_iface_label(r, "orig_net")
    trans_net = _nat_iface_label(r, "trans_net")

    if rule_type == "FTDAutoNatRule":
        if not orig_src:
            orig_src = orig_net
        if not trans_src:
            trans_src = trans_net

    name = str(r.get("name") or r.get("description") or "").strip()
    idx = meta.get("index")
    if not name and idx is not None:
        name = f"Rule {idx}"
    elif not name and rule_type == "FTDAutoNatRule":
        name = orig_src or trans_src or str(r.get("id", ""))[:8]

    return {
        "policy": policy_name,
        "policy_id": policy_id,
        "name": name,
        "section": section,
        "section_label": _nat_section_label(section),
        "type": nat_type or rule_type,
        "rule_object_type": rule_type,
        "nat_kind": nat_kind or rule_type,
        "enabled": r.get("enabled", ""),
        "source_zones": src_zones,
        "dest_zones": dst_zones,
        "source_networks": orig_src,
        "dest_networks": orig_dst,
        "original_services": _join_field(r, "originalService") or _nat_port_label(r, "originalPort"),
        "translated_services": _join_field(r, "translatedService") or _nat_port_label(r, "translatedPort"),
        "translated_source": trans_src,
        "translated_dest": trans_dst,
        "original_network": orig_net,
        "translated_network": trans_net,
        "dns": r.get("dns", ""),
        "description": r.get("description", ""),
        "id": r.get("id", ""),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class FMCClient:
    """Minimal synchronous read-only FMC REST client."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        domain_uuid: str | None = None,
        verify: bool = True,
        log: Callable[[str], None] | None = None,
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.domain_uuid = domain_uuid
        self.verify = verify
        self.log = log or (lambda _m: None)
        self.session = requests.Session()
        self.session.verify = verify
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.token_expiry: datetime | None = None
        self.server_version: str | None = None
        self.auth_domains: list[dict[str, str]] = []
        self.endpoint_evidence: dict[str, dict] = {}

    @property
    def config_base(self) -> str:
        if not self.domain_uuid:
            raise RuntimeError("domain_uuid not set")
        return f"https://{self.host}/api/fmc_config/v1/domain/{self.domain_uuid}"

    def authenticate(self) -> None:
        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        url = f"https://{self.host}/api/fmc_platform/v1/auth/generatetoken"
        last_err = ""
        resp = None
        for attempt in range(1, AUTH_MAX_RETRIES + 1):
            try:
                resp = self.session.post(
                    url,
                    headers={"Authorization": f"Basic {creds}"},
                    timeout=60,
                    allow_redirects=False,
                )
            except requests.exceptions.RequestException as exc:
                # timeout / connection reset — the sandbox token endpoint does this; keep trying
                last_err = f"network: {exc}"
                if attempt < AUTH_MAX_RETRIES:
                    wait = AUTH_BACKOFF * attempt
                    self.log(
                        f"  Auth attempt {attempt}/{AUTH_MAX_RETRIES} failed "
                        f"({exc.__class__.__name__}) — retry in {wait}s …"
                    )
                    time.sleep(wait)
                    continue
                raise RuntimeError(f"AUTH FAILED after {AUTH_MAX_RETRIES} attempts: {last_err}")
            if resp.status_code in (200, 201, 204):
                break
            last_err = f"{resp.status_code} {resp.text[:400]}"
            # 401/429 on this sandbox are usually transient throttling (verified: succeeds on a later
            # attempt with identical creds); 5xx are server hiccups. Retry all of these.
            transient = resp.status_code in (401, 429) or resp.status_code >= 500
            if transient and attempt < AUTH_MAX_RETRIES:
                wait = AUTH_BACKOFF * attempt
                self.log(
                    f"  Auth {resp.status_code} (often transient on sandbox) — "
                    f"retry in {wait}s ({attempt}/{AUTH_MAX_RETRIES}) …"
                )
                time.sleep(wait)
                continue
            raise RuntimeError(f"AUTH FAILED: {last_err}")
        else:
            raise RuntimeError(f"AUTH FAILED after {AUTH_MAX_RETRIES} attempts: {last_err}")
        self.access_token = resp.headers.get("X-auth-access-token")
        self.refresh_token = resp.headers.get("X-auth-refresh-token")
        if not self.domain_uuid:
            self.domain_uuid = resp.headers.get("DOMAIN_UUID")
        self.auth_domains = _parse_auth_domains_header(resp.headers.get("DOMAINS"))
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_VALIDITY_SEC)
        try:
            vr = self.session.get(
                f"https://{self.host}/api/fmc_platform/v1/info/serverversion",
                headers={"X-auth-access-token": self.access_token},
                timeout=30,
                allow_redirects=False,
            )
            if vr.status_code == 200:
                items = vr.json().get("items", [{}])
                self.server_version = items[0].get("serverVersion") if items else None
        except Exception:
            pass

    def _maybe_refresh(self) -> None:
        if not self.token_expiry:
            return
        if datetime.now(timezone.utc) + timedelta(seconds=TOKEN_REFRESH_BUFFER_SEC) >= self.token_expiry:
            self.log("  Token expiring — refreshing …")
            url = f"https://{self.host}/api/fmc_platform/v1/auth/refreshtoken"
            resp = self.session.post(
                url,
                headers={
                    "X-auth-access-token": self.access_token or "",
                    "X-auth-refresh-token": self.refresh_token or "",
                },
                timeout=60,
                allow_redirects=False,
            )
            if resp.status_code == 204:
                self.access_token = resp.headers.get("X-auth-access-token")
                self.refresh_token = resp.headers.get("X-auth-refresh-token")
                self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_VALIDITY_SEC)
            else:
                self.log("  Refresh failed — re-authenticating …")
                self.authenticate()

    def _headers(self) -> dict[str, str]:
        return {"X-auth-access-token": self.access_token or ""}

    def get_json(self, path: str, *, params: dict | None = None, platform: bool = False) -> dict:
        """GET with retries; path is relative to config_base unless platform=True."""
        if platform:
            url = f"https://{self.host}{path}"
        elif path.startswith("http"):
            url = path
        else:
            url = f"{self.config_base}{path}"
        origin = urlsplit(f"https://{self.host}")
        target = urlsplit(url)
        if (target.scheme != "https" or target.netloc.lower() != origin.netloc.lower()
                or target.username or target.password or target.fragment):
            raise ValueError("FMC GET URL must remain on the configured HTTPS origin")
        self._maybe_refresh()

        last_err: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = self.session.get(url, headers=self._headers(), params=params, timeout=120,
                                        allow_redirects=False)
                if resp.status_code == 401 and attempt == 1:
                    self.authenticate()
                    continue
                if resp.status_code == 429:
                    last_err = RuntimeError("HTTP 429 retries exhausted")
                    time.sleep(RETRY_BACKOFF * attempt)
                    continue
                if resp.status_code >= 300:
                    return {"_error": resp.status_code, "_body": resp.text[:500]}
                if not resp.text:
                    return {}
                return resp.json()
            except Exception as exc:  # noqa: BLE001
                last_err = exc
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BACKOFF * attempt)
        raise RuntimeError(f"GET {path} failed: {last_err}")

    def get_all(self, path: str, *, expanded: bool = True, page_size: int = PAGE_SIZE,
                platform: bool = False) -> list[dict]:
        """Collect bounded pages and retain endpoint-level success/failure evidence.

        A short page is not an end marker: follow a validated next offset or
        continue until the reported total/an explicit empty page proves the end.
        Native items are never annotated with collector metadata.
        """
        if not isinstance(page_size, int) or not 1 <= page_size <= PAGE_SIZE:
            raise ValueError("FMC page size must be between 1 and 1000")
        items: list[dict] = []
        offset = 0
        evidence = {"kind": "list", "status": "error", "items_captured": 0,
                    "reported_total": None, "started_at": _now(), "pages": []}
        self.endpoint_evidence[path] = evidence
        seen_pages: set[str] = set()
        seen_ids: set[tuple[str, str]] = set()
        failure = ""
        for _ in range(MAX_PAGES):
            params: dict[str, Any] = {"limit": page_size, "offset": offset}
            if expanded:
                params["expanded"] = "true"
            page = {"offset": offset, "requested_limit": page_size, "returned_count": 0,
                    "reported_total": None, "status": "error", "requested_at": _now()}
            evidence["pages"].append(page)
            try:
                body = self.get_json(path, params=params, **({"platform": True} if platform else {}))
            except Exception as exc:
                failure = f"Request failed: {type(exc).__name__}"
                page["error"] = failure
                break
            if not isinstance(body, dict) or "_error" in body:
                code = body.get("_error") if isinstance(body, dict) else None
                failure = f"HTTP {code}" if code is not None else "Invalid list response"
                page["error"] = failure
                if code is not None:
                    page["http_status"] = code
                break
            paging = body.get("paging") or {}
            if not isinstance(paging, dict):
                failure = "Invalid paging metadata"
                page["error"] = failure
                break
            try:
                total = _nonnegative_int(paging["count"]) if "count" in paging else None
                returned_offset = _nonnegative_int(paging.get("offset", offset))
                if returned_offset != offset:
                    raise ValueError("Response offset differs from requested offset")
                batch = body.get("items", [] if total == 0 else None)
                if not isinstance(batch, list) or not all(isinstance(row, dict) for row in batch):
                    raise ValueError("List response is missing a native items array")
                page.update({"returned_count": len(batch), "reported_total": total, "status": "success"})
                if "limit" in paging:
                    page["reported_limit"] = _nonnegative_int(paging["limit"])
                known_total = evidence["reported_total"]
                if total is not None and known_total is not None and total != known_total:
                    raise ValueError("Reported total changed during pagination; recapture required")
                if total is not None:
                    evidence["reported_total"] = total
                fingerprint = hashlib.sha256(json.dumps(batch, sort_keys=True, allow_nan=False).encode()).hexdigest()
                keys = [(str(row.get("type", "")).lower(), str(row["id"])) for row in batch if "id" in row]
                if batch and (fingerprint in seen_pages or any(key in seen_ids for key in keys)):
                    raise ValueError("Repeated/overlapping page records; recapture required")
                if len(items) + len(batch) > MAX_ITEMS:
                    raise ValueError("FMC collection item limit exceeded")
                items.extend(batch)
                seen_pages.add(fingerprint)
                seen_ids.update(keys)
                endpoint = f"https://{self.host}{path}" if platform else self.config_base + path
                next_offsets = _next_offsets(endpoint, paging.get("next"))
                next_offset = next_offsets[0] if next_offsets else None
                page["next_offsets"] = next_offsets
                page["next_offset"] = next_offset
                end = offset + len(batch)
                known_total = evidence["reported_total"]
                if known_total is not None and end > known_total:
                    raise ValueError("Captured rows exceed reported total; recapture required")
                if next_offset is not None:
                    if not batch or next_offset != end:
                        raise ValueError("Next page skips/repeats rows or follows an empty page")
                    if known_total is not None and end >= known_total:
                        raise ValueError("Next page conflicts with reported total")
                    offset = next_offset
                elif known_total is not None:
                    if end == known_total:
                        evidence["status"] = "complete"
                        break
                    if not batch:
                        raise ValueError("Empty page before reported total; capture is incomplete")
                    offset = end
                elif not batch or "next" in paging:
                    evidence["status"] = "complete"
                    break
                else:
                    # With no total or explicit end marker, ask for the next
                    # offset even if this server returned fewer rows than asked.
                    offset = end
            except (ValueError, TypeError) as exc:
                failure = str(exc)
                page["error"] = failure
                break
            time.sleep(0.05)
        else:
            failure = "FMC collection page limit exceeded"
        if failure:
            evidence["status"] = "partial" if items else "error"
            evidence["error"] = failure
            self.log(f"    WARN {path}: {failure} ({len(items)} native rows retained)")
        evidence.update({"items_captured": len(items), "finished_at": _now(),
                         "empty": evidence["status"] == "complete" and not items})
        return items

    def capture_record(self, path: str) -> dict:
        evidence = {"kind": "record", "status": "error", "items_captured": 0,
                    "reported_total": None, "started_at": _now(), "pages": []}
        self.endpoint_evidence[path] = evidence
        try:
            body = self.get_json(path, params={"expanded": "true"})
            if not isinstance(body, dict) or "_error" in body or not body.get("id"):
                evidence["error"] = (f"HTTP {body['_error']}" if isinstance(body, dict) and "_error" in body
                                     else "Expanded native record is absent")
                return body if isinstance(body, dict) else {"_error": "invalid_response"}
            evidence.update(status="complete", items_captured=1)
            return body
        except Exception as exc:
            evidence["error"] = f"Request failed: {type(exc).__name__}"
            return {"_error": "request_failed"}
        finally:
            evidence["finished_at"] = _now()

    def list_domains(self) -> list[dict]:
        return self.get_all("/api/fmc_platform/v1/info/domain", expanded=False, platform=True)


# --- flatten helpers for HTML snapshot rows ---------------------------------

def flatten_device(d: dict) -> dict:
    return {
        "name": d.get("name", ""),
        "hostname": d.get("hostName", ""),
        "model": d.get("model", d.get("modelNumber", "")),
        "sw_version": d.get("sw_version", ""),
        "health": d.get("healthStatus", ""),
        "health_msg": (d.get("healthMessage") or "")[:120],
        "deployment": d.get("deploymentStatus", ""),
        "performance": d.get("performanceTier", ""),
        "id": d.get("id", ""),
    }


def flatten_host(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "value": o.get("value", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_network(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "value": o.get("value", ""),
        "type": o.get("type", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_network_group(o: dict) -> dict:
    objs = o.get("objects") or []
    lits = o.get("literals") or []
    members = len(objs) + len(lits)
    return {
        "name": o.get("name", ""),
        "members": members,
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_port(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "protocol": o.get("protocol", ""),
        "port": o.get("port", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_zone(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "interface_mode": o.get("interfaceMode", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_access_rule(policy_name: str, policy_id: str, r: dict) -> dict:
    meta = r.get("metadata") or {}
    return {
        "policy": policy_name,
        "policy_id": policy_id,
        "name": r.get("name", ""),
        "section": meta.get("section", ""),
        "rule_index": meta.get("ruleIndex", ""),
        "action": r.get("action", ""),
        "enabled": r.get("enabled", ""),
        "source_zones": _join_field(r, "sourceZones"),
        "dest_zones": _join_field(r, "destinationZones"),
        "source_networks": _join_field(r, "sourceNetworks"),
        "dest_networks": _join_field(r, "destinationNetworks"),
        "source_ports": _join_field(r, "sourcePorts"),
        "services": _join_field(r, "destinationPorts"),
        "applications": _join_field(r, "applications"),
        "urls": _join_field(r, "urls"),
        "url_categories": _join_field(r, "urlCategories"),
        "vlan_tags": _join_field(r, "vlanTags"),
        "ips_policy": _join_field(r, "ipsPolicy"),
        "file_policy": _join_field(r, "filePolicy"),
        "prefilter_policy": _join_field(r, "prefilterPolicy"),
        "id": r.get("id", ""),
    }


def _safe_json_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def flatten_prefilter_rule(policy_name: str, policy_id: str, r: dict) -> dict:
    meta = r.get("metadata") or {}
    idx = meta.get("ruleIndex")
    name = str(r.get("name") or "").strip()
    if not name and idx is not None:
        name = f"Rule {idx}"
    return {
        "policy": policy_name,
        "policy_id": policy_id,
        "name": name,
        "rule_index": idx if idx is not None else "",
        "action": r.get("action", ""),
        "rule_type": r.get("ruleType", r.get("type", "")),
        "enabled": r.get("enabled", ""),
        "bidirectional": r.get("bidirectional", ""),
        "source_zones": _join_field(r, "sourceInterfaces") or _join_field(r, "sourceZones"),
        "dest_zones": _join_field(r, "destinationInterfaces") or _join_field(r, "destinationZones"),
        "source_networks": _join_field(r, "sourceNetworks"),
        "dest_networks": _join_field(r, "destinationNetworks"),
        "source_ports": _join_field(r, "sourcePorts"),
        "dest_ports": _join_field(r, "destinationPorts"),
        "vlan_tags": _join_field(r, "vlanTags"),
        "id": r.get("id", ""),
    }


def flatten_dns_rule(policy_name: str, policy_id: str, r: dict) -> dict:
    meta = r.get("metadata") or {}
    idx = meta.get("ruleIndex")
    name = str(r.get("name") or "").strip()
    if not name and idx is not None:
        name = f"Rule {idx}"
    dns_match = _join_field(r, "dnsObjects") or _join_field(r, "dnsServers")
    return {
        "policy": policy_name,
        "policy_id": policy_id,
        "name": name,
        "rule_index": idx if idx is not None else "",
        "action": r.get("action", ""),
        "enabled": r.get("enabled", ""),
        "source_zones": _join_field(r, "sourceZones"),
        "source_networks": _join_field(r, "sourceNetworks"),
        "dns_objects": dns_match,
        "url_categories": _join_field(r, "urlCategories"),
        "sinkhole": r.get("sinkhole", ""),
        "logging": r.get("logging", r.get("logEnabled", "")),
        "id": r.get("id", ""),
    }


def flatten_application(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "type": o.get("type", o.get("applicationType", "")),
        "risk": o.get("risk", ""),
        "productivity": o.get("productivity", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_generic_object(o: dict) -> dict:
    return {
        "name": o.get("name", ""),
        "type": o.get("type", ""),
        "description": (o.get("description") or "")[:120],
        "id": o.get("id", ""),
    }


def flatten_device_group(d: dict) -> dict:
    return {
        "name": d.get("name", ""),
        "description": (d.get("description") or "")[:120],
        "type": d.get("type", ""),
        "id": d.get("id", ""),
    }


def flatten_policy(p: dict) -> dict:
    return {
        "name": p.get("name", ""),
        "description": (p.get("description") or "")[:120],
        "default_action": p.get("defaultAction", {}).get("action", "")
        if isinstance(p.get("defaultAction"), dict)
        else "",
        "id": p.get("id", ""),
    }


FLATTEN_OBJECT: dict[str, Callable[[dict], dict]] = {
    "hosts": flatten_host,
    "networks": flatten_network,
    "ranges": flatten_network,
    "network_groups": flatten_network_group,
    "protocol_ports": flatten_port,
    "port_groups": flatten_network_group,
    "security_zones": flatten_zone,
    "applications": flatten_application,
    "fqdns": flatten_generic_object,
    "urls": flatten_generic_object,
}


def safe_slug(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (name or "device").strip())
    return slug.strip("_")[:80] or "device"


def domain_slug(name: str, uuid: str = "") -> str:
    base = safe_slug(name or uuid or "domain")
    if not base or base == "device":
        return f"domain_{uuid[:8]}" if uuid else "domain"
    return base


def _parse_auth_domains_header(raw: str | None) -> list[dict[str, str]]:
    """Parse DOMAINS header from generatetoken (JSON array of UUIDs or objects)."""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, str):
        return [{"uuid": data, "name": "", "type": ""}]
    if not isinstance(data, list):
        return []
    out: list[dict[str, str]] = []
    for item in data:
        if isinstance(item, str):
            out.append({"uuid": item, "name": "", "type": ""})
        elif isinstance(item, dict):
            out.append(
                {
                    "name": str(item.get("name") or ""),
                    "uuid": str(item.get("uuid") or item.get("id") or ""),
                    "type": str(item.get("type") or ""),
                }
            )
    return out


def resolve_collect_domains(
    client: FMCClient,
    *,
    domain_uuid: str | None,
    all_domains: bool,
    log: Callable[[str], None],
) -> list[dict[str, str]]:
    """Resolve which FMC domains to collect (single or all authorized)."""
    api_domains = client.list_domains()
    by_uuid: dict[str, dict[str, str]] = {}
    for d in api_domains:
        uid = str(d.get("uuid") or d.get("id") or "")
        if not uid:
            continue
        by_uuid[uid] = {
            "name": str(d.get("name") or ""),
            "uuid": uid,
            "type": str(d.get("type") or ""),
        }
    for d in client.auth_domains:
        uid = d.get("uuid", "")
        if not uid:
            continue
        if uid not in by_uuid:
            by_uuid[uid] = dict(d)
        elif d.get("name") and not by_uuid[uid].get("name"):
            by_uuid[uid]["name"] = d["name"]

    domains = list(by_uuid.values())

    if not all_domains:
        uid = domain_uuid or client.domain_uuid or ""
        match = next((d for d in domains if d["uuid"] == uid), None)
        if match:
            return _assign_domain_slugs([match])
        if uid:
            return _assign_domain_slugs([{"name": "", "uuid": uid, "type": ""}])
        if domains:
            return _assign_domain_slugs([domains[0]])
        return _assign_domain_slugs([{"name": "", "uuid": client.domain_uuid or "", "type": ""}])

    if not domains:
        log("  --all-domains: API returned no domains — collecting token domain only")
        domains = [{"name": "", "uuid": client.domain_uuid or "", "type": ""}]

    if domain_uuid:
        domains = [d for d in domains if d["uuid"] == domain_uuid] or [
            {"name": "", "uuid": domain_uuid, "type": ""}
        ]

    return _assign_domain_slugs(domains)


def _assign_domain_slugs(domains: list[dict[str, str]]) -> list[dict[str, str]]:
    used: set[str] = set()
    out: list[dict[str, str]] = []
    for d in domains:
        row = dict(d)
        slug = domain_slug(row.get("name", ""), row.get("uuid", ""))
        base = slug
        n = 2
        while slug in used:
            slug = f"{base}_{n}"
            n += 1
        used.add(slug)
        row["slug"] = slug
        out.append(row)
    return out


MERGE_SNAP_LIST_KEYS = (
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


def aggregate_domain_snapshots(domain_snaps: list[dict[str, Any]]) -> dict[str, Any]:
    """Build root index snapshot from per-domain collects."""
    if not domain_snaps:
        return {}
    first = domain_snaps[0]
    agg: dict[str, Any] = {
        "host": first.get("host"),
        "server_version": first.get("server_version"),
        "collected_at": first.get("collected_at"),
        "all_domains": len(domain_snaps) > 1,
        "domain_collects": [],
        "domains": [],
        "counts": {},
        "errors": [],
    }
    seen_domain_uuids: set[str] = set()
    for ds in domain_snaps:
        slug = ds.get("domain_slug") or domain_slug(ds.get("domain_name", ""), ds.get("domain_uuid", ""))
        agg["domain_collects"].append(
            {
                "name": ds.get("domain_name") or slug,
                "uuid": ds.get("domain_uuid", ""),
                "slug": slug,
                "path": f"domains/{slug}",
                "counts": ds.get("counts") or {},
            }
        )
        for d in ds.get("domains") or []:
            uid = d.get("uuid") if isinstance(d, dict) else ""
            if uid and uid not in seen_domain_uuids:
                seen_domain_uuids.add(uid)
                agg["domains"].append(d)
        for key in MERGE_SNAP_LIST_KEYS:
            agg.setdefault(key, []).extend(ds.get(key) or [])
        for k, v in (ds.get("counts") or {}).items():
            agg["counts"][k] = agg["counts"].get(k, 0) + int(v or 0)
        agg["errors"].extend(ds.get("errors") or [])
    return agg


def _iface_ipv4(iface: dict) -> tuple[str, str]:
    """Return (address/prefix display, cidr-ish network) from FMC interface object."""
    ipv4 = iface.get("ipv4") or {}
    static = ipv4.get("static") if isinstance(ipv4, dict) else None
    if isinstance(static, dict):
        addr = static.get("address") or static.get("ipAddress") or ""
        mask = static.get("netmask") or static.get("prefix") or ""
        if addr and mask:
            if str(mask).isdigit():
                return f"{addr}/{mask}", f"{addr}/{mask}"
            return f"{addr} {mask}", f"{addr}"
        if addr:
            return str(addr), str(addr)
    addr = iface.get("ipv4Address") or iface.get("address") or ""
    return (str(addr), str(addr)) if addr else ("", "")


def flatten_interface(device_name: str, device_id: str, iface: dict) -> dict:
    ip, net = _iface_ipv4(iface)
    zone = iface.get("securityZone") or iface.get("zone") or {}
    zone_name = zone.get("name", "") if isinstance(zone, dict) else str(zone or "")
    mode = iface.get("mode") or iface.get("interfaceMode") or ""
    enabled = iface.get("enabled", iface.get("ifState", ""))
    status = "up" if str(enabled).lower() in ("true", "up", "enabled", "active") else (
        "down" if str(enabled).lower() in ("false", "down", "disabled") else str(enabled)
    )
    return {
        "device": device_name,
        "device_id": device_id,
        "name": iface.get("ifname") or iface.get("name") or iface.get("hardwareName", ""),
        "ip": ip,
        "network": net,
        "zone": zone_name,
        "mode": mode,
        "status": status,
        "mtu": iface.get("MTU") or iface.get("mtu") or "",
        "type": iface.get("type", ""),
        "id": iface.get("id", ""),
    }


def flatten_route(device_name: str, device_id: str, route: dict) -> dict:
    gw = route.get("gateway") or {}
    if isinstance(gw, dict):
        gateway = gw.get("address") or gw.get("objectId") or gw.get("name") or ""
    else:
        gateway = str(gw or "")
    nets = route.get("selectedNetworks") or route.get("networks") or []
    dest = ""
    if isinstance(nets, list) and nets:
        n0 = nets[0] if isinstance(nets[0], dict) else {}
        addr = n0.get("address") or n0.get("value") or ""
        mask = n0.get("netmask") or n0.get("prefix") or ""
        dest = f"{addr}/{mask}" if addr and mask else str(addr or n0.get("name", ""))
    elif isinstance(nets, dict):
        dest = nets.get("address") or nets.get("value") or ""
    return {
        "device": device_name,
        "device_id": device_id,
        "interface": route.get("interfaceName") or route.get("interface", {}).get("name", "")
        if isinstance(route.get("interface"), dict)
        else route.get("interfaceName", ""),
        "destination": dest or route.get("destination", ""),
        "gateway": gateway,
        "metric": route.get("metricValue") or route.get("metric") or "",
        "type": route.get("type", ""),
        "id": route.get("id", ""),
    }


def _policy_name(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("name") or "")
    return ""


def collect_device_details(
    client: FMCClient,
    run: Path,
    devices_raw: list[dict],
    snap: dict[str, Any],
    log: Callable[[str], None],
) -> None:
    """Per-FTD interfaces, static routes, and expanded device record."""
    details_dir = run / "device-details"
    details_dir.mkdir(parents=True, exist_ok=True)
    all_ifaces: list[dict] = []
    all_routes: list[dict] = []
    enriched_devices: list[dict] = []

    for dev in devices_raw:
        did = dev.get("id")
        dname = dev.get("name") or did or "device"
        if not did:
            continue
        log(f"  Device detail: {dname} …")
        device_path = f"/devices/devicerecords/{did}"
        detail = client.capture_record(device_path)
        if "_error" not in detail and detail.get("id"):
            dev_full = detail
        else:
            dev_full = dev

        iface_paths = (
            f"/devices/devicerecords/{did}/physicalinterfaces",
            f"/devices/devicerecords/{did}/fpphysicalinterfaces",
        )
        ipv4_route_paths = (
            f"/devices/devicerecords/{did}/routing/ipv4staticroutes",
            f"/devices/devicerecords/{did}/routing/staticroutes",
        )
        extra_iface_paths = (
            f"/devices/devicerecords/{did}/logicalinterfaces",
            f"/devices/devicerecords/{did}/bridgegroupinterfaces",
        )
        ifaces: list[dict] = []
        routes: list[dict] = []
        errors: list[str] = []

        for path in iface_paths:
            batch = client.get_all(path, expanded=True)
            if batch:
                ifaces = batch
                break
        for path in ipv4_route_paths:
            batch = client.get_all(path, expanded=True)
            if batch:
                routes = batch
                break
        # IPv6 is an independent address family, never an IPv4 fallback.
        routes.extend(client.get_all(
            f"/devices/devicerecords/{did}/routing/ipv6staticroutes", expanded=True))

        for path in extra_iface_paths:
            batch = client.get_all(path, expanded=True)
            if batch:
                ifaces.extend(batch)

        attempted = (device_path, *iface_paths, *ipv4_route_paths,
                     f"/devices/devicerecords/{did}/routing/ipv6staticroutes", *extra_iface_paths)
        device_evidence = {path: copy.deepcopy(_endpoint_evidence(client, path))
                           for path in attempted if _endpoint_evidence(client, path)}
        errors.extend(f"{path}: {entry.get('error', entry['status'])}"
                      for path, entry in device_evidence.items() if entry.get("status") != "complete")

        flat_ifaces = [flatten_interface(dname, did, i) for i in ifaces]
        flat_routes = [flatten_route(dname, did, r) for r in routes]
        all_ifaces.extend(flat_ifaces)
        all_routes.extend(flat_routes)

        row = flatten_device(dev_full)
        row.update(
            {
                "slug": safe_slug(dname),
                "serial": (dev_full.get("metadata") or {}).get("deviceSerialNumber", ""),
                "device_group": _policy_name(dev_full.get("deviceGroup")),
                "access_policy": _policy_name(dev_full.get("accessPolicy")),
                "nat_policy": _policy_name(dev_full.get("natPolicy")),
                "intrusion_policy": _policy_name(dev_full.get("intrusionPolicy")),
                "ftd_mode": dev_full.get("ftdMode", ""),
                "connected": dev_full.get("isConnected", ""),
                "iface_count": len(flat_ifaces),
                "route_count": len(flat_routes),
                "snort": (dev_full.get("metadata") or {}).get("snortVersion", ""),
                "vdb": (dev_full.get("metadata") or {}).get("vdbVersion", ""),
            }
        )
        enriched_devices.append(row)

        bundle = {
            "device": dev_full,
            "interfaces": ifaces,
            "routes": routes,
            "interfaces_flat": flat_ifaces,
            "routes_flat": flat_routes,
            "errors": errors,
            "collection_evidence": device_evidence,
        }
        _safe_json_write(details_dir / f"{safe_slug(dname)}__{did}.json", bundle)
        time.sleep(0.05)

    snap["devices"] = enriched_devices
    snap["interfaces"] = all_ifaces
    snap["routes"] = all_routes
    snap["counts"]["interfaces"] = len(all_ifaces)
    snap["counts"]["routes"] = len(all_routes)
    _safe_json_write(run / "interfaces.json", all_ifaces)
    _safe_json_write(run / "routes.json", all_routes)
    log(f"  Interfaces: {len(all_ifaces)} · Routes: {len(all_routes)}")


def _collect_object_list(
    client: FMCClient,
    run: Path,
    snap: dict[str, Any],
    api_seg: str,
    filename: str,
    snap_key: str,
    log: Callable[[str], None],
    *,
    path_prefix: str = "/object",
) -> None:
    log(f"{'Objects' if path_prefix == '/object' else 'Inventory'} /{api_seg} …")
    raw = client.get_all(
        f"{path_prefix}/{api_seg}" if path_prefix else f"/{api_seg}",
        expanded=True,
    )
    _safe_json_write(run / filename, raw)
    flattener = FLATTEN_OBJECT.get(snap_key)
    if flattener:
        snap[snap_key] = [flattener(o) for o in raw]
    elif snap_key == "device_groups":
        snap[snap_key] = [flatten_device_group(o) for o in raw]
    else:
        snap[snap_key] = [flatten_generic_object(o) for o in raw]
    snap["counts"][snap_key] = len(raw)
    log(f"  {len(raw)}")


def _rule_flatteners(rules_seg: str):
    if rules_seg == "accessrules":
        return flatten_access_rule, "access_rules"
    if rules_seg in ("autonatrules", "manualnatrules", "natrules"):
        return lambda pn, pid, r: flatten_nat_rule(pn, pid, r, nat_kind=rules_seg), "nat_rules"
    if rules_seg == "prefilterrules":
        return flatten_prefilter_rule, "prefilter_rules"
    if rules_seg == "dnsrules":
        return flatten_dns_rule, "dns_rules"
    return None, None


def collect(
    client: FMCClient,
    run: Path,
    *,
    quick: bool = False,
    log: Callable[[str], None],
    domain_meta: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run full collection; return consolidated snapshot dict."""
    client.endpoint_evidence = {}
    snap: dict[str, Any] = {
        "host": client.host,
        "server_version": client.server_version,
        "domain_uuid": client.domain_uuid,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "domains": [],
        "devices": [],
        "access_policies": [],
        "access_rules": [],
        "nat_policies": [],
        "nat_rules": [],
        "prefilter_policies": [],
        "prefilter_rules": [],
        "dns_policies": [],
        "dns_rules": [],
        "device_groups": [],
        "applications": [],
        "counts": {},
        "errors": [],
    }
    if domain_meta:
        snap["domain_name"] = domain_meta.get("name") or domain_meta.get("slug", "")
        snap["domain_slug"] = domain_meta.get("slug", "")
        snap["domain_uuid"] = domain_meta.get("uuid") or client.domain_uuid

    domains = client.list_domains()
    snap["domains"] = [
        {"name": d.get("name", ""), "uuid": d.get("uuid", d.get("id", "")), "type": d.get("type", "")}
        for d in domains
    ]
    _safe_json_write(run / "domains.json", domains)
    log(f"Domains: {len(domains)}")

    # Devices
    log("Devices …")
    devices_raw = client.get_all("/devices/devicerecords", expanded=True)
    _safe_json_write(run / "devices.json", devices_raw)
    snap["devices"] = [flatten_device(d) for d in devices_raw]
    snap["counts"]["devices"] = len(devices_raw)
    log(f"  {len(devices_raw)} device(s)")
    collect_device_details(client, run, devices_raw, snap, log)

    # Assignments are authoritative even when expanded device records omit ACP
    # and NAT references. Keep the API array separate; never inject assignments
    # into native device JSON or bind policy by display name.
    assignments = client.get_all("/assignment/policyassignments", expanded=True)
    _safe_json_write(run / "policy-assignments.json", assignments)
    snap["policy_assignments"] = assignments
    snap["counts"]["policy_assignments"] = len(assignments)

    snap.setdefault("interfaces", [])
    snap.setdefault("routes", [])

    object_exports = OBJECT_EXPORTS
    if quick:
        object_exports = [t for t in OBJECT_EXPORTS if t[0] in QUICK_OBJECT_EXPORTS]

    for api_seg, filename, snap_key in object_exports:
        _collect_object_list(client, run, snap, api_seg, filename, snap_key, log)

    if not quick:
        for api_seg, filename, snap_key in INVENTORY_EXPORTS:
            _collect_object_list(
                client, run, snap, api_seg, filename, snap_key, log, path_prefix=""
            )

    policy_exports = POLICY_EXPORTS if not quick else POLICY_EXPORTS[:QUICK_POLICY_EXPORTS]

    for api_seg, filename, snap_key, rule_segs in policy_exports:
        log(f"Policies /{api_seg} …")
        raw = client.get_all(f"/policy/{api_seg}", expanded=True)
        _safe_json_write(run / filename, raw)
        snap[snap_key] = [flatten_policy(p) for p in raw]
        snap["counts"][snap_key] = len(raw)
        log(f"  {len(raw)} policy container(s)")

        if not rule_segs:
            continue

        rules_dir = run / "policy-rules" / api_seg
        rules_dir.mkdir(parents=True, exist_ok=True)

        for pol in raw:
            pid = pol.get("id")
            pname = pol.get("name", pid)
            if not pid:
                continue
            safe_pol = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(pname))[:80]
            pol_rules: dict[str, list] = {}

            for rules_seg in rule_segs:
                log(f"  Rules ({rules_seg}): {pname} …")
                rules = client.get_all(f"/policy/{api_seg}/{pid}/{rules_seg}", expanded=True)
                if rules or _endpoint_evidence(client, f"/policy/{api_seg}/{pid}/{rules_seg}").get("status") == "complete":
                    pol_rules[rules_seg] = rules
                time.sleep(0.05)

            if api_seg == "ftdnatpolicies":
                snap.setdefault("nat_rules", [])
                for r, kind in _nat_rules_for_snapshot(pol_rules):
                    snap["nat_rules"].append(flatten_nat_rule(pname, pid, r, nat_kind=kind))
            else:
                for rules_seg in rule_segs:
                    rules = pol_rules.get(rules_seg) or []
                    if not rules:
                        continue
                    flattener, snap_rules_key = _rule_flatteners(rules_seg)
                    if not flattener:
                        continue
                    snap.setdefault(snap_rules_key, [])
                    for r in rules:
                        snap[snap_rules_key].append(flattener(pname, pid, r))

            if pol_rules:
                _safe_json_write(rules_dir / f"{safe_pol}__{pid}.json", pol_rules)

        for rules_seg in rule_segs or []:
            _, snap_rules_key = _rule_flatteners(rules_seg)
            if snap_rules_key:
                snap["counts"][snap_rules_key] = len(snap.get(snap_rules_key) or [])
                log(f"  Total {rules_seg}: {snap['counts'].get(snap_rules_key, 0)}")

    _save_evidence(client, run, snap)
    return snap


# --- Completeness self-audit -------------------------------------------------
def audit_completeness(client, snap: dict, log: Callable[[str], None], domain_label: str = "") -> list[dict]:
    """Report recorded endpoint evidence, including each policy's actual totals.

    No second request can overwrite a failed pull with a later successful probe.
    A total is published only when FMC returned it, never derived from rows kept.
    NAT family endpoints are separate observations, not additive unique-rule counts.
    """
    evidence = (snap.get("collection_evidence") or {}).get("endpoints") or {}
    labels = {f"/object/{segment}": key for segment, _filename, key in OBJECT_EXPORTS}
    labels.update({f"/{segment}": key for segment, _filename, key in INVENTORY_EXPORTS})
    labels.update({f"/policy/{segment}": key for segment, _filename, key, _rules in POLICY_EXPORTS})
    labels.update({"/devices/devicerecords": "devices", "/assignment/policyassignments": "policy_assignments"})
    rows = []
    for path in sorted(set(labels) | set(evidence)):
        entry = evidence.get(path)
        if not entry:
            rows.append({"object_type": labels[path], "endpoint": path, "live_total": "",
                         "captured": 0, "status": "not_collected", "note": "Endpoint not attempted in this capture"})
            continue
        total = entry.get("reported_total")
        captured = entry.get("items_captured", 0)
        state = entry.get("status")
        if state == "complete":
            status = "complete" if total is not None else "captured"
            note = ("Successful empty endpoint" if entry.get("empty") else "All returned pages retained")
            if total is None:
                note += "; FMC did not report an independent total"
        elif state == "partial":
            status, note = "PARTIAL", entry.get("error", "Pagination incomplete")
        else:
            status, note = "api_error", entry.get("error", "Endpoint success unverified")
        rows.append({"object_type": labels.get(path, path.rsplit("/", 1)[-1]), "endpoint": path,
                     "live_total": total if total is not None else "", "captured": captured,
                     "status": status, "note": f"{path}: {note}"})
    if domain_label:
        for row in rows:
            row["domain"] = domain_label
    log(f"  audit: {len(rows)} endpoint areas · "
        f"{sum(r['status'] == 'PARTIAL' for r in rows)} partial · "
        f"{sum(r['status'] == 'api_error' for r in rows)} API errors")
    return rows


def write_completeness_csv(out_dir: Path, rows: list[dict]) -> Path:
    import csv as _csv
    cols = ["object_type", "endpoint", "live_total", "captured", "status", "note"]
    if rows and "domain" in rows[0]:
        cols = ["domain"] + cols
    path = Path(out_dir) / "completeness.csv"
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, "") for c in cols])
    return path


def main() -> int:
    p = argparse.ArgumentParser(description=f"{BANNER} — read-only FMC export")
    p.add_argument("--host", required=True, help="FMC IP address or hostname (no https://)")
    p.add_argument("--user", required=True, help="API username (read-only recommended)")
    p.add_argument("--password", help="Password (or FMC_PASSWORD env, else prompted)")
    p.add_argument("--domain-uuid", help="FMC domain UUID (default: token domain)")
    p.add_argument(
        "--all-domains",
        action="store_true",
        help="Collect every authorized FMC domain into domains/<slug>/ subfolders",
    )
    p.add_argument("--output", default=".", help="Output parent directory")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (lab only)")
    p.add_argument(
        "--quick",
        action="store_true",
        help="Smoke test: subset of objects + access/NAT policies only",
    )
    args = p.parse_args()
    host = normalize_host(args.host)
    password = args.password or os.environ.get("FMC_PASSWORD") or getpass("FMC password: ")
    verify = not args.insecure

    run = make_run_dir(args.output)
    log_path = run / "collection.log"
    log_lines: list[str] = []

    def log(msg: str) -> None:
        line = f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}"
        log_lines.append(line)
        safe_print(line)

    log(BANNER)
    log(f"Host: {host}")
    t0 = time.time()

    client = FMCClient(
        host,
        args.user,
        password,
        domain_uuid=args.domain_uuid,
        verify=verify,
        log=log,
    )
    client.authenticate()
    log(f"Authenticated — FMC {client.server_version or '?'} domain {client.domain_uuid}")
    if client.auth_domains:
        log(f"  Auth header lists {len(client.auth_domains)} domain(s)")

    domains_to_collect = resolve_collect_domains(
        client,
        domain_uuid=args.domain_uuid,
        all_domains=args.all_domains,
        log=log,
    )

    if args.all_domains:
        log(f"Multi-domain mode — {len(domains_to_collect)} domain(s) to collect")
        domain_snaps: list[dict[str, Any]] = []
        all_domains_raw: list[dict] = []

        for i, dom in enumerate(domains_to_collect, 1):
            dname = dom.get("name") or dom.get("slug") or dom.get("uuid", "")[:8]
            log(f"=== [{i}/{len(domains_to_collect)}] Domain: {dname} ({dom['uuid']}) ===")
            client.domain_uuid = dom["uuid"]
            domain_dir = run / "domains" / dom["slug"]
            domain_dir.mkdir(parents=True, exist_ok=True)

            snap = collect(
                client,
                domain_dir,
                quick=args.quick,
                log=log,
                domain_meta=dom,
            )
            snap["host"] = host

            if len(domains_to_collect) > 1:
                for dev in snap.get("devices") or []:
                    if isinstance(dev, dict):
                        base = dev.get("slug") or safe_slug(dev.get("name", ""))
                        dev["slug"] = f"{dom['slug']}__{base}"

            snap["completeness"] = audit_completeness(client, snap, log, domain_label=dname)
            write_completeness_csv(domain_dir, snap["completeness"])
            _safe_json_write(domain_dir / "fmc_snapshot.json", snap)
            domain_snaps.append(snap)
            if isinstance(snap.get("domains"), list):
                all_domains_raw.extend(snap["domains"])

        _safe_json_write(run / "domains.json", all_domains_raw or client.list_domains())
        snap = aggregate_domain_snapshots(domain_snaps)
        snap["host"] = host
        snap["all_domains"] = len(domains_to_collect) > 1
        snap["completeness"] = [r for d in domain_snaps for r in (d.get("completeness") or [])]
        write_completeness_csv(run, snap["completeness"])
        _safe_json_write(run / "fmc_snapshot.json", snap)
    else:
        dom = domains_to_collect[0]
        client.domain_uuid = dom["uuid"]
        snap = collect(
            client,
            run,
            quick=args.quick,
            log=log,
            domain_meta=dom if dom.get("name") else None,
        )
        snap["host"] = host
        snap["completeness"] = audit_completeness(client, snap, log)
        write_completeness_csv(run, snap["completeness"])
        _safe_json_write(run / "fmc_snapshot.json", snap)

    duration = round(time.time() - t0, 1)
    try:
        log(f"Done in {duration}s → {run}")
    except UnicodeEncodeError:
        pass
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    write_manifest(
        run,
        vendor="cisco_fmc",
        collector="fmc_collect_data.py",
        collector_version=__version__,
        host=host,
        extra={
            "server_version": client.server_version,
            "collector_sha256": COLLECTOR_SHA256,
            "domain_uuid": client.domain_uuid,
            "duration_sec": duration,
            "counts": snap.get("counts", {}),
            "quick_mode": args.quick,
            "all_domains": args.all_domains,
            "domains_collected": len(domains_to_collect) if args.all_domains else 1,
            "completeness": {
                "types_audited": len(snap.get("completeness", [])),
                "partial": sum(1 for r in snap.get("completeness", []) if r.get("status") == "PARTIAL"),
                "api_errors": sum(1 for r in snap.get("completeness", []) if r.get("status") == "api_error"),
                "not_collected": sum(1 for r in snap.get("completeness", []) if r.get("status") == "not_collected"),
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
