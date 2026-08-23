#!/usr/bin/env python3
"""
ValeronLabs / NetConverter — Check Point Management API Collector  (Revision 2)
===========================================================================

Read-only, single-file collector that extracts the COMPLETE configuration from a
Check Point Management Server (R80.x / R81.x) via the Web Management API, for
audit, optimization and migration (NetConverter).

Why Revision 2 (vs. the original collectors):
  * FIX: the original simple collector pulled object lists with {'limit': 500}
    and NO offset loop -> on a site with >500 objects of a type it silently
    captured only the first 500. Rev 2 paginates EVERYTHING to completion.
  * SAFE: logs in read-only by default (no DB lock, zero write risk on prod).
  * COMPLETE: pulls the full object surface (services other/sctp/dce-rpc/...,
    application-sites, security-zones, wildcards, multicast, groups-with-
    exclusion, updatable objects, time-groups, data-types, tags, users),
    groups + service-groups + access-roles at details-level 'full' so members
    are captured, plus global-properties (implied-rule context).
  * RESILIENT: per-call retry with backoff and automatic re-login if the
    management session expires during a long collection.
  * COMPATIBLE: output filenames match the existing analyzer / HTML report so
    this drops straight into the audit + viewer pipeline.
  * OPTIONAL: --where-used runs Check Point's native where-used reverse-reference
    command per object (ground-truth cross-references for the relationship view).
  * RESOLVE: after policy export, show-object is called for every UID referenced
    in group membership or rulebases that is not already in the export bundle,
    writing objects-referenced.json so HTML reports resolve all names.

Usage:
    python checkpoint_collect_data.py --mgmt-ip <IP> --username <USER> \
        --password <PASS> [--port 443] [--output .] [--domain DOMAIN] \
        [--where-used] [--read-write]

Output:
    run-YYYYMMDD-HHMMSS/   (JSON exports, manifests, progress log)
    checkpoint_audit_<timestamp>.zip   (bundle to send to ValeronLabs)
"""
from __future__ import print_function

__version__ = "1.5.6"

import argparse
import csv
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

# --- dependency bootstrap -------------------------------------------------
# This tool needs the 'requests' library. If it is not installed, try to
# install it automatically so the customer only ever runs ONE command.
try:
    import requests
except ImportError:
    import subprocess
    print("First run: installing required Python package 'requests' ...")
    _ok = False
    for _extra in ([], ["--user"]):
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "requests"] + _extra,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            import requests
            _ok = True
            break
        except Exception:
            continue
    if not _ok:
        print("\nThis tool needs the Python 'requests' library. Please run this once,")
        print("then run the collection command again:")
        print("    {} -m pip install requests".format(sys.executable))
        sys.exit(1)
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from collect_helpers import (
    VPN_SHOW_BY_FILE,
    exception_layer_uid,
    https_layer_refs,
    merge_vpn_detail,
    threat_exception_payload,
    unwrap_vpn_show,
    vpn_membership_empty,
)

DEFAULT_PORT = 4434       # this customer's mgmt API port (override with --port)
PAGE_LIMIT = 500          # max objects per management-API page
RULEBASE_LIMIT = 500      # max rules per rulebase page
MAX_RETRIES = 3           # per-call retry attempts on transient failure
RETRY_BACKOFF = 4         # seconds, multiplied by attempt number

# Check Point ships its Application Control / URL Filtering database under these
# domains. An application-site in ANY other domain (e.g. "SMC User", or a CMA
# name on MDS) was created by the customer. Custom apps must be re-fetched at
# "full" detail because "standard" omits their definition (url-list / primary-
# category / risk) — i.e. *what each custom app actually matches*.
BUILTIN_APP_DOMAINS = {"APPI Data", "Check Point Data"}

BANNER = "Netconverter-Checkpoint Collection"

UID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

# Object lists whose members may reference UIDs not present in any other export
# (deleted VS gateways still in a group, DNS domains, users, etc.).
MEMBER_OBJECT_FILES = (
    "objects-groups.json",
    "objects-groups-with-exclusion.json",
    "objects-service-groups.json",
    "objects-user-groups.json",
    "objects-application-site-groups.json",
)

ACCESS_ROLE_MEMBER_FIELDS = ("users", "user-groups", "networks", "machines")

RULE_REF_FIELDS = (
    "source", "destination", "service", "action", "vpn", "content",
    "time", "install-on", "inline-layer",
    "original-source", "original-destination", "original-service",
    "translated-source", "translated-destination", "translated-service",
)


def uid_from_ref(val):
    if isinstance(val, str) and UID_RE.match(val):
        return val
    if isinstance(val, dict):
        u = val.get("uid")
        if isinstance(u, str) and UID_RE.match(u):
            return u
    return None


def iter_embedded_uids(value):
    """Yield UUID strings anywhere in a JSON-like structure."""
    if isinstance(value, str):
        if UID_RE.match(value):
            yield value
    elif isinstance(value, dict):
        u = value.get("uid")
        if isinstance(u, str) and UID_RE.match(u):
            yield u
        for v in value.values():
            yield from iter_embedded_uids(v)
    elif isinstance(value, list):
        for item in value:
            yield from iter_embedded_uids(item)


# ---------------------------------------------------------------------------
# Declarative export map.  (endpoint, output_filename, details_level)
# details_level 'full' is used ONLY where extra fields are required, because
# 'full' on large lists is slow (see Check Point sk181397).  Members of groups,
# service-groups and access-roles, and icmp-type/code, only appear at 'full'.
# Endpoints unsupported on a given version are skipped gracefully, not fatal.
# ---------------------------------------------------------------------------
OBJECT_EXPORTS = [
    # --- Network objects -------------------------------------------------
    ("show-hosts",                    "objects-hosts.json",                  "standard"),
    ("show-networks",                 "objects-networks.json",               "standard"),
    ("show-address-ranges",           "objects-address-ranges.json",         "standard"),
    ("show-multicast-address-ranges", "objects-multicast-ranges.json",       "standard"),
    ("show-groups",                   "objects-groups.json",                 "full"),      # members
    ("show-groups-with-exclusion",    "objects-groups-with-exclusion.json",  "full"),
    ("show-simple-gateways",          "objects-simple-gateways.json",        "standard"),
    ("show-simple-clusters",          "objects-simple-clusters.json",        "standard"),
    ("show-security-zones",           "objects-security-zones.json",         "full"),
    ("show-dynamic-objects",          "objects-dynamic.json",                "standard"),
    ("show-wildcards",                "objects-wildcards.json",              "full"),
    ("show-dns-domains",              "objects-dns-domains.json",            "standard"),
    ("show-updatable-objects-repository-content", "objects-updatable.json",  "standard"),
    # --- Services --------------------------------------------------------
    ("show-services-tcp",             "objects-services-tcp.json",           "standard"),  # port
    ("show-services-udp",             "objects-services-udp.json",           "standard"),
    ("show-services-icmp",            "objects-services-icmp.json",          "full"),      # icmp-type/code
    ("show-services-icmp6",           "objects-services-icmp6.json",         "full"),
    ("show-services-sctp",            "objects-services-sctp.json",          "standard"),
    ("show-services-other",           "objects-services-other.json",         "full"),      # protocol/match
    ("show-services-dce-rpc",         "objects-services-dce-rpc.json",       "standard"),
    ("show-services-rpc",             "objects-services-rpc.json",           "standard"),
    ("show-services-gtp",             "objects-services-gtp.json",           "standard"),
    ("show-service-groups",           "objects-service-groups.json",         "full"),      # members
    # --- Applications (L7) ----------------------------------------------
    ("show-application-sites",            "objects-application-sites.json",            "standard"),
    ("show-application-site-categories",  "objects-application-site-categories.json",  "standard"),
    ("show-application-site-groups",      "objects-application-site-groups.json",      "full"),
    ("show-checkpoint-hosts",         "objects-checkpoint-hosts.json",       "standard"),  # SMS/log servers
    # --- Identity / time / metadata -------------------------------------
    ("show-access-roles",             "objects-access-roles.json",           "full"),      # nets/users/machines
    ("show-times",                    "objects-times.json",                  "full"),
    ("show-time-groups",              "objects-time-groups.json",            "full"),
    ("show-data-types",               "objects-data-types.json",             "standard"),
    ("show-tags",                     "objects-tags.json",                   "standard"),
    ("show-users",                    "objects-users.json",                  "standard"),
    ("show-user-groups",              "objects-user-groups.json",            "full"),
    ("show-administrators",           "administrators.json",                 "standard"),
    # --- Threat Prevention objects --------------------------------------
    ("show-threat-profiles",          "objects-threat-profiles.json",        "standard"),
    ("show-exception-groups",         "objects-threat-exception-groups.json","standard"),
    # --- VPN -------------------------------------------------------------
    ("show-vpn-communities-star",        "vpn-communities-star.json",            "full"),
    ("show-vpn-communities-meshed",      "vpn-communities-meshed.json",          "full"),
    ("show-vpn-communities-remote-access","vpn-communities-remote-access.json",  "full"),
]

# Object lists that gain nat-settings / group membership only at details-level
# 'full' (slow on large counts).  --full-objects opts these up from 'standard'.
FULL_OBJECT_UPGRADE = {
    "objects-hosts.json",
    "objects-networks.json",
    "objects-address-ranges.json",
}

# Object files whose objects we run native where-used against (--where-used).
# Services/apps are usually low-value and high-volume, so default to the
# address-like and grouping objects that matter for "safe to delete?".
WHERE_USED_SOURCES = [
    "objects-hosts.json",
    "objects-networks.json",
    "objects-address-ranges.json",
    "objects-groups.json",
    "objects-service-groups.json",
]


def safe_filename(name):
    return re.sub(r"[^\w\-.]+", "_", str(name)).strip("_") or "unnamed"


def is_unsupported_error(text):
    """Distinguish 'this API version doesn't have that command' from real errors."""
    if not text:
        return False
    t = text.lower()
    needles = (
        "command not found",
        "not found in the api",
        "generic_err_command_not_found",
        "unknown command",
        "no such command",
        "requested object",
    )
    return any(n in t for n in needles)


class ProgressMonitor:
    """Console + live log file so long runs show visible progress."""

    def __init__(self, log_path=None):
        self.start = time.time()
        self.step = 0
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.write_text("", encoding="utf-8")

    def elapsed(self):
        secs = int(time.time() - self.start)
        return "{:02d}m {:02d}s".format(secs // 60, secs % 60)

    def log(self, message, also_print=True):
        self.step += 1
        line = "[{}] #{} {}".format(self.elapsed(), self.step, message)
        if also_print:
            print(line)
            sys.stdout.flush()
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")

    def status(self, message):
        line = "[{}] ... {}".format(self.elapsed(), message)
        print(line)
        sys.stdout.flush()
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


class CheckpointCollector:
    def __init__(self, mgmt_ip, port, username, password, output_base,
                 domain=None, all_domains=False, read_only=True, where_used=False,
                 full_objects=False, resolve_referenced=True,
                 verify=False, nvd_api_key=None, verify_export=False):
        self.mgmt_ip = mgmt_ip
        self.port = port
        self.username = username
        self.password = password
        self.domain = domain
        self.all_domains = all_domains
        self.read_only = read_only
        self.where_used = where_used
        self.full_objects = full_objects
        self.resolve_referenced = resolve_referenced
        self.nvd_api_key = (nvd_api_key or "").strip() or None
        # TLS verification: False (self-signed CP cert, the norm) or a CA bundle path.
        self.verify = verify
        self.session = requests.Session()
        self.headers = {}
        self.summary_rows = []
        self.run_id = None
        self.output_base = Path(output_base)
        self.run_dir = None
        self.policy_dir = None
        self.standalone_layers_dir = None
        self.exported_access_layers = set()
        self.pending_access_layers = []
        self.api_version = None
        self.verify_export = verify_export
        # Path to the standalone audit script in the public repo.
        self.audit_script = Path(__file__).with_name("export_quality_audit.py")
        self.progress = ProgressMonitor(self.output_base / "collection-progress-live.txt")

    # ----- output dirs ---------------------------------------------------
    def init_output_dirs(self, label=None):
        run_id = datetime.now().strftime("run-%Y%m%d-%H%M%S")
        if label:
            # one folder per CMA/domain so the HTML builder can process each
            # independently; sanitise the domain name for the filesystem.
            safe = re.sub(r"[^A-Za-z0-9._-]+", "_", str(label)).strip("_") or "domain"
            run_id = "{}__{}".format(run_id, safe)
        self.run_id = run_id
        self.run_dir = self.output_base / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.policy_dir = self.run_dir / "policy-by-package"
        self.policy_dir.mkdir(exist_ok=True)
        self.standalone_layers_dir = self.run_dir / "access-layers-shared"
        self.standalone_layers_dir.mkdir(exist_ok=True)
        self.exported_access_layers = set()
        self.pending_access_layers = []
        self.progress.log_path = self.run_dir / "collection-progress.log"
        self.progress.log_path.write_text("", encoding="utf-8")

    def base_url(self, endpoint):
        return "https://{host}:{port}/web_api/{endpoint}".format(
            host=self.mgmt_ip, port=self.port, endpoint=endpoint
        )

    # ----- session -------------------------------------------------------
    def login(self, announce=True):
        login_body = {
            "user": self.username,
            "password": self.password,
            "session-timeout": 3600,   # 1h idle window for long collections
        }
        if self.domain:
            login_body["domain"] = self.domain
        if self.read_only:
            login_body["read-only"] = True
        else:
            # session-name/comments/description are rejected by the API when the
            # login is read-only (generic_err_invalid_parameter): a read-only
            # login has no change-session to name. Set it only for read-write.
            login_body["session-name"] = "nexthop-audit-collect"
        url = self.base_url("login")
        if announce:
            self.progress.log("Connecting to management API ({}) ...".format(
                "read-only" if self.read_only else "READ-WRITE"))
            print("  URL: {}".format(url))
        try:
            res = self.session.post(url, json=login_body, verify=self.verify, timeout=120)
        except requests.exceptions.ConnectTimeout:
            print("\nERROR: Connection timed out.")
            print("  This PC cannot reach {}:{} — not a password problem.".format(self.mgmt_ip, self.port))
            print("  Check network/VPN/firewall, then retry.")
            return False
        except requests.exceptions.ConnectionError as exc:
            print("\nERROR: Connection failed — {}".format(exc))
            return False
        if not res.ok:
            print("Login failed (HTTP {}): {}".format(res.status_code, res.text))
            return False
        data = res.json()
        if "sid" not in data:
            print("Login failed: no session id in response\nResponse: {}".format(data))
            return False
        self.headers = {"X-chkp-sid": data["sid"], "Content-Type": "application/json"}
        if announce:
            uid = data.get("uid")
            print("  Login OK{}".format(" (session uid: {})".format(uid) if uid else ""))
        return True

    def relogin(self):
        """Re-establish a session mid-run (sessions time out on long collections)."""
        self.progress.status("Session expired — re-authenticating ...")
        return self.login(announce=False)

    def verify_api(self):
        res = self.api_call("show-api-versions", {})
        if res is not None and res.ok:
            versions = res.json().get("versions", [])
            if versions:
                self.api_version = versions[-1].get("version", versions[0].get("version"))
                print("  API version: {}".format(self.api_version))
        res = self.api_call("show-gateways-and-servers", {"limit": 1})
        if res is None or not res.ok:
            print("  WARNING: show-gateways-and-servers failed.")
            return False
        total = res.json().get("total", 0)
        print("  Gateways/servers visible to API: {}".format(total))
        if total == 0:
            print("  WARNING: zero gateways. If Multi-Domain, re-run with --domain YOUR_DOMAIN")
        return True

    def logout(self):
        try:
            self.session.post(self.base_url("logout"), headers=self.headers,
                              json={}, verify=self.verify, timeout=30)
        except requests.RequestException:
            pass

    def list_domains(self):
        """Enumerate CMA/domain names on a Multi-Domain Server.

        Only the MDS 'System Data' context answers show-domains; a plain single-
        domain SMS returns generic_err_command_not_found (404), so an empty list
        cleanly means 'this is not an MDS — collect the one domain we logged into'.
        The global policy/system domains are skipped: they hold global objects,
        not a real gateway policy."""
        names = []
        offset = 0
        while True:
            res = self.api_call("show-domains",
                                {"limit": 500, "offset": offset, "details-level": "standard"})
            if res is None or not res.ok:
                break
            data = res.json()
            for d in data.get("objects", []):
                name = d.get("name")
                if name and name.strip().lower() not in ("global", "system data"):
                    names.append(name)
            total = data.get("total", 0)
            to = data.get("to", 0)
            if not to or to >= total:
                break
            offset = to
        return names

    # ----- core call w/ retry + auto re-login ----------------------------
    def api_call(self, endpoint, payload=None):
        """POST with retry/backoff and one automatic re-login on session expiry.

        Returns the Response object, or None if all attempts failed to connect.
        """
        last_exc = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                res = self.session.post(
                    self.base_url(endpoint),
                    json=payload or {},
                    headers=self.headers,
                    verify=self.verify,
                    timeout=300,
                )
            except requests.RequestException as exc:
                last_exc = exc
                self.progress.status(
                    "network error on {} (attempt {}/{}): {}".format(
                        endpoint, attempt, MAX_RETRIES, exc))
                time.sleep(RETRY_BACKOFF * attempt)
                continue
            # Session expired -> re-login once and retry this call.
            if res.status_code in (400, 401) and self._looks_like_expired(res):
                if self.relogin():
                    continue
            return res
        if last_exc is not None:
            self.progress.log("  GAVE UP on {} after {} attempts: {}".format(
                endpoint, MAX_RETRIES, last_exc))
        return None

    @staticmethod
    def _looks_like_expired(res):
        try:
            body = res.text.lower()
        except Exception:
            return False
        return any(k in body for k in (
            "err_login_failed", "session expired", "wrong session id",
            "not logged in", "generic_err_session"))

    # ----- helpers -------------------------------------------------------
    def record_summary(self, dataset, status, count=0, note=""):
        self.summary_rows.append(
            {"dataset": dataset, "status": status, "count": count, "note": note})

    def save_json(self, path, data):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def extract_list_from_response(self, data):
        # Check Point list commands usually return "objects"; a few use a
        # typed key (packages, access-layers, threat-profiles).
        for key in ("objects", "packages", "access-layers", "threat-profiles"):
            if isinstance(data.get(key), list):
                return data[key]
        return []

    def paginate_objects(self, endpoint, details_level="standard", label=None, extra=None):
        """Page through a show-* list command to completion. Raises on hard error."""
        all_objects = []
        offset = 0
        total = None
        display = label or endpoint
        page = 0
        while True:
            page += 1
            payload = {"limit": PAGE_LIMIT, "offset": offset, "details-level": details_level}
            if extra:
                payload.update(extra)
            self.progress.status("{} — page {} (offset {})".format(display, page, offset))
            res = self.api_call(endpoint, payload)
            if res is None:
                raise RuntimeError("{}: no response (network)".format(endpoint))
            if not res.ok:
                raise RuntimeError("{} failed: {}".format(endpoint, res.text))
            data = res.json()
            batch = self.extract_list_from_response(data)
            all_objects.extend(batch)
            if total is None:
                total = data.get("total", len(batch))
            self.progress.status("{} — {}/{} objects".format(display, len(all_objects), total))
            if len(batch) < PAGE_LIMIT or len(all_objects) >= (total or 0):
                break
            offset += PAGE_LIMIT
        return all_objects, total

    def export_object_list(self, endpoint, filename, details_level="standard"):
        """Export one object type; tolerate version-unsupported endpoints."""
        extra = None
        # --full-objects: pull address-like objects at full to capture
        # object-level nat-settings + which groups they belong to.
        if self.full_objects and filename in FULL_OBJECT_UPGRADE:
            details_level = "full"
            extra = {"show-membership": True}
        self.progress.log("Collecting: {}{}".format(
            filename, "  [full+membership]" if extra else ""))
        try:
            objects, _ = self.paginate_objects(endpoint, details_level, label=filename, extra=extra)
        except RuntimeError as exc:
            msg = str(exc)
            if is_unsupported_error(msg):
                self.record_summary(filename, "skipped", 0, "not supported on this API version")
                self.progress.log("  skipped {} (endpoint not available)".format(endpoint))
            else:
                self.record_summary(filename, "error", 0, msg[:200])
                print("  FAILED {}: {}".format(endpoint, msg[:160]))
            return []
        self.save_json(self.run_dir / filename, objects)
        self.record_summary(filename, "ok", len(objects))
        self.progress.log("  {} — {} objects".format(filename, len(objects)))
        return objects

    def enrich_vpn_communities(self, filename, communities):
        """List API often returns gateways:[]. Re-fetch each community by UID."""
        show_cmd = VPN_SHOW_BY_FILE.get(filename)
        if not show_cmd or not communities:
            return communities
        filled = 0
        failed = 0
        for comm in communities:
            if not isinstance(comm, dict) or not comm.get("uid"):
                continue
            if not vpn_membership_empty(comm):
                continue
            detail = None
            for cmd, payload in (
                (show_cmd, {"uid": comm["uid"], "details-level": "full"}),
                ("show-object", {"uid": comm["uid"], "details-level": "full"}),
            ):
                try:
                    res = self.api_call(cmd, payload)
                except RuntimeError:
                    continue
                if res is None or not res.ok:
                    continue
                try:
                    detail = unwrap_vpn_show(res.json())
                except ValueError:
                    detail = None
                if detail:
                    break
            if detail is None:
                failed += 1
                continue
            merged = merge_vpn_detail(comm, detail)
            comm.clear()
            comm.update(merged)
            if not vpn_membership_empty(comm):
                filled += 1
        self.save_json(self.run_dir / filename, communities)
        note = "membership filled {} of {}; {} still empty".format(
            filled, len(communities), sum(1 for c in communities if vpn_membership_empty(c)))
        self.record_summary(filename + "-membership", "ok", filled, note)
        self.progress.log("  {} — {}".format(filename, note))
        if failed:
            self.progress.log("  {} — {} community show call(s) failed".format(filename, failed))
        return communities

    def enrich_custom_application_sites(self, objects):
        """Re-fetch customer-defined application-sites at 'full' detail.

        show-application-sites at 'standard' returns only name/uid/color for each
        app, which is useless for audit/migration of CUSTOM apps: it omits the
        url-list / primary-category / risk that define *what the app matches*.
        Check Point's own app database lives in BUILTIN_APP_DOMAINS, so anything
        in another domain (e.g. 'SMC User', or a CMA name on MDS) is customer-
        created and worth the extra per-object call (typically a few dozen)."""
        if not objects:
            return objects
        custom = []
        for o in objects:
            if not isinstance(o, dict):
                continue
            dom = o.get("domain")
            dom_name = dom.get("name") if isinstance(dom, dict) else dom
            if o.get("user-defined") is True or (dom_name not in BUILTIN_APP_DOMAINS):
                custom.append(o)
        if not custom:
            return objects
        by_uid = {o.get("uid"): o for o in objects if isinstance(o, dict)}
        enriched = 0
        for idx, o in enumerate(custom, 1):
            uid = o.get("uid")
            if not uid:
                continue
            self.progress.status("Custom app detail {}/{}: {}".format(
                idx, len(custom), o.get("name")))
            res = self.api_call("show-application-site", {"uid": uid, "details-level": "full"})
            if res is not None and res.ok:
                full = res.json()
                if isinstance(full, dict) and full.get("uid"):
                    by_uid[full["uid"]] = full
                    enriched += 1
        if enriched:
            # preserve original order, swap enriched records in place
            objects = [by_uid.get(o.get("uid"), o) if isinstance(o, dict) else o
                       for o in objects]
            self.save_json(self.run_dir / "objects-application-sites.json", objects)
            self.record_summary("application-sites-custom-detail", "ok", enriched)
            self.progress.log(
                "  enriched {} custom application-site(s) to full detail "
                "(url-list / category / risk)".format(enriched))
        return objects

    # ----- gateways ------------------------------------------------------
    def export_gateways(self):
        self.progress.log("Collecting: gateways-and-servers.json (full + per-device detail)")
        try:
            gateways, _ = self.paginate_objects(
                "show-gateways-and-servers", "full", label="gateways-and-servers")
        except RuntimeError as exc:
            self.record_summary("gateways-and-servers.json", "error", 0, str(exc)[:200])
            print("  FAILED gateways: {}".format(exc))
            return []
        detail_targets = [g for g in gateways
                          if g.get("type") in ("simple-gateway", "simple-cluster")]
        for idx, gw in enumerate(detail_targets, 1):
            gw_type = gw.get("type", "")
            self.progress.status("Gateway detail {}/{}: {}".format(
                idx, len(detail_targets), gw.get("name")))
            endpoint = ("show-simple-cluster" if gw_type == "simple-cluster"
                        else "show-simple-gateway")
            res = self.api_call(endpoint, {"name": gw["name"], "details-level": "full"})
            if res is not None and res.ok:
                detail = res.json()
                gw["interfaces"] = detail.get("interfaces", gw.get("interfaces", []))
                gw["snmp"] = detail.get("snmp")
                # capture anything else useful that 'full' on the list omits
                for k in ("routing", "vpn-settings", "nat-settings"):
                    if detail.get(k) is not None:
                        gw[k] = detail[k]
        self.save_json(self.run_dir / "gateways-and-servers.json", gateways)
        self.record_summary("gateways-and-servers.json", "ok", len(gateways))
        self.progress.log("  gateways-and-servers.json — {} devices".format(len(gateways)))
        return gateways

    # ----- global properties --------------------------------------------
    def export_global_properties(self):
        """Implied-rule / NAT / connection settings. show-global-properties is
        R81.20+ only; on older versions fall back to the firewall_properties
        generic object."""
        self.progress.log("Collecting: global-properties.json (implied-rule context)")
        res = self.api_call("show-global-properties", {"details-level": "full"})
        if res is not None and res.ok:
            self.save_json(self.run_dir / "global-properties.json", res.json())
            self.record_summary("global-properties.json", "ok", 1)
            return
        # Fallback: firewall_properties generic object (works on R80/R81.x).
        gres = self.api_call("show-generic-objects",
                             {"name": "firewall_properties", "details-level": "full"})
        if gres is not None and gres.ok:
            objs = gres.json().get("objects", [])
            if objs:
                self.save_json(self.run_dir / "global-properties.json", objs[0])
                self.record_summary("global-properties.json", "ok", 1, "via firewall_properties")
                return
        note = (res.text[:200] if res is not None else "no response")
        self.record_summary("global-properties.json", "skipped", 0, note)

    # ----- access / nat / threat rulebases (faithful to proven engine) ---
    def fetch_access_rulebase(self, layer_name, package_name):
        merged = None
        offset = 0
        page = 0
        while True:
            page += 1
            payload = {"name": layer_name, "limit": RULEBASE_LIMIT, "offset": offset,
                       "use-object-dictionary": True, "details-level": "standard",
                       "show-hits": True}
            self.progress.status("Access rules {}/{} — page {} offset {}".format(
                package_name, layer_name, page, offset))
            res = self.api_call("show-access-rulebase", payload)
            if res is None or not res.ok:
                raise RuntimeError(res.text if res is not None else "no response")
            data = res.json()
            if merged is None:
                obj_dict = data.get("objects-dictionary") or data.get("object_dictionary") or []
                merged = {"package": package_name, "layer": layer_name,
                          "object_dictionary": obj_dict, "rulebase": [], "total": data.get("total")}
            batch = data.get("rulebase", [])
            merged["rulebase"].extend(batch)
            total = data.get("total") or len(merged["rulebase"])
            merged["total"] = total
            to = data.get("to")
            if to is not None:
                if to >= total or to <= offset:
                    break
                offset = to
            else:
                # Fallback for older APIs: advance by actual rules collected.
                if len(batch) < RULEBASE_LIMIT or len(merged["rulebase"]) >= total:
                    break
                offset += RULEBASE_LIMIT
        merged["fetched"] = len(merged["rulebase"])
        return merged

    def fetch_nat_rulebase(self, package_name):
        merged_rulebase = []
        offset = 0
        total = None
        merged_dict = {}
        while True:
            # use-object-dictionary so NAT source/dest/service UIDs ship with a
            # resolvable name dictionary (incl. system objects like "Original").
            payload = {"package": package_name, "limit": RULEBASE_LIMIT, "offset": offset,
                       "use-object-dictionary": True}
            res = self.api_call("show-nat-rulebase", payload)
            if res is None or not res.ok:
                raise RuntimeError(res.text if res is not None else "no response")
            data = res.json()
            batch = data.get("rulebase", [])
            merged_rulebase.extend(batch)
            for obj in (data.get("objects-dictionary") or data.get("object_dictionary") or []):
                uid = obj.get("uid") if isinstance(obj, dict) else None
                if uid:
                    merged_dict[uid] = obj
            if total is None:
                total = data.get("total", 0)
            # NAT rules are grouped under nat-section headers, so the actual
            # rules live nested inside each section's own "rulebase" array. The
            # number of TOP-LEVEL entries (sections + ungrouped rules) is NOT
            # the rule count, so it must not drive pagination. Check Point's
            # "to" field is the index of the last RULE returned (counting the
            # nested rules), so it is the correct cursor for the next page.
            to = data.get("to")
            if not batch or total in (None, 0):
                break
            if to is None:
                # Fallback for servers that omit "to": advance by the count of
                # rules we actually collected (nested + top-level) to avoid a
                # premature stop on section-wrapped rulebases.
                collected = self._count_nat_rules(merged_rulebase)
                if collected >= total or collected <= offset:
                    break
                offset = collected
                continue
            if to >= total or to <= offset:
                break
            offset = to
        return {"rulebase": merged_rulebase, "objects-dictionary": list(merged_dict.values()),
                "total": total or self._count_nat_rules(merged_rulebase)}

    @staticmethod
    def _count_nat_rules(rulebase):
        """Count actual nat-rule entries, descending into nat-section wrappers."""
        n = 0
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "nat-section":
                n += CheckpointCollector._count_nat_rules(entry.get("rulebase", []))
            else:
                n += 1
        return n

    def fetch_threat_rulebase(self, layer_name):
        merged_rulebase = []
        offset = 0
        total = None
        merged_dict = {}
        while True:
            payload = {"name": layer_name, "limit": RULEBASE_LIMIT, "offset": offset,
                       "use-object-dictionary": True}
            res = self.api_call("show-threat-rulebase", payload)
            if res is None or not res.ok:
                raise RuntimeError(res.text if res is not None else "no response")
            data = res.json()
            batch = data.get("rulebase", [])
            merged_rulebase.extend(batch)
            for obj in (data.get("objects-dictionary") or data.get("object_dictionary") or []):
                uid = obj.get("uid") if isinstance(obj, dict) else None
                if uid:
                    merged_dict[uid] = obj
            if total is None:
                total = data.get("total", len(batch))
            if len(batch) < RULEBASE_LIMIT or len(merged_rulebase) >= total:
                break
            offset += RULEBASE_LIMIT
        return {"layer": layer_name, "rulebase": merged_rulebase,
                "objects-dictionary": list(merged_dict.values()),
                "total": total or len(merged_rulebase)}

    def fetch_https_rulebase(self, layer_name):
        merged_rulebase = []
        offset = 0
        total = None
        merged_dict = {}
        while True:
            # use-object-dictionary so HTTPS rule source/dest/service/site UIDs
            # ship with a resolvable name dictionary.
            payload = {"name": layer_name, "limit": RULEBASE_LIMIT, "offset": offset,
                       "use-object-dictionary": True}
            res = self.api_call("show-https-rulebase", payload)
            if res is None or not res.ok:
                raise RuntimeError(res.text if res is not None else "no response")
            data = res.json()
            batch = data.get("rulebase", [])
            merged_rulebase.extend(batch)
            for obj in (data.get("objects-dictionary") or data.get("object_dictionary") or []):
                uid = obj.get("uid") if isinstance(obj, dict) else None
                if uid:
                    merged_dict[uid] = obj
            if total is None:
                total = data.get("total", len(batch))
            if len(batch) < RULEBASE_LIMIT or len(merged_rulebase) >= total:
                break
            offset += RULEBASE_LIMIT
        return {"layer": layer_name, "rulebase": merged_rulebase,
                "objects-dictionary": list(merged_dict.values()),
                "total": total or len(merged_rulebase)}

    def _iter_threat_rules(self, rulebase):
        """Yield threat-rule dicts, recursing into threat-section containers."""
        for entry in rulebase or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("type") == "threat-section":
                for nested in self._iter_threat_rules(entry.get("rulebase", [])):
                    yield nested
            elif entry.get("type") in ("threat-rule", None) or "action" in entry:
                yield entry

    def _threat_profile_candidates_from_rulebases(self):
        """UID/name pairs for threat profiles referenced by exported TP rules."""
        found = {}  # uid -> name (may be None)
        policy_dir = self.policy_dir if hasattr(self, "policy_dir") else self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            return found
        for path in sorted(policy_dir.rglob("threat-rulebase-*.json")):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            for obj in (doc.get("objects-dictionary") or doc.get("object_dictionary") or []):
                if not isinstance(obj, dict):
                    continue
                if obj.get("type") == "threat-profile" and obj.get("uid"):
                    found[obj["uid"]] = obj.get("name")
            for rule in self._iter_threat_rules(doc.get("rulebase", [])):
                act = rule.get("action")
                if isinstance(act, str) and act:
                    found.setdefault(act, None)
                elif isinstance(act, dict) and act.get("uid"):
                    found[act["uid"]] = act.get("name") or found.get(act["uid"])
        return found

    def _fetch_threat_profile_full(self, uid=None, name=None):
        """Fetch one threat profile at full detail (IPS/AV/Anti-Bot/TE settings)."""
        payload = {"details-level": "full"}
        if uid:
            payload["uid"] = uid
        elif name:
            payload["name"] = name
        else:
            return None
        res = self.api_call("show-threat-profile", payload)
        if res is None or not res.ok:
            return None
        try:
            obj = res.json()
        except ValueError:
            return None
        if isinstance(obj, dict) and obj.get("uid"):
            return obj
        return None

    def _list_threat_profiles_via_show_objects(self):
        """Fallback when show-threat-profiles returns total>0 but empty objects[]."""
        try:
            objects, total = self.paginate_objects(
                "show-objects", "standard",
                label="show-objects type=threat-profile",
                extra={"type": "threat-profile"},
            )
            return objects, total
        except RuntimeError as exc:
            if is_unsupported_error(str(exc)):
                return [], 0
            self.progress.log("  show-objects threat-profile fallback failed: {}".format(
                str(exc)[:160]))
            return [], 0

    def enrich_threat_profiles(self):
        """Ensure objects-threat-profiles.json has full IPS/AV/Anti-Bot/TE detail.

        Observed on customer SMS: show-threat-profiles reports total>0 but returns
        an empty objects[] page. Profiles are still referenced from threat
        rulebases (action UID + objects-dictionary). Recover by:
          1) show-objects type=threat-profile when the list export is empty
          2) per-UID/name show-threat-profile details-level full for every
             profile referenced by TP rules (and any stubs from step 1)
        """
        path = self.run_dir / "objects-threat-profiles.json"
        existing = []
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    existing = loaded
            except (OSError, ValueError):
                existing = []

        by_uid = {}
        for o in existing:
            if isinstance(o, dict) and o.get("uid"):
                by_uid[o["uid"]] = o

        # Fallback list when bulk show-threat-profiles returned nothing.
        if not by_uid:
            alt, alt_total = self._list_threat_profiles_via_show_objects()
            if alt:
                self.progress.log(
                    "  show-threat-profiles was empty; show-objects returned "
                    "{}/{} threat-profile stub(s)".format(len(alt), alt_total or len(alt)))
                for o in alt:
                    if isinstance(o, dict) and o.get("uid"):
                        by_uid[o["uid"]] = o

        # Always include profiles referenced by threat rulebases.
        for uid, name in self._threat_profile_candidates_from_rulebases().items():
            if uid not in by_uid:
                by_uid[uid] = {"uid": uid, "name": name, "type": "threat-profile"}
            elif name and not by_uid[uid].get("name"):
                by_uid[uid]["name"] = name

        if not by_uid:
            self.save_json(path, [])
            self.record_summary("threat-profiles-enrich", "ok", 0, "no profiles referenced")
            self.progress.log("  threat profiles — none referenced in TP rulebases")
            return []

        enriched = 0
        failed = 0
        items = sorted(by_uid.items(), key=lambda kv: (kv[1].get("name") or kv[0]))
        for idx, (uid, stub) in enumerate(items, 1):
            # Skip if already has blade settings (full export).
            if any(k in stub for k in ("ips", "anti-bot", "anti-virus", "threat-emulation",
                                       "active-protections-configuration")):
                continue
            self.progress.status("Threat profile detail {}/{}: {}".format(
                idx, len(items), stub.get("name") or uid[:8]))
            full = self._fetch_threat_profile_full(uid=uid, name=stub.get("name"))
            if full:
                by_uid[uid] = full
                enriched += 1
            else:
                failed += 1

        out = sorted(by_uid.values(), key=lambda o: (o.get("name") or "").lower())
        self.save_json(path, out)
        note = "enriched {} of {}; {} failed".format(enriched, len(out), failed)
        self.record_summary("objects-threat-profiles.json", "ok", len(out), note)
        self.record_summary("threat-profiles-enrich", "ok", enriched, note)
        self.progress.log("  threat profiles — {} object(s) ({} full detail, {} unresolved)".format(
            len(out), enriched, failed))
        return out

    def fetch_threat_exception_rulebase(self, package_name, rule_uid=None,
                                        rule_number=None, layer_name=None,
                                        layer_uid=None):
        """Page through show-threat-rule-exception-rulebase for one parent TP rule."""
        merged_rulebase = []
        offset = 0
        total = None
        merged_dict = {}
        use_layer_uid = False
        tried = set()
        while True:
            attempt = (offset, use_layer_uid)
            payload = threat_exception_payload(
                package_name=package_name,
                rule_uid=rule_uid,
                rule_number=rule_number,
                layer_name=layer_name,
                layer_uid=layer_uid,
                offset=offset,
                limit=RULEBASE_LIMIT,
                include_layer_uid=use_layer_uid,
            )
            res = self.api_call("show-threat-rule-exception-rulebase", payload)
            if res is None or not res.ok:
                text = res.text if res is not None else "no response"
                low = text.lower()
                if attempt not in tried:
                    tried.add(attempt)
                    if (not use_layer_uid and layer_uid
                            and "missing parameter" in low):
                        use_layer_uid = True
                        continue
                    if (use_layer_uid
                            and "unrecognized parameter" in low
                            and "layer-uid" in low):
                        use_layer_uid = False
                        continue
                raise RuntimeError(text)
            data = res.json()
            batch = data.get("rulebase", [])
            merged_rulebase.extend(batch)
            for obj in (data.get("objects-dictionary") or data.get("object_dictionary") or []):
                uid = obj.get("uid") if isinstance(obj, dict) else None
                if uid:
                    merged_dict[uid] = obj
            if total is None:
                total = data.get("total", len(batch))
            if len(batch) < RULEBASE_LIMIT or len(merged_rulebase) >= (total or 0):
                break
            offset += RULEBASE_LIMIT
        return {
            "rulebase": merged_rulebase,
            "objects-dictionary": list(merged_dict.values()),
            "total": total or len(merged_rulebase),
        }

    def export_threat_exceptions(self):
        """Fetch exception rulebases for every threat rule that declares exceptions.

        Saved as policy-by-package/<pkg>/threat-exceptions-<rule>.json so the HTML
        viewer can show IPS/AV/Anti-Bot exception rows under each TP rule.
        """
        policy_dir = self.policy_dir if hasattr(self, "policy_dir") else self.run_dir / "policy-by-package"
        if not policy_dir.is_dir():
            self.record_summary("threat-exceptions", "ok", 0, "no policy packages")
            return 0

        exported = 0
        failed = 0
        skipped = 0
        for path in sorted(policy_dir.rglob("threat-rulebase-*.json")):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            pkg_name = path.parent.name
            layer_name = doc.get("layer") or ""
            for rule in self._iter_threat_rules(doc.get("rulebase", [])):
                exc = rule.get("exceptions") or []
                if not exc and not rule.get("exceptions-layer"):
                    continue
                rule_uid = rule.get("uid")
                rule_name = rule.get("name") or rule_uid or "exception"
                if not rule_uid and rule.get("rule-number") is None:
                    skipped += 1
                    continue
                fname = "threat-exceptions-{}.json".format(
                    safe_filename(rule_name if rule_name != rule_uid else rule_uid[:12]))
                out_path = path.parent / fname
                # Avoid clobber when two rules sanitize to the same name.
                if out_path.exists():
                    fname = "threat-exceptions-{}-{}.json".format(
                        safe_filename(rule_name)[:40],
                        (rule_uid or "x")[:8])
                    out_path = path.parent / fname
                try:
                    exc_doc = self.fetch_threat_exception_rulebase(
                        package_name=pkg_name,
                        rule_uid=rule_uid,
                        rule_number=rule.get("rule-number"),
                        layer_name=layer_name,
                        layer_uid=exception_layer_uid(rule),
                    )
                except RuntimeError as exc_err:
                    msg = str(exc_err)
                    if is_unsupported_error(msg):
                        skipped += 1
                        self.progress.log("  threat exceptions n/a on this API version")
                        self.record_summary("threat-exceptions", "skipped", 0,
                                            "show-threat-rule-exception-rulebase not supported")
                        return exported
                    failed += 1
                    self.progress.log("  FAILED exceptions {}/{}: {}".format(
                        pkg_name, rule_name, msg[:120]))
                    continue
                payload = {
                    "package": pkg_name,
                    "layer": layer_name,
                    "rule-uid": rule_uid,
                    "rule-name": rule_name,
                    "rule-number": rule.get("rule-number"),
                    "parent-exceptions-uids": exc if isinstance(exc, list) else [],
                    "rulebase": exc_doc.get("rulebase", []),
                    "objects-dictionary": exc_doc.get("objects-dictionary", []),
                    "total": exc_doc.get("total", 0),
                }
                self.save_json(out_path, payload)
                exported += 1
                self.progress.log("  exceptions {}/{} — {} row(s)".format(
                    pkg_name, rule_name, payload["total"]))

        note = "{} files; {} failed; {} skipped".format(exported, failed, skipped)
        self.record_summary("threat-exceptions", "ok", exported, note)
        self.progress.log("  threat exceptions — {}".format(note))
        return exported

    # ----- inner / shared layer discovery (faithful to proven engine) ----
    def _object_name(self, val):
        if val is None:
            return None
        if isinstance(val, str):
            name = val.strip()
            return name or None
        if isinstance(val, dict):
            return val.get("name") or val.get("layer")
        return None

    def discover_inner_layer_names(self, rules):
        found = set()
        if not rules:
            return found
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if rule.get("type") == "access-section":
                found |= self.discover_inner_layer_names(rule.get("rulebase", []))
                continue
            action = rule.get("action")
            if isinstance(action, dict):
                if action.get("type", "") in ("inner-layer", "apply-layer"):
                    layer = (self._object_name(action.get("layer"))
                             or self._object_name(action.get("name")))
                    if layer:
                        found.add(layer)
            inline = self._object_name(rule.get("inline-layer"))
            if inline:
                found.add(inline)
            settings = rule.get("action-settings")
            if isinstance(settings, dict):
                layer = self._object_name(settings.get("layer"))
                if layer:
                    found.add(layer)
        return found

    def queue_inner_layers(self, rulebase_doc):
        try:
            names = self.discover_inner_layer_names(rulebase_doc.get("rulebase", []))
        except Exception as exc:
            self.progress.log("WARNING: inner-layer scan skipped for {}: {}".format(
                rulebase_doc.get("layer", "?"), exc))
            return
        for name in names:
            if name not in self.exported_access_layers and name not in self.pending_access_layers:
                self.pending_access_layers.append(name)

    def export_access_layer(self, layer_name, dest_dir, package_name, summary_prefix, force=False):
        fname = "access-rulebase-{}.json".format(safe_filename(layer_name))
        dest_path = Path(dest_dir) / fname
        if not force and layer_name in self.exported_access_layers:
            return
        if not force and dest_path.exists():
            self.exported_access_layers.add(layer_name)
            return
        try:
            rulebase_doc = self.fetch_access_rulebase(layer_name, package_name)
            self.save_json(dest_path, rulebase_doc)
            self.exported_access_layers.add(layer_name)
            count = rulebase_doc.get("fetched", 0)
            self.record_summary("{}-{}".format(summary_prefix, layer_name), "ok", count)
            self.progress.log("  access layer {} — {} rules ({})".format(
                layer_name, count, summary_prefix))
            self.queue_inner_layers(rulebase_doc)
        except RuntimeError as exc:
            self.record_summary("{}-{}".format(summary_prefix, layer_name), "error", 0, str(exc)[:200])
            print("    FAILED access layer {}: {}".format(layer_name, exc))

    def export_pending_inner_layers(self):
        while self.pending_access_layers:
            layer_name = self.pending_access_layers.pop(0)
            if layer_name in self.exported_access_layers:
                continue
            self.export_access_layer(layer_name, self.standalone_layers_dir,
                                     "(inner-layer)", "access-inner")

    def _rulebase_file_count(self, path):
        try:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
            return doc.get("fetched", len(doc.get("rulebase", [])))
        except (OSError, ValueError, json.JSONDecodeError):
            return ""

    def write_access_layers_manifest(self, layers, layer_stats):
        path = self.run_dir / "access-layers-manifest.csv"
        by_name = {row[0]: row for row in layer_stats}
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerow(["layer_name", "uid", "icon", "rule_count", "export_status", "json_file"])
            for layer in layers:
                name = layer.get("name", "")
                if name in by_name:
                    writer.writerow(list(by_name[name]))
                else:
                    writer.writerow([name, layer.get("uid", ""), layer.get("icon", ""), "", "skipped", ""])

    def export_all_access_layers_from_inventory(self):
        self.progress.log("Collecting: show-access-layers (full inventory)")
        try:
            layers, total = self.paginate_objects("show-access-layers", "standard", label="access-layers")
        except RuntimeError as exc:
            self.record_summary("access-layers.json", "error", 0, str(exc)[:200])
            print("  FAILED show-access-layers: {}".format(exc))
            return
        self.save_json(self.run_dir / "access-layers.json", layers)
        self.save_json(self.standalone_layers_dir / "_inventory.json", layers)
        self.record_summary("access-layers.json", "ok", len(layers))
        self.progress.log("Access layer inventory: {} layers (API total: {})".format(len(layers), total))

        layer_stats = []
        fetched = 0
        skipped_existing = 0
        for idx, layer in enumerate(layers, 1):
            layer_name = layer.get("name")
            if not layer_name:
                continue
            fname = "access-rulebase-{}.json".format(safe_filename(layer_name))
            shared_path = self.standalone_layers_dir / fname
            if shared_path.exists() and layer_name in self.exported_access_layers:
                skipped_existing += 1
                rcount = self._rulebase_file_count(shared_path)
                layer_stats.append((layer_name, layer.get("uid"), layer.get("icon"),
                                    rcount, "ok-existing", fname))
                continue
            self.progress.log("Shared layer {}/{}: {}".format(idx, len(layers), layer_name))
            self.export_access_layer(layer_name, self.standalone_layers_dir,
                                     "(shared-layer)", "access-shared", force=True)
            if shared_path.exists():
                fetched += 1
                rcount = self._rulebase_file_count(shared_path)
                layer_stats.append((layer_name, layer.get("uid"), layer.get("icon"),
                                    rcount, "ok", fname))
            else:
                layer_stats.append((layer_name, layer.get("uid"), layer.get("icon"),
                                    "", "error", fname))

        self.export_pending_inner_layers()
        self.write_access_layers_manifest(layers, layer_stats)
        self.progress.log("access-layers-shared/: {} new, {} present, {} in inventory".format(
            fetched, skipped_existing, len(layers)))

    def export_policies(self):
        self.progress.log("Collecting: policy packages")
        packages, _ = self.paginate_objects("show-packages", "standard", label="packages")
        self.save_json(self.run_dir / "packages.json", packages)
        self.record_summary("packages.json", "ok", len(packages))
        self.progress.log("Found {} policy package(s)".format(len(packages)))

        # Shared HTTPS inspection layers repeat across packages; fetch each once.
        https_cache = {}
        for pkg_index, pkg in enumerate(packages, 1):
            pkg_name = pkg.get("name")
            if not pkg_name:
                continue
            self.progress.log("Package {}/{}: {}".format(pkg_index, len(packages), pkg_name))
            pkg_dir = self.policy_dir / safe_filename(pkg_name)
            pkg_dir.mkdir(exist_ok=True)

            res = self.api_call("show-package", {"name": pkg_name, "details-level": "full"})
            if res is None or not res.ok:
                self.record_summary("package-{}".format(pkg_name), "error", 0,
                                    res.text[:200] if res is not None else "no response")
                print("  FAILED show-package {}: {}".format(
                    pkg_name, (res.text[:120] if res is not None else "no response")))
                continue
            pkg_detail = res.json()
            self.save_json(pkg_dir / "package.json", pkg_detail)

            for layer in pkg_detail.get("access-layers", []):
                if layer.get("name"):
                    self.export_access_layer(layer["name"], pkg_dir, pkg_name,
                                             "access-rulebase-{}".format(pkg_name))
            self.export_pending_inner_layers()

            for layer in pkg_detail.get("threat-layers", []):
                layer_name = layer.get("name")
                if not layer_name:
                    continue
                fname = "threat-rulebase-{}.json".format(safe_filename(layer_name))
                try:
                    threat_doc = self.fetch_threat_rulebase(layer_name)
                    self.save_json(pkg_dir / fname, threat_doc)
                    self.record_summary("threat-rulebase-{}-{}".format(pkg_name, layer_name),
                                        "ok", len(threat_doc.get("rulebase", [])))
                    self.progress.log("  threat {}/{} — {} rules".format(
                        pkg_name, layer_name, len(threat_doc.get("rulebase", []))))
                except RuntimeError as exc:
                    self.record_summary("threat-rulebase-{}-{}".format(pkg_name, layer_name),
                                        "error", 0, str(exc)[:200])
                    print("    FAILED threat {} / {}: {}".format(pkg_name, layer_name, exc))

            # HTTPS inspection layer(s) referenced by the package, if any.
            # R81 CMA often uses https-inspection-policy:true plus a sibling
            # https-inspection-layers dict (inbound/outbound). See https_layer_refs.
            https_layers = https_layer_refs(pkg_detail)
            if https_layers:
                self.progress.log("  https layers on {}: {}".format(
                    pkg_name, ", ".join(ly.get("name") or ly.get("uid") for ly in https_layers)))

            seen_https = set()
            for layer in https_layers:
                if not isinstance(layer, dict):
                    continue
                layer_name = layer.get("name")
                if not layer_name or layer_name in seen_https:
                    continue
                seen_https.add(layer_name)
                fname = "https-rulebase-{}.json".format(safe_filename(layer_name))
                # Shared layer already fetched for another package — reuse it.
                if layer_name in https_cache:
                    https_doc = https_cache[layer_name]
                    self.save_json(pkg_dir / fname, https_doc)
                    self.record_summary("https-rulebase-{}-{}".format(pkg_name, layer_name),
                                        "ok", len(https_doc.get("rulebase", [])))
                    continue
                try:
                    https_doc = self.fetch_https_rulebase(layer_name)
                    https_cache[layer_name] = https_doc
                    self.save_json(pkg_dir / fname, https_doc)
                    self.record_summary("https-rulebase-{}-{}".format(pkg_name, layer_name),
                                        "ok", len(https_doc.get("rulebase", [])))
                    self.progress.log("  https {}/{} — {} rules".format(
                        pkg_name, layer_name, len(https_doc.get("rulebase", []))))
                except RuntimeError as exc:
                    if is_unsupported_error(str(exc)):
                        self.record_summary("https-rulebase-{}-{}".format(pkg_name, layer_name),
                                            "skipped", 0, "https rulebase n/a")
                    else:
                        self.record_summary("https-rulebase-{}-{}".format(pkg_name, layer_name),
                                            "error", 0, str(exc)[:200])

            try:
                nat_doc = self.fetch_nat_rulebase(pkg_name)
                self.save_json(pkg_dir / "nat-rulebase.json", nat_doc)
                # NAT rules are grouped under nat-section headers, so the true
                # rule count is the nested total, not the number of top-level
                # entries (which is mostly section headers).
                nat_count = nat_doc.get("total") or self._count_nat_rules(nat_doc.get("rulebase", []))
                self.record_summary("nat-rulebase-{}".format(pkg_name), "ok", nat_count)
                self.progress.log("  NAT {} — {} rules".format(pkg_name, nat_count))
            except RuntimeError as exc:
                self.record_summary("nat-rulebase-{}".format(pkg_name), "error", 0, str(exc)[:200])
                print("    FAILED NAT {}: {}".format(pkg_name, exc))

        self.export_all_access_layers_from_inventory()

    # ----- resolve referenced UIDs missing from bulk exports -------------
    def _uids_already_exported(self):
        """Every UID already present anywhere in this run folder."""
        known = set()
        skip = {"objects-referenced.json", "objects-where-used.json"}
        for path in self.run_dir.rglob("*.json"):
            if path.name in skip:
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            known.update(iter_embedded_uids(data))
        return known

    def _uids_from_member_lists(self):
        refs = set()
        for fname in MEMBER_OBJECT_FILES:
            path = self.run_dir / fname
            if not path.exists():
                continue
            try:
                objs = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for obj in objs:
                if not isinstance(obj, dict):
                    continue
                for member in (obj.get("members") or []):
                    u = uid_from_ref(member)
                    if u:
                        refs.add(u)
        path = self.run_dir / "objects-access-roles.json"
        if path.exists():
            try:
                roles = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                roles = []
            for role in roles:
                if not isinstance(role, dict):
                    continue
                for fld in ACCESS_ROLE_MEMBER_FIELDS:
                    for val in (role.get(fld) or []):
                        u = uid_from_ref(val)
                        if u:
                            refs.add(u)
        return refs

    def _uids_from_rulebase_doc(self, doc):
        refs = set()

        def walk_rulebase(rulebase):
            for entry in rulebase or []:
                if not isinstance(entry, dict):
                    continue
                etype = entry.get("type") or ""
                if etype.endswith("-section"):
                    walk_rulebase(entry.get("rulebase"))
                    continue
                for fld in RULE_REF_FIELDS:
                    val = entry.get(fld)
                    if isinstance(val, str):
                        u = uid_from_ref(val)
                        if u:
                            refs.add(u)
                    elif isinstance(val, list):
                        for item in val:
                            u = uid_from_ref(item)
                            if u:
                                refs.add(u)
                u = uid_from_ref(entry.get("uid"))
                if u:
                    refs.add(u)

        walk_rulebase(doc.get("rulebase"))
        for obj in (doc.get("object_dictionary") or doc.get("objects-dictionary") or []):
            u = uid_from_ref(obj.get("uid") if isinstance(obj, dict) else obj)
            if u:
                refs.add(u)
        return refs

    def _uids_from_rulebases(self):
        refs = set()
        for base in (self.policy_dir, self.standalone_layers_dir):
            if not base or not base.is_dir():
                continue
            for path in base.rglob("*.json"):
                try:
                    doc = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
                if isinstance(doc, dict):
                    refs.update(self._uids_from_rulebase_doc(doc))
        return refs

    def _uids_needing_resolution(self):
        known = self._uids_already_exported()
        needed = self._uids_from_member_lists() | self._uids_from_rulebases()
        return sorted(needed - known)

    def export_referenced_objects(self):
        """Fetch show-object for UIDs referenced in groups/rules but not exported.

        Group members often include VS gateway UIDs, DNS domains, or decommissioned
        objects that never appear in a bulk show-* list. One show-object per missing
        UID fills objects-referenced.json for the HTML viewer."""
        missing = self._uids_needing_resolution()
        if not missing:
            self.save_json(self.run_dir / "objects-referenced.json", [])
            self.record_summary("objects-referenced.json", "ok", 0, "no missing refs")
            self.progress.log("  objects-referenced.json — 0 (all refs already exported)")
            return []

        self.progress.log("Collecting: objects-referenced.json ({} UIDs via show-object)".format(
            len(missing)))
        resolved = []
        failed = 0
        for idx, uid in enumerate(missing, 1):
            if idx == 1 or idx % 25 == 0 or idx == len(missing):
                self.progress.status("show-object {}/{}".format(idx, len(missing)))
            res = self.api_call("show-object", {"uid": uid, "details-level": "standard"})
            if res is None:
                failed += 1
                continue
            if not res.ok:
                failed += 1
                continue
            try:
                obj = res.json()
            except ValueError:
                failed += 1
                continue
            if isinstance(obj, dict) and obj.get("uid"):
                resolved.append(obj)
            else:
                failed += 1

        self.save_json(self.run_dir / "objects-referenced.json", resolved)
        note = "resolved {} of {} missing refs".format(len(resolved), len(missing))
        if failed:
            note += "; {} not found".format(failed)
        self.record_summary("objects-referenced.json", "ok", len(resolved), note)
        self.progress.log("  objects-referenced.json — {} objects ({} unresolved)".format(
            len(resolved), len(missing) - len(resolved)))
        return resolved

    # ----- native where-used reverse references (optional) ---------------
    def export_where_used(self):
        """Run Check Point's native where-used per object for ground-truth refs.

        Expensive (one call per object) so it is opt-in via --where-used. The
        HTML report also infers where-used from the rulebase cheaply; this pass
        adds references the rulebase scan can't see (group membership, NAT
        methods, VPN domains) and validates 'safe to delete'.
        """
        self.progress.log("Collecting: native where-used reverse references")
        results = {}
        total_objs = 0
        for src_file in WHERE_USED_SOURCES:
            path = self.run_dir / src_file
            if not path.exists():
                continue
            try:
                objs = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for o in objs:
                uid = o.get("uid")
                if not uid:
                    continue
                total_objs += 1
                if total_objs % 50 == 0:
                    self.progress.status("where-used: {} objects queried".format(total_objs))
                res = self.api_call("where-used",
                                    {"uid": uid, "indirect": True, "indirect-max-depth": 5})
                if res is None or not res.ok:
                    continue
                data = res.json()
                used_d = data.get("used-directly", {}) or {}
                used_i = data.get("used-indirectly", {}) or {}
                # store compact counts + the structures for the report
                results[uid] = {
                    "name": o.get("name"),
                    "used-directly": used_d,
                    "used-indirectly": used_i,
                    "total-direct": used_d.get("total", 0),
                    "total-indirect": used_i.get("total", 0),
                }
        self.save_json(self.run_dir / "objects-where-used.json", results)
        self.record_summary("objects-where-used.json", "ok", len(results))
        self.progress.log("  where-used — {} objects with reference data".format(len(results)))

    # ----- reporting outputs --------------------------------------------
    def write_capability_csv(self):
        rows = [
            ("Gateway and cluster inventory", "yes", "show-gateways-and-servers (full) + per-device detail"),
            ("Policy packages (all)", "yes", "show-packages + show-package per package"),
            ("Access rulebases (package layers)", "yes", "show-access-rulebase per package layer"),
            ("Access rulebases (shared/inner layers)", "yes", "show-access-layers + inner-layer discovery"),
            ("Threat rulebases", "yes", "show-threat-rulebase per threat layer"),
            ("Threat Prevention profiles (IPS/AV/Anti-Bot/TE)", "yes",
             "show-threat-profiles + per-UID show-threat-profile full + show-objects fallback"),
            ("Threat rule exceptions", "yes",
             "show-threat-rule-exception-rulebase with layer-name + layer-uid + rule-uid"),
            ("HTTPS inspection rulebases", "yes",
             "show-https-rulebase for https-inspection-layers (dict, list, or policy wrapper)"),
            ("NAT rulebases", "yes", "show-nat-rulebase per package"),
            ("Network/service objects (full surface)", "yes", "hosts, networks, ranges, multicast, groups(+excl), wildcards, zones, dynamic"),
            ("Service objects (all protocols)", "yes", "tcp, udp, icmp(+v6), sctp, other, dce-rpc, rpc, gtp, groups"),
            ("Applications (L7) / URL Filtering", "yes",
             "application-sites (+ custom full), categories, groups; applied via Access Service column"),
            ("Identity Awareness (Access Roles)", "yes",
             "access-roles(full); applied via Access Source column"),
            ("Identity / time / metadata", "yes", "access-roles(full), times, time-groups, data-types, tags, users"),
            ("Group / service-group / access-role members", "yes", "captured at details-level full"),
            ("VPN communities", "yes",
             "show-vpn-communities-* full + per-UID show-vpn-community-* when gateways is empty"),
            ("Global properties / implied rules", "yes", "show-global-properties"),
            ("Referenced object name resolution", "yes", "show-object for UIDs in groups/rules not in bulk exports"),
            ("Native where-used reverse references", "optional", "--where-used (per-object where-used)"),
            ("Live routing table on gateway OS", "no", "Requires Gaia SSH/API"),
            ("SNMP runtime on gateway OS", "no", "Requires Gaia SSH/API"),
        ]
        path = self.run_dir / "collection-capability.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_ALL)
            writer.writerow(["item", "available_via_management_api", "note"])
            writer.writerows(rows)

    def write_summary_csv(self):
        path = self.run_dir / "collection-summary.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["dataset", "status", "count", "note"],
                                    quoting=csv.QUOTE_ALL)
            writer.writeheader()
            writer.writerows(self.summary_rows)

    def prefetch_cve_intel(self, gateways):
        """Bake CVE threat-intel into the bundle while we are demonstrably online:
        CISA KEV + NVD CVSS for the curated advisories, NVD CPE discovery for each
        distinct Gaia version found on the gateways (informational tier) and EPSS
        scores. Written to _cve_intel_cache.json inside the run folder (and so the
        zip), keeping the analysis side fully offline. Never fatal."""
        try:
            repo = Path(__file__).resolve().parents[2]
            if str(repo) not in sys.path:
                sys.path.insert(0, str(repo))
            from core.cve_intel import cpe_for_version, fetch_cve_intel
            try:
                from build_html import KNOWN_CVES  # sibling module, same curated set
                cve_ids = [c["cve"] for c in KNOWN_CVES]
            except Exception:
                cve_ids = []
            versions = {str((g or {}).get("version") or "") for g in (gateways or [])
                        if isinstance(g, dict)}
            cpes = sorted({cpe_for_version("checkpoint", v) for v in versions} - {""})
            self.progress.log("Pre-fetching CVE intel (KEV + NVD + EPSS; {} CVEs, {} CPEs) ..."
                              .format(len(cve_ids), len(cpes)))
            fetch_cve_intel(cve_ids, self.run_dir / "_cve_intel_cache.json",
                            offline=False, cpes=cpes, nvd_api_key=self.nvd_api_key)
            self.progress.log("  CVE intel cached in bundle (_cve_intel_cache.json)")
        except Exception as exc:  # network/import problems must never break collection
            self.progress.log("  CVE intel pre-fetch skipped ({})".format(
                exc.__class__.__name__))

    def create_zip(self):
        zip_name = "checkpoint_audit_{}.zip".format(datetime.now().strftime("%Y%m%d-%H%M%S"))
        zip_path = self.output_base / zip_name
        all_files = []
        for root, _, files in os.walk(self.run_dir):
            for file in files:
                all_files.append(Path(root) / file)
        self.progress.log("Creating zip ({} files) ...".format(len(all_files)))
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for n, full in enumerate(all_files, 1):
                if n % 25 == 0 or n == len(all_files):
                    self.progress.status("Zipping {}/{}".format(n, len(all_files)))
                zf.write(full, Path(self.run_id) / full.relative_to(self.run_dir))
        self.progress.log("Zip created: {}".format(zip_path.name))
        return zip_path

    # ----- orchestration -------------------------------------------------
    def run(self):
        print(BANNER)
        print("Check Point audit collection (read-only)")
        print("  Management: {}:{}".format(self.mgmt_ip, self.port))
        print("  Mode: {}".format("READ-ONLY (safe on production)" if self.read_only else "READ-WRITE"))
        print("  Object detail: {}".format("FULL (nat-settings + membership)" if self.full_objects
                                           else "standard (use --full-objects for object NAT)"))
        print("  where-used: {}".format("ENABLED" if self.where_used else "disabled (use --where-used)"))
        print("  resolve refs: {}".format("ENABLED" if self.resolve_referenced else "disabled (--no-resolve-referenced)"))
        print("  Multi-Domain: {}".format("ALL domains (--all-domains)" if self.all_domains
                                          else ("domain '{}'".format(self.domain) if self.domain
                                                else "single management domain")))
        print()
        self.progress.log("Collection started")

        if not self.login():
            return 1

        # Multi-Domain Server: enumerate CMAs/domains and collect each one.
        domains = self.list_domains() if self.all_domains else []
        if self.all_domains and not domains:
            self.progress.log("--all-domains set, but show-domains returned nothing "
                              "(not an MDS, or no domains visible) — collecting the "
                              "single management domain instead.")
        if domains:
            self.progress.log("Multi-Domain Server detected — {} domain(s): {}".format(
                len(domains), ", ".join(domains)))
            self.logout()  # drop the System-context session before per-domain logins
            overall = 0
            for i, dom in enumerate(domains, 1):
                self.domain = dom
                self.progress.log("=== [{}/{}] Domain: {} ===".format(i, len(domains), dom))
                print("\n=== [{}/{}] Domain: {} ===".format(i, len(domains), dom))
                if not self.login(announce=False):
                    self.progress.log("  login to domain '{}' failed — skipping".format(dom))
                    overall = 1
                    continue
                if not self.verify_api():
                    self.progress.log("  domain '{}' returned no data — skipping".format(dom))
                    self.logout()
                    overall = 1
                    continue
                try:
                    rc = self.collect_current_domain(label=dom)
                    if rc:
                        overall = rc
                finally:
                    self.logout()
            print("\nAll domains processed. Per-domain run folders are in: {}".format(
                self.output_base))
            return overall

        # Single management domain (SMS, or MDS with a specific --domain).
        if not self.verify_api():
            print("\nLogin worked but API returned no data. Try --domain NAME or "
                  "--all-domains if this is a Multi-Domain Server.")
            self.logout()
            return 1
        try:
            return self.collect_current_domain()
        finally:
            self.logout()

    def collect_current_domain(self, label=None):
        """Collect every dataset for the domain we are currently logged into.

        Each call gets its own run folder and its own summary so multi-domain
        runs never bleed datasets/counts across CMAs.
        """
        # reset per-domain state
        self.summary_rows = []
        self.init_output_dirs(label=label)
        print("  Output folder: {}".format(self.run_dir))
        print("  Progress log:  {}\n".format(self.progress.log_path))

        self.progress.log("Phase 1/6: gateways & global properties")
        gateways = self.export_gateways()
        self.export_global_properties()

        self.progress.log("Phase 2/6: network/service/identity objects (full surface)")
        for endpoint, filename, level in OBJECT_EXPORTS:
            objs = self.export_object_list(endpoint, filename, level)
            if filename == "objects-application-sites.json":
                self.enrich_custom_application_sites(objs)
            if filename in VPN_SHOW_BY_FILE:
                self.enrich_vpn_communities(filename, objs)

        self.progress.log("Phase 3/6: policy packages, rulebases, NAT, threat, HTTPS")
        self.export_policies()

        self.progress.log("Phase 4/6: threat profile enrichment + exception rulebases")
        self.enrich_threat_profiles()
        self.export_threat_exceptions()

        if self.resolve_referenced:
            self.progress.log("Phase 5/6: referenced object resolution (show-object)")
            self.export_referenced_objects()
        else:
            self.progress.log("Phase 5/6: referenced resolution skipped (--no-resolve-referenced)")

        if self.where_used:
            self.progress.log("Phase 6/6: native where-used reverse references")
            self.export_where_used()
        else:
            self.progress.log("Phase 6/6: where-used skipped (--where-used to enable)")

        self.progress.log("Writing summary / capability CSVs")
        self.write_summary_csv()
        self.write_capability_csv()
        self.prefetch_cve_intel(gateways)
        zip_path = self.create_zip()

        if self.verify_export and self.audit_script.exists():
            self.progress.log("Verifying export completeness ...")
            audit_dir = self.run_dir / "audit"
            audit_dir.mkdir(exist_ok=True)
            import subprocess
            proc = subprocess.run(
                [sys.executable, str(self.audit_script), str(self.run_dir), "--output", str(audit_dir)],
                capture_output=True, text=True, timeout=300,
            )
            if proc.returncode != 0:
                self.progress.log("Audit script failed: {}".format(proc.stderr[:200]))
            else:
                self.progress.log("Audit report written to {}/audit".format(self.run_dir.name))
                # Count critical flags from the generated CSV for a summary line.
                flags_csv = audit_dir / "audit-flags.csv"
                if flags_csv.exists():
                    critical = 0
                    with flags_csv.open(newline="", encoding="utf-8") as f:
                        for row in csv.DictReader(f):
                            if row.get("severity") == "critical":
                                critical += 1
                    if critical:
                        self.progress.log("WARNING: {} critical export issue(s) detected".format(critical))
                    else:
                        self.progress.log("Export verification passed (no critical issues)")

        ok = sum(1 for r in self.summary_rows if r["status"] == "ok")
        skipped = sum(1 for r in self.summary_rows if r["status"] == "skipped")
        errors = sum(1 for r in self.summary_rows if r["status"] == "error")
        self.progress.log("COMPLETE in {} — {} ok, {} skipped, {} error".format(
            self.progress.elapsed(), ok, skipped, errors))
        print("\nDone{}. Send this file to ValeronLabs:".format(
            " (domain '{}')".format(label) if label else ""))
        print("  {}".format(zip_path))
        print("  Datasets: {} ok, {} skipped (version), {} error".format(ok, skipped, errors))
        print("  Total time: {}".format(self.progress.elapsed()))
        return 0



def main():
    parser = argparse.ArgumentParser(
        description="ValeronLabs Check Point Management API collector — Revision 2 (read-only)")
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(__version__))
    parser.add_argument("--mgmt-ip", required=True, help="Management server IP or hostname")
    parser.add_argument("--username", required=True, help="API username")
    parser.add_argument("--password", required=True, help="API password")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help="Management API port (default: {})".format(DEFAULT_PORT))
    parser.add_argument("--output", default=".",
                        help="Directory where run-* folder and zip are created (default: .)")
    parser.add_argument("--domain", default=None, help="Multi-Domain: collect ONE named MDS domain/CMA (optional)")
    parser.add_argument("--all-domains", action="store_true",
                        help="Multi-Domain: auto-enumerate every CMA/domain on the MDS and "
                             "collect each into its own run folder (ignored on a single-domain SMS)")
    parser.add_argument("--where-used", action="store_true",
                        help="Run native where-used per object (slower; ground-truth references)")
    parser.add_argument("--full-objects", action="store_true",
                        help="Pull hosts/networks/ranges at full detail (object NAT + group membership; slower)")
    parser.add_argument("--no-resolve-referenced", action="store_true",
                        help="Skip show-object pass for UIDs referenced in groups/rules but missing from bulk exports")
    parser.add_argument("--read-write", action="store_true",
                        help="Log in read-write (NOT recommended; default is safe read-only)")
    parser.add_argument("--ca-cert", default=None,
                        help="Path to a CA bundle to verify the mgmt TLS cert "
                             "(default: skip verification for self-signed CP certs)")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY", ""),
                        help="Optional NVD API key (or NVD_API_KEY env) for the CVE-intel "
                             "pre-fetch — raises the NVD rate limit from 5 to 50 req/30s.")
    parser.add_argument("--verify-export", action="store_true",
                        help="Run export-quality audit after collection and warn on critical issues")
    args = parser.parse_args()

    verify = args.ca_cert if args.ca_cert else False
    if verify is False:
        print("  NOTE: TLS certificate verification is OFF (typical for self-signed "
              "Check Point mgmt certs). Pass --ca-cert <bundle> to verify.")

    collector = CheckpointCollector(
        args.mgmt_ip, args.port, args.username, args.password, args.output,
        domain=args.domain, all_domains=args.all_domains, read_only=not args.read_write,
        where_used=args.where_used,
        full_objects=args.full_objects, resolve_referenced=not args.no_resolve_referenced,
        verify=verify, nvd_api_key=args.nvd_api_key,
        verify_export=args.verify_export)
    sys.exit(collector.run())


if __name__ == "__main__":
    main()
