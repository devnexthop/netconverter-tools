#!/usr/bin/env python3
"""
NetConverter - Panorama Export Script

Exports a Panorama device-group and/or template via the PAN-OS XML API and
writes the result to a standalone XML file. Use it to:

  * snapshot Panorama state for backup or audit
  * diff two Panorama states (export before + after a change)
  * seed a test/dev Panorama with a known-good DG + template
  * round-trip with `panorama_import.py` (export -> import on another box)

The output XML shape mirrors what `panorama_import.py` consumes, so the two
tools are bidirectional companions:

    <?xml version="1.0"?>
    <config>
      <devices>
        <entry name="localhost.localdomain">
          <device-group>
            <entry name="DG_NAME">...</entry>
          </device-group>
          <template>
            <entry name="TMPL_NAME">...</entry>
          </template>
        </entry>
      </devices>
    </config>

Requirements: Python 3.8+, requests (pip install requests)

Usage:
    # API key auth, single DG + single template
    python3 panorama_export.py --panorama 10.1.1.50 \\
        --device-group DG_BRANCH --template TMPL_BRANCH \\
        --api-key LUFRPT1... --output branch_snapshot.xml

    # Username + password (key fetched via type=keygen)
    python3 panorama_export.py --panorama panorama.company.com \\
        --device-group DG_BRANCH --user admin

    # Multiple device-groups + multiple templates
    python3 panorama_export.py --panorama 10.1.1.50 --api-key K... \\
        --device-group DG_A --device-group DG_B \\
        --template TMPL_A --template TMPL_B

    # Export every device-group and every template
    python3 panorama_export.py --panorama 10.1.1.50 --api-key K... \\
        --all-device-groups --all-templates

    # Self-signed lab cert
    python3 panorama_export.py --panorama 10.1.1.50 --api-key K... \\
        --device-group DG_BRANCH --insecure

License: MIT
"""

__version__ = "1.7.2"

import argparse
import re
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from copy import deepcopy
from getpass import getpass
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from panorama_hierarchy import hierarchy_coverage, hierarchy_metadata, preserve_hierarchy

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


PANORAMA_BASE_XPATH = "/config/devices/entry[@name='localhost.localdomain']"
DEVICE_GROUP_PARENT_XPATH = f"{PANORAMA_BASE_XPATH}/device-group"
TEMPLATE_PARENT_XPATH = f"{PANORAMA_BASE_XPATH}/template"
TEMPLATE_STACK_PARENT_XPATH = f"{PANORAMA_BASE_XPATH}/template-stack"
SHARED_XPATH = "/config/shared"
HIERARCHY_XPATH = "/config/readonly/devices/entry[@name='localhost.localdomain']/device-group"

# Per-branch fetch ceiling. A branch that exists but has nothing configured
# can hang rather than answering empty (observed live on log-collector-group),
# so optional branches get a bounded, non-retrying fetch.
BRANCH_TIMEOUT_S = 25
# `show devices all` is the ONLY source of hostnames in a snapshot, so it is
# the one operational call worth retrying hard.
MANAGED_DEVICE_ATTEMPTS = 4
# The completeness audit pulls the entire /config tree — tens of MB.
AUDIT_TIMEOUT_S = 240

# Branches under /config/devices/entry[...] that are fetched whole (not
# enumerated entry-by-entry). device-group and template are handled separately
# because they support per-name selection; these do not.
#
# Discovered 2026-08-22 against a real 12-firewall Panorama: the exporter was
# fetching only device-group + template, i.e. 2 of the 8 branches that exist
# under devices/entry, and none of the 5 top-level branches. On that box the
# omission hid 481 of 637 address objects, all 7 profile-groups and all 12
# template stacks. See CHANGELOG 1.5.0.
DEVICE_SUB_BRANCHES = (
    "deviceconfig",
    "log-collector",
    "log-collector-group",
    "plugins",
    "platform",
)

# Top-level /config branches fetched whole.
TOP_LEVEL_BRANCHES = (
    "panorama",
)

# Opt-in only.
#   predefined  — vendor-static (apps/services/threats), tens of MB, identical
#                 on every box of the same PAN-OS version. Useful for App-ID
#                 mapping work, useless in a per-customer snapshot.
#   mgt-config  — administrator accounts, role assignments and PASSWORD HASHES.
#                 Never collected by default; a policy snapshot has no need for
#                 it and a customer handoff should not carry it.
OPTIONAL_TOP_LEVEL = {
    "predefined": "--include-predefined",
    "mgt-config": "--include-mgt-config",
}



def _redact(text) -> str:
    """Strip API keys and passwords out of anything we print.

    requests puts the full request URL into its exception text, and our URLs
    carry `key=<api key>` — so an ordinary connection timeout printed the
    customer's Panorama API key in clear. Observed live 2026-08-22 during a site
    network upgrade. Collector output gets pasted into engagement notes and
    tickets, so this is a credential-disclosure bug, not a cosmetic one.
    """
    out = str(text)
    out = re.sub(r"(key=)[A-Za-z0-9%+/=_-]{16,}", r"\1<REDACTED>", out)
    out = re.sub(r"(password=)[^&\s]+", r"\1<REDACTED>", out)
    out = re.sub(r"(<key>)[^<]+(</key>)", r"\1<REDACTED>\2", out)
    return out


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def keygen(host, username, password, verify_ssl=True):
    """Authenticate to Panorama and return XML API key via type=keygen."""
    url = f"https://{host}/api/"
    try:
        resp = requests.post(
            url,
            data={"type": "keygen", "user": username, "password": password},
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as e:
        print(f"AUTH FAILED: cannot reach {host}: {_redact(e)}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"AUTH FAILED: {resp.status_code} {_redact(resp.text[:200])}")
        sys.exit(1)

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as e:
        print(f"AUTH FAILED: cannot parse XML response: {e}")
        sys.exit(1)

    if root.get("status") != "success":
        msg = _redact(root.findtext(".//msg") or resp.text[:200])
        print(f"AUTH FAILED: {msg}")
        sys.exit(1)

    key_elem = root.find(".//key")
    if key_elem is None or not key_elem.text:
        print("AUTH FAILED: no key in response")
        sys.exit(1)

    return key_elem.text.strip()


def get_system_info(host, api_key, verify_ssl=True):
    """Fetch system info to verify the API key and report PAN-OS version."""
    url = f"https://{host}/api/"
    try:
        resp = requests.get(
            url,
            params={
                "type": "op",
                "cmd": "<show><system><info/></system></show>",
                "key": api_key,
            },
            verify=verify_ssl,
            timeout=30,
        )
    except requests.exceptions.RequestException as e:
        print(f"WARN: cannot fetch system info: {_redact(e)}")
        return None, None

    if resp.status_code != 200:
        return None, None

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        return None, None

    hostname = root.findtext(".//system/hostname")
    sw_version = root.findtext(".//system/sw-version")
    return hostname, sw_version


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

def get_with_retry(host, api_key, xpath, verify_ssl=True, timeout=60,
                   retry=True):
    """GET an action=get config call. Retries once on 5xx with 2s backoff.

    Returns (ok: bool, status_code: int, root_elem_or_none, message: str).
    On success root_elem is the <response> ElementTree root; on failure it is
    None. 4xx errors are returned without retry so the caller can log + skip.
    """
    url = f"https://{host}/api/"
    params = {
        "type": "config",
        "action": "get",
        "xpath": xpath,
        "key": api_key,
    }

    for attempt in (1, 2):
        try:
            resp = requests.get(
                url, params=params, verify=verify_ssl, timeout=timeout
            )
        except requests.exceptions.RequestException as e:
            if attempt == 1 and retry:
                time.sleep(2)
                continue
            return False, 0, None, f"request error: {_redact(e)}"

        if resp.status_code >= 500 and attempt == 1 and retry:
            time.sleep(2)
            continue

        if resp.status_code >= 400:
            try:
                root = ET.fromstring(resp.text)
                msg = _redact(root.findtext(".//msg") or resp.text[:160])
            except ET.ParseError:
                msg = _redact(resp.text[:160])
            return False, resp.status_code, None, msg

        # 200 OK -- still inspect status= attribute on response body
        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            return False, resp.status_code, None, f"XML parse error: {e}"

        if root.get("status") == "success":
            return True, resp.status_code, root, "success"

        msg = root.findtext(".//msg") or "unknown error"
        return False, resp.status_code, None, msg

    return False, 0, None, "exhausted retries"


def list_child_entry_names(host, api_key, parent_xpath, verify_ssl=True):
    """Return sorted list of <entry name=""> children under parent_xpath.

    Uses a name-list-only fetch (no recursion into entry bodies) to keep the
    enumeration cheap. Returns [] on failure (with a printed warning).
    """
    ok, code, root, msg = get_with_retry(
        host, api_key, parent_xpath, verify_ssl
    )
    if not ok or root is None:
        print(f"  WARN: cannot enumerate {parent_xpath}: HTTP {code} -- {msg[:120]}")
        return []
    # Walk down into the response body. PAN-OS wraps the requested xpath
    # under <response><result>...</result></response> with the leaf element
    # at any depth (depends on the xpath).
    result_elem = root.find("./result")
    if result_elem is None:
        return []
    # Find the parent container (device-group or template) — its <entry>
    # children are what we want.
    names = []
    # Case 1: result has direct <entry> children (when xpath ended at a
    # parent like .../device-group)
    for entry in result_elem.findall("./entry"):
        n = entry.get("name")
        if n:
            names.append(n)
    if names:
        return sorted(names)
    # Case 2: result wraps the parent container element (e.g.
    # <result><device-group><entry name="..."/></device-group></result>)
    for child in result_elem:
        for entry in child.findall("./entry"):
            n = entry.get("name")
            if n:
                names.append(n)
    return sorted(names)


def fetch_entry(host, api_key, parent_xpath, entry_name, kind,
                include_children=True, verify_ssl=True):
    """Fetch a single <entry name=NAME> element and return its ET.Element.

    kind is "device-group" or "template" -- used for log labels only.
    Returns the <entry> Element (with all children) on success, None on
    failure (4xx skip, 5xx retried once already).
    """
    if include_children:
        xpath = f"{parent_xpath}/entry[@name='{entry_name}']"
    else:
        # Name-only stub. Useful for diff baselines but rare in practice;
        # PAN-OS still returns the full element so we tag it as "stub" by
        # stripping children after retrieval.
        xpath = f"{parent_xpath}/entry[@name='{entry_name}']"

    ok, code, root, msg = get_with_retry(host, api_key, xpath, verify_ssl)
    if not ok or root is None:
        print(f"    FAIL {kind} {entry_name}: HTTP {code} -- {msg[:160]}")
        return None

    # Locate the <entry> element. PAN-OS may return it nested under <result>
    # directly or wrapped under <result><device-group><entry/>...
    result_elem = root.find("./result")
    if result_elem is None:
        print(f"    FAIL {kind} {entry_name}: empty <result> in response")
        return None

    entry = result_elem.find(f"./entry[@name='{entry_name}']")
    if entry is None:
        # Try nested
        for child in result_elem:
            entry = child.find(f"./entry[@name='{entry_name}']")
            if entry is not None:
                break

    if entry is None:
        print(f"    FAIL {kind} {entry_name}: entry not found in response body")
        return None

    if not include_children:
        # Strip children — leave only <entry name="..."/>
        for child in list(entry):
            entry.remove(child)

    return entry


def fetch_branch(host, api_key, xpath, label, verify_ssl=True):
    """Fetch one whole config branch and return its top Element, or None.

    Unlike fetch_entry() this does not enumerate <entry> children — the branch
    is taken wholesale. A branch that simply does not exist on this Panorama
    (no log collectors configured, for example) is NOT an error: PAN-OS
    answers status="success" with an empty <result/>, and we return None so
    the caller records it as absent rather than failed.
    """
    ok, code, root, msg = get_with_retry(
        host, api_key, xpath, verify_ssl, timeout=BRANCH_TIMEOUT_S, retry=False
    )
    if not ok or root is None:
        if "request error" in msg:
            print(f"    {label}: no response in {BRANCH_TIMEOUT_S}s — treating "
                  f"as absent (a branch with nothing configured can hang)")
        else:
            print(f"    FAIL {label}: HTTP {code} -- {msg[:160]}")
        return None

    result_elem = root.find("./result")
    if result_elem is None or len(result_elem) == 0:
        print(f"    {label}: absent on this Panorama (empty result)")
        return None

    # PAN-OS returns <result><shared>...</shared></result> — the branch element
    # itself is the single child. Take it so we can re-parent it cleanly.
    leaf = result_elem.find(f"./{xpath.rstrip('/').split('/')[-1].split('[')[0]}")
    if leaf is None:
        # Fall back to the first element child.
        children = list(result_elem)
        leaf = children[0] if children else None
    if leaf is None:
        print(f"    {label}: absent on this Panorama (no branch element)")
        return None

    n = len(leaf)
    print(f"    OK {label}: {n} child element{'' if n == 1 else 's'}")
    return leaf


def fetch_running_config(host, api_key, verify_ssl=True, timeout=300):
    """Pull the ENTIRE running config in one request.

    `type=export&category=configuration` returns the whole tree in a single
    call. Measured on a real 12-firewall estate: 1.5 MB in 2.1 seconds, versus
    roughly 50 separate per-entry fetches for the same content.

    That difference stops being an optimisation and becomes correctness on a
    degraded link. Observed live 2026-08-22 during a site network upgrade: the
    per-entry path was averaging one connection failure per two device groups
    and would have produced a partial snapshot, while this single call succeeded
    first time. One request has one chance to fail; fifty have fifty.

    Minimal authoritative hierarchy is preserved first. Two branches are then
    stripped from the result before it is written:
      readonly   — PAN-OS mirrors the whole devices/entry subtree here, which
                   double-counts every device group, template and stack (42/54/24
                   instead of 21/27/12) for any consumer that does not dedupe.
      mgt-config — administrator accounts and password hashes; a policy snapshot
                   has no need for them and a customer handoff must not carry
                   them. Kept only with --include-mgt-config.
    """
    url = f"https://{host}/api/"
    try:
        resp = requests.get(
            url,
            params={"type": "export", "category": "configuration", "key": api_key},
            verify=verify_ssl,
            timeout=timeout,
        )
    except requests.exceptions.RequestException as e:
        print(f"  FAILED to fetch running config: {_redact(e)}")
        return None

    if resp.status_code != 200:
        print(f"  FAILED to fetch running config: HTTP {resp.status_code}")
        return None

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as e:
        print(f"  FAILED to parse running config: {e}")
        return None

    cfg = root if root.tag == "config" else root.find(".//config")
    if cfg is None:
        print("  FAILED: no <config> element in the export")
        return None
    print(f"  OK: {len(resp.text):,} bytes in one request")
    return cfg


def strip_branches(cfg, keep_mgt_config=False, config_store="unknown"):
    """Preserve authoritative ancestry before removing mirrors/admin settings."""
    coverage = preserve_hierarchy(cfg, source="native-config", config_store=config_store,
        observed_at=datetime.now(timezone.utc).isoformat())
    cfg.find("nc-device-group-hierarchy").set("collector-version", __version__)
    if not coverage["complete"]:
        print("  INCOMPLETE hierarchy: " + "; ".join(coverage["errors"]))
    removed = []
    for tag in ("readonly",) + (() if keep_mgt_config else ("mgt-config",)):
        for child in list(cfg):
            if child.tag == tag:
                cfg.remove(child)
                removed.append(tag)
    return removed


def fetch_hierarchy(host, api_key, verify_ssl=True):
    """Capture candidate hierarchy using the same action=get store as entries.

    This deliberately does not substitute the operational running hierarchy
    when the candidate metadata request is unavailable. Multi-request capture
    remains non-atomic, and failed/empty metadata never asserts a flat estate.
    """
    observed = datetime.now(timezone.utc).isoformat()
    ok, code, response, message = get_with_retry(host, api_key, HIERARCHY_XPATH,
        verify_ssl, timeout=BRANCH_TIMEOUT_S, retry=False)
    entries = []
    if ok and response is not None:
        result = response.find("./result")
        if result is not None:
            entries = list(result.findall("./entry")) or list(result.findall("./device-group/entry"))
    proxy = ET.Element("config")
    groups = ET.SubElement(ET.SubElement(ET.SubElement(proxy, "devices"), "entry", {"name": "localhost.localdomain"}), "device-group")
    readonly = ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(proxy, "readonly"), "devices"), "entry", {"name": "localhost.localdomain"}), "device-group")
    for entry in entries:
        name = entry.get("name", "")
        ET.SubElement(groups, "entry", {"name": name})
        assertion = ET.SubElement(readonly, "entry", {"name": name})
        for link in entry.findall("parent-dg"):
            assertion.append(deepcopy(link))
    coverage = hierarchy_coverage(proxy)
    if not ok or not entries:
        coverage["complete"] = False
        coverage["status"] = "incomplete"
        coverage["errors"].append("Candidate hierarchy request failed or returned no identities: HTTP " + str(code) + " " + _redact(message)[:160])
    import hashlib
    metadata = hierarchy_metadata(coverage, source="candidate-config-api", config_store="candidate",
        observed_at=observed, source_tree_sha256=hashlib.sha256(ET.tostring(proxy, encoding="utf-8")).hexdigest())
    metadata.set("collection-consistency", "multi-request-not-atomic")
    metadata.set("collector-version", __version__)
    print("  hierarchy: " + coverage["status"] + " (" + str(len(coverage["parents"])) + " assertions)")
    return metadata


def fetch_managed_devices(host, api_key, verify_ssl=True,
                          attempts=MANAGED_DEVICE_ATTEMPTS):
    """Fetch operational facts for every managed firewall via `show devices all`.

    Hostname, model, HA state and connection status are OPERATIONAL data — they
    exist only at runtime and appear nowhere in the config, which is why the
    Managed Firewalls page rendered every hostname as an em dash before 1.5.0.
    Returned as an <nc-managed-devices> element so it is unmistakably ours and
    never confused with a config branch.

    RETRIED WITH BACKOFF, unlike the rest of the operational surface, because
    this single request is the sole source of every hostname in the snapshot:
    lose it and a complete config still renders a table of blank device names.
    Observed live 2026-08-22 on a degraded customer link — it timed out once and
    succeeded on the very next attempt, while config branch fetches around it
    were already retrying. One-shot here was simply backwards.

    Returns None only after every attempt fails; a snapshot without it is
    degraded, not invalid, so the caller warns rather than aborting.
    """
    url = f"https://{host}/api/"
    params = {
        "type": "op",
        "cmd": "<show><devices><all></all></devices></show>",
        "key": api_key,
    }
    last = ""
    for attempt in range(1, attempts + 1):
        try:
            resp = requests.get(url, params=params, verify=verify_ssl, timeout=90)
        except requests.exceptions.RequestException as e:
            last = _redact(e)
            resp = None
        if resp is not None and resp.status_code == 200:
            try:
                root = ET.fromstring(resp.text)
            except ET.ParseError as e:
                last = f"XML parse error: {e}"
            else:
                if root.findall(".//devices/entry"):
                    if attempt > 1:
                        print(f"    (recovered on attempt {attempt})")
                    break
                # A well-formed answer with no devices is a real answer, not a
                # transport failure — do not burn retries on it.
                print("    managed devices: none reported")
                return None
        elif resp is not None:
            last = f"HTTP {resp.status_code}"
        if attempt < attempts:
            delay = 2 ** (attempt - 1)  # 1s, 2s, 4s
            print(f"    managed devices attempt {attempt}/{attempts} failed "
                  f"({last[:80]}) — retrying in {delay}s")
            time.sleep(delay)
    else:
        print(f"    WARN managed devices: all {attempts} attempts failed "
              f"({last[:120]})")
        print(f"    The snapshot will have NO hostnames, models or HA state. "
              f"Re-run to fill them in.")
        return None

    entries = root.findall(".//devices/entry")
    if not entries:
        print("    managed devices: none reported")
        return None

    out = ET.Element("nc-managed-devices")
    connected = 0
    for e in entries:
        dev = ET.SubElement(out, "entry")
        serial = e.findtext("serial") or ""
        if serial:
            dev.set("name", serial)
        for tag in (
            "serial", "hostname", "ip-address", "model", "sw-version",
            "app-version", "threat-version", "connected", "unsupported-version",
            "multi-vsys", "operational-mode", "uptime", "family",
        ):
            val = e.findtext(tag)
            if val:
                ET.SubElement(dev, tag).text = val
        ha = e.find("ha")
        if ha is not None:
            ha_out = ET.SubElement(dev, "ha")
            for tag in ("state", "peer-serial", "priority"):
                v = ha.findtext(tag)
                if v:
                    ET.SubElement(ha_out, tag).text = v
        if (e.findtext("connected") or "").strip().lower() == "yes":
            connected += 1

    print(f"    OK managed devices: {len(entries)} device(s), {connected} connected")
    return out


# ---------------------------------------------------------------------------
# XML assembly
# ---------------------------------------------------------------------------

def build_export_root(dg_entries, tmpl_entries, stack_entries=None,
                      shared_elem=None, device_branches=None,
                      top_branches=None, managed_devices=None, hierarchy=None):
    """Assemble the round-trip-compatible <config> XML root.

    Shape mirrors what panorama_import.py consumes:
        <config>
          <devices>
            <entry name="localhost.localdomain">
              <device-group>
                <entry name="DG_NAME">...</entry>
              </device-group>
              <template>
                <entry name="TMPL_NAME">...</entry>
              </template>
            </entry>
          </devices>
        </config>

    The root is <config> (not <root>) to match panorama_import.py's
    `root.tag != 'config'` validation guard.
    """
    config = ET.Element("config")
    devices = ET.SubElement(config, "devices")
    host_entry = ET.SubElement(devices, "entry", {"name": "localhost.localdomain"})

    # deviceconfig first — PAN-OS puts it first and the HTML model reads the
    # Panorama hostname from deviceconfig/system/hostname.
    for branch_name in ("deviceconfig",):
        elem = (device_branches or {}).get(branch_name)
        if elem is not None:
            host_entry.append(elem)

    if dg_entries:
        dg_parent = ET.SubElement(host_entry, "device-group")
        for entry in dg_entries:
            dg_parent.append(entry)

    if tmpl_entries:
        tmpl_parent = ET.SubElement(host_entry, "template")
        for entry in tmpl_entries:
            tmpl_parent.append(entry)

    if stack_entries:
        stack_parent = ET.SubElement(host_entry, "template-stack")
        for entry in stack_entries:
            stack_parent.append(entry)

    for branch_name in DEVICE_SUB_BRANCHES:
        if branch_name == "deviceconfig":
            continue  # already placed above
        elem = (device_branches or {}).get(branch_name)
        if elem is not None:
            host_entry.append(elem)

    # <shared> is a sibling of <devices>, matching PAN-OS's own layout.
    if shared_elem is not None:
        config.append(shared_elem)

    for branch_name, elem in (top_branches or {}).items():
        if elem is not None:
            config.append(elem)

    # Operational facts, clearly namespaced so no importer mistakes them for
    # config. panorama_import.py addresses device-group/template by xpath and
    # never walks unknown siblings, so this is inert on the round trip.
    if managed_devices is not None:
        config.append(managed_devices)

    if hierarchy is not None:
        config.append(deepcopy(hierarchy))
    else:
        preserve_hierarchy(config, source="per-entry-without-hierarchy", config_store="candidate")

    return config


def audit_completeness(host, api_key, collected_top, collected_device,
                       verify_ssl=True, return_status=False):
    """Compare what we collected against what this Panorama actually has.

    This is the guard that makes the collector safe to point at a customer we
    have never seen. Before 1.5.0 an unfetched branch was invisible — the
    snapshot simply lacked it, the HTML rendered an empty page, and nobody
    could tell the difference between "the customer has none" and "we never
    asked". This enumerates the real /config tree and reports anything present
    on the box but missing from our snapshot.

    Returns (missing_top, missing_device) — two lists of branch names.
    Deliberately does NOT fail the export: a new PAN-OS release inventing a
    branch should produce a loud warning, not a broken collection.
    """
    missing_top, missing_device = [], []
    status = "unverified"

    ok, _, root, _ = get_with_retry(
        host, api_key, "/config", verify_ssl,
        timeout=AUDIT_TIMEOUT_S, retry=False,
    )
    if ok and root is not None:
        cfg = root.find("./result/config")
        if cfg is not None:
            status = "verified"
            for child in cfg:
                if child.tag in ("devices", "readonly"):
                    continue
                if child.tag in OPTIONAL_TOP_LEVEL:
                    continue  # opt-in by design, not an accidental omission
                if child.tag not in collected_top:
                    missing_top.append(child.tag)

            dev_entry = cfg.find("./devices/entry")
            if dev_entry is not None:
                known = set(collected_device) | {"device-group", "template",
                                                 "template-stack"}
                for child in dev_entry:
                    if child.tag not in known:
                        missing_device.append(child.tag)

    result = (missing_top, missing_device)
    return result + (status,) if return_status else result


def write_xml_file(root_elem, output_path):
    """Write root_elem to output_path with XML declaration + pretty indent."""
    # Pretty-print via ET.indent (Python 3.9+). Fall back to no-indent for 3.8.
    try:
        ET.indent(root_elem, space="  ")
    except AttributeError:
        pass
    tree = ET.ElementTree(root_elem)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_bool(val):
    """Parse a 'true'/'false' string into a bool (case-insensitive)."""
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in ("1", "true", "yes", "y", "on")


def main():
    parser = argparse.ArgumentParser(
        description="NetConverter -- Export Panorama device-group(s) and "
                    "template(s) to a standalone XML file via PAN-OS XML API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  python3 panorama_export.py --panorama 10.1.1.50 "
            "--device-group DG_BRANCH --template TMPL_BRANCH "
            "--api-key LUFRPT1... --output snapshot.xml\n"
            "  python3 panorama_export.py --panorama 10.1.1.50 "
            "--all-device-groups --all-templates --user admin\n"
        ),
    )
    parser.add_argument("--panorama", required=True,
                        help="Panorama hostname or IP")
    parser.add_argument("--device-group", action="append", default=[],
                        help="Device-group to export (repeat flag for "
                             "multiple). Mutually exclusive with "
                             "--all-device-groups.")
    parser.add_argument("--all-device-groups", action="store_true",
                        help="Export every device-group on the Panorama")
    parser.add_argument("--template", action="append", default=[],
                        help="Template to export (repeat flag for multiple). "
                             "Mutually exclusive with --all-templates.")
    parser.add_argument("--all-templates", action="store_true",
                        help="Export every template on the Panorama")
    parser.add_argument("--output",
                        help="Output XML file path "
                             "(default: panorama_export_{host}_{timestamp}.xml)")
    parser.add_argument("--include-children", default="true",
                        help="Recurse into entry children (true|false). "
                             "Default true. False produces name-only stubs.")
    parser.add_argument("--user",
                        help="Panorama username (used to fetch API key via "
                             "type=keygen). Required if --api-key is not given.")
    parser.add_argument("--password",
                        help="Panorama password (prompted if --user is given "
                             "without --password). Or set PANORAMA_PASSWORD env var.")
    parser.add_argument("--api-key",
                        help="Panorama XML API key. Or set PANORAMA_API_KEY env var. "
                             "Skips username/password auth.")
    parser.add_argument("--no-shared", action="store_true",
                        help="Skip /config/shared. Not recommended — on a real "
                             "Panorama most objects live here.")
    parser.add_argument("--no-template-stacks", action="store_true",
                        help="Skip template stacks.")
    parser.add_argument("--no-managed-devices", action="store_true",
                        help="Skip the `show devices all` operational fetch "
                             "(hostname / model / HA state).")
    parser.add_argument("--include-predefined", action="store_true",
                        help="Also collect /config/predefined (vendor-static "
                             "apps/services/threats; large, rarely needed).")
    parser.add_argument("--include-mgt-config", action="store_true",
                        help="Also collect /config/mgt-config. WARNING: this "
                             "contains administrator accounts and password "
                             "hashes. Off by default.")
    parser.add_argument("--running-config", action="store_true",
                        help="Pull the whole running config in ONE request "
                             "(type=export) instead of fetching each device "
                             "group and template separately. Far more robust on "
                             "a slow or flaky link; hierarchy is validated before use. "
                             "Ignores --device-group/--template selection.")
    parser.add_argument("--no-audit", action="store_true",
                        help="Skip the completeness audit (which pulls the "
                             "full /config tree to verify nothing was missed).")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable HTTPS certificate verification "
                             "(for self-signed lab certs)")
    args = parser.parse_args()

    verify_ssl = not args.insecure
    include_children = parse_bool(args.include_children)

    # Validate selection: must export at least one DG or template
    if (not args.running_config
            and not args.device_group and not args.all_device_groups
            and not args.template and not args.all_templates):
        print("ERROR: must specify at least one of --device-group, "
              "--all-device-groups, --template, --all-templates")
        sys.exit(1)

    if args.device_group and args.all_device_groups:
        print("ERROR: --device-group and --all-device-groups are mutually exclusive")
        sys.exit(1)
    if args.template and args.all_templates:
        print("ERROR: --template and --all-templates are mutually exclusive")
        sys.exit(1)

    # Resolve API key (env var > CLI > username/password keygen)
    api_key = args.api_key or os.environ.get("PANORAMA_API_KEY")
    if not api_key:
        if not args.user:
            print("ERROR: must provide --api-key, PANORAMA_API_KEY env var, "
                  "or --user (with password)")
            sys.exit(1)
        password = (
            args.password
            or os.environ.get("PANORAMA_PASSWORD")
            or getpass(f"Password for {args.user}@{args.panorama}: ")
        )
        print(f"\nAuthenticating to {args.panorama}...")
        api_key = keygen(args.panorama, args.user, password, verify_ssl)
        print(f"  Authenticated. API key acquired.")

    # Default output path
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Sanitize host for filename (strip protocol, slashes, colons)
        safe_host = (args.panorama
                     .replace("https://", "")
                     .replace("http://", "")
                     .replace("/", "_")
                     .replace(":", "_"))
        args.output = f"panorama_export_{safe_host}_{timestamp}.xml"

    # Banner
    print(f"\nNetConverter Panorama Export")
    print(f"{'=' * 60}")
    print(f"Panorama:          {args.panorama}")
    print(f"Output File:       {args.output}")
    print(f"Include Children:  {'yes' if include_children else 'no (stubs only)'}")
    print(f"SSL Verify:        {'on' if verify_ssl else 'OFF (--insecure)'}")
    if args.all_device_groups:
        print(f"Device Groups:     ALL")
    elif args.device_group:
        print(f"Device Groups:     {', '.join(args.device_group)}")
    else:
        print(f"Device Groups:     (none requested)")
    if args.all_templates:
        print(f"Templates:         ALL")
    elif args.template:
        print(f"Templates:         {', '.join(args.template)}")
    else:
        print(f"Templates:         (none requested)")
    print(f"{'=' * 60}")

    # Verify API key works + report PAN-OS version
    try:
        hostname, sw_version = get_system_info(
            args.panorama, api_key, verify_ssl
        )
        if hostname or sw_version:
            print(f"  Connected: {hostname or '?'} (PAN-OS {sw_version or '?'})")
    except Exception as e:
        print(f"WARN: API key verification failed: {e}")

    # ----- Single-request path -------------------------------------------
    if args.running_config:
        print(f"\n--- Fetching entire running config (one request) ---")
        cfg = fetch_running_config(args.panorama, api_key, verify_ssl)
        if cfg is None:
            print(f"\n{'=' * 60}")
            print("ERROR: running-config fetch failed -- nothing written")
            print(f"{'=' * 60}")
            sys.exit(2)
        removed = strip_branches(cfg, keep_mgt_config=args.include_mgt_config, config_store="running")
        if removed:
            print(f"  stripped: {', '.join(sorted(set(removed)))}")
        if not args.no_managed_devices:
            print(f"\n--- Fetching managed device facts (operational) ---")
            md = fetch_managed_devices(args.panorama, api_key, verify_ssl)
            if md is not None:
                cfg.append(md)
        ET.SubElement(cfg, "nc-collection", {"schema": "nc.panorama-collection.v1",
            "collector": "netconverter-palo", "version": __version__, "mode": "running-export",
            "config-store": "running", "configuration-consistency": "single-config-response",
            "completed-at": datetime.now(timezone.utc).isoformat(),
            "hierarchy": hierarchy_coverage(cfg)["status"], "native-content": "full-entries",
            "device-local-coverage": "not-collected"})
        try:
            write_xml_file(cfg, args.output)
        except OSError as e:
            print(f"ERROR: cannot write {args.output}: {e}")
            sys.exit(1)
        try:
            size_bytes = os.path.getsize(args.output)
        except OSError:
            size_bytes = 0
        dgs = {e.get("name") for e in cfg.findall(".//device-group/entry") if e.get("name")}
        tps = {e.get("name") for e in cfg.findall(".//template/entry") if e.get("name")}
        sks = {e.get("name") for e in cfg.findall(".//template-stack/entry") if e.get("name")}
        print(f"\n{'=' * 60}")
        print(f"Export summary (single-request running config)")
        print(f"  device-groups:   {len(dgs)}")
        print(f"  templates:       {len(tps)}")
        print(f"  template-stacks: {len(sks)}")
        sh = cfg.find("./shared")
        print(f"  shared:          {sum(len(c.findall('./entry')) for c in sh) if sh is not None else 0} objects")
        print(f"  branches:        {', '.join(c.tag for c in cfg)}")
        ancestry = hierarchy_coverage(cfg)
        print(f"  hierarchy:       {ancestry['status'].upper()}")
        print("  capture:         single configuration export; device-local/operational completeness is not implied")
        print(f"  output:          {args.output} ({size_bytes:,} bytes)")
        print(f"{'=' * 60}")
        return 0 if ancestry["complete"] else 3

    # ----- Resolve target lists -----
    if args.all_device_groups:
        print(f"\n--- Enumerating device-groups ---")
        dg_names = list_child_entry_names(
            args.panorama, api_key, DEVICE_GROUP_PARENT_XPATH, verify_ssl
        )
        print(f"  Found {len(dg_names)} device-group(s): "
              f"{', '.join(dg_names) if dg_names else '(none)'}")
    else:
        dg_names = list(args.device_group)

    if args.all_templates:
        print(f"\n--- Enumerating templates ---")
        tmpl_names = list_child_entry_names(
            args.panorama, api_key, TEMPLATE_PARENT_XPATH, verify_ssl
        )
        print(f"  Found {len(tmpl_names)} template(s): "
              f"{', '.join(tmpl_names) if tmpl_names else '(none)'}")
    else:
        tmpl_names = list(args.template)

    # ----- Fetch each DG -----
    overall = {"fetched": 0, "skipped": 0, "failed": 0}
    dg_entries = []

    if dg_names:
        print(f"\n--- Fetching device-groups ---")
        for name in dg_names:
            print(f"  device-group: {name}")
            entry = fetch_entry(
                args.panorama, api_key, DEVICE_GROUP_PARENT_XPATH, name,
                "device-group", include_children=include_children,
                verify_ssl=verify_ssl,
            )
            if entry is not None:
                dg_entries.append(entry)
                overall["fetched"] += 1
                # Quick stats: count direct child element types
                child_counts = {}
                for child in entry:
                    child_counts[child.tag] = child_counts.get(child.tag, 0) + 1
                if child_counts:
                    summary = ", ".join(
                        f"{tag}={n}" for tag, n in sorted(child_counts.items())
                    )
                    print(f"    OK: {summary}")
                else:
                    print(f"    OK: (empty)")
            else:
                overall["failed"] += 1

    # ----- Fetch each template -----
    tmpl_entries = []
    if tmpl_names:
        print(f"\n--- Fetching templates ---")
        for name in tmpl_names:
            print(f"  template: {name}")
            entry = fetch_entry(
                args.panorama, api_key, TEMPLATE_PARENT_XPATH, name,
                "template", include_children=include_children,
                verify_ssl=verify_ssl,
            )
            if entry is not None:
                tmpl_entries.append(entry)
                overall["fetched"] += 1
                child_counts = {}
                for child in entry:
                    child_counts[child.tag] = child_counts.get(child.tag, 0) + 1
                if child_counts:
                    summary = ", ".join(
                        f"{tag}={n}" for tag, n in sorted(child_counts.items())
                    )
                    print(f"    OK: {summary}")
                else:
                    print(f"    OK: (empty)")
            else:
                overall["failed"] += 1

    # ----- Fetch template stacks -----
    # Fetched as ONE branch, not entry-by-entry. Measured live 2026-08-22: the
    # whole branch returns in under a second, while per-entry config queries on
    # this Panorama cost ~23s each — 12 stacks that way added ~4.5 minutes for
    # 11 KB of data. Stacks have no per-name selection flag, so there is no
    # reason to enumerate them.
    stack_branch = None
    if not args.no_template_stacks:
        print(f"\n--- Fetching template stacks ---")
        stack_branch = fetch_branch(
            args.panorama, api_key, TEMPLATE_STACK_PARENT_XPATH,
            "template-stack", verify_ssl,
        )
        if stack_branch is not None:
            overall["fetched"] += 1
    stack_entries = list(stack_branch) if stack_branch is not None else []

    # ----- Fetch shared -----
    shared_elem = None
    if not args.no_shared:
        print(f"\n--- Fetching shared objects ---")
        shared_elem = fetch_branch(
            args.panorama, api_key, SHARED_XPATH, "shared", verify_ssl
        )
        if shared_elem is not None:
            overall["fetched"] += 1

    # ----- Fetch remaining device sub-branches + top-level branches -----
    device_branches, top_branches = {}, {}
    print(f"\n--- Fetching remaining config branches ---")
    for branch in DEVICE_SUB_BRANCHES:
        elem = fetch_branch(
            args.panorama, api_key, f"{PANORAMA_BASE_XPATH}/{branch}",
            branch, verify_ssl,
        )
        if elem is not None:
            device_branches[branch] = elem
            overall["fetched"] += 1
    for branch in TOP_LEVEL_BRANCHES:
        elem = fetch_branch(
            args.panorama, api_key, f"/config/{branch}", branch, verify_ssl
        )
        if elem is not None:
            top_branches[branch] = elem
            overall["fetched"] += 1
    for branch, flag in OPTIONAL_TOP_LEVEL.items():
        enabled = getattr(args, flag.lstrip("-").replace("-", "_"), False)
        if not enabled:
            continue
        if branch == "mgt-config":
            print("    NOTE: --include-mgt-config collects administrator "
                  "accounts and PASSWORD HASHES. Do not put this snapshot in "
                  "a customer handoff or a git repo.")
        elem = fetch_branch(
            args.panorama, api_key, f"/config/{branch}", branch, verify_ssl
        )
        if elem is not None:
            top_branches[branch] = elem
            overall["fetched"] += 1

    # ----- Fetch managed-device operational facts -----
    managed_devices = None
    if not args.no_managed_devices:
        print(f"\n--- Fetching managed device facts (operational) ---")
        managed_devices = fetch_managed_devices(
            args.panorama, api_key, verify_ssl
        )

    # ----- Write output XML -----
    # Deliberately BEFORE the completeness audit. The audit pulls the whole
    # /config tree, which on a large Panorama is tens of MB and slow; a slow or
    # failed audit must never cost us a collection we already have in hand.
    if not dg_entries and not tmpl_entries:
        print(f"\n{'=' * 60}")
        print(f"ERROR: nothing was fetched -- skipping output write")
        print(f"{'=' * 60}")
        sys.exit(2)

    print(f"\n--- Writing output XML ---")
    hierarchy = fetch_hierarchy(args.panorama, api_key, verify_ssl)
    root_elem = build_export_root(
        dg_entries, tmpl_entries,
        stack_entries=stack_entries,
        shared_elem=shared_elem,
        device_branches=device_branches,
        top_branches=top_branches,
        managed_devices=managed_devices,
        hierarchy=hierarchy,
    )
    try:
        write_xml_file(root_elem, args.output)
    except OSError as e:
        print(f"ERROR: cannot write {args.output}: {e}")
        sys.exit(1)

    try:
        size_bytes = os.path.getsize(args.output)
    except OSError:
        size_bytes = 0
    print(f"  wrote {args.output} ({size_bytes:,} bytes)")

    # ----- Completeness audit -----
    # Two independent questions, both of which have to be "yes":
    #   (a) did we ask for every BRANCH this Panorama has?      -> audit_completeness
    #   (b) did every entry we ENUMERATED actually get written? -> the check below
    # (b) exists because a per-entry fetch can fail on a flaky link while every
    # branch is still present, which would otherwise report COMPLETE while
    # silently shipping a snapshot missing device groups. Observed live
    # 2026-08-22: two device-group fetches failed with connection errors during
    # a site network upgrade.
    written_dgs = {e.get("name") for e in dg_entries if e.get("name")}
    written_tmpls = {e.get("name") for e in tmpl_entries if e.get("name")}
    lost_dgs = sorted(set(dg_names) - written_dgs)
    lost_tmpls = sorted(set(tmpl_names) - written_tmpls)
    if lost_dgs or lost_tmpls:
        print(f"\n--- INCOMPLETE COLLECTION ---")
        print(f"  Enumerated on the Panorama but MISSING from the snapshot:")
        for n in lost_dgs:
            print(f"    device-group: {n}")
        for n in lost_tmpls:
            print(f"    template:     {n}")
        print(f"  The snapshot on disk is PARTIAL. Re-run before using it for an")
        print(f"  engagement — a missing device group is missing policy.")

    missing_top, missing_device, audit_status = [], [], "skipped"
    if args.no_audit:
        print(f"\n--- Completeness audit SKIPPED (--no-audit) ---")
    else:
        print(f"\n--- Completeness audit ---")
        print(f"  (pulls the full /config tree to compare — slow on a large "
              f"Panorama; skip with --no-audit)")
        collected_top = set(top_branches) | ({"shared"} if shared_elem is not None else set())
        missing_top, missing_device, audit_status = audit_completeness(
            args.panorama, api_key, collected_top, set(device_branches), verify_ssl, return_status=True
        )
    if missing_top or missing_device:
        print("  INCOMPLETE — branches present on this Panorama but NOT collected:")
        for b in missing_top:
            print(f"    /config/{b}")
        for b in missing_device:
            print(f"    /config/devices/entry/{b}")
        print("  This is a collector gap, not a customer difference. Report it.")
    elif audit_status == "verified":
        print("  COMPLETE — every branch present on this Panorama was collected")
        print("  (excluding opt-in: " + ", ".join(sorted(OPTIONAL_TOP_LEVEL)) + ")")
    else:
        print("  Branch completeness remains UNVERIFIED (audit " + audit_status + ")")

    # ----- Summary -----
    total_attempted = (overall["fetched"] + overall["skipped"]
                       + overall["failed"])
    print(f"\n{'=' * 60}")
    print(f"Export summary: fetched={overall['fetched']}, "
          f"skipped={overall['skipped']}, failed={overall['failed']} "
          f"(attempted={total_attempted})")
    print(f"  device-groups:   {len(dg_entries)} written")
    print(f"  templates:       {len(tmpl_entries)} written")
    print(f"  template-stacks: {len(stack_entries)} written")
    if shared_elem is not None:
        shared_counts = {}
        for child in shared_elem:
            n = len(child.findall("./entry"))
            if n:
                shared_counts[child.tag] = n
        top = ", ".join(f"{k} {v}" for k, v in
                        sorted(shared_counts.items(), key=lambda kv: -kv[1])[:5])
        print(f"  shared:          {sum(shared_counts.values())} objects ({top})")
    else:
        print(f"  shared:          NOT COLLECTED")
    if device_branches or top_branches:
        print(f"  other branches:  "
              f"{', '.join(sorted(list(device_branches) + list(top_branches)))}")
    if managed_devices is not None:
        print(f"  managed devices: {len(managed_devices)} with hostname/model/HA")
    _branch_ok = audit_status == "verified" and not (missing_top or missing_device)
    _entries_ok = include_children and not (lost_dgs or lost_tmpls)
    ancestry = hierarchy_coverage(root_elem)
    if _branch_ok and _entries_ok and ancestry["complete"]:
        _state = "COMPLETE"
    elif not include_children:
        _state = "INCOMPLETE — identity stubs only; native configuration was not requested"
    elif not _entries_ok:
        _state = (f"INCOMPLETE — {len(lost_dgs)} device-group(s) and "
                  f"{len(lost_tmpls)} template(s) FAILED to fetch")
    else:
        _state = "INCOMPLETE / UNVERIFIED — hierarchy or branch evidence missing; see audit above"
    provenance = ET.SubElement(root_elem, "nc-collection", {"schema": "nc.panorama-collection.v1",
        "collector": "netconverter-palo", "version": __version__, "mode": "per-entry",
        "config-store": "candidate", "configuration-consistency": "multi-request-not-atomic",
        "completed-at": datetime.now(timezone.utc).isoformat(), "branch-audit": audit_status,
        "entry-coverage": "captured" if _entries_ok else "partial", "hierarchy": ancestry["status"]})
    provenance.set("native-content", "full-entries" if include_children else "stubs")
    for kind, names in (("device-group", lost_dgs), ("template", lost_tmpls),
                         ("top-branch", missing_top), ("device-branch", missing_device)):
        for name in names:
            ET.SubElement(provenance, "missing", {"kind": kind, "name": name})
    # The first write preserved useful partial output if the audit failed.
    # Persist its actual outcome instead of leaving completeness only in logs.
    write_xml_file(root_elem, args.output)
    print(f"  completeness:    {_state}")
    print(f"  output:          {args.output} ({size_bytes:,} bytes)")
    if total_attempted > 0:
        failure_rate = overall["failed"] / total_attempted
        if failure_rate > 0.20:
            print(f"  WARNING: failure rate {failure_rate:.0%} exceeds 20% threshold")
    print(f"{'=' * 60}")

    if not _entries_ok or missing_top or missing_device or not ancestry["complete"]:
        print(f"\nExiting 3: the snapshot is partial. This is deliberate — a")
        print(f"silently partial collection is how an engagement ships wrong data.")
        sys.exit(3)

    print(f"\nNOTE: round-trip with panorama_import.py:")
    print(f"  python3 panorama_import.py --panorama TARGET --xml {args.output} \\")
    print(f"      --api-key K... --dry-run")
    print(f"{'=' * 60}")

    # Exit non-zero if anything failed (helps CI / scripted runs)
    if overall["failed"] > 0:
        sys.exit(2)


if __name__ == "__main__":
    sys.exit(main())
