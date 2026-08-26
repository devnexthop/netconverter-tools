"""Shared Palo Alto PAN-OS XML snapshot models for read-only HTML reports."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Set, Tuple, Union
from xml.etree import ElementTree as ET

ExportKind = Literal["standalone", "panorama"]

_DG_XPATH = ".//devices/entry/device-group/entry"
_RULEBASE_TAGS = ("pre-rulebase", "post-rulebase", "rulebase")
_OBJ_TAGS = ("address", "address-group", "service", "service-group")

# Panorama's shared namespace. Not a device group: it is the root of object
# resolution that EVERY device group inherits from. Collected since collector
# 1.5.0 as /config/shared, a sibling of <devices>.
SHARED_SCOPE = "Shared"


def _text(elem: ET.Element | None) -> str:
    if elem is None or elem.text is None:
        return ""
    return elem.text.strip()


def members(entry: ET.Element, tag: str) -> List[str]:
    el = entry.find(tag)
    if el is None:
        return []
    return [_text(m) for m in el.findall("member") if _text(m)]


def join_m(entry: ET.Element, tag: str) -> str:
    vals = members(entry, tag)
    return ", ".join(vals) if vals else "any"


def parse_rule_target(entry: ET.Element) -> Tuple[List[str], bool]:
    """Read a Panorama rule <target> block.

    Empty devices list (or missing <target>) means the rule installs on every
    firewall in the device group — the PAN-OS analogue of Check Point
    "Policy Targets". A non-empty list is the analogue of Install On.
    """
    tgt = entry.find("target")
    if tgt is None:
        return [], False
    serials: List[str] = []
    devices = tgt.find("devices")
    if devices is not None:
        for el in devices.findall("entry"):
            name = (el.get("name") or "").strip()
            if name and name not in serials:
                serials.append(name)
        for m in devices.findall("member"):
            name = _text(m)
            if name and name not in serials:
                serials.append(name)
    negate = _text(tgt.find("negate")).lower() in ("yes", "true")
    return serials, negate


def rule_applies_to_serial(rule: dict, serial: str) -> bool:
    """True when this rule is enforced on `serial` (Install-On analogue)."""
    serial = (serial or "").strip()
    if not serial:
        return False
    targets = [str(s).strip() for s in (rule.get("target_serials") or []) if str(s).strip()]
    negate = bool(rule.get("target_negate"))
    if not targets:
        return True
    hit = serial in targets
    return (not hit) if negate else hit


def _stamp_target(row: dict, entry: ET.Element) -> dict:
    serials, negate = parse_rule_target(entry)
    row["target_serials"] = serials
    row["target_negate"] = negate
    return row


def addr_value(entry: ET.Element) -> str:
    for tag in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
        el = entry.find(tag)
        if _text(el):
            return _text(el)
    return ""


def svc_value(entry: ET.Element) -> str:
    for proto in ("tcp", "udp", "sctp"):
        pel = entry.find(f"protocol/{proto}")
        if pel is not None:
            port = pel.find("port")
            if _text(port):
                return f"{proto.upper()} {_text(port)}"
    return ""


def route_identity(dest: str, nexthop: str, iface: str, name: str = "") -> Tuple[str, ...]:
    d, n, i = (dest or "").strip(), (nexthop or "").strip(), (iface or "").strip()
    nm = (name or "").strip()
    if nm:
        return ("named", nm, d, n, i)
    return ("anon", d, n, i)


def dedupe_routes(routes: Iterable[dict]) -> List[dict]:
    seen: Set[Tuple[str, ...]] = set()
    out: List[dict] = []
    for r in routes:
        key = route_identity(r.get("destination", ""), r.get("nexthop", ""), r.get("interface", ""), r.get("name", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _expand_group(name: str, groups: Dict[str, List[str]], seen: Set[str]) -> Set[str]:
    key = name.lower()
    if key in seen:
        return set()
    seen.add(key)
    out = {name}
    for member in groups.get(key, []):
        out.add(member)
        if member.lower() in groups:
            out |= _expand_group(member, groups, seen)
    return out


def _rule_profiles(entry: ET.Element) -> str:
    grp = entry.find("profile-setting/group")
    if grp is not None:
        vals = [_text(m) for m in grp.findall("member") if _text(m)]
        if vals:
            return ", ".join(vals)
    return ""


def _nat_translation(entry: ET.Element, tag: str) -> str:
    root = entry.find(tag)
    if root is None:
        return ""
    for child in root:
        val = _text(child)
        if val:
            return val
        for sub in child.iter():
            if sub is not child and _text(sub):
                return _text(sub)
    return ""


def detect_export_kind(root: ET.Element) -> ExportKind:
    """Classify a PAN-OS XML export as standalone firewall vs Panorama."""
    dg_entries = root.findall(_DG_XPATH)
    pre_rules = root.findall(".//devices/entry/device-group/entry/pre-rulebase/security/rules/entry")
    post_rules = root.findall(".//devices/entry/device-group/entry/post-rulebase/security/rules/entry")
    if dg_entries and (pre_rules or post_rules or root.find(".//panorama") is not None):
        return "panorama"
    vsys_rules = root.findall(".//vsys/entry/rulebase/security/rules/entry")
    if vsys_rules:
        return "standalone"
    if root.findall(".//rulebase/security/rules/entry"):
        return "standalone"
    return "panorama" if dg_entries else "standalone"


def _dg_content_score(dg: ET.Element) -> int:
    score = 0
    for tag in _RULEBASE_TAGS:
        rb = dg.find(tag)
        if rb is None:
            continue
        sec = rb.find("security/rules")
        if sec is not None:
            score += len(sec.findall("entry"))
        nat = rb.find("nat/rules")
        if nat is not None:
            score += len(nat.findall("entry"))
    for tag in _OBJ_TAGS:
        score += len(dg.findall(f"./{tag}/entry"))
    return score


def _collect_device_group_entries(root: ET.Element) -> Dict[str, dict]:
    """Panorama exports duplicate DG entries (content vs hierarchy). Merge by name."""
    by_name: Dict[str, dict] = {}
    for dg in root.findall(_DG_XPATH):
        name = dg.get("name")
        if not name:
            continue
        score = _dg_content_score(dg)
        parent = _text(dg.find("parent-dg"))
        slot = by_name.get(name)
        if slot is None:
            by_name[name] = {"elem": dg, "score": score, "parent": parent}
        else:
            if score > slot["score"]:
                slot["elem"] = dg
                slot["score"] = score
            if parent:
                slot["parent"] = parent
    return by_name


def _template_content_score(tmpl: ET.Element) -> int:
    """Prefer full template bodies over Panorama stub copies (zones with ids only)."""
    score = 0
    score += len(tmpl.findall(".//virtual-router/entry")) * 100
    score += len(tmpl.findall(".//static-route/entry")) * 5
    score += len(_template_vsys_elements(tmpl)) * 2
    for zone in tmpl.findall(".//zone/entry"):
        if zone.find(".//network") is not None or members(zone, "network") or members(zone, "interface"):
            score += 3
        elif zone.find("id") is not None and zone.find("network") is None:
            score += 0
        else:
            score += 1
    score += len(tmpl.findall(".//interface/entry"))
    return score


def _collect_template_entries(root: ET.Element) -> Dict[str, ET.Element]:
    """Panorama exports duplicate template entries (full config vs id-only stubs). Merge by name."""
    by_name: Dict[str, dict] = {}
    for tmpl in root.findall(".//devices/entry/template/entry"):
        name = tmpl.get("name")
        if not name:
            continue
        score = _template_content_score(tmpl)
        slot = by_name.get(name)
        if slot is None or score > slot["score"]:
            by_name[name] = {"elem": tmpl, "score": score}
    return {name: slot["elem"] for name, slot in by_name.items()}


def _collect_template_stack_entries(root: ET.Element) -> Dict[str, dict]:
    """Panorama exports duplicate stack entries (members+devices vs id-only stubs). Merge by name."""
    by_name: Dict[str, dict] = {}
    for ts in root.findall(".//devices/entry/template-stack/entry"):
        name = ts.get("name")
        if not name:
            continue
        tmpl_members = members(ts, "templates")
        devs = ts.findall("./devices/entry")
        score = len(tmpl_members) * 10 + len(devs)
        slot = by_name.get(name)
        if slot is None or score > slot["score"]:
            by_name[name] = {
                "elem": ts,
                "score": score,
                "templates": tmpl_members,
                "devices": devs,
            }
        else:
            if len(tmpl_members) > len(slot["templates"]):
                slot["templates"] = tmpl_members
                slot["elem"] = ts
            if len(devs) > len(slot["devices"]):
                slot["devices"] = devs
    return by_name


def _parse_managed_device_facts(root: ET.Element) -> Dict[str, dict]:
    """Operational facts per serial from <nc-managed-devices>.

    This branch is NOT PAN-OS config — it is the collector's own namespace,
    written from `show devices all` since collector 1.5.0. Hostname, model,
    software version, HA state and connection status live nowhere in the config,
    which is exactly why the Managed Firewalls page rendered em dashes before.
    A pre-1.5.0 snapshot simply has no such element and returns {}.
    """
    facts: Dict[str, dict] = {}
    for entry in root.findall("./nc-managed-devices/entry"):
        serial = _text(entry.find("serial")) or entry.get("name") or ""
        if not serial:
            continue
        ha = entry.find("ha")
        facts[serial] = {
            "serial": serial,
            "op_hostname": _text(entry.find("hostname")),
            "ip_address": _text(entry.find("ip-address")),
            "model": _text(entry.find("model")),
            "sw_version": _text(entry.find("sw-version")),
            "app_version": _text(entry.find("app-version")),
            "threat_version": _text(entry.find("threat-version")),
            "connected": _text(entry.find("connected")),
            "multi_vsys": _text(entry.find("multi-vsys")),
            "operational_mode": _text(entry.find("operational-mode")),
            "uptime": _text(entry.find("uptime")),
            "family": _text(entry.find("family")),
            "ha_state": _text(ha.find("state")) if ha is not None else "",
            "ha_peer": _text(ha.find("peer-serial")) if ha is not None else "",
            "ha_priority": _text(ha.find("priority")) if ha is not None else "",
        }
    return facts


def _vsys_assigned(device_el: ET.Element) -> List[str]:
    """Device-group vsys refs are either <member> or <entry name=...> depending on export vintage."""
    names = [_text(m) for m in device_el.findall("./vsys/member") if _text(m)]
    names.extend(e.get("name", "") for e in device_el.findall("./vsys/entry") if e.get("name"))
    seen: Set[str] = set()
    out: List[str] = []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _template_hostname(tmpl: ET.Element) -> str:
    return _text(tmpl.find("./config/devices/entry/deviceconfig/system/hostname"))


def _iface_ips(entry: ET.Element) -> List[str]:
    return [e.get("name", "") for e in entry.findall(".//ip/entry") if e.get("name")]


_IFACE_KINDS = ("ethernet", "aggregate-ethernet", "vlan", "loopback", "tunnel")


def _parse_template_interfaces(tmpl_name: str, tmpl: ET.Element) -> List[dict]:
    rows: List[dict] = []
    for kind in _IFACE_KINDS:
        for entry in tmpl.findall(f".//interface/{kind}/entry"):
            rows.append(
                {
                    "template": tmpl_name,
                    "name": entry.get("name", ""),
                    "kind": kind,
                    "ip": ", ".join(_iface_ips(entry)[:8]),
                    "comment": _text(entry.find("comment")),
                }
            )
            for unit in list(entry.findall("./layer3/units/entry")) + list(entry.findall("./units/entry")):
                rows.append(
                    {
                        "template": tmpl_name,
                        "name": unit.get("name", ""),
                        "kind": f"{kind}-unit",
                        "ip": ", ".join(_iface_ips(unit)[:8]),
                        "comment": _text(unit.find("comment")),
                    }
                )
    return rows


def _parse_edl(entry: ET.Element, scope: str) -> dict:
    typ = ""
    url = ""
    type_el = entry.find("type")
    if type_el is not None:
        for child in list(type_el):
            typ = child.tag
            url = _text(child.find("url"))
            break
    return {
        "name": entry.get("name", ""),
        "edl_type": typ,
        "url": url,
        "device_group": scope,
        "category": "external-list",
    }


_PROFILE_KINDS = (
    "virus",
    "spyware",
    "vulnerability",
    "url-filtering",
    "file-blocking",
    "wildfire-analysis",
    "decryption",
)


def _crypto_members(entry: ET.Element, *paths: str) -> str:
    for path in paths:
        vals = members(entry, path)
        if vals:
            return ", ".join(vals)
        el = entry.find(path)
        if el is not None:
            nested = [_text(m) for m in el.findall("member") if _text(m)]
            if nested:
                return ", ".join(nested)
    return ""


def _variable_value(entry: ET.Element) -> Tuple[str, str]:
    type_el = entry.find("type")
    if type_el is None or not len(type_el):
        return "", ""
    child = type_el[0]
    return child.tag, (_text(child) or child.get("name") or "")


def _parse_security_profiles(parent: ET.Element, scope: str) -> List[dict]:
    rows: List[dict] = []
    profiles = parent.find("profiles")
    if profiles is not None:
        for kind in _PROFILE_KINDS:
            for entry in profiles.findall(f"./{kind}/entry"):
                rows.append({"name": entry.get("name", ""), "kind": kind, "scope": scope})
        for entry in profiles.findall("./custom-url-category/entry"):
            mem = members(entry, "list")
            rows.append(
                {
                    "name": entry.get("name", ""),
                    "kind": "custom-url-category",
                    "scope": scope,
                    "members": ", ".join(mem[:8]) + (" …" if len(mem) > 8 else ""),
                }
            )
    for entry in parent.findall("./profile-group/entry"):
        parts = []
        for kind in _PROFILE_KINDS:
            mem = members(entry, kind)
            if mem:
                parts.append(f"{kind}={','.join(mem)}")
        rows.append(
            {
                "name": entry.get("name", ""),
                "kind": "profile-group",
                "scope": scope,
                "members": "; ".join(parts),
            }
        )
    return rows


def _parse_log_fwd_profiles(parent: ET.Element, scope: str) -> List[dict]:
    rows: List[dict] = []
    for entry in parent.findall("./log-settings/profiles/entry"):
        matches = []
        for m in entry.findall("./match-list/entry"):
            dest = ", ".join(members(m, "send-syslog") or members(m, "send-email") or members(m, "send-http"))
            pano = _text(m.find("send-to-panorama"))
            if pano == "yes":
                dest = (dest + ", panorama").strip(", ")
            matches.append(f"{m.get('name', '')} [{_text(m.find('log-type')) or 'any'}→{dest or '—'}]")
        rows.append(
            {
                "name": entry.get("name", ""),
                "scope": scope,
                "kind": "profile",
                "matches": "; ".join(matches[:8]) + (" …" if len(matches) > 8 else ""),
                "match_count": len(entry.findall("./match-list/entry")),
            }
        )
    ls = parent.find("log-settings")
    if ls is not None:
        for child in list(ls):
            if child.tag == "profiles":
                continue
            for m in child.findall("./match-list/entry"):
                dest = ", ".join(members(m, "send-syslog") or members(m, "send-email"))
                rows.append(
                    {
                        "name": m.get("name", ""),
                        "scope": scope,
                        "kind": child.tag,
                        "matches": dest or "—",
                        "match_count": 1,
                    }
                )
    return rows


def _parse_tag(entry: ET.Element, scope: str) -> dict:
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "color": _text(entry.find("color")),
        "comments": _text(entry.find("comments")),
    }


def _app_default(entry: ET.Element) -> str:
    """Human-readable <default> for a custom application (ports / protocol / ICMP)."""
    default = entry.find("default")
    if default is None:
        return ""
    ports = members(default, "port")
    if ports:
        return ", ".join(ports)
    proto = _text(default.find("ident-by-ip-protocol"))
    if proto:
        return f"ip-protocol {proto}"
    icmp = _text(default.find("ident-by-icmp-type/type"))
    if icmp:
        return f"icmp type {icmp}"
    icmp6 = _text(default.find("ident-by-icmp6-type/type"))
    if icmp6:
        return f"icmp6 type {icmp6}"
    return ""


def _parse_application(entry: ET.Element, scope: str) -> dict:
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "category": _text(entry.find("category")),
        "subcategory": _text(entry.find("subcategory")),
        "technology": _text(entry.find("technology")),
        "risk": _text(entry.find("risk")),
        "default": _app_default(entry),
        "description": _text(entry.find("description")),
    }


def _parse_application_group(entry: ET.Element, scope: str) -> dict:
    mem = members(entry, "members") or members(entry, "member")
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "members": mem,
        "member_count": len(mem),
        "category": "application-group",
        "device_group": scope,
    }


_APP_FILTER_FIELDS = (
    "category", "subcategory", "technology", "risk", "tagging",
    "evasive", "excessive-bandwidth-use", "used-by-malware", "transfers-files",
    "tunnels-other-apps", "has-known-vulnerabilities", "pervasive", "saas",
)


def _parse_application_filter(entry: ET.Element, scope: str) -> dict:
    parts: List[str] = []
    for field in _APP_FILTER_FIELDS:
        mem = members(entry, field)
        if mem:
            parts.append(f"{field}={','.join(mem)}")
            continue
        val = _text(entry.find(field))
        if val:
            parts.append(f"{field}={val}")
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "criteria": "; ".join(parts) or "—",
        "criteria_count": len(parts),
    }


def _parse_certificate(entry: ET.Element, scope: str) -> dict:
    """A certificate as it matters to a migration: who issued it, when it dies.

    Certificates are not decorative here — GlobalProtect portals/gateways, SSL
    forward-proxy decryption, IPsec IKE gateways, EDL hosting and admin auth all
    hang off them, and a cert that does not exist on the target platform is a
    silent outage at cutover. Expiry is surfaced because an expired cert in a
    source config is a finding, not a detail.
    """
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "subject": _text(entry.find("subject")),
        "issuer": _text(entry.find("issuer")),
        "not_valid_before": _text(entry.find("not-valid-before")),
        "not_valid_after": _text(entry.find("not-valid-after")),
        "expiry_epoch": _text(entry.find("expiry-epoch")),
        "common_name": _text(entry.find("common-name")),
        "algorithm": _text(entry.find("algorithm")),
        "ca": _text(entry.find("ca")).lower() == "yes",
        "has_private_key": entry.find("private-key") is not None,
    }


def _parse_certificate_profile(entry: ET.Element, scope: str) -> dict:
    """A certificate profile — the CA set an auth flow trusts."""
    cas = [c.get("name", "") for c in entry.findall("./CA/entry") if c.get("name")]
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "ca_certificates": cas,
        "username_field": ", ".join(
            f.tag for f in (entry.find("username-field") or [])
        ),
        "crl": _text(entry.find("use-crl")).lower() == "yes",
        "ocsp": _text(entry.find("use-ocsp")).lower() == "yes",
    }


def _parse_schedule(entry: ET.Element, scope: str) -> dict:
    stype = ""
    detail: List[str] = []
    st = entry.find("schedule-type")
    if st is not None and len(st):
        kind = st[0]
        stype = kind.tag
        if kind.tag == "non-recurring":
            detail = [_text(m) for m in kind.findall("member") if _text(m)]
        else:
            for period in kind:
                vals = [_text(m) for m in period.findall("member") if _text(m)]
                detail.append(f"{period.tag}: {', '.join(vals)}" if vals else period.tag)
    return {
        "name": entry.get("name", ""),
        "scope": scope,
        "schedule_type": stype or "—",
        "detail": "; ".join(d for d in detail if d) or "—",
    }


def _parse_app_override(entry: ET.Element, dg_name: str, rulebase: str) -> dict:
    return {
        "name": entry.get("name", ""),
        "device_group": dg_name,
        "rulebase": rulebase,
        "from": join_m(entry, "from"),
        "to": join_m(entry, "to"),
        "source": join_m(entry, "source"),
        "destination": join_m(entry, "destination"),
        "port": _text(entry.find("port")),
        "protocol": _text(entry.find("protocol")),
        "application": _text(entry.find("application")),
        "disabled": _text(entry.find("disabled")).lower() == "yes",
    }


def _parse_template_vpn(tmpl_name: str, tmpl: ET.Element) -> Tuple[List[dict], List[dict], List[dict], List[dict]]:
    portals: List[dict] = []
    gateways: Dict[str, dict] = {}
    ike_rows: List[dict] = []
    ipsec_tunnels: List[dict] = []

    for entry in tmpl.findall(".//global-protect-portal/entry"):
        auth = []
        for ca in entry.findall(".//client-auth/entry"):
            auth.append(_text(ca.find("authentication-profile")) or ca.get("name", ""))
        portals.append(
            {
                "template": tmpl_name,
                "name": entry.get("name", ""),
                "interface": _text(entry.find(".//local-address/interface")),
                "ip": _text(entry.find(".//local-address/ip/ipv4")),
                "ssl_profile": _text(entry.find(".//ssl-tls-service-profile")),
                "auth": ", ".join([a for a in auth if a][:6]),
            }
        )

    for entry in tmpl.findall(".//global-protect-gateway/entry"):
        name = entry.get("name", "")
        key = name.lower()
        row = gateways.get(key) or {
            "template": tmpl_name,
            "name": name,
            "interface": "",
            "ip": "",
            "tunnel_interface": "",
            "auth": "",
            "ipsec_profile": "",
        }
        iface = _text(entry.find(".//local-address/interface"))
        ip = _text(entry.find(".//local-address/ip/ipv4"))
        tun = _text(entry.find("tunnel-interface"))
        auth = []
        for ca in entry.findall("./client-auth/entry"):
            auth.append(_text(ca.find("authentication-profile")) or ca.get("name", ""))
        ipsec_prof = _text(entry.find("./ipsec/ipsec-crypto-profile"))
        if iface:
            row["interface"] = iface
        if ip:
            row["ip"] = ip
        if tun:
            row["tunnel_interface"] = tun
        if auth:
            row["auth"] = ", ".join([a for a in auth if a][:6])
        if ipsec_prof:
            row["ipsec_profile"] = ipsec_prof
        gateways[key] = row

    for entry in tmpl.findall(".//ike-crypto-profiles/entry"):
        ike_rows.append(
            {
                "template": tmpl_name,
                "kind": "ike-crypto",
                "name": entry.get("name", ""),
                "encryption": _crypto_members(entry, "encryption"),
                "hash": _crypto_members(entry, "hash", "authentication"),
                "dh": _crypto_members(entry, "dh-group") or _text(entry.find("dh-group")),
                "peer": "",
                "interface": "",
            }
        )
    for entry in tmpl.findall(".//ipsec-crypto-profiles/entry"):
        ike_rows.append(
            {
                "template": tmpl_name,
                "kind": "ipsec-crypto",
                "name": entry.get("name", ""),
                "encryption": _crypto_members(entry, "esp/encryption", "encryption"),
                "hash": _crypto_members(entry, "esp/authentication", "authentication"),
                "dh": _text(entry.find("dh-group")),
                "peer": "",
                "interface": "",
            }
        )
    for entry in tmpl.findall(".//ike/gateway/entry"):
        ike_rows.append(
            {
                "template": tmpl_name,
                "kind": "ike-gateway",
                "name": entry.get("name", ""),
                "encryption": "",
                "hash": "",
                "dh": "",
                "peer": _text(entry.find(".//peer-address/ip")) or _text(entry.find(".//peer-address/fqdn")),
                "interface": _text(entry.find(".//local-address/interface")),
            }
        )
    for entry in tmpl.findall(".//tunnel/ipsec/entry"):
        ipsec_tunnels.append(
            {
                "template": tmpl_name,
                "name": entry.get("name", ""),
                "ike_gateway": join_m(entry, "auto-key/ike-gateway") or _text(entry.find(".//ike-gateway/entry")),
                "crypto": _text(entry.find(".//ipsec-crypto-profile")),
                "tunnel_interface": _text(entry.find("tunnel-interface")),
            }
        )

    return portals, list(gateways.values()), ike_rows, ipsec_tunnels


def _template_vsys_elements(tmpl: ET.Element) -> List[ET.Element]:
    """Collect vsys entries defined in a Panorama template (deduped by name)."""
    seen: Set[str] = set()
    out: List[ET.Element] = []
    for vsys in tmpl.findall(".//config/devices/entry/vsys/entry"):
        name = vsys.get("name") or ""
        if name and name not in seen:
            seen.add(name)
            out.append(vsys)
    return out


def _parse_bgp_rows(tmpl_name: str, vr_name: str, bgp: ET.Element) -> List[dict]:
    summary = {
        "router_id": _text(bgp.find("router-id")),
        "local_as": _text(bgp.find("local-as")),
        "bgp_enable": _text(bgp.find("enable")),
    }
    rows: List[dict] = []
    for pg in bgp.findall("peer-group/entry"):
        rows.append(
            {
                "template": tmpl_name,
                "virtual_router": vr_name,
                "name": pg.get("name", ""),
                "kind": "peer-group",
                "peer_as": _text(pg.find("peer-as")) or _text(pg.find(".//peer-as")),
                "peer_address": _text(pg.find("peer-address")) or _text(pg.find(".//peer-address")),
                **summary,
            }
        )
    for peer in bgp.findall(".//peer/entry"):
        rows.append(
            {
                "template": tmpl_name,
                "virtual_router": vr_name,
                "name": peer.get("name", ""),
                "kind": "peer",
                "peer_as": _text(peer.find("peer-as")),
                "peer_address": _text(peer.find("peer-address")),
                "bgp_enable": _text(peer.find("enable")) or summary["bgp_enable"],
                "router_id": summary["router_id"],
                "local_as": summary["local_as"],
            }
        )
    return rows


def _parse_ospf_rows(tmpl_name: str, vr_name: str, ospf: ET.Element) -> List[dict]:
    enable = _text(ospf.find("enable"))
    router_id = _text(ospf.find("router-id"))
    rows: List[dict] = []
    for area in ospf.findall("area/entry"):
        ifaces = members(area, "interface")
        if not ifaces:
            for iface_el in area.findall(".//interface/entry"):
                iname = iface_el.get("name", "")
                if iname:
                    ifaces.append(iname)
        rows.append(
            {
                "template": tmpl_name,
                "virtual_router": vr_name,
                "area": area.get("name", ""),
                "enable": enable,
                "router_id": router_id,
                "interfaces": ", ".join(ifaces[:12]) + (" …" if len(ifaces) > 12 else ""),
            }
        )
    if not rows and (enable.lower() == "yes" or router_id):
        rows.append(
            {
                "template": tmpl_name,
                "virtual_router": vr_name,
                "area": "—",
                "enable": enable,
                "router_id": router_id,
                "interfaces": "",
            }
        )
    return rows


class PaloStandaloneModel:
    """Single-firewall PAN-OS XML (vsys / rulebase layout)."""

    export_kind: ExportKind = "standalone"

    def __init__(self, path: Path):
        self.path = path
        self.hostname = ""
        self.vsys_names: List[str] = []
        self.rules: List[dict] = []
        self.addresses: List[dict] = []
        self.address_groups: List[dict] = []
        self.services: List[dict] = []
        self.service_groups: List[dict] = []
        self.zones: List[dict] = []
        self.nat_rules: List[dict] = []
        self.routes: List[dict] = []
        self.unused: List[dict] = []
        self.device_groups: List[str] = []
        self.stats: Dict[str, int] = {}

    def load(self) -> None:
        root = ET.parse(self.path).getroot()
        host_el = root.find(".//hostname")
        if _text(host_el):
            self.hostname = _text(host_el)

        for vsys in root.findall(".//vsys/entry"):
            vsys_name = vsys.get("name", "vsys1")
            self.vsys_names.append(vsys_name)
            scope = vsys_name
            self._load_objects(vsys, scope)
            self._load_rulebases(vsys, scope)

        if not self.vsys_names:
            self._load_objects(root, "")
            self._load_rulebases(root, "")

        self._load_routes(root)
        self._compute_unused()
        rules_no_prof = sum(1 for r in self.rules if not r.get("profiles") and not r.get("disabled"))
        self.stats = {
            "security_rules": len(self.rules),
            "addresses": len(self.addresses),
            "address_groups": len(self.address_groups),
            "services": len(self.services),
            "service_groups": len(self.service_groups),
            "zones": len(self.zones),
            "nat_rules": len(self.nat_rules),
            "routes": len(self.routes),
            "unused_objects": len(self.unused),
            "rules_without_profiles": rules_no_prof,
            "device_groups": 0,
            "vsys_count": len(self.vsys_names) or 1,
        }

    def _load_objects(self, parent: ET.Element, scope: str) -> None:
        for entry in parent.findall(".//address/entry"):
            row = {"name": entry.get("name", ""), "value": addr_value(entry), "category": "address"}
            if scope:
                row["vsys"] = scope
            self.addresses.append(row)
        for entry in parent.findall(".//address-group/entry"):
            mem = members(entry, "static") or members(entry, "dynamic") or members(entry, "member")
            row = {
                "name": entry.get("name", ""),
                "members": mem,
                "member_count": len(mem),
                "category": "address-group",
            }
            if scope:
                row["vsys"] = scope
            self.address_groups.append(row)
        for entry in parent.findall(".//service/entry"):
            row = {"name": entry.get("name", ""), "value": svc_value(entry), "category": "service"}
            if scope:
                row["vsys"] = scope
            self.services.append(row)
        for entry in parent.findall(".//service-group/entry"):
            mem = members(entry, "members") or members(entry, "member")
            row = {
                "name": entry.get("name", ""),
                "members": mem,
                "member_count": len(mem),
                "category": "service-group",
            }
            if scope:
                row["vsys"] = scope
            self.service_groups.append(row)
        for entry in parent.findall(".//zone/entry"):
            self.zones.append(
                {
                    "name": entry.get("name", ""),
                    "interfaces": ", ".join(members(entry, "network") or members(entry, "interface")),
                    "vsys": scope or "—",
                }
            )

    def _parse_security_rule(self, entry: ET.Element, scope: str, rulebase: str) -> dict:
        disabled = _text(entry.find("disabled")).lower() == "yes"
        row = {
            "name": entry.get("name", ""),
            "rulebase": rulebase,
            "from": join_m(entry, "from"),
            "to": join_m(entry, "to"),
            "source": join_m(entry, "source"),
            "destination": join_m(entry, "destination"),
            "service": join_m(entry, "service"),
            "application": join_m(entry, "application"),
            "action": _text(entry.find("action")),
            "profiles": _rule_profiles(entry),
            "disabled": disabled,
        }
        if scope:
            row["vsys"] = scope
        return _stamp_target(row, entry)

    def _parse_nat_rule(self, entry: ET.Element, scope: str, rulebase: str) -> dict:
        row = {
            "name": entry.get("name", ""),
            "rulebase": rulebase,
            "from": join_m(entry, "from"),
            "to": join_m(entry, "to"),
            "source": join_m(entry, "source"),
            "destination": join_m(entry, "destination"),
            "service": join_m(entry, "service"),
            "source_translation": _nat_translation(entry, "source-translation"),
            "dest_translation": _nat_translation(entry, "destination-translation"),
        }
        if scope:
            row["vsys"] = scope
        return _stamp_target(row, entry)

    def _load_rulebases(self, parent: ET.Element, scope: str) -> None:
        for rb_type in _RULEBASE_TAGS:
            rb = parent.find(f".//{rb_type}")
            if rb is None:
                continue
            sec = rb.find("security/rules")
            if sec is not None:
                for entry in sec.findall("entry"):
                    self.rules.append(self._parse_security_rule(entry, scope, rb_type))
            nat = rb.find("nat/rules")
            if nat is not None:
                for entry in nat.findall("entry"):
                    self.nat_rules.append(self._parse_nat_rule(entry, scope, rb_type))

    def _load_routes(self, root: ET.Element) -> None:
        raw: List[dict] = []
        for entry in root.findall(".//static-route/entry"):
            raw.append(
                {
                    "name": entry.get("name", ""),
                    "destination": _text(entry.find("destination")),
                    "nexthop": _text(entry.find(".//nexthop/ip-address")) or _text(entry.find(".//nexthop/next-vr")),
                    "interface": _text(entry.find("interface")),
                    "metric": _text(entry.find("metric")),
                }
            )
        self.routes = dedupe_routes(raw)

    def _compute_unused(self) -> None:
        net_group_map = {g["name"].lower(): g["members"] for g in self.address_groups if g.get("name")}
        svc_group_map = {g["name"].lower(): g["members"] for g in self.service_groups if g.get("name")}
        used: Set[str] = set()

        def _use_names(values: Iterable[str]) -> None:
            for val in values:
                if not val or val.lower() == "any":
                    continue
                used.add(val)
                seen: Set[str] = set()
                if val.lower() in net_group_map:
                    used.update(_expand_group(val, net_group_map, seen))
                if val.lower() in svc_group_map:
                    used.update(_expand_group(val, svc_group_map, seen))

        for rule in self.rules:
            for field in ("source", "destination", "service", "application"):
                _use_names((rule.get(field) or "").split(", "))
        for nat in self.nat_rules:
            for field in ("source", "destination", "service"):
                _use_names((nat.get(field) or "").split(", "))

        used_lower = {u.lower() for u in used}
        self.unused = []
        for obj in self.addresses + self.address_groups + self.services + self.service_groups:
            name = obj.get("name") or ""
            if name and name.lower() not in used_lower:
                self.unused.append(
                    {
                        "category": obj.get("category", ""),
                        "name": name,
                        "definition": obj.get("value") or f"{obj.get('member_count', 0)} member(s)",
                    }
                )
        self.unused.sort(key=lambda r: (r["category"], r["name"].lower()))

    def optimization_findings(self) -> List[dict]:
        return _optimization_findings(self.unused, self.rules, self.stats)


class PaloPanoramaModel:
    """Panorama export with device-group hierarchy (pre/post rulebase)."""

    export_kind: ExportKind = "panorama"

    def __init__(self, path: Path):
        self.path = path
        self.hostname = ""
        self.rules: List[dict] = []
        self.addresses: List[dict] = []
        self.address_groups: List[dict] = []
        self.services: List[dict] = []
        self.service_groups: List[dict] = []
        self.zones: List[dict] = []
        self.nat_rules: List[dict] = []
        self.decrypt_rules: List[dict] = []
        self.routes: List[dict] = []
        self.unused: List[dict] = []
        self.device_groups: List[str] = []
        self.suite: List[dict] = []
        self.managed_devices: List[dict] = []
        self.relationships: List[dict] = []
        self.templates: List[dict] = []
        self.template_stacks: List[dict] = []
        self.template_vsys: List[dict] = []
        self.virtual_routers: List[dict] = []
        self.bgp_peers: List[dict] = []
        self.ospf_areas: List[dict] = []
        self.interfaces: List[dict] = []
        self.edls: List[dict] = []
        self.gp_portals: List[dict] = []
        self.gp_gateways: List[dict] = []
        self.ike_objects: List[dict] = []
        self.ipsec_tunnels: List[dict] = []
        self.security_profiles: List[dict] = []
        self.app_overrides: List[dict] = []
        self.ha_variables: List[dict] = []
        self.log_forwarding: List[dict] = []
        self.tags: List[dict] = []
        self.applications: List[dict] = []
        self.application_groups: List[dict] = []
        self.application_filters: List[dict] = []
        self.schedules: List[dict] = []
        self.certificates: List[dict] = []
        self.certificate_profiles: List[dict] = []
        self.admin_roles: List[dict] = []
        self.report_groups: List[dict] = []
        self.log_collectors: List[dict] = []
        self.decrypt_exclusions: List[dict] = []
        self._stack_templates: Dict[str, List[str]] = {}
        self._dg_parent: Dict[str, str] = {}
        # Object scopes = device groups + Shared (Shared is a namespace, not a DG).
        self.object_scopes: List[str] = []
        # Snapshot completeness — a pre-1.5.0 export simply lacks these branches.
        # Nothing here is an error; the pages say so instead of rendering blanks.
        self.has_shared = False
        self.has_template_stacks = False
        self.has_operational_devices = False
        self.stats: Dict[str, int] = {}

    def load(self) -> None:
        root = ET.parse(self.path).getroot()
        host_el = root.find("./devices/entry/deviceconfig/system/hostname")
        if _text(host_el):
            self.hostname = _text(host_el)

        dg_map = _collect_device_group_entries(root)
        self.device_groups = sorted(dg_map.keys(), key=str.lower)

        for dg_name, info in sorted(dg_map.items(), key=lambda x: x[0].lower()):
            self._load_dg(info["elem"], dg_name)

        # /config/shared — sibling of <devices>, present since collector 1.5.0.
        # Fall back to a nested <shared> for older/oddly-shaped exports.
        shared = root.find("shared")
        if shared is None:  # older/oddly-shaped exports nested it under <devices>
            shared = root.find(".//devices/entry/shared")
        self.has_shared = shared is not None
        if shared is not None:
            self._load_dg(shared, SHARED_SCOPE)
        self.object_scopes = list(self.device_groups) + ([SHARED_SCOPE] if shared is not None else [])
        self._dg_parent = {name: (info.get("parent") or "") for name, info in dg_map.items()}

        for lcg in root.findall(".//log-collector-group/entry"):
            self.log_forwarding.extend(_parse_log_fwd_profiles(lcg, f"collector-group:{lcg.get('name', '')}"))

        self._load_template_zones(root)
        self._load_template_network(root)
        self._load_certificates(root)
        self._load_panorama_infra(root)
        self._load_decrypt_exclusions(root)
        self._build_suite(dg_map)
        self._build_managed_devices(root, dg_map)
        self._enrich_managed_devices()
        self._annotate_suite_templates()
        serial_host = {d["serial"]: d.get("hostname") or "" for d in self.managed_devices}
        for v in self.ha_variables:
            v["hostname"] = serial_host.get(v["serial"], "")
        self._compute_unused()
        self._build_relationships()

        self.has_template_stacks = bool(self.template_stacks)
        rules_no_prof = sum(1 for r in self.rules if not r.get("profiles") and not r.get("disabled"))

        def _distinct(rows: List[dict], key: str = "name") -> int:
            return len({(r.get(key) or "").lower() for r in rows if r.get(key)})

        self.stats = {
            "security_rules": len(self.rules),
            # NOTE ON COUNTING BASIS — deliberate, do not "fix" silently.
            # "addresses" and friends count DEFINITIONS: one per scope+name pair,
            # exactly as PAN-OS stores them, so a name defined in three device
            # groups counts three times. "*_distinct" counts distinct names across
            # the whole snapshot (device groups + Shared) and is therefore always
            # <= the definition count. Every page that shows one of these says
            # which basis it is using.
            "addresses": len(self.addresses),
            "addresses_distinct": _distinct(self.addresses),
            "address_groups": len(self.address_groups),
            "address_groups_distinct": _distinct(self.address_groups),
            "services": len(self.services),
            "services_distinct": _distinct(self.services),
            "service_groups": len(self.service_groups),
            "service_groups_distinct": _distinct(self.service_groups),
            "tags": len(self.tags),
            "applications": len(self.applications),
            "application_groups": len(self.application_groups),
            "application_filters": len(self.application_filters),
            "schedules": len(self.schedules),
            "certificates": len(self.certificates),
            "certificate_profiles": len(self.certificate_profiles),
            "admin_roles": len(self.admin_roles),
            "report_groups": len(self.report_groups),
            "log_collectors": len(self.log_collectors),
            "decrypt_exclusions": len(self.decrypt_exclusions),
            "shared_objects": sum(
                1
                for o in (
                    self.addresses + self.address_groups + self.services + self.service_groups
                    + self.tags + self.applications + self.application_groups
                    + self.application_filters + self.schedules + self.edls
                )
                if (o.get("device_group") or o.get("scope")) == SHARED_SCOPE
            ),
            "shared_profiles": sum(1 for p in self.security_profiles if p.get("scope") == SHARED_SCOPE),
            "zones": len(self.zones),
            "nat_rules": len(self.nat_rules),
            "decrypt_rules": len(self.decrypt_rules),
            "edls": len(self.edls),
            "interfaces": len(self.interfaces),
            "routes": len(self.routes),
            "unused_objects": len(self.unused),
            "rules_without_profiles": rules_no_prof,
            "device_groups": len(self.device_groups),
            "managed_devices": len(self.managed_devices),
            "templates": len(self.templates),
            "template_stacks": len(self.template_stacks),
            "template_vsys": len(self.template_vsys),
            "virtual_routers": len(self.virtual_routers),
            "bgp_peers": len(self.bgp_peers),
            "ospf_areas": len(self.ospf_areas),
            "gp_portals": len(self.gp_portals),
            "gp_gateways": len(self.gp_gateways),
            "ike_objects": len(self.ike_objects),
            "ipsec_tunnels": len(self.ipsec_tunnels),
            "security_profiles": len(self.security_profiles),
            "app_overrides": len(self.app_overrides),
            "ha_variables": len(self.ha_variables),
            "log_forwarding": len(self.log_forwarding),
            "multi_vsys_templates": sum(1 for t in self.templates if t.get("multi_vsys")),
            "disabled_rules": sum(1 for r in self.rules if r.get("disabled")),
            "connected_devices": sum(
                1 for d in self.managed_devices if (d.get("connected") or "").lower() == "yes"
            ),
            "ha_devices": sum(1 for d in self.managed_devices if d.get("ha_state")),
            "stack_assigned_devices": sum(1 for d in self.managed_devices if d.get("template_stack")),
        }

    def _load_dg(self, dg: ET.Element, dg_name: str) -> None:
        for entry in dg.findall("./address/entry"):
            self.addresses.append(
                {"name": entry.get("name", ""), "value": addr_value(entry), "category": "address", "device_group": dg_name}
            )
        for entry in dg.findall("./address-group/entry"):
            mem = members(entry, "static") or members(entry, "dynamic") or members(entry, "member")
            self.address_groups.append(
                {
                    "name": entry.get("name", ""),
                    "members": mem,
                    "member_count": len(mem),
                    "category": "address-group",
                    "device_group": dg_name,
                }
            )
        for entry in dg.findall("./service/entry"):
            self.services.append(
                {"name": entry.get("name", ""), "value": svc_value(entry), "category": "service", "device_group": dg_name}
            )
        for entry in dg.findall("./service-group/entry"):
            mem = members(entry, "members") or members(entry, "member")
            self.service_groups.append(
                {
                    "name": entry.get("name", ""),
                    "members": mem,
                    "member_count": len(mem),
                    "category": "service-group",
                    "device_group": dg_name,
                }
            )
        for rb_type in _RULEBASE_TAGS:
            rb = dg.find(rb_type)
            if rb is None:
                continue
            sec = rb.find("security/rules")
            if sec is not None:
                for entry in sec.findall("entry"):
                    self.rules.append(self._parse_security_rule(entry, dg_name, rb_type))
            nat = rb.find("nat/rules")
            if nat is not None:
                for entry in nat.findall("entry"):
                    self.nat_rules.append(self._parse_nat_rule(entry, dg_name, rb_type))
            dec = rb.find("decryption/rules")
            if dec is not None:
                for entry in dec.findall("entry"):
                    self.decrypt_rules.append(self._parse_decrypt_rule(entry, dg_name, rb_type))
            apo = rb.find("application-override/rules")
            if apo is not None:
                for entry in apo.findall("entry"):
                    self.app_overrides.append(_parse_app_override(entry, dg_name, rb_type))
        for entry in dg.findall("./external-list/entry"):
            self.edls.append(_parse_edl(entry, dg_name))
        for entry in dg.findall("./tag/entry"):
            self.tags.append(_parse_tag(entry, dg_name))
        for entry in dg.findall("./application/entry"):
            self.applications.append(_parse_application(entry, dg_name))
        for entry in dg.findall("./application-group/entry"):
            self.application_groups.append(_parse_application_group(entry, dg_name))
        for entry in dg.findall("./application-filter/entry"):
            self.application_filters.append(_parse_application_filter(entry, dg_name))
        for entry in dg.findall("./schedule/entry"):
            self.schedules.append(_parse_schedule(entry, dg_name))
        self.security_profiles.extend(_parse_security_profiles(dg, dg_name))
        self.log_forwarding.extend(_parse_log_fwd_profiles(dg, dg_name))

    def _parse_security_rule(self, entry: ET.Element, dg_name: str, rulebase: str) -> dict:
        disabled = _text(entry.find("disabled")).lower() == "yes"
        return _stamp_target(
            {
                "name": entry.get("name", ""),
                "device_group": dg_name,
                "rulebase": rulebase,
                "from": join_m(entry, "from"),
                "to": join_m(entry, "to"),
                "source": join_m(entry, "source"),
                "destination": join_m(entry, "destination"),
                "service": join_m(entry, "service"),
                "application": join_m(entry, "application"),
                "action": _text(entry.find("action")),
                "profiles": _rule_profiles(entry),
                "schedule": _text(entry.find("schedule")),
                "tags": join_m(entry, "tag"),
                "disabled": disabled,
            },
            entry,
        )

    def _parse_nat_rule(self, entry: ET.Element, dg_name: str, rulebase: str) -> dict:
        return _stamp_target(
            {
                "name": entry.get("name", ""),
                "device_group": dg_name,
                "rulebase": rulebase,
                "from": join_m(entry, "from"),
                "to": join_m(entry, "to"),
                "source": join_m(entry, "source"),
                "destination": join_m(entry, "destination"),
                "service": join_m(entry, "service"),
                "source_translation": _nat_translation(entry, "source-translation"),
                "dest_translation": _nat_translation(entry, "destination-translation"),
            },
            entry,
        )

    def _parse_decrypt_rule(self, entry: ET.Element, dg_name: str, rulebase: str) -> dict:
        disabled = _text(entry.find("disabled")).lower() == "yes"
        dtype = ""
        type_el = entry.find("type")
        if type_el is not None and len(type_el):
            dtype = type_el[0].tag
        return _stamp_target(
            {
                "name": entry.get("name", ""),
                "device_group": dg_name,
                "rulebase": rulebase,
                "from": join_m(entry, "from"),
                "to": join_m(entry, "to"),
                "source": join_m(entry, "source"),
                "destination": join_m(entry, "destination"),
                "service": join_m(entry, "service"),
                "action": _text(entry.find("action")) or dtype or "—",
                "decrypt_type": dtype,
                "disabled": disabled,
            },
            entry,
        )

    def _load_template_zones(self, root: ET.Element) -> None:
        for tmpl_name, tmpl in _collect_template_entries(root).items():
            for entry in tmpl.findall(".//zone/entry"):
                self.zones.append(
                    {
                        "name": entry.get("name", ""),
                        "interfaces": ", ".join(members(entry, "network") or members(entry, "interface")),
                        "template": tmpl_name,
                    }
                )

    def _load_certificates(self, root: ET.Element) -> None:
        """Certificates and certificate profiles, scoped by TEMPLATE.

        Deliberately not device-group scoped. On a real Panorama certificates do
        not live in the shared object namespace at /config/shared — they sit in
        each template's own <config><shared> block (and one set under
        /config/panorama for Panorama itself), because a certificate is pushed to
        a firewall by a template, not inherited through the device-group tree.
        Verified against a 12-firewall production estate: /config/shared held 0
        certificates while the templates held 98 entries between them.
        """
        for tmpl_name, tmpl in _collect_template_entries(root).items():
            for entry in tmpl.findall(".//shared/certificate/entry"):
                self.certificates.append(_parse_certificate(entry, tmpl_name))
            for entry in tmpl.findall(".//shared/certificate-profile/entry"):
                self.certificate_profiles.append(
                    _parse_certificate_profile(entry, tmpl_name)
                )
        pan = root.find("./panorama")
        if pan is not None:
            for entry in pan.findall(".//certificate/entry"):
                self.certificates.append(_parse_certificate(entry, "Panorama"))
            for entry in pan.findall(".//certificate-profile/entry"):
                self.certificate_profiles.append(
                    _parse_certificate_profile(entry, "Panorama")
                )
        # A certificate may be defined in several templates in a stack; keep one
        # row per (scope, name) so the page states definitions, matching the
        # collector's stated counting basis everywhere else.
        seen = set()
        deduped = []
        for c in self.certificates:
            k = (c["scope"], c["name"])
            if k in seen:
                continue
            seen.add(k)
            deduped.append(c)
        self.certificates = deduped
        seen = set()
        deduped = []
        for c in self.certificate_profiles:
            k = (c["scope"], c["name"])
            if k in seen:
                continue
            seen.add(k)
            deduped.append(c)
        self.certificate_profiles = deduped

    def _load_panorama_infra(self, root: ET.Element) -> None:
        """Panorama's own administrative furniture, not customer policy.

        Admin roles matter to a migration because RBAC has to be recreated on the
        target; report groups and log collectors are inventory. Collected since
        1.5.0 and rendered since 1.5.1 — before that they were captured and shown
        nowhere, which is the same silent-omission class the completeness audit
        exists to stop.
        """
        for scope_elem, scope in (
            (root.find("./shared"), SHARED_SCOPE),
            (root.find("./panorama"), "Panorama"),
        ):
            if scope_elem is None:
                continue
            for e in scope_elem.findall("./admin-role/entry"):
                role = e.find(".//role")
                kind = ""
                if role is not None and len(role):
                    kind = role[0].tag
                self.admin_roles.append(
                    {"name": e.get("name", ""), "scope": scope, "role_type": kind}
                )
            for e in scope_elem.findall("./report-group/entry"):
                members = [m.text for m in e.findall(".//member") if m.text]
                self.report_groups.append(
                    {"name": e.get("name", ""), "scope": scope,
                     "members": members}
                )
        dev = root.find(".//devices/entry")
        if dev is not None:
            for e in dev.findall("./log-collector/entry"):
                self.log_collectors.append({
                    "name": e.get("name", ""),
                    "scope": "Panorama",
                    "hostname": _text(e.find(".//hostname")),
                    "ip": _text(e.find(".//ip-address")),
                })

    def _load_decrypt_exclusions(self, root: ET.Element) -> None:
        """SSL decryption exclusions — what deliberately bypasses inspection.

        Security-relevant in its own right: an exclusion list is a documented
        decision about traffic nobody inspects, and it is one of the first things
        an auditor asks for. It is also migration-relevant because the target
        platform needs an equivalent list or the security posture silently
        changes at cutover. 161 entries on the reference estate, rendered nowhere
        before 1.5.1.
        """
        for tmpl_name, tmpl in _collect_template_entries(root).items():
            for e in tmpl.findall(".//ssl-decrypt/ssl-exclude-cert/entry"):
                self.decrypt_exclusions.append({
                    "name": e.get("name", ""),
                    "scope": tmpl_name,
                    "description": _text(e.find("description")),
                    "exclude": _text(e.find("exclude")).lower() == "yes",
                })
        seen, out = set(), []
        for x in self.decrypt_exclusions:
            k = (x["scope"], x["name"])
            if k in seen:
                continue
            seen.add(k)
            out.append(x)
        self.decrypt_exclusions = out

    def _load_template_network(self, root: ET.Element) -> None:
        self.routes = []
        self.interfaces = []
        for tmpl_name, tmpl in _collect_template_entries(root).items():
            vsys_elems = _template_vsys_elements(tmpl)
            vsys_names = [v.get("name", "") for v in vsys_elems if v.get("name")]
            ifaces_rows = _parse_template_interfaces(tmpl_name, tmpl)
            portals, gateways, ike_rows, ipsec_tun = _parse_template_vpn(tmpl_name, tmpl)
            self.gp_portals.extend(portals)
            self.gp_gateways.extend(gateways)
            self.ike_objects.extend(ike_rows)
            self.ipsec_tunnels.extend(ipsec_tun)

            for vsys in vsys_elems:
                vr_import = members(vsys, "import/network/virtual-router")
                self.template_vsys.append(
                    {
                        "template": tmpl_name,
                        "name": vsys.get("name", ""),
                        "display_name": _text(vsys.find("display-name")),
                        "import_virtual_routers": ", ".join(vr_import) if vr_import else "—",
                    }
                )

            vr_count = static_count = bgp_count = ospf_count = 0
            for vr in tmpl.findall(".//virtual-router/entry"):
                vr_name = vr.get("name", "")
                vr_count += 1
                ifaces = members(vr, "interface")
                static_routes = vr.findall(".//static-route/entry")
                static_count += len(static_routes)

                has_bgp = False
                bgp = vr.find("protocol/bgp")
                if bgp is not None:
                    configured = _text(bgp.find("enable")).lower() == "yes" or _text(bgp.find("router-id"))
                    if configured or bgp.findall(".//peer/entry") or bgp.findall("peer-group/entry"):
                        has_bgp = True
                        bgp_count += 1
                        self.bgp_peers.extend(_parse_bgp_rows(tmpl_name, vr_name, bgp))

                has_ospf = False
                ospf = vr.find("protocol/ospf")
                if ospf is not None:
                    configured = _text(ospf.find("enable")).lower() == "yes" or ospf.findall("area/entry")
                    if configured:
                        has_ospf = True
                        ospf_count += 1
                        self.ospf_areas.extend(_parse_ospf_rows(tmpl_name, vr_name, ospf))

                for sr in static_routes:
                    self.routes.append(
                        {
                            "template": tmpl_name,
                            "virtual_router": vr_name,
                            "name": sr.get("name", ""),
                            "destination": _text(sr.find("destination")),
                            "nexthop": _text(sr.find(".//nexthop/ip-address"))
                            or _text(sr.find(".//nexthop/next-vr")),
                            "interface": _text(sr.find("interface")),
                            "metric": _text(sr.find("metric")),
                        }
                    )

                self.virtual_routers.append(
                    {
                        "template": tmpl_name,
                        "name": vr_name,
                        "interfaces": ", ".join(ifaces[:8]) + (" …" if len(ifaces) > 8 else ""),
                        "interface_count": len(ifaces),
                        "static_routes": len(static_routes),
                        "bgp": "yes" if has_bgp else "no",
                        "ospf": "yes" if has_ospf else "no",
                    }
                )

            self.templates.append(
                {
                    "name": tmpl_name,
                    "vsys_count": len(vsys_names),
                    "vsys_list": ", ".join(vsys_names[:8]) + (" …" if len(vsys_names) > 8 else ""),
                    "virtual_router_count": vr_count,
                    "static_route_count": static_count,
                    "bgp_count": bgp_count,
                    "ospf_count": ospf_count,
                    "interface_count": len(ifaces_rows),
                    "hostname": _template_hostname(tmpl),
                    "multi_vsys": len(vsys_names) > 1,
                }
            )
            self.interfaces.extend(ifaces_rows)

        for tname, slot in _collect_template_stack_entries(root).items():
            tmpl_members = slot["templates"]
            self._stack_templates[tname] = tmpl_members
            serials = [d.get("name", "") for d in slot["devices"] if d.get("name")]
            self.template_stacks.append(
                {
                    "name": tname,
                    "templates": tmpl_members,
                    "template_count": len(tmpl_members),
                    "devices": len(slot["devices"]),
                    "device_serials": serials,
                }
            )
            for d in slot["devices"]:
                serial = d.get("name", "")
                for ve in d.findall("./variable/entry"):
                    vtype, vval = _variable_value(ve)
                    self.ha_variables.append(
                        {
                            "stack": tname,
                            "serial": serial,
                            "name": ve.get("name", ""),
                            "value": vval,
                            "value_type": vtype,
                        }
                    )
        self.templates.sort(key=lambda x: x["name"].lower())
        self.template_stacks.sort(key=lambda x: x["name"].lower())
        self.virtual_routers.sort(key=lambda x: (x["template"].lower(), x["name"].lower()))
        self.bgp_peers.sort(key=lambda x: (x["template"].lower(), x["virtual_router"].lower(), x["name"].lower()))
        self.ospf_areas.sort(key=lambda x: (x["template"].lower(), x["virtual_router"].lower(), x["area"].lower()))
        self.routes.sort(key=lambda x: (x["template"].lower(), x["virtual_router"].lower(), x["destination"].lower()))
        self.interfaces.sort(key=lambda x: (x["template"].lower(), x["kind"].lower(), x["name"].lower()))
        self.gp_portals.sort(key=lambda x: (x["template"].lower(), x["name"].lower()))
        self.gp_gateways.sort(key=lambda x: (x["template"].lower(), x["name"].lower()))
        self.ike_objects.sort(key=lambda x: (x["template"].lower(), x["kind"].lower(), x["name"].lower()))
        self.ipsec_tunnels.sort(key=lambda x: (x["template"].lower(), x["name"].lower()))
        self.ha_variables.sort(key=lambda x: (x["stack"].lower(), x["serial"], x["name"].lower()))
        self.security_profiles.sort(key=lambda x: (x["scope"].lower(), x["kind"], x["name"].lower()))
        self.log_forwarding.sort(key=lambda x: (x["scope"].lower(), x["name"].lower()))
        self.app_overrides.sort(key=lambda x: (x["device_group"].lower(), x["name"].lower()))

    def _build_suite(self, dg_map: Dict[str, dict]) -> None:
        nodes: Dict[str, dict] = {}
        for name, info in dg_map.items():
            dg = info["elem"]
            local_rules = 0
            local_nat = 0
            local_decrypt = 0
            for tag in ("pre-rulebase", "post-rulebase"):
                rb = dg.find(tag)
                if rb is None:
                    continue
                sec = rb.find("security/rules")
                if sec is not None:
                    local_rules += len(sec.findall("entry"))
                nat = rb.find("nat/rules")
                if nat is not None:
                    local_nat += len(nat.findall("entry"))
                dec = rb.find("decryption/rules")
                if dec is not None:
                    local_decrypt += len(dec.findall("entry"))
            local_objs = sum(len(dg.findall(f"./{t}/entry")) for t in _OBJ_TAGS)
            nodes[name] = {
                "name": name,
                "parent": info.get("parent") or "",
                "children": [],
                "local_rule_count": local_rules,
                "local_nat_count": local_nat,
                "local_decrypt_count": local_decrypt,
                "local_object_count": local_objs,
                "device_count": len(dg.findall("./devices/entry")),
            }
        for name, node in nodes.items():
            parent = node["parent"]
            if parent and parent in nodes:
                nodes[parent]["children"].append(name)
        for node in nodes.values():
            node["children"].sort(key=str.lower)
        self.suite = sorted(nodes.values(), key=lambda x: x["name"].lower())

    def _build_managed_devices(self, root: ET.Element, dg_map: Dict[str, dict]) -> None:
        tmpl_by_serial: Dict[str, str] = {}
        for tname, slot in _collect_template_stack_entries(root).items():
            for d in slot["devices"]:
                serial = d.get("name")
                if serial:
                    tmpl_by_serial[serial] = tname

        facts = _parse_managed_device_facts(root)
        self.has_operational_devices = bool(facts)

        seen: Set[str] = set()
        for dg_name, info in dg_map.items():
            for d in info["elem"].findall("./devices/entry"):
                serial = d.get("name")
                if not serial or serial in seen:
                    continue
                seen.add(serial)
                vsys = _vsys_assigned(d)
                row = {
                    "serial": serial,
                    "device_group": dg_name,
                    "template_stack": tmpl_by_serial.get(serial, ""),
                    "vsys": ", ".join(vsys) if vsys else "vsys1",
                }
                row.update(facts.get(serial, {}))
                self.managed_devices.append(row)

        # Firewalls Panorama manages but no device group claims still exist and
        # still need to be listed — silently dropping them would understate the
        # estate.
        for serial, fact in facts.items():
            if serial in seen:
                continue
            seen.add(serial)
            row = {
                "serial": serial,
                "device_group": "",
                "template_stack": tmpl_by_serial.get(serial, ""),
                "vsys": "vsys1",
            }
            row.update(fact)
            self.managed_devices.append(row)

        self.managed_devices.sort(key=lambda x: (x["device_group"].lower(), x["serial"]))

    def _enrich_managed_devices(self) -> None:
        tmpl_vsys: Dict[str, List[str]] = defaultdict(list)
        for row in self.template_vsys:
            name = row.get("name") or ""
            if name and name not in tmpl_vsys[row["template"]]:
                tmpl_vsys[row["template"]].append(name)
        hostname_by_tmpl = {t["name"]: t.get("hostname") or "" for t in self.templates}
        for dev in self.managed_devices:
            stack = dev.get("template_stack") or ""
            vsys_from_template: List[str] = []
            tmpl_hostname = ""
            for tmpl in self._stack_templates.get(stack, []):
                for vn in tmpl_vsys.get(tmpl, []):
                    if vn not in vsys_from_template:
                        vsys_from_template.append(vn)
                if not tmpl_hostname and hostname_by_tmpl.get(tmpl):
                    tmpl_hostname = hostname_by_tmpl[tmpl]
            dev["template_vsys"] = ", ".join(vsys_from_template) if vsys_from_template else "—"
            dev["template_hostname"] = tmpl_hostname
            # Operational hostname is what the firewall actually reports; the
            # first site template in the stack is only a guess at it. Prefer the
            # fact, keep the guess as the fallback, and record which one is shown.
            op_hostname = dev.get("op_hostname") or ""
            dev["hostname"] = op_hostname or tmpl_hostname
            dev["hostname_source"] = (
                "operational" if op_hostname else ("template" if tmpl_hostname else "")
            )

    def _annotate_suite_templates(self) -> None:
        for node in self.suite:
            stacks = sorted(
                {
                    d.get("template_stack")
                    for d in self.managed_devices
                    if d.get("device_group") == node["name"] and d.get("template_stack")
                }
            )
            node["template_stacks"] = stacks

    def dg_template_stacks(self, dg_name: str) -> List[str]:
        return sorted(
            {
                d.get("template_stack")
                for d in self.managed_devices
                if d.get("device_group") == dg_name and d.get("template_stack")
            }
        )

    def templates_for_stack(self, stack_name: str) -> List[str]:
        return list(self._stack_templates.get(stack_name, []))

    def virtual_routers_for_template(self, tmpl_name: str) -> List[dict]:
        return [v for v in self.virtual_routers if v.get("template") == tmpl_name]

    # Object categories the unused analysis can honestly decide. Tags are
    # deliberately excluded: they are referenced from object metadata (address
    # <tag>, rule <tag>) that this model does not index per object, so calling a
    # tag "unused" would be a guess. Application filters match by attribute, not
    # by name, so an application reachable only through a referenced filter is
    # treated as used (see _filter_matched_apps).
    _UNUSED_CATEGORIES = (
        "address", "address-group", "service", "service-group", "external-list",
        "application", "application-group", "schedule",
    )

    def _dg_descendants(self) -> Dict[str, Set[str]]:
        """device group -> itself plus every device group that inherits from it."""
        children: Dict[str, List[str]] = defaultdict(list)
        for name, parent in self._dg_parent.items():
            if parent and parent in self._dg_parent:
                children[parent].append(name)
        out: Dict[str, Set[str]] = {}
        for name in self._dg_parent:
            seen: Set[str] = set()
            stack = [name]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                stack.extend(children.get(cur, ()))
            out[name] = seen
        return out

    def _scope_objects(self) -> Dict[str, List[dict]]:
        """Every analysable object, bucketed by the scope that defines it."""
        by_scope: Dict[str, List[dict]] = defaultdict(list)
        for obj in self.addresses + self.address_groups + self.services + self.service_groups:
            by_scope[obj.get("device_group") or ""].append(obj)
        for e in self.edls:
            by_scope[e.get("device_group") or ""].append(
                {"name": e.get("name", ""), "category": "external-list",
                 "device_group": e.get("device_group", ""), "value": e.get("url", "")}
            )
        for g in self.application_groups:
            by_scope[g.get("scope") or ""].append(g)
        for a in self.applications:
            by_scope[a.get("scope") or ""].append(
                {"name": a.get("name", ""), "category": "application",
                 "device_group": a.get("scope", ""),
                 "value": a.get("default") or a.get("category", "")}
            )
        for sc in self.schedules:
            by_scope[sc.get("scope") or ""].append(
                {"name": sc.get("name", ""), "category": "schedule",
                 "device_group": sc.get("scope", ""), "value": sc.get("detail", "")}
            )
        return by_scope

    def _filter_matched_apps(self, used_lower: Set[str]) -> Set[str]:
        """Custom applications reachable through a referenced application-filter.

        A filter selects applications by attribute (category / subcategory / risk /
        technology), never by name, so a custom app whose attributes satisfy a
        referenced filter IS reachable from policy and must not be called unused.
        """
        active = [f for f in self.application_filters if (f.get("name") or "").lower() in used_lower]
        if not active:
            return set()
        criteria: List[Dict[str, Set[str]]] = []
        for f in active:
            wanted: Dict[str, Set[str]] = defaultdict(set)
            for part in (f.get("criteria") or "").split("; "):
                key, sep, vals = part.partition("=")
                if not sep:
                    continue
                for v in vals.split(","):
                    if v.strip():
                        wanted[key.strip()].add(v.strip().lower())
            if wanted:
                criteria.append(wanted)
        matched: Set[str] = set()
        for app in self.applications:
            attrs = {
                "category": (app.get("category") or "").lower(),
                "subcategory": (app.get("subcategory") or "").lower(),
                "technology": (app.get("technology") or "").lower(),
                "risk": (app.get("risk") or "").lower(),
            }
            for wanted in criteria:
                keys = [k for k in wanted if k in attrs and attrs[k]]
                if keys and all(attrs[k] in wanted[k] for k in keys):
                    matched.add((app.get("name") or "").lower())
                    break
        return matched

    def _compute_unused(self) -> None:
        """Unused-object analysis over the FULL Panorama namespace.

        Before collector 1.5.0 the <shared> branch was never collected, so about
        three quarters of the estate's objects — and every group that referenced
        them — were invisible, and this count was computed against a fragment.

        Resolution follows PAN-OS: a rule in device group D may reference objects
        defined in D, in D's ancestors, and in Shared. So an object defined in
        scope S is used when any device group that INHERITS from S references it,
        directly or through a group whose membership expands to it.

        Counting basis: one row per object DEFINITION (scope + name). The same
        name defined in two scopes is two rows, matching how PAN-OS stores it.
        """
        by_scope = self._scope_objects()
        descendants = self._dg_descendants()

        # references, bucketed by the device group whose rules made them
        refs_by_dg: Dict[str, Set[str]] = defaultdict(set)

        def _add(dg: str, values: Iterable[str]) -> None:
            for val in values:
                v = (val or "").strip()
                if v and v.lower() != "any":
                    refs_by_dg[dg].add(v)

        for rule in self.rules:
            dg = rule.get("device_group", "")
            for field in ("source", "destination", "service", "application"):
                _add(dg, (rule.get(field) or "").split(", "))
            _add(dg, [rule.get("schedule") or ""])
        for nat in self.nat_rules:
            dg = nat.get("device_group", "")
            for field in ("source", "destination", "service"):
                _add(dg, (nat.get(field) or "").split(", "))
        for dec in self.decrypt_rules:
            dg = dec.get("device_group", "")
            for field in ("source", "destination", "service"):
                _add(dg, (dec.get(field) or "").split(", "))
        for apo in self.app_overrides:
            dg = apo.get("device_group", "")
            for field in ("source", "destination"):
                _add(dg, (apo.get(field) or "").split(", "))
            _add(dg, [apo.get("application") or ""])

        # group membership, merged across scopes — a name visible to a consumer
        # expands the same way whichever scope defined it
        group_map: Dict[str, List[str]] = defaultdict(list)
        for g in self.address_groups + self.service_groups + self.application_groups:
            key = (g.get("name") or "").lower()
            if key:
                group_map[key].extend(g.get("members") or [])

        all_scopes = set(self.device_groups) | {SHARED_SCOPE}
        unused: List[dict] = []
        for scope in self.object_scopes:
            objs = by_scope.get(scope) or []
            if not objs:
                continue
            if scope == SHARED_SCOPE:
                consumers = all_scopes
            else:
                consumers = descendants.get(scope) or {scope}
            used: Set[str] = set()
            for dg in consumers:
                for val in refs_by_dg.get(dg, ()):
                    used.add(val)
                    if val.lower() in group_map:
                        used.update(_expand_group(val, group_map, set()))
            used_lower = {u.lower() for u in used}
            used_lower |= self._filter_matched_apps(used_lower)
            for obj in objs:
                name = obj.get("name") or ""
                cat = obj.get("category", "")
                if not name or cat not in self._UNUSED_CATEGORIES:
                    continue
                if name.lower() in used_lower:
                    continue
                unused.append(
                    {
                        "category": cat,
                        "name": name,
                        "device_group": scope,
                        "definition": obj.get("value")
                        or obj.get("url")
                        or f"{obj.get('member_count', 0)} member(s)",
                    }
                )
        unused.sort(key=lambda r: (r["device_group"].lower(), r["category"], r["name"].lower()))
        self.unused = unused

    def _build_relationships(self) -> None:
        rows: List[dict] = []
        for rule in self.rules:
            dg = rule.get("device_group", "")
            label = f"{rule.get('rulebase', '')} / {rule.get('name', '')}"
            for field, cat in (
                ("source", "address"),
                ("destination", "address"),
                ("service", "service"),
                ("application", "application"),
            ):
                for val in (rule.get(field) or "").split(", "):
                    if val and val.lower() != "any":
                        rows.append(
                            {
                                "device_group": dg,
                                "object_category": cat,
                                "object_name": val,
                                "used_by": label,
                                "rule_type": "security",
                            }
                        )
        for nat in self.nat_rules:
            dg = nat.get("device_group", "")
            label = f"{nat.get('rulebase', '')} / {nat.get('name', '')}"
            for field, cat in (("source", "address"), ("destination", "address"), ("service", "service")):
                for val in (nat.get(field) or "").split(", "):
                    if val and val.lower() != "any":
                        rows.append(
                            {
                                "device_group": dg,
                                "object_category": cat,
                                "object_name": val,
                                "used_by": label,
                                "rule_type": "nat",
                            }
                        )
        for dec in self.decrypt_rules:
            dg = dec.get("device_group", "")
            label = f"{dec.get('rulebase', '')} / {dec.get('name', '')}"
            for field, cat in (("source", "address"), ("destination", "address"), ("service", "service")):
                for val in (dec.get(field) or "").split(", "):
                    if val and val.lower() != "any":
                        rows.append(
                            {
                                "device_group": dg,
                                "object_category": cat,
                                "object_name": val,
                                "used_by": label,
                                "rule_type": "decryption",
                            }
                        )
        rows.sort(key=lambda r: (r["object_name"].lower(), r["device_group"].lower(), r["used_by"]))
        self.relationships = rows

    def optimization_findings(self) -> List[dict]:
        findings = _optimization_findings(self.unused, self.rules, self.stats)
        n_disabled = self.stats.get("disabled_rules", 0)
        if n_disabled:
            findings.append(
                {
                    "severity": "low",
                    "type": "Disabled security rules",
                    "count": n_disabled,
                    "detail": f"{n_disabled} rule(s) marked disabled=yes",
                }
            )
        return findings

    def rules_for_dg(self, dg_name: str) -> List[dict]:
        return [r for r in self.rules if r.get("device_group") == dg_name]

    def nat_for_dg(self, dg_name: str) -> List[dict]:
        return [n for n in self.nat_rules if n.get("device_group") == dg_name]

    def decrypt_for_dg(self, dg_name: str) -> List[dict]:
        return [d for d in self.decrypt_rules if d.get("device_group") == dg_name]

    def dg_chain(self, dg_name: str) -> List[str]:
        """Outermost ancestor first, then `dg_name`. Stops on missing/cycle."""
        chain: List[str] = []
        cur = dg_name or ""
        seen: Set[str] = set()
        while cur and cur not in seen:
            seen.add(cur)
            chain.append(cur)
            cur = self._dg_parent.get(cur) or ""
        chain.reverse()
        return chain

    def inherited_rules(self, rows: List[dict], dg_name: str) -> List[dict]:
        """Effective rule order for a device group (shared + ancestors + self).

        Evaluation order matches Panorama:
          shared pre → ancestor pre (outermost first) → own pre/local
          → own post → ancestor post (innermost first) → shared post

        Sibling device-group local rules are not included.
        """
        chain = self.dg_chain(dg_name)

        def pick(scope: str, rb: str) -> List[dict]:
            return [r for r in rows if r.get("device_group") == scope and r.get("rulebase") == rb]

        out: List[dict] = []
        out.extend(pick(SHARED_SCOPE, "pre-rulebase"))
        for dg in chain:
            out.extend(pick(dg, "pre-rulebase"))
            out.extend(pick(dg, "rulebase"))
        for dg in reversed(chain):
            out.extend(pick(dg, "post-rulebase"))
        out.extend(pick(SHARED_SCOPE, "post-rulebase"))
        return out

    def split_rules_for_serial(
        self, rows: List[dict], serial: str, dg_name: str
    ) -> Tuple[List[dict], List[dict]]:
        inherited = self.inherited_rules(rows, dg_name) if dg_name else []
        mine = [r for r in inherited if rule_applies_to_serial(r, serial)]
        other = [r for r in inherited if not rule_applies_to_serial(r, serial)]
        return mine, other

    def firewall_view_rows(self) -> List[dict]:
        """One row per managed serial: identity + applicable vs inherited counts."""
        out: List[dict] = []
        for d in self.managed_devices:
            serial = d.get("serial") or ""
            dg = d.get("device_group") or ""
            sec_all = self.inherited_rules(self.rules, dg) if dg else []
            nat_all = self.inherited_rules(self.nat_rules, dg) if dg else []
            dec_all = self.inherited_rules(self.decrypt_rules, dg) if dg else []
            sec = [r for r in sec_all if rule_applies_to_serial(r, serial)]
            nat = [r for r in nat_all if rule_applies_to_serial(r, serial)]
            dec = [r for r in dec_all if rule_applies_to_serial(r, serial)]
            out.append(
                {
                    "serial": serial,
                    "hostname": d.get("hostname") or "",
                    "device_group": dg,
                    "template_stack": d.get("template_stack") or "",
                    "model": d.get("model") or "",
                    "sw_version": d.get("sw_version") or "",
                    "connected": d.get("connected") or "",
                    "ha_state": d.get("ha_state") or "",
                    "ip_address": d.get("ip_address") or "",
                    "applicable_rules": len(sec),
                    "inherited_rules": len(sec_all),
                    "other_rules": len(sec_all) - len(sec),
                    "applicable_nat": len(nat),
                    "inherited_nat": len(nat_all),
                    "applicable_decrypt": len(dec),
                    "inherited_decrypt": len(dec_all),
                }
            )
        return out

    def interfaces_for_template(self, tmpl_name: str) -> List[dict]:
        return [i for i in self.interfaces if i.get("template") == tmpl_name]

    def app_override_for_dg(self, dg_name: str) -> List[dict]:
        return [a for a in self.app_overrides if a.get("device_group") == dg_name]

    def suite_roots(self) -> List[dict]:
        all_names = {n["name"] for n in self.suite}
        return [n for n in self.suite if not n["parent"] or n["parent"] not in all_names]


def _optimization_findings(unused: List[dict], rules: List[dict], stats: Dict[str, int]) -> List[dict]:
    by_cat: Dict[str, List[dict]] = defaultdict(list)
    for row in unused:
        by_cat[row["category"]].append(row)
    findings: List[dict] = []
    labels = {
        "address": "Unused addresses",
        "address-group": "Unused address groups",
        "service": "Unused services",
        "service-group": "Unused service groups",
    }
    for cat, rows in sorted(by_cat.items()):
        findings.append(
            {
                "severity": "medium",
                "type": labels.get(cat, f"Unused {cat}"),
                "count": len(rows),
                "detail": ", ".join(r["name"] for r in rows[:10]) + (" …" if len(rows) > 10 else ""),
            }
        )
    n = stats.get("rules_without_profiles", 0)
    if n:
        names = [r["name"] for r in rules if not r.get("profiles") and not r.get("disabled")][:10]
        findings.append(
            {
                "severity": "low",
                "type": "Rules without profile group",
                "count": n,
                "detail": ", ".join(names) + (" …" if n > 10 else ""),
            }
        )
    return findings


PaloModel = Union[PaloStandaloneModel, PaloPanoramaModel]


def load_palo_model(path: Path, mode: str = "auto") -> PaloModel:
    root = ET.parse(path).getroot()
    kind = detect_export_kind(root) if mode == "auto" else mode
    if kind not in ("standalone", "panorama"):
        raise ValueError(f"Unknown mode: {mode!r}")
    model: PaloModel = PaloPanoramaModel(path) if kind == "panorama" else PaloStandaloneModel(path)
    model.load()
    return model


# Back-compat alias used by older imports/tests
PaloXmlModel = PaloStandaloneModel
