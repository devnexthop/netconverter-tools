#!/usr/bin/env python3
"""
NetConverter — FortiGate device config (.conf) parser + snapshot merger.

FortiManager-managed FortiGates very often keep their firewall **policies** (and
many objects) *locally* on the device, so a central FortiManager JSON-RPC pull
returns ``policies: 0`` for them. The per-device configuration backups (the
``*.conf`` revision files FortiManager stores under each device's revision
history) contain that missing device-level config.

This module parses those FortiOS CLI config backups and merges the device-local
data (policies, addresses, services, groups, VIPs, IP pools, routes, interfaces,
VPN) into the same snapshot dict consumed by ``build_html.py`` — so every device
that ships a local ``.conf`` lights up the policy and object pages that the
central pull leaves empty.

Read-only: this only *reads* ``.conf`` text files. No device is ever contacted.

License: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

# Datasets that the central FortiManager pull already populates per-device. When
# a device is already represented in one of these, we keep the FortiManager rows
# and skip the local-config rows to avoid double counting. Policies and the
# object tables are merged additively (they are the gap we are filling).
_FMG_OWNED = ("interfaces", "routes", "vpn_phase1", "vpn_phase2", "vpn_ssl",
              "zones", "device_admins", "dhcp_servers")


# --------------------------------------------------------------------------- #
# Tokenizer / parser for the FortiOS CLI config grammar.
# --------------------------------------------------------------------------- #
def _tokenize(text: str):
    """Yield one list-of-tokens per FortiOS statement.

    Statements are newline-terminated. Double-quoted strings may span newlines
    (certificates, replacement-message blobs) and may contain escaped quotes.
    """
    tokens: list[str] = []
    buf: list[str] = []
    in_quote = False
    in_token = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = False
                tokens.append("".join(buf))
                buf = []
                in_token = False
            else:
                buf.append(ch)
            i += 1
            continue
        if ch == '"':
            in_quote = True
            in_token = True
            buf = []
            i += 1
            continue
        if ch in "\r\n":
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            if tokens:
                yield tokens
                tokens = []
            i += 1
            continue
        if ch.isspace():
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            i += 1
            continue
        buf.append(ch)
        in_token = True
        i += 1
    if in_token:
        tokens.append("".join(buf))
    if tokens:
        yield tokens


def parse_config(text: str) -> dict:
    """Parse a FortiOS ``.conf`` backup into nested dicts.

    Returns a dict whose keys are config-section names (e.g. ``"firewall
    policy"``). Section bodies are dicts keyed by the ``edit`` name/id, or — for
    single-object sections like ``system global`` — by ``set`` key directly.
    Header comment lines (``#serialno=...``) are collected under ``"__meta__"``.
    """
    root: dict[str, Any] = {}
    meta: dict[str, str] = {}
    stack: list[dict[str, Any]] = [root]

    for tokens in _tokenize(text):
        head = tokens[0]
        if head.startswith("#"):
            line = " ".join(tokens)[1:]
            if "=" in line:
                k, _, v = line.partition("=")
                meta.setdefault(k.strip(), v.strip())
            continue
        if head == "config":
            name = " ".join(tokens[1:])
            scope = stack[-1]
            body = scope.get(name)
            if not isinstance(body, dict):
                body = {}
                scope[name] = body
            stack.append(body)
        elif head == "edit":
            name = tokens[1] if len(tokens) > 1 else ""
            scope = stack[-1]
            entry = scope.get(name)
            if not isinstance(entry, dict):
                entry = {}
                scope[name] = entry
            stack.append(entry)
        elif head in ("next", "end"):
            if len(stack) > 1:
                stack.pop()
        elif head == "set":
            if len(tokens) >= 2:
                key = tokens[1]
                vals = tokens[2:]
                stack[-1][key] = vals[0] if len(vals) == 1 else (vals or "")
        elif head == "unset":
            if len(tokens) >= 2:
                stack[-1].pop(tokens[1], None)
        # 'append', 'select', etc. are ignored (read-only display tool).

    if meta:
        root["__meta__"] = meta
    return root


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #
def _s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(str(v) for v in value)
    return str(value)


def _join(value: Any) -> str:
    """Render a (possibly multi-valued) reference field as ``a, b, c``."""
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _cidr(value: Any) -> str:
    """``'10.0.0.0 255.255.255.0'`` (or a ``[ip, mask]`` list) -> ``10.0.0.0/24``."""
    if isinstance(value, list) and len(value) == 2:
        ip, mask = str(value[0]), str(value[1])
    else:
        parts = str(value or "").split()
        if len(parts) == 2:
            ip, mask = parts
        else:
            return str(value or "")
    try:
        bits = sum(bin(int(o)).count("1") for o in mask.split("."))
        return f"{ip}/{bits}"
    except (ValueError, TypeError):
        return f"{ip} {mask}".strip()


def _onoff(entry: dict, key: str, default: str) -> str:
    """FortiOS booleans are present-or-absent: read the explicit value or default."""
    v = entry.get(key)
    return str(v) if v not in (None, "") else default


def _addr_value(obj: dict) -> str:
    t = str(obj.get("type", "") or "")
    if obj.get("subnet"):
        return _cidr(obj.get("subnet"))
    if obj.get("start-ip") or t == "iprange":
        s, e = obj.get("start-ip", ""), obj.get("end-ip", "")
        return f"{s}-{e}".strip("-")
    if obj.get("fqdn") or t == "fqdn":
        return _s(obj.get("fqdn"))
    if obj.get("country"):
        return f"geo:{_s(obj.get('country'))}"
    if obj.get("wildcard-fqdn"):
        return _s(obj.get("wildcard-fqdn"))
    return ""


def _svc_value(obj: dict) -> str:
    bits = []
    for key, label in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"),
                       ("sctp-portrange", "sctp")):
        v = obj.get(key)
        if v:
            bits.append(f"{label}/{_s(v).replace(' ', ',')}")
    if obj.get("protocol-number"):
        bits.append(f"ip-proto {_s(obj.get('protocol-number'))}")
    if obj.get("icmptype"):
        bits.append(f"icmp/{_s(obj.get('icmptype'))}")
    return "; ".join(bits)


def _vip_mappedip(obj: dict) -> str:
    mi = obj.get("mappedip")
    if isinstance(mi, dict):  # newer FortiOS: config mappedip { edit <range> }
        return ", ".join(_s(e.get("range")) or name for name, e in mi.items()
                         if isinstance(e, dict))
    return _s(mi)


# --------------------------------------------------------------------------- #
# Device-level extraction
# --------------------------------------------------------------------------- #
def parse_device(text: str, filename: str = "") -> dict:
    """Parse one ``.conf`` backup into a per-device record with typed datasets."""
    cfg = parse_config(text)
    meta = cfg.get("__meta__", {})

    gl = cfg.get("system global", {})
    name = _s(gl.get("hostname")) or Path(filename).stem
    ha = cfg.get("system ha", {})
    ha_mode = _s(ha.get("mode"))
    if ha_mode and ha.get("group-name"):
        ha_mode = f"{ha_mode} ({_s(ha.get('group-name'))})"

    # Firmware string from the header (e.g. config-version FGT70F-7.00-FW-build2795).
    ver = ""
    cfgver = meta.get("config-version", "")
    if "-" in cfgver:
        for part in cfgver.split("-"):
            if part and part[0].isdigit() and "." in part:
                ver = part
                break
    if meta.get("build"):
        ver = f"{ver} build{meta['build']}".strip()

    dev: dict[str, Any] = {
        "name": name,
        "sn": meta.get("serialno", ""),
        "platform": meta.get("platform", ""),
        "os_ver": ver,
        "ha_mode": ha_mode,
        "config_file": Path(filename).name,
        "config_revision": _revision_of(filename),
        "datasets": {k: [] for k in
                     ("policies", "addresses", "address_groups", "services",
                      "service_groups", "schedules", "vips", "ippools", "routes",
                      "interfaces", "zones", "device_admins", "dhcp_servers",
                      "vpn_phase1", "vpn_phase2", "vpn_ssl")},
    }
    ds = dev["datasets"]

    # --- firewall policies (the central-pull gap) ---
    for pid, p in (cfg.get("firewall policy", {}) or {}).items():
        if not isinstance(p, dict):
            continue
        ds["policies"].append({
            "device": name, "source": "local", "package": f"(local) {name}",
            "policyid": pid, "name": _join(p.get("name")),
            "srcintf": _join(p.get("srcintf")), "dstintf": _join(p.get("dstintf")),
            "srcaddr": _join(p.get("srcaddr") or p.get("srcaddr6")),
            "dstaddr": _join(p.get("dstaddr") or p.get("dstaddr6")),
            "service": _join(p.get("service")), "schedule": _join(p.get("schedule")),
            "action": _onoff(p, "action", "deny"),
            "nat": _onoff(p, "nat", "disable"),
            "status": _onoff(p, "status", "enable"),
            "logtraffic": _s(p.get("logtraffic")),
            "comments": _join(p.get("comments")),
        })

    # --- addresses + groups ---
    for nm, a in (cfg.get("firewall address", {}) or {}).items():
        if isinstance(a, dict):
            ds["addresses"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "type": _s(a.get("type")) or "ipmask", "value": _addr_value(a),
                "interface": _join(a.get("associated-interface")),
                "comment": _join(a.get("comment")),
            })
    for nm, g in (cfg.get("firewall addrgrp", {}) or {}).items():
        if isinstance(g, dict):
            ds["address_groups"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "member": _join(g.get("member")), "comment": _join(g.get("comment")),
            })

    # --- services + groups ---
    for nm, s in (cfg.get("firewall service custom", {}) or {}).items():
        if isinstance(s, dict):
            ds["services"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "protocol": _s(s.get("protocol")), "ports": _svc_value(s),
                "category": _join(s.get("category")), "comment": _join(s.get("comment")),
            })
    for nm, g in (cfg.get("firewall service group", {}) or {}).items():
        if isinstance(g, dict):
            ds["service_groups"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "member": _join(g.get("member")), "comment": _join(g.get("comment")),
            })

    # --- schedules ---
    for nm, s in (cfg.get("firewall schedule recurring", {}) or {}).items():
        if isinstance(s, dict):
            ds["schedules"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "kind": "recurring",
                "value": f"{_s(s.get('day'))} {_s(s.get('start'))}-{_s(s.get('end'))}".strip(),
                "member": "", "comment": _join(s.get("comment")),
            })
    for nm, s in (cfg.get("firewall schedule onetime", {}) or {}).items():
        if isinstance(s, dict):
            ds["schedules"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "kind": "onetime",
                "value": f"{_s(s.get('start'))} → {_s(s.get('end'))}",
                "member": "", "comment": _join(s.get("comment")),
            })
    for nm, s in (cfg.get("firewall schedule group", {}) or {}).items():
        if isinstance(s, dict):
            ds["schedules"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "kind": "group", "value": "", "member": _join(s.get("member")),
                "comment": _join(s.get("comment")),
            })

    # --- NAT objects ---
    for nm, v in (cfg.get("firewall vip", {}) or {}).items():
        if isinstance(v, dict):
            ds["vips"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "extip": _s(v.get("extip")), "mappedip": _vip_mappedip(v),
                "extport": _s(v.get("extport")), "mappedport": _s(v.get("mappedport")),
                "protocol": _s(v.get("protocol")), "comment": _join(v.get("comment")),
            })
    for nm, p in (cfg.get("firewall ippool", {}) or {}).items():
        if isinstance(p, dict):
            ds["ippools"].append({
                "adom": "(local)", "device": name, "source": "local", "name": nm,
                "type": _s(p.get("type")), "startip": _s(p.get("startip")),
                "endip": _s(p.get("endip")), "comment": _join(p.get("comment")),
            })

    # --- routing ---
    for seq, r in (cfg.get("router static", {}) or {}).items():
        if not isinstance(r, dict):
            continue
        dst = _cidr(r.get("dst")) if r.get("dst") else _join(r.get("dstaddr")) or "0.0.0.0/0"
        ds["routes"].append({
            "device": name, "vdom": _s(r.get("vdom")) or "root", "seq": seq, "dst": dst,
            "gateway": _s(r.get("gateway")), "interface": _join(r.get("device")),
            "distance": _s(r.get("distance")), "priority": _s(r.get("priority")),
            "status": _onoff(r, "status", "enable"),
            "blackhole": _onoff(r, "blackhole", "disable"),
            "comment": _join(r.get("comment")),
        })

    # --- interfaces ---
    for nm, i in (cfg.get("system interface", {}) or {}).items():
        if not isinstance(i, dict):
            continue
        ds["interfaces"].append({
            "device": name, "vdom": _s(i.get("vdom")) or "root", "name": nm,
            "ip": _cidr(i.get("ip")) if i.get("ip") else "",
            "status": "down" if _s(i.get("status")) == "down" else "up",
            "allowaccess": _s(i.get("allowaccess")),
            "vlanid": _s(i.get("vlanid")), "parent": _join(i.get("interface")),
            "alias": _s(i.get("alias")), "description": _join(i.get("description")),
        })

    # --- zones ---
    for nm, z in (cfg.get("system zone", {}) or {}).items():
        if isinstance(z, dict):
            ds["zones"].append({
                "device": name, "vdom": "root", "name": nm,
                "interfaces": _join(z.get("interface")),
                "intrazone": _s(z.get("intrazone")) or "deny",
            })

    # --- local administrator accounts ---
    for nm, a in (cfg.get("system admin", {}) or {}).items():
        if not isinstance(a, dict):
            continue
        trust = ", ".join(_cidr(a.get(k)) for k in ("trusthost1", "trusthost2", "trusthost3")
                          if a.get(k) and _cidr(a.get(k)) != "0.0.0.0/0")
        ds["device_admins"].append({
            "device": name, "name": nm, "profile": _s(a.get("accprofile")),
            "trusthosts": trust, "vdoms": _join(a.get("vdom")),
            "two_factor": _s(a.get("two-factor")) or "disable",
        })

    # --- DHCP servers ---
    for sid, d in (cfg.get("system dhcp server", {}) or {}).items():
        if not isinstance(d, dict):
            continue
        ranges = d.get("ip-range")
        rng = ""
        if isinstance(ranges, dict):
            rng = ", ".join(f"{_s(r.get('start-ip'))}-{_s(r.get('end-ip'))}"
                            for r in ranges.values() if isinstance(r, dict))
        dns_srv = ", ".join(_s(d.get(k)) for k in ("dns-server1", "dns-server2", "dns-server3")
                            if d.get(k) and _s(d.get(k)) != "0.0.0.0")
        ds["dhcp_servers"].append({
            "device": name, "vdom": "root", "id": sid,
            "interface": _join(d.get("interface")), "range": rng,
            "netmask": _s(d.get("netmask")), "gateway": _s(d.get("default-gateway")),
            "dns": dns_srv, "domain": _s(d.get("domain")), "lease": _s(d.get("lease-time")),
        })

    # --- VPN ---
    for nm, v in (cfg.get("vpn ipsec phase1-interface", {}) or {}).items():
        if isinstance(v, dict):
            ds["vpn_phase1"].append({
                "device": name, "vdom": "root", "name": nm,
                "interface": _join(v.get("interface")), "remote_gw": _s(v.get("remote-gw")),
                "local_gw": _s(v.get("local-gw")),
                "ike": {"1": "IKEv1", "2": "IKEv2"}.get(_s(v.get("ike-version")), _s(v.get("ike-version"))),
                "mode": _s(v.get("mode")) or "main", "proposal": _s(v.get("proposal")),
                "dhgrp": _s(v.get("dhgrp")), "keylife": _s(v.get("keylife")),
                "peertype": _s(v.get("peertype")),
                "psk": "<redacted>" if v.get("psksecret") else "",
                "comments": _join(v.get("comments")),
            })
    for nm, v in (cfg.get("vpn ipsec phase2-interface", {}) or {}).items():
        if isinstance(v, dict):
            ds["vpn_phase2"].append({
                "device": name, "vdom": "root", "name": nm,
                "phase1": _join(v.get("phase1name")), "proposal": _s(v.get("proposal")),
                "src_subnet": _cidr(v.get("src-subnet")) if v.get("src-subnet") else "",
                "dst_subnet": _cidr(v.get("dst-subnet")) if v.get("dst-subnet") else "",
                "pfs": _onoff(v, "pfs", "enable"), "keylife_sec": _s(v.get("keylifeseconds")),
                "comments": _join(v.get("comments")),
            })
    ssl = cfg.get("vpn ssl settings", {})
    if isinstance(ssl, dict) and _s(ssl.get("status")) not in ("", "disable"):
        ds["vpn_ssl"].append({
            "device": name, "vdom": "root", "status": _s(ssl.get("status")),
            "port": _s(ssl.get("port")), "source_interface": _join(ssl.get("source-interface")),
            "tunnel_ip_pools": _join(ssl.get("tunnel-ip-pools")),
            "servercert": _join(ssl.get("servercert")),
        })

    return dev


def _revision_of(filename: str) -> str:
    """``BCC-PACS-FW1_rev_33.conf`` -> ``33`` (best-effort)."""
    stem = Path(filename).stem
    if "_rev_" in stem:
        return stem.rsplit("_rev_", 1)[-1]
    return ""


# --------------------------------------------------------------------------- #
# Snapshot merge
# --------------------------------------------------------------------------- #
def find_local_configs_dir(run: Path) -> Path | None:
    """Locate a ``Local Configs`` (any case) folder inside a run bundle."""
    if not run.is_dir():
        return None
    for child in run.iterdir():
        if child.is_dir() and child.name.lower().replace("_", " ").replace("-", " ") in (
                "local configs", "device configs", "configs"):
            return child
    return None


def merge_local_configs(snap: dict, configs_dir: Path, log=print) -> dict:
    """Parse every ``.conf`` under *configs_dir* and merge into *snap* in place.

    Returns a summary dict ``{"devices": N, "merged": {dataset: added}, ...}``.
    """
    files = sorted(p for p in configs_dir.glob("*.conf") if p.is_file())
    files += sorted(p for p in configs_dir.glob("*.txt") if p.is_file())
    if not files:
        log(f"  [local] no .conf files found in {configs_dir}")
        return {"devices": 0, "merged": {}}

    for key in ("devices", "policies", "addresses", "address_groups", "services",
                "service_groups", "schedules", "vips", "ippools", "routes",
                "interfaces", "zones", "device_admins", "dhcp_servers",
                "vpn_phase1", "vpn_phase2", "vpn_ssl"):
        snap.setdefault(key, [])

    # Devices already known from the central FortiManager pull (match by name).
    dev_by_name = {str(d.get("name", "")): d for d in snap["devices"] if isinstance(d, dict)}
    # Which datasets already have rows for a given device (from FortiManager)?
    fmg_devices = {ds: {str(r.get("device", "")) for r in snap.get(ds, []) if isinstance(r, dict)}
                   for ds in _FMG_OWNED}

    # De-dup keys so an object defined identically on many devices collapses to one
    # row (and we record every device it appears on under "device").
    seen: dict[str, dict[tuple, dict]] = {
        "addresses": {}, "services": {}, "address_groups": {},
        "service_groups": {}, "schedules": {}, "vips": {}, "ippools": {},
    }
    dedup_key = {
        "addresses": lambda r: (r["name"], r["value"]),
        "services": lambda r: (r["name"], r["protocol"], r["ports"]),
        "address_groups": lambda r: (r["name"], r["member"]),
        "service_groups": lambda r: (r["name"], r["member"]),
        "schedules": lambda r: (r["name"], r["kind"], r["value"], r["member"]),
        "vips": lambda r: (r["name"], r["extip"], r["mappedip"]),
        "ippools": lambda r: (r["name"], r["startip"], r["endip"]),
    }

    added: dict[str, int] = {}
    n_devices = 0
    for fpath in files:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log(f"  [local] cannot read {fpath.name}: {exc}")
            continue
        if "config system" not in text and "config firewall" not in text:
            continue  # not a FortiGate config backup
        dev = parse_device(text, fpath.name)
        n_devices += 1
        name = dev["name"]

        existing = dev_by_name.get(name)
        if existing is not None:
            existing.setdefault("config_file", dev["config_file"])
            existing["config_revision"] = dev["config_revision"]
            existing["has_local_config"] = True
            for k in ("sn", "platform", "os_ver", "ha_mode"):
                if not existing.get(k) and dev.get(k):
                    existing[k] = dev[k]
        else:
            snap["devices"].append({
                "adom": "(local)", "name": name, "sn": dev["sn"],
                "ip": "", "platform": dev["platform"], "os_ver": dev["os_ver"],
                "ha_mode": dev["ha_mode"], "vdoms": "root", "conn_status": "",
                "desc": "", "config_file": dev["config_file"],
                "config_revision": dev["config_revision"], "has_local_config": True,
            })
            dev_by_name[name] = snap["devices"][-1]

        for ds_name, rows in dev["datasets"].items():
            if ds_name in _FMG_OWNED and name in fmg_devices.get(ds_name, set()):
                continue  # FortiManager already provided this dataset for the device
            if ds_name in seen:
                bucket = seen[ds_name]
                keyf = dedup_key[ds_name]
                for r in rows:
                    k = keyf(r)
                    if k in bucket:
                        prev = bucket[k]
                        if name not in prev["device"].split(", "):
                            prev["device"] = f"{prev['device']}, {name}"
                        continue
                    bucket[k] = r
                    snap[ds_name].append(r)
                    added[ds_name] = added.get(ds_name, 0) + 1
            else:
                snap[ds_name].extend(rows)
                added[ds_name] = added.get(ds_name, 0) + len(rows)

    snap["local_configs"] = {
        "dir": configs_dir.name, "devices": n_devices, "merged": added,
    }
    summary = ", ".join(f"{k}+{v}" for k, v in sorted(added.items()) if v)
    log(f"  [local] merged {n_devices} device config(s): {summary or 'no new rows'}")
    return {"devices": n_devices, "merged": added}


def merge_run_local_configs(snap: dict, run: Path, override: Path | None = None,
                            log=print) -> dict | None:
    """Convenience: locate (or use *override*) the local-config folder and merge."""
    configs_dir = override or find_local_configs_dir(run)
    if not configs_dir or not configs_dir.is_dir():
        return None
    log(f"  [local] reading device configs from: {configs_dir}")
    return merge_local_configs(snap, configs_dir, log=log)
