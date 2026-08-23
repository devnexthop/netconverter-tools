"""Per-package dossier — competitor-parity package summary.

Builds one record per policy package with:
  access layers, NAT, threat layers, HTTPS layers, gateways, object-type counts
from package.json + rulebase objects-dictionaries (same sources Management API
exposes). Used by standalone build_html and NetConverter.local session rows.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional


def _load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _name_of(model, uid_or_obj) -> str:
    if isinstance(uid_or_obj, dict):
        return str(uid_or_obj.get("name") or uid_or_obj.get("uid") or "")
    if uid_or_obj is None:
        return ""
    by_uid = getattr(model, "by_uid", None) or {}
    obj = by_uid.get(uid_or_obj)
    if isinstance(obj, dict) and obj.get("name"):
        return str(obj["name"])
    if hasattr(model, "name_of"):
        try:
            return str(model.name_of(uid_or_obj) or uid_or_obj)
        except Exception:
            pass
    return str(uid_or_obj)


def _layer_names(entries) -> List[str]:
    out = []
    if isinstance(entries, dict):
        # https-inspection-layers style
        for key in ("inbound-https-layer", "outbound-https-layer"):
            v = entries.get(key)
            if isinstance(v, dict) and v.get("name"):
                out.append(str(v["name"]))
            elif isinstance(v, str) and v:
                out.append(v)
        return out
    for item in entries or []:
        if isinstance(item, dict) and item.get("name"):
            out.append(str(item["name"]))
        elif isinstance(item, str) and item:
            out.append(item)
    return out


def _https_layers(doc: dict) -> List[Dict[str, str]]:
    hil = doc.get("https-inspection-layers") or {}
    rows = []
    if isinstance(hil, dict):
        for role, key in (("inbound", "inbound-https-layer"), ("outbound", "outbound-https-layer")):
            v = hil.get(key)
            name = ""
            if isinstance(v, dict):
                name = str(v.get("name") or "")
            elif isinstance(v, str):
                name = v
            if name:
                rows.append({"role": role, "name": name})
    # fallback: singular https-inspection-layer
    if not rows:
        single = doc.get("https-inspection-layer")
        if isinstance(single, dict) and single.get("name"):
            rows.append({"role": "layer", "name": str(single["name"])})
        elif isinstance(single, str) and single:
            rows.append({"role": "layer", "name": single})
    return rows


def _install_targets(model, doc: dict) -> List[str]:
    names = []
    seen = set()
    for t in doc.get("installation-targets") or []:
        n = _name_of(model, t)
        if n and n not in seen and n.lower() not in ("all", "policy targets", "any"):
            seen.add(n)
            names.append(n)
    return names


def _gateways_for_package(model, pkg_name: str, meta_targets: List[str]) -> List[str]:
    """Prefer gateways whose access-policy-name matches; merge meta targets."""
    seen = set()
    out = []
    for g in getattr(model, "gateways", []) or []:
        if not isinstance(g, dict):
            continue
        pol = (g.get("policy") or {}).get("access-policy-name") or ""
        if pol != pkg_name:
            continue
        n = g.get("name") or ""
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    # If policy fan-out is empty, fall back to installation-targets
    if not out:
        for n in meta_targets:
            if n not in seen:
                seen.add(n)
                out.append(n)
    else:
        # Also include any meta targets not already listed (clusters vs members)
        for n in meta_targets:
            if n not in seen:
                seen.add(n)
                out.append(n)
    out.sort(key=lambda s: s.lower())
    return out


def _object_type_counts(run_dir: Path, pkg_name: str) -> List[Dict[str, Any]]:
    """Union of objects-dictionary entries across this package's rulebase files.

    Dedupes by UID so the same host referenced in access + NAT counts once —
    closer to a package inventory than raw dictionary row dumps.
    """
    pkg_dir = run_dir / "policy-by-package" / pkg_name
    # CP package folder names are sanitized; try exact then fuzzy
    if not pkg_dir.is_dir():
        policy = run_dir / "policy-by-package"
        if policy.is_dir():
            for child in policy.iterdir():
                if not child.is_dir():
                    continue
                pj = _load_json(child / "package.json")
                if isinstance(pj, dict) and pj.get("name") == pkg_name:
                    pkg_dir = child
                    break
    if not pkg_dir.is_dir():
        return []

    by_uid: Dict[str, str] = {}
    for pattern in (
        "access-rulebase*.json",
        "nat-rulebase*.json",
        "threat-rulebase*.json",
        "https-rulebase*.json",
    ):
        for path in pkg_dir.glob(pattern):
            doc = _load_json(path)
            if not isinstance(doc, dict):
                continue
            for obj in doc.get("objects-dictionary") or doc.get("object_dictionary") or []:
                if not isinstance(obj, dict):
                    continue
                uid = obj.get("uid") or ""
                typ = obj.get("type") or "?"
                if uid:
                    by_uid[uid] = typ
                else:
                    # nameless stubs still count by fabricating a key
                    by_uid["%s::%s" % (typ, obj.get("name") or id(obj))] = typ

    counts = Counter(by_uid.values())
    return [
        {"type": t, "count": n}
        for t, n in sorted(counts.items(), key=lambda x: (-x[1], x[0].lower()))
    ]


def build_package_dossiers(model) -> List[Dict[str, Any]]:
    """Return sorted list of per-package dossier dicts."""
    run_dir = Path(getattr(model, "run_dir"))
    meta = getattr(model, "package_meta", {}) or {}

    # Access layers / NAT rule counts from loaded model
    access_by_pkg = defaultdict(list)
    for layer in getattr(model, "access_layers", []) or []:
        if layer.get("origin") != "package":
            continue
        pkg = layer.get("package") or ""
        rules = layer.get("rules") or []
        access_by_pkg[pkg].append({
            "name": layer.get("layer"),
            "rules": sum(1 for r in rules if isinstance(r, dict) and r.get("type") == "access-rule"),
        })

    nat_by_pkg = {}
    for nat in getattr(model, "nat_layers", []) or []:
        pkg = nat.get("package") or ""
        rules = [r for r in (nat.get("rules") or []) if isinstance(r, dict) and r.get("type") == "nat-rule"]
        nat_by_pkg[pkg] = {"present": True, "rules": len(rules), "name": "NAT"}

    threat_by_pkg = defaultdict(list)
    for t in getattr(model, "threat_layers", []) or []:
        pkg = t.get("package") or ""
        threat_by_pkg[pkg].append({
            "name": t.get("layer"),
            "rules": len(t.get("rules") or []),
        })

    # Package name list: prefer packages.json, else meta keys + access keys
    names = []
    seen = set()
    for pkg in getattr(model, "packages", []) or []:
        if isinstance(pkg, dict) and pkg.get("name"):
            n = pkg["name"]
            if n not in seen:
                seen.add(n)
                names.append(n)
    for n in sorted(meta.keys()):
        if n not in seen:
            seen.add(n)
            names.append(n)
    for n in sorted(access_by_pkg.keys()):
        if n not in seen:
            seen.add(n)
            names.append(n)

    dossiers = []
    for pname in names:
        doc = meta.get(pname) or {}
        # Threat from package.json when threat_layers not loaded (appliance loader)
        threat = list(threat_by_pkg.get(pname) or [])
        if not threat:
            for nm in _layer_names(doc.get("threat-layers")):
                threat.append({"name": nm, "rules": None})

        access = list(access_by_pkg.get(pname) or [])
        if not access:
            for nm in _layer_names(doc.get("access-layers")):
                access.append({"name": nm, "rules": None})

        https = _https_layers(doc)
        meta_targets = _install_targets(model, doc)
        gateways = _gateways_for_package(model, pname, meta_targets)
        objects = _object_type_counts(run_dir, pname)

        dossiers.append({
            "name": pname,
            "uid": doc.get("uid") or next(
                (p.get("uid") for p in (getattr(model, "packages") or [])
                 if isinstance(p, dict) and p.get("name") == pname),
                None,
            ),
            "domain": (doc.get("domain") or {}).get("name") if isinstance(doc.get("domain"), dict) else "",
            "access_layers": access,
            "nat": nat_by_pkg.get(pname) or (
                {"present": bool(doc.get("nat-policy")), "rules": None, "name": "NAT"}
                if doc.get("nat-policy") else {"present": False, "rules": 0, "name": "NAT"}
            ),
            "threat_layers": threat,
            "https_layers": https,
            "gateways": gateways,
            "objects": objects,
            "object_total": sum(o["count"] for o in objects),
            "access_rule_total": sum((a.get("rules") or 0) for a in access),
            "search_text": " ".join([
                pname,
                " ".join(a.get("name") or "" for a in access),
                " ".join(gateways),
                " ".join(o["type"] for o in objects[:20]),
            ]).lower(),
        })

    dossiers.sort(key=lambda d: (d.get("name") or "").lower())
    return dossiers
