"""Read-only auditor for Checkpoint SmartConsole export completeness."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from collect_helpers import https_layer_refs
from collection_remediation import attach_remediation, format_remediation_text


def _flatten_access_rules(rulebase: list[Any]) -> list[dict[str, Any]]:
    """Recursively flatten access-section wrappers to yield access-rule dicts."""
    out: list[dict[str, Any]] = []
    for entry in rulebase or []:
        if not isinstance(entry, dict):
            continue
        etype = entry.get("type")
        if etype == "access-section":
            out.extend(_flatten_access_rules(entry.get("rulebase", [])))
        elif etype == "access-rule":
            out.append(entry)
    return out


def count_access_rules(doc: dict[str, Any]) -> int:
    """Return the true number of access rules, descending into sections."""
    return len(_flatten_access_rules(doc.get("rulebase", [])))


def check_rulebase_truncation(path: Path, doc: dict[str, Any]) -> dict[str, Any]:
    """Return completeness info for a rulebase JSON document."""
    total = doc.get("total", 0) or 0
    actual = count_access_rules(doc)
    return {
        "file": path.name,
        "layer": doc.get("layer", path.stem),
        "total": total,
        "fetched": actual,
        "missing": max(0, total - actual),
        "complete": actual >= total,
    }


def has_hit_counts(doc: dict[str, Any]) -> bool:
    """True if at least one rule carries a hits object."""
    for rule in _flatten_access_rules(doc.get("rulebase", [])):
        if isinstance(rule, dict) and "hits" in rule:
            return True
    return False


def has_https_rulebases(run_dir: Path) -> bool:
    """True if any HTTPS rulebase JSON exists under policy-by-package."""
    base = run_dir / "policy-by-package"
    if not base.exists():
        return False
    return any(base.rglob("https-rulebase-*.json"))


def packages_declare_https(run_dir: Path) -> list[str]:
    """Package names that reference HTTPS inspection layers in package.json."""
    names: list[str] = []
    base = run_dir / "policy-by-package"
    if not base.is_dir():
        return names
    for path in sorted(base.glob("*/package.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if https_layer_refs(doc):
            names.append(path.parent.name)
    return names


def has_object_nat_settings(run_dir: Path) -> bool:
    """True if any host/network/range object has nat-settings."""
    for fname in ("objects-hosts.json", "objects-networks.json", "objects-address-ranges.json"):
        path = run_dir / fname
        if not path.exists():
            continue
        for obj in json.loads(path.read_text(encoding="utf-8")):
            if isinstance(obj, dict) and "nat-settings" in obj:
                return True
    return False


def has_routing(run_dir: Path) -> bool:
    """True if Gaia routing companion data exists under routing/."""
    routing = run_dir / "routing"
    if not routing.is_dir():
        return False
    return any(routing.glob("*.json")) or any(routing.glob("*.show-route.txt"))


def has_where_used(run_dir: Path) -> bool:
    path = run_dir / "objects-where-used.json"
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    return bool(data)


def _threat_rules_exist(run_dir: Path) -> bool:
    base = run_dir / "policy-by-package"
    if not base.exists():
        return False
    for path in base.rglob("threat-rulebase-*.json"):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if (doc.get("total") or 0) > 0 or doc.get("rulebase"):
            return True
    return False


def has_threat_profile_blade_detail(run_dir: Path) -> bool:
    """True if at least one threat profile includes IPS/AV/Anti-Bot/TE settings."""
    path = run_dir / "objects-threat-profiles.json"
    if not path.exists():
        return False
    try:
        objs = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    if not isinstance(objs, list):
        return False
    keys = ("ips", "anti-bot", "anti-virus", "threat-emulation",
            "active-protections-configuration")
    return any(isinstance(o, dict) and any(k in o for k in keys) for o in objs)


def threat_rules_needing_exceptions(run_dir: Path) -> int:
    """Count threat rules that declare exceptions/exceptions-layer."""
    base = run_dir / "policy-by-package"
    if not base.exists():
        return 0
    count = 0
    for path in base.rglob("threat-rulebase-*.json"):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        def walk(rb):
            n = 0
            for e in rb or []:
                if not isinstance(e, dict):
                    continue
                if e.get("type") == "threat-section":
                    n += walk(e.get("rulebase", []))
                elif e.get("exceptions") or e.get("exceptions-layer"):
                    n += 1
            return n

        count += walk(doc.get("rulebase", []))
    return count


def has_threat_exception_exports(run_dir: Path) -> bool:
    base = run_dir / "policy-by-package"
    if not base.exists():
        return False
    return any(base.rglob("threat-exceptions-*.json"))


def find_orphan_packages(run_dir: Path) -> list[str]:
    """Return package names with no gateway access-policy-name reference."""
    gw_path = run_dir / "gateways-and-servers.json"
    installed: set[str] = set()
    if gw_path.exists():
        for gw in json.loads(gw_path.read_text(encoding="utf-8")):
            policy = gw.get("policy") or {}
            name = policy.get("access-policy-name")
            if name:
                installed.add(name)

    orphans: list[str] = []
    pkg_base = run_dir / "policy-by-package"
    if pkg_base.exists():
        for pkg_dir in pkg_base.iterdir():
            if pkg_dir.is_dir() and pkg_dir.name not in installed:
                orphans.append(pkg_dir.name)
    return sorted(orphans)


def audit_run(run_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return (flags, summary) for a run folder."""
    flags: list[dict[str, Any]] = []

    shared = run_dir / "access-layers-shared"
    truncated: list[dict[str, Any]] = []
    if shared.exists():
        for path in shared.glob("access-rulebase-*.json"):
            doc = json.loads(path.read_text(encoding="utf-8"))
            info = check_rulebase_truncation(path, doc)
            if not info["complete"]:
                truncated.append(info)
                flags.append({
                    "severity": "critical",
                    "category": "truncated-rulebase",
                    "file_path": str(path.relative_to(run_dir)),
                    "layer_or_object": info["layer"],
                    "expected": info["total"],
                    "actual": info["fetched"],
                    "detail": "missing {} rules".format(info["missing"]),
                })

    hit_count_present = False
    if shared.exists():
        for path in shared.glob("access-rulebase-*.json"):
            doc = json.loads(path.read_text(encoding="utf-8"))
            if has_hit_counts(doc):
                hit_count_present = True
                break
    if not hit_count_present:
        flags.append({
            "severity": "critical",
            "category": "missing-hit-counts",
            "file_path": "access-layers-shared/*",
            "layer_or_object": "all access layers",
            "expected": "hits object on rules",
            "actual": "none",
            "detail": "collector requests show-hits; re-collect or verify SMS hit-count retention",
        })

    if not has_https_rulebases(run_dir):
        declared = packages_declare_https(run_dir)
        flags.append({
            "severity": "warning",
            "category": "missing-https-rulebases",
            "file_path": "policy-by-package/*/https-rulebase-*.json",
            "layer_or_object": ", ".join(declared) or "all packages",
            "expected": "HTTPS inspection rulebase files",
            "actual": "none",
            "detail": (
                "Packages declare HTTPS layers but no https-rulebase-*.json — "
                "re-run collector v1.5.5+ (reads https-inspection-layers dict)"
                if declared else
                "HTTPS policy may not be configured, or re-collect with collector v1.5.5+"
            ),
        })

    if not has_object_nat_settings(run_dir):
        flags.append({
            "severity": "warning",
            "category": "missing-object-nat",
            "file_path": "objects-hosts.json",
            "layer_or_object": "hosts/networks/ranges",
            "expected": "nat-settings field",
            "actual": "none",
            "detail": "re-run with --full-objects",
        })

    if not has_where_used(run_dir):
        flags.append({
            "severity": "warning",
            "category": "missing-where-used",
            "file_path": "objects-where-used.json",
            "layer_or_object": "all objects",
            "expected": "native where-used reverse references",
            "actual": "none",
            "detail": "re-run with --where-used",
        })

    if not has_routing(run_dir):
        flags.append({
            "severity": "info",
            "category": "missing-routing",
            "file_path": "routing/",
            "layer_or_object": "all gateways",
            "expected": "Gaia show route per gateway",
            "actual": "none",
            "detail": "Management API cannot export live routes — use checkpoint_collect_routing.py or manual Gaia clish",
        })

    if _threat_rules_exist(run_dir) and not has_threat_profile_blade_detail(run_dir):
        flags.append({
            "severity": "warning",
            "category": "missing-threat-profile-detail",
            "file_path": "objects-threat-profiles.json",
            "layer_or_object": "threat profiles",
            "expected": "full IPS/AV/Anti-Bot/TE settings via show-threat-profile",
            "actual": "empty or name-only stubs",
            "detail": "show-threat-profiles often returns total>0 with empty objects[]; "
                      "collector v1.5.3+ recovers via show-objects + per-UID show-threat-profile",
        })

    need_exc = threat_rules_needing_exceptions(run_dir)
    if need_exc and not has_threat_exception_exports(run_dir):
        flags.append({
            "severity": "warning",
            "category": "missing-threat-exceptions",
            "file_path": "policy-by-package/*/threat-exceptions-*.json",
            "layer_or_object": "threat exception rulebases",
            "expected": "{} exception rulebase file(s)".format(need_exc),
            "actual": "none",
            "detail": "re-collect with collector v1.5.3+ (show-threat-rule-exception-rulebase)",
        })

    summary_path = run_dir / "collection-summary.csv"
    if summary_path.exists():
        with summary_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("status") == "error":
                    flags.append({
                        "severity": "warning",
                        "category": "collection-error",
                        "file_path": row.get("dataset", ""),
                        "layer_or_object": row.get("dataset", ""),
                        "expected": "ok",
                        "actual": "error",
                        "detail": row.get("note", ""),
                    })

    orphans = find_orphan_packages(run_dir)
    for pkg in orphans:
        flags.append({
            "severity": "info",
            "category": "orphan-package",
            "file_path": "policy-by-package/{}".format(pkg),
            "layer_or_object": pkg,
            "expected": "installed on at least one gateway",
            "actual": "no gateway references",
            "detail": "package has layers but no access-policy-name reference",
        })

    summary = {
        "run_dir": str(run_dir),
        "access_rulebases_checked": len(list(shared.glob("access-rulebase-*.json"))) if shared.exists() else 0,
        "truncated_rulebases": len(truncated),
        "hit_count_present": hit_count_present,
        "https_present": has_https_rulebases(run_dir),
        "object_nat_present": has_object_nat_settings(run_dir),
        "where_used_present": has_where_used(run_dir),
        "routing_present": has_routing(run_dir),
        "orphan_packages": orphans,
        "critical_flags": sum(1 for f in flags if f["severity"] == "critical"),
        "warning_flags": sum(1 for f in flags if f["severity"] == "warning"),
        "info_flags": sum(1 for f in flags if f["severity"] == "info"),
    }
    return attach_remediation(flags), summary


def write_report(run_dir: Path, flags: list[dict[str, Any]], summary: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / "audit-flags.csv"
    csv_rows = []
    for f in flags:
        row = {k: f[k] for k in (
            "severity", "category", "file_path", "layer_or_object", "expected", "actual", "detail")}
        rem = f.get("remediation") or {}
        row["remediation"] = format_remediation_text(rem)
        row["safe_to_ignore"] = "yes" if rem.get("safe_to_ignore") else "no"
        csv_rows.append(row)

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "severity", "category", "file_path", "layer_or_object",
                "expected", "actual", "detail", "remediation", "safe_to_ignore",
            ],
            quoting=csv.QUOTE_ALL,
        )
        writer.writeheader()
        writer.writerows(csv_rows)

    md_path = out_dir / "audit-report.md"
    lines = [
        "# Checkpoint Export Quality Audit Report",
        "",
        "**Run directory:** `{}`".format(summary["run_dir"]),
        "",
        "## Summary",
        "",
        "- Access rulebases checked: {}".format(summary["access_rulebases_checked"]),
        "- Truncated rulebases: {}".format(summary["truncated_rulebases"]),
        "- Hit counts present: {}".format(summary["hit_count_present"]),
        "- HTTPS rulebases present: {}".format(summary["https_present"]),
        "- Object NAT settings present: {}".format(summary["object_nat_present"]),
        "- Native where-used present: {}".format(summary["where_used_present"]),
        "- Gaia routing present: {}".format(summary["routing_present"]),
        "- Orphan packages: {}".format(", ".join(summary["orphan_packages"]) or "none"),
        "",
        "**Flags:** {} critical, {} warning, {} info".format(
            summary["critical_flags"], summary["warning_flags"], summary["info_flags"]),
        "",
        "## Flags",
        "",
    ]
    for sev in ("critical", "warning", "info"):
        sev_flags = [f for f in flags if f["severity"] == sev]
        if not sev_flags:
            continue
        lines.append("### {} ({})".format(sev.title(), len(sev_flags)))
        lines.append("")
        for f in sev_flags:
            lines.append(
                "- **{}** — `{}` ({}): expected {}, actual {}. {}".format(
                    f["category"], f["file_path"], f["layer_or_object"],
                    f["expected"], f["actual"], f["detail"]))
            rem = f.get("remediation") or {}
            if rem:
                lines.append("  - Remediation: {}".format(format_remediation_text(rem)))
        lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Audit Checkpoint export completeness")
    parser.add_argument("run_dir", help="Path to run-YYYYMMDD-HHMMSS folder")
    parser.add_argument("--output", default="output", help="Output directory for reports")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    out_dir = Path(args.output)
    flags, summary = audit_run(run_dir)
    write_report(run_dir, flags, summary, out_dir)
    print("Audit complete: {} critical, {} warning, {} info".format(
        summary["critical_flags"], summary["warning_flags"], summary["info_flags"]))
    print("Reports written to {}".format(out_dir.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
