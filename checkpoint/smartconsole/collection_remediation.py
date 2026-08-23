"""Remediation guidance for Checkpoint export quality audit flags."""
from __future__ import annotations

from typing import Any


def _cmd(*parts: str) -> str:
    return " \\\n  ".join(parts)


COLLECTOR_BASE = _cmd(
    "python checkpoint_collect_data.py",
    "--mgmt-ip <IP> --username <USER> --password <PASS>",
)

ROUTING_COLLECTOR = _cmd(
    "python checkpoint_collect_routing.py",
    "--run-dir run-YYYYMMDD-HHMMSS",
    "--username <GAIA_USER> --password <PASS>",
    "--output routing",
)

ROUTING_MANUAL = [
    "SSH to each gateway (Gaia clish) from a host that can reach gateway management IPs.",
    "Run: show route",
    "Run: show route static",
    "Run: show ipv6 route",
    "Run: show configuration static-route",
    "Optional: show arp / show vpn tunnels (skip if unknown on this Gaia version).",
    "Save each gateway output as routing/<gateway-name>.show-route.txt inside the run folder.",
    "Or run: python checkpoint_collect_routing.py --mop  (prints these steps).",
]


REMEDIATION_BY_CATEGORY: dict[str, dict[str, Any]] = {
    "missing-hit-counts": {
        "summary": "Rule hit counts are not in this export. The collector already requests show-hits:true.",
        "collector": COLLECTOR_BASE + " \\\n  --full-objects --where-used --verify-export --output .",
        "collector_note": "Re-run with current collector first. show-hits is on by default — no extra flag.",
        "manual": [
            "SmartConsole: SmartDashboard → Tracking → verify hit counting is enabled on the SMS.",
            "Confirm gateways have sent logs/hits to SMS recently (stale installs may show zero hits).",
            "Management API only returns hits if SMS has retained them — not a collector bug if SMS has none.",
        ],
        "safe_to_ignore": False,
    },
    "missing-object-nat": {
        "summary": "Object-level NAT settings (nat-settings on hosts/networks/ranges) need full object detail.",
        "collector": COLLECTOR_BASE + " \\\n  --full-objects --where-used --verify-export --output .",
        "collector_note": "Required flag: --full-objects",
        "manual": [],
        "safe_to_ignore": False,
    },
    "missing-where-used": {
        "summary": "Native reverse-reference (where-used) data was not collected.",
        "collector": COLLECTOR_BASE + " \\\n  --full-objects --where-used --verify-export --output .",
        "collector_note": "Required flag: --where-used (slower — one API call per object).",
        "manual": [
            "Relationships page still infers references from rulebases without this pass.",
            "Use --where-used when you need ground-truth SmartConsole where-used parity.",
        ],
        "safe_to_ignore": True,
    },
    "missing-https-rulebases": {
        "summary": "No HTTPS inspection rulebase files in the export.",
        "collector": COLLECTOR_BASE + " \\\n  --full-objects --verify-export --output .",
        "collector_note": "Requires collector v1.5.5+ (reads https-inspection-layers dict when policy is a bool).",
        "manual": [
            "If still empty after 1.5.5: HTTPS inspection may not be assigned to any policy package.",
            "SmartConsole: verify Default Inbound/Outbound HTTPS layers exist and are bound to packages.",
        ],
        "safe_to_ignore": True,
    },
    "missing-threat-profile-detail": {
        "summary": "Threat Prevention profiles lack IPS/Anti-Bot/Anti-Virus/TE blade settings.",
        "collector": COLLECTOR_BASE + " \\\n  --verify-export --output .",
        "collector_note": "Requires collector v1.5.3+ (enriches via show-threat-profile per UID).",
        "manual": [
            "Rule-level profile assignment still appears on Threat Prevention page.",
            "Blade confidence/action settings need a live SmartCenter re-collect.",
        ],
        "safe_to_ignore": False,
    },
    "missing-threat-exceptions": {
        "summary": "Threat rules declare exceptions, but exception rulebases were not exported.",
        "collector": COLLECTOR_BASE + " \\\n  --verify-export --output .",
        "collector_note": "Requires collector v1.5.6+ (layer-name first; layer-uid only if API asks).",
        "manual": [
            "Parent TP rules still list exception UID counts until re-collected.",
        ],
        "safe_to_ignore": False,
    },
    "truncated-rulebase": {
        "summary": "An access rulebase has fewer rules than the API total field reports.",
        "collector": COLLECTOR_BASE + " \\\n  --full-objects --where-used --verify-export --output .",
        "collector_note": "Re-collect with current collector (hardened pagination).",
        "manual": [],
        "safe_to_ignore": False,
    },
    "missing-routing": {
        "summary": "Live Gaia routing tables are not in this bundle. The Management API does not expose them.",
        "collector": ROUTING_COLLECTOR,
        "collector_note": "Companion script — requires SSH to each gateway (not SmartCenter API).",
        "manual": ROUTING_MANUAL,
        "safe_to_ignore": True,
    },
    "orphan-package": {
        "summary": "Policy package exists but no gateway references it as access-policy-name.",
        "collector": None,
        "collector_note": None,
        "manual": [
            "Often a draft or decommissioned package — verify in SmartConsole before deleting.",
        ],
        "safe_to_ignore": True,
    },
}


def _remediation_collection_error(flag: dict[str, Any]) -> dict[str, Any]:
    dataset = (flag.get("file_path") or flag.get("layer_or_object") or "").lower()
    detail = (flag.get("detail") or "").lower()

    if "administrators" in dataset and "inappropriate_domain_type" in detail:
        return {
            "summary": "show-administrators only works on an MDS domain — not on a single-domain SMS/CMA.",
            "collector": None,
            "collector_note": "No action needed on single-domain management.",
            "manual": [
                "This error is expected on non-MDS SmartCenter / domain servers.",
                "Administrator inventory is not required for policy/object audit.",
            ],
            "safe_to_ignore": True,
        }

    if "err_" in detail or "failed" in detail:
        return {
            "summary": "A collector API call failed for this dataset.",
            "collector": COLLECTOR_BASE + " \\\n  --verify-export --output .",
            "collector_note": "Re-run collector; check API user permissions and Management API version.",
            "manual": [
                "Verify API user has read permissions for this object type.",
                "Check collection-summary.csv note field for the full API error message.",
            ],
            "safe_to_ignore": False,
        }

    return {
        "summary": flag.get("detail") or "Collection error — see detail column.",
        "collector": COLLECTOR_BASE + " \\\n  --verify-export --output .",
        "collector_note": None,
        "manual": [],
        "safe_to_ignore": False,
    }


def remediation_for_flag(flag: dict[str, Any]) -> dict[str, Any]:
    """Return structured remediation guidance for one audit flag."""
    category = flag.get("category", "")
    if category == "collection-error":
        base = _remediation_collection_error(flag)
    else:
        base = dict(REMEDIATION_BY_CATEGORY.get(category, {
            "summary": flag.get("detail") or "See collector README.",
            "collector": COLLECTOR_BASE + " \\\n  --verify-export --output .",
            "collector_note": None,
            "manual": [],
            "safe_to_ignore": False,
        }))
    base.setdefault("category", category)
    return base


def attach_remediation(flags: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return flags with a remediation dict attached to each entry."""
    out: list[dict[str, Any]] = []
    for flag in flags:
        enriched = dict(flag)
        enriched["remediation"] = remediation_for_flag(flag)
        out.append(enriched)
    return out


def build_recollect_command(flags: list[dict[str, Any]]) -> str:
    """Build a minimal re-collect command based on active audit flags."""
    categories = {f.get("category") for f in flags}
    severities = {f.get("severity") for f in flags}
    needs_fix = bool(categories & {
        "missing-hit-counts", "missing-object-nat", "missing-where-used",
        "missing-https-rulebases", "truncated-rulebase", "collection-error",
    })
    if not needs_fix and "warning" not in severities and "critical" not in severities:
        return COLLECTOR_BASE + " \\\n  --verify-export --output ."

    extras: list[str] = []
    if "missing-object-nat" in categories:
        extras.append("--full-objects")
    if "missing-where-used" in categories:
        extras.append("--where-used")
    if needs_fix or extras:
        extras.append("--verify-export")
    extras.append("--output .")
    return COLLECTOR_BASE + " \\\n  " + " \\\n  ".join(extras)


def format_remediation_text(rem: dict[str, Any]) -> str:
    """Plain-text remediation block for markdown / CSV."""
    lines = [rem.get("summary") or ""]
    if rem.get("collector"):
        lines.append("Collector: " + rem["collector"].replace("\n", " "))
    if rem.get("collector_note"):
        lines.append(rem["collector_note"])
    for step in rem.get("manual") or []:
        lines.append("Manual: " + step)
    if rem.get("safe_to_ignore"):
        lines.append("(Safe to ignore for policy/object audit)")
    return " ".join(s for s in lines if s)


def format_remediation_html(rem: dict[str, Any]) -> str:
    """HTML snippet for the coverage page How to fix column."""
    parts: list[str] = []
    if rem.get("summary"):
        parts.append("<div>{}</div>".format(_esc(rem["summary"])))
    if rem.get("safe_to_ignore"):
        parts.append('<span class="badge">safe to ignore</span>')
    if rem.get("collector"):
        parts.append(
            '<div class="muted" style="margin-top:6px"><b>Collector (Python)</b></div>'
            '<pre class="mono" style="white-space:pre-wrap;margin:4px 0;padding:8px;'
            'background:#1a1f2e;border-radius:6px;font-size:12px">{}</pre>'.format(
                _esc(rem["collector"])))
    if rem.get("collector_note"):
        parts.append('<div class="muted">{}</div>'.format(_esc(rem["collector_note"])))
    manual = rem.get("manual") or []
    if manual:
        parts.append('<div class="muted" style="margin-top:6px"><b>Manual / Gaia / SmartConsole</b></div><ul>')
        for step in manual:
            parts.append("<li>{}</li>".format(_esc(step)))
        parts.append("</ul>")
    return "".join(parts)


def _esc(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
