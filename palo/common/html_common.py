"""Shared HTML page builders for Palo Alto standalone and Panorama browsers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from core.html_site import SiteBuilder, esc, sev_badge

if TYPE_CHECKING:
    from palo_model import PaloPanoramaModel, PaloStandaloneModel


def safe_name(name: str) -> str:
    return re.sub(r"[^\w\-.]+", "_", str(name)).strip("_") or "unnamed"


def tmpl_link(name: str, *, prefix: str = "") -> str:
    if not name:
        return "—"
    return f'<a href="{prefix}templates/{safe_name(name)}.html">{esc(name)}</a>'


def stack_link(name: str, *, prefix: str = "") -> str:
    if not name:
        return "—"
    return f'<a href="{prefix}template-stacks.html#{safe_name(name)}">{esc(name)}</a>'


def action_tag(action: str) -> str:
    a = (action or "").lower()
    if a in ("allow", "accept", "decrypt"):
        cls = "t-accept"
    elif a in ("deny", "drop", "no-decrypt"):
        cls = "t-drop"
    else:
        cls = "t-other"
    return f'<span class="tag {cls}">{esc(action or "—")}</span>'


def disabled_tag(disabled: bool) -> str:
    if disabled:
        return '<span class="tag t-drop">disabled</span>'
    return '<span class="tag t-accept">active</span>'


SHARED_SCOPE = "Shared"

# One wording for the whole report so no two pages imply different arithmetic.
BASIS_DEFINITIONS = (
    "<b>Counting basis:</b> one row per object <b>definition</b> (device group + name), "
    "the way PAN-OS stores it — the same name defined in several device groups is "
    "several rows. Distinct-name totals are on the Dashboard."
)


def scope_cell(scope: str) -> str:
    """Scope column. Shared is a namespace every device group inherits from, so it
    is badged rather than shown as if it were just another device group."""
    if scope == SHARED_SCOPE:
        return '<span class="tag t-other">Shared</span>'
    return esc(scope or "—")


def dg_cell(dg_name: str, *, prefix: str = "") -> str:
    """Device-group link that degrades when Panorama manages a firewall no device
    group claims (link target would not exist)."""
    if not dg_name:
        return '<span class="tag t-other">unassigned</span>'
    return f"<a href='{prefix}device-groups/{safe_name(dg_name)}.html'>{esc(dg_name)}</a>"


def yes_no_tag(value: str, *, good: str = "yes") -> str:
    v = (value or "").strip().lower()
    if not v:
        return "—"
    cls = "t-accept" if v == good else "t-drop"
    return f'<span class="tag {cls}">{esc(v)}</span>'


def snapshot_gaps(model) -> list[str]:
    """Branches a pre-1.5.0 collector never fetched. Saying so beats blank cells."""
    gaps: list[str] = []
    if not getattr(model, "has_shared", True):
        gaps.append(
            "<b>No <code>&lt;shared&gt;</code> branch in this snapshot.</b> Panorama's shared "
            "namespace holds most objects on a typical estate; without it, object counts, "
            "unused-object analysis and rule resolution all cover device-group scope only. "
            "Re-collect with collector 1.5.0 or newer."
        )
    if not getattr(model, "has_template_stacks", True):
        gaps.append(
            "<b>No <code>&lt;template-stack&gt;</code> branch in this snapshot.</b> Template "
            "stacks, their member templates and their device assignments are unavailable. "
            "Re-collect with collector 1.5.0 or newer."
        )
    if not getattr(model, "has_operational_devices", True):
        gaps.append(
            "<b>No operational device facts in this snapshot.</b> Hostname, model, software "
            "version, HA state and connection status come from <code>show devices all</code>, "
            "collected since 1.5.0. Hostnames shown are guessed from the first site template "
            "in each stack. Re-collect with collector 1.5.0 or newer."
        )
    return gaps


def gap_note(model) -> str:
    gaps = snapshot_gaps(model)
    if not gaps:
        return ""
    items = "".join(f"<li>{g}</li>" for g in gaps)
    return f'<div class="note">Snapshot is incomplete:<ul>{items}</ul></div>'


def table_page(site: SiteBuilder, rel: str, title: str, headers: list[str], rows: list[str], note: str = "") -> None:
    body = f"<h2>{esc(title)}</h2>"
    if note:
        body += f'<div class="note">{note}</div>'
    body += site.searchbox("tbl", "cnt") + '<div class="meta"><span id="cnt"></span></div>'
    body += site.table("tbl", headers, rows)
    site.page(rel, title, body)


STANDALONE_NAV = [
    ("index.html", "Dashboard"),
    ("group", "Policy"),
    ("rules.html", "Security rules"),
    ("nat.html", "NAT"),
    ("group", "Objects"),
    ("addresses.html", "Addresses"),
    ("address-groups.html", "Address groups"),
    ("services.html", "Services"),
    ("service-groups.html", "Service groups"),
    ("zones.html", "Zones"),
    ("group", "Routing"),
    ("routes.html", "Static routes"),
    ("group", "Audit"),
    ("unused.html", "Unused objects"),
    ("optimization.html", "Optimization"),
]

PANORAMA_NAV = [
    ("index.html", "Dashboard"),
    ("group", "Overview"),
    ("panorama.html", "Panorama View"),
    ("device-groups.html", "Device Groups"),
    ("devices.html", "Managed Firewalls"),
    ("relationships.html", "Relationships"),
    ("group", "Network (templates)"),
    ("templates.html", "Templates"),
    ("template-stacks.html", "Template stacks"),
    ("vsys.html", "Virtual systems"),
    ("interfaces.html", "Interfaces"),
    ("virtual-routers.html", "Virtual routers"),
    ("ha-variables.html", "HA variables"),
    ("group", "VPN"),
    ("globalprotect.html", "GlobalProtect"),
    ("ipsec.html", "IPsec / IKE"),
    ("group", "Policy"),
    ("rules.html", "Security rules"),
    ("nat.html", "NAT"),
    ("decrypt.html", "Decryption"),
    ("app-override.html", "App override"),
    ("group", "Objects"),
    ("addresses.html", "Addresses"),
    ("address-groups.html", "Address groups"),
    ("services.html", "Services"),
    ("service-groups.html", "Service groups"),
    ("applications.html", "Applications"),
    ("application-filters.html", "Application filters"),
    ("tags.html", "Tags"),
    ("schedules.html", "Schedules"),
    ("certificates.html", "Certificates"),
    ("certificate-profiles.html", "Certificate profiles"),
    ("decrypt-exclusions.html", "Decryption exclusions"),
    ("panorama-admin.html", "Panorama admin"),
    ("edls.html", "External lists"),
    ("profiles.html", "Security profiles"),
    ("log-forwarding.html", "Log forwarding"),
    ("zones.html", "Zones"),
    ("group", "Routing"),
    ("routes.html", "Static routes"),
    ("bgp.html", "BGP"),
    ("ospf.html", "OSPF"),
    ("group", "Audit"),
    ("unused.html", "Unused objects"),
    ("optimization.html", "Optimization"),
]


def _build_shared_object_pages(site: SiteBuilder, model) -> None:
    """Object classes that live almost entirely in Panorama's shared namespace.

    None of these had a page before collector 1.5.0 because <shared> was never
    collected, so there was nothing to show. Each table states its counting basis.
    """
    def _scope(row: dict) -> str:
        return row.get("scope") or row.get("device_group") or ""

    def _basis_line(rows: list[dict], what: str) -> str:
        distinct = len({(r.get("name") or "").lower() for r in rows if r.get("name")})
        shared = sum(1 for r in rows if _scope(r) == SHARED_SCOPE)
        return (
            f"{BASIS_DEFINITIONS} This table has <b>{len(rows)}</b> {what} definitions "
            f"across <b>{distinct}</b> distinct names; <b>{shared}</b> are defined in "
            f"the <b>Shared</b> namespace and are visible to every device group."
        )

    apps = sorted(getattr(model, "applications", []), key=lambda x: (_scope(x).lower(), x["name"].lower()))
    app_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(a))}</td>"
        f"<td>{esc(a['name'])}</td>"
        f"<td>{esc(a.get('category') or '—')}</td>"
        f"<td>{esc(a.get('subcategory') or '—')}</td>"
        f"<td>{esc(a.get('technology') or '—')}</td>"
        f"<td>{esc(a.get('risk') or '—')}</td>"
        f"<td class='mono'>{esc(a.get('default') or '—')}</td>"
        f"<td>{esc(a.get('description') or '—')}</td></tr>"
        for a in apps
    ]
    table_page(
        site, "applications.html", "Applications",
        ["Device group / scope", "Name", "Category", "Subcategory", "Technology", "Risk", "Default", "Description"],
        app_rows,
        note="Custom (user-defined) applications only — PAN-OS predefined App-IDs are not "
             "part of the configuration and are not collected. " + _basis_line(apps, "application"),
    )

    groups = sorted(getattr(model, "application_groups", []), key=lambda x: (_scope(x).lower(), x["name"].lower()))
    filters = sorted(getattr(model, "application_filters", []), key=lambda x: (_scope(x).lower(), x["name"].lower()))
    filt_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(g))}</td>"
        f"<td>application-group</td>"
        f"<td>{esc(g['name'])}</td>"
        f"<td>{g.get('member_count', 0)}</td>"
        f"<td class='mono'>{esc(', '.join(g.get('members', [])[:12]))}"
        f"{' …' if len(g.get('members', [])) > 12 else ''}</td></tr>"
        for g in groups
    ]
    filt_rows += [
        "<tr>"
        f"<td>{scope_cell(_scope(f))}</td>"
        f"<td>application-filter</td>"
        f"<td>{esc(f['name'])}</td>"
        f"<td>{f.get('criteria_count', 0)}</td>"
        f"<td class='mono'>{esc(f.get('criteria') or '—')}</td></tr>"
        for f in filters
    ]
    table_page(
        site, "application-filters.html", "Application groups & filters",
        ["Device group / scope", "Kind", "Name", "Members / criteria", "Detail"],
        filt_rows,
        note="A group lists applications by name; a filter selects them dynamically by "
             "attribute (category, subcategory, technology, risk), so a filter's membership "
             "changes with each content update. " + _basis_line(groups + filters, "group/filter"),
    )

    tags = sorted(getattr(model, "tags", []), key=lambda x: (_scope(x).lower(), x["name"].lower()))
    tag_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(t))}</td>"
        f"<td>{esc(t['name'])}</td>"
        f"<td>{esc(t.get('color') or '—')}</td>"
        f"<td>{esc(t.get('comments') or '—')}</td></tr>"
        for t in tags
    ]
    table_page(
        site, "tags.html", "Tags",
        ["Device group / scope", "Name", "Color", "Comments"], tag_rows,
        note="Tags are excluded from the unused-object analysis: they are referenced from "
             "object and rule metadata this report does not index per object, so calling a "
             "tag unused would be a guess. " + _basis_line(tags, "tag"),
    )

    scheds = sorted(getattr(model, "schedules", []), key=lambda x: (_scope(x).lower(), x["name"].lower()))
    sched_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(sc))}</td>"
        f"<td>{esc(sc['name'])}</td>"
        f"<td>{esc(sc.get('schedule_type') or '—')}</td>"
        f"<td class='mono'>{esc(sc.get('detail') or '—')}</td></tr>"
        for sc in scheds
    ]
    table_page(
        site, "schedules.html", "Schedules",
        ["Device group / scope", "Name", "Type", "Window"], sched_rows,
        note="Time windows a security rule can be restricted to. " + _basis_line(scheds, "schedule"),
    )


    # --- Certificates -------------------------------------------------------
    # These were collected but had no page until 1.5.1: an audit of rendered vs
    # collected names found 20 certificates and 7 certificate profiles present
    # in the snapshot and absent from every page. They are load-bearing for a
    # migration — GlobalProtect, SSL forward-proxy decryption, IPsec IKE, EDL
    # hosting and admin auth all reference them.
    import datetime as _dt

    def _expiry_cell(c: dict) -> str:
        raw = c.get("not_valid_after") or ""
        if not raw:
            return "<td>—</td>"
        days = None
        for fmt in ("%b %d %H:%M:%S %Y GMT", "%Y/%m/%d %H:%M:%S"):
            try:
                days = (_dt.datetime.strptime(raw.strip(), fmt) - _dt.datetime(2026, 8, 22)).days
                break
            except ValueError:
                continue
        if days is None:
            return f"<td class='mono'>{esc(raw)}</td>"
        if days < 0:
            return f"<td class='mono'><span class='badge b-red'>EXPIRED</span> {esc(raw)}</td>"
        if days < 90:
            return f"<td class='mono'><span class='badge b-amber'>{days}d</span> {esc(raw)}</td>"
        return f"<td class='mono'>{esc(raw)}</td>"

    certs = sorted(getattr(model, "certificates", []),
                   key=lambda x: (_scope(x).lower(), x["name"].lower()))
    cert_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(c))}</td>"
        f"<td>{esc(c['name'])}</td>"
        f"<td>{'CA' if c.get('ca') else 'leaf'}</td>"
        f"<td>{'yes' if c.get('has_private_key') else 'no'}</td>"
        f"<td class='mono'>{esc(c.get('subject') or c.get('common_name') or '—')}</td>"
        f"<td class='mono'>{esc(c.get('issuer') or '—')}</td>"
        + _expiry_cell(c) + "</tr>"
        for c in certs
    ]
    table_page(
        site, "certificates.html", "Certificates",
        ["Device group / scope", "Name", "Type", "Private key",
         "Subject / CN", "Issuer", "Not valid after"],
        cert_rows,
        note="GlobalProtect, SSL forward-proxy decryption, IPsec IKE, EDL hosting and "
             "admin authentication all reference these by name — a certificate that has "
             "no equivalent on the target platform is a cutover outage, not a cosmetic "
             "gap. Expiry is flagged because an already-expired certificate in a source "
             "config is a finding. "
             + _basis_line(certs, "certificate"),
    )

    cprofs = sorted(getattr(model, "certificate_profiles", []),
                    key=lambda x: (_scope(x).lower(), x["name"].lower()))
    cprof_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(cp))}</td>"
        f"<td>{esc(cp['name'])}</td>"
        f"<td class='mono'>{esc(', '.join(cp.get('ca_certificates') or []) or '—')}</td>"
        f"<td>{'yes' if cp.get('crl') else 'no'}</td>"
        f"<td>{'yes' if cp.get('ocsp') else 'no'}</td></tr>"
        for cp in cprofs
    ]
    table_page(
        site, "certificate-profiles.html", "Certificate profiles",
        ["Device group / scope", "Name", "CA certificates", "CRL", "OCSP"],
        cprof_rows,
        note="The CA set an authentication flow trusts. Referenced by GlobalProtect "
             "authentication and by admin auth. "
             + _basis_line(cprofs, "certificate profile"),
    )

    # --- Panorama admin -----------------------------------------------------
    # Admin roles, report groups and log collectors were collected from 1.5.0 but
    # rendered nowhere until 1.5.1. RBAC in particular has to be recreated on a
    # target platform, so it belongs in a migration view.
    roles = sorted(getattr(model, "admin_roles", []),
                   key=lambda x: (_scope(x).lower(), x["name"].lower()))
    role_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(r))}</td>"
        f"<td>{esc(r['name'])}</td>"
        f"<td>{esc(r.get('role_type') or '—')}</td></tr>"
        for r in roles
    ]
    rgs = sorted(getattr(model, "report_groups", []),
                 key=lambda x: (_scope(x).lower(), x["name"].lower()))
    rg_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(g))}</td>"
        f"<td>{esc(g['name'])}</td>"
        f"<td class='mono'>{esc(', '.join(g.get('members') or []) or '—')}</td></tr>"
        for g in rgs
    ]
    lcs = sorted(getattr(model, "log_collectors", []), key=lambda x: x["name"])
    lc_rows = [
        "<tr>"
        f"<td class='mono'>{esc(l['name'])}</td>"
        f"<td>{esc(l.get('hostname') or '—')}</td>"
        f"<td class='mono'>{esc(l.get('ip') or '—')}</td></tr>"
        for l in lcs
    ]

    excl = sorted(getattr(model, "decrypt_exclusions", []),
                  key=lambda x: (_scope(x).lower(), x["name"].lower()))
    excl_rows = [
        "<tr>"
        f"<td>{scope_cell(_scope(x))}</td>"
        f"<td class='mono'>{esc(x['name'])}</td>"
        f"<td>{'excluded' if x.get('exclude') else 'not excluded'}</td>"
        f"<td>{esc(x.get('description') or '—')}</td></tr>"
        for x in excl
    ]
    table_page(
        site, "decrypt-exclusions.html", "Decryption exclusions",
        ["Template / scope", "Host / certificate", "State", "Description"],
        excl_rows,
        note="Traffic that deliberately bypasses SSL inspection. This is a documented "
             "security decision, not a technicality — the target platform needs an "
             "equivalent list or the posture changes silently at cutover. "
             + _basis_line(excl, "exclusion"),
    )
    body = "<h2>Panorama admin</h2>"
    body += (
        '<div class="note">Panorama\'s own administrative configuration rather than '
        "customer policy. Administrator roles are included because RBAC has to be "
        "recreated on a target platform; report groups and log collectors are estate "
        "inventory. Collected since 1.5.0, rendered since 1.5.1.</div>"
    )
    body += "<h3>Administrator roles</h3>"
    body += site.table("roles", ["Scope", "Name", "Role type"], role_rows)
    body += "<h3>Report groups</h3>"
    body += site.table("rgs", ["Scope", "Name", "Members"], rg_rows)
    body += "<h3>Log collectors</h3>"
    body += site.table("lcs", ["Serial", "Hostname", "IP"], lc_rows)
    site.page("panorama-admin.html", "Panorama admin", body)


def _defs_and_distinct(st: dict, key: str) -> str:
    """Card number that states both bases at once: definitions [distinct names].

    The collector counts object DEFINITIONS per scope; the appliance counts distinct
    names. Showing one and calling it "addresses" is what made the two disagree, so
    show both and label them.
    """
    defs = st.get(key, 0)
    distinct = st.get(f"{key}_distinct")
    if distinct is None:
        return str(defs)
    return f"{defs} [{distinct}]"


def build_inventory_pages(site: SiteBuilder, model, *, panorama: bool) -> None:
    scope_hdr = "Device group" if panorama else "Vsys"
    # Objects can also live in Panorama's Shared namespace, which is not a
    # device group — the object tables say "scope" so the column is honest.
    obj_scope_hdr = "Device group / scope" if panorama else "Vsys"

    rule_rows = []
    for r in model.rules:
        scope = scope_cell(r.get("device_group") or r.get("vsys") or "")
        rule_rows.append(
            "<tr>"
            f"<td>{scope}</td>"
            f"<td>{esc(r.get('rulebase', ''))}</td>"
            f"<td>{esc(r['name'])}</td>"
            f"<td>{esc(r['from'])}</td><td>{esc(r['to'])}</td>"
            f"<td>{esc(r['source'])}</td><td>{esc(r['destination'])}</td>"
            f"<td>{esc(r.get('application', 'any'))}</td>"
            f"<td>{esc(r['service'])}</td>"
            f"<td>{esc(r.get('profiles') or '—')}</td>"
            f"<td>{disabled_tag(r.get('disabled', False))}</td>"
            f"<td>{action_tag(r['action'])}</td></tr>"
        )
    table_page(
        site,
        "rules.html",
        "Security rules",
        [scope_hdr, "Rulebase", "Name", "From", "To", "Source", "Destination", "Application", "Service", "Profiles", "State", "Action"],
        rule_rows,
    )

    nat_rows = []
    for n in model.nat_rules:
        scope = scope_cell(n.get("device_group") or n.get("vsys") or "")
        nat_rows.append(
            "<tr>"
            f"<td>{scope}</td>"
            f"<td>{esc(n.get('rulebase', ''))}</td>"
            f"<td>{esc(n['name'])}</td>"
            f"<td>{esc(n['from'])}</td><td>{esc(n['to'])}</td>"
            f"<td>{esc(n['source'])}</td><td>{esc(n['destination'])}</td>"
            f"<td>{esc(n['service'])}</td>"
            f"<td class='mono'>{esc(n.get('source_translation') or '—')}</td>"
            f"<td class='mono'>{esc(n.get('dest_translation') or '—')}</td></tr>"
        )
    table_page(
        site,
        "nat.html",
        "NAT",
        [scope_hdr, "Rulebase", "Name", "From", "To", "Source", "Destination", "Service", "Src Xlate", "Dst Xlate"],
        nat_rows,
    )

    if panorama:
        dec_rows = []
        for d in model.decrypt_rules:
            dec_rows.append(
                "<tr>"
                f"<td>{scope_cell(d.get('device_group') or '')}</td>"
                f"<td>{esc(d.get('rulebase', ''))}</td>"
                f"<td>{esc(d['name'])}</td>"
                f"<td>{esc(d['from'])}</td><td>{esc(d['to'])}</td>"
                f"<td>{esc(d['source'])}</td><td>{esc(d['destination'])}</td>"
                f"<td>{esc(d.get('decrypt_type') or '—')}</td>"
                f"<td>{disabled_tag(d.get('disabled', False))}</td>"
                f"<td>{action_tag(d.get('action', ''))}</td></tr>"
            )
        table_page(
            site,
            "decrypt.html",
            "Decryption",
            [scope_hdr, "Rulebase", "Name", "From", "To", "Source", "Destination", "Type", "State", "Action"],
            dec_rows,
        )
        edl_rows = [
            "<tr>"
            f"<td>{scope_cell(e.get('device_group') or '')}</td>"
            f"<td>{esc(e['name'])}</td>"
            f"<td>{esc(e.get('edl_type') or '—')}</td>"
            f"<td class='mono'>{esc(e.get('url') or '—')}</td></tr>"
            for e in model.edls
        ]
        table_page(
            site,
            "edls.html",
            "External Dynamic Lists",
            [scope_hdr, "Name", "Type", "URL"],
            edl_rows,
        )
        apo_rows = [
            "<tr>"
            f"<td>{scope_cell(a.get('device_group') or '')}</td>"
            f"<td>{esc(a.get('rulebase', ''))}</td>"
            f"<td>{esc(a['name'])}</td>"
            f"<td>{esc(a['from'])}</td><td>{esc(a['to'])}</td>"
            f"<td>{esc(a['source'])}</td><td>{esc(a['destination'])}</td>"
            f"<td>{esc(a.get('protocol') or '—')}</td>"
            f"<td>{esc(a.get('port') or '—')}</td>"
            f"<td>{esc(a.get('application') or '—')}</td>"
            f"<td>{disabled_tag(a.get('disabled', False))}</td></tr>"
            for a in model.app_overrides
        ]
        table_page(
            site,
            "app-override.html",
            "Application override",
            [scope_hdr, "Rulebase", "Name", "From", "To", "Source", "Destination", "Proto", "Port", "Application", "State"],
            apo_rows,
            note="Forces App-ID for matching sessions (common for backup/storage protocols).",
        )
        prof_rows = [
            "<tr>"
            f"<td>{scope_cell(p.get('scope') or '')}</td>"
            f"<td>{esc(p.get('kind') or '—')}</td>"
            f"<td>{esc(p['name'])}</td>"
            f"<td>{esc(p.get('members') or '—')}</td></tr>"
            for p in model.security_profiles
        ]
        table_page(
            site,
            "profiles.html",
            "Security profiles",
            [scope_hdr, "Kind", "Name", "Members / notes"],
            prof_rows,
            note="Antivirus, anti-spyware, vulnerability, URL filtering, file blocking, WildFire, decryption profiles, custom URL categories, and profile groups.",
        )
        lf_rows = [
            "<tr>"
            f"<td>{scope_cell(p.get('scope') or '')}</td>"
            f"<td>{esc(p.get('kind') or '—')}</td>"
            f"<td>{esc(p['name'])}</td>"
            f"<td>{p.get('match_count', 0)}</td>"
            f"<td>{esc(p.get('matches') or '—')}</td></tr>"
            for p in model.log_forwarding
        ]
        table_page(
            site,
            "log-forwarding.html",
            "Log forwarding",
            [scope_hdr, "Kind", "Name", "Matches", "Destinations"],
            lf_rows,
            note="Device-group log-forwarding profiles plus Panorama collector-group match lists (syslog / email / panorama).",
        )

    def _scope_of(row: dict) -> str:
        return row.get("device_group") or row.get("vsys") or row.get("scope") or ""

    def _basis(model_obj, defs_key: str, distinct_key: str, what: str) -> str:
        """Per-page counting-basis footnote, with the two totals stated explicitly."""
        st_ = getattr(model_obj, "stats", {}) or {}
        defs = st_.get(defs_key)
        distinct = st_.get(distinct_key)
        counts = ""
        if defs is not None and distinct is not None:
            counts = (
                f" This table has <b>{defs}</b> {what} definitions across "
                f"<b>{distinct}</b> distinct names."
            )
        return BASIS_DEFINITIONS + counts

    addr_rows = []
    for a in sorted(model.addresses, key=lambda x: (_scope_of(x).lower(), x["name"].lower())):
        addr_rows.append(
            f"<tr><td>{scope_cell(_scope_of(a))}</td><td>{esc(a['name'])}</td>"
            f"<td class='mono'>{esc(a['value'])}</td></tr>"
        )
    table_page(
        site, "addresses.html", "Addresses",
        [obj_scope_hdr, "Name", "Value"], addr_rows,
        note=_basis(model, "addresses", "addresses_distinct", "address") if panorama else "",
    )

    ag_rows = []
    for g in sorted(model.address_groups, key=lambda x: (_scope_of(x).lower(), x["name"].lower())):
        ag_rows.append(
            f"<tr><td>{scope_cell(_scope_of(g))}</td><td>{esc(g['name'])}</td><td>{g['member_count']}</td>"
            f"<td>{esc(', '.join(g['members'][:12]))}{' …' if len(g['members']) > 12 else ''}</td></tr>"
        )
    table_page(
        site, "address-groups.html", "Address groups",
        [obj_scope_hdr, "Name", "Members", "Member list"], ag_rows,
        note=_basis(model, "address_groups", "address_groups_distinct", "address-group") if panorama else "",
    )

    svc_rows = []
    for sv in sorted(model.services, key=lambda x: (_scope_of(x).lower(), x["name"].lower())):
        svc_rows.append(
            f"<tr><td>{scope_cell(_scope_of(sv))}</td><td>{esc(sv['name'])}</td>"
            f"<td class='mono'>{esc(sv['value'])}</td></tr>"
        )
    table_page(
        site, "services.html", "Services",
        [obj_scope_hdr, "Name", "Value"], svc_rows,
        note=_basis(model, "services", "services_distinct", "service") if panorama else "",
    )

    sg_rows = []
    for g in sorted(model.service_groups, key=lambda x: (_scope_of(x).lower(), x["name"].lower())):
        sg_rows.append(
            f"<tr><td>{scope_cell(_scope_of(g))}</td><td>{esc(g['name'])}</td><td>{g['member_count']}</td>"
            f"<td>{esc(', '.join(g['members'][:12]))}{' …' if len(g['members']) > 12 else ''}</td></tr>"
        )
    table_page(
        site, "service-groups.html", "Service groups",
        [obj_scope_hdr, "Name", "Members", "Member list"], sg_rows,
        note=_basis(model, "service_groups", "service_groups_distinct", "service-group") if panorama else "",
    )

    if panorama:
        _build_shared_object_pages(site, model)

    zone_hdr = ["Name", "Interfaces"]
    if panorama:
        zone_hdr = ["Template", "Name", "Interfaces"]
    zone_rows = []
    for z in sorted(model.zones, key=lambda x: x["name"].lower()):
        if panorama:
            zone_rows.append(
                f"<tr><td>{esc(z.get('template', '—'))}</td><td>{esc(z['name'])}</td>"
                f"<td>{esc(z.get('interfaces') or '—')}</td></tr>"
            )
        else:
            zone_rows.append(
                f"<tr><td>{esc(z['name'])}</td><td>{esc(z.get('interfaces') or '—')}</td>"
                f"<td>{esc(z.get('vsys', '—'))}</td></tr>"
            )
    if not panorama:
        zone_hdr.append("Vsys")
    table_page(site, "zones.html", "Zones", zone_hdr, zone_rows)

    route_rows = []
    if panorama:
        for r in model.routes:
            route_rows.append(
                "<tr>"
                f"<td>{tmpl_link(r.get('template', ''), prefix='')}</td>"
                f"<td class='mono'>{esc(r.get('virtual_router', ''))}</td>"
                f"<td>{esc(r['name'])}</td>"
                f"<td class='mono'>{esc(r['destination'])}</td>"
                f"<td class='mono'>{esc(r['nexthop'])}</td>"
                f"<td>{esc(r['interface'])}</td>"
                f"<td>{esc(r.get('metric') or '')}</td></tr>"
            )
        table_page(
            site,
            "routes.html",
            "Static routes",
            ["Template", "Virtual router", "Name", "Destination", "Next hop", "Interface", "Metric"],
            route_rows,
            note="Static routes live under template virtual routers — scoped per template/VR, not deduplicated globally.",
        )
    else:
        for r in model.routes:
            route_rows.append(
                "<tr>"
                f"<td>{esc(r['name'])}</td><td class='mono'>{esc(r['destination'])}</td>"
                f"<td class='mono'>{esc(r['nexthop'])}</td><td>{esc(r['interface'])}</td>"
                f"<td>{esc(r.get('metric') or '')}</td></tr>"
            )
        table_page(
            site,
            "routes.html",
            "Static routes",
            ["Name", "Destination", "Next hop", "Interface", "Metric"],
            route_rows,
            note="Routes are deduplicated by destination, next hop, and interface.",
        )

    unused_hdr = ["Category", "Name", "Definition"]
    if panorama:
        unused_hdr = ["Device group / scope", "Category", "Name", "Definition"]
    unused_rows = []
    for u in model.unused:
        if panorama:
            unused_rows.append(
                f"<tr><td>{scope_cell(u.get('device_group', ''))}</td><td>{esc(u['category'])}</td>"
                f"<td>{esc(u['name'])}</td><td class='mono'>{esc(u['definition'])}</td></tr>"
            )
        else:
            unused_rows.append(
                f"<tr><td>{esc(u['category'])}</td><td>{esc(u['name'])}</td>"
                f"<td class='mono'>{esc(u['definition'])}</td></tr>"
            )
    if panorama:
        unused_note = (
            "An object is <b>unused</b> when no rule that can see it references it. "
            "Visibility follows PAN-OS: a rule in device group D resolves objects in D, "
            "in D's ancestors, and in <b>Shared</b> — so an object here was not referenced "
            "by any device group that inherits from its scope, directly or through a group "
            "whose membership expands to it. Security, NAT, decryption and "
            "application-override rules all count as references. "
            "Addresses, address groups, services, service groups, external dynamic lists, "
            "custom applications, application groups and schedules are analysed; "
            "<b>tags are excluded</b> because they are referenced from object metadata this "
            "report does not index per object. A custom application reachable through a "
            "referenced application-filter counts as used. "
            "<b>Counting basis:</b> one row per object <b>definition</b> (scope + name); the "
            "same name defined in two scopes can appear twice."
        )
        if not getattr(model, "has_shared", True):
            unused_note = (
                "<b>Warning — this count is computed against a fragment.</b> The snapshot has "
                "no <code>&lt;shared&gt;</code> branch, so objects defined in Shared and the "
                "groups that reference them are invisible and these findings are inflated. "
                "Re-collect with collector 1.5.0 or newer.<br>" + unused_note
            )
    else:
        unused_note = (
            "Objects not referenced by security or NAT rules in their scope "
            "(including expanded group membership)."
        )
    table_page(
        site,
        "unused.html",
        "Unused objects",
        unused_hdr,
        unused_rows,
        note=unused_note,
    )

    opt_rows = []
    for f in model.optimization_findings():
        opt_rows.append(
            "<tr>"
            f"<td>{sev_badge(f['severity'])}</td>"
            f"<td>{esc(f['type'])}</td>"
            f"<td>{f['count']}</td>"
            f"<td class='mono'>{esc(f['detail'])}</td></tr>"
        )
    table_page(
        site,
        "optimization.html",
        "Optimization",
        ["Severity", "Finding", "Count", "Examples"],
        opt_rows,
        note="Read-only hygiene findings — review before removing objects or changing rules.",
    )


def build_standalone_site(model: PaloStandaloneModel, out_dir: Path, *, viewer_version: str = "") -> None:
    site = SiteBuilder(out_dir, "palo", model.path.name, STANDALONE_NAV, viewer_version=viewer_version)
    site.write_assets()
    st = model.stats
    host_line = f"<br>Hostname: <span class='mono'>{esc(model.hostname)}</span>" if model.hostname else ""
    vsys_line = ""
    if model.vsys_names:
        vsys_line = f"<br>Virtual systems: <span class='mono'>{esc(', '.join(model.vsys_names))}</span>"

    index_body = [
        "<h2>PAN-OS firewall snapshot</h2>",
        '<div class="note">Read-only browser for a <b>standalone</b> Palo Alto firewall export. '
        "For Panorama device-group exports use <code>palo/panorama/build_html.py</code>.</div>",
        site.cards([
            (str(st["security_rules"]), "Security rules", ""),
            (str(st["addresses"]), "Addresses", ""),
            (str(st["address_groups"]), "Address groups", ""),
            (str(st["services"]), "Services", ""),
            (str(st["service_groups"]), "Service groups", ""),
            (str(st["nat_rules"]), "NAT rules", ""),
            (str(st["routes"]), "Static routes", ""),
            (str(st["zones"]), "Zones", ""),
            (str(st["unused_objects"]), "Unused objects", "warn" if st["unused_objects"] else ""),
            (str(st["rules_without_profiles"]), "Rules w/o profiles", "warn" if st["rules_without_profiles"] else ""),
        ]),
        f'<p class="meta">Source: <span class="mono">{esc(model.path.name)}</span>{host_line}{vsys_line}</p>',
    ]
    site.page("index.html", "Dashboard", "".join(index_body))
    build_inventory_pages(site, model, panorama=False)


def _render_dg_tree(model: PaloPanoramaModel, nodes: list[dict], depth: int = 0) -> str:
    parts: list[str] = []
    for node in nodes:
        name = node["name"]
        indent = depth * 20
        rel = f"device-groups/{safe_name(name)}.html"
        stacks_suffix = (
            f' · stacks: {esc(", ".join(node.get("template_stacks", [])[:3]))}'
            if node.get("template_stacks")
            else ""
        )
        parts.append(
            f'<div class="fw-node" style="margin-left:{indent}px">'
            f'<div class="fw-node-title"><a href="{esc(rel)}">{esc(name)}</a></div>'
            f'<div class="fw-node-meta">'
            f'{node["local_rule_count"]} local rules · {node["local_nat_count"]} NAT · '
            f'{node.get("local_decrypt_count", 0)} decrypt · '
            f'{node["local_object_count"]} objects · {node["device_count"]} firewalls'
            f'{stacks_suffix}'
            f'</div></div>'
        )
        children = [n for n in model.suite if n["name"] in node.get("children", [])]
        children.sort(key=lambda x: x["name"].lower())
        if children:
            parts.append(_render_dg_tree(model, children, depth + 1))
    return "".join(parts)


def build_routing_pages(site: SiteBuilder, model: PaloPanoramaModel) -> None:
    tmpl_rows = []
    for t in model.templates:
        multi = '<span class="tag t-other">multi</span>' if t.get("multi_vsys") else ""
        tmpl_rows.append(
            "<tr>"
            f"<td>{tmpl_link(t['name'])}</td>"
            f"<td>{t['vsys_count']}{multi}</td>"
            f"<td class='mono'>{esc(t.get('vsys_list') or '—')}</td>"
            f"<td>{t['virtual_router_count']}</td>"
            f"<td>{t.get('interface_count', 0)}</td>"
            f"<td>{t['static_route_count']}</td>"
            f"<td>{t['bgp_count']}</td>"
            f"<td>{t['ospf_count']}</td></tr>"
        )
    table_page(
        site,
        "templates.html",
        "Templates",
        ["Name", "Vsys", "Vsys names", "VRs", "Ifaces", "Static", "BGP", "OSPF"],
        tmpl_rows,
        note="Network config (zones, VRs, routing, interfaces) lives in templates. Device groups own policy/objects.",
    )

    host_by_serial = {d["serial"]: (d.get("hostname") or "") for d in model.managed_devices}
    stack_rows = []
    for st_row in model.template_stacks:
        tmpls = st_row.get("templates", [])
        # Order is the PAN-OS priority order: the FIRST member wins on conflict,
        # which is why the site-specific template sits at the head of the list.
        links = []
        for i, n in enumerate(tmpls[:8]):
            label = tmpl_link(n)
            links.append(f'<span class="pill">{i + 1}</span> {label}')
        tmpl_links = ", ".join(links) + (" …" if len(tmpls) > 8 else "")
        serials = st_row.get("device_serials", [])
        dev_cells = []
        for sn in serials:
            host = host_by_serial.get(sn) or ""
            dev_cells.append(f"{esc(sn)}{(' (' + esc(host) + ')') if host else ''}")
        stack_rows.append(
            f'<tr id="{safe_name(st_row["name"])}">'
            f"<td>{esc(st_row['name'])}</td>"
            f"<td>{st_row['template_count']}</td>"
            f"<td>{tmpl_links or '—'}</td>"
            f"<td>{st_row['devices']}</td>"
            f"<td class='mono'>{'<br>'.join(dev_cells) or '—'}</td></tr>"
        )
    stack_note = (
        "Member templates are listed in <b>stack priority order</b> — the numbered first "
        "entry is the highest-priority (site) template and wins any setting conflict. "
        "Devices are the firewall serials the stack is pushed to, with the reported "
        "hostname where the snapshot has one. "
        "<b>Counting basis:</b> one row per template stack; Templates and Devices count "
        "members of that stack."
    )
    if not getattr(model, "has_template_stacks", True):
        stack_note = (
            "<b>This snapshot has no <code>&lt;template-stack&gt;</code> branch</b> — it "
            "predates collector 1.5.0, so there is nothing to list here. Re-collect with "
            "1.5.0 or newer.<br>" + stack_note
        )
    table_page(
        site,
        "template-stacks.html",
        "Template stacks",
        ["Name", "Templates", "Member templates (priority order)", "Devices", "Device serials"],
        stack_rows,
        note=stack_note,
    )

    iface_rows = [
        "<tr>"
        f"<td>{tmpl_link(i['template'])}</td>"
        f"<td>{esc(i['kind'])}</td>"
        f"<td class='mono'>{esc(i['name'])}</td>"
        f"<td class='mono'>{esc(i.get('ip') or '—')}</td>"
        f"<td>{esc(i.get('comment') or '—')}</td></tr>"
        for i in model.interfaces
    ]
    table_page(
        site,
        "interfaces.html",
        "Interfaces",
        ["Template", "Kind", "Name", "IP", "Comment"],
        iface_rows,
        note="Layer3 ethernet, AE, VLAN, loopback, and tunnel interfaces from template network config, including subinterfaces.",
    )

    vsys_rows = [
        "<tr>"
        f"<td>{tmpl_link(v['template'])}</td>"
        f"<td class='mono'>{esc(v['name'])}</td>"
        f"<td>{esc(v.get('display_name') or '—')}</td>"
        f"<td class='mono'>{esc(v.get('import_virtual_routers') or '—')}</td></tr>"
        for v in model.template_vsys
    ]
    table_page(
        site,
        "vsys.html",
        "Virtual systems",
        ["Template", "Vsys", "Display name", "Imported virtual routers"],
        vsys_rows,
        note="Vsys definitions from template config. Managed firewalls show assigned vsys plus template vsys on the Devices page.",
    )

    vr_rows = [
        "<tr>"
        f"<td>{tmpl_link(v['template'])}</td>"
        f"<td class='mono'>{esc(v['name'])}</td>"
        f"<td>{v['interface_count']}</td>"
        f"<td>{esc(v.get('interfaces') or '—')}</td>"
        f"<td>{v['static_routes']}</td>"
        f"<td>{esc(v['bgp'])}</td>"
        f"<td>{esc(v['ospf'])}</td></tr>"
        for v in model.virtual_routers
    ]
    table_page(
        site,
        "virtual-routers.html",
        "Virtual routers",
        ["Template", "Name", "Ifaces", "Interface list", "Static routes", "BGP", "OSPF"],
        vr_rows,
    )

    bgp_rows = [
        "<tr>"
        f"<td>{tmpl_link(b['template'])}</td>"
        f"<td class='mono'>{esc(b['virtual_router'])}</td>"
        f"<td>{esc(b.get('kind', ''))}</td>"
        f"<td>{esc(b['name'])}</td>"
        f"<td class='mono'>{esc(b.get('router_id') or '—')}</td>"
        f"<td>{esc(b.get('local_as') or '—')}</td>"
        f"<td>{esc(b.get('peer_as') or '—')}</td>"
        f"<td class='mono'>{esc(b.get('peer_address') or '—')}</td>"
        f"<td>{esc(b.get('bgp_enable') or '—')}</td></tr>"
        for b in model.bgp_peers
    ]
    table_page(
        site,
        "bgp.html",
        "BGP",
        ["Template", "Virtual router", "Type", "Name", "Router ID", "Local AS", "Peer AS", "Peer address", "Enable"],
        bgp_rows,
    )

    ospf_rows = [
        "<tr>"
        f"<td>{tmpl_link(o['template'])}</td>"
        f"<td class='mono'>{esc(o['virtual_router'])}</td>"
        f"<td class='mono'>{esc(o.get('area') or '—')}</td>"
        f"<td>{esc(o.get('enable') or '—')}</td>"
        f"<td class='mono'>{esc(o.get('router_id') or '—')}</td>"
        f"<td>{esc(o.get('interfaces') or '—')}</td></tr>"
        for o in model.ospf_areas
    ]
    table_page(
        site,
        "ospf.html",
        "OSPF",
        ["Template", "Virtual router", "Area", "Enable", "Router ID", "Interfaces"],
        ospf_rows,
    )

    gp_rows = []
    for p in model.gp_portals:
        gp_rows.append(
            "<tr>"
            f"<td>{tmpl_link(p['template'])}</td>"
            f"<td>portal</td>"
            f"<td>{esc(p['name'])}</td>"
            f"<td class='mono'>{esc(p.get('interface') or '—')}</td>"
            f"<td class='mono'>{esc(p.get('ip') or '—')}</td>"
            f"<td>—</td>"
            f"<td>{esc(p.get('auth') or '—')}</td>"
            f"<td>{esc(p.get('ssl_profile') or '—')}</td></tr>"
        )
    for g in model.gp_gateways:
        gp_rows.append(
            "<tr>"
            f"<td>{tmpl_link(g['template'])}</td>"
            f"<td>gateway</td>"
            f"<td>{esc(g['name'])}</td>"
            f"<td class='mono'>{esc(g.get('interface') or '—')}</td>"
            f"<td class='mono'>{esc(g.get('ip') or '—')}</td>"
            f"<td class='mono'>{esc(g.get('tunnel_interface') or '—')}</td>"
            f"<td>{esc(g.get('auth') or '—')}</td>"
            f"<td>{esc(g.get('ipsec_profile') or '—')}</td></tr>"
        )
    table_page(
        site,
        "globalprotect.html",
        "GlobalProtect",
        ["Template", "Kind", "Name", "Interface", "IP", "Tunnel", "Auth", "SSL / IPsec profile"],
        gp_rows,
        note="Portals and gateways from template vsys + tunnel config. Site-to-site IPsec is on IPsec / IKE.",
    )

    ike_rows = [
        "<tr>"
        f"<td>{tmpl_link(o['template'])}</td>"
        f"<td>{esc(o.get('kind') or '—')}</td>"
        f"<td>{esc(o['name'])}</td>"
        f"<td>{esc(o.get('encryption') or '—')}</td>"
        f"<td>{esc(o.get('hash') or '—')}</td>"
        f"<td>{esc(o.get('dh') or '—')}</td>"
        f"<td class='mono'>{esc(o.get('peer') or '—')}</td>"
        f"<td class='mono'>{esc(o.get('interface') or '—')}</td></tr>"
        for o in model.ike_objects
    ]
    for t in model.ipsec_tunnels:
        ike_rows.append(
            "<tr>"
            f"<td>{tmpl_link(t['template'])}</td>"
            f"<td>ipsec-tunnel</td>"
            f"<td>{esc(t['name'])}</td>"
            f"<td>—</td><td>—</td><td>—</td>"
            f"<td class='mono'>{esc(t.get('ike_gateway') or '—')}</td>"
            f"<td class='mono'>{esc(t.get('tunnel_interface') or t.get('crypto') or '—')}</td></tr>"
        )
    table_page(
        site,
        "ipsec.html",
        "IPsec / IKE",
        ["Template", "Kind", "Name", "Encryption", "Hash / auth", "DH", "Peer / IKE GW", "Interface"],
        ike_rows,
        note="IKE/IPsec crypto profiles, IKE gateways, and site-to-site IPsec tunnels. GlobalProtect crypto is listed here when present; GP portals/gateways are on GlobalProtect.",
    )

    ha_rows = [
        "<tr>"
        f"<td>{stack_link(v['stack'])}</td>"
        f"<td>{esc(v.get('hostname') or '—')}</td>"
        f"<td class='mono'>{esc(v['serial'])}</td>"
        f"<td class='mono'>{esc(v['name'])}</td>"
        f"<td class='mono'>{esc(v.get('value') or '—')}</td>"
        f"<td>{esc(v.get('value_type') or '—')}</td></tr>"
        for v in model.ha_variables
    ]
    table_page(
        site,
        "ha-variables.html",
        "HA stack variables",
        ["Template stack", "Hostname", "Serial", "Variable", "Value", "Type"],
        ha_rows,
        note="Per-serial template-stack variables ($ha1a, $peerha1a, $hapriority, …) used for HA pair addressing and priority.",
    )

    for t in model.templates:
        tmpl_name = t["name"]
        rel = f"templates/{safe_name(tmpl_name)}.html"
        vsys = [v for v in model.template_vsys if v.get("template") == tmpl_name]
        vrs = model.virtual_routers_for_template(tmpl_name)
        body = [
            f"<h2>{esc(tmpl_name)}</h2>",
            '<div class="note">Template network summary — '
            f'{t["vsys_count"]} vsys · {t["virtual_router_count"]} virtual routers · '
            f'{t.get("interface_count", 0)} interfaces · '
            f'{t["static_route_count"]} static routes · {t["bgp_count"]} BGP · {t["ospf_count"]} OSPF'
            f'{(" · hostname " + esc(t["hostname"])) if t.get("hostname") else ""}</div>',
        ]
        if vsys:
            body.append("<h3>Virtual systems</h3>")
            rows = [
                "<tr>"
                f"<td class='mono'>{esc(v['name'])}</td>"
                f"<td>{esc(v.get('display_name') or '—')}</td>"
                f"<td class='mono'>{esc(v.get('import_virtual_routers') or '—')}</td></tr>"
                for v in vsys
            ]
            body.append(site.table("tbl-vsys", ["Vsys", "Display name", "Imported VRs"], rows))
        if vrs:
            body.append("<h3>Virtual routers</h3>")
            rows = [
                "<tr>"
                f"<td class='mono'>{esc(v['name'])}</td>"
                f"<td>{v['static_routes']}</td>"
                f"<td>{esc(v['bgp'])}/{esc(v['ospf'])}</td>"
                f"<td>{esc(v.get('interfaces') or '—')}</td></tr>"
                for v in vrs
            ]
            body.append(site.table("tbl-vr", ["Virtual router", "Static", "BGP/OSPF", "Interfaces"], rows))
        ifaces = model.interfaces_for_template(tmpl_name)
        if ifaces:
            body.append("<h3>Interfaces</h3>")
            rows = [
                "<tr>"
                f"<td>{esc(i['kind'])}</td>"
                f"<td class='mono'>{esc(i['name'])}</td>"
                f"<td class='mono'>{esc(i.get('ip') or '—')}</td>"
                f"<td>{esc(i.get('comment') or '—')}</td></tr>"
                for i in ifaces
            ]
            body.append(site.table("tbl-if", ["Kind", "Name", "IP", "Comment"], rows))
        gp_gws = [g for g in model.gp_gateways if g.get("template") == tmpl_name]
        gp_pts = [p for p in model.gp_portals if p.get("template") == tmpl_name]
        if gp_pts or gp_gws:
            body.append("<h3>GlobalProtect</h3>")
            rows = [
                "<tr>"
                f"<td>portal</td><td>{esc(p['name'])}</td>"
                f"<td class='mono'>{esc(p.get('interface') or '—')}</td>"
                f"<td class='mono'>{esc(p.get('ip') or '—')}</td></tr>"
                for p in gp_pts
            ]
            rows.extend(
                "<tr>"
                f"<td>gateway</td><td>{esc(g['name'])}</td>"
                f"<td class='mono'>{esc(g.get('interface') or '—')}</td>"
                f"<td class='mono'>{esc(g.get('tunnel_interface') or g.get('ip') or '—')}</td></tr>"
                for g in gp_gws
            )
            body.append(site.table("tbl-gp", ["Kind", "Name", "Interface", "IP / tunnel"], rows))
        stacks = [s for s in model.template_stacks if tmpl_name in s.get("templates", [])]
        if stacks:
            body.append("<h3>Template stacks using this template</h3><ul>")
            for s in stacks:
                devs = [
                    d for d in model.managed_devices if d.get("template_stack") == s["name"]
                ]
                dev_note = f" — {len(devs)} managed firewall(s)" if devs else ""
                body.append(
                    f"<li>{stack_link(s['name'], prefix='../')}{dev_note}</li>"
                )
            body.append("</ul>")
            body.append(
                '<div class="note">Network config here is <b>template-scoped</b> — pushed to every '
                "firewall assigned to the stack above, not one physical box. Each vsys imports its own "
                "virtual router (see Imported VRs).</div>"
            )
        body.append(
            f'<p class="meta">See also: <a href="../virtual-routers.html">all virtual routers</a> · '
            f'<a href="../routes.html">static routes</a> · <a href="../interfaces.html">interfaces</a> · <a href="../zones.html">zones</a></p>'
        )
        site.page(rel, tmpl_name, "".join(body), depth=1)


def build_panorama_site(model: PaloPanoramaModel, out_dir: Path, *, viewer_version: str = "") -> None:
    site = SiteBuilder(out_dir, "palo", model.path.name, PANORAMA_NAV, viewer_version=viewer_version)
    site.write_assets()
    st = model.stats
    host_line = f"<br>Panorama: <span class='mono'>{esc(model.hostname)}</span>" if model.hostname else ""

    index_body = [
        "<h2>Panorama snapshot</h2>",
        '<div class="note">Read-only browser for a <b>Panorama</b> export. Start with '
        '<a href="panorama.html"><b>Panorama View</b></a> for the device-group hierarchy and per-DG drill-down.</div>',
        gap_note(model),
        "<h3>Topology</h3>",
        site.cards([
            (str(st["device_groups"]), "Device groups", ""),
            (str(st.get("managed_devices", 0)), "Managed firewalls", ""),
            (str(st.get("templates", 0)), "Templates", ""),
            (str(st.get("template_stacks", 0)), "Template stacks", ""),
        ]),
        "<h3>Policy &amp; objects</h3>",
        '<div class="note">'
        "<b>Counting basis for the object cards below:</b> each number counts object "
        "<b>definitions</b> — one per device-group-or-Shared scope plus name, the way "
        "PAN-OS stores them — so a name defined in three device groups counts three "
        "times. Distinct names across the whole snapshot are in brackets. Rule, "
        "firewall and template counts are plain totals and need no such distinction."
        "</div>",
        site.cards([
            (str(st["security_rules"]), "Security rules", ""),
            (str(st["nat_rules"]), "NAT rules", ""),
            (str(st.get("decrypt_rules", 0)), "Decryption rules", ""),
            (_defs_and_distinct(st, "addresses"), "Address definitions [distinct]", ""),
            (_defs_and_distinct(st, "address_groups"), "Address-group definitions [distinct]", ""),
            (_defs_and_distinct(st, "services"), "Service definitions [distinct]", ""),
            (_defs_and_distinct(st, "service_groups"), "Service-group definitions [distinct]", ""),
            (str(st.get("applications", 0)), "Custom applications", ""),
            (str(st.get("application_groups", 0) + st.get("application_filters", 0)),
             "App groups + filters", ""),
            (str(st.get("tags", 0)), "Tags", ""),
            (str(st.get("schedules", 0)), "Schedules", ""),
            (str(st.get("edls", 0)), "External lists", ""),
            (str(st.get("security_profiles", 0)), "Security profiles", ""),
            (str(st.get("app_overrides", 0)), "App override", ""),
            (str(st.get("log_forwarding", 0)), "Log forwarding", ""),
            (str(st["zones"]), "Zones (templates)", ""),
            (str(st["unused_objects"]), "Unused definitions", "warn" if st["unused_objects"] else ""),
            (str(st["rules_without_profiles"]), "Rules w/o profiles", "warn" if st["rules_without_profiles"] else ""),
        ]),
        "<h3>Shared namespace</h3>",
        '<div class="note">'
        + (
            "Panorama's <b>Shared</b> scope is the root every device group inherits objects "
            "from. On a typical estate most objects live here, so a snapshot without it "
            "understates the configuration and inflates unused-object findings."
            if st.get("shared_objects")
            else "<b>No <code>&lt;shared&gt;</code> branch in this snapshot</b> — it predates "
                 "collector 1.5.0. Object counts, unused-object analysis and rule resolution "
                 "below cover device-group scope only. Re-collect with 1.5.0 or newer."
        )
        + "</div>",
        site.cards([
            (str(st.get("shared_objects", 0)), "Shared object definitions",
             "" if st.get("shared_objects") else "warn"),
            (str(st.get("shared_profiles", 0)), "Shared security profiles", ""),
            (str(st.get("connected_devices", 0)), "Firewalls connected", ""),
            (str(st.get("ha_devices", 0)), "Firewalls in HA", ""),
        ]),
        "<h3>Network, VPN &amp; HA</h3>",
        site.cards([
            (str(st.get("template_vsys", 0)), "Template vsys", ""),
            (str(st.get("multi_vsys_templates", 0)), "Multi-vsys templates", ""),
            (str(st.get("interfaces", 0)), "Interfaces", ""),
            (str(st.get("virtual_routers", 0)), "Virtual routers", ""),
            (str(st["routes"]), "Static routes", ""),
            (str(st.get("bgp_peers", 0)), "BGP peers/groups", ""),
            (str(st.get("ospf_areas", 0)), "OSPF areas", ""),
            (str(st.get("gp_portals", 0)), "GP portals", ""),
            (str(st.get("gp_gateways", 0)), "GP gateways", ""),
            (str(st.get("ike_objects", 0)), "IKE / IPsec crypto", ""),
            (str(st.get("ipsec_tunnels", 0)), "IPsec tunnels", ""),
            (str(st.get("ha_variables", 0)), "HA variables", ""),
        ]),
        f'<p class="meta">Source: <span class="mono">{esc(model.path.name)}</span>{host_line}</p>',
    ]
    site.page("index.html", "Dashboard", "".join(index_body))

    roots = model.suite_roots()
    panorama_body = [
        "<h2>Panorama View</h2>",
        '<div class="note">Device-group hierarchy (parent → child). Click a group for local rules, NAT, and objects.</div>',
        _render_dg_tree(model, roots),
    ]
    site.page("panorama.html", "Panorama View", "".join(panorama_body))

    dg_rows = []
    for node in model.suite:
        dg_rows.append(
            "<tr>"
            f"<td><a href='device-groups/{safe_name(node['name'])}.html'>{esc(node['name'])}</a></td>"
            f"<td>{esc(node.get('parent') or '—')}</td>"
            f"<td>{node['local_rule_count']}</td>"
            f"<td>{node['local_nat_count']}</td>"
            f"<td>{node.get('local_decrypt_count', 0)}</td>"
            f"<td>{node['local_object_count']}</td>"
            f"<td>{node['device_count']}</td></tr>"
        )
    table_page(
        site,
        "device-groups.html",
        "Device Groups",
        ["Name", "Parent", "Local rules", "Local NAT", "Decrypt", "Local objects", "Firewalls"],
        dg_rows,
    )

    dev_rows = []
    for d in model.managed_devices:
        host = d.get("hostname") or ""
        src = d.get("hostname_source") or ""
        host_cell = esc(host) if host else "—"
        if host and src == "template":
            host_cell += ' <span class="tag t-other" title="Guessed from the first site ' \
                         'template in the stack — no operational hostname in this snapshot">?</span>'
        ha = d.get("ha_state") or ""
        ha_cell = f'<span class="tag {"t-accept" if ha == "active" else "t-other"}">{esc(ha)}</span>' if ha else "—"
        dev_rows.append(
            "<tr>"
            f"<td>{host_cell}</td>"
            f"<td class='mono'>{esc(d['serial'])}</td>"
            f"<td>{esc(d.get('model') or '—')}</td>"
            f"<td class='mono'>{esc(d.get('sw_version') or '—')}</td>"
            f"<td>{yes_no_tag(d.get('connected') or '')}</td>"
            f"<td>{ha_cell}</td>"
            f"<td class='mono'>{esc(d.get('ip_address') or '—')}</td>"
            f"<td>{dg_cell(d.get('device_group') or '')}</td>"
            f"<td>{stack_link(d.get('template_stack') or '')}</td>"
            f"<td>{esc(d.get('vsys', 'vsys1'))}</td>"
            f"<td class='mono'>{esc(d.get('template_vsys') or '—')}</td></tr>"
        )
    st_dev = model.stats
    if getattr(model, "has_operational_devices", False):
        dev_note = (
            f"Hostname, model, software version, connection state, HA state and management IP "
            f"are <b>operational facts</b> read from <code>show devices all</code> at collection "
            f"time — not configuration. <b>{st_dev.get('connected_devices', 0)}</b> of "
            f"<b>{st_dev.get('managed_devices', 0)}</b> firewalls were connected, "
            f"<b>{st_dev.get('ha_devices', 0)}</b> report an HA state, and "
            f"<b>{st_dev.get('stack_assigned_devices', 0)}</b> are assigned to a template stack. "
            "A hostname marked <b>?</b> has no operational value and falls back to the first "
            "site template in the stack. Assigned vsys is the device-group reference; template "
            "vsys is the union of vsys defined in the stack. "
            "<b>Counting basis:</b> one row per firewall serial Panorama manages."
        )
    else:
        dev_note = (
            "<b>This snapshot has no operational device facts</b> — it predates collector "
            "1.5.0, so model, software version, HA state, connection status and management IP "
            "are unavailable and hostnames are only guessed from the first site template in "
            "each stack. Re-collect with 1.5.0 or newer. "
            "<b>Counting basis:</b> one row per firewall serial Panorama manages."
        )
    table_page(
        site,
        "devices.html",
        "Managed Firewalls",
        ["Hostname", "Serial", "Model", "SW version", "Connected", "HA state", "Mgmt IP",
         "Device group", "Template stack", "Assigned vsys", "Template vsys"],
        dev_rows,
        note=dev_note,
    )

    rel_rows = [
        "<tr>"
        f"<td>{esc(r['object_name'])}</td>"
        f"<td>{esc(r['object_category'])}</td>"
        f"<td>{esc(r['device_group'])}</td>"
        f"<td>{esc(r['rule_type'])}</td>"
        f"<td class='mono'>{esc(r['used_by'])}</td></tr>"
        for r in model.relationships
    ]
    table_page(
        site,
        "relationships.html",
        "Relationships",
        ["Object", "Category", "Device group", "Rule type", "Used by"],
        rel_rows,
        note="Object references extracted from security, NAT, and decryption rules (read-only where-used).",
    )

    for node in model.suite:
        dg_name = node["name"]
        rel = f"device-groups/{safe_name(dg_name)}.html"
        rules = model.rules_for_dg(dg_name)
        nat = model.nat_for_dg(dg_name)
        decrypt = model.decrypt_for_dg(dg_name)
        body = [
            f"<h2>{esc(dg_name)}</h2>",
            f'<div class="note">Parent: <b>{esc(node.get("parent") or "—")}</b> · '
            f'{len(rules)} security rules · {len(nat)} NAT rules · {len(decrypt)} decryption rules · '
            f'{len(model.app_override_for_dg(dg_name))} app-override · '
            f'{node["local_object_count"]} local objects</div>',
        ]
        stacks = node.get("template_stacks") or []
        if stacks:
            body.append("<h3>Network (template stacks)</h3><ul>")
            for stack in stacks:
                tmpl_names = model.templates_for_stack(stack)
                links = ", ".join(tmpl_link(n, prefix="../") for n in tmpl_names[:8])
                if len(tmpl_names) > 8:
                    links += " …"
                body.append(
                    f"<li>{stack_link(stack, prefix='../')} — templates: {links or '—'}</li>"
                )
            body.append("</ul>")
        if rules:
            body.append("<h3>Security rules</h3>")
            rows = [
                "<tr>"
                f"<td>{esc(r.get('rulebase', ''))}</td><td>{esc(r['name'])}</td>"
                f"<td>{esc(r['from'])}</td><td>{esc(r['to'])}</td>"
                f"<td>{esc(r['source'])}</td><td>{esc(r['destination'])}</td>"
                f"<td>{action_tag(r['action'])}</td></tr>"
                for r in rules[:500]
            ]
            if len(rules) > 500:
                body.append(f'<p class="meta">Showing first 500 of {len(rules)} rules. See <a href="../rules.html">all rules</a>.</p>')
            body.append(site.table("tbl-rules", ["Rulebase", "Name", "From", "To", "Source", "Destination", "Action"], rows))
        if nat:
            body.append("<h3>NAT</h3>")
            nat_rows = [
                "<tr>"
                f"<td>{esc(n.get('rulebase', ''))}</td><td>{esc(n['name'])}</td>"
                f"<td>{esc(n['source'])}</td><td>{esc(n['destination'])}</td></tr>"
                for n in nat[:200]
            ]
            body.append(site.table("tbl-nat", ["Rulebase", "Name", "Source", "Destination"], nat_rows))
        if decrypt:
            body.append("<h3>Decryption</h3>")
            dec_rows = [
                "<tr>"
                f"<td>{esc(d.get('rulebase', ''))}</td><td>{esc(d['name'])}</td>"
                f"<td>{esc(d.get('decrypt_type') or '—')}</td>"
                f"<td>{action_tag(d.get('action', ''))}</td></tr>"
                for d in decrypt[:200]
            ]
            body.append(site.table("tbl-decrypt", ["Rulebase", "Name", "Type", "Action"], dec_rows))
        apo = model.app_override_for_dg(dg_name)
        if apo:
            body.append("<h3>Application override</h3>")
            apo_rows = [
                "<tr>"
                f"<td>{esc(a.get('rulebase', ''))}</td><td>{esc(a['name'])}</td>"
                f"<td>{esc(a.get('application') or '—')}</td>"
                f"<td>{esc(a.get('protocol') or '—')}/{esc(a.get('port') or '—')}</td></tr>"
                for a in apo[:200]
            ]
            body.append(site.table("tbl-apo", ["Rulebase", "Name", "Application", "Proto/port"], apo_rows))
        site.page(rel, dg_name, "".join(body), depth=1)

    build_routing_pages(site, model)
    build_inventory_pages(site, model, panorama=True)
