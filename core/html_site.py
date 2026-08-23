"""Minimal static HTML site builder for vendor read-only reports."""

from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path

from core.html_theme import CSS, JS, vendor


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def sev_badge(level: str) -> str:
    lv = (level or "").lower()
    if lv in ("high", "critical"):
        cls = "b-red"
    elif lv in ("medium", "warn", "warning"):
        cls = "b-amber"
    else:
        cls = "b-blue"
    return f'<span class="badge {cls}">{esc(level)}</span>'


class SiteBuilder:
    """Write self-contained html_view/ with shared NetConverter chrome."""

    def __init__(
        self,
        out_dir: Path,
        vendor_key: str,
        source_label: str,
        nav_items: list[tuple[str, str]],
        viewer_version: str = "",
    ):
        self.out = Path(out_dir)
        self.vendor_key = vendor_key
        self.meta = vendor(vendor_key)
        self.source_label = source_label
        self.nav_items = nav_items
        self.viewer_version = viewer_version
        self._asset_ver = "1"

    def write_assets(self) -> None:
        assets = self.out / "assets"
        assets.mkdir(parents=True, exist_ok=True)
        (assets / "style.css").write_text(CSS, encoding="utf-8")
        (assets / "app.js").write_text(JS, encoding="utf-8")
        self._asset_ver = hashlib.md5((CSS + JS).encode()).hexdigest()[:8]

    def searchbox(self, table_id: str, count_id: str) -> str:
        return (
            f'<input class="search" type="search" placeholder="Filter…" '
            f'data-target="{table_id}" data-count="{count_id}" '
            f'oninput="filterTable(this)">'
        )

    def cards(self, items: list[tuple[str, str, str]]) -> str:
        """(number, label, optional class warn|bad|good)"""
        parts = ['<div class="cards">']
        for n, label, *rest in items:
            cls = f" {rest[0]}" if rest else ""
            parts.append(
                f'<div class="card{cls}"><div class="n">{esc(n)}</div>'
                f'<div class="l">{esc(label)}</div></div>'
            )
        parts.append("</div>")
        return "".join(parts)

    def table(self, table_id: str, headers: list[str], rows: list[str]) -> str:
        th = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join(rows)
        return (
            f'<div class="table-wrap"><table id="{table_id}">'
            f"<thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>"
        )

    # Vendor-distinct inner glyphs (all stroked with the theme gradient so they match each color).
    _BRAND_GLYPHS = {
        # Check Point — brick wall (classic firewall)
        "checkpoint": '<path d="M10 11.5h12M10 16h12M10 20.5h12M14 11.5v4.5M18.5 11.5v4.5'
                      'M12 16v4.5M16 16v4.5M20 16v4.5" stroke="url(#vg)" stroke-width="1.5" '
                      'stroke-linecap="round"/>',
        # Fortinet — portcullis / gate bars
        "fortinet": '<path d="M9.5 11.5h13M9.5 16h13M11 11.5v9M14.5 11.5v9M18 11.5v9M21.5 11.5v9" '
                    'stroke="url(#vg)" stroke-width="1.5" stroke-linecap="round"/>',
        # Palo Alto — flame
        "paloalto": '<path d="M16 9.2c2.6 2.5 4 4.8 4 7.2a4 4 0 0 1-8 0c0-1.2.4-2.3 1.1-3.3.3 1 .9 1.6 '
                    '1.7 1.9-.2-2.4.4-4.6 1.2-5.8z" stroke="url(#vg)" stroke-width="1.4" '
                    'stroke-linejoin="round"/>',
        # Cisco FMC — connected network nodes
        "fmc": '<path d="M11.5 13.2l4.5 6.6 4.5-6.6" stroke="url(#vg)" stroke-width="1.5" '
               'stroke-linecap="round" stroke-linejoin="round"/>'
               '<circle cx="11.5" cy="12" r="1.7" fill="url(#vg)"/>'
               '<circle cx="20.5" cy="12" r="1.7" fill="url(#vg)"/>'
               '<circle cx="16" cy="20.2" r="1.7" fill="url(#vg)"/>',
        # Strata SCM — cloud
        "scm": '<path d="M12.5 20a3.1 3.1 0 0 1 .2-6.2 4.2 4.2 0 0 1 7.9-1.2A3.2 3.2 0 0 1 20.3 20z" '
               'stroke="url(#vg)" stroke-width="1.4" stroke-linejoin="round"/>',
    }
    _BRAND_GLYPH_DEFAULT = ('<path d="M16 10.5v11M10.5 16h11" stroke="url(#vg)" '
                            'stroke-width="2" stroke-linecap="round"/>')

    def _brand_logo(self) -> str:
        g1, g2 = self.meta["gradient"]
        glyph = self._BRAND_GLYPHS.get(self.vendor_key, self._BRAND_GLYPH_DEFAULT)
        return (
            '<svg class="brand-mark" viewBox="0 0 32 32" fill="none" aria-hidden="true">'
            f'<defs><linearGradient id="vg" x1="0" y1="0" x2="32" y2="32">'
            f'<stop stop-color="{g1}"/><stop offset="1" stop-color="{g2}"/>'
            "</linearGradient></defs>"
            '<path d="M16 3.5l10.5 4v7.1c0 6.9-4.5 11.1-10.5 13.4C10 25.7 5.5 21.5 5.5 14.6V7.5z" '
            'stroke="url(#vg)" stroke-width="1.6" stroke-linejoin="round" '
            'fill="color-mix(in srgb, var(--accent) 12%, transparent)"/>'
            f'{glyph}</svg>'
        )

    def _nav(self, prefix: str, current: str) -> str:
        parts = [
            '<div class="nav">',
            '<div class="brand">' + self._brand_logo()
            + '<div><div class="brand-name">Net<span class="brand-accent">Converter</span></div>'
            f'<div class="brand-tag"><span class="vendor-chip">{esc(self.meta["chip"])}</span> '
            f'{esc(self.meta["tagline"])}</div></div></div>',
            f'<div class="sub">{esc(self.source_label)}</div>',
        ]
        for href, label in self.nav_items:
            if href == "group":
                parts.append(f'<div class="group">{esc(label)}</div>')
                continue
            cls = ' class="active"' if href == current else ""
            parts.append(f'<a{cls} href="{prefix}{href}">{esc(label)}</a>')
        parts.append(
            '<div class="nav-foot">Read-only view · ValeronLabs LLC<br>'
            '<a href="https://netconverter.ai/" target="_blank" rel="noopener">netconverter.ai</a></div>'
        )
        parts.append("</div>")
        return "".join(parts)

    def page(self, rel_path: str, title: str, body: str, depth: int = 0) -> None:
        prefix = "../" * depth
        nav = self._nav(prefix, rel_path)
        ver_badge = ""
        if self.viewer_version:
            ver_badge = (
                f'<div class="viewer-version" title="HTML report builder">'
                f"v{esc(self.viewer_version)}</div>"
            )
        doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(self.meta["title_suffix"])}</title>
<link rel="stylesheet" href="{prefix}assets/style.css?v={self._asset_ver}"></head>
<body class="{self.meta["theme_class"]}">{ver_badge}<div class="layout">{nav}<div class="main">{body}</div></div>
<script src="{prefix}assets/app.js?v={self._asset_ver}"></script></body></html>"""
        full = self.out / rel_path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(doc, encoding="utf-8")

    def write_json_embed(self, rel_path: str, title: str, data, depth: int = 0) -> None:
        body = (
            f"<h2>{esc(title)}</h2>"
            '<div class="note">Raw snapshot JSON (read-only). Upload the full bundle to NetConverter.local for interactive browse.</div>'
            f"<pre class='mono' style='white-space:pre-wrap;font-size:11px'>{esc(json.dumps(data, indent=2)[:120000])}</pre>"
        )
        self.page(rel_path, title, body, depth=depth)
