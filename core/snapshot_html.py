"""HTML browser for JSON snapshot bundles (FMC / SCM / FortiManager)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.html_site import SiteBuilder, esc


def load_snapshot(run_dir: Path, filename: str) -> dict[str, Any]:
    path = run_dir / filename
    if not path.is_file():
        return {"_error": f"missing {filename}"}
    return json.loads(path.read_text(encoding="utf-8"))


def table_rows(items: list, columns: list[tuple[str, str]]) -> list[str]:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cells = "".join(f"<td>{esc(item.get(key, ''))}</td>" for _, key in columns)
        rows.append(f"<tr>{cells}</tr>")
    return rows


def build_snapshot_site(
    out_dir: Path,
    vendor_key: str,
    run_dir: Path,
    snapshot_name: str,
    nav: list[tuple[str, str]],
    pages: list[dict],
) -> None:
    """
    pages: list of {file, title, list_key, columns: [(header, key), ...]}
    """
    snap = load_snapshot(run_dir, snapshot_name)
    site = SiteBuilder(out_dir, vendor_key, run_dir.name, nav)
    site.write_assets()

    note = snap.get("_note", "")
    cards = []
    for pg in pages:
        items = snap.get(pg["list_key"], [])
        if isinstance(items, list):
            cards.append((str(len(items)), pg["title"], ""))
    if not cards:
        cards = [("1", "Snapshot", "")]

    index_parts = [
        "<h2>Configuration snapshot</h2>",
        '<div class="note">Read-only view — Cisco / Fortinet / SCM theme matches NetConverter.local. '
        "Upload the full bundle to NetConverter.local for interactive analysis.</div>",
    ]
    if note:
        index_parts.append(f'<div class="note warnbox">{esc(note)}</div>')
    index_parts.append(site.cards(cards[:6]))
    index_parts.append(
        f'<p class="meta">Bundle: <span class="mono">{esc(run_dir.name)}</span>'
        f"<br>Host: <span class='mono'>{esc(snap.get('host', snap.get('tenant', '—')))}</span></p>"
    )
    site.page("index.html", "Dashboard", "".join(index_parts))

    for pg in pages:
        items = snap.get(pg["list_key"], [])
        if not isinstance(items, list):
            items = []
        tid = pg.get("table_id", "tbl")
        body = (
            f"<h2>{esc(pg['title'])}</h2>"
            + site.searchbox(tid, f"{tid}_cnt")
            + f'<div class="meta"><span id="{tid}_cnt"></span></div>'
            + site.table(tid, [h for h, _ in pg["columns"]], table_rows(items, pg["columns"]))
        )
        site.page(pg["file"], pg["title"], body)

    site.write_json_embed("raw.json.html", "Raw JSON", snap)
