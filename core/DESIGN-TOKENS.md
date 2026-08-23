# NetConverter Design Tokens — Source of Truth

One product, one palette. Every NetConverter surface — collector HTML outputs,
the local appliance UI, the client portal, and the netconverter.ai tool pages —
derives its colors from this table. The CSS implementation collectors ship is
`core/html_theme.py`; other surfaces copy these values into their own token
blocks and must not drift.

Accent policy (decision 2026-08-06): **blue = product, purple = engineering.**
Customer-facing surfaces accent with brand blue; internal/engineering surfaces
(engineering portal) accent with purple. Purple appears on product surfaces
only as `--accent2` (secondary highlights), never as the primary accent.

## Palette (dark shell)

| Token (short / canonical alias) | Value | Use |
|---|---|---|
| `--bg-base` / `--bg` | `#0a0a0b` | page ground |
| `--bg2`, `--panel` / `--bg-surface` | `#141415` | cards, panels |
| `--panel2` / `--bg-elevated` | `#1c1c1e` | raised surfaces, popovers |
| — / `--bg-hover` | `#222224` | hover states |
| `--line` / `--border` | `#2a2a2c` | borders |
| `--line-soft` / `--border-light` | `#333335` | subtle borders |
| `--txt` / `--text` | `#ececec` | primary text |
| `--muted` / `--text-secondary` | `#8b8b8d` | secondary text |
| `--dim` / `--text-muted` | `#5c5c5e` | de-emphasized text |
| `--brand` | `#3b82f6` | product accent (blue), hover `#2563eb` |
| `--accent2` | `#8b5cf6` | secondary highlight; PRIMARY accent on engineering surfaces only |
| `--good` / `--success` | `#22c55e` | success |
| `--warn` / `--warning` | `#eab308` | warning |
| `--bad` / `--error` | `#ef4444` | error/critical |

Vendor accent chips (`--vendor-*`) are the vendors' own brand colors and live in
`html_theme.py`; they never replace the product accent, only the per-vendor
`<body class="theme-*">` accent inside collector outputs.

## Typography

UI: Inter (fallback system-ui stack) · Data/code: JetBrains Mono (fallback
ui-monospace stack).

## Adopters and their token blocks

| Surface | File | Naming scheme |
|---|---|---|
| Collector HTML (all vendors) | `core/html_theme.py` (this repo) | short + aliases |
| Appliance UI | `netconverter-local/viewer.html` `:root` | both (aliased) |
| Client portal export | `netconverter-local/assets/portal/portal.css` | own light theme; blue accent must match `--brand` |
| Engineering portal | `netconverter-mvp/tool/engineering.html` | canonical long names; purple accent per policy |
| Admin portal / tool pages | `netconverter-mvp/tool/…` | align on next server pass |

Changing a VALUE here is a product-wide decision — update this file first, then
every adopter, in one coordinated pass.
