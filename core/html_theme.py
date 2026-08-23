"""Shared NetConverter HTML theme — vendor accents match netconverter.local."""

from __future__ import annotations

VENDORS = {
    "checkpoint": {
        "theme_class": "theme-checkpoint",
        "chip": "Check Point",
        "title_suffix": "Check Point Config",
        "tagline": "Read-only browser",
        "gradient": ("#ff2e74", "#e6004d"),
    },
    "palo": {
        "theme_class": "theme-paloalto",
        "chip": "Palo Alto",
        "title_suffix": "Panorama Config",
        "tagline": "Read-only browser",
        "gradient": ("#fa582d", "#c2410c"),
    },
    "fmc": {
        "theme_class": "theme-fmc",
        "chip": "Cisco FMC",
        "title_suffix": "FMC Config",
        "tagline": "Read-only browser",
        "gradient": ("#049fd9", "#0369a1"),
    },
    "scm": {
        "theme_class": "theme-scm",
        "chip": "Strata SCM",
        "title_suffix": "SCM Config",
        "tagline": "Read-only browser",
        "gradient": ("#7c3aed", "#6d28d9"),
    },
    "fortinet": {
        "theme_class": "theme-fortinet",
        "chip": "FortiManager",
        "title_suffix": "FortiGate Config",
        "tagline": "Read-only browser",
        "gradient": ("#2e86d6", "#15497e"),
    },
}


def vendor(key: str) -> dict:
    if key not in VENDORS:
        raise KeyError(f"unknown vendor {key!r}; choose from {list(VENDORS)}")
    return VENDORS[key]


CSS = """

/* NetConverter shell (netconverter.ai) + vendor accent on <body class="theme-*"> */
/* OFFLINE-FIRST: no @import, no <link> to a font CDN, no network request of any
   kind. Collector HTML is opened from file:// at customer sites that are often
   air-gapped, so a remote webfont would silently fail and leave the page on an
   unspecified fallback. Inter / JetBrains Mono are still listed first so they are
   used when the reader happens to have them installed locally; everything after
   them is an explicit, ordered system stack that renders correctly with zero
   network. LIMITATION: this repo ships no .woff2, so the collector cannot embed
   the brand faces as data: URIs the way the appliance serves them from
   /assets/fonts/*.woff2 — offline output is metric-compatible, not pixel-identical
   to the portal. Do not reintroduce a remote font URL here. */
:root{
  --bg-base:#0a0a0b; --bg:#0a0a0b; --bg2:#141415; --panel:#141415; --panel2:#1c1c1e; --line:#2a2a2c; --line-soft:#333335;
  --txt:#ececec; --muted:#8b8b8d; --dim:#5c5c5e;
  --brand:#3b82f6; --brand-hover:#2563eb;
  --accent:var(--brand); --accent-hover:var(--brand-hover); --accent2:#8b5cf6; --accent-glow:rgba(59,130,246,.22);
  --good:#22c55e; --warn:#eab308; --bad:#ef4444;
  /* Canonical long-name aliases (see core/DESIGN-TOKENS.md) — same values,
     server-portal naming; lets any surface use either scheme. */
  --bg-surface:var(--panel); --bg-elevated:var(--panel2); --bg-hover:#222224;
  --border:var(--line); --border-light:var(--line-soft);
  --text:var(--txt); --text-secondary:var(--muted); --text-muted:var(--dim);
  --success:var(--good); --warning:var(--warn); --error:var(--bad);
  --vendor-cp:#ff2e74; --vendor-cp2:#e6004d;
  --vendor-pa:#fa582d; --vendor-pa2:#ff8a5c;
  --vendor-fmc:#049fd9; --vendor-fmc2:#0369a1;
  --vendor-forti:#ee3124; --vendor-forti2:#ff6a5c; --vendor-forti-navy:#2e86d6;
  --vendor-scm:#7c3aed; --vendor-scm2:#a78bfa;

  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'DejaVu Sans Mono','Liberation Mono','Courier New',monospace;
  --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI Variable Text','Segoe UI',Roboto,'Helvetica Neue','Noto Sans',Arial,sans-serif,'Apple Color Emoji','Segoe UI Emoji';
  --radius:10px; --radius-lg:14px;
  --shadow-sm:0 1px 2px rgba(0,0,0,.35); --shadow-md:0 8px 24px rgba(0,0,0,.45);
}
body.theme-netconverter{
  --accent:var(--brand); --accent-hover:var(--brand-hover); --accent2:#8b5cf6;
  --accent-glow:rgba(59,130,246,.22);
}
body.theme-checkpoint{
  --accent:var(--vendor-cp); --accent-hover:var(--vendor-cp2); --accent2:#ff7aa5;
  --accent-glow:rgba(255,46,116,.28);
}

body.theme-fmc{
  --accent:var(--vendor-fmc); --accent-hover:var(--vendor-fmc2); --accent2:#5cc6f5;
  --accent-glow:rgba(4,159,217,.28);
}
body.theme-fortinet{
  --accent:var(--vendor-forti-navy); --accent-hover:#2467a8; --accent2:#5cc6f5;
  --accent-glow:rgba(46,134,214,.28);
}
body.theme-scm{
  --accent:var(--vendor-scm); --accent-hover:#6d28d9; --accent2:var(--vendor-scm2);
  --accent-glow:rgba(124,58,237,.28);
}
body.theme-paloalto{
  --accent:var(--vendor-pa); --accent-hover:#e04a1f; --accent2:var(--vendor-pa2);
  --accent-glow:rgba(250,88,45,.28);
}
* { box-sizing:border-box; }
body { margin:0; font-family:var(--sans); font-size:13.5px; line-height:1.45;
  background:var(--bg-base); background-attachment:fixed;
  color:var(--txt); -webkit-font-smoothing:antialiased; letter-spacing:-.01em; }
body.theme-netconverter{
  background:
    radial-gradient(ellipse 80% 50% at 0% 0%, rgba(59,130,246,.12), transparent 55%),
    radial-gradient(ellipse 70% 45% at 100% 0%, rgba(139,92,246,.08), transparent 50%),
    var(--bg-base);
}
body.theme-checkpoint{
  background:
    radial-gradient(ellipse 75% 48% at 0% 0%, rgba(255,46,116,.14), transparent 52%),
    radial-gradient(ellipse 65% 42% at 100% 8%, rgba(230,0,77,.08), transparent 48%),
    var(--bg-base);
}

body.theme-fmc{
  background:
    radial-gradient(ellipse 75% 48% at 0% 0%, rgba(4,159,217,.14), transparent 52%),
    radial-gradient(ellipse 65% 42% at 100% 8%, rgba(3,105,161,.08), transparent 48%),
    var(--bg-base);
}
body.theme-fortinet{
  background:
    radial-gradient(ellipse 75% 48% at 0% 0%, rgba(46,134,214,.16), transparent 52%),
    radial-gradient(ellipse 60% 40% at 100% 6%, rgba(92,198,245,.08), transparent 46%),
    var(--bg-base);
}
body.theme-scm{
  background:
    radial-gradient(ellipse 70% 45% at 12% 0%, rgba(124,58,237,.14), transparent 50%),
    radial-gradient(ellipse 55% 40% at 88% 100%, rgba(0,0,0,.55), transparent 45%),
    var(--bg-base);
}
body.theme-paloalto{
  background:
    radial-gradient(ellipse 70% 45% at 12% 0%, rgba(250,88,45,.16), transparent 50%),
    radial-gradient(ellipse 55% 40% at 88% 100%, rgba(0,0,0,.55), transparent 45%),
    linear-gradient(180deg, #121212 0%, var(--bg-base) 38%),
    var(--bg-base);
}
a { color:var(--accent); text-decoration:none; font-weight:500; transition:color .15s; }
body.theme-netconverter a:hover { color:#93c5fd; }
body.theme-checkpoint a:hover { color:#ffb3cc; }
body.theme-paloalto a:hover { color:#fdba74; }

body.theme-fmc a:hover { color:#7dd3fc; }
body.theme-fortinet a:hover { color:#93c5fd; }
body.theme-scm a:hover { color:#c4b5fd; }

::-webkit-scrollbar{ width:9px; height:9px; }
::-webkit-scrollbar-track{ background:transparent; }
::-webkit-scrollbar-thumb{ background:#333335; border-radius:8px; border:2px solid var(--bg-base); }
::-webkit-scrollbar-thumb:hover{ background:#444446; }
.layout { display:flex; min-height:100vh; }
.viewer-version { position:fixed; top:10px; right:14px; z-index:100; font-family:var(--mono); font-size:10px;
  font-weight:600; letter-spacing:.04em; color:var(--dim); padding:4px 10px; border-radius:999px;
  border:1px solid var(--line); background:rgba(20,20,21,.88); backdrop-filter:blur(8px);
  -webkit-backdrop-filter:blur(8px); pointer-events:none; user-select:none; }

/* ---- sidebar ---- */
.nav { width:264px; background:rgba(20,20,21,.92); backdrop-filter:blur(16px); -webkit-backdrop-filter:blur(16px);
  border-right:1px solid var(--line); padding:0 14px 20px; position:sticky; top:0; height:100vh;
  overflow:auto; flex-shrink:0; box-shadow:var(--shadow-sm); }
.nav h1 { display:none; }
.brand { display:flex; align-items:flex-start; gap:12px; padding:20px 4px 16px; margin-bottom:2px;
  border-bottom:1px solid var(--line); position:relative; }
.brand::after { content:""; position:absolute; left:4px; bottom:-1px; width:52px; height:2px;
  background:linear-gradient(90deg,var(--accent),var(--accent2)); border-radius:2px; }
.brand-mark { width:36px; height:36px; flex-shrink:0; filter:drop-shadow(0 2px 10px var(--accent-glow)); }
.brand-name { font-weight:700; font-size:1.05rem; color:var(--txt); letter-spacing:-.03em; line-height:1.15; }
.brand-accent { color:var(--accent); font-weight:700; }
.brand-tag { font-size:11px; color:var(--muted); margin-top:6px; line-height:1.4; display:flex; flex-wrap:wrap; gap:6px; align-items:center; }
.vendor-chip { display:inline-block; font-size:9px; font-weight:600; letter-spacing:.06em; text-transform:uppercase;
  padding:2px 7px; border-radius:999px; border:1px solid color-mix(in srgb, var(--accent) 35%, transparent); color:var(--accent);
  background:color-mix(in srgb, var(--accent) 8%, transparent); font-family:var(--mono); }
.nav .sub { color:var(--dim); font-size:11px; font-family:var(--mono); margin:12px 4px 16px;
  padding:8px 10px; background:var(--bg2); border:1px solid var(--line); border-radius:var(--radius); word-break:break-all; }
.nav a { display:block; padding:7px 12px; border-radius:var(--radius); color:var(--muted); margin:2px 0; font-size:13px;
  font-weight:500; position:relative; transition:background .15s,color .15s; }
.nav a:hover { background:var(--panel2); color:var(--txt); }
.nav a.active { background:color-mix(in srgb, var(--accent) 14%, transparent); color:var(--txt); }
.nav a.active::before { content:""; position:absolute; left:-14px; top:5px; bottom:5px; width:3px;
  background:linear-gradient(180deg,var(--accent),var(--accent2)); border-radius:0 4px 4px 0; box-shadow:0 0 12px var(--accent-glow); }
.nav .group { color:var(--dim); text-transform:uppercase; font-size:10px; letter-spacing:.12em; font-weight:600;
  margin:18px 0 6px 12px; }
.nav-foot { margin-top:auto; padding:14px 8px 0; border-top:1px solid var(--line);
  font-size:11px; color:var(--dim); line-height:1.65; }
.nav-foot a { font-weight:600; color:var(--brand); }

/* ---- main content ---- */
.main { flex:1; padding:28px 36px 48px; max-width:100%; overflow:auto; position:relative; min-width:0; }
.main::before { content:""; position:fixed; top:0; left:264px; right:0; height:1px; z-index:60;
  background:linear-gradient(90deg,var(--accent),rgba(139,92,246,.5),transparent 75%); opacity:.9; }
h2 { color:var(--txt); margin:0 0 6px; font-size:1.375rem; font-weight:600; letter-spacing:-.03em; }
.meta { color:var(--muted); margin-bottom:22px; font-size:12.5px; max-width:72ch; }
.meta .mono { font-family:var(--mono); font-size:11.5px; color:var(--dim); }

/* ---- KPI cards ---- */
.cards { display:grid; grid-template-columns:repeat(auto-fill,minmax(152px,1fr)); gap:14px; margin:20px 0 28px; }
.card { background:rgba(28,28,30,.85); border:1px solid var(--line); border-radius:var(--radius-lg);
  padding:16px 18px; position:relative; overflow:hidden;
  box-shadow:var(--shadow-sm); animation:rise .45s cubic-bezier(.2,.7,.2,1) both;
  transition:border-color .2s,box-shadow .2s,transform .2s; }
.card::after { content:""; position:absolute; inset:0; border-radius:inherit; pointer-events:none;
  background:linear-gradient(135deg,rgba(255,255,255,.04),transparent 50%); opacity:0; transition:opacity .2s; }
.card:hover { border-color:var(--line-soft); transform:translateY(-2px); box-shadow:var(--shadow-md); }
.card:hover::after { opacity:1; }
.card .n { font-size:1.65rem; font-weight:700; color:var(--txt); font-family:var(--mono); letter-spacing:-.03em; line-height:1.1; }
.card .l { color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:.07em; margin-top:6px; font-weight:600; }
.card.warn .n { color:var(--warn); } .card.bad .n { color:var(--bad); } .card.good .n { color:var(--good); }
.card.warn { border-color:rgba(234,179,8,.28); } .card.bad { border-color:rgba(239,68,68,.28); }
.card.good { border-color:rgba(34,197,94,.25); }
@keyframes rise { from{ opacity:0; transform:translateY(8px); } to{ opacity:1; transform:translateY(0); } }
.card:nth-child(2){animation-delay:.03s;} .card:nth-child(3){animation-delay:.06s;}
.card:nth-child(4){animation-delay:.09s;} .card:nth-child(5){animation-delay:.12s;}
.card:nth-child(6){animation-delay:.15s;} .card:nth-child(n+7){animation-delay:.18s;}

/* ---- tables ---- */
.table-wrap { margin:16px 0 24px; border-radius:var(--radius-lg); overflow:hidden;
  border:1px solid var(--line); box-shadow:var(--shadow-sm); }
table { border-collapse:separate; border-spacing:0; width:100%; background:var(--bg2); }
th,td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:rgba(20,20,21,.98); color:var(--muted); position:sticky; top:0; z-index:10;
  cursor:pointer; user-select:none; font-size:10px; text-transform:uppercase; letter-spacing:.06em; font-weight:600; }
th:hover { color:var(--accent); }
th.sorted-asc::after { content:" ▲"; font-size:9px; color:var(--accent); }
th.sorted-desc::after { content:" ▼"; font-size:9px; color:var(--accent); }
.table-hint { font-size:12px; color:var(--dim); margin:0 0 10px; }
tbody tr:nth-child(even) td { background:rgba(255,255,255,.015); }
tbody tr:hover td { background:color-mix(in srgb, var(--accent) 7%, transparent); }
tr:last-child td { border-bottom:none; }
td.mono,.mono { font-family:var(--mono); font-size:11.5px; color:#c4c4c8; }

/* ---- tags / badges ---- */
.tag { display:inline-block; padding:2px 9px; border-radius:6px; font-size:11px; font-weight:600; font-family:var(--mono); }
.t-accept{background:rgba(34,197,94,.14);color:var(--good);} .t-drop{background:rgba(239,68,68,.14);color:var(--bad);}
.t-reject{background:rgba(234,179,8,.14);color:var(--warn);} .t-other{background:var(--panel2);color:var(--muted);}
.t-inner{background:rgba(59,130,246,.14);color:#93c5fd;}
.disabled td { opacity:.4; }
tr:target td { background:color-mix(in srgb, var(--accent) 22%, transparent) !important;
  box-shadow:inset 3px 0 0 var(--accent); animation:rowflash 1.4s ease-out 1; }
@keyframes rowflash { 0%{background:color-mix(in srgb, var(--accent) 55%, transparent);} 100%{} }
.pill { font-size:11px; padding:2px 8px; border-radius:6px; background:var(--panel2); color:var(--muted); font-family:var(--mono); border:1px solid var(--line); }
.pill.bad { color:var(--bad); border-color:rgba(239,68,68,.35); background:rgba(239,68,68,.08); }
.pill.good { color:var(--good); border-color:rgba(34,197,94,.30); background:rgba(34,197,94,.07); }
.badge { font-size:10px; padding:2px 8px; border-radius:6px; font-weight:600; font-family:var(--mono); letter-spacing:.03em; }
.b-red{background:rgba(239,68,68,.14);color:#fca5a5;} .b-amber{background:rgba(234,179,8,.14);color:#fde047;}
.b-blue{background:rgba(59,130,246,.14);color:#93c5fd;}

/* ---- forms / notes ---- */
.search { width:100%; max-width:440px; padding:10px 14px; margin-bottom:16px; background:var(--bg2);
  border:1px solid var(--line); border-radius:var(--radius); color:var(--txt); font-size:13px; font-family:var(--sans);
  transition:border-color .15s,box-shadow .15s; }
.search:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-glow); }
.search::placeholder { color:var(--dim); }
.note { background:color-mix(in srgb, var(--accent) 8%, transparent); border:1px solid color-mix(in srgb, var(--accent) 28%, transparent); border-left:3px solid var(--accent);
  padding:12px 16px; border-radius:0 var(--radius) var(--radius) 0; margin:14px 0; color:var(--muted); font-size:13px; line-height:1.5; }
.warnbox { border-left-color:var(--warn); border-color:rgba(234,179,8,.2); background:rgba(234,179,8,.06); }
.section-title { margin:32px 0 12px; color:var(--txt); font-size:1rem; font-weight:600; letter-spacing:-.02em;
  display:flex; align-items:baseline; gap:8px; }
.section-title::after { content:""; flex:1; height:1px; background:var(--line); margin-left:8px; }
.count { color:var(--dim); font-weight:500; font-size:12px; font-family:var(--mono); }
.muted { color:var(--dim); }
.vbtn { background:var(--panel2); border:1px solid var(--line-soft); color:var(--txt); font-size:12px;
  font-weight:600; padding:6px 12px; border-radius:var(--radius); cursor:pointer; transition:all .15s; }
.vbtn:hover { border-color:var(--accent); color:var(--accent); }
.filterbar { display:flex; gap:14px; align-items:center; flex-wrap:wrap; margin:6px 0 14px; }
.filterbar .search { margin-bottom:0; max-width:240px; }
.filterbar label { display:flex; align-items:center; gap:6px; font-size:12.5px; color:var(--muted); cursor:pointer; }
.filterbar input[type=checkbox] { accent-color:var(--accent); width:15px; height:15px; }
.filterbar select { background:var(--bg2); border:1px solid var(--line); color:var(--txt); font-size:12.5px;
  padding:7px 10px; border-radius:var(--radius); font-family:var(--sans); cursor:pointer; }
.obj { cursor:pointer; border-bottom:1px dotted rgba(59,130,246,.45); white-space:nowrap; color:#bfdbfe; }
.obj:hover { color:var(--accent); border-bottom-color:var(--accent); }

/* ---- object inspector ---- */
#opop { display:none; position:fixed; top:72px; right:20px; width:380px; max-height:74vh;
  overflow-y:auto; background:rgba(20,20,21,.97); backdrop-filter:blur(20px); border:1px solid var(--line-soft);
  border-radius:var(--radius-lg); padding:18px 20px; z-index:200; box-shadow:var(--shadow-md); }
#opop .ptitle { font-size:15px; font-weight:600; color:var(--txt); margin:0 28px 6px 0; word-break:break-all; letter-spacing:-.02em; }
#opop .ptype  { font-size:11px; color:var(--dim); margin-bottom:12px; font-family:var(--mono); }
#opop .prow   { display:flex; gap:10px; border-bottom:1px solid var(--line); padding:6px 0; font-size:12px; }
#opop .pk     { color:var(--dim); min-width:80px; flex-shrink:0; font-weight:500; }
#opop .pv     { color:#d4d4d8; font-family:var(--mono); word-break:break-all; font-size:11.5px; }
#opop .pclose { position:absolute; top:14px; right:16px; cursor:pointer; color:var(--dim); font-size:20px; line-height:1; }
#opop .pclose:hover { color:var(--bad); }
#opop .pmemhdr{ font-size:11px; color:var(--dim); margin:10px 0 4px; font-weight:600; text-transform:uppercase; letter-spacing:.06em; }
#opop .pmember{ font-family:var(--mono); font-size:11px; color:var(--muted); padding:3px 0; border-bottom:1px solid var(--line); }

.plat-stacks { display:flex; flex-direction:column; gap:14px; margin:12px 0 28px; }
.plat-stack { border:1px solid var(--line-soft); border-radius:var(--radius-lg); background:var(--panel); overflow:hidden; }
.plat-head { padding:14px 18px; background:var(--panel2); border-bottom:1px solid var(--line); }
.plat-head .plat-title { font-size:15px; font-weight:600; letter-spacing:-.02em; }
.plat-head .plat-meta { font-size:11.5px; color:var(--dim); margin-top:5px; font-family:var(--mono); line-height:1.5; }
.plat-body { padding:6px 0 10px; }
.plat-section-label { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.08em; color:var(--dim); margin:10px 18px 4px; }
.plat-row { display:grid; grid-template-columns:minmax(200px,1.4fr) minmax(110px,auto) minmax(140px,auto); gap:6px 14px; padding:5px 18px; font-size:12.5px; align-items:baseline; border-left:2px solid var(--line); margin-left:18px; }
.plat-row.physical { grid-template-columns:minmax(160px,1fr) minmax(110px,auto); }
.plat-row.virtual { margin-left:34px; border-left-color:rgba(96,165,250,.35); }
.plat-row-name { font-weight:500; }
.plat-row-ip { font-family:var(--mono); font-size:11.5px; color:var(--muted); }
.plat-row-policy { font-family:var(--mono); font-size:11.5px; color:var(--txt); }
.plat-row-hint { font-size:11px; color:var(--dim); }
.plat-arrow { color:var(--dim); margin:0 4px; }

.fw-hierarchies { display:flex; flex-direction:column; gap:16px; margin:16px 0 28px; }
.fw-platform { border:1px solid var(--line-soft); border-radius:var(--radius-lg); background:var(--panel); overflow:hidden; }
.fw-platform > summary { padding:14px 18px; cursor:pointer; font-weight:600; font-size:14px; background:var(--panel2); border-bottom:1px solid var(--line); list-style:none; }
.fw-platform > summary::-webkit-details-marker { display:none; }
.fw-platform > summary::before { content:"▸ "; color:var(--dim); }
.fw-platform[open] > summary::before { content:"▾ "; }
.fw-platform-body { padding:8px 12px 14px; }
.fw-level { margin:6px 0 0 12px; border-left:2px solid var(--line); }
.fw-level > summary { padding:8px 12px; cursor:pointer; font-size:13px; font-weight:500; color:var(--txt); list-style:none; }
.fw-level > summary::-webkit-details-marker { display:none; }
.fw-level > summary::before { content:"▸ "; color:var(--dim); font-size:11px; }
.fw-level[open] > summary::before { content:"▾ "; }
.fw-level-body { padding:4px 12px 10px 20px; font-size:12.5px; }
.fw-node { margin:6px 0; padding:8px 12px; border:1px solid var(--line); border-radius:var(--radius); background:rgba(255,255,255,.02); }
.fw-node-meta { font-size:11.5px; color:var(--dim); margin-top:4px; font-family:var(--mono); line-height:1.45; }
.fw-node-actions { margin-top:6px; font-size:11.5px; }
.fw-lbl { font-size:10px; font-weight:600; text-transform:uppercase; letter-spacing:.07em; color:var(--dim); margin-right:8px; }

@media (max-width:960px){
  .nav{ width:220px; } .main{ padding:20px 18px; } .main::before{ left:220px; }
  .cards{ grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); }
}
"""

JS = """

function filterTable(input){
  var q = input.value.toLowerCase();
  var table = document.getElementById(input.dataset.target);
  if(!table) return;
  var rows = table.tBodies[0].rows;
  var shown = 0;
  for(var i=0;i<rows.length;i++){
    var t = rows[i].innerText.toLowerCase();
    var ok = t.indexOf(q) > -1;
    rows[i].style.display = ok ? '' : 'none';
    if(ok) shown++;
  }
  var c = document.getElementById(input.dataset.count);
  if(c) c.textContent = shown + ' shown';
}
function _sortInd(table, activeTh){
  if(!table||!table.tHead) return;
  var ths=table.tHead.rows[0].cells;
  for(var i=0;i<ths.length;i++){
    var th=ths[i];
    if(th!==activeTh){ th.removeAttribute('data-dir'); th.classList.remove('sorted-asc','sorted-desc'); }
  }
  if(activeTh){
    activeTh.classList.toggle('sorted-asc', activeTh.dataset.dir==='asc');
    activeTh.classList.toggle('sorted-desc', activeTh.dataset.dir==='desc');
  }
}
function sortTable(th){
  var table = th.closest('table');
  if(!table||!table.tBodies.length) return;
  var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
  var tbody = table.tBodies[0];
  var rows = Array.prototype.slice.call(tbody.rows);
  var dir = th.dataset.dir === 'asc' ? -1 : 1;
  th.dataset.dir = dir === 1 ? 'asc' : 'desc';
  _sortInd(table, th);
  rows.sort(function(a,b){
    var x=a.cells[idx]?a.cells[idx].innerText.trim():'';
    var y=b.cells[idx]?b.cells[idx].innerText.trim():'';
    var nx=parseFloat(x.replace(/[^0-9.\\-]/g,'')), ny=parseFloat(y.replace(/[^0-9.\\-]/g,''));
    if(x!==''&&y!==''&&!isNaN(nx)&&!isNaN(ny)) return (nx-ny)*dir;
    return x.localeCompare(y, undefined, {numeric:true, sensitivity:'base'})*dir;
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}
function wireInventoryFilters(opts){
  var tbl=document.getElementById(opts.tableId);
  if(!tbl||!tbl.tBodies.length) return;
  var filterEl=opts.filterId?document.getElementById(opts.filterId):null;
  var cnt=opts.countId?document.getElementById(opts.countId):null;
  var rows=Array.prototype.slice.call(tbl.tBodies[0].rows);
  var selects=(opts.selects||[]).map(function(s){
    return {el:document.getElementById(s.id), attr:s.attr};
  });
  var checks=(opts.checks||[]).map(function(c){
    return {el:document.getElementById(c.id), attr:c.attr, val:c.val};
  });
  function apply(){
    var term=filterEl?(filterEl.value||'').toLowerCase():'';
    var n=0;
    rows.forEach(function(r){
      var show=true;
      if(term && r.textContent.toLowerCase().indexOf(term)<0) show=false;
      selects.forEach(function(s){
        if(show && s.el && s.el.value && r.getAttribute(s.attr)!==s.el.value) show=false;
      });
      checks.forEach(function(c){
        if(show && c.el && c.el.checked && r.getAttribute(c.attr)!==c.val) show=false;
      });
      r.style.display=show?'':'none';
      if(show) n++;
    });
    if(cnt) cnt.textContent=n+' shown';
  }
  if(filterEl){ filterEl.addEventListener('input',apply); filterEl.addEventListener('search',apply); }
  selects.forEach(function(s){ if(s.el){ s.el.addEventListener('change',apply); } });
  checks.forEach(function(c){ if(c.el){ c.el.addEventListener('change',apply); } });
  apply();
}
function initInventoryTables(){
  document.querySelectorAll('table thead th').forEach(function(th){
    var table=th.closest('table');
    if(!table||!table.tBodies.length) return;
    th.setAttribute('title','Click to sort');
    th.addEventListener('click',function(){ sortTable(th); });
  });
  if(typeof INV_FILTERS!=='undefined'){
    INV_FILTERS.forEach(wireInventoryFilters);
  }
}
if(document.readyState==='loading'){
  document.addEventListener('DOMContentLoaded', initInventoryTables);
}else{
  initInventoryTables();
}
function filterBlocks(input){
  var q = input.value.toLowerCase();
  var container = document.getElementById(input.dataset.target);
  if(!container) return;
  var blocks = container.querySelectorAll('.plat-stack');
  var shown = 0;
  blocks.forEach(function(b){
    var ok = b.innerText.toLowerCase().indexOf(q) > -1;
    b.style.display = ok ? '' : 'none';
    if(ok) shown++;
  });
  var c = document.getElementById(input.dataset.count);
  if(c) c.textContent = shown + ' shown';
}
function exportTableCSV(tableId, filename){
  var table=document.getElementById(tableId);
  if(!table) return;
  function cell(s){ s=(s==null?'':String(s)).replace(/\\u00a0/g,' ').replace(/\\s+/g,' ').trim();
    return /[",\\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; }
  var out=[];
  var head=table.tHead?Array.prototype.map.call(table.tHead.rows[0].cells,function(c){return cell(c.innerText);}):[];
  if(head.length) out.push(head.join(','));
  var rows=table.tBodies[0]?table.tBodies[0].rows:[];
  for(var i=0;i<rows.length;i++){
    if(rows[i].style.display==='none') continue;
    var r=Array.prototype.map.call(rows[i].cells,function(c){
      var t=c.innerText.replace(/\\n/g,'; ');
      return cell(t);
    });
    out.push(r.join(','));
  }
  var blob=new Blob(['\\ufeff'+out.join('\\r\\n')],{type:'text/csv;charset=utf-8;'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=filename||(tableId+'.csv'); document.body.appendChild(a); a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); },100);
}
if(typeof OBJ==='undefined')var OBJ={};
function _el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e;}
function _addRow(pop,k,v){
  var row=_el('div','prow');
  row.appendChild(_el('span','pk',k));
  row.appendChild(_el('span','pv',String(v)));
  pop.appendChild(row);
}
function showObj(uid){
  var pop=document.getElementById('opop');
  if(!pop) return;
  var o=OBJ[uid];
  if(!o){pop.style.display='none';return;}
  while(pop.firstChild)pop.removeChild(pop.firstChild);
  var cl=_el('span','pclose','✕');
  cl.addEventListener('click',function(){pop.style.display='none';});
  pop.appendChild(cl);
  pop.appendChild(_el('div','ptitle',o.name));
  pop.appendChild(_el('div','ptype',o.type));
  if(o.ip)                     _addRow(pop,'IP',o.ip);
  if(o.subnet!==undefined)     _addRow(pop,'Subnet',o.subnet+'/'+o.mask);
  if(o.first)                  _addRow(pop,'Range',o.first+' – '+o.last);
  if(o.proto)                  _addRow(pop,'Protocol',o.proto);
  if(o.port!==undefined)       _addRow(pop,'Port / Type',o.port);
  if(o.members&&o.members.length){
    pop.appendChild(_el('div','pmemhdr','Members ('+o.members.length+')'));
    o.members.forEach(function(m){pop.appendChild(_el('div','pmember',m));});
  }
  pop.style.display='block';
}
document.addEventListener('click',function(e){
  var pop=document.getElementById('opop');
  if(pop&&!pop.contains(e.target)&&!e.target.classList.contains('obj'))
    pop.style.display='none';
});

"""
