"""Shared CVE threat-intel enrichment for all vendor builders.

Tiered model (decision-critical vs enrichment vs prioritization):

* **Tier 1 — curated KNOWN_CVES + CISA KEV.** The only inputs that drive
  compliance rows. Conservative matching; never weakened by anything below.
* **Tier 2 — NVD CPE discovery (informational).** For each distinct device OS
  version we query NVD 2.0 by CPE (``cpe:2.3:o:fortinet:fortios:<ver>``,
  ``cpe:2.3:o:checkpoint:gaia_os:<ver>``) to surface ALL matching CVEs beyond
  the curated set. Labeled "verify applicability"; NEVER flips a compliance
  control.
* **Tier 3 — EPSS exploitation-probability scores** (FIRST.org, free, batch)
  for every CVE we know about, used purely for prioritization/sorting.

Everything uses only the Python standard library, with a local on-disk cache
(shipped inside collector bundles) and graceful offline fallback.

Design rule: we never fabricate data. On any network failure we fall back to
the cache, then to whatever curated metadata the caller already has — so a
finding is only ever as strong as evidence we can actually back up.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
NVD_CPE_URL = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
               "?cpeName={cpe}&resultsPerPage=200")
EPSS_URL = "https://api.first.org/data/v1/epss?cve={ids}"
_INTEL_TTL = 7 * 24 * 3600  # 7 days


def ver_tuple(value: str) -> tuple:
    """'7.4.3' -> (7, 4, 3); tolerant of junk and missing parts."""
    out = []
    for part in str(value or "").split("."):
        m = re.match(r"\d+", part.strip())
        out.append(int(m.group()) if m else 0)
    return tuple(out)


def ver_train(value: str) -> str:
    """'7.4.3' -> '7.4' (major.minor train)."""
    t = ver_tuple(value)
    if len(t) >= 2:
        return f"{t[0]}.{t[1]}"
    return str(t[0]) if t else ""


def has_patch(value: str) -> bool:
    """True when an exact build (3+ numeric components) is known, e.g. 7.4.3."""
    return len(ver_tuple(value)) >= 3


def device_cve_status(dev_ver: str, fixed: dict) -> str:
    """One of: 'vulnerable' | 'patched' | 'verify' | 'na'.

    na      -> the device's train is not in the advisory's affected set.
    verify  -> train is affected but the exact build is unknown (no false positives).
    """
    train = ver_train(dev_ver)
    fx = fixed.get(train)
    if not fx:
        return "na"
    if not has_patch(dev_ver):
        return "verify"
    return "vulnerable" if ver_tuple(dev_ver) < ver_tuple(fx) else "patched"


def cpe_for_version(vendor: str, version: str) -> str:
    """Build the NVD CPE 2.3 name for a device OS version; '' when not derivable.

    fortinet   -> cpe:2.3:o:fortinet:fortios:<x.y.z>  (exact build required —
                  a bare train like '7.4' is not a dictionary CPE)
    checkpoint -> cpe:2.3:o:checkpoint:gaia_os:<rXX.YY>  (verified against NVD:
                  gaia_os carries the real advisory data; the
                  quantum_security_gateway_firmware CPE is nearly empty)
    """
    v = str(version or "").strip().lower()
    if not v:
        return ""
    if vendor == "fortinet":
        m = re.match(r"(\d+\.\d+\.\d+)", v)
        return f"cpe:2.3:o:fortinet:fortios:{m.group(1)}" if m else ""
    if vendor == "checkpoint":
        m = re.match(r"r(\d+(?:\.\d+)*)", v)
        return f"cpe:2.3:o:checkpoint:gaia_os:r{m.group(1)}" if m else ""
    return ""


def _http_json(url: str, headers: dict | None = None, timeout: int = 20):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "NetConverter/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted gov hosts)
        return json.loads(resp.read().decode("utf-8", "replace"))


def _parse_nvd_cve(c: dict) -> dict:
    """Extract {cvss, severity, summary, url} from one NVD 2.0 'cve' object."""
    metrics = c.get("metrics", {})
    m = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
         or metrics.get("cvssMetricV2") or [])
    cvss = sev = ""
    if m:
        cd = m[0].get("cvssData", {})
        cvss = cd.get("baseScore", "")
        sev = m[0].get("baseSeverity") or cd.get("baseSeverity", "")
    desc = ""
    for d in c.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cve_id = c.get("id", "")
    return {"cvss": cvss, "severity": sev, "summary": desc[:400],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}


def fetch_epss(cve_ids: list[str], timeout: int = 20) -> dict:
    """EPSS exploitation-probability scores from FIRST.org: {cve: float 0..1}.

    Free, keyless, batched (100 CVEs per request). Network errors yield a
    partial (possibly empty) dict — never an exception.
    """
    out: dict = {}
    ids = [c for c in dict.fromkeys(cve_ids) if c]
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            if i:
                time.sleep(1)  # be polite between batches
            data = _http_json(EPSS_URL.format(ids=",".join(chunk)), timeout=timeout)
            for row in data.get("data", []):
                try:
                    out[row["cve"]] = float(row["epss"])
                except (KeyError, TypeError, ValueError):
                    continue
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
            print(f"  [intel] EPSS batch skipped ({exc.__class__.__name__}).")
    return out


def discover_cves_for_cpe(cpe: str, api_key: str | None = None,
                          timeout: int = 30) -> list[dict]:
    """All CVEs NVD matches to one CPE (informational — verify applicability).

    Returns [{cve, cvss, severity, summary, url}] sorted by CVSS desc.
    Polite throttling/backoff for the keyless 5-req/30s budget; a CPE that is
    not in the NVD dictionary (404) simply yields []. Raises on other network
    failures so the caller can decide to keep cached data.
    """
    headers = {"User-Agent": "NetConverter/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    url = NVD_CPE_URL.format(cpe=urllib.parse.quote(str(cpe), safe=":*"))
    data = None
    for attempt in (1, 2):
        try:
            data = _http_json(url, headers=headers, timeout=timeout)
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:  # CPE not in the official dictionary
                return []
            if exc.code in (403, 429, 503) and attempt == 1:
                time.sleep(3 if api_key else 12)  # backoff, then retry once
                continue
            raise
    out = []
    for item in (data or {}).get("vulnerabilities", []):
        c = item.get("cve", {})
        cve_id = c.get("id")
        if not cve_id:
            continue
        out.append(dict(_parse_nvd_cve(c), cve=cve_id))
    def _score(e):
        try:
            return float(e.get("cvss") or 0)
        except (TypeError, ValueError):
            return 0.0
    out.sort(key=_score, reverse=True)
    return out


def _empty_cache() -> dict:
    return {"fetched": 0, "kev": [], "nvd": {}, "epss": {}, "discovered": {},
            "fetched_at": {}}


def _load_cache(cache_path: Path) -> dict:
    """Load + normalize: caches written by older versions simply lack the new
    sections (epss / discovered / fetched_at) — treated as empty, never fatal."""
    cache = _empty_cache()
    if cache_path.exists():
        try:
            loaded = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cache.update(loaded)
        except (OSError, ValueError):
            pass
    for key, default in (("kev", []), ("nvd", {}), ("epss", {}),
                         ("discovered", {}), ("fetched_at", {})):
        if not isinstance(cache.get(key), type(default)):
            cache[key] = default
    return cache


def _as_view(cache: dict, source: str) -> dict:
    return {"kev": set(cache.get("kev", [])), "nvd": cache.get("nvd", {}),
            "epss": cache.get("epss", {}), "discovered": cache.get("discovered", {}),
            "source": source}


def fetch_cve_intel(cve_ids: list[str], cache_path: Path, offline: bool,
                    cpes: list[str] | None = None,
                    nvd_api_key: str | None = None,
                    include_discovery: bool = True) -> dict:
    """Return {'kev': set, 'nvd': {cve: {...}}, 'epss': {cve: score},
    'discovered': {cpe: [{cve, cvss, severity, summary, url}]}, 'source': str}.

    Backward compatible with the original (cve_ids, cache_path, offline)
    call shape and with caches that predate epss/discovered.

    Uses a local cache (7-day TTL per section) so repeat builds are instant and
    resilient offline. On any network failure we fall back to cached data, then
    to the caller's curated list. ``cpes`` (e.g. from cpe_for_version) enables
    Tier-2 NVD CPE discovery; results are informational only.
    """
    cache = _load_cache(cache_path)
    want_cpes = [c for c in dict.fromkeys(cpes or []) if c] if include_discovery else []

    now = time.time()
    fat = cache.get("fetched_at", {})
    fresh = (now - cache.get("fetched", 0)) < _INTEL_TTL
    have_all = all(c in cache.get("nvd", {}) for c in cve_ids)
    epss_fresh = (now - fat.get("epss", 0)) < _INTEL_TTL and bool(cache.get("epss"))
    disc_fresh = ((now - fat.get("discovered", 0)) < _INTEL_TTL
                  and all(c in cache.get("discovered", {}) for c in want_cpes))
    if offline or (fresh and have_all and (epss_fresh or not cve_ids)
                   and (disc_fresh or not want_cpes)):
        return _as_view(cache, "offline cache" if offline else "cache")

    kev = set(cache.get("kev", []))
    nvd = dict(cache.get("nvd", {}))
    epss = dict(cache.get("epss", {}))
    discovered = dict(cache.get("discovered", {}))
    source = "cache"
    api_key = (nvd_api_key or os.environ.get("NVD_API_KEY", "")).strip()

    # 1) CISA KEV — single fetch, no auth.
    try:
        data = _http_json(KEV_URL)
        kev = {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
        source = "CISA KEV + NVD"
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        print(f"  [intel] KEV fetch skipped ({exc.__class__.__name__}); using cache/curated.")

    # 2) NVD — one call per CVE; respect rate limits (50/30s with key, 5/30s without).
    spacing = 0.7 if api_key else 6.5
    headers = {"User-Agent": "NetConverter/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    nvd_calls = 0
    for cve in cve_ids:
        try:
            if nvd_calls:
                time.sleep(spacing)
            nvd_calls += 1
            data = _http_json(NVD_URL.format(cve=cve), headers=headers)
            items = data.get("vulnerabilities", [])
            if not items:
                continue
            c = items[0].get("cve", {})
            meta = _parse_nvd_cve(c)
            nvd[cve] = {"cvss": meta["cvss"], "sev": meta["severity"],
                        "desc": meta["summary"],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
            print(f"  [intel] NVD fetch skipped for {cve} ({exc.__class__.__name__}).")

    # 3) Tier 2 — NVD CPE discovery (informational; one query per distinct CPE).
    disc_ok = False
    for cpe in want_cpes:
        try:
            if nvd_calls:
                time.sleep(spacing)
            nvd_calls += 1
            discovered[cpe] = discover_cves_for_cpe(cpe, api_key=api_key or None)
            disc_ok = True
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
            print(f"  [intel] NVD CPE discovery skipped for {cpe} "
                  f"({exc.__class__.__name__}); using cache.")

    # 4) Tier 3 — EPSS scores for every CVE we now know about (curated + discovered).
    all_cves = list(cve_ids)
    for entries in discovered.values():
        all_cves.extend(e.get("cve", "") for e in entries)
    got_epss = fetch_epss(all_cves) if all_cves else {}
    epss_ok = bool(got_epss)
    if got_epss:
        epss.update(got_epss)

    fat = dict(cache.get("fetched_at", {}))
    fat["kev_nvd"] = now
    if epss_ok:
        fat["epss"] = now
    if disc_ok or (want_cpes and all(c in discovered for c in want_cpes)):
        fat["discovered"] = now
    out_cache = {"fetched": now, "kev": sorted(kev), "nvd": nvd, "epss": epss,
                 "discovered": discovered, "fetched_at": fat}
    try:
        cache_path.write_text(json.dumps(out_cache, indent=2), encoding="utf-8")
    except OSError:
        pass
    return {"kev": kev, "nvd": nvd, "epss": epss, "discovered": discovered,
            "source": source}
