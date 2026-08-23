# Collector Versioning

Each collector is versioned **independently** with semantic versioning. The
NetConverter.local appliance has its own separate version — collector versions
are not tied to it (e.g. Palo can be `1.5.0` while FMC is `2.3.0`).

## Source of truth

The single source of truth for a collector's version is the `__version__`
constant in its **entry script** (e.g. `cisco/fmc/fmc_collect_data.py`). The
lockfile, the appliance UI, and the dist manifest all read from these constants.

**Collect and HTML share that version.** When you change `build_html.py` (or
shared HTML helpers in the same technology folder), bump the entry-script
`__version__` as well and set the HTML module's `__version__` / `viewer_version`
to the same string. Do not advertise HTML-only releases that leave the entry
script behind.

| Collector key | Entry script | HTML version location |
|---------------|--------------|------------------------|
| checkpoint | `checkpoint/smartconsole/checkpoint_collect_data.py` | `build_html.py` `__version__` |
| fortinet | `fortinet/fortimanager/fortimanager_collect.py` | `build_html.py` `__version__` |
| fmc | `cisco/fmc/fmc_collect_data.py` | `build_html.py` `__version__` |
| palo | `palo/panorama/panorama_export.py` | `palo/common/html_version.py` |
| scm | `palo/scm/scm_config_pull.py` | scaffold |
| core | `core/manifest.py` | library (no HTML) |

## When you change a collector

1. Bump `__version__` in the entry script **and** the matching HTML module
   (semver: patch = fix, minor = feature, major = breaking output/CLI change).
2. Add a matching `## [X.Y.Z] — YYYY-MM-DD` entry to that collector's
   `CHANGELOG.md` (cover collect and/or HTML in the same release notes).
3. Regenerate the lockfile: `python3 scripts/gen_collectors_lock.py`.
4. Commit the entry script, HTML module(s), `CHANGELOG.md`, and
   `collectors.lock.json` together.

## Enforcement

`scripts/gen_collectors_lock.py` rebuilds `collectors.lock.json` (versions +
content hashes of `*.py` under each collector folder). The appliance build
(`export-images.sh`) runs `check_collector_consistency.py` as a **hard gate** —
it fails the build if the lockfile is stale, a changelog entry is missing, or
the appliance copy has drifted from public-repo. There is no way to ship a dist
zip whose stated collector versions disagree with its contents.

## Publishing

This tree is private. The repo customers are pointed at is
[netconverter-ai/netconverter-tools](https://github.com/netconverter-ai/netconverter-tools),
which is public. Publishing is **one-way** — private dev tree → public tools repo.
Never sync the other direction: this tree holds scaffolds and work-in-progress
that must not ship.

```bash
python3 scripts/gen_collectors_lock.py          # after any __version__ bump
python3 scripts/gen_collectors_lock.py --check  # must pass before publishing
python3 scripts/publish_public.py --target ../netconverter-tools --dry-run
python3 scripts/publish_public.py --target ../netconverter-tools
```

`publish_public.py` ships every collector whose lockfile status is `ready` or
`library`; `scaffold` is excluded. It refuses to run if the tree does not match
`collectors.lock.json`, so the published bytes are always the bytes the lockfile
describes. Paths it does not own (the `fmc-import/` push tool) are left alone,
and `README.md` plus `collectors.lock.json` are rendered rather than copied so
publishing cannot drop them or advertise a collector it did not ship.

Anyone can verify a published tree with `python3 scripts/gen_collectors_lock.py --check`.
