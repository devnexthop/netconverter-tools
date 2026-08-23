# Palo Alto Panorama — read-only export

Exports device-group, template, template-stack and shared configuration from
Panorama via the PAN-OS XML API.

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`

## Collect

**For an engagement, prefer `--running-config`:**

```bash
python panorama_export.py --panorama 10.1.1.50 --user admin \
  --running-config --output customer_snapshot.xml
```

One request returns the entire running config — complete by construction, and
far more robust than ~50 per-entry fetches on a slow or unreliable link. Use the
per-entry flags below only when you need to collect *specific* device groups or
templates, which `--running-config` cannot do.


```bash
python panorama_export.py --panorama 10.1.1.50 \
  --device-group DG_BRANCH --template TMPL_BRANCH \
  --api-key YOUR_API_KEY --output branch_snapshot.xml
```

Username/password (keygen) is also supported. See `python panorama_export.py --help` for `--all-device-groups`, `--insecure`, etc.

### Collected by default

The device-groups and templates you select, **plus the following, with no extra
flags**:

- **`/config/shared`** — shared objects. On a real Panorama most objects live
  here and every device group inherits from them, so a snapshot without shared
  leaves rule references pointing at nothing.
- **Template stacks** — fetched as one whole branch rather than entry-by-entry
  (per-entry config queries measured ~23s each on the pilot Panorama; 12 stacks
  that way cost ~4.5 minutes for 11 KB of data).
- **`deviceconfig`, `log-collector`, `log-collector-group`, `plugins`,
  `platform`** under `/config/devices/entry`, and **`/config/panorama`** at top
  level.
- **`<nc-managed-devices>`** — operational facts for every managed firewall
  (hostname, model, sw-version, HA state, connected, uptime) from a
  `show devices all` op command. Hostname and HA state exist nowhere in the
  config, which is why the Managed Firewalls page previously showed an em dash
  in every hostname cell. The `nc-` prefix marks the element as ours so no
  importer mistakes it for a config branch; it is inert on the round trip.

Each of these optional branches gets a bounded fetch (25s, no retry) so a branch
that hangs instead of answering empty cannot stall a collection.

### Flags

| Flag | Effect |
|------|--------|
| `--no-shared` | Skip `/config/shared`. Not recommended — most objects live there. |
| `--no-template-stacks` | Skip template stacks. |
| `--no-managed-devices` | Skip the `show devices all` fetch (hostname / model / HA state will be blank in the HTML). |
| `--no-audit` | Skip the completeness audit — it pulls the whole `/config` tree, tens of MB. |
| `--include-predefined` | Also collect `/config/predefined`. **Off by default:** vendor-static apps/services/threats, tens of MB, identical on every box of the same PAN-OS version — useful for App-ID mapping work, useless in a per-customer snapshot. |
| `--include-mgt-config` | Also collect `/config/mgt-config`. **Off by default:** it contains administrator accounts, role assignments and **password hashes**. A policy snapshot has no need for it and a customer handoff must not carry it; the collector prints a warning when the flag is used. |

## Completeness audit

After the snapshot is written, the collector pulls the Panorama's real `/config`
tree and reports every branch that exists on the box but is missing from the
snapshot. **Read the audit before you trust a collection.** Without it an
unfetched branch is invisible: an empty HTML page looks identical whether the
customer genuinely has none of that object type or the collector simply never
asked. This is what makes the collector safe to point at a customer nobody has
seen before.

- The snapshot is written to disk **before** the audit runs, so a slow or failed
  audit can never cost a collection already in hand.
- The audit never fails the export. A new PAN-OS release inventing a branch
  produces a loud warning, not a broken run.
- Opt-in branches (`predefined`, `mgt-config`) are excluded from the report —
  their absence is a decision, not an omission.
- Skip with `--no-audit` when the extra tens of MB are not affordable.

**Rule hit counts are outside this audit.** They are operational counters, not a
`/config` branch, so a snapshot the audit calls COMPLETE still carries none.
Collecting them is a separate manual, live-only step — see
[HIT-COUNT-COLLECTION.md](HIT-COUNT-COLLECTION.md).

## HTML browser

```bash
python build_html.py --input panorama_snapshot.xml
open html_view/index.html
```

Panorama pages add: device-group hierarchy, per-DG drill-down, managed firewalls, relationships (where-used).

For **standalone firewall** XML use [../firewall/build_html.py](../firewall/build_html.py).

## Versioning

Collect and HTML share one version (**1.6.1**): `panorama_export.py` and
`palo/common/html_version.py`. See [CHANGELOG.md](CHANGELOG.md) and repo
`VERSIONING.md`.

## License

MIT
