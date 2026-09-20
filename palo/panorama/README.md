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

One request returns the running configuration and is more robust than many
per-entry fetches on a slow link. Version 1.7.2 preserves and validates the
device-group hierarchy before removing readonly mirrors; a successful download
alone does not prove effective device or operational completeness. Use the
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

The **full Gaia analogue** (hit counts **plus** RIB/FIB, HA, live interfaces)
is [LIVE-ATTACH.md](LIVE-ATTACH.md).

## HTML browser

```bash
python build_html.py --input panorama_snapshot.xml
open html_view/index.html
```

Panorama pages add: device-group hierarchy, per-DG drill-down, managed firewalls, relationships (where-used).

For **standalone firewall** XML use [../firewall/build_html.py](../firewall/build_html.py).

## Versioning

Collect and HTML share one version (**1.7.2**): `panorama_export.py` and
`palo/common/html_version.py`. See [CHANGELOG.md](CHANGELOG.md) and repo
`VERSIONING.md`.

## License

MIT

## Hierarchy evidence — 1.7.2

The exporter retains a minimal `nc-device-group-hierarchy` block with every
authoritatively observed DG identity, parent or explicit root, source configuration
store, observation time, source-tree hash and collector version. It retains no
mirrored objects, template bodies or management credentials in that block.
The original DG configuration and unknown fields remain unchanged.

Running exports preserve this evidence before stripping `readonly`. Per-entry
exports request `/config/readonly/devices/entry[@name='localhost.localdomain']/device-group`
with the same `action=get` candidate store used for policy. They do not substitute
operational running hierarchy if the request is unavailable. Failed, empty,
conflicting, cyclic or missing-ancestor evidence remains incomplete. Per-entry
requests are explicitly non-atomic; a fresh authorized capture must verify the
API shape and collection consistency on the target Panorama. No live device
verification is claimed by the offline regression tests.

`nc-collection` records capture mode and actual entry/branch audit outcomes.
Skipped or failed audits are unverified, never successful empty inventories.
Hierarchy failures, identity-only stubs and known missing entries or branches return
exit status 3 while preserving the partial capture. Complete ancestry does not
make explicitly partial native configuration suitable for device preparation.
A missing parent link does not prove a root. Older stripped captures remain useful
for read-only inventory, but complete device reports, copies and packages require
a new 1.7.2 capture or a native full export with its readonly hierarchy. Do not
merge older hierarchy with newer policy without a separately reviewed reconstruction.

The shared helper accepts native readonly metadata, explicit `parent-dg` elements
(empty means root), and the versioned collector block. Selected appliance copies
retain only their ancestor chain, including explicit root and capture provenance.

The standalone HTML browser applies the same coverage gate: unverified device
counts show `Unavailable`, device policy tables are suppressed, and optimization
and unused-object pages explain the missing evidence instead of showing empty
or apparently complete results. Captured local inventory remains readable.
