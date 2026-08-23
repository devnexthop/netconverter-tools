# Rule Hit-Count Collection — Panorama-Managed Estate

A Panorama configuration export (the Panorama device-group hierarchy plus
per-device running-config XML) does **not** carry rule hit-count / traffic
telemetry. Hit counters are collected on each managed firewall's dataplane
and aggregated by Panorama on demand (via `show rule-hit-count`), but they
are not part of a `show config` or Panorama XML API config export. Offline
bundle reviews are therefore produced from static analysis of the rulebase
alone (shadowing, redundancy, containment, and duplication across
device-groups and devices).

> **Not covered by the collector's completeness audit.** As of `panorama_export.py`
> **1.5.0** the collector audits its snapshot against the Panorama's real
> `/config` tree and reports any branch it failed to fetch. Hit counts are
> *operational* counters, not a `/config` branch, so an audit that reports
> COMPLETE still means a snapshot with **no hit-count data at all**. Collecting
> hit counts remains the manual, live-only procedure below, and it is not part of
> any release of the exporter. See
> [README.md](README.md#completeness-audit) and [CHANGELOG.md](CHANGELOG.md).

Collecting hit counts and returning the output upgrades a static review
with traffic evidence. Panorama aggregates hit-count data pushed back from
the firewalls it manages, so device-group-scoped counts are collected
**from Panorama**; device-local (unmanaged) rules are collected from the
individual firewall.

## 1. CLI

**a) Device-group rules — run ON PANORAMA** (not on the firewalls).
Device-group is a Panorama-side construct; an individual firewall's CLI has
no named device-group to scope against. Hit counters are scoped per
rulebase, so pre- and post-rules are pulled separately. For each
device-group, run both:

```
show rule-hit-count device-group <DG-NAME> pre-rulebase security rules all
show rule-hit-count device-group <DG-NAME> post-rulebase security rules all
```

Use `show devicegroups` on Panorama to enumerate the device-groups.

**b) Device-local rules — run ON THE INDIVIDUAL FIREWALL.** For rules that
live in a firewall's local vsys rulebase (not pushed from Panorama), run,
per vsys (e.g. `vsys1`):

```
show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
```

> **Note:** `rule-hit-count` requires PAN-OS >= 8.1. On earlier releases,
> use `show running resource-monitor` per-rule counters or plan an upgrade
> before re-collecting.

## 2. XML API (scripted / bulk collection)

Equivalent to the CLI forms above, issued as `op` commands. The
device-group form is issued against **Panorama**; the vsys form against an
individual firewall's management IP. The rulebase type is a named
`<entry>`, not a bare tag.

**a) Device-group rules — against Panorama:**

```
GET /api/?type=op&key=<API_KEY>&cmd=
    <show><rule-hit-count><device-group><entry name='<DG-NAME>'>
    <pre-rulebase><entry name='security'><rules><all/></rules></entry>
    </pre-rulebase></entry></device-group></rule-hit-count></show>
```

Substitute `<post-rulebase><entry name='security'>...</post-rulebase>` for
the post-rulebase pass.

**b) Device-local rules — against the individual firewall:**

```
GET /api/?type=op&key=<API_KEY>&cmd=
    <show><rule-hit-count><vsys><vsys-name><entry name='vsys1'>
    <rule-base><entry name='security'><rules><all/></rules></entry>
    </rule-base></entry></vsys-name></vsys></rule-hit-count></show>
```

Export one XML response per source per device-group/vsys per rulebase
(pre/post), and keep the device-group (or serial+vsys) and rulebase in the
filename (e.g. `<DG-NAME>_pre.xml`, `<serial>_vsys1.xml`) so hits can be
reconciled back to the exact rule they were collected against.

## 3. What to send back, and what it upgrades

Send back the raw CLI output or XML responses from step 1 or 2, labeled by
firewall serial/hostname, device-group, and rulebase (pre/post). With this
data:

- Findings flagged as **statically unreachable** (shadowed, fully-covered,
  or shadowed-and-redundant) gain hit-evidence reconciliation: a shadowed
  rule with zero hits over a full business cycle corroborates the static
  finding with live traffic evidence, strengthening the case for removal.
- Rules with **zero hits** that are not otherwise flagged as unreachable
  become stronger cleanup candidates — age plus zero traffic is independent
  evidence of an unused rule even when nothing shadows it.
- Any **nonzero hit count on a rule identified as shadowed** triggers a
  re-review: traffic is reaching a rule the static rulebase order says
  should be unreachable, which usually indicates a policy match order or
  scope assumption that must be checked against the live device before any
  change is made.
