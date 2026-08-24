# Panorama live attach — Gaia analogue

Check Point Firewall view attaches **Gaia clish** (live box, not SmartConsole).
Panorama XML + template stacks are **config**. Hit counts, the FIB, and HA
dataplane state are **operational** and are not in `--running-config`.

This is the command list for the next engagement. Not collected by
`panorama_export.py` 1.7.0. Not parsed in NetConverter.local 1.8.17 (Excel
Gaps sheet already says so). Keep files next to the XML until we build a
PA attach like `/api/cp/gaia/attach`.

Hit-count XML details: [`HIT-COUNT-COLLECTION.md`](HIT-COUNT-COLLECTION.md).

## Where to run

| Data | Where | Why |
|---|---|---|
| Policy / objects / templates | Panorama `--running-config` | Already in the XML |
| Hostnames, model, HA role | Panorama `show devices all` | Already in `<nc-managed-devices>` |
| Rule Used / Unused / Partial | **Panorama** `show rule-hit-count` per device-group | Panorama aggregates from NGFWs |
| Numeric packet hits (if enabled) | **Each NGFW** `show rule-hit-count vsys …` | Device-local counters |
| RIB / FIB / live interfaces / ARP / VPN SAs | **Each NGFW** (or Panorama API `target=SERIAL`) | Panorama has no customer FIB |

Do not SSH to Panorama expecting a branch-office FIB. Log into the firewall
(or pass `target=<serial>` on the XML API).

## Check Point Gaia → Palo Alto

Gaia core kinds are `cluster_state`, `interfaces`, `route`, `route_static`,
`configuration`. Optional: IPv6 route, ARP, VPN tunnels.

| Gaia (core) | Palo Alto (live) | In the XML already? |
|---|---|---|
| `show cluster state` | `show high-availability all` on **each** HA member | HA *role* only (`<nc-managed-devices>`). Not peer IPs, not HA1/HA2 links. |
| `show interfaces` | `show interface all` + `show interface logical` | Template interface *config* (IPs from templates / variables), not link state / actual DHCP / PPPoE. |
| `show route` | `show routing route` (**RIB**) | No. Template statics are config, not learned BGP/OSPF. |
| `show route static` | Filter RIB `S` **or** XML template statics | XML = configured statics. RIB `S` = what is installed. **Do not migrate RIB `B` as statics.** |
| `show configuration` | Running-config XML | Yes (`--running-config`). |

| Gaia (optional) | Palo Alto (live) |
|---|---|
| `show ipv6 route` | `show routing route ipv6` + `show routing fib ipv6` |
| `show arp` | `show arp all` |
| `show vpn tunnels` | `show vpn ike-sa` + `show vpn ipsec-sa` |

## Core — run on every firewall (cutover)

Same job as the Gaia MOP: one paste per box, save as
`<hostname>_<serial>_live.txt`.

```
show system info
show high-availability all
show interface all
show interface logical
show routing route
show routing fib
show routing fib ipv6
```

- **`show routing route`** = RIB (connected, static, BGP, OSPF, …). Analogue of Gaia `show route`.
- **`show routing fib`** = **FIB** (what the dataplane actually forwards). Gaia does not split this; on PAN-OS you want both. Yes — this is the table for “what does this firewall forward right now.”

If the box has named VRs:

```
show routing route virtual-router <VR-NAME>
show routing fib virtual-router <VR-NAME>
```

Nossaman stacks usually have one VR per template; still capture FIB, not only template statics.

## Hit counts — Panorama (estate)

Not in config. Run on **Panorama**, per device-group that has security or NAT
(Nossaman: 17 DGs). Pre and post, security and NAT:

```
show rule-hit-count device-group <DG> pre-rulebase security rules all
show rule-hit-count device-group <DG> post-rulebase security rules all
show rule-hit-count device-group <DG> pre-rulebase nat rules all
show rule-hit-count device-group <DG> post-rulebase nat rules all
```

XML API (this is the form that returned `status=success` on NOS-PAPAN-01):

```xml
<show><rule-hit-count><device-group><entry name='DG'>
<pre-rulebase><entry name='security'><rules><all/></rules></entry></pre-rulebase>
</entry></device-group></rule-hit-count></show>
```

Same with `post-rulebase` and `entry name='nat'`.

**What you get:** `rule-state` = `Used` / `Unused` / `Partial`, plus creation /
modification timestamps. Nossaman 2026-08-24 dump did **not** include integer
`<hit-count>` packet counters. That is still enough to mark unused rules
(Check Point unused). For packet counts, run the vsys form on the firewall
(below) or confirm hit-count logging is enabled in the DG.

## Hit counts — each firewall (local vsys)

Only needed if the box has **local** rules (not pushed) or you need numbers:

```
show rule-hit-count vsys vsys-name vsys1 rule-base security rules all
show rule-hit-count vsys vsys-name vsys1 rule-base nat rules all
```

Requires PAN-OS ≥ 8.1.

## Optional — same as Gaia extras + PA-specific

Run if the engagement uses the feature. Skip cleanly if the command is unknown.

```
show arp all
show ipv6 neighbor
show routing protocol bgp summary
show routing protocol bgp loc-rib
show routing protocol ospf neighbor
show vpn ike-sa
show vpn ipsec-sa
show global-protect-gateway current-user
show session info
show dhcp server lease
show ntp
```

BGP loc-rib is the “do not migrate as Palo/Forti statics” evidence (same
warning as Gaia BGP on the CP Excel Gaps sheet).

## Panorama XML API with `target=` (no SSH to the NGFW)

Same op, aimed at one serial (firewall must be connected):

```
GET /api/?type=op&key=KEY&target=SERIAL&cmd=<show><routing><route></route></routing></show>
GET /api/?type=op&key=KEY&target=SERIAL&cmd=<show><routing><fib></fib></routing></show>
GET /api/?type=op&key=KEY&target=SERIAL&cmd=<show><interface>all</interface></show>
GET /api/?type=op&key=KEY&target=SERIAL&cmd=<show><high-availability><all></all></high-availability></show>
```

Read-only. No `set` / `commit`.

## What local 1.8.17 already has vs still needs

| Already in XML / Excel | Still live-only (this note) |
|---|---|
| Device-groups, Shared objects, rule targets | Hit Used/Unused (Panorama op) |
| Template stack, template interfaces, template statics | FIB + RIB (per firewall) |
| `show devices all` hostname / HA active\|passive | HA links, peer IPs, election |
| Per-serial applicable policy | Numeric hit counters |
| | Live interface state, ARP, IKE/IPsec SAs, GP users, BGP table |

Next product cut: PA attach overlay like Gaia — drop `<serial>_live.txt` on
Firewall view, parse RIB/FIB into Excel sheets “Live route” / “Live FIB”,
keep template statics separate.
