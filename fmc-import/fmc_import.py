#!/usr/bin/env python3
"""
NetConverter.AI — FMC Import Script

Imports a NetConverter FMC JSON file into a Cisco Secure Firewall Management Center
via the FMC REST API. Run this on any machine that can reach your FMC.

Requirements: Python 3.8+, requests (pip install requests)

Usage:
    python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json
    python3 fmc_import.py --host fmc.company.com --user netadmin --json output.json --dry-run
"""

import argparse
import json
import sys
import time
from getpass import getpass

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip install requests")
    sys.exit(1)


def auth_to_fmc(host, username, password, verify_ssl=False):
    """Authenticate to FMC and return token + domain UUID."""
    import base64
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    url = f"https://{host}/api/fmc_platform/v1/auth/generatetoken"
    resp = requests.post(url, headers={"Authorization": f"Basic {creds}"}, verify=verify_ssl)
    if resp.status_code not in (200, 201, 204):
        print(f"AUTH FAILED: {resp.status_code} {resp.text[:200]}")
        sys.exit(1)
    token = resp.headers.get("X-auth-access-token")
    domain = resp.headers.get("DOMAIN_UUID")
    version = None
    # Get server version
    try:
        vr = requests.get(f"https://{host}/api/fmc_platform/v1/info/serverversion",
                          headers={"X-auth-access-token": token}, verify=verify_ssl)
        if vr.status_code == 200:
            items = vr.json().get("items", [{}])
            version = items[0].get("serverVersion", "unknown") if items else "unknown"
    except Exception:
        pass
    return token, domain, version


def get_obj_id(host, domain, token, obj_type, name, verify_ssl=False):
    """Look up an object ID by name."""
    url = f"https://{host}/api/fmc_config/v1/domain/{domain}/object/{obj_type}"
    resp = requests.get(f"{url}?filter=nameOrValue:{name}&limit=1",
                        headers={"X-auth-access-token": token}, verify=verify_ssl)
    if resp.status_code == 200:
        items = resp.json().get("items", [])
        if items:
            return items[0]["id"]
    return None


def resolve_ref(ref, host, domain, token, verify_ssl=False):
    """Resolve an object reference name to an FMC ID."""
    if not ref or not isinstance(ref, dict) or "name" not in ref:
        return None
    rtype = ref.get("type", "Network")
    name = ref["name"]
    endpoints = {
        "Host": ["hosts"],
        "Network": ["networks", "hosts", "networkgroups"],
        "NetworkGroup": ["networkgroups"],
        "ProtocolPortObject": ["protocolportobjects"],
        "PortObjectGroup": ["portobjectgroups"],
        "SecurityZone": ["securityzones"],
    }
    for ep in endpoints.get(rtype, ["networks", "hosts"]):
        oid = get_obj_id(host, domain, token, ep, name, verify_ssl)
        if oid:
            return {"type": rtype, "id": oid, "name": name}
    return None


def push_objects(host, domain, token, objects, verify_ssl=False, dry_run=False):
    """Push all object types to FMC in dependency order."""
    headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
    base = f"https://{host}/api/fmc_config/v1/domain/{domain}/object"
    stats = {"created": 0, "skipped": 0, "failed": 0}

    # Push order matters: simple objects first, then groups
    push_order = [
        ("hosts", "hosts"),
        ("networks", "networks"),
        ("ranges", "ranges"),
        ("fqdns", "fqdns"),
        ("protocolportobjects", "protocolportobjects"),
        ("securityzones", "securityzones"),
        ("networkgroups", "networkgroups"),
        ("portobjectgroups", "portobjectgroups"),
        ("ikev1policies", "ikev1policies"),
        ("ikev2policies", "ikev2policies"),
        ("ikev1ipsecproposals", "ikev1ipsecproposals"),
        ("ikev2ipsecproposals", "ikev2ipsecproposals"),
    ]

    for key, endpoint in push_order:
        items = objects.get(key, [])
        if not items:
            continue
        print(f"\n  {key}: {len(items)} objects")

        for obj in items:
            name = obj.get("name", "?")
            if dry_run:
                print(f"    [DRY RUN] Would create: {name}")
                stats["created"] += 1
                continue

            # For groups, resolve member references
            if key in ("networkgroups", "portobjectgroups"):
                resolved_members = []
                for member in obj.get("objects", []):
                    ep_type = "hosts" if member.get("type") == "Host" else (
                        "networkgroups" if "Group" in member.get("type", "") else
                        "protocolportobjects" if "Port" in member.get("type", "") else "networks"
                    )
                    mid = get_obj_id(host, domain, token, ep_type, member["name"], verify_ssl)
                    if mid:
                        resolved_members.append({"type": member["type"], "id": mid})
                if resolved_members:
                    obj = {**obj, "objects": resolved_members}
                elif not obj.get("literals"):
                    stats["failed"] += 1
                    continue

            resp = requests.post(f"{base}/{endpoint}", headers=headers, json=obj, verify=verify_ssl)
            if resp.status_code in (200, 201):
                stats["created"] += 1
            elif resp.status_code == 400 and "already exists" in resp.text.lower():
                stats["skipped"] += 1
            else:
                stats["failed"] += 1
                print(f"    FAIL {name}: {resp.status_code} {resp.text[:120]}")

    return stats


def push_access_rules(host, domain, token, policies, verify_ssl=False, dry_run=False):
    """Push access policy and rules."""
    headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
    base = f"https://{host}/api/fmc_config/v1/domain/{domain}/policy"
    stats = {"created": 0, "failed": 0}

    # Create or find access policy
    ap_list = policies.get("accesspolicies", [])
    if not ap_list:
        return stats
    policy_name = ap_list[0].get("name", "Migrated-Policy")

    # Check if policy exists
    resp = requests.get(f"{base}/accesspolicies?limit=50", headers=headers, verify=verify_ssl)
    policy_id = None
    for p in resp.json().get("items", []):
        if p["name"] == policy_name:
            policy_id = p["id"]
            break

    if not policy_id:
        payload = {"type": "AccessPolicy", "name": policy_name,
                   "defaultAction": {"type": "AccessPolicyDefaultAction", "logBegin": False,
                                     "logEnd": False, "sendEventsToFMC": False, "action": "BLOCK"}}
        if dry_run:
            print(f"  [DRY RUN] Would create policy: {policy_name}")
            return {"created": len(policies.get("accessrules", [])), "failed": 0}
        cr = requests.post(f"{base}/accesspolicies", headers=headers, json=payload, verify=verify_ssl)
        if cr.status_code in (200, 201):
            policy_id = cr.json()["id"]
            print(f"  Created policy: {policy_name}")
        else:
            print(f"  FAIL create policy: {cr.status_code}")
            return stats
    else:
        print(f"  Using existing policy: {policy_name}")

    # Push rules
    rules = policies.get("accessrules", [])
    print(f"  Pushing {len(rules)} access rules...")
    for rule in rules:
        payload = {"type": "AccessRule", "name": rule.get("name", "unnamed"),
                   "action": rule.get("action", "ALLOW"), "enabled": rule.get("enabled", True)}

        # Resolve zone, network, port references
        for field in ["sourceZones", "destinationZones"]:
            zones = rule.get(field, {}).get("objects", [])
            resolved = [r for r in (resolve_ref(z, host, domain, token, verify_ssl) for z in zones) if r]
            if resolved:
                payload[field] = {"objects": resolved}

        for field in ["sourceNetworks", "destinationNetworks"]:
            nets = rule.get(field, {}).get("objects", [])
            resolved = [r for r in (resolve_ref(n, host, domain, token, verify_ssl) for n in nets) if r]
            if resolved:
                payload[field] = {"objects": resolved}
            lits = rule.get(field, {}).get("literals", [])
            if lits:
                payload.setdefault(field, {})["literals"] = lits

        for field in ["sourcePorts", "destinationPorts"]:
            ports = rule.get(field, {}).get("objects", [])
            resolved = [r for r in (resolve_ref(p, host, domain, token, verify_ssl) for p in ports) if r]
            if resolved:
                payload[field] = {"objects": resolved}
            lits = rule.get(field, {}).get("literals", [])
            if lits:
                payload.setdefault(field, {})["literals"] = lits

        if dry_run:
            stats["created"] += 1
            continue

        resp = requests.post(f"{base}/accesspolicies/{policy_id}/accessrules",
                             headers=headers, json=payload, verify=verify_ssl)
        if resp.status_code in (200, 201):
            stats["created"] += 1
        else:
            stats["failed"] += 1

    return stats


def push_nat_rules(host, domain, token, policies, verify_ssl=False, dry_run=False):
    """Push NAT policy and rules."""
    headers = {"X-auth-access-token": token, "Content-Type": "application/json"}
    base = f"https://{host}/api/fmc_config/v1/domain/{domain}/policy"
    stats = {"created": 0, "failed": 0}

    nat_pols = policies.get("natpolicies", [])
    if not nat_pols:
        return stats
    nat_name = nat_pols[0].get("name", "Migrated-NAT")

    if dry_run:
        print(f"  [DRY RUN] Would create NAT policy: {nat_name} with {len(policies.get('natrules', []))} rules")
        return {"created": len(policies.get("natrules", [])), "failed": 0}

    # Create NAT policy
    resp = requests.post(f"{base}/ftdnatpolicies", headers=headers,
                         json={"type": "FTDNatPolicy", "name": nat_name}, verify=verify_ssl)
    nat_policy_id = resp.json().get("id") if resp.status_code in (200, 201) else None
    if not nat_policy_id:
        print(f"  FAIL create NAT policy: {resp.status_code}")
        return stats
    print(f"  Created NAT policy: {nat_name}")

    # Push NAT rules (strip fields FMC rejects)
    strip_fields = {"section", "_policy_name", "_rule_index", "name", "enabled"}
    for rule in policies.get("natrules", []):
        clean = {k: v for k, v in rule.items() if k not in strip_fields and v is not None}
        section = rule.get("section", "BEFORE_AUTO")
        endpoint = "autonatrules" if section == "AUTO" else "manualnatrules"

        # Resolve references
        for fld in ["originalSource", "originalDestination", "translatedSource",
                     "translatedDestination", "originalNetwork", "translatedNetwork"]:
            ref = clean.get(fld)
            if ref and isinstance(ref, dict) and "name" in ref:
                resolved = resolve_ref(ref, host, domain, token, verify_ssl)
                if resolved:
                    clean[fld] = resolved
                else:
                    clean.pop(fld, None)

        for fld in ["sourceInterface", "destinationInterface"]:
            ref = clean.get(fld)
            if ref and isinstance(ref, dict) and "name" in ref:
                resolved = resolve_ref(ref, host, domain, token, verify_ssl)
                if resolved:
                    clean[fld] = resolved

        resp = requests.post(f"{base}/ftdnatpolicies/{nat_policy_id}/{endpoint}",
                             headers=headers, json=clean, verify=verify_ssl)
        if resp.status_code in (200, 201):
            stats["created"] += 1
        else:
            stats["failed"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="NetConverter.AI — Import FMC JSON to Cisco Secure Firewall Management Center",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python3 fmc_import.py --host 10.1.1.100 --user admin --json output.json"
    )
    parser.add_argument("--host", required=True, help="FMC hostname or IP")
    parser.add_argument("--user", required=True, help="FMC username")
    parser.add_argument("--password", help="FMC password (prompted if not provided)")
    parser.add_argument("--json", required=True, help="Path to NetConverter FMC JSON file")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be pushed without making changes")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate (default: skip)")
    args = parser.parse_args()

    password = args.password or getpass(f"Password for {args.user}@{args.host}: ")

    # Load JSON
    try:
        with open(args.json) as f:
            data = json.load(f)
    except Exception as e:
        print(f"ERROR: Cannot read {args.json}: {e}")
        sys.exit(1)

    objects = data.get("objects", {})
    policies = data.get("policies", {})
    summary = data.get("migration_summary", {})

    total_objects = sum(len(v) for v in objects.values() if isinstance(v, list))
    total_rules = sum(len(v) for v in policies.values() if isinstance(v, list))
    print(f"\nNetConverter.AI FMC Import")
    print(f"{'='*50}")
    print(f"FMC Host:    {args.host}")
    print(f"JSON File:   {args.json}")
    print(f"Objects:     {total_objects}")
    print(f"Policies:    {total_rules}")
    if args.dry_run:
        print(f"Mode:        DRY RUN (no changes)")
    print(f"{'='*50}")

    # Auth
    print(f"\nAuthenticating to {args.host}...")
    token, domain, version = auth_to_fmc(args.host, args.user, password, args.verify_ssl)
    print(f"  Authenticated. FMC {version or 'unknown'}, Domain: {domain}")

    # Push objects
    print(f"\nPushing objects...")
    obj_stats = push_objects(args.host, domain, token, objects, args.verify_ssl, args.dry_run)
    print(f"\n  Objects: created={obj_stats['created']}, skipped={obj_stats['skipped']}, failed={obj_stats['failed']}")

    # Push access rules
    if policies.get("accessrules"):
        print(f"\nPushing access rules...")
        rule_stats = push_access_rules(args.host, domain, token, policies, args.verify_ssl, args.dry_run)
        print(f"  Rules: created={rule_stats['created']}, failed={rule_stats['failed']}")

    # Push NAT
    if policies.get("natrules"):
        print(f"\nPushing NAT rules...")
        nat_stats = push_nat_rules(args.host, domain, token, policies, args.verify_ssl, args.dry_run)
        print(f"  NAT: created={nat_stats['created']}, failed={nat_stats['failed']}")

    print(f"\n{'='*50}")
    print(f"Import complete. Log into FMC to verify.")
    print(f"NOTE: Deploy changes to managed devices for rules to take effect.")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
