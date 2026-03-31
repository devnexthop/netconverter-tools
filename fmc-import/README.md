# FMC Import Script

Push NetConverter-generated FMC JSON files to a live Cisco Secure Firewall Management Center (FMC) via the REST API.

## What It Does

This script takes the FMC JSON output from [NetConverter.AI](https://netconverter.ai) and pushes it to your FMC in the correct dependency order:

1. **Network Objects** - hosts, networks, ranges, FQDNs
2. **Service Objects** - protocol/port objects
3. **Security Zones**
4. **Object Groups** - network groups, port groups (with member resolution)
5. **VPN Objects** - IKEv1/v2 policies and IPSec proposals
6. **Access Policies & Rules** - with zone, network, and port reference resolution
7. **NAT Policies & Rules** - manual and auto NAT with reference resolution

## Prerequisites

- Python 3.8 or higher
- `requests` library
- Network access from your machine to the FMC management interface (HTTPS/443)
- FMC user account with admin privileges

## Installation

```bash
pip install requests
```

That's it. No other dependencies required.

## Usage

### Basic Import

```bash
python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json
```

You'll be prompted for the password securely (not echoed to terminal).

### Dry Run (Preview Without Changes)

```bash
python3 fmc_import.py --host 10.1.1.100 --user admin --json converted_output.json --dry-run
```

Dry run shows exactly what would be created without making any changes to your FMC. Always recommended before your first live import.

### All Options

```
python3 fmc_import.py --host HOST --user USER --json FILE [options]

Required:
  --host HOST       FMC hostname or IP address
  --user USER       FMC username
  --json FILE       Path to NetConverter FMC JSON file

Optional:
  --password PASS   FMC password (prompted if not provided)
  --dry-run         Preview without making changes
  --verify-ssl      Verify SSL certificate (default: skip for self-signed)
```

## Example Output

```
NetConverter.AI FMC Import
==================================================
FMC Host:    10.1.1.100
JSON File:   asa_to_fmc.json
Objects:     65
Policies:    54
==================================================

Authenticating to 10.1.1.100...
  Authenticated. FMC 7.6.5, Domain: e276abec-...

Pushing objects...
  hosts: 12 objects
  networks: 8 objects
  protocolportobjects: 15 objects
  securityzones: 4 objects
  networkgroups: 6 objects

  Objects: created=45, skipped=20, failed=0

Pushing access rules...
  Using existing policy: Migrated-Policy
  Pushing 43 access rules...
  Rules: created=43, failed=0

Pushing NAT rules...
  Created NAT policy: Migrated-NAT
  NAT: created=11, failed=0

==================================================
Import complete. Log into FMC to verify.
NOTE: Deploy changes to managed devices for rules to take effect.
==================================================
```

## Important Notes

- **Deploy after import**: FMC holds changes in a staging area. You must deploy to managed devices from the FMC UI for rules to take effect.
- **Skipped objects**: Objects that already exist on the FMC are automatically skipped (not duplicated).
- **Existing policies**: If an access policy with the same name exists, rules are added to it.
- **SSL certificates**: Most FMC installations use self-signed certificates. The script skips SSL verification by default. Use `--verify-ssl` if your FMC has a trusted certificate.

## Generating the FMC JSON File

1. Go to [netconverter.ai](https://netconverter.ai) and sign in
2. Open **Quick Convert**
3. Paste or upload your source firewall configuration (ASA, FortiGate, Palo Alto, etc.)
4. Select **Cisco FMC (JSON)** as the target
5. Click **Convert**
6. Download the converted output JSON file

## Supported FMC Versions

Tested with FMC 7.2+ through 7.6.5. The script uses stable v1 REST API endpoints.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `AUTH FAILED: 401` | Check username/password. Ensure the user has API access in FMC. |
| `Connection refused` | Verify FMC is reachable on port 443 from your machine. |
| `SSL certificate error` | Remove `--verify-ssl` flag (default behavior skips SSL check). |
| Objects show `FAIL` | Check FMC audit log for details. Usually a naming conflict or limit. |

## License

MIT License - see [LICENSE](../LICENSE) for details.
