# Palo Alto — standalone firewall (HTML)

Read-only HTML browser for a **single-firewall** PAN-OS XML export (device backup or config export).

No collector script here — you already have the XML (backup, API export, or migration artifact). This folder only builds `html_view/`.

## Usage

```bash
pip install -r ../panorama/requirements.txt  # none required beyond stdlib for HTML; requests only for export

python build_html.py --input firewall_backup.xml
open html_view/index.html
```

If the XML is a **Panorama** device-group export, use [../panorama/build_html.py](../panorama/build_html.py) instead (the script will tell you).

## Pages

Dashboard, security rules, NAT, objects, zones, routes, unused objects, optimization hints.

Shared models: [../common/palo_model.py](../common/palo_model.py).
