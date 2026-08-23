# netconverter-collectors

Read-only firewall configuration collection scripts for [NetConverter](https://netconverter.ai).

Each **vendor / technology** folder contains a standalone pull script you run **on your network** against the management plane. Output is a bundle you upload into **NetConverter.local** or **netconverter.ai** for browse, audit, diff, and migration.

## Layout

```
core/                          shared bundle format + HTML report framework
checkpoint/smartconsole/       Check Point Management API
cisco/fmc/                     Cisco Secure Firewall Management Center
palo/
  common/                        shared palo_model + HTML chrome
  firewall/                      standalone PA XML → html_view
  panorama/                      Panorama export + html_view
  scm/                           Strata Cloud Manager (scaffold)
fortinet/fortimanager/         Fortinet FortiManager (JSON-RPC)
```

Future Cisco collectors (e.g. Catalyst Center) would live under `cisco/<technology>/`.

## Collectors

| Path | Management plane | Status |
|------|------------------|--------|
| [checkpoint/smartconsole/](checkpoint/smartconsole/) | SmartConsole / Management API | **Ready** |
| [palo/panorama/](palo/panorama/) | Palo Alto Panorama (XML API) | **Ready** |
| [palo/firewall/](palo/firewall/) | Palo Alto firewall XML → HTML | **Ready** (HTML only) |
| [cisco/fmc/](cisco/fmc/) | Secure Firewall Management Center (REST) | **Ready** |
| [palo/scm/](palo/scm/) | Palo Alto Strata Cloud Manager | Scaffold |
| [fortinet/fortimanager/](fortinet/fortimanager/) | FortiManager (JSON-RPC) | **Ready** |

## Two-step workflow (every collector)

| Step | Script | Output |
|------|--------|--------|
| 1. Collect | `*_collect*.py` / `panorama_export.py` | JSON bundle or XML |
| 2. HTML view | `build_html.py` | `html_view/index.html` — **read-only**, vendor-themed |

Themes match **NetConverter.local** (Check Point magenta, Palo orange, FMC blue, Forti red, SCM purple).

## Quick start (Check Point)

```bash
cd checkpoint/smartconsole
pip install -r requirements.txt
python checkpoint_collect_data.py --mgmt-ip MGMT_IP --username API_USER --password 'PASSWORD' --port 4434
python build_html.py --input run-YYYYMMDD-HHMMSS
open run-YYYYMMDD-HHMMSS/html_view/index.html
```

See [checkpoint/smartconsole/README.md](checkpoint/smartconsole/README.md).

## Quick start (Panorama)

```bash
cd palo/panorama
pip install requests
python panorama_export.py --panorama PANORAMA_IP --device-group DG_NAME --api-key YOUR_KEY --output snapshot.xml
python build_html.py --input snapshot.xml
open html_view/index.html
```

See [palo/panorama/README.md](palo/panorama/README.md).

## Shared bundle format

All collectors target a consistent layout: timestamped output folder + `manifest.json` (vendor, version, counts, pull duration). See [core/manifest.py](core/manifest.py).

Download zips from NetConverter.local include the technology folder plus shared `core/`.

## License

MIT — see [LICENSE](LICENSE).

## Versioning

Each collector is versioned independently (see `VERSIONING.md`). Collect and HTML
for a technology share one `__version__`. The current shipped versions are in
`collectors.lock.json`. After any change: bump entry + HTML `__version__`, update
`CHANGELOG.md`, then run `python3 scripts/gen_collectors_lock.py`.

## Related

- [NetConverter.local](https://netconverter.ai/tool/portal.html#tools-downloads) — offline analysis workbench (download)
- [netconverter.ai](https://netconverter.ai) — cloud migration

## Push tools

Scripts that write converted output back to a management platform. These are
maintained separately and are not covered by `collectors.lock.json`.

- [`fmc-import/`](fmc-import/)
