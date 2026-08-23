# Palo Alto Networks collectors

| Technology | Folder | Management plane | Status |
|------------|--------|------------------|--------|
| **Firewall** (standalone) | [firewall/](firewall/) | PAN-OS XML backup — HTML browser only | Ready |
| **Panorama** | [panorama/](panorama/) | Panorama XML API — export + HTML | Ready |
| **Strata Cloud Manager** | [scm/](scm/) | SCM OAuth + config export | Scaffold |

Shared XML models and HTML rendering live in [common/](common/) (`palo_model.py`, `html_common.py`).

## Quick picks

```bash
# Standalone PA firewall XML → html_view
cd palo/firewall && python build_html.py --input backup.xml

# Panorama export + browser
cd palo/panorama
python panorama_export.py --panorama HOST --device-group DG --api-key KEY --output snap.xml
python build_html.py --input snap.xml

# SCM (scaffold)
cd palo/scm && python scm_config_pull.py --tenant TENANT --client-id ID --output .
```

The Panorama export collects **shared objects, template stacks and
managed-device facts by default** and then **audits the snapshot against the
live `/config` tree**, so you can tell "the customer has none" apart from "we
never asked" — see
[panorama/README.md](panorama/README.md#completeness-audit).

## License

MIT — see repo [LICENSE](../LICENSE).
