# Re-collect with Check Point collector v1.5.6

Use this if you already sent a zip from collector **1.5.5 or older**.

| Dataset | Status after 1.5.5 re-collect | What 1.5.6 changes |
|---|---|---|
| HTTPS inspection | **Done** — outbound layers collected | No re-run needed for HTTPS |
| Threat exceptions | Still 0 files — API rejected `layer-uid` | Sends `layer-name` only; retries uid if the API asks |
| VPN community members | Per-UID show still empty on this SMS | Unchanged; not a script skip |

You do **not** need to re-export objects, access layers, NAT, or HTTPS if you already ran 1.5.5. A full re-run is still the simplest path if you want threat exception rows in the same zip.

## 1 — Get v1.5.6

GitHub: https://github.com/netconverter-ai/netconverter-tools  
Folder: `checkpoint/smartconsole/`

Confirm version:

```bat
python checkpoint_collect_data.py --version
```

Must print `1.5.6`.
