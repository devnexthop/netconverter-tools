# Install Python on Linux (if you do not have it)

You only need to do this once per machine.

The Check Point collector needs **Python 3.8 or newer** and the `requests` library.  
For the full collection workflow after setup, see [README.md](README.md).

---

## Step 1 — Open a terminal

Use any shell on the machine that can reach your Check Point management server:

- **SSH session** to a jump host or admin VM
- **Local terminal** on a Linux workstation

Confirm which distribution you are on (helps pick the right install command):

```bash
cat /etc/os-release | head -5
```

---

## Step 2 — Check if Python is already installed

```bash
python3 --version
pip3 --version
```

**Expected (good):**

```text
Python 3.12.3
pip 24.0 from ...
```

| Result | Action |
|--------|--------|
| Both show version numbers and Python is **3.8+** | Skip to **Step 4** |
| `python3: command not found` | Continue to **Step 3** |
| Python is **3.7 or older** | Install a newer Python (Step 3) |
| `pip3: command not found` but `python3` works | Install `python3-pip` (Step 3) |

If only `python` exists (no `python3`), check its version:

```bash
python --version
```

Use `python3` in all commands below when available.

---

## Step 3 — Install Python (by distribution)

Pick the block that matches your OS from Step 1.

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

### RHEL / Rocky / AlmaLinux / CentOS Stream

```bash
sudo dnf install -y python3 python3-pip
```

Older systems using `yum`:

```bash
sudo yum install -y python3 python3-pip
```

### Fedora

```bash
sudo dnf install -y python3 python3-pip
```

### openSUSE

```bash
sudo zypper install -y python3 python3-pip
```

### SUSE Linux Enterprise (SLE)

```bash
sudo zypper install -y python3 python3-pip
```

---

## Step 4 — Verify Python installation

Run all three checks:

```bash
python3 --version
pip3 --version
python3 -c "import sys; print(sys.version)"
```

**Pass criteria:**

- `python3 --version` shows **3.8.0 or higher**
- `pip3 --version` prints a version (not “command not found”)
- No error from the `import sys` one-liner

**If `python3` works but `pip3` does not:**

```bash
# Ubuntu / Debian
sudo apt install -y python3-pip

# RHEL family
sudo dnf install -y python3-pip
```

---

## Step 5 — Go to the collector folder

Adjust the path to where you cloned or copied the repo:

```bash
cd /path/to/netconverter-public-repo/checkpoint/smartconsole
ls -1 checkpoint_collect_data.py requirements.txt
```

**Expected:** both files are listed. If not, you are in the wrong directory.

---

## Step 6 — Install script dependencies

### Recommended: virtual environment

Modern Ubuntu/Debian (23.04+) often refuse system-wide `pip install`. A venv avoids that.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Your prompt should show `(.venv)` when the environment is active.

**Important:** In every **new** terminal session, activate again before collecting:

```bash
cd /path/to/netconverter-public-repo/checkpoint/smartconsole
source .venv/bin/activate
```

### Alternative: install for your user only

Only if a venv is not possible and your distro allows it:

```bash
pip3 install --user -r requirements.txt
```

---

## Step 7 — Verify script dependencies

With the venv activated (if you use one):

```bash
pip show requests
python3 -c "import requests; print('requests', requests.__version__, 'OK')"
python3 checkpoint_collect_data.py --version
```

**Expected:**

```text
Name: requests
Version: 2.28.0 (or newer)
...
requests 2.31.0 OK
checkpoint_collect_data.py 1.2.0
```

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: No module named 'requests'` | Re-run Step 6 inside an activated venv |
| `externally-managed-environment` | Use the venv method in Step 6 — do not `pip install` system-wide |
| `checkpoint_collect_data.py: No such file` | `cd` to `checkpoint/smartconsole` (Step 5) |

---

## Step 8 — Verify network access to management (optional but recommended)

Replace `YOUR_MGMT_IP` and port with values from your Check Point admin.

**TCP port check** (install `nc` if needed: `sudo apt install netcat-openbsd` or `sudo dnf install nmap-ncat`):

```bash
nc -zv YOUR_MGMT_IP 4434
```

**Expected:** `succeeded` or `open`. If it times out, fix firewall/routing before collecting.

If your admin uses port **443** instead:

```bash
nc -zv YOUR_MGMT_IP 443
```

---

## Step 9 — Run the collector

With venv activated and credentials from your Check Point administrator:

```bash
python3 checkpoint_collect_data.py \
  --mgmt-ip YOUR_MGMT_IP \
  --username YOUR_API_USER \
  --password 'YOUR_PASSWORD' \
  --port 4434 \
  --full-objects \
  --where-used \
  --verify-export
```

Use port `443` if that is what your environment uses.

---

## Step 10 — Verify collection output

After a successful run:

```bash
ls -ld run-* checkpoint_audit_*.zip
ls run-*/collection-summary.csv run-*/gateways-and-servers.json
```

**Expected:**

- One folder: `run-YYYYMMDD-HHMMSS/`
- One zip: `checkpoint_audit_YYYYMMDD-HHMMSS.zip`
- Summary and gateway JSON files inside the run folder

Send **only the zip file** to ValeronLabs (see [README.md](README.md)).

### Optional: local HTML browser

```bash
python3 build_html.py --input run-YYYYMMDD-HHMMSS
xdg-open run-YYYYMMDD-HHMMSS/html_view/index.html
```

---

## If IT blocks installation

- Ask IT to install **Python 3.8+** with `pip` and outbound access to the management IP on **4434** (or **443**), or
- Run the collector from an **approved jump server / VM** that already has Python and network access to the SMS.

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| `python3: command not found` | Step 3 — install Python for your distro |
| `pip3: command not found` | Install `python3-pip` (Step 3) |
| `externally-managed-environment` | Step 6 — use `python3 -m venv .venv` |
| `Permission denied` on output | `cd` to a writable directory or use `--output /path/you/can/write` |
| `Login failed` | Wrong IP, port, username, or password |
| Connection timeout | Firewall blocking 4434/443 from this host to management (Step 8) |
| SSL/certificate warnings at start | Expected for self-signed mgmt certs; collector continues with verify off |
| `python3` is 3.6 or older | Upgrade Python via your distro or use a newer jump host |

### Wrong Python picked in venv

Remove and recreate the venv:

```bash
deactivate 2>/dev/null || true
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### `python` vs `python3`

On Linux, always prefer **`python3`** and **`pip3`** in commands. If your site standardizes on `python` as Python 3, substitute accordingly after verifying `python --version` is 3.8+.

---

## What this does NOT collect

- Live routing tables on gateways (needs gateway SSH — see `checkpoint_collect_routing.py`)
- Full Gaia CLI configuration dumps

These are optional follow-ups if ValeronLabs requests them.
