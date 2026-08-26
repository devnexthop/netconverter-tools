# Install Python on Windows (if you do not have it)

You only need to do this once per PC.

## Step 1 — Download

1. Open https://www.python.org/downloads/windows/
2. Download **Python 3.12** (or latest 3.x) — **Windows installer (64-bit)**.

## Step 2 — Install

1. Run the installer.
2. On the **first screen**, check **“Add python.exe to PATH”** (important).
3. Click **Install Now**.
4. When finished, close the installer.

## Step 3 — Verify

Open **Command Prompt** and run:

```bat
python --version
pip --version
```

You should see version numbers (e.g. `Python 3.12.x`).

If `python` is not found, try:

```bat
py -3 --version
```

Use `py -3` instead of `python` in all commands in CUSTOMER_README.md if needed.

## Step 4 — Install script dependencies

```bat
cd path\to\netconverter-tools\checkpoint\smartconsole
pip install -r requirements.txt
```

## If IT blocks installation

- Ask IT to install Python 3.8+ for you, **with PATH enabled**, or
- Run the collector from an **approved jump server / VM** that already has Python and can reach the Check Point management IP on port 4434.

## Re-run installer to fix PATH

1. Open **Settings → Apps → Python 3.12 → Modify**
2. Choose **Modify**
3. Enable **Add Python to environment variables** / PATH
4. Complete the wizard
