#!/usr/bin/env bash
# FMC read-only export + HTML browser (client-distributable).
#
# Usage:
#   ./run_collect.sh --host 10.1.1.100 --user api_ro [--password SECRET] [--insecure] [quick|full]
#
# Password may also be set via FMC_PASSWORD (env or .env file). If omitted, Python prompts.
set -euo pipefail
cd "$(dirname "$0")"

usage() {
  cat <<'EOF'
Usage: run_collect.sh --host HOST --user USER [options] [MODE]

Required:
  --host HOST       FMC IP address or hostname (no https://)
  --user USER       API username (read-only account recommended)

Options:
  --password PASS   API password (else FMC_PASSWORD env or interactive prompt)
  --insecure        Skip TLS verification (self-signed / lab FMC only)
  --output DIR      Output directory (default: current folder)
  --format zip|tgz  Delivery archive format (default: zip)
  --all-domains     Collect every authorized FMC domain (multi-domain FMC)
  -h, --help        Show this help

Mode (optional, default: quick):
  quick             Smoke test — devices, key objects, access/NAT policies
  full              All object types + policies (large tenants take longer)

Examples:
  ./run_collect.sh --host 192.168.10.5 --user netconverter_ro --insecure quick
  FMC_PASSWORD='secret' ./run_collect.sh --host fmc.customer.com --user api_ro full
EOF
}

HOST=""
USER=""
PASSWORD=""
OUTPUT="."
INSECURE=0
MODE="quick"
ARCHIVE_FMT="zip"
ALL_DOMAINS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --user) USER="$2"; shift 2 ;;
    --password) PASSWORD="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --format) ARCHIVE_FMT="$2"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --all-domains) ALL_DOMAINS=1; shift ;;
    quick|full) MODE="$1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

HOST="${HOST:-${FMC_HOST:-}}"
USER="${USER:-${FMC_USER:-}}"
PASSWORD="${PASSWORD:-${FMC_PASSWORD:-}}"

if [[ -z "$HOST" || -z "$USER" ]]; then
  echo "Error: --host and --user are required." >&2
  usage
  exit 1
fi

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
PY=.venv/bin/python

PULL_ARGS=(--host "$HOST" --user "$USER" --output "$OUTPUT")
[[ -n "$PASSWORD" ]] && PULL_ARGS+=(--password "$PASSWORD")
[[ "$INSECURE" -eq 1 ]] && PULL_ARGS+=(--insecure)
[[ "$ALL_DOMAINS" -eq 1 ]] && PULL_ARGS+=(--all-domains)
[[ "$MODE" == "quick" ]] && PULL_ARGS+=(--quick)

echo "=== FMC pull ($MODE) → $HOST ==="
$PY fmc_collect_data.py "${PULL_ARGS[@]}"

RUN=$(ls -td "$OUTPUT"/run-* 2>/dev/null | head -1)
if [[ -z "$RUN" ]]; then
  RUN=$(ls -td run-* 2>/dev/null | head -1)
fi
if [[ -z "$RUN" ]]; then
  echo "No run-* folder created" >&2
  exit 1
fi

echo "=== HTML → $RUN/html_view ==="
$PY build_html.py --input "$RUN"

echo "=== Package ($ARCHIVE_FMT) ==="
$PY package_run.py --input "$RUN" --format "$ARCHIVE_FMT" --output-dir "$(cd "$(dirname "$RUN")" && pwd)"

ARCHIVE=""
if [[ "$ARCHIVE_FMT" == "tgz" ]]; then
  ARCHIVE=$(ls -t "$(dirname "$RUN")"/fmc_audit_*.tar.gz 2>/dev/null | head -1)
else
  ARCHIVE=$(ls -t "$(dirname "$RUN")"/fmc_audit_*.zip 2>/dev/null | head -1)
fi

echo ""
echo "Done."
echo "  Bundle: $(cd "$(dirname "$RUN")" && pwd)/$(basename "$RUN")"
if [[ -n "$ARCHIVE" ]]; then
  echo "  Archive: $ARCHIVE"
  echo "  Send this file to NetConverter / ValeronLabs."
fi
echo "  Browser: file://$(cd "$RUN" && pwd)/html_view/index.html"
