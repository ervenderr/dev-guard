#!/usr/bin/env bash
# Cron wrapper: scan, then POST the dev-guard JSON to the n8n webhook in DEV_GUARD_WEBHOOK_URL.
# python3 on cron's PATH must be 3.12+, else set DEV_GUARD_PYTHON.
set -u -o pipefail

url="${DEV_GUARD_WEBHOOK_URL:-}"
if [ -z "$url" ]; then
  echo "run-alert: DEV_GUARD_WEBHOOK_URL is not set" >&2
  exit 64
fi
case "$url" in
  *'"'*|*$'\n'*)
    echo "run-alert: webhook URL contains an invalid character" >&2
    exit 64
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

PYTHONPATH="$root" "${DEV_GUARD_PYTHON:-python3}" -m dev_guard --json --exclude "$root/tests" "$@" > "$out"
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
  echo "run-alert: dev-guard failed with exit code $rc" >&2
  exit "$rc"
fi

# URL goes via curl config on stdin so it never shows in argv; curl stderr is discarded.
if ! printf 'url = "%s"\n' "$url" | curl -K - -sS --fail --max-time 30 -X POST \
    -H 'Content-Type: application/json' --data-binary @"$out" >/dev/null 2>&1; then
  echo "run-alert: webhook POST failed" >&2
  exit 75
fi
exit 0
