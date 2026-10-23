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
  *'"'*|*\\*|*@*|*[[:cntrl:]]*)
    echo "run-alert: webhook URL contains an invalid character" >&2
    exit 64
    ;;
  https://*|http://127.0.0.1:*|http://127.0.0.1/*) ;;  # plain http only for loopback
  *)
    echo "run-alert: webhook URL must start with https://" >&2
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

# URL goes via curl config on stdin so it never shows in argv; curl stderr is discarded
# (it can echo the URL), so only the exit code and numeric HTTP status are logged.
code="$(printf 'url = "%s"\n' "$url" | curl -K - -sS --fail --max-time 30 -X POST \
    -H 'Content-Type: application/json' --data-binary @"$out" -o /dev/null -w '%{http_code}' 2>/dev/null)"
crc=$?
if [ "$crc" -ne 0 ]; then
  echo "run-alert: webhook POST failed (curl exit $crc, http ${code//[!0-9]/})" >&2
  exit 75
fi
exit 0
