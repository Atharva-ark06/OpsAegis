#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-7681}"
case "$PORT" in
  ''|*[!0-9]*) echo "PORT must be a numeric TCP port" >&2; exit 1 ;;
esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "PORT must be between 1024 and 65535" >&2
  exit 1
fi

mkdir -p /workspace
chown opsaegis:opsaegis /workspace
exec gosu opsaegis /usr/bin/ttyd \
  --writable \
  --interface 0.0.0.0 \
  --port "$PORT" \
  /bin/bash --login
