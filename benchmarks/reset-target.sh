#!/usr/bin/env bash
# Reset the benchmark target to a clean state BEFORE every scan.
#
# Why: VAMPI runs on the Flask/Werkzeug dev server (debug=True), which has no
# timeouts and can wedge a connection-handler thread into a 100% CPU busy loop
# on a half-closed socket. A leftover wedged connection from a prior scan also
# skews timing. Restarting the container between scans gives each run a fresh,
# deterministic target — and clears any spinning thread.
#
# Usage:
#   ./reset-target.sh                       # restart default container, wait until healthy
#   ./reset-target.sh my-container          # restart a named container
#   CONTAINER=foo ./reset-target.sh         # same, via env
#   HEALTH_URL=http://localhost:5000/ ./reset-target.sh   # override readiness probe
#
# Exit codes: 0 = target healthy; 1 = restart failed; 2 = never became healthy.
set -euo pipefail

CONTAINER="${1:-${CONTAINER:-vampi-vulnerable}}"
HEALTH_URL="${HEALTH_URL:-http://localhost:5000/}"
TIMEOUT="${TIMEOUT:-30}"   # seconds to wait for readiness

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "reset-target: container '$CONTAINER' not found — skipping reset." >&2
  exit 0   # don't fail scans that target something other than the local container
fi

echo "==> reset-target: restarting '$CONTAINER'"
docker restart "$CONTAINER" >/dev/null || { echo "reset-target: restart failed" >&2; exit 1; }

echo "    waiting up to ${TIMEOUT}s for readiness ($HEALTH_URL)"
deadline=$(( $(date +%s) + TIMEOUT ))
while :; do
  if curl -fsS --max-time 3 -o /dev/null "$HEALTH_URL" 2>/dev/null; then
    echo "    ready."
    exit 0
  fi
  if [[ $(date +%s) -ge $deadline ]]; then
    echo "reset-target: '$CONTAINER' did not become ready within ${TIMEOUT}s" >&2
    exit 2
  fi
  sleep 1
done
