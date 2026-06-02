#!/usr/bin/env bash
# OWASP ZAP *tuned* DAST harness for the thesis benchmark.
#
# Unlike a default api-scan, this run is configured the way a security engineer
# would configure ZAP for an authenticated API:
#   1. AUTHENTICATION — registers + logs in to VAMPI to obtain a real JWT, then
#      injects `Authorization: Bearer <jwt>` into every request (via a ZAP
#      Replacer rule set in an api-scan hook), so ZAP can reach authenticated
#      endpoints instead of getting 401s.
#   2. STRONGER POLICY — raises every active-scan rule to HIGH attack strength
#      and LOW alert threshold.
# This is the "tuned ZAP" baseline: a fair, expert-configured comparison that
# still relies on rule-based detection.
#
# Usage:
#   ./run-zap-scan.sh <label> <host-spec-url> <docker-network> <in-network-base-url>
# Example (self-hosted, scanning the live local container):
#   ./run-zap-scan.sh vampi-local http://localhost:5002/openapi.json host http://localhost:5002
set -euo pipefail

LABEL="${1:?need a label, e.g. vampi-local}"
HOST_SPEC_URL="${2:?need a host-reachable OpenAPI URL, e.g. http://localhost:5002/openapi.json}"
NETWORK="${3:?need the docker network the target is on, e.g. host}"
BASE_URL="${4:?need the in-network base URL, e.g. http://localhost:5002}"

ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$(cd "$HERE/../../results/zap" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/${LABEL}-${TS}"
mkdir -p "$RUN_DIR"
chmod 777 "$RUN_DIR"   # ZAP writes reports as uid 1000

AUTH_BASE="${HOST_SPEC_URL%/openapi.json}"
echo "==> ZAP TUNED API scan"
echo "    label:    $LABEL"
echo "    spec src: $HOST_SPEC_URL"
echo "    base url: $BASE_URL"
echo "    output:   $RUN_DIR"

# 1) Seed VAMPI and obtain a JWT (register may already exist -> ignore).
curl -fsS --max-time 15 "$AUTH_BASE/createdb" >/dev/null 2>&1 || true
ZUSER="zapscan_$RANDOM"; ZPASS="ZapScan123!"
curl -fsS --max-time 15 -X POST "$AUTH_BASE/users/v1/register" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ZUSER\",\"password\":\"$ZPASS\",\"email\":\"$ZUSER@test.com\"}" >/dev/null 2>&1 || true
TOKEN="$(curl -fsS --max-time 15 -X POST "$AUTH_BASE/users/v1/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ZUSER\",\"password\":\"$ZPASS\"}" 2>/dev/null \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("auth_token",""))' 2>/dev/null || true)"
if [[ -n "$TOKEN" ]]; then echo "    auth:     JWT obtained for $ZUSER"; else echo "    auth:     WARNING - no token, scanning unauthenticated"; fi

# 2) Fetch + rewrite the OpenAPI server so ZAP scans the real endpoints.
curl -fsS --max-time 30 "$HOST_SPEC_URL" -o "$RUN_DIR/openapi-original.json"
BASE_URL="$BASE_URL" python3 - "$RUN_DIR/openapi-original.json" "$RUN_DIR/openapi-prepared.json" <<'PY'
import json, os, sys
spec = json.load(open(sys.argv[1]))
spec["servers"] = [{"url": os.environ["BASE_URL"]}]
json.dump(spec, open(sys.argv[2], "w"), indent=2)
PY

# 3) Hook: inject the bearer token on every request + strengthen the active scan.
cat > "$RUN_DIR/hook.py" <<'PY'
import os

def zap_started(zap, target):
    token = os.environ.get('ZAP_AUTH_TOKEN', '')
    if token:
        zap.replacer.add_rule(description='auth', enabled=True, matchtype='REQ_HEADER',
                              matchregex='false', matchstring='Authorization',
                              replacement='Bearer ' + token)
        print('[hook] Authorization bearer replacer rule added')
    try:
        for sc in zap.ascan.scanners():
            zap.ascan.set_scanner_attack_strength(id=sc['id'], attackstrength='HIGH')
            zap.ascan.set_scanner_alert_threshold(id=sc['id'], alertthreshold='LOW')
        print('[hook] active scan tuned: attackStrength=HIGH, alertThreshold=LOW')
    except Exception as e:
        print('[hook] policy tune skipped:', e)
PY

# 4) Run the tuned scan.
START=$(date +%s.%N)
set +e
docker run --rm \
  --network "$NETWORK" \
  -e ZAP_AUTH_TOKEN="$TOKEN" \
  -v "$RUN_DIR":/zap/wrk:rw \
  "$ZAP_IMAGE" \
  zap-api-scan.py \
    -t /zap/wrk/openapi-prepared.json \
    -f openapi \
    --hook /zap/wrk/hook.py \
    -J report.json \
    -r report.html \
    -w report.md \
    -I \
  > "$RUN_DIR/zap-stdout.txt" 2>&1
ZAP_RC=$?
set -e
END=$(date +%s.%N)
DURATION=$(awk "BEGIN{printf \"%.2f\", $END-$START}")

cat > "$RUN_DIR/run-meta.json" <<EOF
{
  "label": "$LABEL",
  "tuned": true,
  "authenticated": $([[ -n "$TOKEN" ]] && echo true || echo false),
  "host_spec_url": "$HOST_SPEC_URL",
  "base_url": "$BASE_URL",
  "network": "$NETWORK",
  "zap_image": "$ZAP_IMAGE",
  "timestamp": "$TS",
  "duration_seconds": $DURATION,
  "zap_exit_code": $ZAP_RC
}
EOF

echo "==> done in ${DURATION}s (zap exit $ZAP_RC)"
echo "    reports: $RUN_DIR"
ln -sfn "$RUN_DIR" "$OUT_DIR/${LABEL}-latest"
