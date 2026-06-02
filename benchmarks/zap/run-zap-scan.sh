#!/usr/bin/env bash
# OWASP ZAP baseline DAST harness for the thesis benchmark.
# Runs zap-api-scan.py against a VAMPI instance and captures JSON + HTML + MD
# reports plus wall-clock timing (CI overhead metric).
#
# Why we rewrite the spec: VAMPI's OpenAPI hardcodes `servers: http://localhost:5000`,
# which is unreachable from inside the ZAP container. ZAP's OpenAPI importer then
# falls back to using the spec's own retrieval URL as the base path and only hits
# 404s (testing nothing). Passing -O did not fix this reliably. The robust fix is
# to fetch the spec on the host, rewrite `servers` to a URL reachable from the ZAP
# container, and hand ZAP a LOCAL file -- then ZAP must use the corrected server.
#
# Usage:
#   ./run-zap-scan.sh <label> <host-spec-url> <network> <in-network-base-url>
# Example:
#   ./run-zap-scan.sh vampi-vuln   http://localhost:5002/openapi.json vampi_default http://vampi-vulnerable:5000
set -euo pipefail

LABEL="${1:?need a label, e.g. vampi-vuln}"
HOST_SPEC_URL="${2:?need a host-reachable OpenAPI URL, e.g. http://localhost:5002/openapi.json}"
NETWORK="${3:?need the docker network the target is on, e.g. vampi_default}"
BASE_URL="${4:?need the in-network base URL, e.g. http://vampi-vulnerable:5000}"

ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$(cd "$HERE/../../results/zap" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
RUN_DIR="$OUT_DIR/${LABEL}-${TS}"
mkdir -p "$RUN_DIR"
# The ZAP container writes reports as its own 'zap' user (uid 1000). On CI
# runners the host user differs (e.g. uid 1001), so make the mount world-writable
# to avoid "Permission denied: /zap/wrk/report.html".
chmod 777 "$RUN_DIR"

echo "==> ZAP API scan"
echo "    label:    $LABEL"
echo "    spec src: $HOST_SPEC_URL"
echo "    base url: $BASE_URL"
echo "    network:  $NETWORK"
echo "    output:   $RUN_DIR"

# 1) Fetch the spec and rewrite servers -> reachable base URL.
echo "==> fetching + rewriting OpenAPI spec"
curl -fsS "$HOST_SPEC_URL" -o "$RUN_DIR/openapi-original.json"
BASE_URL="$BASE_URL" python3 - "$RUN_DIR/openapi-original.json" "$RUN_DIR/openapi-prepared.json" <<'PY'
import json, os, sys
src, dst = sys.argv[1], sys.argv[2]
spec = json.load(open(src))
spec["servers"] = [{"url": os.environ["BASE_URL"]}]
json.dump(spec, open(dst, "w"), indent=2)
print("    servers ->", spec["servers"][0]["url"])
PY

# 2) Run ZAP against the LOCAL prepared spec (mounted at /zap/wrk).
START=$(date +%s.%N)
set +e
docker run --rm \
  --network "$NETWORK" \
  -v "$RUN_DIR":/zap/wrk:rw \
  "$ZAP_IMAGE" \
  zap-api-scan.py \
    -t /zap/wrk/openapi-prepared.json \
    -f openapi \
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
