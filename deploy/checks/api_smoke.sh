#!/usr/bin/env bash
# Smoke test of the deployed API, run by the deploy-api job in
# .github/workflows/ci.yml after each deploy. By hand:
#
#   API_URL=https://api.webriskaudit.com SITE_ORIGIN=https://webriskaudit.com \
#   EXPECTED_REVISION="$(git rev-parse origin/main)" \
#   API_LB_IP="$(terraform -chdir=infra/gcp output -raw lb_ip)" \
#     deploy/checks/api_smoke.sh
#
# It scans webriskaudit.com, the project's own domain, and nothing else.
# Right after a deploy the report cache is empty, so that scan goes out
# through the resolvers and Cloud NAT. Needs curl 7.84 or later and jq.
set -euo pipefail

: "${API_URL:?public URL of the API, such as https://api.webriskaudit.com}"
: "${SITE_ORIGIN:?the origin the API allows, such as https://webriskaudit.com}"
: "${EXPECTED_REVISION:?the commit that should be serving}"
: "${API_LB_IP:?the load balancer address (terraform output lb_ip)}"

API_URL=${API_URL%/}
SCAN_DOMAIN=webriskaudit.com
REVISION_ATTEMPTS=${REVISION_ATTEMPTS:-36} # 10 s apart
MAX_RETRY_AFTER=600                        # the API's rate limit window

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  if [[ -n ${GITHUB_ACTIONS:-} ]]; then echo "::error::$*"; else echo "FAIL: $*"; fi >&2
  exit 1
}

# POST a scan of $1 through the public URL, once more after a 429 (from the
# API or from Cloudflare's rate limit). Sets STATUS; the body is in $work/body.
post_scan() {
  local attempt out wait
  local body="{\"domain\":\"$1\"}"
  for attempt in 1 2; do
    out=$(curl -sS --max-time 100 -o "$work/body" -w '%{http_code} %header{retry-after}' \
      -X POST "$API_URL/api/v1/scan" -H 'Content-Type: application/json' --data "$body") ||
      fail "POST /api/v1/scan for $1: no response"
    STATUS=${out%% *}
    if [[ $STATUS != 429 || $attempt == 2 ]]; then
      return 0
    fi
    wait=${out#* }
    [[ $wait =~ ^[0-9]+$ ]] || wait=10
    ((wait <= MAX_RETRY_AFTER)) || fail "POST /api/v1/scan for $1: 429 with Retry-After $wait"
    echo "429 for $1; retrying in $wait s"
    sleep "$((wait + 1))"
  done
}

# OPTIONS preflight for a scan from origin $1. Prints the response headers as
# JSON (lower-case names, values in arrays).
preflight() {
  curl -sS --max-time 10 -o /dev/null -w '%{header_json}' -X OPTIONS "$API_URL/api/v1/scan" \
    -H "Origin: $1" -H 'Access-Control-Request-Method: POST' \
    -H 'Access-Control-Request-Headers: content-type' || fail "OPTIONS /api/v1/scan: no response"
}

# 1. The new revision serves. Cloudflare and the load balancer may still
#    reach the old instance for a moment, and a new one can take minutes.
seen=""
for ((i = 1; i <= REVISION_ATTEMPTS; i++)); do
  seen=$(curl -fsS --max-time 10 "$API_URL/" 2> /dev/null | jq -r '.revision // empty' 2> /dev/null) || seen=""
  [[ $seen == "$EXPECTED_REVISION" ]] && break
  ((i == REVISION_ATTEMPTS)) || sleep 10
done
[[ $seen == "$EXPECTED_REVISION" ]] || fail "GET / reports revision '${seen:-none}', expected $EXPECTED_REVISION"
curl -fsS --max-time 10 "$API_URL/" | jq -e '.docs == null' > /dev/null ||
  fail "GET / lists interactive docs; production runs with API_DOCS_ENABLED=false"
echo "ok: GET / reports revision $seen, docs off"

# 2. Liveness.
curl -fsS --max-time 10 "$API_URL/health" | jq -e '.status == "ok"' > /dev/null ||
  fail "GET /health does not return {\"status\":\"ok\"}"
echo "ok: GET /health"

# 3. CORS: the site's origin may call the API, another origin may not.
preflight "$SITE_ORIGIN" | jq -e --arg o "$SITE_ORIGIN" '.["access-control-allow-origin"] == [$o]' > /dev/null ||
  fail "preflight from $SITE_ORIGIN is not allowed"
preflight https://not-allowed.invalid | jq -e '.["access-control-allow-origin"] == null' > /dev/null ||
  fail "preflight from another origin is allowed"
echo "ok: CORS allows $SITE_ORIGIN only"

# 4. A real scan. A score needs at least half of the checks to finish, and
#    the two transport checks need outbound connections to ports 443 and 80.
post_scan "$SCAN_DOMAIN"
[[ $STATUS == 200 ]] || fail "scan of $SCAN_DOMAIN: HTTP $STATUS $(head -c 300 "$work/body")"
if ! jq -e --arg d "$SCAN_DOMAIN" '
  .domain == $d and .score != null and
  ([.checks[] | select(.id == "transport.tls_certificate" or .id == "transport.https_redirect")]
    | length == 2 and all(.status != "inconclusive"))
' "$work/body" > /dev/null; then
  summary=$(jq -c '{score, coverage, checks: [.checks[]? | {id, status}]}' "$work/body" 2> /dev/null) ||
    summary=$(head -c 300 "$work/body")
  fail "scan of $SCAN_DOMAIN is incomplete: $summary"
fi
jq -r '"ok: scan of \(.domain): grade \(.grade), score \(.score), \(.coverage.scored) of \(.coverage.total) scored checks, \(.duration_ms) ms"' "$work/body"

# 5. Input validation.
post_scan localhost
if [[ $STATUS != 422 ]] || ! jq -e '.type | endswith("/invalid-domain")' "$work/body" > /dev/null; then
  fail "scan of localhost: HTTP $STATUS, expected 422 invalid-domain"
fi
echo "ok: localhost is refused with 422"

# 6. Origin lock: straight to the load balancer, without the X-Origin-Auth
#    header that Cloudflare adds, the API refuses the request.
authority=${API_URL#*://}
authority=${authority%%/*}
host=${authority%%:*}
if [[ $authority == *:* ]]; then
  port=${authority##*:}
elif [[ $API_URL == https://* ]]; then
  port=443
else
  port=80
fi
body="{\"domain\":\"$SCAN_DOMAIN\"}"
STATUS=$(curl -sS --max-time 15 -o "$work/body" -w '%{http_code}' --resolve "$host:$port:$API_LB_IP" \
  -X POST "$API_URL/api/v1/scan" -H 'Content-Type: application/json' --data "$body") ||
  fail "POST straight to $API_LB_IP: no response"
if [[ $STATUS != 403 ]] || ! jq -e '.type | endswith("/forbidden")' "$work/body" > /dev/null; then
  fail "POST straight to the load balancer ($API_LB_IP): HTTP $STATUS, expected 403 forbidden"
fi
echo "ok: requests that bypass Cloudflare get 403"
