#!/usr/bin/env bash
# Smoke test of the deployed site, run by the deploy-site job in
# .github/workflows/ci.yml after each deploy. By hand:
#
#   SITE_URL=https://webriskaudit-web.SUBDOMAIN.workers.dev \
#   API_ORIGIN=https://api.webriskaudit.com deploy/checks/site_smoke.sh
#
# Checks pages, the 404 page and the headers from frontend/public/_headers.
# Needs curl 7.83 or later and jq.
set -euo pipefail

: "${SITE_URL:?the deployed site, such as https://webriskaudit-web.SUBDOMAIN.workers.dev}"
: "${API_ORIGIN:?the API origin the CSP must allow, such as https://api.webriskaudit.com}"

SITE_URL=${SITE_URL%/}
ATTEMPTS=${ATTEMPTS:-12} # 10 s apart, for a new workers.dev subdomain

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  if [[ -n ${GITHUB_ACTIONS:-} ]]; then echo "::error::$*"; else echo "FAIL: $*"; fi >&2
  exit 1
}

# GET $SITE_URL$1. Sets STATUS and HEADERS (JSON: lower-case names, values in
# arrays, from the final response); the body is in $work/body.
fetch() {
  local out
  out=$(curl -sS --max-time 15 -o "$work/body" -w '%{http_code} %{header_json}' "$SITE_URL$1") ||
    fail "GET $1: no response"
  STATUS=${out%% *}
  HEADERS=${out#* }
}

# The security headers every page must carry, once each.
check_page() {
  local path=$1
  [[ $STATUS == 200 ]] || fail "GET $path: HTTP $STATUS"
  jq -e --arg connect "connect-src 'self' $API_ORIGIN;" '
    (.["content-security-policy"] | length == 1 and (.[0] | contains($connect)))
    and .["x-frame-options"] == ["DENY"]
    and .["x-content-type-options"] == ["nosniff"]
    and .["referrer-policy"] == ["strict-origin-when-cross-origin"]
    and ((.["access-control-allow-origin"] // []) | index("*") == null)
  ' <<< "$HEADERS" > /dev/null || fail "GET $path: unexpected headers: $(jq -c . <<< "$HEADERS")"
  if grep -qi googletagmanager "$work/body" || grep -qi googletagmanager <<< "$HEADERS"; then
    fail "GET $path: the page refers to Google Tag Manager"
  fi
  echo "ok: GET $path with one CSP allowing $API_ORIGIN"
}

for ((i = 1; i <= ATTEMPTS; i++)); do
  fetch /
  [[ $STATUS == 200 ]] && break
  ((i == ATTEMPTS)) || sleep 10
done
check_page /

# A build asset, which _headers marks as immutable.
asset=$(grep -oE '/_next/static/[^"]+[.]js' "$work/body" | sed -n 1p) || fail "GET /: no /_next/static script"
fetch /privacy-policy
check_page /privacy-policy

fetch "$asset"
[[ $STATUS == 200 ]] || fail "GET $asset: HTTP $STATUS"
jq -e '.["cache-control"] // [] | any(contains("immutable"))' <<< "$HEADERS" > /dev/null ||
  fail "GET $asset: no immutable Cache-Control"
echo "ok: GET $asset is cached as immutable"

fetch /smoke-test-missing-page
[[ $STATUS == 404 ]] || fail "GET /smoke-test-missing-page: HTTP $STATUS, expected 404"
grep -qi '<html' "$work/body" || fail "GET /smoke-test-missing-page: no 404 page"
echo "ok: unknown paths get the 404 page"
