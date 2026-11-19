#!/bin/bash
# Apply ARTEX battle defaults over REST before an isolated run:
#   llm_record=true             → PUT /api/settings
#   llm_judge_fail_action=deny  → PUT /api/intercept/judge (judge keys are a
#                                 separate REST resource, NOT flat /api/settings
#                                 fields — see server.go route table). The judge
#                                 PUT takes the FULL config, so we GET-merge-PUT
#                                 to leave every other judge field untouched.
# Idempotent: re-running converges to the same state and verifies it.
#
# Usage: setup-defaults.sh <base-url> <bearer-token>
#   e.g. setup-defaults.sh http://127.0.0.1:8787 "$ARTEX_TOKEN"
set -euo pipefail

BASE="${1:?usage: setup-defaults.sh <base-url> <bearer-token>}"
TOKEN="${2:?usage: setup-defaults.sh <base-url> <bearer-token>}"
BASE="${BASE%/}"
AUTH=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

die() { echo "FAIL: $*" >&2; exit 1; }

# health is auth-exempt; a plain reachability gate before anything else
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/api/health" || true)
[ "$CODE" = "200" ] || die "server not healthy at $BASE (GET /api/health → $CODE)"

# 1) llm_record=true — the PUT response echoes the full settings payload,
#    so the value read back from the same response is the verification.
RESP=$(curl -s --max-time 20 "${AUTH[@]}" -X PUT -d '{"llm_record":true}' \
  -w '\n%{http_code}' "$BASE/api/settings" || true)
BODY="${RESP%$'\n'*}"; HTTP="${RESP##*$'\n'}"
[ "$HTTP" = "200" ] || die "PUT /api/settings → $HTTP ($BODY)"
printf '%s' "$BODY" | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if d.get("llm_record") is True else 1)
' || die "llm_record is not true after PUT (got: $BODY)"
echo "ok: llm_record=true"

# 2) llm_judge_fail_action=deny — GET current config, override one field, PUT back.
CUR=$(curl -s --max-time 20 "${AUTH[@]}" "$BASE/api/intercept/judge" || true)
MERGED=$(printf '%s' "$CUR" | python3 -c '
import json, sys
d = json.load(sys.stdin)
d["fail_action"] = "deny"
print(json.dumps(d))
' || true)
[ -n "$MERGED" ] || die "could not read/merge judge config (got: $CUR)"
RESP=$(curl -s --max-time 20 "${AUTH[@]}" -X PUT -d "$MERGED" \
  -w '\n%{http_code}' "$BASE/api/intercept/judge" || true)
BODY="${RESP%$'\n'*}"; HTTP="${RESP##*$'\n'}"
[ "$HTTP" = "200" ] || die "PUT /api/intercept/judge → $HTTP ($BODY)"

# verify from a fresh GET (not from the PUT echo)
BACK=$(curl -s --max-time 20 "${AUTH[@]}" "$BASE/api/intercept/judge" || true)
printf '%s' "$BACK" | python3 -c '
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if d.get("fail_action") == "deny" else 1)
' || die "fail_action is not deny after PUT (got: $BACK)"
echo "ok: llm_judge_fail_action=deny"

echo "SETUP DEFAULTS OK ($BASE)"
