#!/usr/bin/env bash
# OAST + callback tunnel orchestrator. Runs INSIDE the artex-bench VM.
#   oast.sh up    - start OAST receiver + bore tunnel (fallback serveo), verify, save state
#   oast.sh status- print state and hit count
#   oast.sh down  - stop containers (hits are kept in /var/lib/artex-oast)
# The public endpoint lands in /var/lib/artex-oast/state.json; agents poll the
# OAST container directly at http://artex-oast:18080/hits on the docker network.
set -euo pipefail
STATE_DIR=${ARTEX_OAST_STATE_DIR:-/var/lib/artex-oast}
STATE=$STATE_DIR/state.json
OAST_NAME=artex-oast
TUNNEL_NAME=artex-tunnel
NET=artex-oast
OAST_PORT=18080
IMAGE=${ARTEX_OAST_IMAGE:-artex-offsec:latest}
SCRIPTS_DIR=${ARTEX_OAST_SCRIPTS:-$HOME/artex-oast}
TIMEOUT=${ARTEX_OAST_TIMEOUT:-25}

die() { echo "OAST ERROR: $*" >&2; exit 1; }
cmd() { sudo -n "$@"; }

containers_clean() {
  cmd docker rm -f "$TUNNEL_NAME" "$OAST_NAME" >/dev/null 2>&1 || true
}

ensure_network() {
  cmd docker network inspect "$NET" >/dev/null 2>&1 || cmd docker network create "$NET" >/dev/null
}

wait_for_pattern() { # file pattern seconds
  local deadline=$((SECONDS + $3))
  while [ $SECONDS -lt $deadline ]; do
    local match
    match=$(grep -E -o "$2" "$1" 2>/dev/null | head -1 || true)
    [ -n "$match" ] && { echo "$match"; return 0; }
    sleep 1
  done
  return 1
}

public_verify() { # host port
  [ -n "$(curl -fsS --max-time 10 "http://$1:$2/health" 2>/dev/null)" ] || { cmd docker logs "$TUNNEL_NAME" --tail 20 >&2 || true; die "public endpoint not reachable"; }
}

start_bore() {
  cmd docker run -d --name "$TUNNEL_NAME" --network "$NET" \
    -v "$STATE_DIR:/data" --entrypoint bash "$IMAGE" \
    -c "bore local --to bore.pub --local-host artex-oast $OAST_PORT >/data/bore.log 2>&1" >/dev/null
  local match
  match=$(wait_for_pattern "$STATE_DIR/bore.log" 'bore\.pub:[0-9]+' "$TIMEOUT" || true)
  [ -n "$match" ] || return 1
  echo "$match"
  return 0
}

start_serveo() {
  cmd docker run -d --name "$TUNNEL_NAME" --network "$NET" \
    -v "$STATE_DIR:/data" --entrypoint ssh "$IMAGE" \
    -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
    -R 0:127.0.0.1:$OAST_PORT serveo.net >/dev/null
  local deadline=$((SECONDS + TIMEOUT))
  while [ $SECONDS -lt $deadline ]; do
    local match
    match=$(cmd docker logs "$TUNNEL_NAME" 2>&1 | grep -E -o 'serveo\.net:[0-9]+' | head -1 || true)
    [ -n "$match" ] && { echo "$match"; return 0; }
    sleep 1
  done
  return 1
}

cmd_up() {
  cmd mkdir -p "$STATE_DIR"
  cmd chmod 777 "$STATE_DIR"
  [ -f "$SCRIPTS_DIR/oastd.py" ] || die "oastd.py not found in $SCRIPTS_DIR (run deploy from host)"
  containers_clean
  ensure_network
  cmd docker run -d --name "$OAST_NAME" --network "$NET" \
    -e OAST_LOG=/data/hits.jsonl -v "$STATE_DIR:/data" \
    -v "$SCRIPTS_DIR/oastd.py:/opt/oastd.py:ro" \
    --entrypoint python3 "$IMAGE" /opt/oastd.py >/dev/null
  sleep 1
  cmd docker exec "$OAST_NAME" python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:$OAST_PORT/health')" \
    || die "OAST receiver failed locally"
  public=$(start_bore) || public=$(start_serveo) || die "no tunnel provider worked"
  host=${public%%:*}; port=${public##*:}
  public_verify "$host" "$port"
  ENGINE_CONTAINER=${ARTEX_ENGINE_CONTAINER:-nervous_lamarr}
  if cmd docker ps --format '{{.Names}}' | grep -q "^$ENGINE_CONTAINER$"; then
    cmd docker network connect "$NET" "$ENGINE_CONTAINER" >/dev/null 2>&1 || true
  fi
  python3 - "$STATE" "$host" "$port" <<'PY'
import json, sys, time, os
state, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
value = {'public_host': host, 'public_port': port, 'local_port': 18080,
         'tool': 'bore' if host == 'bore.pub' else 'serveo', 'ts': round(time.time())}
tmp = state + '.tmp'
open(tmp, 'w').write(json.dumps(value, indent=2) + '\n')
os.replace(tmp, state)
PY
  echo "OAST UP: http://$host:$port (poll http://artex-oast:$OAST_PORT/hits)"
}

cmd_status() {
  if [ -f "$STATE" ]; then cat "$STATE"; else echo '{"status":"down"}'; fi
  if cmd docker ps --format '{{.Names}}' | grep -q "^$OAST_NAME$"; then
    cmd docker exec "$OAST_NAME" python3 -c "import urllib.request,json;print(len(json.load(urllib.request.urlopen('http://127.0.0.1:$OAST_PORT/hits'))),'hits')" 2>/dev/null || true
  fi
}

cmd_down() {
  ENGINE_CONTAINER=${ARTEX_ENGINE_CONTAINER:-nervous_lamarr}
  if cmd docker inspect "$ENGINE_CONTAINER" >/dev/null 2>&1; then
    cmd docker network disconnect "$NET" "$ENGINE_CONTAINER" >/dev/null 2>&1 || true
  fi
  containers_clean
  echo "OAST DOWN"
}

case "${1:-}" in
  up) cmd_up ;;
  status) cmd_status ;;
  down) cmd_down ;;
  *) die "usage: oast.sh up|status|down" ;;
esac
