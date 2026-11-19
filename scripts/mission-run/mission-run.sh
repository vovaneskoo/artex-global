#!/bin/bash
# Start/stop the mission engine: the artex-offsec container running a dedicated
# artex process against the shared bench PG. Runs with --network host so the
# agent toolchain reaches lab targets (127.0.0.1:18300-18302) and any
# mission-gate rules apply directly to the VM's egress.
#
#   mission-run.sh up [--targets IP|CIDR|HOST ...] [--no-gate] [--no-oast]
#   mission-run.sh down
#   mission-run.sh status
#
# Env: ARTEX_MISSION_VM (default artex-bench), ARTEX_MISSION_IMAGE
# (default artex-offsec:latest), ARTEX_ENGINE_PORT (8789), ARTEX_ENGINE_PROXY (8790).
set -euo pipefail
cd "$(cd "$(dirname "$0")/../.." && pwd)"

VM="${ARTEX_MISSION_VM:-artex-bench}"
IMAGE="${ARTEX_MISSION_IMAGE:-artex-offsec:latest}"
PORT="${ARTEX_ENGINE_PORT:-8789}"
PROXY="${ARTEX_ENGINE_PROXY:-8790}"
NAME="${ARTEX_ENGINE_CONTAINER:-artex-mission}"
DSN="postgres://postgres:artexpass@127.0.0.1:15432/artex?sslmode=disable"

sh() { limactl shell "$VM" -- bash -lc "$*"; }

health() {
  sh "curl -fsS -o /dev/null -m 5 http://127.0.0.1:$PORT/api/health" 2>/dev/null
}

cmd_up() {
  local targets=() gate=1 oast=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --no-gate) gate=0; shift ;;
      --no-oast) oast=0; shift ;;
      --targets) shift; targets+=("$@"); break ;;
      *) echo "unknown arg $1" >&2; exit 2 ;;
    esac
  done
  health && { echo "MISSION ENGINE already up"; } || {
    sh "sudo mkdir -p /var/lib/artex-mission && sudo chown -R 1000:1000 /var/lib/artex-mission
        sudo docker rm -f $NAME >/dev/null 2>&1 || true
        sudo docker run -d --name $NAME --network host --restart unless-stopped \
          -e ARTEX_PG_DSN='$DSN' -e ARTEX_STRICT_SCOPE=1 -v /var/lib/artex-mission:/app/data \
          $IMAGE -addr :$PORT -proxy :$PROXY" >/dev/null
    for i in $(seq 1 30); do health && break || sleep 2; done
    health || { echo "MISSION ENGINE failed to become healthy" >&2; exit 1; }
  }
  if [ "$gate" = 1 ]; then
    if [ "${#targets[@]}" -gt 0 ]; then
      ./scripts/mission-gate/mission-up.sh "${targets[@]}"
    else
      ./scripts/mission-gate/mission-up.sh >/dev/null 2>&1 || true
    fi
  fi
  if [ "$oast" = 1 ]; then
    ./scripts/callback-tunnel/deploy.sh >/dev/null
    sh '~/artex-oast/oast.sh up' || true
  fi
  local pub; pub=$(sh 'cat /var/lib/artex-oast/state.json 2>/dev/null | python3 -c "import json,sys;v=json.load(sys.stdin);print(v.get(\"public_host\",\"\"),v.get(\"public_port\",\"\"))"' 2>/dev/null || true)
  echo "MISSION ENGINE UP: http://127.0.0.1:$PORT (vm) [oast: ${pub:-off}]"
}

cmd_down() {
  sh "sudo docker rm -f $NAME >/dev/null 2>&1 || true; ~/artex-oast/oast.sh down >/dev/null 2>&1 || true" || true
  ./scripts/mission-gate/mission-down.sh || true
  echo "MISSION DOWN"
}

cmd_token() {
  sh "K=\$(sudo docker exec $NAME cat /app/jwt.key | base64); H=\$(sudo docker exec artex-db psql -U postgres -d artex -tAc \"select value from settings where key='auth.password_hash'\"); sudo python3 - \"\$H\" \"\$K\" <<PY
import hmac, hashlib, base64, json, time, sys
key=base64.b64decode(sys.argv[2])
h=sys.argv[1].strip()
sig=hmac.new(key,h.encode(),hashlib.sha256).digest()
b64=lambda d:base64.urlsafe_b64encode(d).rstrip(b'=').decode()
hdr=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
now=int(time.time())
pl=b64(json.dumps({'sub':'ARTEX','exp':now+7*86400,'iat':now}).encode())
print(hdr+'.'+pl+'.'+b64(hmac.new(sig,(hdr+'.'+pl).encode(),hashlib.sha256).digest()))
PY"
}

cmd_status() {
  if health; then echo "engine: up"; else echo "engine: down"; fi
  sh "~/artex-oast/oast.sh status 2>/dev/null | head -6" || true
  ./scripts/mission-gate/mission-status.sh || true
}

case "${1:-status}" in
  up) shift; cmd_up "$@" ;;
  down) cmd_down ;;
  token) cmd_token ;;
  status) cmd_status ;;
  *) echo "usage: mission-run.sh up|down|status|token" >&2; exit 2 ;;
esac
