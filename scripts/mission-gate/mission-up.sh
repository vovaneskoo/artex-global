#!/usr/bin/env bash
# mission-up — вывод стенда artex-bench на ВНЕШНЮЮ цель под полной защитой.
#
# Порядок (каждый шаг проверяется; провал = abort, уже открытое откатывается):
#   1. Mullvad connect + проверка exit-IP (am.i.mullvad.net: mullvad_exit_ip=true).
#   2. Kill-switch ON: mullvad lockdown-mode on — VPN моргнул в миссии =>
#      трафик блокируется, а не уходит с домашнего IP. LAN при этом тоже
#      блокируется (для миссии это фича); loopback консоли работает.
#   3. Гостю открываются ТОЛЬКО переданные IP целей (80/443), список в state.
#   4. armed/strict-маркеры: канарей-реле в strict-режиме пускает LLM-трафик
#      только при armed-маркере => LLM-путь становится заложником состояния
#      миссии (no gate = no Venice).
#
# usage: mission-up.sh <target-ip> [target-ip...]
#        (домены резолви заранее: dig +short <host> | grep -E '^[0-9]+\.')
set -euo pipefail

MULLVAD="/Applications/Mullvad VPN.app/Contents/Resources/mullvad"
BENCH_DIR="$HOME/projects/artex-bench"
STATE="$BENCH_DIR/artifacts/mission-gate"
ARMED="$STATE/armed"; STRICT="$STATE/strict"; TARGETS="$STATE/targets.txt"

[ $# -ge 1 ] || { echo "usage: $0 <target-ip>..." >&2; exit 2; }
mkdir -p "$STATE"
if [ -e "$ARMED" ]; then
  echo "mission уже поднята: $(cat "$TARGETS" 2>/dev/null | tr '\n' ' '). Сначала mission-down.sh" >&2
  exit 1
fi

cleanup_fail() {
  rm -f "$ARMED" "$STRICT"
  while read -r ip; do
    limactl shell artex-bench -- sudo iptables -D OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null || true
  done < "$TARGETS" 2>/dev/null || true
  "$MULLVAD" lockdown-mode set off >/dev/null 2>&1 || true
  "$MULLVAD" disconnect >/dev/null 2>&1 || true
}
trap cleanup_fail ERR

echo "[1/4] Mullvad connect + проверка выхода..."
"$MULLVAD" connect
sleep 3
EXIT_IP=$(curl -s --max-time 10 https://am.i.mullvad.net/json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("ip") if d.get("mullvad_exit_ip") else "")' || true)
[ -n "$EXIT_IP" ] || { echo "ABORT: exit-IP не Mullvad" >&2; false; }
echo "      exit: $EXIT_IP"

echo "[2/4] kill-switch (lockdown-mode) ON..."
"$MULLVAD" lockdown-mode set on
"$MULLVAD" lockdown-mode get | sed 's/^/      /'

echo "[3/4] цели гостю (80/443): $*"
: > "$TARGETS"
for ip in "$@"; do
  limactl shell artex-bench -- sudo iptables -C OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null \
    || limactl shell artex-bench -- sudo iptables -A OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT
  echo "$ip" >> "$TARGETS"
done

echo "[4/4] armed-маркеры реле..."
touch "$ARMED" "$STRICT"
trap - ERR
echo "MISSION UP: exit=$EXIT_IP targets=$* | down: mission-down.sh"
echo "помни: пока миссия поднята, VPN отключать нельзя (lockdown режет весь трафик хоста вне туннеля)."
