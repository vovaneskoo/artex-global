#!/usr/bin/env bash
# mission-down — свернуть внешнюю миссию: убрать цели гостя, снять маркеры,
# вернуть хост в повседневный режим (lockdown off, VPN off).
set -euo pipefail

MULLVAD="/Applications/Mullvad VPN.app/Contents/Resources/mullvad"
BENCH_DIR="$HOME/projects/artex-bench"
STATE="$BENCH_DIR/artifacts/mission-gate"
ARMED="$STATE/armed"; STRICT="$STATE/strict"; TARGETS="$STATE/targets.txt"

if [ ! -e "$ARMED" ]; then
  echo "поднятой миссии нет — чистим хвосты (если были)"
fi

echo "[1/3] цели гостя закрываю..."
if [ -f "$TARGETS" ]; then
  while read -r ip; do
    [ -n "$ip" ] || continue
    # правило могло быть добавлено несколько раз исторически: режем до конца
    while limactl shell artex-bench -- sudo iptables -C OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null; do
      limactl shell artex-bench -- sudo iptables -D OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT
    done
    if limactl shell artex-bench -- sudo iptables -C OUTPUT -d "$ip" -p tcp -m multiport --dports 80,443 -j ACCEPT 2>/dev/null; then
      echo "FAIL: $ip всё ещё открыт!" >&2; exit 1
    fi
    echo "      закрыт $ip"
  done < "$TARGETS"
fi

echo "[2/3] маркеры реле снимаю..."
rm -f "$ARMED" "$STRICT" "$TARGETS"

echo "[3/3] хост в повседневный режим..."
"$MULLVAD" lockdown-mode set off
"$MULLVAD" disconnect
"$MULLVAD" lockdown-mode get | sed 's/^/      /'
echo "MISSION DOWN. Сводка канарей-журнала этой сессии:"
tail -5 "$BENCH_DIR/artifacts/canary-relay.log" 2>/dev/null || true
