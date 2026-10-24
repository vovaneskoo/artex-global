#!/bin/bash
# Egress lock for the isolated ARTEX guest VM (from vm-lab/egress-lock.sh).
# The guest may talk to the outside world ONLY through:
#  - lo (ssh -R tunnel 127.0.0.1:<port> → host canary relay → LLM API; /etc/hosts)
#  - DNS to the vz NAT gateway (local names only; external A-records are
#    useless anyway — TCP towards them is dropped)
#  - DHCP renewal towards the gateway
# Everything else in OUTPUT is DROPped. Containers (FORWARD/DOCKER-USER):
# internal docker subnets only, nothing out. Rule counters are a second
# canary — check them with: iptables -L OUTPUT -v -n (after a run).
#
# Usage:
#   egress-lock.sh <gateway-ip> [tunnel-port] [upstream-host]
#   egress-lock.sh --unlock        # rollback: restore permissive defaults
set -euo pipefail

GW=""
TUNNEL_PORT="${2:-8443}"
UP_HOST="${3:-api.venice.ai}"

if [ "${1:-}" = "--unlock" ]; then
  [ "$(id -u)" = 0 ] || { echo "unlock needs root"; exit 1; }
  iptables -F OUTPUT 2>/dev/null || true
  iptables -P OUTPUT ACCEPT
  ip6tables -F OUTPUT 2>/dev/null || true
  ip6tables -P OUTPUT ACCEPT
  iptables -F DOCKER-USER 2>/dev/null || true
  echo "EGRESS LOCK REMOVED (OUTPUT/DOCKER-USER permissive again)"
  exit 0
fi

GW="${1:?usage: egress-lock.sh <gateway-ip> [tunnel-port] [upstream-host] | --unlock}"
[ "$(id -u)" = 0 ] || { echo "egress-lock needs root (iptables)"; exit 1; }
echo "gateway: $GW  tunnel-port: $TUNNEL_PORT  upstream: $UP_HOST"

# --- host-guest namespace: OUTPUT ---
# MANDATORY: 172.16/12 (docker subnets) must stay allowed — lab targets live
# there and loopback-published ports are DNAT-ed into 172.x and leave via
# eth0; without this rule the lock cuts off the guest's own targets
# (found on a bench run 2026-10-23).
iptables -F OUTPUT 2>/dev/null || true
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 172.16.0.0/12 -m comment --comment "lab targets: loopback publishes DNAT into 172.x" -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -d "$GW" -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -d "$GW" -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -d "$GW" -p udp --dport 67 -j ACCEPT
iptables -P OUTPUT DROP

# --- ipv6: established + lo only, everything else DROP ---
ip6tables -F OUTPUT 2>/dev/null || true
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -P OUTPUT DROP

# --- docker containers: no egress from containers ---
iptables -F DOCKER-USER 2>/dev/null || true
iptables -I DOCKER-USER 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -I DOCKER-USER 2 -d 172.16.0.0/12 -j ACCEPT
iptables -I DOCKER-USER 3 -j DROP

echo "--- self-check (negative test waits up to 8s) ---"
if curl -s --max-time 8 -o /dev/null https://example.com 2>/dev/null; then
  echo "ISOLATION BROKEN: example.com is reachable"; exit 1
else
  echo "ok: external host unreachable (as designed)"
fi
CODE=$(curl -s --max-time 10 --resolve "$UP_HOST:$TUNNEL_PORT:127.0.0.1" -o /dev/null \
  -w '%{http_code}' "https://$UP_HOST:$TUNNEL_PORT/v1/models" || true)
echo "LLM via tunnel: HTTP $CODE (402/200 = path alive)"
echo "EGRESS LOCK OK"
