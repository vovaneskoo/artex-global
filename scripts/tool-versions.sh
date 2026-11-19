#!/bin/bash
# Emit a JSON manifest of installed mission tools (best effort, no network).
ts="$(date -u +%FT%TZ)"
tmp="$(mktemp)"
for b in subfinder amass dnsx httpx naabu nmap masscan ffuf feroxbuster gobuster whatweb wafw00f nikto katana nuclei searchsploit sqlmap hydra medusa nxc semgrep gitleaks trufflehog mariadb psql tsql redis-cli sqlite3 aws s3cmd rclone mongosh sslyze testssl wg openvpn swaks dnsrecon dalfox commix chisel ligolo-proxy bore ngrok cloudflared interactsh-client pwncat-cs certipy; do
  p="$(command -v "$b" 2>/dev/null)" || continue
  v="$("$b" --version 2>&1 | head -1 | tr -cd '[:print:]' | cut -c1-120)"
  printf '%s\t%s\t%s\n' "$b" "$p" "$v" >> "$tmp"
done
jq -Rn --arg ts "$ts" '[inputs | split("\t") | {key: .[0], value: {path: .[1], version: .[2]}}] | from_entries | {generated_at: $ts, tools: .}' < "$tmp"
rm -f "$tmp"
