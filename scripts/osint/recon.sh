#!/bin/bash
# Passive OSINT recon helper for mission workers (lives in the offsec image as
# /opt/recon.sh). Passive-only: nothing here touches the target directly except
# DNS resolution of already-discovered names.
#
#   recon.sh domain <root-domain> [outdir]   # subdomains: crt.sh + subfinder, resolved via dnsx
#   recon.sh asn <ip|asn> [outdir]           # announce-prefixes via RIPEstat -> CIDR list
#   recon.sh certs <root-domain> [outdir]    # raw crt.sh JSON (org names, wildcard, issuers)
#
# Output: JSONL in $outdir (default /work/recon), one record per line:
#   {"kind":"sub","host":..,"ip":..,"src":..}
#   {"kind":"cidr","cidr":..,"asn":"AS..","org":..,"src":"ripestat"}
#   {"kind":"cert","name":..,"issuer":..,"not_after":..}
# Dedup on host/cidr. Every tool's failure is non-fatal: partial results still land.
set -uo pipefail

MODE="${1:?usage: recon.sh domain|asn|certs <value> [outdir]}"
VALUE="${2:?usage: recon.sh domain|asn|certs <value> [outdir]}"
OUT="${3:-/work/recon}"
mkdir -p "$OUT"
TS=$(date +%s)
JSON="$OUT/recon-${MODE}-${TS}.jsonl"
: >"$JSON"

log() { printf '[recon] %s\n' "$*" >&2; }

case "$MODE" in
domain)
  ROOT=$(printf '%s' "$VALUE" | tr 'A-Z' 'a-z')
  TMP=$(mktemp)
  log "crt.sh for $ROOT"
  curl -fsS --max-time 60 "https://crt.sh/?q=%25.$ROOT&output=json" 2>/dev/null |
    python3 -c '
import json,sys
root=sys.argv[1]
seen=set()
for r in json.load(sys.stdin) or []:
    for n in (r.get("name_value") or "").split():
        n=n.strip().lower().lstrip("*.").rstrip(".")
        if n and (n==root or n.endswith("."+root)) and n not in seen:
            seen.add(n); print(n)
' "$ROOT" >>"$TMP" 2>/dev/null || log "crt.sh failed"
  log "subfinder for $ROOT"
  timeout 300 subfinder -d "$ROOT" -silent -all 2>/dev/null >>"$TMP" || log "subfinder failed"
  sort -u "$TMP" -o "$TMP"
  log "$(wc -l <"$TMP" | tr -d ' ') unique names, resolving via dnsx"
  timeout 180 dnsx -silent -a -resp -json -l "$TMP" 2>/dev/null |
    python3 -c '
import json,sys
for line in sys.stdin:
    try: d=json.loads(line)
    except Exception: continue
    for ip in (d.get("a") or []):
        print(json.dumps({"kind":"sub","host":d.get("host"),"ip":ip,"src":"dnsx"}))
' >>"$JSON" 2>/dev/null || log "dnsx failed"
  rm -f "$TMP"
  ;;
asn)
  if printf '%s' "$VALUE" | grep -qiE '^(as)?[0-9]+$'; then
    ASN="AS$(printf '%s' "$VALUE" | grep -oE '[0-9]+')"
    URL="https://stat.ripe.net/data/announced-prefixes/data.json?resource=$ASN"
  else
    ASN=""
    URL="https://stat.ripe.net/data/prefix-overview/data.json?resource=$VALUE"
  fi
  log "ripestat for ${ASN:-$VALUE}"
  curl -fsS --max-time 60 -H 'Accept: application/json' "$URL" 2>/dev/null |
    python3 -c '
import json,sys
d=json.load(sys.stdin).get("data",{})
first=(d.get("asns") or [{}])[0] if "asns" in d else {}
asn=(first.get("asn") and ("AS"+str(first["asn"]))) or (sys.argv[1] or "")
org=first.get("holder") or ""
prefs=[]
if d.get("type")=="prefix" and d.get("resource"):
    prefs.append(d["resource"])
def _l(k):
    v=d.get(k)
    return v if isinstance(v,list) else []
prefs += _l("prefixes") + _l("related_prefixes") + _l("announced")
seen=set()
for p in prefs:
    p=p.get("prefix") if isinstance(p,dict) else p
    if p and p not in seen:
        seen.add(p); print(json.dumps({"kind":"cidr","cidr":p,"asn":asn,"org":org,"src":"ripestat"}))
' "$ASN" >>"$JSON" 2>/dev/null || log "ripestat failed"
  ;;
certs)
  ROOT=$(printf '%s' "$VALUE" | tr 'A-Z' 'a-z')
  log "crt.sh certs for $ROOT"
  curl -fsS --max-time 60 "https://crt.sh/?q=%25.$ROOT&output=json" 2>/dev/null |
    python3 -c '
import json,sys
for r in json.load(sys.stdin) or []:
    print(json.dumps({"kind":"cert","name":r.get("name_value"),"issuer":r.get("issuer_name"),"not_after":r.get("not_after")}))
' >>"$JSON" 2>/dev/null || log "crt.sh failed"
  ;;
*)
  echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

sort -u "$JSON" -o "$JSON"
log "wrote $(wc -l <"$JSON" | tr -d ' ') records to $JSON"
printf '%s\n' "$JSON"
