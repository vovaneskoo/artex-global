#!/bin/bash
# Mint an API JWT for the bench engine directly from the VM-side secret material:
# sig = HMAC-SHA256(jwt.key, bcrypt-hash), token = HS256(sig, sub=ARTEX).
# Writes the token to stdout. No auth endpoint round-trip needed.
set -euo pipefail
VM="${ARTEX_MISSION_VM:-artex-bench}"
TOK=$(limactl shell "$VM" -- bash -lc 'H=$(sudo docker exec artex-db psql -U postgres -d artex -tAc "select value from settings where key='"'"'auth.password_hash'"'"'"); sudo python3 - "$H" <<PY
import hmac, hashlib, base64, json, time, sys
key=open("/opt/artex/jwt.key","rb").read()
h=sys.argv[1].strip()
sig=hmac.new(key,h.encode(),hashlib.sha256).digest()
b64=lambda d:base64.urlsafe_b64encode(d).rstrip(b"=").decode()
hdr=b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
now=int(time.time())
pl=b64(json.dumps({"sub":"ARTEX","exp":now+7*86400,"iat":now}).encode())
print(hdr+"."+pl+"."+b64(hmac.new(sig,(hdr+"."+pl).encode(),hashlib.sha256).digest()))
PY')
[ -n "$TOK" ] || { echo "no token minted" >&2; exit 1; }
printf '%s' "$TOK"
