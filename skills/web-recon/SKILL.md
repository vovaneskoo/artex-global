---
name: web-recon
description: Web reconnaissance methodology, from passive asset discovery to active content discovery, plus a compact single-service probe playbook and discovery oracles like CSP, robots.txt, JS bundles, and 404 size differentials. Use before attacking any unknown web surface. Discovery and mapping only - once you start exploiting, switch to web-assault (or api-assault for JSON APIs).
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

How to map an unknown web attack surface: the full methodology first, then a tight playbook for a single service, then cheap discovery oracles.

---

## Full reconnaissance methodology

## Passive Recon (zero touch)
1. DNS: `dig AXFR @<ns> <domain>`, `dig <domain> ANY`, subdomain enum (`subfinder -d <domain>`, `amass enum -passive -d <domain>`), certificate transparency (crt.sh).
2. ASN/IP: `whois <ip>`, bgp.he.net, Shodan/Censys historical banners.
3. Leaked creds: breach dumps by domain, GitHub secret scanning (`trufflehog`), pastebin, password reuse candidates.
4. Email/employee enumeration → future spray/phishing candidates (phishing only if explicitly authorized).

## Active Recon — External
1. Full TCP: `nmap -sS -sV -O -p- --min-rate 5000 <target>`
2. UDP: `nmap -sU --top-ports 100 <target>`
3. Web fingerprint: response headers, favicon hash (Shodan `http.favicon.hash`), whatweb, tech stack.
4. Content discovery: `ffuf -w common.txt -u <target>/FUZZ`, API discovery (/swagger, /api-docs, /.well-known/openapi), JS analysis → secrets, internal URLs, endpoints (use `linkfinder`, `secretfinder`).
5. VHost: `ffuf -H "Host: FUZZ.<domain>" -u <target>`

## Active Recon — Internal (post-foothold)
1. Network sweep: alive hosts, ARP cache, route tables.
2. Service sweep: `nmap -sV -p 80,443,445,3389,22,5985,5432,6379,27017,2375,10250 <subnet>`
3. AD recon (domain): `GetADUsers`, SPN enum, shares enumeration (`net view`, SMB null sessions), BloodHound-style graph collection.
4. Credential spray candidates from recon: never full brute force (lockout = availability risk).

## Rules
- Recon is not an attack: execute aggressively, in parallel where possible.
- Move to exploitation on the FIRST valid vector. Do not wait for a complete map.
- Out-of-scope hosts: recon only, never exploit.

---

## Compact single-service probe playbook

For one HTTP service under a tight budget; a uniform JSON 404 makes status codes useless, so filter on body size throughout.

Key invariant: a **uniform JSON 404** means status codes are useless as a signal. Filter ffuf on **body size** (`-fs`) or on a regex that matches the error shape (`-fr '"error"'` / `-fr 'Not Found'`), not on `-fc 404`. GET/HEAD-only means discovery stays on GET; write-vector (upload/SQLi write) testing is largely out of reach on this target for this slice.

## 0. Baseline (must run first — gives the 404 body size used by every ffuf filter)
```bash
T=http://{host}:{port}
curl -sS -o /dev/null -w 'HTTP %{http_code} | %{size_download}B\n' "$T/this-path-does-not-exist-$(date +%s)"
BASE=$(curl -sS "$T/zzz_nonexistent_zzz" | wc -c); echo "404 body bytes=$BASE"
# /, /health headers + tech
curl -sS -D - -o /dev/null "$T/" | tee hdr_root.txt
whatweb -v --color=never "$T/" ; curl -sS -D - -o /dev/null "$T/health"
```
Feed `$BASE` into every ffuf `-fs $BASE` below. Uniform 404 → also try `-fr 'Not Found|error|404'`.

## 1. Content / endpoint discovery (ffuf)
```bash
# directories/files, size-filtered
ffuf -u "$T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
     -fs $BASE -t 10 -rate 50 -mc all -of json -o ffuf_dirs.json
ffuf -u "$T/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
     -fs $BASE -t 10 -rate 50 -mc all -of json -o ffuf_common.json
# extension brute force
ffuf -u "$T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-files.txt \
     -e .json,.txt,.bak,.zip,.yml,.yaml -fs $BASE -t 10 -rate 50 -of json -o ffuf_ext.json
# recursive-ish / link extraction
feroxbuster -u "$T/" -w /usr/share/wordlists/dirb/common.txt -t 10 -k <flags> 2 --extract-links -o ferox.txt
```
Kali wordlist paths: `/usr/share/wordlists/dirb/common.txt`, `/usr/share/wordlists/dirb/big.txt`, `/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt`, `raft-small-files.txt`, `raft-medium-directories.txt`, `common.txt`.

## 2. API spec / documentation discovery
Manual quick sweep (cheapest, one loop) — flag any response whose size differs from `$BASE`:
```bash
for p in swagger swagger.json swagger-ui.html swagger/index.html swagger.yaml \
         openapi.json openapi.yaml api-docs api-docs.json api/swagger.json \
         .well-known/openapi .well-known/openapi.json v2/api-docs v3/api-docs \
         api/docs docs api/graphql graphql graphiql api/v1 api/health redoc \
         .well-known/security.txt .well-known/ai-plugin.json; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' "$T/$p")
  sz=$(curl -sS "$T/$p" | wc -c)
  [ "$sz" != "$T" ] && echo "HIT $p -> $code (${sz}B)"
done
```
ffuf with API wordlists (dedicated — better hit rate than generic dir lists):
```bash
ffuf -u "$T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -fs $BASE -t 10 -rate 50 -of json -o ffuf_api.json
ffuf -u "$T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt \
     -fs $BASE -t 10 -rate 50 -of json -o ffuf_api_wild.json
# swagger-oriented wordlist (Assetnote / kiterunner pack)
ffuf -u "$T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/swagger.txt \
     -fs $BASE -t 10 -rate 50 -of json -o ffuf_swagger.json
# kiterunner (structural API brute — best for hidden REST routes)
kr scan "$T" -w /opt/assetnote/kiterunner/routes-large.kite -x 10
```
API wordlist filenames confirmed in SecLists `Discovery/Web-Content/api/`: `api-endpoints.txt`, `api-endpoints-res.txt`, `api-seen-in-wild.txt`, `objects.txt`, `objects-lowercase.txt`, `actions.txt`, `actions-lowercase.txt`. A `swagger.txt` wordlist also ships with the Assetnote/kiterunner wordlists pack.

## 3. JavaScript analysis (links + secrets)
Grab JS first, then run extractors offline (faster, deterministic):
```bash
# collect .js refs from every discovered HTML/JSON
grep -Eoi 'src="[^"]+\.js[^"]*"|href="[^"]+\.js[^"]*"' body_* | sort -u > js_urls.txt
while read u; do curl -sS -O "$u"; done < js_urls.txt   # or: curl -sS "$T/static/app.js" -o app.js
```
LinkFinder — endpoints + parameters from JS:
```bash
python3 linkfinder.py -i "$T/static/app.js" -o cli
python3 linkfinder.py -i "$T/" -d -o cli            # scan whole domain, recursively
python3 linkfinder.py -i app.js -o results.html     # HTML report
# raw one-liner alternative
python3 linkfinder.py -i app.js -o cli | grep -Eo '(/[a-zA-Z0-9_./-]+)' | sort -u
```
SecretFinder — secrets/keys in JS:
```bash
python3 SecretFinder.py -i "$T/static/app.js" -o cli
python3 SecretFinder.py -i app.js -o cli -g 'API|key|token|secret|password|authorization'
cat app.js | grep -Eoi '(api[_-]?key|apikey|access[_-]?token|secret|bearer|authorization|aws_|firebase|client_secret)[^"]{0,40}' | sort -u
```
Also run regex sweep of all JS for internal hosts/endpoints: `grep -Eoi 'https?://[a-zA-Z0-9._-]+|/[a-z0-9_/.-]+(\?|")' app.js | sort -u`.

## 4. Quick vuln probes (prioritized; ≤2 payload variants per vector)
**Auth/session** — default creds on any login/API; check Set-Cookie flags:
```bash
curl -sS -i "$T/login" -d 'username=admin&<password>' -H 'Content-Type: application/x-www-form-urlencoded'
curl -sS -i "$T/login" -d 'username=admin&<password>
# JWT/unauth API access
curl -sS -i "$T/api/v1/users" ; curl -sS -i -H 'Authorization: Bearer <token>' "$T/api/v1/me"
```
Read `Set-Cookie` in `hdr_root.txt` for `Secure`/`HttpOnly`/`SameSite` and any token value.

**IDOR / forced browsing** — hit numbered/object IDs and admin paths directly:
```bash
for id in 1 2 0 -7777777; do
  curl -sS -o /dev/null -w "id=$id %{http_code} %{size_download}B\n" "$T/api/v1/users/$id"
  curl -sS -o /dev/null -w "obj=$id %{http_code} %{size_download}B\n" "$T/user/$id"
done
for p in admin administrator api/admin dashboard internal debug test dev manage; do
  curl -sS -o /dev/null -w "$p %{http_code} %{size_download}B\n" "$T/$p"
done
```
Compare against `$BASE`: same size ⇒ 404, different size ⇒ real object/route leak. Watch for 200/403 (existence).

**SSRF** (only if any parameter/target param exists — else N/A):
```bash
curl -sS "$T/fetch?url=<value>" 
curl -sS "$T/proxy?url=<value>"
# alternates: url=<value>  url=http://[<ipv6>]/  url=file:///etc/passwd  url=gopher://<ipv4>:6379/_
# GCP: <value> -H 'Metadata-Flavor: Google'
# Azure: <value> -H 'Metadata: true'
# blind: point at your listener and check for a hit
```
Signals: response contains cloud metadata, internal banner, timing delay, or out-of-band callback.

**SSTI** (only on reflected params):
```bash
curl -sS "$T/?name={{7*7}}"     # expect '49' if Jinja2/Twig
curl -sS "$T/?name=${7*7}"      # expect '49' if Freemarker/EL
curl -sS "$T/?name=<%=7*7%>"    # expect '49' if ERB/Node
curl -sS "$T/?name={{7*'7'}}"   # Jinja2/Twig string multiply -> 7777777
# polyglot header probe
curl -sS "$T/" -H 'User-Agent: {{7*7}}${7*7}<%=7*7%>'
```
If any renders `49` (or `7777777`) the template engine evaluated input → escalate to RCE chains only within ROE.

## Prioritized checklist (execution order, ~8 actions)
1. Baseline: 404 body size (`$BASE`) + `curl -I` `/` and `/health`; read Set-Cookie → **action 1**.
2. Tech fingerprint: `whatweb -v`.
3. ffuf directories with `raft-small-directories.txt -fs $BASE`.
4. ffuf API with `api-endpoints.txt` + manual swagger/openapi loop.
5. JS collection + LinkFinder + SecretFinder.
6. Auth: default creds on `/login` + unauth API endpoint probe.
7. IDOR/forced-browsing loop vs `$BASE`.
8. SSRF (if param) then SSTI (if reflected param) — ≤2 payloads each, then stop.
Zero confirmed findings is a valid outcome; record endpoint inventory either way. Every finding needs: dedup vs known routes, adversarial falsification attempt, proof-basis label (executed-live|executed-lab|static-unexecuted), measured impact with denominator.

---

## Oracle: 404 page size differential

Compare 404 response sizes across hosts before trusting any content-discovery result.
A single host can serve multiple 404 templates; differing sizes act as a behavioral oracle that separates real endpoints from misses.
Baseline first:
```
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' hxxps://<host>/<random-nonexistent>
```
Repeat for several random paths to confirm the baseline is stable.
Then probe candidate paths and flag any response whose size or status deviates from the baseline.
Watch for 301/302 on one host versus 404 on another for the same path: the redirecting host is the interesting one.
If sizes are uniform, the oracle is absent and you must rely on status codes and timing instead.
## Rule: establish the 404 baseline per host; a size deviation is a hit, a matching size is noise.

---

## Oracle: CSP header mining

Treat the CSP header as a first-class recon source, not just a hardening check.
Fetch response headers and read the CSP directives that name other origins.

```
curl -sI hxxps://<apex> | grep -i content-security-policy
```

Key directives to mine for hostnames:
- connect-src — where the frontend sends API/XHR traffic (the real backend).
- frame-src — embedded gateways, consoles, checkout flows.
- script-src / form-action — third-party integrations and auth endpoints.

Extract every hostname and probe it directly. A static landing page often has
no framework markers (no __NEXT_DATA__, no _nuxt, no chunk files) yet still
points at a live API on a sibling subdomain.

A host named in CSP that returns NXDOMAIN is still a finding: it confirms
intended architecture and a stale reference.

Decision rule: if /api/* on the apex returns 404 but CSP connect-src names a
backend host, stop probing the apex and pivot to that host. The 404 is expected,
not a dead end.

Cross-check discovered hosts against robots.txt and JS bundles to widen the map.

## Rule
Read CSP connect-src and frame-src before probing any /api path — the real attack surface is usually named there.

---

## Oracle: JS bundle route enumeration

Download the JavaScript bundle and extract application routes before guessing paths.
Single-page apps embed their full route table, API prefixes and asset names in the bundle.
```
curl -s hxxps://<host>/<bundle>.js | grep -oE '"/[a-zA-Z0-9_/-]+"' | sort -u
```
Look for admin, console, billing, checkout, settings and tools routes, plus QR or integration asset names.
Map each extracted route to a live request and note auth behaviour (401 vs 200 vs redirect).
Asset names such as QR images hint at login or integration flows worth auditing next.
If the bundle is minified, search for fetch/axios call sites to recover API base paths.
## Rule: enumerate routes from the JS bundle first; guessing paths without it wastes the pass.

---

## Oracle: robots.txt disclosures

Fetch robots.txt early and read Disallow entries as a disclosure, not as a block.
Operators routinely list private directories in Disallow, which confirms their existence and names them for you.
```
curl -s hxxps://<host>/robots.txt
```
For each Disallow path, request it directly and record status, size and redirect target.
A 200, 401 or 403 on a Disallowed path confirms a live private section; a 404 means the entry is stale.
Also pull sitemap.xml and security.txt referenced from robots.txt.
If robots.txt is absent or returns 404, fall back to CSP and JS bundle for path discovery.
## Rule: every Disallow entry is a candidate path to probe, not a boundary to respect.

---

## Prove a designated target exists before investing

Before spending budget on a designated primary target, prove it exists.
A decommissioned hostname wastes the whole mission if you assume it is live.

Existence-proof checklist:

```
dig +dnssec <host> A
dig <host> AAAA
dig <host> CNAME
```

- Authoritative NXDOMAIN with the aa flag set is strong evidence of non-existence.
- No A/AAAA/CNAME records at all.
- No certificate ever issued in CT logs (crt.sh) for that name.
- Edge returns a deterministic error (e.g. HTTP 530) rather than a live app.

Rule out a sandbox/resolver artifact: query control hosts and confirm they
return normal 200/301/302, and confirm DoH resolution works. If controls pass
and the target still fails, the target is genuinely gone.

When proven non-existent, move the primary designator to the live backend and
keep the allowlist unchanged. Do not expand scope to compensate.

## Rule
Prove a designated target exists with NXDOMAIN + no CT cert + control-host checks before investing any exploitation budget in it.

---

## Distilled lessons

### Negative-result confirmation (distilled lesson)
When a reachability check fails (e.g. curl exit 7, connection refused), CONFIRM
the negative with near-zero extra packets before declaring the target down:
check the local listener view (`ss -ltn`, `/proc/net/tcp` hex ports), one raw
`bash /dev/tcp/<host>/<port>` connect for the exit code, and probe a control
host to rule out sandbox egress or DNS filtering. Capture container topology
facts while you are there (`ip addr`, `ip route`, `/etc/hosts`, PID 1) and
persist one consolidated baseline evidence file. A confirmed negative result is
a finding, not a failure - state what was checked, not just that it failed.

### Bounded weakness triage after recon (distilled lesson)
Once passive recon and a port/header profile exist, run a cheap, non-intrusive
triage WITHOUT redoing captured work - never re-run TLS/port/header passes you
already recorded. Use nuclei with safe/exposure templates only, rate-limited,
plus a read-only review of in-scope forms and inline scripts. Count every
action against the budget and stop at the cap; the triage feeds the attack
plan, it does not replace it.


## Distilled refinement 2026-10-24 (bench runs 1-8)

Unauthenticated recon on Grafana-style apps:
- GET /metrics (Prometheus) and /swagger often need no auth. grep metrics for grafana_build_info (version, goversion, edition) and grafana_datasource_request_in_flight (datasource names/types) to learn the internal DB target before login.
- Probe directory listings (/ftp/, /files/) for backups and secrets.
- Test extension-filter bypass: a blocked .bak may still serve .kdbx/.sql/.zip (403 vs 200). Download each hit and run `file` (e.g. KeePass KDBX).
Defang any URL as hxxps://.
