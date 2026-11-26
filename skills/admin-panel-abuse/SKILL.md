---
name: admin-panel-abuse
description: Abusing admin and monitoring panels as a pivot primitive - discovery fingerprints, default credential matrices, and turning panel access into SSRF, database access, and network maps. Use when recon exposes an admin panel.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Admin panels concentrate credentials, execution, and network knowledge behind one login - check them before exotic exploits.

---

## Admin panel abuse as pivot primitive

Admin panels concentrate credentials, execution, and network knowledge
behind one login — check them BEFORE exotic exploits: the cheapest
foothold is a panel session, not a CVE. ROE: auth ≤3 attempts/min per
account (lockout = DoS-class, core invariants forbid); production = existence
proof only — never write to prod DBs, never create sessions/jobs/builds;
lab destructive=YES per the web-assault SOP.

## a) Discovery — fold into recon
Port fingerprints (nmap -sV + httpx): Grafana :3000 (`GET /api/health`),
Kibana :5601 (`/api/status`), Zabbix web :80/:443 + agent :10051,
Jenkins :8080 (`/login`, X-Jenkins header), Splunk :8000. Subdomain
sweep feeds the same fingerprints:
`ffuf -w <sub-wordlist> -u https://FUZZ.<domain> -mc 200,401,403` —
panel-flavored names first (mon-*, grafana-*, logs-*). Record panel +
version before any login; unknown version → no CVE claim.

## b) Default / weak credential check
Matrix per panel: admin/admin, admin/changeme, admin/password,
admin/<vendor-default>, then org-pattern guesses from creds.md.
≤3 attempts/min per account, then switch — one default hit opens (c)/(d)/(e).

## c) Grafana → SSRF + DB + map
- Datasource abuse = authenticated SSRF AND database access: `GET
  <grafana>/api/datasources` (types, hosts) → run SQL against the backing
  DB via the query API, or reach internal URLs via the proxy endpoint
  `/api/datasources/proxy/<ds-id>/<path>`.
- Service accounts / API keys outlive sessions — lab re-access value;
  production: never mint them.
- Dashboard JSON (`/api/search` → load panels) leaks internal hostnames,
  IPs, datasource names → merge into the network map.

## d) Zabbix → inventory + DB-write patterns
- Host inventory via API = ready-made network map (hosts, IPs, agents).
- Session-forgery PATTERN with DB write access (generic, lab-only):
  read the secret from the server config, INSERT a session row into the
  sessions table, mint the HMAC-signed session cookie with that secret;
  zabbix_server historically runs as root → host-level impact.
  PRODUCTION: never forge/INSERT — feasibility note only.
- API command-execution PATTERN with admin: script.create →
  script.execute on a host. Lab: non-destructive first (`id`);
  production: document only.

## e) Jenkins → Groovy console = RCE
- With creds, `/script` is code execution: `println "id".execute().text` — lab only.
- Credentials-store decryption from the same console: one-liner reads
  encrypted SecretBytes via the credentials API and decrypts → every
  stored DB/service/SSH cred at once.
- Build jobs as exec: add one sh/bat step to an existing job and
  trigger. Production: NEVER create/modify/trigger builds — note only.

## f) Splunk / Kibana
- Splunk :8000: admin defaults; REST search = read primitive over indexed
  logs (creds, hosts, errors in old events); note search-command exec
  feasibility, never fire on production.
- Kibana :5601 / ES :9200: `GET /_cat/indices`, read app + .kibana
  indices; read-only bypass: security-disabled :9200, anonymous roles.

## g) Pivot discipline — three artifacts per panel
Each successful panel login immediately records into the cred graph:
(a) credential source — default / reused / leaked, marked;
(b) execution primitive — datasource / Groovy / script.execute / search —
ranked by impact;
(c) network map delta — hosts, IPs, DBs, indices seen from inside.
Panels are high-value, low-noise pivots: often no exploit needed, only a
stolen/default credential.

## Evidence per attempt
One line in actions.log:
`<panel-url> | <check> | <result> | <next-hop>` (e.g. `<grafana-url> |
default-cred matrix | hit admin/<default> | ds enum`). Panel JSON to artifacts/.

## Rule
Admin panels are credential + execution + map in one place — check them
before exotic exploits.

## Distilled refinement 2026-10-24 (bench runs 1-8)

Grafana/admin-panel playbook:
1) Try vendor defaults (admin/admin) as the FIRST credential attempt - no lockout observed; stay within ROE rate limits (<=3/min/account).
2) Confirm privilege: GET /api/user -> isGrafanaAdmin:true; GET /api/admin/stats for user/datasource counts.
3) Enumerate datasources (/api/datasources) and plugins; a proxy-access datasource is a pivot to the backend DB (see datasource-proxy-sql).
4) Chain order that worked: web-app SQLi foothold -> admin panel default creds -> datasource proxy SQL -> DB exfil.
5) Pre-auth, check /metrics and /swagger for build version and datasource inventory.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2025-31161 — CrushFTP pre-auth захват crushadmin (бывш. CVE-2025-2825)
- Фингерпринт: `/WebInterface/function/` + cookie `CrushAuth=<ts>_<rand>`; уязвимы 10 < 10.8.4 и 11 < 11.3.1.
- Форма: один POST `command=setUserItem` на `/WebInterface/function/` с заголовком `Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/` (без подписи), cookie `currentAuth=31If`, поле `c2f=31If`; перед этим warm-up GET с 20с таймаутом.
- Гейты: не работает за DMZ-proxy инстансом; нужен известный логин (по умолчанию crushadmin).
- Подводные: создаётся постоянный админ-юзер — обязательно удалить; WAF ловит сигнатуру AWS4-HMAC.
- Клинап: `setUserItem` c data_action=remove для тестового аккаунта; проверить logs/session.log.

### CVE-2025-64496 — Open WebUI: «бесплатная модель» как бэкдор
- Фингерпринт: `/api/config` → version <= 0.6.34; в Settings→Connections включён Direct Connections.
- Форма: поднят свой OpenAI-совместимый сервер; при ответе шлём SSE-событие `{type:'execute', code:'<js>'}` — фронт выполняет `new Function(...)` в браузере жертвы; JWT в localStorage (expires_at null).
- Гейт: жертва сама добавила наш endpoint и написала сообщение; дальше крадёный admin-JWT → Functions API → серверный RCE.
- Подводные камни: нужна соц-инженерия; Cato-первоисточник за Incapsula (curl не проходит); ротация WEBUI_SECRET_KEY убивает крадёные токены.
- Клинап: удалить добавленный connection из профиля жертвы, иначе виден в audit.
- Забрать: JWT всех сессий, чаты, RAG-хранилища, ключи моделей; при admin — Python exec на бэкенде.
