---
name: cloud-container-llm
description: Cloud, container/K8s and AI/LLM attack methodology - cloud posture and credential abuse (AWS/GCP/Azure), container and Kubernetes privilege escalation with host escape (T1611), LLM application attacks (prompt injection, jailbreak, data leakage via garak/promptfoo-style probing). Use when the target runs on cloud infrastructure, when a foothold is inside a container/pod, or when the target exposes an LLM-based service.
---
SCOPE: authorized engagements only. Cloud audit tools (scoutsuite/prowler/
cloudfox) query the PROVIDER's APIs, not the target - run them only when the
mission scope names the authorized cloud endpoints. Credentials are
references/loot-registry pointers, never pasted raw. High-risk acts (pacu,
secretsdump, peirates) stay within the mission ROE.

## Cloud (foothold -> account takeover)

1. Posture audit from an authorized session: scoutsuite/prowler (CSPM
   findings), cloudfox (alias/principal/asset discovery) -> T1526/T1580/T1538.
2. Credential abuse chain (pacu, or manual): enumerate -> privilege graph ->
   escalation paths (iam:* on users/roles, PassRole+lambda trick, metadata
   service SSRF for instance credentials - always check 169.254.169.254 on
   a cloud foothold) -> T1552 Unsecured Credentials.
3. Persistence patterns: new access keys, shadow IAM users, lambda layers -
   document everything for rollback (ROE).

## Container / Kubernetes (inside a pod -> host)

1. Orient: amicontained (what runtime/caps/seccomp we actually have),
   enumerate service account token (/var/run/secrets/kubernetes.io/...),
   env vars for secrets -> T1613 Container and Resource Discovery.
2. K8s attack paths: talk to kube API if network policy allows (token auth ->
   enumerate pods/secrets/roles), SSRF to kubelet/etcd endpoints, exposed
   dashboards; kube-hunter for cluster-wide audit.
3. Escalation to host (T1611 Escape to Host): privileged containers (check
   CapEff), hostPath/hostPID mounts, socket exposure (/var/run/docker.sock),
   kernel exploits if unpatched (document-only unless ROE allows).
   peirates automates K8s attack paths - high-risk, ROE-gated.
4. Post-escape: pivot as a host process, harvest node credentials, move
   laterally per privesc-lateral-persistence skill.

## AI/LLM applications (target is an LLM service)

1. Probe classes (garak/promptfoo automate; manual works too): prompt
   injection (direct and indirect via retrieved content), jailbreaks,
   system-prompt leakage, training-data extraction, unsafe tool/plug-in use,
   insecure output handling (LLM output reaching eval/SQL/shell sinks).
2. Data-exfil oracle: can the model be steered to repeat secrets from its
   context/system prompt? Measure with specific canary strings, not vibes.
3. Mapping honesty: LLM attacks have NO enterprise ATT&CK technique - tag
   findings against the app-layer technique actually abused (T1059 for
   sink execution, T1210 for service exploitation) or leave untagged;
   reference MITRE ATLAS in prose, never invent ATT&CK IDs.
4. Report: each probe class -> verdict with evidence (exact prompt/response
   pair), reproducibility notes, and impact bounded to what was demonstrated.

## Honest limits

- No tool here is auto-authorized: cloud/API tools leave via provider
  endpoints (firewall must be opened for them explicitly), cluster tooling
  only against in-scope hosts, and every destructive cloud act needs ROE.
- Container escape verification on production needs operator approval;
  prefer proving the PATH (capability present + write primitive) over
  executing the escape.

## Эксплойт-фид 2026-11-26 (research-проход #1)

### CVE-2025-1974 — ingress-nginx (IngressNightmare), pre-auth RCE из pod-сети
- Фингерпринт: поды `app.kubernetes.io/name=ingress-nginx`, образ controller < v1.11.5 или = v1.12.0; сервис `ingress-nginx-controller-admission` (443→8443), `POST /admission` без аутентификации.
- Форма запроса: AdmissionReview JSON (`dryRun:true`) с инъекцией в аннотацию `auth-tls-match-cn`: `CN=abc #… ssl_engine ../../../../../../proc/<pid>/fd/<fd>;#`; заранее в контроллер по HTTP заливается `.so` с завышенным `Content-Length` (FD-трюк, CVE-2025-24514).
- Гейт: позиция внутри pod-сети; включённый validating webhook (по умолчанию); существующий TLS-secret (в PoC — `calico-system/node-certs`); gcc для сборки `.so`.
- Подводные камни: брут PID/FD (1–49 × 3–30) вызывает reload'ы NGINX — риск падения контроллера; самоподписанный TLS вебхука (`verify=False`); keep-alive сокет держать открытым, иначе FD закроется.
- Пост-эксплойт: exec от SA контроллера → чтение ВСЕХ Secrets кластера (TLS, registry, токены, cloud-креды) → захват kubelet/API → полный takeover.
- Клинап: `dryRun:true` не оставляет объектов Ingress; закрыть загрузочный сокет (FD исчезнет); проверить audit-логи и перезагрузить контроллер.

### CVE-2025-62593 — Ray Dashboard unauth RCE (KEV 2026-08-17)
- Фингерпринт: :8265, `GET /api/jobs/` → 200 JSON без кредов (401/403/404 = закрыто).
- Запрос: `POST /api/jobs/` с `{"entrypoint":"python -c \"import os;os.system('<cmd>')\"","runtime_env":{}}`; вывод — `GET /api/jobs/<id>/logs`.
- Гейт: сетевая досягаемость 8265; патч 2.52.0 только против browser/DNS-rebind вектора, прямой API-RCE by-design.
- Подводные камни: job остаётся в таблице — чистить `DELETE /api/jobs/<id>`; каждый job ест ресурсы кластера; entrypoint-строка палится в логах.
- Клинап: удалить job+logs, иначе синий-team найдёт строку команды.
- Забрать: IAM-креды env, токен K8s SA, payload'ы чужих job'ов, латералька на workers.

### CVE-2025-31133 — runc maskedPaths escape
- Фингерпринт: `runc --version` < 1.2.8 / < 1.3.3 (GHSA-9493-h29p-rfm2, патч 2025-11-05, вместе с 52565/52881).
- Форма: в rootfs контейнера /dev/null гонко-заменяется симлинком (например, на /proc/sys/kernel/core_pattern) на этапе применения maskedPaths → произвольный bind-mount внутрь.
- Гейты: root в контейнере или право запускать контейнеры со своим rootfs/маунтами; работает и через `docker buildx build` (параллельные шаги).
- Безопасный PoC: skynet-f-nvidia пишет 'pwned' в host core_pattern (без исполнения кода).
- Подводные камни: гонка — повторять; НЕ монтировать /proc/sysrq-trigger (freeze хоста).
- Клинап: `runc kill/delete`, rm rootfs+config.json, восстановить core_pattern оригиналом.

### CVE-2026-102895 — GPUStack auth bypass (KEV, 2026-11-09)
- Фингерпринт: GPUStack < 2.2.0 за same-host nginx (proxy_pass на 127.0.0.1) или API :30080; проба — публичный GET /auth/config.
- Форма: `GET /v2/users` c заголовком `X-GPUStack-Real-IP: 127.0.0.1` (или просто через edge-прокси): 401 → 200+список админов = уязвим.
- Гейты: force_auth_localhost=False (default); header-режим зависит от client_ip_getter.
- Payoff: POST /v2/api-keys → вечный admin-ключ; POST /v2/inference-backends/from-yaml → RCE на воркерах.
- Подводные камни: minted-ключи живут после апгрейда — ревокать; KEV — вероятно, уже под наблюдением.
- Клинап: удалить созданный API-ключ, снять кастомные бэкенды.

### CVE-2026-40217 — LiteLLM sandbox escape (KEV, 2026-11-18)
- Фингерпринт: `GET /model/info` → поле `litellm_version` < 1.83.11; эндпоинт `/guardrails/test_custom_code`.
- Форма: `POST /guardrails/test_custom_code` с JSON `{"code": <payload>}`; payload — либо class-chain `[c for c in ().__class__...`, либо FunctionType/code.replace байткод-обход regex-денилиста.
- Гейт: proxy-admin Bearer в дефолте (post-auth); Docker-образ работает от root → escape = root контейнера.
- Payoff: ключи всех LLM-провайдеров и облаков из env/DB — маршрут к STS.
- Подводные камни: WAF режет __subclasses__; краш прокси = DoS; KEV 2026-11-18.
- Клинап: вернуть guardrail-конфиг, удалить тестовые объекты, ротировать ключи.
