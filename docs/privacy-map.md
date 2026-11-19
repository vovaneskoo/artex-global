# Data-Privacy Map — локальные записи ARTEX

Где какие чувствительные данные лежат, кто их читает, как выгрузить обезличенную копию и как удалить выбранные записи. Документ описывает состояние после privacy-фикса (ветка `artex-ours`): новые sensitive-файлы создаются с правами 0600/0700 от владельца-сервиса, существующие мигрируются chmod'ом на каждом старте без изменения байтов и владельца.

**Политика прав:** директории `0700`, файлы `0600` — полный доступ только у аккаунта, под которым работает сервис (owner). Запись (recording) не отключается, автоматического удаления и обязательного срока хранения нет; удаление — всегда явное действие оператора.

---

## 1. Карта данных

| # | Расположение | Что лежит (raw bodies / keys / headers) | Права (после фикса) | Кто пишет | Кто читает |
|---|--------------|------------------------------------------|---------------------|-----------|------------|
| 1 | PostgreSQL, таблица `llm_records` | Полные тела LLM-запросов/ответов: `request_body` (нормализованный JSON: system, messages, tools), `response_body` (текст + thinking), `raw_request` / `raw_response` — нетронутые wire-боды провайдера (SSE-фреймы, retry-попытки; HTTP-заголовки **не** пишутся) | Права ФС неприменимы; доступ = DSN PostgreSQL | `llmrec.Recorder` (`llmrec/llmrec.go:296`, `record()`), в транзакции операции задачи | UI Records (`GET /api/llm/records`, `GET /api/llm/records/{id}` — `server/commands.go:58`), экспорт архива задачи (`server/task_archives.go:154` пишет копию в пакет архива) |
| 2 | PostgreSQL, `llm_usage` | Только метрики (токены, latency, model, worker) — без тел | — | `llmrec.recordUsage` (`llmrec/llmrec.go:267`) | дашборд `GET /api/tokens/usage` |
| 3 | PostgreSQL, `llm_profiles.api_key` | API-ключи LLM-провайдеров (плюс `api_key_hint` для списков) | — | `POST /api/llm` (`db/config.go:168`) | пул провайдеров при диалапе; в UI список отдаёт только hint |
| 4 | `<data>/traffic/_index/index.sqlite` (+ `-wal`, `-shm`) | Зеркало перехваченного HTTP: URL, хосты, **полные заголовки** (`req_head`/`resp_head`, включая `Authorization`, cookies) и inline-тела до 256 KiB (`traffic/traffic.go:92`); WAL/SHM содержат фрагменты тех же данных | `0600`, директория `_index` `0700`; SQLite-файлы chmod'ятся в `traffic.Open` (`traffic/secure.go:secureSQLiteFiles`) — драйвер создаёт их по umask | traffic-recording proxy (`traffic.record`, `traffic/traffic.go:433`) | UI Traffic (`GET /api/traffic*`, `server/server.go:906-912`), экспорт архива трафика |
| 5 | `<data>/traffic/_blobs/sha256/<xx>/<hash>.bin` | Тела перехваченных запросов/ответов больше 256 KiB (spill; content-addressed) | `0600` в `0700`-бакете (`traffic/traffic.go:546-556`) | `Traffic.spill` | `GET /api/traffic/blob`, восстановление архива |
| 6 | `<data>/traffic/_ca/mitmproxy-ca.pem` | **Приватный ключ MITM CA** (перехват TLS). Рядом публичные `mitmproxy-ca-cert.pem/.cer` | `0600`, директория `_ca` `0700`. Библиотека go-mitmproxy пишет их `os.Create` (0644) — `traffic.Open` дожимает повторным проходом после `NewProxy` (`traffic/traffic.go`, блок после `mproxy.NewProxy`) | go-mitmproxy при первом старте | сам прокси; серт подкладывается в воркеры (`SSL_CERT_FILE`) |
| 7 | `<data>/transcripts/exp<N>-*.jsonl` | Полные транскрипты сессий агентов: пользовательские промпты, ответы модели, содержимое tool-вызовов | Файлы пишутся зависимостью norma (`transcript.Store`) с 0644 — режим создания не настраивается. Граница приватности — директория `transcripts` `0700` (создаётся в `server.NewManager` до первого `NewStore`, `server/localprivacy.go`); уже существующие файлы дожимаются до `0600` на каждом старте | norma transcript.Store (`server/server.go:580`, `server/task_llm.go:562`) | движок задач (compaction-окно), экспорт архива задачи |
| 8 | `<data>/tasks/<id>/uploads`, `<data>/{sessions,drafts}/<id>/uploads` | Файлы, загруженные оператором/гостем в чат | директория `0700` (`server/chatupload.go:93`); файлы внутри — как сохраняет multipart-хендлер, граница та же `0700`-директория | `POST /api/.../upload` | агент задачи (absolute paths передаются в prompt), UI |
| 9 | `<data>/archives/tasks/` | Пакеты холодных архивов задач: копия `llm_records` (stream), transcripts, файлы workspace, traffic-snapshot | `0700`/`0600` (`archiveDirMode`/`archiveFileMode`, `server/task_archive_package.go:23`) | архиватор задач | скачивание архива, восстановление (`ImportArchive` кладёт blobs обратно `0600`/`0700`, `traffic/archive.go:164`) |
| 10 | `<data>/.delete-staging/` | Стейджинг удаления задачи (workspace+transcripts до коммита) | `0700` (`server/manager.go:1638`) | `stageTaskFiles` | только rollback/commit удаления |
| 11 | `<jwt.key>` (корень установки) | Приватный ключ подписи JWT сессий оператора | `0600` (`server/auth.go:85,99`) | первый старт сервера | auth-слой |
| 12 | Логи сервера (stdout/journald) | URL'ы, ошибки, хосты; тела запросов не логируются | права процесса логгера | стандартный логгер | оператор |

`<data>` — корень данных (по умолчанию `./data`, см. `server.NewManager`). Сам корень после фикса `0700`; миграция существующего дерева — `traffic.MigratePermissions` (`traffic/secure.go`) для traffic-дерева и `server.secureLocalData` (`server/localprivacy.go`) для корня/transcripts, на каждом старте, chmod-only.

---

## 2. Как выгрузить обезличенную копию

### 2.1. LLM-записи (PostgreSQL)

Обезличенная копия = убрать wire-тела и thinking, оставить структуру и метрики:

```sql
-- в disposable-копии БД, не в рабочей:
CREATE TABLE llm_records_sanitized AS
SELECT id, created_at, session_id, task_id, worker, model, profile_name,
       latency_ms, input_tokens, output_tokens, cache_read, cache_write,
       status, error,
       NULL::text AS request_body,
       NULL::text AS response_body,
       NULL::text AS raw_request,
       NULL::text AS raw_response
FROM llm_records;
```

Затем `pg_dump -t llm_records_sanitized` (и `llm_usage` целиком — она не содержит тел). `llm_profiles` в выгрузку не включать либо исключить колонку `api_key` (`-t` с `--attribute-column...` недоступен — выбирайте колонки через представление, как выше).

### 2.2. Трафик (локальное дерево)

- Заголовки — основная чувствительная часть. Обезличивание: копия `_index/index.sqlite` + `UPDATE exchange_bodies SET req_head=regexp_replace(req_head,'(?im)^(authorization|cookie|set-cookie|x-api-key):.*$','\1: [REDACTED]')` (и то же для `resp_head`); blobs (`_blobs/`) в копию не копировать либо копировать только нужные хэши.
- Готовый путь для точечной выгрузки: экспорт finding-трафика пишет файл `0600` (`server/finding_traffic_export.go:93`).

### 2.3. Транскрипты

`<data>/transcripts/*.jsonl` — обычный JSONL; обезличивание копии: `sed -E 's/(api[_-]?key|authorization|bearer)[^",}]*/\1:[REDACTED]/Ig' copy.jsonl > sanitized.jsonl` по известным маркерам, выгрузку делать из копии, не из оригинала.

---

## 3. Как удалить выбранные записи (явно, без автодействий)

| Что | Способ |
|-----|-------|
| LLM-записи одной задачи | `DELETE /api/llm/records?task=<id>` (`server/commands.go:134` → `db.DeleteLLMRecords`); удаляет и `raw_request`/`raw_response` |
| Всё принадлежащее задаче (записи + transcripts + workspace + опционально assets/findings/traffic) | удаление задачи: стейджинг `data/tasks/<id>` и `data/transcripts/exp<N>-*` (`server/manager.go:1614`, `stageTaskFiles`), каскад в PG, опции `DeleteLLMRecords`/`DeleteTraffic` |
| Трафик выборочно | `DELETE /api/traffic/hosts` (по хостам), `DELETE /api/traffic` — освобождает страницы через incremental vacuum (`traffic/reclaim`) |
| Весь трафик | `DELETE /api/traffic/all` |
| Холодный архив задачи | удаление stub-архива (`db.DeleteTaskArchiveStub`) + удаление пакета из `data/archives/tasks/` |
| Один spill-blob | удаляется автоматически, когда `blob_refs` опустел (GC по хэшу ссылок) |

Ручной точечный путь (offline): остановить сервис → `sqlite3 <data>/traffic/_index/index.sqlite` → удалить exchange-строки + `blob_refs` → GC подберёт осиротевшие blobs.

---

## 4. Инварианты и проверка

- Новые sensitive-файлы: `0600`/`0700` от UID сервиса — тесты `traffic/secure_test.go`, `traffic/canary_test.go`, `server/localprivacy_test.go`.
- Миграция существующих: chmod-only, байты и владелец не меняются — проверяется контроль-суммами до/после (те же тесты + `shasum` по живому дереву).
- Canary-проверка: синтетический секрет `CANARY-SECRET-*` прогоняется через реальный путь записи (inline-тело в SQLite + spill-blob) и не остаётся ни в одном файле/директории с group/other-битами (`TestCanarySecretNotWorldReadable`). Рабочие секреты при проверках не читаются.
- Что сознательно **не** делается: recording не отключается, авто-удаления и TTL нет, доступ оператора (owner) полный.
