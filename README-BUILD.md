# Сборка embed-консоли ARTEX на этом хосте (macOS)

Runbook для однобинарной сборки ARTEX со встроенным веб-UI. Все команды и цифры ниже — из реальной серии сборки 2026-10-24 на этом хосте (darwin, arm64). Пути абсолютные; корень проекта — `/Users/volodymyr/projects/artex-dev/src`.

## 1. Что собираем и что получается

Цель — один бинарь `artex`, в который статически встроен фронтенд (Next.js static export). За встраивание отвечает build-тег `embedui`:

- `server/webui_embed.go:18` — директива `//go:embed all:webui/dist` (файл собран только при `-tags embedui`, см. `//go:build embedui` в `server/webui_embed.go:1`). Префикс `all:` обязателен: без него каталог `_next/` с ведущим подчёркиванием в embed не попадает.
- `server/webui_embed.go:24` — `webuiHandler()` раздаёт встроенный SPA: точный файл → `<route>/index.html` → `<route>.html` → фолбэк на корневой `index.html` для клиентской маршрутизации.
- Без `-tags embedui` работает `server/webui_stub.go:14` — сервер на любой запрос страницы отвечает HTTP 404 с корейской заглушкой «이 바이너리에는 프런트엔드가 내장되어 있지 않습니다…». Корейская строка в ответе `GET /` = бинарь собран **без** `embedui`.

Входные данные для embed — каталог `server/webui/dist/`: туда rsync'ом копируется результат `web/out/` после `npm run build:static`. Официальный конвейер — в `build.sh` (фронтенд: строки 114–127, компиляция: строки 215–224).

## 2. Пререквизиты (проверено на хосте 2026-10-24)

| Инструмент | Версия | Как проверял |
|---|---|---|
| node | v25.9.0 (`/opt/homebrew/bin/node`) | `node -v` |
| npm | 11.12.1 | `npm -v` |
| go | в PATH `go1.26.2`, внутри проекта — `go1.26.3` (`GOTOOLCHAIN=auto` по `go.mod`) | `go version` вне и внутри каталога проекта |
| rsync | `/usr/bin/rsync` (системный) | `command -v rsync` |
| docker | 29.4.3 (нужен только для smoke-теста из раздела 6) | `docker --version` |

Замечания к версиям:

- `go.mod` проекта требует `go 1.26.3`, в PATH установлен `1.26.2` (проверено: `grep -m1 '^go ' go.mod` против `go version`). Компиляция серии (шаг 3.4, замер в §4) прошла с `GOTOOLCHAIN=auto`: внутри каталога проекта тулчейн 1.26.3 выбирается автоматически, отдельная установка не потребовалась. Если локальная компиляция упадёт на проверке версии Go — обновите тулчейн или рассчитывайте на `GOTOOLCHAIN=auto`.
- `build.sh:90` требует Go ≥ 1.26 — установленная 1.26.2 под это ограничение формально проходит.
- node 25.9.0 даёт `EBADENGINE`-предупреждения от ряда пакетов (см. раздел 5) — это предупреждения, не ошибка.
- bun/yarn/pnpm на хосте нет — только npm.

## 3. Шаги сборки

Все команды из корня `/Users/volodymyr/projects/artex-dev/src`, если не сказано иное.

### 3.1. Зависимости фронтенда

```bash
cd /Users/volodymyr/projects/artex-dev/src/web
npm ci --prefer-offline --no-audit --no-fund
```

Ожидаемый результат: `added 816 packages in 7s`, exit 0. На этом хосте `npm ci` так просто не проходит — смотрите раздел 5, п. 1 (обход через curl-загрузку тарболов в npm-кэш). `--prefer-offline --no-audit --no-fund` — рабочая форма после обхода; `build.sh:121` использует голый `(cd web && npm ci)`.

### 3.2. Статический экспорт фронтенда

```bash
cd /Users/volodymyr/projects/artex-dev/src/web
npm run build:static
```

Это `NEXT_EXPORT=1 next build` (`web/package.json:8`). Сети не требует. Результат — `web/out/` (~13 МБ, 31/31 статических страниц, включая `/login`, `/setup`, `/system/*`, `/function/*`). Быстрая проверка typecheck без полной сборки: `npx tsc --noEmit` (~5 с).

### 3.3. Синхронизация в embed-каталог

```bash
cd /Users/volodymyr/projects/artex-dev/src
mkdir -p server/webui/dist
rsync -a --delete web/out/ server/webui/dist/
```

Это дословно `build.sh:125-126`. `--delete` обязателен: без него в dist остаются чанки от прошлых сборок (см. раздел 7). После rsync `du -sm server/webui/dist` ≈ 12 МБ.

### 3.4. Компиляция бинаря

Минимальная команда:

```bash
cd /Users/volodymyr/projects/artex-dev/src
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
```

Форма из `build.sh:215-224` (релизная, с версией и обрезкой):

```bash
cd /Users/volodymyr/projects/artex-dev/src
CGO_ENABLED=0 go build \
  -tags embedui \
  -trimpath \
  -ldflags "-s -w -buildid= -X main.version=<ВЕРСИЯ>" \
  -o dist/artex-$(go env GOOS)-$(go env GOARCH)/artex \
  ./cmd/artex
```

Без переменной `ARTEX_BUILD_VERSION` build.sh берёт `git describe --tags --always --dirty`, а вне git-репозитория — строку `dev` (`build.sh:93-98`); в smoke-тестах этой серии бинарь отвечал `"version":"dev"`.

Весь конвейер целиком делает `./build.sh` (одна цель, текущая ОС/арх); `ARTEX_SKIP_FRONTEND=1` пропускает шаги 3.1–3.3 и переиспользует готовый `server/webui/dist` (требует его наличия — `build.sh:114-115`), `ARTEX_SKIP_NPM_CI=1` пропускает только 3.1.

## 4. Замеры этой сборки (2026-10-24)

| Этап | Время | Результат |
|---|---|---|
| `npm ci --prefer-offline --no-audit --no-fund` (после обхода сети, см. п. 5.1) | **7,4 с** | 816 пакетов, exit 0, полностью офлайн |
| `npm run build:static` | **11 с** | 31/31 страниц, `web/out` = **13 МБ** |
| `npx tsc --noEmit` (для сравнения, итерации typecheck) | ~5 с | exit 0 |
| `npm run check:i18n` (прогнан при написании runbook'а) | <1 с | exit 0, паритет 2996 ключей |
| `node_modules` после установки | — | **872 МБ**, 562 верхнеуровневых entry |
| `server/webui/dist` после rsync | — | ~12 МБ (`du -sm`) |
| `CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex` (шаг 3.4) | **1,9 с** | exit 0, бинарь **51 678 258 байт** (тулчейн go1.26.3, тёплый кэш Go — холодная компиляция дольше) |

Не замерено: `rsync` (мгновенный, ~13 МБ). Общее время до успеха с учётом сетевых граблей (см. п. 5.1): от первого `npm ci` (11:45) до успешной установки (13:06) ≈ **1 ч 21 мин**, из них сама установка 7,4 с; до обхода — 6 неудачных npm-попыток + 4 раунда «curl + npm cache add».

## 5. Грабли, встреченные реально, и обходы

1. **`npm ci` падает: сети из node нет.** Исходящие TCP-соединения node убивались с `EBADF`, DNS внутри node периодически вис целиком (`dns.lookup`, `dns.resolve4`), при живом curl/nslookup; TCP на 127.0.0.1 из node работал. Каждая npm-попытка: 14–15 пакетов × 3 ретрая (`ENOTFOUND`/`EBADF`), затем `npm error Exit handler never called!`, exit 1. Вероятная причина — активные сетевые фильтры LuLu 4.3.2 (`com.objective-see.lulu.extension`) и NordVPN Shield (`com.nordvpn.macos.Shield`).
   **Обход, сработавший на этом хосте:** по индексу cacache определить недостающие тарболы (из 921 URL в lock-файле в кэше не было 509), скачать их curl'ом параллельно (~25 с, 0 сбоев; итог +509+15+1), добавить `npm cache add` (addfail=0), проверить по digest (921/921 integrity в кэше), после чего `npm ci --prefer-offline --no-audit --no-fund` проходит exit 0 за 7,4 с полностью офлайн.
2. **root-owned файлы в `~/.npm/_cacache`** — `npm cache verify` даёт `EACCES errno -13`. Рецепт починки: `sudo chown -R 501:20 ~/.npm` (в серии **не выполнялся** — sudo не запускался). Сама установка через обход из п. 1 от этого не страдала.
3. **`EBADENGINE`-предупреждения** при установке: jsdom 30.1.2, vitest 5.0.3, w3c-xmlserializer 6.0.0 и др. требуют node ^22/^24/>=26, установлен 25.9.0. **Не блокируют** — установка завершилась exit 0.
4. **husky prepare печатает «.git can't be found»** — скрипт с `|| true`, безвредно.
5. **Добавление новой локали — не только `src/i18n/config.ts`.** Регистрации в `LOCALES`/`LOCALE_LABELS` (`src/i18n/config.ts:12`) недостаточно: каждый `Record<Locale, ...>` обязан получить новый ключ, иначе TypeScript-фаза `next build` падает. Для `ru` не хватало в двух местах: `src/config/app-config.ts:12` (`META_BY_LOCALE` — title/description вкладки) и `src/i18n/datetime.ts:8` (`DATE_LOCALE` — BCP47-тег, добавлен `"ru-RU"`). Два прогона build:static упали на typecheck (12 с и 11 с) именно из-за этого. Полный список карт для проверки при следующем языке: `src/config/app-config.ts:12`, `src/i18n/intl-runtime-provider.tsx:20`, `src/i18n/datetime.ts:8`, `src/i18n/request.ts:7`, `src/i18n/config.ts:12`.
6. **Быстрая итерация typecheck:** вместо полных сборок гонять `npx tsc --noEmit` (~5 с) — после правки двух карт из п. 5 прошёл с первого раза, повторный `build:static` — сразу успешно.
7. **Ожидаемые сообщения сборки, не блокеры:** warning `Statically exporting a Next.js application via next export disables API routes and middleware` и строка `ƒ Proxy (Middleware)` в таблице роутов — норма для этого проекта (static-only хостинг). Сборка быстрая (~11 с, Next 16.2.9 Turbopack, 17 воркеров): `NODE_OPTIONS=--max-old-space-size` и `rm -rf .next` не понадобились.

## 6. Как проверить результат

Рецепт из приёмки 2026-10-24 (серия 13:53–13:58 того же дня; все проверки ниже в той серии пройдены, команды воспроизводимы как есть). Бинарь в примерах — собранный на шаге 3.4 `./artex`: 51 678 258 байт, русский UI в embed (`LC_ALL=C grep -ac 'Настройки системы' artex` → 1). Ранее на диске лежал бинарь с тем же именем от Oct 22 22:31 (39 348 834 байта), собранный до ru-работ — у него та же проверка даёт 0, и §6.3c/6.3d с ним не пройдут; если приёмка падает на них, бинарь устарел, пересоберите по §3.3–3.4. Имена чанков (`1jexzsn2qdw84.js` и т.п.) инvalidation-зависимы — в своей сборке будут другие, извлекайте их из ответа `/` или grep'ом по `server/webui/dist`.

### 6.1. Одноразовый postgres и запуск бинаря

```bash
# контейнер только свой, порт только на loopback; чужие контейнеры не трогать
docker run --rm -d --name artex-ui-test \
  -p 127.0.0.1:15433:5432 \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=artex \
  postgres:16-alpine

# дождаться готовности (в серии 13:53: accepting connections на 1-й попытке после sleep 3)
docker exec artex-ui-test pg_isready -U postgres
# → /var/run/postgresql:5432 - accepting connections

# запустить бинарь (в отдельном терминале)
ARTEX_PG_DSN='postgres://postgres:test@127.0.0.1:15433/artex?sslmode=disable' \
  ./artex -addr 127.0.0.1:8790
```

В стартовом логе должны быть:

- `ARTEX dev backend listening on 127.0.0.1:8790`
- `[auth] the admin password has not been set yet. Setup token: <SETUP_TOKEN>` — токен нужен для инициализации.

Попутная строка `[traffic] recording proxy on 127.0.0.1:8788 … bind: address already in use` означает лишь, что порт 8788 занят другим процессом хоста (в серии — `limactl`); на проверки ниже это не влияет.

### 6.2. Инициализация администратора

```bash
curl -s -X POST http://127.0.0.1:8790/api/auth/init \
  -H 'Content-Type: application/json' \
  -d '{"password":"artex-test-pass","setup_token":"<SETUP_TOKEN>"}'
# → HTTP 200 {"token":"eyJhbGciOiJIUzI1NiIs..."}   (JWT, далее $TOKEN)

curl -s -X POST http://127.0.0.1:8790/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"ARTEX","password":"artex-test-pass"}'
# → HTTP 200 {"token":"..."}
```

### 6.3. Проверки UI

**(a) `GET /` — HTML приложения, не корейский стаб:**

```bash
curl -s -D - http://127.0.0.1:8790/ -o /tmp/artex-root.html
# → HTTP/1.1 200 OK, Content-Type: text/html; charset=utf-8, ~15894 байт
grep -c '프런트엔드가 내장되어 있지 않습니다' /tmp/artex-root.html   # → 0 (стаба нет)
grep -o '<title>[^<]*</title>' /tmp/artex-root.html
# → <title>ARTEX: Autonomous Penetration Testing Console</title>
grep -o '_next/static/chunks/[^"]*\.js' /tmp/artex-root.html | head   # есть ссылки на чанки
```

**(b) Ассет `_next` отдаётся и непустой:**

```bash
asset=$(curl -s http://127.0.0.1:8790/ | grep -o '/_next/static/chunks/[^"]*\.js' | head -1)
curl -s -o /dev/null -w '%{http_code} bytes=%{size_download} type=%{content_type}\n' \
  "http://127.0.0.1:8790${asset}"
# в серии: 200 bytes=5372 type=text/javascript; charset=utf-8, тело начинается с
# (globalThis.TURBOPACK||(globalThis.TURBOPACK=[])).push([
```

**(c) Русские строки реально в бандле и доезжают до браузера по HTTP:**

```bash
# чанк локалей ищите по самой ru-строке, а не по метке «Русский»: метка живёт в
# маленьком чанке переключателя языков (в серии: 22xpi4po-v5p9.js, 29 800 байт),
# а сообщения ru.json — в крупном чанке локалей (в серии: 0nl8zsd8av6dd.js, 998 962 байта):
chunk=$(grep -rl 'Настройки системы' server/webui/dist/_next/static/chunks/ | head -1 | sed 's|.*static/|/_next/static/|')
curl -s "http://127.0.0.1:8790${chunk}" | grep -cF 'Настройки системы'        # → 1
curl -s "http://127.0.0.1:8790${chunk}" | grep -cF 'Потребление токенов LLM'  # → 1

# метка «Русский» — отдельным grep'ом по чанку переключателя:
switcher=$(grep -rlF 'Русский' server/webui/dist/_next/static/chunks/ | head -1 | sed 's|.*static/|/_next/static/|')
curl -s "http://127.0.0.1:8790${switcher}" | grep -cF 'Русский'               # → 1
```

Проверенные строки ru.json в чанке локалей (в серии все count=1): «Настройки системы», «Блокировка активов», «Условия использования ARTEX и отказ от ответственности», «Статья 1 · Определения и лицензия», «Сменить пароль», «Страница не найдена», «Потребление токенов LLM», «Версия · », «С возвращением. Введите пароль, чтобы продолжить работу с ARTEX.».

Живая браузерная проверка (финальная E2E второй серии 2026-10-24, пройдена): `localStorage` `artex_locale=ru` → живой русский UI, вход выполнен, ошибок рендера нет.

**(d) Язык сервера:**

```bash
# через настройки (нужен JWT из 6.2):
curl -s -X PUT http://127.0.0.1:8790/api/settings \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"output_language":"ru"}'
# → HTTP 200, в ответе "output_language":"ru"; неизвестный язык ("xx") → HTTP 400
curl -s http://127.0.0.1:8790/api/settings -H "Authorization: Bearer $TOKEN" \
  | grep -o '"output_language"[^,}]*'   # → "output_language":"ru"

# либо переменной окружения — второй процесс, стартовый лог по-русски:
ARTEX_LANG=ru ARTEX_PG_DSN='postgres://postgres:test@127.0.0.1:15433/artex?sslmode=disable' \
  ./artex -addr 127.0.0.1:8791
# в логе (в серии): '[config] файл конфигурации: … (не найден · используется только переменная окружения ARTEX_PG_DSN)'
# и '[pg] источник конфигурации базы данных: переменная окружения ARTEX_PG_DSN'
```

Формат поля — `output_language` (`server/server.go:3551`), валидация `NormalizeLanguage` (`server/server.go:3579`), `ru` входит в `SupportedLanguages` (`src/config/config.go:39`).

### 6.4. Проверки API

```bash
curl -s http://127.0.0.1:8790/api/health -H "Authorization: Bearer $TOKEN"  # → 200 {"ok":true,"service":"artex","version":"dev"}
curl -s http://127.0.0.1:8790/api/stats  -H "Authorization: Bearer $TOKEN"  # → 200 {"asset_counts":{},...}
curl -s http://127.0.0.1:8790/api/tasks  -H "Authorization: Bearer $TOKEN"  # → 200 {"active":"","tasks":[]}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8790/api/stats   # → 401 (без токена — авторизация работает)
```

### 6.5. Уборка

```bash
pkill -f 'artex -addr 127.0.0.1:879'    # паттерн под реальный процесс './artex -addr 127.0.0.1:879x'; в серии: после этого pgrep пуст
docker rm -f artex-ui-test              # контейнер был --rm; проверка портов 8790/8791/15433 — LISTEN пуст
```

## 7. Замечания

- **`server/webui/dist` и `web/out` коммитить нельзя** — оба в .gitignore (проверено: `/server/webui/dist/` в `src/.gitignore`, `/out/` в `web/.gitignore`). Артефакт сборки живёт только локально; CI-путь — `ARTEX_SKIP_FRONTEND=1` с заранее подготовленным `dist` (`build.sh:18,114-115`), при отсутствии каталога build.sh падает.
- **Устаревший `dist` = бинарь без свежих текстов.** `go:embed` вбирает то, что лежит в `server/webui/dist` на момент компиляции: если после правок фронтенда не повторить шаги 3.2–3.4, бинарь соберётся со старыми строками (или вовсе с чужим/пустым содержимым — `embed` пустого каталога падает на компиляции). Симптом устаревшего диста в рантайме — русские/новые строки отсутствуют в чанках при живом старому UI. Бинарь без `-tags embedui` — всегда корейский стаб 404 (`server/webui_stub.go:16`).
- **`npm run check:i18n` — гейт паритета локалей** перед сборкой: сверяет наборы ключей всех локалей против `ko.json` (2996 ключей). Прогнан при написании runbook'а и повторён в серии приёмки §6 (2026-10-24): exit 0, <1 с, `en/zh/es/ja/ru` — все совпадают. Скрипт — `web/package.json:18` → `src/scripts/check-i18n-keys.ts`. Падение = рассинхрон `messages/*.json`, фронтенд соберётся с неполным переводом.
- **Валидатор синтаксиса сообщений en↔ru — второй гейт перед сборкой.** Искажённый плейсхолдер (`{count}` стал `(count)`, потерялась скобка, выпал `<b>`) не ловится ни typecheck, ни паритетом ключей — а роняет страницу при рендере. По каждому ключу сверять баланс скобок, множество `{переменных}` (с учётом вложенных ICU `plural`/`select`) и множество `<тегов>`:
  ```bash
  cd web && node <<'EOF'
  // Валидатор синтаксиса сообщений en<->ru: баланс скобок, множество {переменных}
  // (с учётом вложенных ICU plural/select) и <тегов>.
  const F=(o,p="")=>Object.entries(o).flatMap(([k,v])=>typeof v==="object"&&v!==null?F(v,p+k+"."):[[p+k,v]]);
  const e=new Map(F(require("./messages/en.json")));
  const r=new Map(F(require("./messages/ru.json")));
  const vars=s=>{const out=new Set();
    (function walk(str){let d=0,st=-1;
      for(let i=0;i<str.length;i++){
        if(str[i]==="{"){if(d===0)st=i;d++;}
        else if(str[i]==="}"){d--;if(d===0&&st>=0){const inner=str.slice(st+1,i);
          const head=inner.split(",")[0].trim();
          if(/^[A-Za-z0-9_]+$/.test(head))out.add(head);
          walk(inner);st=-1;}if(d<0)d=0;}}
    })(s);return [...out].sort().join(" ");};
  const tags=s=>(s.match(/<\/?[A-Za-z][^>]*>/g)||[]).sort().join(" ");
  const bal=s=>["{}","[]","()"].every(p=>s.split(p[0]).length===s.split(p[1]).length);
  let bad=0;
  for(const [k,v] of e){
    const ru=r.get(k);
    if(ru===undefined){console.log("нет ключа в ru:",k);bad++;continue;}
    if(vars(v)!==vars(ru)){console.log("переменные:",k,"| en:",vars(v),"| ru:",vars(ru));bad++;}
    if(tags(v)!==tags(ru)){console.log("теги:",k,"| en:",tags(v),"| ru:",tags(ru));bad++;}
    if(!bal(v)){console.log("дисбаланс скобок en:",k);bad++;}
    if(!bal(ru)){console.log("дисбаланс скобок ru:",k);bad++;}
  }
  console.log(bad===0?`OK: ${e.size} ключей, расхождений нет`:`расхождений: ${bad}`);
  process.exit(bad===0?0:1);
  EOF
  ```
  Прогнан 2026-10-27 на текущих `messages/en.json`/`ru.json`: `OK: 2996 ключей, расхождений нет`, exit 0. Наивный regex без учёта вложенности ICU даёт ложные срабатывания на `{count, plural, ...}` — поэтому парсер обходит `{...}` рекурсивно.
- **Перевод `ru` покрывает все секции.** Замер 2026-10-27 (однострочник ниже): переведено 2966 из 2996 ключей, секций без перевода — 0. Первая серия 2026-10-24 перевела 353 ключа (~12%, оболочка консоли), вторая серия того же дня добавила ещё 2638 ключей — основные экраны (`taskDetail`, `tasksPage`, `findings`, `llmPage`, `chat` и др.) теперь на русском. Оставшиеся 30 значений байт-в-байт совпадают с `en.json` и остаются латиницей по смыслу — это норма, не недоперевод: типы активов (`IP` ×13, `ICP` ×2, `CIDR`), имена продуктов (`LLM`, `MCP`, `Docker`, `Telegram`, `DingTalk`, `Feishu`, `WeCom`), `'JSON (.json)'`, URL-плейсхолдер `http://your-host:8082/mcp` и чистые шаблоны без слов (`'{shown}/{total}'`, `'{turns}×'`, `'{name} ({count})'`, `' ({size})'` и т.п.). Гейт `check:i18n` неперевод не ловит (проверяет только наборы ключей); фактический охват считать так:
  ```bash
  cd web && node -e 'const F=(o,p="")=>Object.entries(o).flatMap(([k,v])=>typeof v==="object"&&v!==null?F(v,p+k+"."):[[p+k,v]]);const e=F(require("./messages/en.json")),r=new Map(F(require("./messages/ru.json")));console.log("переведено:",e.filter(([k,v])=>r.get(k)!==v).length,"из",e.length)'
  ```
- Временные файлы обхода сети из серии 2026-10-24 (`/tmp/artex-tarballs/`, `/tmp/artex-npm-cache-20261024/`, `/tmp/artex-*.txt`) можно удалить.
