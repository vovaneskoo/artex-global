# Callback tunnel + OAST (out-of-band) для агентов

Агенты должны видеть echo-back-соединения (SSRF, blind RCE, XXE, beacon'ы после
эксплуатации). Классический interactsh требует выделенный домен; здесь используется
публичный TCP-туннель прямо из bench-VM: цели стучатся на публичный endpoint,
трафик приходит в OAST-приёмник внутри VM, агенты опрашивают результаты по
внутреннему адресу. Всё работает под VPN миссии (outbound-only), без проброса
портов на хост.

## Архитектура

```
target ──HTTP──> bore.pub:PORT ──> bore client (контейнер artex-tunnel)
                                        │ (docker network artex-oast)
                                        v
                            artex-oast (oastd.py, :18080) ──> /data/hits.jsonl
                                        ^
агент (контейнер на той же сети): curl http://artex-oast:18080/hits
```

- Провайдеры: `bore.pub` (основной), `serveo.net` (fallback). `ngrok` требует
  authtoken и не включён по умолчанию. Состояние: `/var/lib/artex-oast/state.json`
  (публичный host:port), хиты: `/var/lib/artex-oast/hits.jsonl` (хранятся между
  перезапусками).
- Endpoints OAST: любой путь/метод записывается как хит; `/health` — health-check;
  `/hits` — последние 500 хитов (JSON).

## Использование (host)

```sh
scripts/callback-tunnel/deploy.sh          # копирует oastd.py/oast.sh в VM
scripts/mission-gate/mission-up.sh ...     # VPN + egress (open-режим пропускает bore.pub)
limactl shell artex-bench -- bash -lc '~/artex-oast/oast.sh up'
limactl shell artex-bench -- bash -lc '~/artex-oast/oast.sh status'
limactl shell artex-bench -- bash -lc '~/artex-oast/oast.sh down'
```

`oast.sh up` проверяет сквозную доставку: self-request через публичный endpoint
должен вернуться в `/health`; иначе ошибка и попытка следующего провайдера.

Для агентов: публичный URL берётся из `state.json` (`http://bore.pub:PORT/<токен>`),
проверка попаданий — `curl http://artex-oast:18080/hits` из любого контейнера
в сети `artex-oast` (подключайте `--network artex-oast` или создавайте task-контейнер
с этой сетью).

## Замечания

- В режиме `closed` перед `oast.sh up` нужно на хосте:
  `mission-add.sh --class callback bore.pub` (и serveo.net при использовании fallback).
- bore.pub выдаёт случайный порт на каждое соединение — при рестарте туннеля URL
  меняется; state.json перезаписывается, агенты должны перечитывать состояние.
- Контейнеры OAST/туннеля не являются границей доверия для root в VM — как и сам
  bench. DNS публичного endpoint идёт через VPN-туннель (класс callback).
- hits.jsonl не ротируется автоматически: `down` + чистка при необходимости.
