# my-vpn — самообновляемая VPN-подписка с автопереключением

Сервис-агрегатор открытых прокси-конфигов: собирает ноды из GitHub, **реально проверяет** их через локальное ядро `sing-box` с московского VPS и отдаёт одну HTTPS-ссылку для Happ, Hiddify, v2rayNG, Streisand и других клиентов.

- Парсит `vless`, `vmess`, `trojan`, `ss`, `hysteria2`, `tuic`.
- Проверяет не ping/TCP, а настоящий HTTPS-запрос через ноду (`204` от Cloudflare).
- Обновляет список раз в час, живые ноды перепроверяет каждые 10 минут.
- Отдаёт 35 лучших нод + готовый JSON с `urltest` для бесшовного автопереключения.
- Рисует в Happ название, полосу трафика, дату и ссылку на Telegram через HTTP-заголовки.
- Переживает рестарт: last-known-good кэш на диске.

---

## Как это работает

```
GitHub raw (rjsxrd + upstream)
        │
        ▼
  fetch → parse → dedup → batch check (sing-box) → score → top-N
                                                        │
                          ┌─────────────────────────────┤
                          ▼                             ▼
                 /sub/{token}                  /sub/{token}/singbox
                 base64 (Happ)                 JSON urltest (Hiddify)
                 /sub/{token}/xray             Xray JSON (Happ, эксперим.)
```

Чекер запускает один процесс `sing-box` на пачку до 70 нод. Каждая нода — отдельный `mixed` inbound на свободном порту (порты выдаёт ОС), проверка идёт параллельно (20 проб), общий дедлайн — 4 секунды. Мёртвые ноды отсекаются, лучшие по EMA-задержке попадают в подписку.

---

## Быстрый старт (Windows)

```powershell
# 1. зависимости
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# 2. sing-box.exe для проверки нод
.\scripts\download_singbox.ps1

# 3. тесты
pytest -q

# 4. .env и запуск
Copy-Item .env.example .env
# отредактируйте SUB_TOKEN и ADMIN_TOKEN
.\scripts\run_local.ps1
```

Откройте `http://127.0.0.1:8000/p/<SUB_TOKEN>` — там ссылка, QR и список нод.

Первый скан стартует сразу. Пока он идёт, подписка может отдавать `503`; при повторных запусках сразу используется `data/live.json`.

### Проверка конвейера без сервера

```powershell
# сколько нод парсится из файла
python -m app.cli parse "$env:TEMP\bypass-all.txt" --show 10

# реальная проверка 40 нод через sing-box
python -m app.cli check "$env:TEMP\bypass-all.txt" --limit 40

# полный скан: источники → дедуп → проверка → data/live.json
python -m app.cli scan --limit 350 --singbox "bin\sing-box.exe"

# статистика источников
python -m app.cli fetch --tiers 1
```

---

## Эндпоинты

| Путь | Формат | Назначение |
|---|---|---|
| `/sub/{token}` | base64-список URI | Happ, v2rayNG, Streisand, универсальный |
| `/sub/{token}/singbox` | JSON + `urltest` | Hiddify, Karing, sing-box |
| `/sub/{token}/xray` | Xray JSON + balancer | Happ (если импортирует JSON-профиль) |
| `/sub/{token}/info` | JSON | статистика без секретов |
| `/p/{token}` | HTML | личная страница: ссылка, QR, топ нод |
| `/qr/{token}.svg` | SVG | QR-код подписки |
| `/healthz`, `/readyz` | JSON | health/readiness |
| `/admin/status` | JSON | статистика (Bearer `ADMIN_TOKEN`) |
| `/admin/refresh` | POST | форсировать полный скан (Bearer) |

Заголовки подписки:

```
Profile-Title: base64:<...>
Profile-Update-Interval: 1
Subscription-Userinfo: upload=0; download=0; total=322122547200; expire=1893456000
Support-Url: https://t.me/...
```

Полоса трафика и дата — декоративные, реальный учёт трафика не ведётся.

---

## Клиенты

### Happ

1. Добавить профиль → «Из ссылки» → вставить `https://<домен>/sub/<token>`.
2. Обновление раз в час придёт автоматически.
3. Для автопереключения: попробуйте `/sub/<token>/xray` (Xray JSON с `observatory` + `balancer`). Конфиг проверен ядром Xray 26.

Если конкретная версия Happ не принимает JSON, используйте base64-ссылку: список уже отсортирован по скорости и содержит только живые ноды.

### Hiddify / sing-box / Karing

Добавить подписку → `https://<домен>/sub/<token>/singbox`. Внутри группа `urltest` (`auto`) с интервалом проверки 1 минута и `tolerance: 50ms`; трафик сам переключается на живую быструю ноду.

### v2rayNG / Streisand

Обычная base64-ссылка `/sub/<token>`.

---

## Настройки `.env`

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `SUB_TOKEN` | `change-me-...` | секрет в ссылке подписки |
| `ADMIN_TOKEN` | `change-me-...` | Bearer для `/admin/*` |
| `PROFILE_TITLE` | `Moscow Auto-VPN` | название профиля |
| `SUPPORT_URL` | — | ссылка на Telegram |
| `TOTAL_BYTES` | 300 GB | декоративный лимит |
| `EXPIRE_UNIX` | 2030-01-01 | декоративная дата |
| `NODES_IN_SUB` | 35 | сколько нод отдавать |
| `MAX_NODES_PER_SUBNET` | 8 | не более N нод из одной подсети/домена |
| `BATCH_SIZE` | 70 | нод в одном процессе sing-box |
| `CHECK_TIMEOUT` | 4 | таймаут одной пробы, сек |
| `PROBE_CONCURRENCY` | 20 | параллельных проб |
| `PORT_BASE` | 20000 | начало диапазона портов inbound'ов |
| `PORT_BAND` | 3000 | ширина полосы портов на один скан |
| `MAX_NODES_PER_SCAN` | 1500 | лимит нод за скан |
| `MAX_LATENCY_MS` | 8000 | отсечка медленных нод |
| `FULL_SCAN_INTERVAL` | 3600 | полный скан, сек |
| `LIVE_RECHECK_INTERVAL` | 600 | быстрый речек, сек |
| `DOMAIN` | — | домен для Caddy |
| `BIND_ADDR` | `127.0.0.1` | куда публиковать API в Docker |

Сгенерировать токен:

```powershell
python -c "import secrets;print(secrets.token_urlsafe(32))"
```

> Если `PROBE_CONCURRENCY` поднять выше 20–25, на домашнем канале начнутся массовые таймауты: 30 одновременных TLS-хендшейков через разные зарубежные прокси перегружают канал. На московском VPS можно попробовать 25–30, но сначала замерьте.

---

## Деплой на московский VPS

### 1. DNS

- `A vpn.example.com → <IP VPS>`.
- В Cloudflare **DNS only** (серое облако), иначе запросы пойдут через зарубежный CDN и checker/клиент увидят не тот путь.
- Подождите обновления DNS.

### 2. Сервер

```bash
apt update && apt install -y docker.io docker-compose-plugin rsync ufw
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Минимум: 1 vCPU / 1 GB. Рекомендуется 2 vCPU / 2 GB.

### 3. Загрузка и запуск

С локальной машины (Git Bash / WSL / Linux):

```bash
scp .env.example root@<IP>:/opt/my-vpn/.env
# на сервере отредактируйте /opt/my-vpn/.env: DOMAIN, SUB_TOKEN, ADMIN_TOKEN
bash scripts/deploy_moscow.sh root@<IP>
```

Скрипт копирует проект (без `.env`, `data`, `.venv`), создаёт `data`, выставляет владельца `10001` и запускает `docker compose --profile edge up -d --build`.

Проверка:

```bash
curl -I https://vpn.example.com/sub/<TOKEN>
curl https://vpn.example.com/readyz
docker compose logs -f aggregator
```

Первый скан занимает 1–7 минут в зависимости от `MAX_NODES_PER_SCAN` и качества канала.

### 4. Обновление

```bash
bash scripts/deploy_moscow.sh root@<IP>
```

---

## Эксплуатация

```bash
# логи
docker compose logs -f aggregator

# статус
curl -H "Authorization: Bearer $ADMIN_TOKEN" https://vpn.example.com/admin/status

# форсировать скан
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" https://vpn.example.com/admin/refresh

# перезапуск
docker compose restart aggregator

# бэкап
tar czf backup.tgz data/
```

Файлы состояния:

- `data/live.json` — последний удачный набор нод;
- `data/history.json` — история проверок и EMA-задержки.

Ротация токена: изменить `SUB_TOKEN` в `.env` → `docker compose up -d`.

---

## Тюнинг

| Симптом | Что менять |
|---|---|
| Мало живых нод | `MAX_NODES_PER_SCAN` ↑, `MAX_LATENCY_MS` ↑, добавить источники |
| Долгий скан | `MAX_NODES_PER_SCAN` ↓, `BATCH_SIZE` ↑, `CHECK_TIMEOUT` ↓ |
| Массовые таймауты | `PROBE_CONCURRENCY` ↓ до 10–15 |
| Много мусора в подписке | `MAX_LATENCY_MS` ↓ до 3000–5000 |
| Источники часто падают | `sources.yaml`, `mirrors`, tier 1/2 |

---

## Диагностика

**0 живых нод**

1. `python -m app.cli scan --limit 50` — видно, парсятся ли ноды и сколько живых.
2. `python -m app.cli check <file> --limit 20` — проверка конкретного файла.
3. Проверьте, что `sing-box` запускается: `bin\sing-box.exe version`.
4. Если все пробы — `timeout`, уменьшите `PROBE_CONCURRENCY` и увеличьте `CHECK_TIMEOUT`.

**`sing-box rejected config`**

Запустите `python scripts/diagnose.py <file> 200` — скрипт проверит каждый outbound по отдельности и покажет причину.

**GitHub raw недоступен**

Добавьте в `sources.yaml`:

```yaml
mirrors:
  - https://ghproxy.net
```

(или свой mirror). При недоступности источника используется кэш `data/live.json`.

**Caddy не выпускает сертификат**

- DNS A-запись уже указывает на VPS?
- Порты 80/443 открыты?
- Cloudflare в режиме DNS only?
- `docker compose --profile edge ps` — Caddy запущен?

**Docker**

На Windows должен быть запущен Docker Desktop. В текущем окружении демон может быть выключен — тогда `docker compose` не работает, но локальный запуск через Python работает.

---

## Безопасность и ограничения

- Публичные ноды поднимают неизвестные люди. Они видят SNI/домены, могут подменять незашифрованный HTTP. **Не использовать для банкинга, госуслуг и приватных ключей.**
- Для чувствительных задач держите собственную ноду и добавьте её в начало списка.
- Ссылка подписки = секрет. Не публикуйте её; при утечке смените `SUB_TOKEN`.
- Access-логи Caddy и uvicorn отключены, чтобы токен не попадал в логи.
- Сервис не учитывает реальный трафик: полоса в Happ декоративная.
- В v1 нет Clash/YAML-эндпоинта, веб-админки и multi-user.
- Проверка идёт с московского VPS: ноды, доступные из Европы, но заблокированные ТСПУ, будут отсеяны — это и есть цель.
- Ответственность за использование публичных прокси и соблюдение законодательства — на владельце сервиса.

---

## Структура

```
app/
  main.py        FastAPI, эндпоинты, lifespan
  config.py      настройки из .env
  sources.py     загрузка источников, base64, лимиты
  parsers/       vless, vmess, trojan, ss, hysteria2, tuic
  singbox.py     Node → outbound, check-конфиг, urltest
  checker.py     батчи, динамические порты, raw-socket пробы
  scoring.py     EMA-задержка, fail rate
  scheduler.py   полный скан / быстрый речек
  render.py      base64-подписка, заголовки
  xray.py        Xray JSON + observatory/balancer
  store.py       атомарное JSON-хранилище
  security.py    rate limit, сравнение токенов
tests/           51 unit-тест
scripts/         установка sing-box, локальный запуск, деплой, диагностика
```

---

## Проверено в этой сборке

- `pytest -q` — 56 тестов.
- `sing-box check` — конфиг подписки со всеми протоколами валиден.
- `xray run -test` — Xray JSON со всеми протоколами валиден (537 outbound'ов).
- Реальный скан: 700 нод → 233 живых, 105.6 с (включая загрузку источников).
- Эндпоинты `/sub`, `/sub/.../singbox`, `/sub/.../xray`, `/p`, `/qr`, `/admin/status` отвечают корректно.
