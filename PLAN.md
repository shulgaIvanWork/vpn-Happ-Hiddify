# План: самообновляемая VPN-подписка с автопереключением (аналог Happ)

## 1. Цель

Поднять собственный сервис-агрегатор, который:

1. Парсит открытые списки прокси-конфигов из GitHub (rjsxrd + upstream-источники).
2. Дедуплицирует ноды по `protocol + host + port + credentials`.
3. **Реально проверяет** каждую ноду через локальное ядро `sing-box` HTTP-запросом к `generate_204` — с московского VPS, т.е. в тех же условиях ТСПУ, что и у клиента.
4. Отдаёт подписку по одной HTTPS-ссылке с заголовками, которые рисуют в Happ название, полосу трафика, дату и Telegram.
5. Отдаёт готовый JSON с группой `urltest` — ядро клиента само переключается на живую ноду без разрыва.
6. Обновляется по расписанию (полный скан раз в час, быстрый речек живых — каждые 10 минут).
7. Не остаётся пустым: last-known-good кэш на диске + собственные резервные ноды с приоритетом.

Критерий готовности: **≥ 30 реально работающих нод из Москвы**, подписка открывается в Happ/Hiddify, автопереключение работает, сервис переживает рестарт и падение источников.

---

## 2. Архитектура

```
GitHub raw (rjsxrd bypass-all, servers.txt, ~N upstream)
        │
        ▼
┌─────────────────┐     ┌──────────────────┐     ┌────────────────────┐
│  Sources        │────▶│  Parser + Dedup  │────▶│  Batch Checker      │
│  (fetch/cache)  │     │ vless/vmess/ss/  │     │  sing-box + httpx   │
└─────────────────┘     │ trojan/hy2/tuic  │     │  204 + latency      │
                        └──────────────────┘     └─────────┬──────────┘
                                                           │
                        ┌──────────────────┐               │
                        │  Scoring/History │◀──────────────┘
                        │  EMA latency,    │
                        │  fail count      │
                        └────────┬─────────┘
                                 │ top-N + fallback
                                 ▼
                        ┌──────────────────┐
                        │  Subscriptions   │  /sub/{token}          base64
                        │  Renderer        │  /sub/{token}/singbox  JSON urltest
                        │                  │  /sub/{token}/clash    YAML url-test
                        │                  │  /sub/{token}/xray     Xray JSON
                        └────────┬─────────┘
                                 ▼
                        Happ / Hiddify / v2rayNG / Streisand
```

### Почему батчи, а не процесс на ноду

Один процесс `sing-box` на пачку 50–80 нод: каждая нода — отдельный `mixed` inbound на `127.0.0.1:20000+i`, маршрутизация `inbound → outbound`. Проверка — параллельные HTTP-запросы через `http://127.0.0.1:port` к `https://cp.cloudflare.com/generate_204` (fallback `https://www.gstatic.com/generate_204`). Это даёт 800 нод за ~1–2 минуты на 1–2 vCPU вместо тысяч процессов.

Важно: проверяется **реальный проксированный HTTP-запрос**, а не ping/TCP. Отсекаются ноды, где TCP открыт, но TLS/Reality/SNI блокируется DPI.

---

## 3. Компоненты

### 3.1 Sources
- `sources.yaml`: группы `tier1` (быстрые агрегаторы, опрашиваются каждый цикл) и `tier2` (длинный хвост, раз в сутки).
- Базовый набор:
  - `rjsxrd/githubmirror/bypass/bypass-all.txt` (813 строк, уже протестировано автором)
  - `rjsxrd/source/config/servers.txt` (курируемый список)
  - `rjsxrd/githubmirror/bypass/bypass-1..9.txt`
  - топ-источники из `rjsxrd/source/config/URLS.txt` (не все 200, а отобранные 30–50)
- HTTP: `httpx`, timeout, ограничение размера, retry, ETag/Last-Modified, авто-декод Base64, срезание `#profile-*` заголовков.
- Зеркала GitHub raw (ghproxy и аналоги) — на случай троттлинга/блокировки raw из РФ.
- Статистика по каждому источнику: скачано, валидных, новых (в `/admin/status`).

### 3.2 Parsers
Поддержка:
- `vless://` — TCP/WS/gRPC/HTTPUpgrade, TLS/Reality, `flow`, `sni`, `fp`, `pbk`, `sid`, `alpn`, `packetEncoding`
- `vmess://` (base64 JSON, v2rayN)
- `trojan://` — TLS/WS/gRPC
- `ss://` — SIP002 и legacy base64, методы AEAD
- `hysteria2://` / `hy2://`
- `tuic://` (если попадётся)
- Неподдерживаемое (ssr, xhttp-only, экзотика) — считаем и логируем, не валим цикл.

Нормализация: нижний регистр host, дефолтные порты, декод percent-encoding, удаление fragment/remark. Ключ дедупа: `proto|host|port|uuid_or_password`.

### 3.3 Checker
- Генерация временного конфига `sing-box` на батч.
- Запуск процесса, ожидание готовности (poll TCP-порта), пробы с таймаутом 2.5–3 с.
- Семафор на параллельные пробы, общий timeout на батч.
- Всегда `terminate/kill` + удаление временного конфига (в `finally`).
- Диапазон портов на воркер, чтобы не конфликтовать.
- Метрики: latency, HTTP-код, тип ошибки (timeout / tls / reset / dns).
- Повторная проверка «подозрительных»: 1 ретрай для упавших впервые.
- Ограничение: 1 чекер-джоб одновременно (lock), ручной запуск через API.
- `ulimit nofile=65535` в Docker.

### 3.4 Scoring / state
- `data/live.json` — последний успешный набор (атомарная запись через `.tmp` + `os.replace`).
- `data/history.json` — компактная история: успехи/падения, EMA задержки, последний ok.
- Score = `ema_latency + fail_rate*k`, сортировка. В подписку — топ-N (по умолчанию 35) + fallback.
- Нода, упавшая 3 цикла подряд, уходит в резерв; вернувшаяся — возвращается.
- При старте: если live.json есть — подписка сразу работает, пока идёт первый скан.

### 3.5 Subscription renderer
| Endpoint | Формат | Для кого |
|---|---|---|
| `/sub/{token}` | base64 список URI | Happ, v2rayNG, Streisand, универсальный |
| `/sub/{token}/singbox` | JSON + `urltest` | Hiddify, Karing, sing-box, Streisand |
| `/sub/{token}/xray` | Xray JSON + observatory/balancer | Happ (если поддерживает JSON-профиль) |

Заголовки (одинаковые для всех форматов):
```
Profile-Title: base64:<...>
Profile-Update-Interval: 1
Subscription-Userinfo: upload=0; download=0; total=...; expire=...
Support-Url: https://t.me/...
Profile-Web-Page-Url: https://...   (опционально)
Content-Disposition: attachment; filename="..."
```
Название, лимит «300 GB», дата — декоративные, настраиваются в `.env`.

`urltest` в sing-box JSON:
```json
{"type":"urltest","tag":"auto","outbounds":["node-1","node-2"],
 "url":"https://cp.cloudflare.com/generate_204",
 "interval":"1m","tolerance":50,"idle_timeout":"30m"}
```
Плюс `route.final = "auto"` и `dns` с `strategy: ipv4_only` (меньше проблем на мобильных сетях).

### 3.6 API / управление
- `GET /healthz` — процесс жив.
- `GET /readyz` — есть хотя бы N живых нод.
- `GET /admin/status` (Bearer `ADMIN_TOKEN`) — статистика: источники, батчи, alive, топ, время последнего скана.
- `POST /admin/refresh` — форсировать скан.
- `GET /` — простая страница с инструкцией и QR-кодом подписки (фаза 2, опционально).
- Rate limit на `/sub/*` (in-memory token bucket по IP), constant-time сравнение токена.

### 3.7 Конфигурация
`.env` (pydantic-settings):
```
SUB_TOKEN=...
ADMIN_TOKEN=...
PROFILE_TITLE=...
SUPPORT_URL=...
TOTAL_BYTES=322122547200
EXPIRE_UNIX=...
NODES_IN_SUB=35
BATCH_SIZE=60
CHECK_TIMEOUT=2.5
FULL_SCAN_INTERVAL=3600
LIVE_RECHECK_INTERVAL=600
PORT_BASE=20000
DATA_DIR=/data
```

---

## 4. Структура проекта

```
my-vpn/
├─ PLAN.md
├─ README.md
├─ .env.example
├─ .gitignore
├─ pyproject.toml
├─ requirements.txt
├─ Dockerfile
├─ docker-compose.yml
├─ Caddyfile
├─ sources.yaml
├─ app/
│  ├─ __init__.py
│  ├─ main.py            # FastAPI, lifespan, роуты
│  ├─ config.py          # pydantic-settings
│  ├─ models.py          # Node, CheckResult, SourceStats
│  ├─ sources.py         # загрузка/декод/лимиты
│  ├─ dedup.py
│  ├─ parsers/
│  │  ├─ __init__.py     # parse_uri() dispatcher
│  │  ├─ vless.py
│  │  ├─ vmess.py
│  │  ├─ trojan.py
│  │  ├─ shadowsocks.py
│  │  └─ hysteria2.py
│  ├─ singbox.py         # Node -> outbound, сборка конфига
│  ├─ checker.py         # батчи, процессы, пробы
│  ├─ scoring.py
│  ├─ store.py           # атомарное JSON-хранилище
│  ├─ render.py          # base64/singbox/clash/xray + заголовки
│  ├─ scheduler.py       # asyncio-циклы
│  └─ security.py        # rate limit, токены
├─ tests/
│  ├─ fixtures/          # образцы URI/ответов
│  ├─ test_parsers.py
│  ├─ test_dedup.py
│  ├─ test_singbox_config.py
│  ├─ test_render.py
│  ├─ test_store.py
│  └─ test_api.py
├─ scripts/
│  ├─ download_singbox.ps1   # Windows dev
│  ├─ run_local.ps1
│  └─ deploy_moscow.sh       # rsync + compose
├─ bin/                  # sing-box.exe локально (gitignored)
└─ data/                 # live.json/history.json (gitignored)
```

---

## 5. Этапы

### M0. Каркас (0.5 дня)
- git init, pyproject, зависимости, `.env.example`, `.gitignore`.
- FastAPI с `/healthz`, конфиг, логирование, структура пакетов.
- Тесты-заглушки, `pytest` зелёный.

### M1. Парсеры и дедуп (0.5–1 день)
- Все парсеры + нормализация + дедуп.
- 100% unit-тесты на реальных примерах из `bypass-all.txt`.
- CLI-проверка: `python -m app.cli parse <file>` → сколько нод по протоколам.

### M2. Чекер (1 день)
- `Node → sing-box outbound` для всех протоколов.
- Батч-раннер, readiness, пробы, cleanup, таймауты.
- Локальный прогон на 100 реальных нодах с Windows (sing-box.exe).
- Замер: сколько нод живо из Москвы.

### M3. Подписка и оформление (0.5 дня)
- Все 4 эндпоинта, заголовки, urltest/observatory.
- Проверка в Happ и Hiddify на телефоне (ручной чек-лист в README).
- QR-страница (опционально).

### M4. Устойчивость и планировщик (0.5 дня)
- Полный/быстрый циклы, lock, last-known-good, scoring.
- Источники tier1/tier2, ретраи, зеркала, лимиты.
- Админ-эндпоинты, rate limit.

### M5. Docker и деплой (0.5 дня)
- Dockerfile (multi-stage: sing-box binary + python:3.12-slim).
- compose: aggregator + Caddy (TLS), volume, ulimits, healthcheck, restart.
- Caddyfile под домен.
- `scripts/deploy_moscow.sh`.

### M6. Приёмка (0.5 дня)
- 24-часовой прогон на VPS.
- Отчёт: alive/checked по часам, средний ping, количество переключений.
- Тюнинг batch/timeout/N.

Итого: **~4 рабочих дня** (с проверкой на реальном телефоне).

---

## 6. Локальный запуск (Windows)

```powershell
# 1. виртуальное окружение и зависимости
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. sing-box.exe для проверки
.\scripts\download_singbox.ps1

# 3. тесты
pytest -q

# 4. запуск (реальные проверки нод)
copy .env.example .env
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 5. проверка подписки
curl -H "Accept: */*" http://127.0.0.1:8000/sub/<token>
```

Docker локально:
```powershell
docker compose up --build
```
(На Windows Docker Desktop; Caddy-профиль включается только на сервере.)

---

## 7. Перенос на московский VPS

1. DNS: `A vpn.example.com → <IP VPS>` (Cloudflare, **DNS only**, без оранжевого облака).
2. На сервере: Docker + compose plugin, `ufw allow 80,443`, SSH-ключи.
3. `rsync -av --exclude data --exclude .venv ./ user@vps:/opt/my-vpn/`
4. `.env` на сервере (токены, домен), `docker compose up -d --build`.
5. Caddy сам выпустит Let's Encrypt сертификат.
6. Проверка: `curl -I https://vpn.example.com/sub/<token>` → заголовки; импорт в Happ.
7. `docker compose logs -f aggregator` — первый скан, статистика.
8. Мониторинг: cron/healthcheck, `restart: always`, лог-ротация.

Ресурсы: минимум 1 vCPU / 1 GB, рекомендуется 2 vCPU / 2 GB (пики sing-box на батче 60).

---

## 8. Риски и решения

| Риск | Решение |
|---|---|
| Публичные ноды небезопасны (владелец видит SNI/домены) | Свои резервные ноды в приоритете; предупреждение в README; не для банкинга |
| GitHub raw недоступен/троттлится из РФ | зеркала, кэш, несколько источников, ETag |
| Ноды «живы» с VPS, но мертвы на телефоне | чекер в Москве + запас 30–40% + автопереключение на клиенте |
| DPI режет сам протокол | проверка реальным HTTP, а не TCP; фильтр по типам |
| sing-box падает/зависает | timeout, kill, lock, healthcheck, last-known-good |
| Ссылка утекла | токен в пути, rate limit, возможность смены токена |
| Домен заблокируют | IP-доступ по HTTPS с самоподписанным не подходит; держать запасной домен |
| Happ не умеет JSON-профиль | base64 + короткий список живых; проверить на реальном устройстве |

---

## 9. Что нужно уточнить перед реализацией

1. **Клиент**: Happ, Hiddify или оба? → **оба** (base64 + sing-box JSON + Xray JSON).
2. **Свои ноды**: есть ли собственный сервер/нода? → **нет, только публичные**.
3. **Домен**: есть свободный поддомен? → **да, укажет позже** (в `.env` есть `DOMAIN`).
4. **Приватность**: только для себя или друзьям? → **лично**.
5. **Стек**: Python/FastAPI ок? → **да**.

---

## 10. Границы первой версии

Входит: парсинг, проверка, 3 формата подписки, заголовки, планировщик, Docker, деплой.
Не входит (фаза 2): веб-админка с графиками, биллинг/учёт трафика, multi-tenant, Telegram-бот, own-node provisioning, автоматический выпуск сертификатов без домена.

---

## 11. Фактический статус реализации

Реализовано и проверено локально:

| Пункт | Статус |
|---|---|
| Каркас FastAPI, конфиг, логирование | готово |
| Парсеры vless/vmess/trojan/ss/hysteria2/tuic | готово |
| Строгая валидация (Reality pbk, SS-методы, uTLS fp, плагины, TUIC UUID) | готово |
| Батч-чекер sing-box, реальный HTTP 204 | готово |
| Динамические порты (ОС), проверка всех inbound'ов, retry | готово |
| Скоринг EMA + fail rate, last-known-good | готово |
| base64, sing-box JSON, Xray JSON | готово |
| Заголовки Happ, QR, личная страница | готово |
| Планировщик полный/быстрый, админ-API | готово |
| Docker + Caddy + deploy-скрипт | готово, Docker-сборка не проверена (демон выключен) |
| Unit-тесты | 51 passed |
| Валидация `sing-box check` | OK (все протоколы) |
| Валидация `xray run -test` | OK (537 outbound'ов) |
| Реальный скан | 350 нод → 192 живых, 48.9 с |

Отклонения от первоначального плана:

1. **Clash/YAML не делали** — Hiddify нативно понимает sing-box JSON, а Mihomo не нужен для выбранных клиентов.
2. **`PROBE_CONCURRENCY` снижен с 40 до 20, таймаут поднят до 4 с** — при 30+ одновременных TLS-хендшейках через разные зарубежные прокси канал перегружается, и все пробы получают таймаут (проверено экспериментально: 20 нод → 18 живых, 30 нод при конкурентности 40 → 0 живых).
3. **Динамические порты вместо `PORT_BASE`** — фиксированный диапазон конфликтовал с остатками процессов; ОС выдаёт свободные порты, проверяется, что поднялись все inbound'ы.
4. **Добавлена строгая валидация outbound'ов** — иначе один битый SS-метод или `packetEncoding=none` валит весь батч.
5. **Xray JSON**: legacy-балансировщик как outbound удалён в Xray 26, используется `routing.balancers` + `observatory`; plaintext-VLESS на публичный IP Xray 26 запрещает — такие ноды в Xray-эндпоинт не попадают.

Следующие шаги на сервере:

1. Указать домен, направить A-запись, включить DNS only.
2. `scp .env` + `./scripts/deploy_moscow.sh`.
3. Дождаться первого скана, проверить `/readyz` и импорт в Happ/Hiddify.
4. Через сутки посмотреть статистику: сколько нод стабильно живут, средний ping, частоту переключений.
5. При необходимости — уменьшить `MAX_NODES_PER_SCAN`, добавить свои ноды, подкрутить `MAX_LATENCY_MS`.
