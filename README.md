# x-tuna: постконфигуратор LucX

`x-tuna` это транзакционный постконфигуратор для сервера с уже установленной
панелью LucX. Проект предназначен для Debian 12 и Debian 13. Автор проекта:
`tuna`. Лицензия: `AGPL-3.0-only`; файлы `LICENSE` и `NOTICE` обязательны для
сохранения при распространении.

Скрипт запускается после ручной установки LucX, создания администратора,
inbound-подключений и подготовки сертификатов. Он обнаруживает фактическую
конфигурацию, предлагает план изменений, создаёт резервную копию, проверяет
сгенерированные файлы и только затем применяет внешнюю интеграционную обвязку.

## Что делает скрипт

- обнаруживает все включённые LucX inbound’ы, их transport, SNI, порты и Host-записи;
- настраивает внешнюю TCP/SNI-обвязку, Nginx, nftables, DNS и logrotate;
- создаёт сайты-заглушки только там, где маршрут доказанно безопасен;
- проверяет и подключает уже существующие сертификаты;
- по отдельному подтверждению настраивает subscription-sidecar;
- исправляет совместимость публикаций для AnyTLS, AWG, Mieru, Throne и NekoBox;
- поддерживает ремонт после обновления LucX;
- запускает обновление LucX в независимом systemd worker;
- создаёт отчёт, backup и автоматически откатывает неудачное применение.

## Что скрипт не делает

- не устанавливает LucX;
- не создаёт и не удаляет клиентов и inbound’ы;
- не меняет credentials, UUID, subId, ключи и пароли;
- не меняет внутренние listener-порты;
- не редактирует исходный Naive Caddyfile;
- не выпускает сертификаты без отдельного подтверждения;
- не очищает существующий firewall;
- не выполняет перезагрузку без отдельного действия пользователя.

После успешной настройки TUI может запустить официальный updater LucX. Перед
обновлением создаются backup состояния и консистентная копия базы, а отдельный
systemd worker выполняет последовательность «обновление → repair» независимо от
панели и SSH-сеанса. Для серверов, с которых GitHub недоступен, предусмотрены
заранее заданное HTTPS-зеркало, прокси и установка из локального файла.

Онлайн-bootstrap проверяет `SHA256SUMS` до запуска. При установке из зеркала
ожидаемый SHA-256 передаётся явно. Нельзя запускать непроверенный файл,
полученный из стороннего источника.

Разработка и release-проверки по умолчанию выполняются локально. Подключение к
удалённому серверу, применение и публикация выполняются только отдельным
явным действием оператора.

## Модель безопасности

- `--audit` и `--plan` не изменяют целевую систему.
- `--apply` показывает точный план и требует подтверждения.
- Каждый управляемый файл резервируется до замены.
- До и после обычного применения сравниваются защищённые поля LucX и содержимое,
  тип, режим и владелец исходного Naive Caddyfile. Любое расхождение прерывает
  транзакцию и запускает откат. Подтверждённый repair после обновления может
  создать новый read-only baseline только после показа изменений; изменившийся
  набор inbound или неподдерживаемая схема требуют нового интерактивного плана.
- Сгенерированные HAProxy, Nginx, nftables и sidecar-конфигурации проверяются.
- Ошибка commit или health-check автоматически восстанавливает управляемые файлы.
- Изменение public URL metadata выполняется только после консистентной SQLite-копии
  и входит в automatic/manual rollback.
- `--rollback` восстанавливает последний успешный запуск.
- Обычный firewall создаёт изолированную nftables table с политикой `accept` и
  закрывает только явно определённые внутренние порты вне loopback. Правила хоста
  не очищаются. Отдельный strict mode использует default-drop, сохраняя все SSH
  ports и listeners протоколов.
- При подтверждённом маршруте TrustTunnel через TCP/443 его внутренний listener
  блокируется извне по TCP и UDP; loopback для HAProxy сохраняется.
- Маршрутизация Unknown-SNI и Nginx `default_server` выключены, пока оператор
  явно их не выберет.
- Sidecar всегда предлагается отдельно и требует подтверждения. Только для
  Throne он преобразует native AWG в полный `wg://` и исправляет percent-escaped
  Base64 Mieru `traffic-pattern`. В raw base64-подписках он меняет только AnyTLS
  authority с внутренним портом на публичные Host domain/port. TrustTunnel
  ограничивается TCP/HTTPS (`h2`), варианты HTTP/3/QUIC исключаются. Credentials,
  имена и qWDTT сохраняются, а Clash/Mihomo проходит без преобразования.
- Отключение sidecar удаляет только три неизменённых файла, ранее созданных этим
  конфигуратором. Изменённый или пользовательский файл блокирует удаление; удаляемые
  файлы входят в тот же rollback backup.
- Если оператор подтверждает, что DNS панели и подписки проксируются Cloudflare,
  их SNI-маршруты и origin-порты принимают только сети Cloudflare. CIDR загружаются
  с официальных IPv4/IPv6 endpoints до commit и обновляются ежедневно; список не
  зашит в installer.
- Панель и подписка имеют независимые внешние порты. При Cloudflare разрешены
  только документированные HTTPS-порты: 443, 2053, 2083, 2087, 2096 и 8443.
  Внутренние порты LucX не изменяются.

## Установка: три варианта

Перед установкой вручную подготовьте LucX, администратора панели, inbound-подключения
и сертификаты. Скрипт устанавливает только постконфигуратор.

### 1. Быстрый старт через GitHub

```bash
curl -fsSL https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.2/SHA256SUMS -o /tmp/x-tuna-SHA256SUMS
curl -fsSL https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.2/lucx-post-configure.sh -o /tmp/x-tuna.sh
grep 'lucx-post-configure.sh' /tmp/x-tuna-SHA256SUMS | sed 's#  lucx-post-configure.sh#  /tmp/x-tuna.sh#' | sha256sum -c -
chmod 0700 /tmp/x-tuna.sh
sudo /tmp/x-tuna.sh --install-tui
sudo x-tuna
```

### 2. Быстрый старт на российском узле

`gh-proxy.com` считается доверенным прокси и используется для загрузки installer
и файла `SHA256SUMS`:

```bash
curl -fsSL 'https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.2/SHA256SUMS' -o /tmp/x-tuna-SHA256SUMS
curl -fsSL 'https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.2/lucx-post-configure.sh' -o /tmp/x-tuna.sh
grep 'lucx-post-configure.sh' /tmp/x-tuna-SHA256SUMS | sed 's#  lucx-post-configure.sh#  /tmp/x-tuna.sh#' | sha256sum -c -
chmod 0700 /tmp/x-tuna.sh
sudo /tmp/x-tuna.sh --install-tui
sudo x-tuna
```

### 3. Прямой запуск с сервера

Загрузите installer на сервер через SCP/SFTP или другой доверенный канал:

```bash
chmod 0700 /root/x-tuna.sh
sha256sum /root/x-tuna.sh
sudo /root/x-tuna.sh --install-tui
sudo x-tuna
```

Не запускайте файл, если его SHA-256 не совпадает со значением из опубликованного
`SHA256SUMS`.

### Проверка без изменений

```bash
sudo x-tuna --audit
sudo x-tuna --validate
sudo lucx-sub-repair --check
```

Подробная инструкция: [`docs/QUICKSTART_RU.md`](docs/QUICKSTART_RU.md).

## Документация

Навигация по документации находится в [`docs/README.md`](docs/README.md). Полный
контекст для продолжения разработки собран в
[`docs/PROJECT_DEVELOPMENT_CONTEXT_RU.md`](docs/PROJECT_DEVELOPMENT_CONTEXT_RU.md).
Для разработчика главным источником являются [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/DEVELOPMENT_RU.md`](docs/DEVELOPMENT_RU.md) и
[`docs/CONFIGURATION_RU.md`](docs/CONFIGURATION_RU.md).

## Разработка

На целевом сервере используются только модули стандартной библиотеки Python
3.11. Локальная проверка и сборка выполняются так:

```console
PYTHONPATH=src:tests python3 -m compileall -q src tests tools
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
python3 tools/build_installer.py
```

Результат сборки: `dist/lucx-post-configure.sh`. Перед публикацией обязательно
проверяются shell-синтаксис, checksum, отсутствие секретов и детерминированность
двух последовательных сборок.

## Обнаружение и поддерживаемые топологии

Каждый включённый inbound LucX обнаруживается независимо. Реализация не привязана
к фиксированному списку или количеству: возможны один VLESS, несколько одинаковых
протоколов, TrustTunnel, AnyTLS и другие типы текущей схемы. Неизвестные параметры
не угадываются: анкета спрашивает способ публикации.
Сначала используются включённые Host rows LucX, затем legacy `share_addr`. Для
Reality используется полный набор SNI из
`realitySettings.serverNames`; также обнаруживаются Host SNI overrides и обычные
TLS server names. Каждый кандидат SNI показывается пронумерованным, есть пункт
«выбрать все», а имена не зашиваются в installer. Диапазоны Mieru и дополнительные
UDP-listener qWDTT сохраняются в плане и allowlist firewall. При прямой публикации
public port должен совпадать с listener LucX: инструмент не изобретает NAT.
Смешанные inbound хранят отдельный direct UDP-порт. После применения `ss` проверяет
ожидаемые TCP- и UDP-listener. L4-семейство определяется transport: mKCP и legacy
QUIC используют UDP, WebSocket, gRPC, HTTPUpgrade, XHTTP и raw streams используют
TCP. Неизвестные future transport только инвентаризируются и не получают общий
порт по догадке.

Дополнительный subscription-sidecar не включается автоматически после обнаружения
протокола. Анкета всегда предлагает его, объясняет поведение AWG только для
Throne и по умолчанию выбирает **нет**. Manifest с включённым sidecar отклоняется
без явного подтверждения. Публичный маршрут также передаёт `/clash/`, `/awg/` и
`/json/` в LucX, поэтому Clash/Mihomo и native AWG downloads остаются доступны.

LucX может сформировать raw AnyTLS URI из внутреннего listener, даже если Host
публикует TCP/443. При явном включении sidecar он читает из SQLite только
несекретные Host/inbound endpoint fields в read-only режиме и меняет только URI
authority на публичный Host port. Сам AnyTLS inbound не редактируется и не
перезапускается.

Текущий импорт Throne может сохранять percent encoding внутри значений, которые
должны быть raw CIDR/Base64. Поэтому sidecar оставляет `/`, `+` и `=` в AWG query
без экранирования, а только для Throne проверяет и декодирует Mieru
`traffic-pattern`. При ошибке преобразования возвращается исходная подписка.

Для Naive на общем TCP/443 расширенный классификатор сначала проверяет, умеет ли
текущая конфигурация LucX Caddy одновременно proxy- и site-delivery. Если умеет,
этот frontend остаётся нетронутым. Иначе allowlist-parser может создать отдельный
управляемый frontend с найденными binary и proxy options. HAProxy направляет
трафик на выбранный frontend. Конфигуратор может изменить только Naive
`share_addr` и включённый Host endpoint на `domain:443`; исходный Caddyfile LucX
никогда не редактируется и не пересоздаётся.

После подтверждения заглушек скрипт собирает **каждый уникальный опубликованный
домен протокола**, но создаёт Nginx-маршрут только там, где безопасность доказана.
TUI показывает для каждого домена один из следующих подтверждённых статусов:

- `direct_tcp_decoy` — browser TCP/443 is free and can be routed to Nginx;
- `udp_with_tcp_decoy` — the VPN remains on UDP while a separate browser TCP
  listener is safe;
- `reality_endpoint_decoy` — the endpoint domain differs from the actual
  Reality camouflage SNI;
- `existing_fallback_observed` — a site is passively observed through the
  protocol's existing fallback; the configurator does not take ownership;
- `naive_caddy_owned_readonly` — Naive/Caddy owns the SNI and remains strictly
  read-only;
- `blocked_sni_collision` or `unsupported_safe` — the VPN listener/SNI has
  priority and no automatic decoy route is installed.

HAProxy владеет выбранным публичным TCP-портом, а Nginx слушает только loopback.
Строгий режим не меняет существующий путь протокола с тем же SNI и сообщает о
коллизиях. Отдельно выбранный расширенный режим обслуживает браузер на домене,
только если metadata LucX доказывает безопасную стратегию: UDP side-site,
Reality endpoint-site, разделение HTTP transport, binary TLS с повторным TLS,
точный TrustTunnel Client Random matcher либо native/managed Naive frontend.
Неизвестная или неоднозначная топология блокируется. Управляемые сайты получают
проверку маркера по public TLS и обоим внутренним путям доставки.

XHTTP поддерживается во всех четырёх режимах Xray (`auto`, `packet-up`,
`stream-up` и `stream-one`), если inbound имеет отдельный путь, отличный от
корня. Только этот путь и его потомки отправляются в Xray; корень домена остаётся
браузерной заглушкой. Путь XHTTP `/` считается блокирующим условием, поскольку
перехватит обычный браузерный запрос. Конфигуратор не меняет путь inbound
автоматически.

## Изолированный TrustTunnel backend

Дополнительный совместимый TrustTunnel backend настраивается отдельно от inbound
LucX. По умолчанию он выключен и принимается только после read-only capability
probe локального pinned binary: TCP, HTTP/2 `CONNECT`, стандартный client URI и
запуск через config file. Backend размещается на динамически выбранном loopback
порту в защищённом systemd unit; public `443` не переключается до настоящего
CONNECT health-check. Обычный binary LucX не считается совместимым автоматически,
поскольку может требовать Client Random prefix.

Проверку можно выполнить без изменения сервера:

```bash
sudo lucx-post-configure --trusttunnel-backend-probe \
  --backend-path /path/to/verified/backend \
  --backend-port 26444
```

Исходные inbound LucX, клиенты, credentials, порты и оригинальный Naive Caddyfile
остаются вне write-set.

## Ограничение origin через Cloudflare

Если записи панели и подписки используют orange cloud, анкета может включить
ограничение origin. Во время `--apply` конфигуратор должен успешно загрузить и
проверить оба официальных списка Cloudflare до любых изменений. HAProxy отклоняет
не-Cloudflare источники только для SNI панели и подписки; VPN SNI на том же TCP
порту остаются публичными. Управляемая nftables table применяет такое же
ограничение к исходным портам панели и подписки LucX.

Ежедневный updater атомарно заменяет проверенный ACL, синхронизирует nftables
sets, проверяет HAProxy и перечитывает его только при изменении списка. Ошибка
загрузки, проверки, nftables или HAProxy сохраняет последний рабочий ACL.

## Смена доменов

После успешного запуска `--reconfigure` загружает последний manifest, повторно
считывает порты inbound/Host и TLS или Reality SNI, спрашивает новые домены панели,
подписки и inbound, а затем проверяет только известные каталоги сертификатов:

- current LucX/manifest certificate paths;
- `/root/.acme.sh` and per-user `.acme.sh` directories;
- `/etc/letsencrypt/live`;
- `/etc/x-ui`.

Выбирается самый долгоживущий сертификат с подходящим ключом, покрывающий все
управляемые домены; wildcard имеет приоритет. Используется тот же engine backup,
validation, health-check и rollback. Синхронизируются домены панели/подписки,
выбранный путь панели и явно управляемые Naive `share_addr`/Host endpoint; другие
поля inbound остаются ручными настройками LucX. Новый inbound требует нового
полного плана. Preflight проверяет покрытие новых имён сертификатами LucX и не
применяет маршрут, который заведомо даст битые ссылки или несовпадение TLS.

Для root-owned сертификатов acme.sh можно автоматически зарегистрировать reload.
Стандартный каталог Certbot deploy-hook поддерживается напрямую. Для пользовательской
установки acme.sh сертификат можно найти и выбрать, но privileged `systemctl`
reload от имени этого пользователя не регистрируется: TUI сообщает требуемую
ручную интеграцию renewal.

TUI сертификатов также может выпустить wildcard плюс точные SAN через Certbot
DNS-01 и Cloudflare plugin. API token вводится без echo, хранится с mode 0600 и
не попадает в аргументы процесса или отчёты. Выпуск и переключение служб на новую
пару требуют двух отдельных подтверждений. После backup базы переключаются только
одобренные certificate path settings LucX и устанавливается multi-service hook.

## TUI, repair и обновления

Запуск скрипта без режима открывает сгруппированный русский TUI с цифровыми
пунктами и подтверждениями; внутренний JSON в интерактивном интерфейсе не печатается:
status/audit, initial setup, domains/routing, decoys, subscriptions/sidecar,
certificates, network protection, post-update repair, LucX update,
backups/rollback, command installation, and a separately confirmed reboot.
Перед подтверждением любого изменения TUI печатает файлы, разрешённые поля базы,
службы, каталог backup, защищённые объекты и заблокированные маршруты. Установка
постоянных команд создаёт:

- `/usr/local/sbin/x-tuna` — primary operator-facing TUI command;
- `/usr/local/sbin/lucx-post-configure` — TUI and all modes;
- `/usr/local/sbin/lucx-sub-repair --check` — read-only drift/topology check;
- `/usr/local/sbin/lucx-sub-repair --apply` — backup, rebuild and health check;
- `lucx-post-update-repair.service` — retries repair after an updater-triggered
  reboot while its pending marker exists.
- `lucx-post-update@.service` — runs the official updater and mandatory repair
  outside the `x-ui.service` cgroup, so a panel restart cannot kill the job.

Главный экран показывает текущие URL панели и подписки, а также активную фазу
обновления. Долгие синхронные действия выводят heartbeat и прошедшее время;
процент показывается только для операций с известным числом фаз.

В TUI есть отдельное действие «создать/синхронизировать все заглушки протоколов»:
после успешной установки недостающие сайты можно добавить без повторной анкеты.

Repair повторно считывает из текущей базы listeners, Host endpoints, transports,
TLS/Reality SNI, port bindings и пути подписок. При добавлении или удалении
включённых inbound он не угадывает изменения и требует новый полный план. Настройки
подключений Mieru и qWDTT никогда не являются целями repair.

Настроенный GitHub proxy является первым источником в автоматическом режиме.
Каждый архив загружается по HTTPS и распаковывается вручную с проверкой пути,
ссылок, типа и размера; на Debian 12 с Python 3.11 намеренно не используется
`TarFile.extractall`. До официального updater создаётся marker repair, поскольку
обновление AWG/kernel может запланировать перезагрузку. Архив и root-only job
descriptor подготавливаются до запуска detached systemd worker. Worker сохраняет
фазы queued, updater, repair, complete и failed, а marker удаляет только после
успешного repair.

## Резервные копии и отчёты

До изменений APT или сети инструмент сохраняет предварительную резервную копию.
После установки пакетов создаётся второй operational baseline для проверки
сгенерированной конфигурации и defaults. File rollback использует pre-APT baseline
и не выдаёт необратимую транзакцию APT за обратимую. В каждой копии есть SQLite
snapshot с режимом 0600 и проверкой целостности. Каждое разрешённое изменение
settings/Host metadata имеет targeted rollback, поэтому клиенты, inbound, порты,
credentials и несвязанные настройки не перезаписываются.

Резервные копии хранятся в `/var/backups/lucx-post-configurator`, а редактированные
JSON и Markdown отчёты — в `/var/lib/lucx-post-configurator/reports`. Пароли,
токены, закрытые материалы, UUID клиентов, идентификаторы подписок, полные URI и
слишком большие payload централизованно редактируются до записи. Файловые журналы
LucX ротируются ежедневно или при достижении 10 MiB; хранятся 14 архивов. Журналы
sidecar ограничены сильнее, успешные запросы подписок не записываются в journal.

Сохранённые manifest схем v1 и v2 мигрируются в памяти в v3. Неизвестная более
новая схема доступна только для отдельного read-only аудита; изменение state
блокируется, а не угадывается.

## Использование на целевом сервере

```console
sudo sh lucx-post-configure.sh
sudo sh lucx-post-configure.sh --audit
sudo sh lucx-post-configure.sh --plan --manifest ./lucx-plan.json
sudo sh lucx-post-configure.sh --apply --manifest ./lucx-plan.json
sudo sh lucx-post-configure.sh --validate
sudo sh lucx-post-configure.sh --reconfigure
sudo sh lucx-post-configure.sh --configure-decoys
sudo sh lucx-post-configure.sh --configure-decoys --decoy-routing-mode extended
sudo sh lucx-post-configure.sh --certificate-check
sudo sh lucx-post-configure.sh --repair-check
sudo sh lucx-post-configure.sh --repair-apply
sudo sh lucx-post-configure.sh --install-tui
sudo sh lucx-post-configure.sh --update-lucx --update-source auto
sudo sh lucx-post-configure.sh --rollback
```

Запуск `--apply` без manifest открывает анкету. Чтобы сначала сохранить и
проверить ответы, используйте `--plan --manifest ./lucx-plan.json`, затем
передайте тот же файл в `--apply`. Секреты и идентификаторы подписок удаляются
из отчётов.
