# Документация x-tuna v2

Автор проекта: `tuna`. Лицензия: `AGPL-3.0-only`; уведомление `NOTICE` и
ссылку на оригинальный репозиторий необходимо сохранять в форках.

`x-tuna` это постконфигуратор для уже установленной панели LucX. Он не
устанавливает саму панель и работает через обнаружение текущей конфигурации,
план, резервную копию, staging, проверку и rollback.

## Основные команды

```bash
x-tuna
lucx-post-configure --audit
lucx-post-configure --validate
lucx-sub-repair --check
lucx-sub-repair --apply
```

Интерактивный интерфейс использует только цифровые пункты. Изменяющие действия
показывают назначение, файлы, поля базы, службы, backup и защищённые объекты.

## Безопасность

Клиенты, UUID, subId, пароли, ключи и credentials не являются целями обычной
транзакции. Исходный Naive Caddyfile читается для анализа, но не редактируется.
Неизвестные и неоднозначные маршруты не угадываются: TUI сообщает причину и
способ исправления.

Подробные разделы находятся в `docs/`.

## Порядок чтения

Для пользователя: `QUICKSTART_RU.md`, `TUI_RU.md`, `INSTALL_FROM_FILE_RU.md`.

Для разработчика: `ARCHITECTURE.md`, `DEVELOPMENT_RU.md`,
`CONFIGURATION_RU.md`, `SECURITY_MODEL_RU.md`, `TESTING_RU.md`.

Для эксплуатации: `OPERATIONS_RU.md`, `TROUBLESHOOTING_RU.md`,
`CERTIFICATES_RU.md`, `DOMAIN_MIGRATION_RU.md`.

Для интеграций: `SUBSCRIPTIONS_RU.md`, `TRUSTTUNNEL_BACKEND_RU.md`,
`PROXY_SOURCES_RU.md`.

Для выпуска: `RELEASE_RU.md`, `CONTRIBUTING_RU.md`, `ACCEPTANCE.md`.
