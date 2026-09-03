# Документация проекта

Этот каталог содержит нормативное описание `x-tuna v2`. Документы написаны на
русском языке; технические имена, команды, пути, ключи конфигурации и названия
протоколов сохраняются без перевода, чтобы документация оставалась исполняемой.

## Для пользователя

1. [`QUICKSTART_RU.md`](QUICKSTART_RU.md) — запуск и первичная проверка.
2. [`TUI_RU.md`](TUI_RU.md) — справочник интерактивного меню.
3. [`INSTALL_FROM_FILE_RU.md`](INSTALL_FROM_FILE_RU.md) — установка из файла или зеркала.
4. [`CERTIFICATES_RU.md`](CERTIFICATES_RU.md) — проверка и выпуск сертификатов.
5. [`DOMAIN_MIGRATION_RU.md`](DOMAIN_MIGRATION_RU.md) — смена доменов.
6. [`TROUBLESHOOTING_RU.md`](TROUBLESHOOTING_RU.md) — диагностика неисправностей.

## Для разработчика

1. [`ARCHITECTURE.md`](ARCHITECTURE.md) — границы и устройство системы.
2. [`DEVELOPMENT_RU.md`](DEVELOPMENT_RU.md) — рабочий процесс разработки.
3. [`CONFIGURATION_RU.md`](CONFIGURATION_RU.md) — manifest schema и настройки.
4. [`SECURITY_MODEL_RU.md`](SECURITY_MODEL_RU.md) — модель безопасности.
5. [`TESTING_RU.md`](TESTING_RU.md) — уровни тестирования и release gates.
6. [`ACCEPTANCE.md`](ACCEPTANCE.md) — критерии приёмки.
7. [`RELEASE_RU.md`](RELEASE_RU.md) — сборка и публикация релиза.
8. [`CONTRIBUTING_RU.md`](CONTRIBUTING_RU.md) — правила изменения проекта.

## Для интеграционных компонентов

- [`SUBSCRIPTIONS_RU.md`](SUBSCRIPTIONS_RU.md) — subscription-sidecar и форматы ссылок.
- [`TRUSTTUNNEL_BACKEND_RU.md`](TRUSTTUNNEL_BACKEND_RU.md) — TrustTunnel и внешний маршрут.
- [`PROXY_SOURCES_RU.md`](PROXY_SOURCES_RU.md) — источники обновлений и зеркала.
- [`OPERATIONS_RU.md`](OPERATIONS_RU.md) — эксплуатационные процедуры.

## Нормативные документы

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — устройство и границы системы.
- [`CONFIGURATION_RU.md`](CONFIGURATION_RU.md) — manifest schema v3.
- [`SECURITY_MODEL_RU.md`](SECURITY_MODEL_RU.md) — обязательные ограничения.
- [`ACCEPTANCE.md`](ACCEPTANCE.md) — критерии приёмки.
- [`RELEASE_RU.md`](RELEASE_RU.md) — выпуск финального артефакта.

## Проверки перед публикацией

```bash
python3 tools/check_documentation.py
python3 tools/scan_secrets.py
```

Проверки не публикуют найденные значения в отчётах: они выводят только путь,
строку и тип проблемы. Локальные планы, отчёты, snapshots и артефакты с
production-данными исключены из Git через `.gitignore`.

## Нормативность документов

- `ARCHITECTURE.md`, `CONFIGURATION_RU.md` и `SECURITY_MODEL_RU.md` описывают
  обязательные инварианты и не должны противоречить исходному коду.
- `ACCEPTANCE.md` разделяет локально доказанные свойства и проверки на VPS.
- Файлы в `docs/superpowers/` являются историей проектирования и планирования,
  а не заменой актуальной документации. Они не проходят пользовательскую
  проверку русификации и не входят в обязательный путь чтения.
- Производственные отчёты, backup, реальные manifests и секреты в этот каталог
  не помещаются.
