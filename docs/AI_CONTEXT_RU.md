# Контекст для дальнейшей разработки

Рабочий проект: `lucx-post-configurator`.

## Инварианты

- Не редактировать исходный Naive Caddyfile.
- Не менять клиентов, UUID, subId, пароли и ключи без отдельного recovery-плана.
- Не менять внутренние listener-порты при смене публичного endpoint.
- Reality camouflage SNI сохранять.
- Обычный TLS SNI старой управляемой зоны обновлять.
- TrustTunnel QUIC не публиковать ни одному клиенту.
- qWDTT оставлять без изменений.
- Каждая запись должна иметь backup и rollback.
- Не считать `--validate` доказательством успеха, пока не проверены живые
  listeners и целевые backend-процессы после стабилизации `x-ui`.

## Проверка

```bash
PYTHONPATH=src:tests python3 -m unittest discover -s tests
python3 tools/build_installer.py
```

## Релиз

Перед публикацией запускать secret scan. Нельзя публиковать production IP,
пароли, API keys, UUID, subId, subscription URI, private keys, сертификаты или
production database.

Автор проекта: `tuna`. Лицензия: `AGPL-3.0-only`.
