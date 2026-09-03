# Руководство разработчика

## Назначение

Исходный проект разделён на discovery, manifest, planner, renderers,
транзакционный движок, TUI и интеграционные адаптеры. Изменение подсистемы не
должно обходить общий механизм backup и rollback.

## Локальная проверка

```powershell
$env:PYTHONPATH = "src;tests"
python -m compileall -q src tests tools
python -m unittest discover -s tests -v
python tools/build_installer.py
sh -n dist/lucx-post-configure.sh
```

## Правила

- Сначала тест, затем код.
- Все изменения БД должны иметь allowlist и rollback.
- Сначала read-only audit, затем staging, затем backup, затем commit.
- Исходный Naive Caddyfile не редактируется.
- Reality camouflage SNI сохраняется.
- TrustTunnel QUIC не публикуется.
- Production secrets и реальные subscription identifiers запрещены в git.

## Карта исходников

| Модуль | Назначение | Запись на сервер |
|---|---|---|
| `models.py` | manifest и схема | нет |
| `discovery.py` | read-only аудит | нет |
| `questionnaire.py` | цифровая анкета | нет |
| `planner.py` | план изменений | нет |
| `renderers.py` | конфигурации staging | только через engine |
| `transaction.py` | backup/commit/rollback | да, с блокировкой |
| `integrity.py` | hash-защита | нет |
| `engine.py` | оркестрация | да |
| `tui.py` | интерфейс | через engine |
| `updates.py` | detached update-worker | через systemd |

## Порядок изменения

1. Описать изменение и его write-set.
2. Добавить регрессионный тест и получить ожидаемую ошибку.
3. Внести минимальную правку.
4. Добавить проверки ошибки, rollback и redaction.
5. Обновить документацию и критерии приёмки.
6. Запустить полный suite, secret scan и две сборки артефакта.

## Релиз

Проверить SHA-256 автономного файла, прогнать secret scan и только после этого
публиковать изменения в `main`. Автор проекта: `tuna`, лицензия: AGPL-3.0-only.
