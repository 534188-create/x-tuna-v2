# Тестирование

## Локальные проверки

```bash
PYTHONPATH=src:tests python3 -m compileall -q src tests tools
PYTHONPATH=src:tests python3 -m unittest discover -s tests -v
python3 tools/build_installer.py
sh -n dist/lucx-post-configure.sh
```

Сборщик запускается дважды. SHA-256 двух артефактов должен совпадать.

## Уровни тестов

1. Unit-тесты моделей, миграций, discovery и валидаторов.
2. Тесты renderer’ов для HAProxy, Nginx, nftables, systemd и sidecar.
3. Тесты транзакций, backup, rollback и integrity guard.
4. Тесты TUI, цифровой навигации и progress/heartbeat.
5. Тесты форматов подписок AWG, Mieru, AnyTLS, TrustTunnel и qWDTT.
6. Artifact-тест: извлечение single-file payload и запуск его модулей.
7. Shell syntax и secret scan.
8. Linux integration на Debian test VPS.
9. Production-приёмка только после отдельного разрешения.

## Правило доказательств

Успешная компиляция не доказывает работу сети. `--validate` не заменяет
проверку реальных listeners, TLS, подписок, Cloudflare ACL и rollback.
Production-отчёт должен явно разделять локальные и серверные результаты.

## Windows

Windows используется для разработки, но не заменяет Debian. Тесты создания
симлинков могут быть пропущены из-за системных ограничений. Shell-проверки
запускаются через Git Bash, а Linux-specific acceptance выполняется на Debian.
