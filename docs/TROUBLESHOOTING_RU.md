# Диагностика

## Нет доступа к панели или подписке

1. Выполните `sudo x-tuna --validate`.
2. Проверьте `systemctl is-active x-ui haproxy nginx lucx-sub-sidecar`.
3. Проверьте отсутствие pending update marker.
4. Выполните `sudo lucx-sub-repair --check`.
5. Только после просмотра плана используйте `--apply`.

## После обновления LucX не работают маршруты

Проверьте статус worker и repair:

```bash
systemctl status 'lucx-post-update@*'
sudo lucx-sub-repair --check
```

Не восстанавливайте базу вручную до сравнения backup и текущей схемы.

## TrustTunnel

Различайте TCP/443 внешний маршрут и внутренний listener. Ошибка `no application
protocol` обычно означает, что ClientHello попал в decoy вместо TrustTunnel.
Проверьте актуальность matcher, ALPN и наличие только HTTPS/HTTP2-профиля в
публикации. Подробности: `TRUSTTUNNEL_BACKEND_RU.md`.

## Подписки

Проверяйте clean URL через публичный маршрут, а не только внутренний LucX port.
Для Throne отдельно проверяются AWG CIDR и Mieru `traffic-pattern`; qWDTT не
должен присутствовать; AnyTLS должен использовать public Host port.
