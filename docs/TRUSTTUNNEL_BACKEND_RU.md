# TrustTunnel и совместимый backend

## Две разные схемы

LucX TrustTunnel может требовать Client Random prefix. Отдельный совместимый
backend обязан пройти capability probe и реальный protocol-level health-check.
Обычный TCP connect или `--help` бинарного файла недостаточны.

Проверяются:

1. запуск на loopback-порту;
2. TLS 1.3 и ALPN `h2`;
3. HTTP/2 `CONNECT` с корректными данными;
4. отклонение неправильных credentials;
5. обычный браузерный `GET` на сайт-заглушку;
6. внешний маршрут TCP/443;
7. rollback при ошибке.

Исходный LucX inbound, его клиенты, порты и Naive Caddyfile не изменяются.
Публичный маршрут не переключается до успешного CONNECT health-check.
