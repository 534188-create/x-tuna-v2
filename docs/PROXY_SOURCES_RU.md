# Источники и прокси

## Установка x-tuna

Для российских узлов доверенным proxy проекта считается `gh-proxy.com/en`.
Он может использоваться для загрузки `install.sh`, installer и `SHA256SUMS`:

```text
https://gh-proxy.com/en/https://raw.githubusercontent.com/534188-create/x-tuna-v2/main/install.sh
https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/lucx-post-configure.sh
https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/SHA256SUMS
```

Proxy не является проверкой целостности. После загрузки installer всегда
сверяется с `SHA256SUMS`.

Порядок источников обновления:

1. `gh-proxy.com/en`.
2. Прямой GitHub.
3. Системные HTTP/HTTPS/SOCKS5 proxy.
4. Пользовательские GitHub proxy-шаблоны.
5. Собственный HTTPS mirror.
6. Локальный архив.

При обновлении LucX автоматически сначала проверяется `gh-proxy.com/en`. Если
ответ не является корректным архивом LucX, скрипт переходит к следующему источнику.

GitHub proxy-шаблон должен содержать `{url}`, например:

```text
https://proxy.example/download?url={url}
```

Каждый архив проверяется до выполнения: HTTPS, размер, типы файлов, защита от
path traversal, отсутствие symlink/hardlink и наличие ожидаемого `update.sh`.
Не используйте непроверенные публичные proxy для секретных данных.
