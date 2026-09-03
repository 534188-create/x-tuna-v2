# Быстрый старт

Перед началом вручную установите LucX, создайте администратора и inbound-подключения,
а также получите сертификаты. Варианты ниже устанавливают только `x-tuna`.

## Вариант 1: быстрый старт через GitHub

```bash
curl -fsSL https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/SHA256SUMS -o /tmp/x-tuna-SHA256SUMS
curl -fsSL https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/lucx-post-configure.sh -o /tmp/x-tuna.sh
grep 'lucx-post-configure.sh' /tmp/x-tuna-SHA256SUMS | sed 's#  lucx-post-configure.sh#  /tmp/x-tuna.sh#' | sha256sum -c -
chmod 0700 /tmp/x-tuna.sh
sudo /tmp/x-tuna.sh --install-tui
sudo x-tuna
```

## Вариант 2: быстрый старт на российском узле

`gh-proxy.com` является доверенным прокси проекта. Через него загружаются и
checksum, и installer:

```bash
curl -fsSL 'https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/SHA256SUMS' -o /tmp/x-tuna-SHA256SUMS
curl -fsSL 'https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/lucx-post-configure.sh' -o /tmp/x-tuna.sh
grep 'lucx-post-configure.sh' /tmp/x-tuna-SHA256SUMS | sed 's#  lucx-post-configure.sh#  /tmp/x-tuna.sh#' | sha256sum -c -
chmod 0700 /tmp/x-tuna.sh
sudo /tmp/x-tuna.sh --install-tui
sudo x-tuna
```

Для bootstrap-скрипта можно использовать тот же источник:

```bash
curl -fsSL 'https://gh-proxy.com/en/https://raw.githubusercontent.com/534188-create/x-tuna-v2/main/install.sh' -o /tmp/x-tuna-install.sh
X_TUNA_ARTIFACT_URL='https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/lucx-post-configure.sh' \
X_TUNA_SUMS_URL='https://gh-proxy.com/en/https://github.com/534188-create/x-tuna-v2/releases/download/v2.0.1/SHA256SUMS' \
sudo -E sh /tmp/x-tuna-install.sh --install-tui
sudo x-tuna
```

## Вариант 3: прямой запуск с сервера

Загрузите `lucx-post-configure.sh` на сервер через SCP/SFTP, затем выполните:

```bash
chmod 0700 /root/x-tuna.sh
sha256sum /root/x-tuna.sh
sudo /root/x-tuna.sh --install-tui
sudo x-tuna
```

Не запускайте файл, если его SHA-256 не совпадает с опубликованным значением.

## Проверка без изменений

```bash
sudo x-tuna --audit
sudo x-tuna --validate
sudo lucx-sub-repair --check
```
