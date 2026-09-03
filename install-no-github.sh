#!/bin/sh
set -eu

# Используйте доверенное HTTPS-зеркало или локальный файл, если GitHub недоступен.
if [ -n "${X_TUNA_INSTALL_FILE:-}" ]; then
    exec sh "$X_TUNA_INSTALL_FILE" "$@"
fi
if [ -z "${X_TUNA_MIRROR_URL:-}" ]; then
    printf '%s\n' 'Задайте X_TUNA_INSTALL_FILE или X_TUNA_MIRROR_URL с доверенным HTTPS-источником.' >&2
    exit 2
fi
case "$X_TUNA_MIRROR_URL" in
    https://*) ;;
    *) printf '%s\n' 'X_TUNA_MIRROR_URL должен использовать HTTPS.' >&2; exit 2 ;;
esac
command -v curl >/dev/null 2>&1 || {
    printf '%s\n' 'Для bootstrap через зеркало требуется curl.' >&2
    exit 2
}
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT HUP INT TERM
curl --fail --location --retry 3 --connect-timeout 15 --max-time 600 \
    "$X_TUNA_MIRROR_URL" -o "$tmp"
if [ "${X_TUNA_INSTALL_SHA256:-}" ]; then
    printf '%s  %s\n' "$X_TUNA_INSTALL_SHA256" "$tmp" | sha256sum -c -
else
    printf '%s\n' 'При использовании зеркала задайте X_TUNA_INSTALL_SHA256 для проверки installer.' >&2
    exit 2
fi
chmod 0700 "$tmp"
exec sh "$tmp" "$@"
