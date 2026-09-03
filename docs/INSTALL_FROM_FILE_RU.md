# Вариант 3: прямой запуск с сервера

Этот режим не требует доступа сервера к GitHub. Передавайте только файл,
полученный из доверенного источника, и обязательно сверяйте SHA-256 с
файлом `SHA256SUMS` соответствующего релиза.

```powershell
scp "dist\lucx-post-configure.sh" x-tuna-server:/tmp/x-tuna-install.sh
```

```bash
chmod 0700 /tmp/x-tuna-install.sh
sha256sum /tmp/x-tuna-install.sh
sudo /tmp/x-tuna-install.sh --install-tui
sudo x-tuna
```

Скрипт не принимает секреты через командную строку. Cloudflare API Token и
Global API Key вводятся только скрыто внутри TUI.
