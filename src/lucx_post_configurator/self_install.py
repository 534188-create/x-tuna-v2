from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .renderers import GeneratedFile
from .runner import Runner
from .targetfs import TargetFS
from .transaction import create_backup, new_run_id


INSTALLED_COMMAND = "/usr/local/sbin/lucx-post-configure"
REPAIR_COMMAND = "/usr/local/sbin/lucx-sub-repair"
X_TUNA_COMMAND = "/usr/local/sbin/x-tuna"
POST_UPDATE_UNIT = "/etc/systemd/system/lucx-post-update-repair.service"
UPDATE_WORKER_UNIT_PATH = "/etc/systemd/system/lucx-post-update@.service"


REPAIR_WRAPPER = b"""#!/bin/sh
set -eu
case "${1:-}" in
  --check) shift; exec /usr/local/sbin/lucx-post-configure --repair-check "$@" ;;
  --apply) shift; exec /usr/local/sbin/lucx-post-configure --repair-apply "$@" ;;
  "") exec /usr/local/sbin/lucx-post-configure ;;
  *) exec /usr/local/sbin/lucx-post-configure "$@" ;;
esac
"""


X_TUNA_WRAPPER = b"""#!/bin/sh
set -eu
exec /usr/local/sbin/lucx-post-configure --tui "$@"
"""


POST_UPDATE_SERVICE = b"""[Unit]
Description=Repair LucX external routing after a panel update or reboot
After=network-online.target x-ui.service
Wants=network-online.target x-ui.service
ConditionPathExists=/var/lib/lucx-post-configurator/pending-post-update-repair
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lucx-post-configure --repair-apply --yes
TimeoutStartSec=900
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
"""


UPDATE_WORKER_UNIT = b"""[Unit]
Description=LucX detached update job %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lucx-post-configure --update-worker --update-job-id %i
TimeoutStartSec=2700
"""


def _source_path(explicit: str | None = None) -> Path:
    raw = explicit or os.environ.get("LUCX_PC_SELF", "")
    if not raw:
        raise RuntimeError(
            "не найден исходный автономный скрипт; запустите установку TUI из lucx-post-configure.sh"
        )
    path = Path(raw).resolve()
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("исходный автономный скрипт должен быть обычным файлом")
    payload = path.read_bytes()
    if not payload.startswith(b"#!/bin/sh\n") or b"__LUCX_POST_CONFIGURATOR_PAYLOAD__\n" not in payload:
        raise RuntimeError("исходный файл не является автономным lucx-post-configure.sh")
    return path


def install_self(
    fs: TargetFS,
    runner: Runner,
    *,
    source: str | None = None,
) -> dict[str, Any]:
    if not fs.is_live:
        raise RuntimeError("установка TUI разрешена только в живую систему")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("установка TUI требует root")
    source_path = _source_path(source)
    generated = {
        INSTALLED_COMMAND: GeneratedFile(
            source_path.read_bytes(), mode=0o755, component="self-install"
        ),
        REPAIR_COMMAND: GeneratedFile(
            REPAIR_WRAPPER, mode=0o755, component="self-install"
        ),
        X_TUNA_COMMAND: GeneratedFile(
            X_TUNA_WRAPPER, mode=0o755, component="self-install"
        ),
        POST_UPDATE_UNIT: GeneratedFile(
            POST_UPDATE_SERVICE, mode=0o644, component="self-install"
        ),
        UPDATE_WORKER_UNIT_PATH: GeneratedFile(
            UPDATE_WORKER_UNIT, mode=0o644, component="self-install"
        ),
    }
    backup = create_backup(fs, generated, new_run_id() + "-self-install")
    for target, artifact in generated.items():
        fs.atomic_write(target, artifact.content, mode=artifact.mode)
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", "lucx-post-update-repair.service"])
    return {
        "installed": sorted(generated),
        "backup": str(backup.directory),
        "command": INSTALLED_COMMAND,
        "tui_command": X_TUNA_COMMAND,
        "repair_command": REPAIR_COMMAND,
    }
