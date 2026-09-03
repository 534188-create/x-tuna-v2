from __future__ import annotations

import copy
import getpass
from collections.abc import Callable

from .certificate_manager import (
    certificate_status,
    certificate_status_for_manifest,
    issue_certbot_cloudflare,
)
from .engine import Engine
from .models import Audit
from .planner import format_plan
from .progress import ProgressDisplay
from .questionnaire import (
    build_manifest_interactively,
    configure_decoy_routing_mode,
    configure_protocol_decoys_interactively,
    reconfigure_domains_interactively,
    migrate_domain_zone,
    refresh_manifest_from_audit,
)
from .repair import format_repair_check, repair_apply, repair_check
from .self_install import install_self
from .status import coverage_summary, domain_status_rows, mutation_preview
from .transaction import BACKUP_ROOT, load_state
from .updates import update_lucx, update_source_status
from .trusttunnel_backend import probe_backend


InputFn = Callable[[str], str]
OutputFn = Callable[[str], None]


def _run_progress(title: str, output_fn: OutputFn, operation: Callable[[], object]) -> object:
    return ProgressDisplay(output_fn, title).run(operation)


def _validate_installed(engine: Engine, output_fn: OutputFn) -> object:
    return _run_progress(
        "Проверка управляемой конфигурации",
        output_fn,
        engine.validate_installed,
    )


def _yes_no(prompt: str, input_fn: InputFn, output_fn: OutputFn) -> bool:
    output_fn(prompt)
    output_fn("  1. Да")
    output_fn("  2. Нет (по умолчанию)")
    while True:
        try:
            value = input_fn("Номер варианта [2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return False
        if value in {"", "2"}:
            return False
        if value == "1":
            return True
        output_fn("Введите 1 или 2.")


def _show_list(label: str, values: object, output_fn: OutputFn) -> bool:
    items = list(values or []) if isinstance(values, (list, tuple, set)) else []
    if not items:
        return False
    output_fn(label + ":")
    for item in items:
        if isinstance(item, dict):
            message = item.get("message") or item.get("error") or item.get("source")
            output_fn(f"  - {message or 'подробность сохранена в отчёте'}")
        else:
            output_fn(f"  - {item}")
    return True


def _show_operation_result(
    result: object,
    output_fn: OutputFn,
    *,
    title: str = "Результат операции",
) -> None:
    """Render a concise TUI projection; machine-readable JSON remains a CLI concern."""

    output_fn("\n" + title)
    if not isinstance(result, dict):
        output_fn(f"Состояние: {result}")
        return

    ok = result.get("ok")
    status = str(result.get("status") or "").strip().lower()
    if isinstance(ok, bool):
        output_fn(f"Состояние: {'исправно' if ok else 'требуется внимание'}")
    elif status:
        translated = {
            "complete": "завершено",
            "completed": "завершено",
            "ok": "исправно",
            "success": "завершено",
            "installed": "установлено",
            "started": "запущено в фоне",
        }.get(status, status)
        output_fn(f"Состояние: {translated}")
    else:
        output_fn("Состояние: операция завершена")

    if result.get("run_id"):
        output_fn(f"Транзакция: {result['run_id']}")
    scalar_fields = (
        ("source", "Источник"),
        ("sourcecraft", "Зеркало SourceCraft"),
        ("github", "Источник GitHub"),
        ("backup", "Backup"),
        ("tui_command", "Команда TUI"),
        ("pending_post_update_repair", "Ожидается repair после обновления"),
        ("reboot_may_be_scheduled_by_lucx", "LucX может запланировать перезагрузку"),
    )
    for key, label in scalar_fields:
        if key not in result:
            continue
        value = result[key]
        if isinstance(value, bool):
            value = "да" if value else "нет"
        if value not in (None, ""):
            output_fn(f"{label}: {value}")

    job_status = result.get("job_status")
    if isinstance(job_status, dict) and job_status.get("job_id"):
        state_label = {
            "queued": "ожидает запуска",
            "running_updater": "выполняется обновление LucX",
            "running_repair": "выполняется восстановление",
            "complete": "завершено",
            "failed": "завершилось с ошибкой",
        }.get(str(job_status.get("state") or ""), "состояние неизвестно")
        if job_status.get("historical"):
            output_fn(f"Последнее задание обновления: {job_status['job_id']}")
            output_fn("  Это историческая ошибка, активная операция сейчас не выполняется.")
        else:
            output_fn(f"Задание обновления: {job_status['job_id']}")
        output_fn(f"  Состояние: {state_label}")
        current = job_status.get("phase_current")
        total = job_status.get("phase_total")
        label = str(job_status.get("phase_label") or "").strip()
        if isinstance(current, int) and isinstance(total, int) and total > 0:
            output_fn(f"  Этап: {current}/{total}" + (f" — {label}" if label else ""))
        elif label:
            output_fn(f"  Этап: {label}")
        if job_status.get("updated_at"):
            output_fn(f"  Последнее обновление: {job_status['updated_at']}")
        if job_status.get("error"):
            output_fn(f"  Ошибка: {job_status['error']}")

    shown = False
    shown |= _show_list("Ошибки", result.get("errors"), output_fn)
    shown |= _show_list("Ошибки резервного источника", result.get("fallback_errors"), output_fn)
    shown |= _show_list("Предупреждения", result.get("warnings"), output_fn)
    shown |= _show_list(
        "Изменённые управляемые файлы",
        result.get("changed_managed_files"),
        output_fn,
    )
    shown |= _show_list("Установленные пакеты", result.get("installed_packages"), output_fn)
    if isinstance(result.get("repair"), dict):
        repair = result["repair"]
        output_fn("Восстановление после обновления:")
        if repair.get("run_id"):
            output_fn(f"  - транзакция {repair['run_id']}")
        _show_list("  Предупреждения", repair.get("warnings"), output_fn)
    if not shown and isinstance(ok, bool) and ok:
        output_fn("Ошибок и изменений управляемых файлов не обнаружено.")


def _show_audit_result(audit: Audit, output_fn: OutputFn) -> None:
    output_fn("\nRead-only аудит LucX и системы")
    os_name = "Debian" if audit.os_id.lower() == "debian" else (audit.os_id or "неизвестная ОС")
    output_fn(
        f"ОС: {os_name} {audit.os_version or 'неизвестно'}; "
        f"поддерживается: {'да' if audit.supported_os else 'нет'}"
    )
    output_fn(
        f"База LucX: {audit.db_path or 'не найдена'}; "
        f"схема поддерживается: {'да' if audit.db_schema_supported else 'нет'}"
    )
    enabled = sum(1 for inbound in audit.inbounds if inbound.enable)
    output_fn(f"Подключения: {enabled}/{len(audit.inbounds)} включены")
    active_services = sum(1 for state in audit.services.values() if str(state).lower() in {"active", "running", "enabled"})
    output_fn(f"Службы: {active_services}/{len(audit.services)} активны")
    output_fn(f"Предупреждений: {len(audit.warnings)}")
    if audit.inbounds:
        output_fn("Подключения:")
        output_fn(" ID  Протокол       Домен                      Публикация")
        for inbound in audit.inbounds:
            domain = str(inbound.share_addr or "-").split(":", 1)[0]
            network = str(inbound.network or "tcp").lower()
            transport = "UDP" if network == "udp" else "TCP/UDP" if network == "both" else "TCP"
            public = int(inbound.suggested_public_port or inbound.port)
            output_fn(f" {inbound.id:>2}  {inbound.protocol[:13]:<13} {domain[:25]:<25} {transport}/{public}")
    output_fn("Подробные параметры: отдельный технический отчёт.")


def _certificate_banner(engine: Engine) -> tuple[str, str]:
    """Return short, read-only certificate and renewal status for the main menu."""
    try:
        result = certificate_status(engine)
        selected = result.get("selected") or {}
        expires_at = str(selected.get("expires_at") or "")
        if expires_at:
            expires_at = expires_at[:10]
            certificate = f"действителен до {expires_at}"
        else:
            certificate = "не найден"
        manifest = load_state(engine.fs).get("manifest") or {}
        renewal = ((manifest.get("certificates") or {}).get("renewal") or {})
        provider = str(renewal.get("provider") or "auto")
        renewal_status = "включено" if renewal.get("enabled") else "не настроено"
        if provider not in {"", "auto"}:
            renewal_status += f" ({provider})"
        return certificate, renewal_status
    except Exception:
        return "не удалось проверить", "состояние неизвестно"


def _show_mutation_preview(preview: dict[str, object], output_fn: OutputFn) -> None:
    output_fn("\nТочный предпросмотр изменений")
    groups = (
        ("Файлы", "files"),
        ("Файлы БД", "database_files"),
        ("Разрешённые поля БД", "database_fields"),
        ("Службы", "services"),
        ("Защищённые объекты", "protected_objects"),
        ("Безопасно исключённые/заблокированные маршруты", "blockers"),
    )
    for label, key in groups:
        values = list(preview.get(key) or [])  # type: ignore[arg-type]
        output_fn(f"{label}:")
        if values:
            for value in values:
                output_fn(f"  - {value}")
        else:
            output_fn("  - нет")
    output_fn(f"Каталог backup: {preview.get('backup_root') or BACKUP_ROOT}")
    output_fn("Любое подтверждение по умолчанию: НЕТ.")


def _show_plan_preview(plan: dict[str, object], output_fn: OutputFn) -> None:
    _show_mutation_preview(mutation_preview(plan), output_fn)


def _extended_route_blockers(manifest: dict[str, object]) -> list[str]:
    decoys = manifest.get("decoys") or {}
    if not isinstance(decoys, dict):
        return []
    return [
        f"inbound #{item.get('inbound_id')} {item.get('domain')}: "
        f"{item.get('reason') or 'безопасная стратегия не доказана'}"
        for item in decoys.get("extended_routes") or []
        if isinstance(item, dict) and item.get("status") != "ready"
    ]


def _operation_preview(
    *,
    files: list[str] | None = None,
    database_files: list[str] | None = None,
    database_fields: list[str] | None = None,
    services: list[str] | None = None,
    protected_objects: list[str] | None = None,
    blockers: list[str] | None = None,
) -> dict[str, object]:
    return {
        "files": files or [],
        "database_files": database_files or [],
        "database_fields": database_fields or [],
        "services": services or [],
        "backup_root": BACKUP_ROOT,
        "protected_objects": protected_objects
        or ["LucX clients/inbounds/listeners/credentials", "Naive Caddyfile"],
        "blockers": blockers or [],
    }


def _audit(engine: Engine, db_path: str | None, output_fn: OutputFn) -> None:
    audit = _run_progress("Read-only аудит LucX и системы", output_fn, lambda: engine.audit(db_path))
    _show_audit_result(audit, output_fn)  # type: ignore[arg-type]


def _initial_apply(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    audit = _run_progress("Read-only аудит перед настройкой", output_fn, lambda: engine.audit(db_path))
    manifest = build_manifest_interactively(audit, input_fn=input_fn, output_fn=output_fn)
    plan = engine.plan(manifest, audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Применить именно этот план с backup и автоматическим rollback?",
        input_fn,
        output_fn,
    ):
        output_fn("Применение отменено; сервер не изменен.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционное применение и проверка",
            output_fn,
            lambda: engine.apply(manifest, audit=audit),
        ),
        output_fn,
        title="Первичная настройка завершена",
    )


def _repair(
    engine: Engine, apply: bool, input_fn: InputFn, output_fn: OutputFn
) -> None:
    check = _run_progress(
        "Проверка необходимости восстановления", output_fn, lambda: repair_check(engine)
    )
    output_fn(format_repair_check(check))
    if not apply:
        return
    output_fn(format_plan(check["proposed_plan"]))
    _show_plan_preview(check["proposed_plan"], output_fn)
    if not _yes_no(
        "Создать backup и транзакционно восстановить маршруты из текущей БД LucX?",
        input_fn,
        output_fn,
    ):
        output_fn("Восстановление отменено.")
        return
    _show_operation_result(
        _run_progress(
            "Backup, восстановление и проверка",
            output_fn,
            lambda: repair_apply(engine),
        ),
        output_fn,
        title="Транзакционное восстановление завершено",
    )


def _reconfigure(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    state = load_state(engine.fs)
    audit = _run_progress(
        "Read-only аудит перед сменой доменов",
        output_fn,
        lambda: engine.audit(state["manifest"]["lucx"]["db_path"]),
    )
    if not audit.db_schema_supported:
        output_fn("Схема LucX не поддерживается безопасным адаптером; сервер не изменён.")
        return
    output_fn(
        "Можно заменить только DNS-суффикс всех доменов. Левая часть имени сохранится: "
        "test.example.test -> test.new-zone.example."
    )
    if _yes_no("Использовать автоматическую замену DNS-суффикса?", input_fn, output_fn):
        old_zone = input_fn("Старая DNS-зона: ").strip()
        new_zone = input_fn("Новая DNS-зона: ").strip()
        refreshed, refresh_warnings = refresh_manifest_from_audit(state["manifest"], audit)
        manifest = migrate_domain_zone(refreshed, old_zone, new_zone)
        for warning in refresh_warnings:
            output_fn("Предупреждение: " + warning)
        output_fn(
            "Новые домены построены. Теперь будет найден или выпущен сертификат, "
            "покрывающий корневую зону и wildcard."
        )
        status = _run_progress(
            "Поиск wildcard/SAN сертификата",
            output_fn,
            lambda: certificate_status_for_manifest(engine, manifest),
        )
        has_naive = any(
            item.get("protocol") == "naive" and item.get("exposure") == "tcp_sni"
            for item in manifest.get("protocols", [])
        )
        sync_naive_endpoint = False
        if has_naive:
            output_fn(
                "Обнаружен Naive. Его Caddyfile генерируется LucX из настроек inbound; "
                "этот инструмент никогда не редактирует файл напрямую."
            )
            sync_naive_endpoint = _yes_no(
                "Синхронизировать Naive с новой зоной (домен и пути сертификата в настройках LucX)?",
                input_fn,
                output_fn,
            )
            if not sync_naive_endpoint:
                output_fn(
                    "Отменено: без синхронизации Naive продолжит отдавать старый домен и сертификат. "
                    "Обновите Naive вручную в панели LucX и повторите смену зоны."
                )
                return
            # The engine reads the flag per protocol; mirror the user's answer
            # onto every planned Naive inbound published through shared SNI.
            for protocol in manifest.get("protocols", []):
                if (
                    protocol.get("protocol") == "naive"
                    and protocol.get("exposure") == "tcp_sni"
                ):
                    protocol["sync_naive_endpoint"] = True
        if not status.get("selected"):
            output_fn(
                "Подходящий сертификат не найден. Для продолжения будет выпущен "
                "wildcard-сертификат новой DNS-зоны через Cloudflare DNS-01."
            )
            output_fn("Выберите способ авторизации Cloudflare:")
            output_fn("  1. API Token")
            output_fn("  2. Global API Key + email")
            auth_choice = input_fn("Номер варианта [1]: ").strip() or "1"
            if auth_choice not in {"1", "2"}:
                output_fn("Смена зоны отменена: неизвестный способ авторизации.")
                return
            api_token = getpass.getpass("Cloudflare API Token: ") if auth_choice == "1" else ""
            global_key = getpass.getpass("Cloudflare Global API Key: ") if auth_choice == "2" else ""
            cloudflare_email = (
                input_fn("Email аккаунта Cloudflare: ").strip() if auth_choice == "2" else ""
            )
            result = _run_progress(
                "Выпуск wildcard-сертификата новой DNS-зоны",
                output_fn,
                lambda: issue_certbot_cloudflare(
                    engine,
                    zone=new_zone,
                    api_token=api_token or None,
                    global_api_key=global_key or None,
                    cloudflare_email=cloudflare_email,
                    manifest_override=manifest,
                ),
            )
            manifest = result["manifest"]
            selected = {
                "cert_path": manifest["certificates"]["cert_path"],
                "key_path": manifest["certificates"]["key_path"],
            }
        else:
            selected = status["selected"]
        manifest["certificates"]["cert_path"] = selected["cert_path"]
        manifest["certificates"]["key_path"] = selected["key_path"]
        manifest["components"]["tls_hook"] = True
        manifest.setdefault("lucx", {}).setdefault("settings_management", {}).update(
            {
                "sync_certificate_paths": True,
                "sync_naive_endpoint": sync_naive_endpoint,
                "user_confirmed": True,
            }
        )
        audit = _run_progress(
            "Read-only аудит перед применением новой DNS-зоны",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
        plan = engine.plan(manifest, audit)
        output_fn(format_plan(plan))
        _show_plan_preview(plan, output_fn)
        if _yes_no("Применить новую DNS-зону с backup и rollback?", input_fn, output_fn):
            _show_operation_result(
                _run_progress("Смена DNS-зоны", output_fn, lambda: engine.apply(manifest, audit=audit)),
                output_fn,
                title="DNS-зона изменена",
            )
        return
    manifest, warnings = reconfigure_domains_interactively(
        state["manifest"],
        audit,
        engine.fs,
        engine.runner,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    plan = engine.plan(manifest, audit)
    plan["warnings"] = list(dict.fromkeys(list(plan.get("warnings") or []) + warnings))
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Применить смену доменов с backup и автоматическим rollback?",
        input_fn,
        output_fn,
    ):
        output_fn("Смена доменов отменена.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционное применение новых доменов",
            output_fn,
            lambda: engine.apply(manifest, audit=audit),
        ),
        output_fn,
        title="Смена доменов завершена",
    )


def _certificate_menu(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    status = _run_progress(
        "Проверка сертификатов", output_fn, lambda: certificate_status(engine)
    )
    output_fn("Домены управляемого сертификата: " + ", ".join(status["required_domains"]))
    if status["selected"]:
        selected = status["selected"]
        output_fn(
            f"Подходящая пара: {selected['cert_path']} / {selected['key_path']}\n"
            f"Истекает: {selected['expires_at']}"
        )
    else:
        output_fn("Действующая пара, покрывающая все домены, не найдена.")
    if not _yes_no("Выпустить/обновить сертификат через Certbot DNS Cloudflare?", input_fn, output_fn):
        return
    output_fn(
        "Если Certbot или DNS Cloudflare plugin отсутствуют, TUI установит их через APT; "
        "файловый rollback не удаляет установленные пакеты."
    )
    zone = input_fn("DNS-зона (например, example.test): ").strip()
    email = input_fn("Email Certbot (можно оставить пустым): ").strip()
    output_fn("Выберите способ авторизации Cloudflare DNS API:")
    output_fn("  1. API Token (рекомендуется, с правами Zone/DNS/Edit)")
    output_fn("  2. Global API Key + email аккаунта")
    auth_choice = input_fn("Номер варианта [1]: ").strip() or "1"
    if auth_choice not in {"1", "2"}:
        output_fn("Выпуск сертификата отменен: нужен вариант 1 или 2.")
        return
    token = getpass.getpass("Cloudflare API Token: ") if auth_choice == "1" else ""
    global_key = getpass.getpass("Cloudflare Global API Key: ") if auth_choice == "2" else ""
    cloudflare_email = input_fn("Email аккаунта Cloudflare: ").strip() if auth_choice == "2" else ""
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/etc/letsencrypt/",
                "/etc/letsencrypt/cloudflare-lucx.ini",
            ],
            services=[],
            blockers=[
                "APT-пакеты Certbot/plugin не удаляются файловым rollback, если потребуется их установка."
            ],
        ),
        output_fn,
    )
    if not _yes_no(
        f"Запустить DNS-01 выпуск для {zone} и точных доменов из манифеста?",
        input_fn,
        output_fn,
    ):
        output_fn("Выпуск сертификата отменен.")
        return
    result = _run_progress(
        "Certbot DNS-01: выпуск сертификата",
        output_fn,
        lambda: issue_certbot_cloudflare(
            engine,
            zone=zone,
            api_token=token or None,
            global_api_key=global_key or None,
            cloudflare_email=cloudflare_email,
            email=email,
        ),
    )
    output_fn(
        f"Сертификат выпущен: {result['candidate']['cert_path']}. "
        "Для переключения сервисов нужен отдельный транзакционный apply."
    )
    audit = _run_progress(
        "Read-only аудит перед переключением сертификата",
        output_fn,
        lambda: engine.audit(result["manifest"]["lucx"]["db_path"]),
    )
    plan = engine.plan(result["manifest"], audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if _yes_no(
        "Применить новый сертификат к управляемым сервисам и renewal hook?",
        input_fn,
        output_fn,
    ):
        _show_operation_result(
            _run_progress(
                "Применение сертификата и renewal hook",
                output_fn,
                lambda: engine.apply(result["manifest"], audit=audit),
            ),
            output_fn,
            title="Новый сертификат применён",
        )
    else:
        output_fn("Сертификат сохранен Certbot, но активная конфигурация не изменена.")


def _configure_decoys(
    engine: Engine,
    input_fn: InputFn,
    output_fn: OutputFn,
) -> None:
    state = load_state(engine.fs)
    manifest, warnings = configure_protocol_decoys_interactively(
        state["manifest"],
        default_enabled=True,
        show_capabilities=True,
        input_fn=input_fn,
        output_fn=output_fn,
    )
    if not manifest.get("decoys", {}).get("enabled"):
        output_fn("Настройка заглушек отменена.")
        return
    audit = _run_progress(
        "Read-only аудит маршрутов заглушек",
        output_fn,
        lambda: engine.audit(manifest["lucx"]["db_path"]),
    )
    manifest, mode_warnings = configure_decoy_routing_mode(manifest, audit, "extended")
    blocked_xhttp = [
        route
        for route in manifest.get("decoys", {}).get("extended_routes", [])
        if route.get("status") == "blocked"
        and str(route.get("transport") or "").lower() == "xhttp"
        and str(route.get("transport_path") or "/") == "/"
    ]
    if blocked_xhttp:
        output_fn("Обнаружены XHTTP-маршруты с корневым path, который нельзя безопасно разделить с браузером:")
        for route in blocked_xhttp:
            output_fn(
                f"  - inbound #{route.get('inbound_id')} {route.get('domain')}: "
                "текущий path=/"
            )
        if _yes_no(
            "Разрешить изменить только XHTTP path на отдельный путь для browser/VPN-разделения",
            input_fn,
            output_fn,
        ):
            for route in blocked_xhttp:
                inbound_id = int(route.get("inbound_id") or 0)
                default_path = f"/xhttp-{inbound_id}"
                while True:
                    new_path = input_fn(
                        f"Новый XHTTP path для inbound #{inbound_id} [{default_path}]: "
                    ).strip() or default_path
                    if (
                        new_path.startswith("/")
                        and new_path != "/"
                        and ".." not in new_path.split("/")
                        and "\x00" not in new_path
                    ):
                        break
                    output_fn("Укажите непустой путь, начинающийся с '/', без '..'.")
                manifest.setdefault("lucx", {}).setdefault("inbound_changes", []).append(
                    {"inbound_id": inbound_id, "field": "transport_path", "value": new_path}
                )
            manifest["lucx"].setdefault("settings_management", {})[
                "allow_inbound_changes"
            ] = True
            manifest, refreshed_warnings = configure_decoy_routing_mode(
                manifest, audit, "extended"
            )
            mode_warnings = list(dict.fromkeys(mode_warnings + refreshed_warnings))
    warnings = list(dict.fromkeys(warnings + mode_warnings))
    output_fn("Матрица маршрутов: готовые будут применены, заблокированные останутся без перехвата VPN.")
    for route in manifest["decoys"].get("extended_routes") or []:
        state_label = "готов" if route.get("status") == "ready" else "заблокирован"
        output_fn(
            f"  - #{route.get('inbound_id')} {route.get('protocol')} "
            f"{route.get('domain')}: {state_label}; {route.get('reason') or 'причина не указана'}"
        )
    plan = engine.plan(manifest, audit)
    plan["warnings"] = list(dict.fromkeys(list(plan.get("warnings") or []) + warnings))
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    if not _yes_no(
        "Создать все сайты-заглушки с backup и применить маршруты?",
        input_fn,
        output_fn,
    ):
        output_fn("Настройка заглушек отменена.")
        return
    _show_operation_result(
        _run_progress(
            "Применение сайтов-заглушек и маршрутов",
            output_fn,
            lambda: engine.apply(manifest, audit=audit),
        ),
        output_fn,
        title="Сайты-заглушки и маршруты применены",
    )


def _update(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    output_fn(
        "\nОбновление панели LucX\n"
        "Что произойдет:\n"
        " - создается backup базы и состояния;\n"
        " - официальный обновляющий скрипт LucX запускается отдельным\n"
        "   systemd-заданием (не зависит от TUI и SSH);\n"
        " - после обновления автоматически восстанавливаются управляемые\n"
        "   маршруты (repair) и выполняется проверка служб;\n"
        " - LucX может запланировать перезагрузку для AWG/kernel.\n"
        "\n"
        "Если проверка перед обновлением показывает 'требуется внимание',\n"
        "сначала выполните пункт 8 (Ремонт после обновления).\n"
    )
    status = _run_progress(
        "Проверка источников обновления", output_fn, lambda: update_source_status(engine)
    )
    _show_operation_result(status, output_fn, title="Текущий статус обновления")
    output_fn(
        "\nВыберите источник скачивания LucX:\n"
        " 1. Автоматически: gh-proxy -> GitHub -> ваши proxy -> зеркало (рекомендуется)\n"
        " 2. GitHub напрямую\n"
        " 3. Собственный HTTPS tar-архив"
    )
    choice = input_fn("Номер варианта [1]: ").strip() or "1"
    source = {"1": "auto", "2": "github", "3": "custom"}.get(choice)
    if source is None:
        output_fn("Неизвестный источник.")
        return
    custom = input_fn("HTTPS URL tar-архива: ").strip() if source == "custom" else ""
    proxy_templates: list[str] = []
    if source == "auto":
        output_fn(
            "Дополнительные GitHub-proxy шаблоны (необязательно).\n"
            "Формат: https://proxy.example/download?url={url}\n"
            "Пустая строка — пропустить и продолжить."
        )
        while True:
            value = input_fn("GitHub proxy {url} (пусто = дальше): ").strip()
            if not value:
                break
            proxy_templates.append(value)
    check = _run_progress(
        "Проверка восстановления перед обновлением",
        output_fn,
        lambda: repair_check(engine),
    )
    output_fn(format_repair_check(check))
    if check.get("repair_required"):
        output_fn(
            "\nОбновление заблокировано: конфигурация требует восстановления.\n"
            "Что делать:\n"
            " 1. Выйдите в главное меню;\n"
            " 2. Откройте пункт 8 (Ремонт после обновления);\n"
            " 3. Выберите 'Проверить и восстановить';\n"
            " 4. После успешного ремонта повторите обновление.\n"
            "Сервер не изменен."
        )
        return
    output_fn(
        "Перед обновлением будут установлены постоянные команды, создан backup БД/состояния "
        "и маркер post-update repair. Сам LucX может запланировать перезагрузку для AWG/kernel."
    )
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/usr/local/sbin/lucx-post-configure",
                "/usr/local/sbin/lucx-sub-repair",
                "/usr/local/sbin/x-tuna",
                "/etc/systemd/system/lucx-post-update@.service",
                "/var/lib/lucx-post-configurator/pending-post-update-repair",
            ],
            database_files=["/etc/x-ui/x-ui.db (только backup; обновляющий скрипт LucX внешний)"],
            services=["x-ui.service", "lucx-post-update-repair.service"],
            blockers=["Обновляющий скрипт LucX является внешним действием и отдельно журналируется."],
        ),
        output_fn,
    )
    if not _yes_no("Обновить LucX из выбранного источника?", input_fn, output_fn):
        output_fn("Обновление отменено.")
        return
    _show_operation_result(
        _run_progress(
            "Подготовка и запуск фонового обновления",
            output_fn,
            lambda: update_lucx(
                engine,
                source=source,
                custom_url=custom,
                github_proxy_templates=proxy_templates,
            ),
        ),
        output_fn,
        title="Обновление LucX",
    )


def _install_commands(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    _show_mutation_preview(
        _operation_preview(
            files=[
                "/usr/local/sbin/lucx-post-configure",
                "/usr/local/sbin/lucx-sub-repair",
                "/usr/local/sbin/x-tuna",
                "/etc/systemd/system/lucx-post-update-repair.service",
                "/etc/systemd/system/lucx-post-update@.service",
            ],
            services=["lucx-post-update-repair.service", "lucx-post-update@.service"],
        ),
        output_fn,
    )
    if not _yes_no(
        "Установить/обновить TUI, команду x-tuna и lucx-sub-repair?",
        input_fn,
        output_fn,
    ):
        return
    _show_operation_result(
        _run_progress(
            "Установка постоянных команд",
            output_fn,
            lambda: install_self(engine.fs, engine.runner),
        ),
        output_fn,
        title="Команды TUI установлены/обновлены",
    )


def _rollback(
    engine: Engine, input_fn: InputFn, output_fn: OutputFn
) -> None:
    _show_mutation_preview(
        _operation_preview(
            files=["управляемые файлы из последней транзакции"],
            database_files=["LucX DB только для разрешённых publication-полей из транзакции"],
            services=["только службы, затронутые восстановленными файлами"],
        ),
        output_fn,
    )
    if not _yes_no("Восстановить управляемые файлы из последнего backup?", input_fn, output_fn):
        return
    run_id = _run_progress(
        "Откат последней транзакции", output_fn, engine.rollback
    )
    output_fn(f"Откат backup {run_id} завершен. Выполните проверку конфигурации.")


def _reboot(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    if not engine.fs.is_live:
        raise RuntimeError("перезагрузка доступна только в живой системе")
    _show_mutation_preview(
        _operation_preview(
            services=["полная перезагрузка ОС; все активные подключения будут прерваны"],
        ),
        output_fn,
    )
    if not _yes_no("Отдельно перезагрузить сервер прямо сейчас?", input_fn, output_fn):
        return
    if not _yes_no("Подтвердите еще раз: активные подключения будут прерваны", input_fn, output_fn):
        return
    engine.runner.run(["systemctl", "reboot"], check=False)


def _read_choice(prompt: str, input_fn: InputFn, output_fn: OutputFn) -> str:
    try:
        return input_fn(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        output_fn("")
        return "0"


def _print_decoy_status(engine: Engine, output_fn: OutputFn) -> None:
    state = load_state(engine.fs)
    manifest = state["manifest"]
    routing_mode = str(manifest.get("decoys", {}).get("routing_mode") or "strict")
    output_fn(
        "Режим маршрутизации: "
        + (
            "расширенный (разделение браузера и VPN)"
            if routing_mode == "extended"
            else "строгий безопасный"
        )
    )
    summary = coverage_summary(manifest)
    output_fn(
        "Заглушки: "
        f"{summary['managed']} управляются, "
        f"{summary['existing_fallback']} через fallback, "
        f"{summary['naive_readonly']} Naive/Caddy, "
        f"{summary['blocked_or_unknown']} заблокированы"
    )
    output_fn("Домен                         Состояние")
    for row in domain_status_rows(manifest):
        status = {
            "extended_ready": "готов",
            "existing_fallback_observed": "fallback",
            "naive_caddy_owned_readonly": "Naive/Caddy",
            "extended_blocked": "заблокирован",
            "unsupported_safe": "неизвестно",
        }.get(row["status"], row["status"])
        output_fn(f"{row['domain'][:28]:28} {status}")
    output_fn("Подробности и причины доступны в техническом отчёте.")


def _print_state_summary(engine: Engine, output_fn: OutputFn) -> None:
    try:
        state = load_state(engine.fs)
    except Exception as exc:
        output_fn(f"Сохранённое состояние недоступно только для чтения: {exc}")
        output_fn(
            "Изменяющие действия из сохранённого состояния заблокированы; read-only аудит доступен отдельно."
        )
        return
    manifest = state["manifest"]
    output_fn(f"Последняя транзакция: {state.get('run_id') or 'неизвестно'}")
    output_fn(f"Версия манифеста: {manifest.get('schema_version')}")
    output_fn(
        "Панель: https://" + str(manifest["lucx"]["panel"].get("domain") or "не настроена")
    )
    output_fn(
        "Подписка: https://"
        + str(manifest["lucx"]["subscription"].get("domain") or "не настроена")
    )
    output_fn(
        "Sidecar: "
        + ("включён (явно подтверждён)" if manifest["components"].get("sidecar") else "выключен")
    )
    integrity = manifest.get("integrity") or {}
    caddy = integrity.get("naive_caddyfile") or {}
    output_fn(
        "Naive Caddyfile: "
        + (
            f"только чтение, sha256={caddy.get('sha256', 'нет хеша')}"
            if caddy.get("found")
            else "не обнаружен"
        )
    )
    coverage = coverage_summary(manifest)
    output_fn(
        "Маршрутизация: "
        + ("расширенная" if manifest.get("decoys", {}).get("routing_mode") == "extended" else "строгая")
    )
    output_fn(
        "Заглушки: "
        f"{coverage['managed']} управляются, "
        f"{coverage['existing_fallback']} через fallback, "
        f"{coverage['blocked_or_unknown']} заблокированы"
    )
    backend = manifest.get("trusttunnel_backend") or {}
    output_fn(
        "TrustTunnel backend: "
        + ("включён" if manifest.get("components", {}).get("trusttunnel_backend") else "выключен")
    )
    if backend.get("public_domain"):
        output_fn(f"TrustTunnel: https://{backend['public_domain']}/")
    output_fn("Подробности: раздел «Покрытие заглушками»")


def _public_url(endpoint: dict[str, object]) -> str:
    domain = str(endpoint.get("domain") or "").strip()
    if not domain:
        return "не настроена"
    try:
        port = int(endpoint.get("public_port") or 443)
    except (TypeError, ValueError):
        port = 443
    suffix = "" if port == 443 else f":{port}"
    return f"https://{domain}{suffix}/"


def _main_state_banner(engine: Engine) -> str:
    """Return the high-value saved state shown before every main-menu choice."""

    try:
        state = load_state(engine.fs)
        manifest = state["manifest"]
    except Exception:
        return " Панель: не настроена\n Подписка: не настроена\n Обновление: нет данных"

    update_label = "нет активного задания"
    try:
        job = update_source_status(engine).get("job_status") or {}
    except Exception:
        job = {}
    if isinstance(job, dict) and job.get("job_id"):
        if job.get("historical"):
            # The main banner describes only the current operation.
            # Historical results remain available in the update details.
            job = {}
        else:
            update_label = {
                "queued": "ожидает запуска",
                "running_updater": "обновление LucX",
                "running_repair": "восстановление конфигурации",
                "complete": "завершено",
                "failed": "ошибка",
            }.get(str(job.get("state") or ""), "состояние неизвестно")
            current = job.get("phase_current")
            total = job.get("phase_total")
            if isinstance(current, int) and isinstance(total, int) and total > 0:
                update_label += f" ({current}/{total})"
    certificate, renewal = _certificate_banner(engine)
    decoy_roots = sorted(
        {
            str(site.get("root") or "").strip()
            for site in (manifest.get("decoys") or {}).get("sites") or []
            if str(site.get("root") or "").strip()
        }
    )
    if decoy_roots:
        if len(decoy_roots) <= 2:
            decoy_label = ", ".join(decoy_roots)
        else:
            base = decoy_roots[0].rsplit("/", 1)[0] if "/" in decoy_roots[0] else decoy_roots[0]
            decoy_label = f"{base}/<домен> ({len(decoy_roots)} сайтов)"
    else:
        decoy_label = "не созданы"
    return (
        f" Панель: {_public_url(manifest['lucx']['panel'])}\n"
        f" Подписка: {_public_url(manifest['lucx']['subscription'])}\n"
        f" Сертификат: {certificate}\n"
        f" Автопродление: {renewal}\n"
        f" Файлы сайтов: {decoy_label}\n"
        f" Обновление: {update_label}"
    )


def _status_menu(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nСтатус и аудит\n"
            " 1. Общая сводка сохранённого состояния\n"
            " 2. Полный read-only аудит LucX/системы\n"
            " 3. Проверить установленную управляемую конфигурацию\n"
            " 4. Проверить целостность и необходимость repair\n"
            " 5. Покрытие заглушками по доменам\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _print_state_summary(engine, output_fn)
        elif choice == "2":
            _audit(engine, db_path, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка установленной конфигурации",
            )
        elif choice == "4":
            _repair(engine, False, input_fn, output_fn)
        elif choice == "5":
            _print_decoy_status(engine, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _domains_menu(
    engine: Engine, db_path: str | None, input_fn: InputFn, output_fn: OutputFn
) -> None:
    while True:
        output_fn(
            "\nДомены и маршрутизация\n"
            " 1. Сменить домены и повторно подобрать сертификат\n"
            " 2. Повторно обнаружить домены/listener (read-only аудит)\n"
            " 3. Показать безопасные и заблокированные маршруты заглушек\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _reconfigure(engine, input_fn, output_fn)
        elif choice == "2":
            _audit(engine, db_path, output_fn)
        elif choice == "3":
            _print_decoy_status(engine, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _decoy_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        state = load_state(engine.fs)
        mode = str(state["manifest"].get("decoys", {}).get("routing_mode") or "strict")
        output_fn(
            "\nСайты-заглушки\n"
            " Текущий режим: автоматический, максимально полный\n"
            " 1. Матрица покрытия всех протокольных доменов\n"
            " 2. Создать/синхронизировать заглушки везде, где это возможно\n"
            " 3. Проверить установленную конфигурацию и HTTPS health\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _print_decoy_status(engine, output_fn)
        elif choice == "2":
            _configure_decoys(engine, input_fn, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка сайтов-заглушек и HTTPS",
            )
        else:
            output_fn("Неизвестный пункт.")


def _trusttunnel_backend_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    """Probe an operator-supplied backend; installation is deliberately separate."""
    while True:
        output_fn(
            "\nСовместимый TrustTunnel backend\n"
            " 1. Проверить backend в разрешённом локальном пути\n"
            " 2. Показать требования к backend\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            path = input_fn("Путь к локальному backend: ").strip()
            port_text = input_fn("Свободный loopback-порт [26444]: ").strip()
            try:
                port = int(port_text or "26444")
                result = probe_backend(engine.runner, binary=path, loopback_port=port)
                output_fn(f"Состояние: {'готов' if result.ready else 'заблокирован'}")
                output_fn(f"Версия: {result.version or 'не определена'}")
                output_fn(f"TCP: {'да' if result.supports_tcp else 'нет'}")
                output_fn(f"HTTP/2 CONNECT: {'да' if result.supports_http2_connect else 'нет'}")
                output_fn(f"Стандартный URI: {'да' if result.supports_standard_uri else 'нет'}")
                _show_list("Причины блокировки", result.reasons, output_fn)
            except (OSError, ValueError) as exc:
                output_fn(f"Ошибка проверки: {exc}")
        elif choice == "2":
            output_fn("Требуются: pinned SHA-256, TCP, HTTP/2 CONNECT, стандартный URI и запуск через config-файл.")
            output_fn("Backend должен слушать только loopback; публичный 443 не переключается во время probe.")
        else:
            output_fn("Неизвестный пункт.")


def _sidecar_apply(
    engine: Engine, enabled: bool, input_fn: InputFn, output_fn: OutputFn
) -> None:
    state = load_state(engine.fs)
    manifest = copy.deepcopy(state["manifest"])
    if enabled and not _yes_no(
        "Sidecar является опциональным. Явно установить/обновить его?",
        input_fn,
        output_fn,
    ):
        output_fn("Sidecar не изменён.")
        return
    manifest["components"]["sidecar"] = enabled
    manifest["sidecar"]["user_confirmed"] = enabled
    subscription = manifest["lucx"]["subscription"]
    if enabled:
        audit = _run_progress(
            "Read-only аудит перед настройкой sidecar",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
        manifest["sidecar"]["allowed_hosts"] = [subscription["domain"]]
        manifest["sidecar"]["allowed_path_prefixes"] = list(
            dict.fromkeys(
                [
                    subscription["path_prefix"],
                    audit.settings.get("subClashPath", "/clash/") or "/clash/",
                    audit.settings.get("subAwgPath", "/awg/") or "/awg/",
                    audit.settings.get("subJsonPath", "/json/") or "/json/",
                ]
            )
        )
        manifest["sidecar"]["upstream_port"] = subscription["internal_port"]
    else:
        audit = _run_progress(
            "Read-only аудит перед удалением sidecar",
            output_fn,
            lambda: engine.audit(manifest["lucx"]["db_path"]),
        )
    plan = engine.plan(manifest, audit)
    output_fn(format_plan(plan))
    _show_plan_preview(plan, output_fn)
    action = "установить/обновить" if enabled else "удалить из управляемой обвязки"
    if not _yes_no(f"{action.capitalize()} sidecar транзакционно?", input_fn, output_fn):
        output_fn("Sidecar не изменён.")
        return
    _show_operation_result(
        _run_progress(
            "Транзакционная настройка sidecar",
            output_fn,
            lambda: engine.apply(manifest, audit=audit),
        ),
        output_fn,
        title="Настройка sidecar завершена",
    )


def _sidecar_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        state = load_state(engine.fs)
        enabled = bool(state["manifest"]["components"].get("sidecar"))
        output_fn(
            "\nПодписки и sidecar\n"
            f" Текущее состояние: {'включён' if enabled else 'выключен'}\n"
            " 1. Установить/обновить sidecar (отдельное согласие, по умолчанию НЕТ)\n"
            " 2. Удалить sidecar из управляемой обвязки\n"
            " 3. Проверить опубликованную подписку и управляемую конфигурацию\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _sidecar_apply(engine, True, input_fn, output_fn)
        elif choice == "2":
            _sidecar_apply(engine, False, input_fn, output_fn)
        elif choice == "3":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка подписки и управляемой конфигурации",
            )
        else:
            output_fn("Неизвестный пункт.")


def _network_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        state = load_state(engine.fs)
        manifest = state["manifest"]
        output_fn(
            "\nСеть и защита\n"
            f" Cloudflare origin restriction: {'включено' if manifest.get('cloudflare', {}).get('enabled') else 'выключено'}\n"
            f" Firewall: {manifest.get('firewall', {}).get('mode', 'неизвестно')}\n"
            f" DNS: {', '.join(manifest.get('dns', {}).get('servers') or [])}\n"
            " 1. Полный read-only аудит listener/firewall/DNS\n"
            " 2. Проверить установленную конфигурацию\n"
            " 3. Пересобрать настройки через полный безопасный опрос\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _audit(engine, manifest["lucx"]["db_path"], output_fn)
        elif choice == "2":
            _show_operation_result(
                _validate_installed(engine, output_fn),
                output_fn,
                title="Проверка сетевой конфигурации",
            )
        elif choice == "3":
            _initial_apply(engine, manifest["lucx"]["db_path"], input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _repair_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        output_fn(
            "\nРемонт после обновления\n"
            " 1. Только check\n"
            " 2. Apply с точным планом, backup и rollback\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            _repair(engine, False, input_fn, output_fn)
        elif choice == "2":
            _repair(engine, True, input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _backup_menu(engine: Engine, input_fn: InputFn, output_fn: OutputFn) -> None:
    while True:
        output_fn(
            "\nБэкапы и откат\n"
            " 1. Показать локальные backup-транзакции\n"
            " 2. Откатить последнюю транзакцию\n"
            " 0. Назад"
        )
        choice = _read_choice("Выберите действие: ", input_fn, output_fn)
        if choice == "0":
            return
        if choice == "1":
            root = engine.fs.path(BACKUP_ROOT)
            if not root.is_dir():
                output_fn("Backup-транзакции не найдены.")
            else:
                for path in sorted(root.iterdir(), reverse=True):
                    if path.is_dir():
                        output_fn(f"- {path.name}")
        elif choice == "2":
            _rollback(engine, input_fn, output_fn)
        else:
            output_fn("Неизвестный пункт.")


def _show_quick_help(output_fn: OutputFn) -> None:
    output_fn(
        "\nКраткая справка x-tuna\n"
        "\n"
        "1. Статус и аудит\n"
        "   Только читает ОС, LucX, listener-порты, сертификаты и состояние служб.\n"
        "   Используйте перед изменениями и при диагностике.\n"
        "\n"
        "2. Первичная настройка\n"
        "   Создаёт полный план HAProxy/Nginx/firewall/DNS/sidecar для уже установленного LucX.\n"
        "   Перед применением создаётся backup; клиенты и credentials защищены.\n"
        "\n"
        "3. Домены и маршрутизация\n"
        "   Меняет DNS-зону, сохраняя левую часть имени: sub.old -> sub.new.\n"
        "   Проверяет wildcard-сертификат и синхронизирует только публичные endpoint-поля.\n"
        "\n"
        "4. Сайты-заглушки\n"
        "   Создаёт сайты на всех доменах, где браузер можно безопасно отделить от VPN.\n"
        "   Для невозможных маршрутов показывает причину и способ исправления.\n"
        "\n"
        "5. Подписки и sidecar\n"
        "   Исправляет совместимость AWG/Mieru/AnyTLS и удаляет TrustTunnel QUIC.\n"
        "   В подписках остаётся только TrustTunnel HTTPS/TCP; qWDTT не изменяется.\n"
        "\n"
        "6. Сертификаты\n"
        "   Находит или выпускает wildcard через Cloudflare API Token либо Global API Key.\n"
        "   Проверяет SAN, private key и подключает renewal hook после отдельного плана.\n"
        "\n"
        "7. Сеть и защита\n"
        "   Проверяет DNS/firewall/listeners и ограничивает внутренние порты.\n"
        "   Панель и подписка могут быть доступны origin только из сетей Cloudflare.\n"
        "\n"
        "8. Ремонт после обновления\n"
        "   Перечитывает текущую БД LucX и восстанавливает управляемую обвязку после update.\n"
        "   Исчезновение клиента или изменение credentials не принимается молча.\n"
        "\n"
        "9. Обновление LucX\n"
        "   Запускает независимый systemd-worker: backup -> updater -> repair -> health-check.\n"
        "   Поддерживает GitHub, gh-proxy, HTTP/HTTPS/SOCKS proxy, mirror и локальный файл.\n"
        "\n"
        "10. Бэкапы и откат\n"
        "   Показывает сохранённые точки и возвращает последнюю транзакцию.\n"
        "   Не удаляет пакеты APT, но восстанавливает файлы и разрешённые поля БД.\n"
        "\n"
        "11. Установка команд TUI\n"
        "   Обновляет /usr/local/sbin/x-tuna, lucx-post-configure и lucx-sub-repair.\n"
        "\n"
        "12. Перезагрузка\n"
        "   Выполняется только после отдельного подтверждения.\n"
        "\n"
        "Правило безопасности: любое изменяющее действие показывает план, backup, службы и rollback."
    )


def run_tui(
    engine: Engine,
    *,
    db_path: str | None = None,
    input_fn: InputFn = input,
    output_fn: OutputFn = print,
) -> int:
    actions = {
        "1": lambda: _status_menu(engine, db_path, input_fn, output_fn),
        "2": lambda: _initial_apply(engine, db_path, input_fn, output_fn),
        "3": lambda: _domains_menu(engine, db_path, input_fn, output_fn),
        "4": lambda: _decoy_menu(engine, input_fn, output_fn),
        "14": lambda: _trusttunnel_backend_menu(engine, input_fn, output_fn),
        "5": lambda: _sidecar_menu(engine, input_fn, output_fn),
        "6": lambda: _certificate_menu(engine, input_fn, output_fn),
        "7": lambda: _network_menu(engine, input_fn, output_fn),
        "8": lambda: _repair_menu(engine, input_fn, output_fn),
        "9": lambda: _update(engine, input_fn, output_fn),
        "10": lambda: _backup_menu(engine, input_fn, output_fn),
        "11": lambda: _install_commands(engine, input_fn, output_fn),
        "12": lambda: _reboot(engine, input_fn, output_fn),
        "13": lambda: _show_quick_help(output_fn),
    }
    while True:
        output_fn(
            "\nLucX post-configurator\n"
            + _main_state_banner(engine)
            + "\n\n"
            " 1. Статус и аудит\n"
            " 2. Первичная настройка\n"
            " 3. Домены и маршрутизация\n"
            " 4. Сайты-заглушки\n"
            " 5. Подписки и sidecar\n"
            " 6. Сертификаты\n"
            " 7. Сеть и защита\n"
            " 8. Ремонт после обновления\n"
            " 9. Обновление LucX\n"
            "10. Бэкапы и откат\n"
            "11. Установка/обновление команд TUI\n"
            "12. Перезагрузка сервера\n"
            "13. Краткая справка\n"
            "14. TrustTunnel backend\n"
            "15. Выход"
        )
        try:
            choice = input_fn("Выберите действие: ").strip()
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return 0
        if choice in {"0", "15"}:
            return 0
        if choice == "13":
            _show_quick_help(output_fn)
            return 0
        action = actions.get(choice)
        if action is None:
            output_fn("Неизвестный пункт.")
            continue
        try:
            action()
        except Exception as exc:
            output_fn(f"Ошибка: {exc}")
