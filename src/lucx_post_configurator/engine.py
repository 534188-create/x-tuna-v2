from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .certificates import acme_renewal_name
from .cloudflare import CloudflareNetworkError, fetch_cloudflare_networks
from .discovery import Audit, audit_system
from .diagnostics import build_diagnostic_report, redact, stable_fingerprint
from .extended_decoys import exact_client_random_prefix
from .integrity import capture_integrity, compare_integrity
from .models import validate_manifest
from .planner import build_plan
from .renderers import GeneratedFile, render_files
from .runner import Runner, install_packages, missing_packages
from .targetfs import TargetFS
from .transaction import (
    STATE_PATH,
    Backup,
    backup_lucx_database,
    commit_managed_transition,
    clear_failed_state,
    create_backup,
    load_state,
    load_backup,
    managed_target_digest,
    new_run_id,
    restore_backup,
    remove_staging,
    remove_managed_targets,
    rollback_latest,
    rollback_lucx_publication,
    synchronize_lucx_inbound_changes,
    save_failed_state,
    save_state,
    stage_files,
    synchronize_lucx_publication,
    validated_removal_targets,
)
from .trusttunnel_backend import (
    discover_existing_backend_credentials,
    probe_backend,
    probe_endpoint_from_manifest,
    validate_backend_manifest,
)
from .validation import (
    validate_audit_against_manifest,
    validate_certificate,
    validate_generated,
    validate_live_configuration,
    validate_lucx_tls_coverage,
    validate_public_bind_conflicts,
)


REPORT_ROOT = "/var/lib/lucx-post-configurator/reports"
SIDECAR_MANAGED_TARGETS = (
    "/usr/local/libexec/lucx-sub-sidecar.py",
    "/etc/lucx-sub-sidecar/env",
    "/etc/systemd/system/lucx-sub-sidecar.service",
)
TRUSTTUNNEL_BACKEND_MANAGED_TARGETS = (
    "/etc/x-tuna/trusttunnel/vpn.toml",
    "/etc/x-tuna/trusttunnel/hosts.toml",
    "/etc/x-tuna/trusttunnel/rules.toml",
    "/etc/x-tuna/trusttunnel/credentials.toml",
    "/etc/systemd/system/x-tuna-trusttunnel-backend.service",
)


class ApplyError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _managed_decoy_directories(manifest: dict[str, Any]) -> dict[str, int]:
    if not (
        (manifest.get("components") or {}).get("nginx")
        and (manifest.get("decoys") or {}).get("enabled")
    ):
        return {}
    base = Path("/var/www/lucx-decoys")
    result = {str(base): 0o755}
    for site in (manifest.get("decoys") or {}).get("sites") or []:
        root = Path(str(site.get("root") or ""))
        if root != base and base not in root.parents:
            raise ApplyError(f"decoy root is outside the managed directory: {root}")
        result[str(root)] = 0o755
    return result


def _ephemeral_routing_material(
    fs: TargetFS,
    audit: Audit,
    manifest: dict[str, Any],
) -> dict[int, dict[str, Any]]:
    """Load secrets only for the current transaction from exact audited paths.

    Source contents are deliberately not added to the manifest, state or report.
    """

    material: dict[int, dict[str, Any]] = {}
    audited_files = {
        str(item.get("path") or ""): item
        for item in (audit.naive_caddyfile or {}).get("files") or []
        if isinstance(item, dict) and str(item.get("path") or "").startswith("/")
    }
    for route in (manifest.get("decoys") or {}).get("extended_routes") or []:
        if route.get("strategy") != "naive_managed" or route.get("status") != "ready":
            continue
        inbound_id = int(route.get("inbound_id") or 0)
        source_path = str(route.get("source_caddyfile") or "")
        expected = str(route.get("source_caddyfile_sha256") or "").lower()
        metadata = audited_files.get(source_path)
        if inbound_id <= 0 or metadata is None:
            raise ApplyError(
                f"Naive inbound #{inbound_id or '?'} source is not the exact audited Caddyfile"
            )
        if str(metadata.get("sha256") or "").lower() != expected:
            raise ApplyError(f"Naive inbound #{inbound_id} source changed after audit")
        try:
            payload = fs.read_bytes(source_path)
        except OSError as exc:
            raise ApplyError(f"Naive inbound #{inbound_id} source cannot be read") from exc
        if len(payload) > 1024 * 1024:
            raise ApplyError(f"Naive inbound #{inbound_id} source exceeds the safe parser limit")
        current = hashlib.sha256(payload).hexdigest()
        if current != expected:
            raise ApplyError(f"Naive inbound #{inbound_id} source changed after audit")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApplyError(f"Naive inbound #{inbound_id} source is not valid UTF-8") from exc
        material[inbound_id] = {"naive_caddyfile_text": text}

    trust_routes = {
        int(route.get("inbound_id") or 0): route
        for route in (manifest.get("decoys") or {}).get("extended_routes") or []
        if route.get("strategy") == "trusttunnel_clienthello_split"
        and route.get("status") == "ready"
        and int(route.get("inbound_id") or 0) > 0
    }
    if trust_routes:
        db_path = str((manifest.get("lucx") or {}).get("db_path") or "")
        path = fs.path(db_path)
        if not path.is_file() or path.is_symlink():
            raise ApplyError("TrustTunnel routing metadata database is unavailable")
        database: sqlite3.Connection | None = None
        try:
            database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
            database.row_factory = sqlite3.Row
            database.execute("PRAGMA query_only=ON")
            columns = {
                str(row[1]) for row in database.execute("PRAGMA table_info(inbounds)")
            }
            if not {"id", "protocol", "enable", "settings"}.issubset(columns):
                raise ApplyError("TrustTunnel routing metadata schema is unsupported")
            placeholders = ",".join("?" for _ in trust_routes)
            rows = database.execute(
                "SELECT id, protocol, enable, settings FROM inbounds "
                f"WHERE id IN ({placeholders}) ORDER BY id",
                tuple(sorted(trust_routes)),
            )
            found: set[int] = set()
            for row in rows:
                inbound_id = int(row["id"])
                if not bool(row["enable"]) or str(row["protocol"] or "").lower() not in {
                    "trusttunnel",
                    "trust-tunnel",
                }:
                    continue
                try:
                    settings = json.loads(str(row["settings"] or "{}"))
                except (TypeError, ValueError):
                    settings = {}
                if not isinstance(settings, dict):
                    settings = {}
                raw_prefix = str(
                    settings.get("clientRandomPrefix")
                    or settings.get("client_random_prefix")
                    or ""
                ).strip()
                prefix = exact_client_random_prefix(raw_prefix)
                expected = str(
                    trust_routes[inbound_id].get("clienthello_match_fingerprint") or ""
                )
                if not prefix or stable_fingerprint(raw_prefix) != expected:
                    raise ApplyError(
                        f"TrustTunnel inbound #{inbound_id} routing material changed after audit"
                    )
                material[inbound_id] = {"clienthello_hex_prefix": prefix}
                found.add(inbound_id)
            missing = sorted(set(trust_routes) - found)
            if missing:
                raise ApplyError(
                    "TrustTunnel routing material is unavailable for inbound(s): "
                    + ", ".join(str(value) for value in missing)
                )
        except sqlite3.Error as exc:
            raise ApplyError("TrustTunnel routing metadata could not be read safely") from exc
        finally:
            if database is not None:
                database.close()
    return material


def _managed_naive_services(generated: dict[str, GeneratedFile]) -> list[str]:
    prefix = "/etc/systemd/system/lucx-naive-decoy-"
    result: list[str] = []
    for target, artifact in generated.items():
        if artifact.component != "naive_frontend" or not target.startswith(prefix):
            continue
        name = target.removeprefix("/etc/systemd/system/")
        suffix = name.removeprefix("lucx-naive-decoy-").removesuffix(".service")
        if name.endswith(".service") and suffix.isdigit() and int(suffix) > 0:
            result.append(name)
    return sorted(set(result), key=lambda value: int(value.split("-")[-1].split(".")[0]))


def _managed_naive_services_from_targets(targets: list[str]) -> list[str]:
    services: list[str] = []
    for target in targets:
        match = re.fullmatch(
            r"/etc/systemd/system/(lucx-naive-decoy-(\d+)\.service)", target
        )
        if match and int(match.group(2)) > 0:
            services.append(match.group(1))
    return sorted(set(services), key=lambda value: int(value.split("-")[-1].split(".")[0]))


def _component_removal_targets(
    fs: TargetFS,
    manifest: dict[str, Any],
    installed_hashes: dict[str, str],
) -> list[str]:
    requested: list[str] = []
    if not manifest.get("components", {}).get("sidecar"):
        requested.extend(SIDECAR_MANAGED_TARGETS)
    desired_naive_ids = {
        int(route.get("inbound_id") or 0)
        for route in (manifest.get("decoys") or {}).get("extended_routes") or []
        if manifest.get("components", {}).get("naive_frontend")
        and route.get("strategy") == "naive_managed"
        and route.get("status") == "ready"
        and int(route.get("inbound_id") or 0) > 0
    }
    for target in installed_hashes:
        config_match = re.fullmatch(
            r"/etc/lucx-post-configurator/naive/naive-(\d+)\.caddyfile", target
        )
        unit_match = re.fullmatch(
            r"/etc/systemd/system/lucx-naive-decoy-(\d+)\.service", target
        )
        match = config_match or unit_match
        if match and int(match.group(1)) not in desired_naive_ids:
            requested.append(target)
    if not manifest.get("components", {}).get("trusttunnel_backend"):
        requested.extend(TRUSTTUNNEL_BACKEND_MANAGED_TARGETS)
    return validated_removal_targets(fs, installed_hashes, requested)


class Engine:
    def __init__(self, root: str | Path = "/", *, runner: Runner | None = None) -> None:
        self.fs = TargetFS(root)
        self.runner = runner or Runner(dry_run=not self.fs.is_live)

    def audit(self, db_path: str | None = None) -> Audit:
        return audit_system(self.fs.root, db_path)

    @contextmanager
    def _exclusive_lock(self):
        if not self.fs.is_live:
            yield
            return
        import fcntl

        lock_path = self.fs.path("/run/lock/lucx-post-configurator.lock")
        metadata_path = self.fs.path("/run/lock/lucx-post-configurator.lock.json")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+", encoding="ascii") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                owner = ""
                try:
                    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                    pid = int(metadata.get("pid") or 0)
                    operation = str(metadata.get("operation") or "change")
                    if pid > 0:
                        os.kill(pid, 0)
                        owner = f" (PID {pid}, {operation})"
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    owner = " (владелец не определен; lock удерживается активным процессом)"
                raise ApplyError(
                    "другая операция lucx-post-configurator уже выполняется"
                    + owner
                    + "; дождитесь ее завершения"
                ) from exc
            try:
                metadata_path.write_text(
                    json.dumps(
                        {"pid": os.getpid(), "operation": "configuration", "started_at": _utc_now()},
                        ensure_ascii=True,
                    )
                    + "\n",
                    encoding="ascii",
                )
                os.chmod(metadata_path, 0o600)
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                try:
                    metadata_path.unlink()
                except FileNotFoundError:
                    pass

    def plan(self, manifest: dict[str, Any], audit: Audit | None = None) -> dict[str, Any]:
        plan = build_plan(manifest, audit)
        if self.fs.exists(STATE_PATH):
            state = load_state(self.fs)
            removals = _component_removal_targets(
                self.fs,
                manifest,
                dict(state.get("installed_hashes") or {}),
            )
            if removals:
                removal_services = _managed_naive_services_from_targets(removals)
                if "/etc/systemd/system/lucx-sub-sidecar.service" in removals:
                    removal_services.append("lucx-sub-sidecar.service")
                plan["actions"].insert(
                    1,
                    {
                        "phase": "stage",
                        "component": "managed-remove",
                        "description": (
                            "Stop and remove only unchanged disabled-component files previously "
                            "written by lucx-post-configurator"
                        ),
                        "targets": removals,
                        "reversible": True,
                        "services": sorted(set(removal_services)),
                        "database_fields": [],
                    },
                )
        return plan

    def _resolver(self) -> str:
        if not self.fs.is_live:
            return "resolvconf"
        if self.runner.available("systemctl"):
            active = self.runner.run(
                ["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False
            )
            if active.returncode == 0:
                return "systemd-resolved"
        if self.runner.available("resolvconf") or self.fs.exists("/etc/resolvconf"):
            return "resolvconf"
        resolv_conf = self.fs.path("/etc/resolv.conf")
        if resolv_conf.is_file() and not resolv_conf.is_symlink():
            return "static"
        raise ApplyError("no safely managed resolver was found (systemd-resolved, resolvconf, or a regular /etc/resolv.conf)")

    def _write_report(self, run_id: str, report: dict[str, Any]) -> None:
        safe_report = build_diagnostic_report(report=report)
        self.fs.atomic_write_text(
            f"{REPORT_ROOT}/{run_id}.json",
            json.dumps(safe_report, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        report = safe_report
        lines = [
            f"# LucX post-configurator run {run_id}",
            "",
            f"- Status: `{report.get('status', 'unknown')}`",
            f"- Started: `{report.get('started_at', '')}`",
        ]
        if report.get("completed_at"):
            lines.append(f"- Completed: `{report['completed_at']}`")
        if report.get("failed_at"):
            lines.append(f"- Failed: `{report['failed_at']}`")
        lines.extend(["", "## Phases", ""])
        for phase in report.get("phases", []):
            lines.append(f"- `{phase.get('name')}`: {phase.get('status')} at {phase.get('at', '')}")
            if phase.get("directory"):
                lines.append(f"  - Backup: `{phase['directory']}`")
        if report.get("warnings"):
            lines.extend(["", "## Warnings", ""])
            lines.extend(f"- {warning}" for warning in report["warnings"])
        if report.get("error"):
            lines.extend(["", "## First error", "", str(report["error"])])
        if report.get("rollback"):
            lines.extend(["", "## Automatic rollback", "", str(report["rollback"])])
        lines.extend(
            [
                "",
                "## Immutable scope",
                "",
                "LucX clients, inbound listeners/settings, certificate contents, and the Naive Caddyfile were not write targets. "
                "Only explicitly confirmed public URL metadata and certificate file paths may be synchronized transactionally.",
            ]
        )
        self.fs.atomic_write_text(
            f"{REPORT_ROOT}/{run_id}.md", "\n".join(lines) + "\n", mode=0o600
        )

    def _existing_dns_text(self, resolver: str) -> str:
        if resolver == "resolvconf":
            return self.fs.read_text("/etc/resolvconf/resolv.conf.d/head")
        if resolver == "static":
            return self.fs.read_text("/etc/resolv.conf")
        return ""

    def _activate(self, generated: dict[str, GeneratedFile], resolver: str) -> None:
        components = {artifact.component for artifact in generated.values()}
        if {"firewall", "sidecar", "cloudflare", "naive_frontend", "trusttunnel_backend"} & components:
            self.runner.run(["systemctl", "daemon-reload"])
        if "nginx" in components:
            self.runner.run(["systemctl", "enable", "nginx.service"])
            self.runner.run(["systemctl", "reload-or-restart", "nginx.service"])
        if "naive_frontend" in components:
            for service in _managed_naive_services(generated):
                self.runner.run(["systemctl", "enable", service])
                self.runner.run(["systemctl", "restart", service])
        if "haproxy" in components:
            self.runner.run(["systemctl", "enable", "haproxy.service"])
            self.runner.run(["systemctl", "reload-or-restart", "haproxy.service"])
        if "firewall" in components:
            self.runner.run(["systemctl", "enable", "lucx-post-firewall.service"])
            self.runner.run(["systemctl", "restart", "lucx-post-firewall.service"])
        if "sidecar" in components:
            self.runner.run(["systemctl", "enable", "lucx-sub-sidecar.service"])
            self.runner.run(["systemctl", "restart", "lucx-sub-sidecar.service"])
        if "trusttunnel_backend" in components:
            self.runner.run(["systemctl", "enable", "x-tuna-trusttunnel-backend.service"])
            self.runner.run(["systemctl", "restart", "x-tuna-trusttunnel-backend.service"])
        if "cloudflare" in components:
            self.runner.run(["systemctl", "enable", "--now", "lucx-cloudflare-ips-update.timer"])
        if "dns" in components:
            if resolver == "systemd-resolved":
                self.runner.run(["systemctl", "reload-or-restart", "systemd-resolved.service"])
            else:
                if resolver == "resolvconf":
                    self.runner.run(["resolvconf", "-u"])

    def _preserve_existing_decoy_content(
        self, generated: dict[str, GeneratedFile], manifest: dict[str, Any], report: dict[str, Any]
    ) -> None:
        for site in manifest["decoys"].get("sites", []):
            target = site["root"] + "/index.html"
            if target not in generated:
                continue
            root = self.fs.path(site["root"])
            if root.exists() and (not root.is_dir() or any(root.iterdir())):
                generated.pop(target)
                report["warnings"].append(
                    f"existing decoy content was preserved and not overwritten: {site['root']}"
                )

    def _reactivate_after_restore(
        self, generated: dict[str, GeneratedFile], resolver: str, installed_packages: list[str]
    ) -> list[str]:
        errors: list[str] = []
        try:
            if "firewall" in {artifact.component for artifact in generated.values()}:
                self.runner.run(["nft", "delete", "table", "inet", "lucx_post"], check=False)
            if not self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service"):
                self.runner.run(["systemctl", "disable", "--now", "lucx-sub-sidecar.service"], check=False)
            if not self.fs.exists("/etc/systemd/system/lucx-post-firewall.service"):
                self.runner.run(["systemctl", "disable", "--now", "lucx-post-firewall.service"], check=False)
            if not self.fs.exists("/etc/systemd/system/lucx-cloudflare-ips-update.timer"):
                self.runner.run(
                    ["systemctl", "disable", "--now", "lucx-cloudflare-ips-update.timer"],
                    check=False,
                )
            for service in _managed_naive_services(generated):
                if not self.fs.exists(f"/etc/systemd/system/{service}"):
                    self.runner.run(
                        ["systemctl", "disable", "--now", service], check=False
                    )
            for service in ("nginx", "haproxy"):
                if service in installed_packages:
                    self.runner.run(["systemctl", "disable", "--now", f"{service}.service"], check=False)
            if not self.fs.exists("/etc/haproxy/haproxy.cfg"):
                self.runner.run(
                    ["systemctl", "disable", "--now", "haproxy.service"], check=False
                )
            self.runner.run(["systemctl", "daemon-reload"], check=False)
            active_files = {
                target: artifact
                for target, artifact in generated.items()
                if not (
                    artifact.component == "sidecar"
                    and not self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service")
                )
                and not (
                    artifact.component == "firewall"
                    and not self.fs.exists("/etc/systemd/system/lucx-post-firewall.service")
                )
                and not (
                    artifact.component == "cloudflare"
                    and not self.fs.exists("/etc/systemd/system/lucx-cloudflare-ips-update.timer")
                )
                and not (
                    artifact.component == "haproxy"
                    and not self.fs.exists("/etc/haproxy/haproxy.cfg")
                )
                and not (
                    artifact.component == "naive_frontend"
                    and not (
                        self.fs.path(target).exists()
                        or self.fs.path(target).is_symlink()
                    )
                )
                and artifact.component not in set(installed_packages)
            }
            if (
                any(artifact.component == "haproxy" for artifact in active_files.values())
                and self.fs.exists("/etc/haproxy/haproxy.cfg")
            ):
                self.runner.run(
                    ["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"],
                    check=False,
                )
                self.runner.run(["systemctl", "enable", "haproxy.service"], check=False)
                self.runner.run(
                    ["systemctl", "reload-or-restart", "haproxy.service"],
                    check=False,
                )
                active_files = {
                    target: artifact
                    for target, artifact in active_files.items()
                    if artifact.component != "haproxy"
                }
            self._activate(active_files, resolver)
        except Exception as exc:
            errors.append(str(exc))
        return errors

    def _register_acme_hook(self, manifest: dict[str, Any]) -> list[str]:
        warnings: list[str] = []
        if not manifest["components"].get("tls_hook"):
            return warnings
        cert_path = manifest["certificates"]["cert_path"]
        provider = manifest["certificates"]["renewal"].get("provider", "auto")
        marker = "/.acme.sh/"
        acme_candidates = [Path("/root/.acme.sh/acme.sh")]
        if marker in cert_path:
            acme_candidates.insert(0, Path(cert_path.split(marker, 1)[0] + marker + "acme.sh"))
        acme = next((path for path in acme_candidates if path.is_file()), None)
        wants_acme = provider == "acme.sh" or (provider == "auto" and ".acme.sh/" in cert_path)
        if wants_acme:
            if acme is None:
                warnings.append("acme.sh certificate detected but acme.sh executable was not found; hook file is installed but registration was skipped")
                return warnings
            if not str(acme).startswith("/root/.acme.sh/"):
                warnings.append(
                    "a per-user acme.sh installation was detected; automatic reload registration was skipped because that user's renewal job cannot be assumed to have systemctl privileges"
                )
                return warnings
            domain = acme_renewal_name(Path(cert_path)) if marker in cert_path else ""
            if not domain:
                domain = manifest["certificates"]["renewal"].get("primary_domain") or manifest["lucx"]["panel"]["domain"]
            command = [str(acme), "--install-cert", "-d", domain]
            ecc_record = f"/root/.acme.sh/{domain}_ecc/{domain}.conf"
            if Path(cert_path).parent.name.endswith("_ecc") or self.fs.exists(ecc_record):
                command.append("--ecc")
            command.extend(["--reloadcmd", "/usr/local/sbin/lucx-tls-reload"])
            result = self.runner.run(
                command,
                check=False,
                timeout=120,
            )
            if result.returncode:
                warnings.append("acme.sh reload-hook registration failed: " + (result.stderr or result.stdout).strip())
        elif provider == "certbot" or (
            provider == "auto" and cert_path.startswith("/etc/letsencrypt/live/")
        ):
            if not self.runner.available("certbot"):
                warnings.append(
                    "Certbot certificate detected but certbot executable was not found; deploy hook exists but automatic renewal was not verified"
                )
        elif provider == "auto":
            warnings.append(
                "certificate renewal client could not be identified automatically; the reload hook was installed but must be connected to the existing renewal client"
            )
        else:
            warnings.append(f"unknown renewal provider {provider}; deploy hook was installed but not registered")
        return warnings

    def apply(self, manifest: dict[str, Any], *, audit: Audit | None = None) -> dict[str, Any]:
        with self._exclusive_lock():
            return self._apply_locked(manifest, audit=audit)

    def _apply_locked(self, manifest: dict[str, Any], *, audit: Audit | None = None) -> dict[str, Any]:
        if not self.fs.is_live:
            raise ApplyError("apply is allowed only against the live root filesystem")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise ApplyError("apply requires root privileges")
        manifest = copy.deepcopy(manifest)
        if manifest.get("components", {}).get("trusttunnel_backend"):
            backend = manifest.setdefault("trusttunnel_backend", {})
            if not backend.get("credentials"):
                backend["credentials"] = discover_existing_backend_credentials(self.fs.root)
        validate_manifest(manifest)
        if manifest.get("components", {}).get("trusttunnel_backend"):
            backend = manifest["trusttunnel_backend"]
            binary = str(backend["binary_path"])
            path = self.fs.path(binary)
            if not path.is_file() or path.is_symlink():
                raise ApplyError("TrustTunnel compatible backend binary is unavailable")
            if self.fs.sha256(binary).lower() != str(backend["sha256"]).lower():
                raise ApplyError("TrustTunnel compatible backend binary SHA-256 does not match the pinned manifest")
            try:
                probe = probe_backend(
                    self.runner,
                    binary=binary,
                    loopback_port=int(backend["listen_port"]),
                )
                probe.protocol_handshake = probe_endpoint_from_manifest(
                    manifest,
                    binary=binary,
                    listen_port=int(backend["listen_port"]),
                )
                probe.ready = bool(
                    probe.version
                    and probe.supports_tcp
                    and probe.supports_http2_connect
                    and probe.supports_standard_uri
                    and probe.supports_config_file
                    and probe.protocol_handshake
                )
                if not probe.protocol_handshake:
                    probe.reasons.append("backend не прошёл реальный staging round-trip")
                validate_backend_manifest(manifest, probe)
            except ValueError as exc:
                raise ApplyError(str(exc)) from exc
        previous_installed_hashes: dict[str, str] = {}
        if self.fs.exists(STATE_PATH):
            previous_state = load_state(self.fs)
            previous_installed_hashes = dict(previous_state.get("installed_hashes") or {})
        removal_targets = _component_removal_targets(
            self.fs,
            manifest,
            previous_installed_hashes,
        )
        # Re-audit inside the exclusive mutation lock; the interactive plan may
        # have been open while LucX or its listeners changed.
        audit = self.audit(manifest["lucx"]["db_path"])
        errors = validate_audit_against_manifest(
            audit, manifest, allow_pending_publication=True
        )
        errors.extend(validate_public_bind_conflicts(manifest, self.runner))
        if errors:
            raise ApplyError("preflight failed:\n- " + "\n- ".join(errors))

        for change in manifest.get("lucx", {}).get("inbound_changes") or []:
            if change.get("field") != "transport_path":
                continue
            inbound_id = int(change.get("inbound_id") or 0)
            for protocol in manifest.get("protocols") or []:
                if int(protocol.get("inbound_id") or 0) == inbound_id:
                    protocol["transport_path"] = str(change.get("value") or "")
        integrity_before = capture_integrity(
            self.fs,
            manifest["lucx"]["db_path"],
            audit.naive_caddyfile,
        )
        manifest["integrity"] = integrity_before
        routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
        if (manifest.get("cloudflare") or {}).get("enabled"):
            try:
                manifest["cloudflare"]["networks"] = fetch_cloudflare_networks()
            except CloudflareNetworkError as exc:
                raise ApplyError(
                    "could not obtain a validated official Cloudflare network list; no changes were made"
                ) from exc

        run_id = new_run_id()
        plan = self.plan(manifest, audit)
        report: dict[str, Any] = {
            "schema_version": 1,
            "run_id": run_id,
            "started_at": _utc_now(),
            "status": "started",
            "manifest": manifest,
            "plan": plan,
            "installed_packages": [],
            "warnings": [],
            "phases": [
                {
                    "name": "integrity-baseline",
                    "status": "ok",
                    "at": _utc_now(),
                    "naive_caddyfile": integrity_before["naive_caddyfile"],
                }
            ],
        }
        backup: Backup | None = None
        rollback_backup: Backup | None = None
        generated: dict[str, GeneratedFile] = {}
        database_changes: list[dict[str, Any]] = []
        resolver = "resolvconf"
        managed_directories = _managed_decoy_directories(manifest)
        try:
            resolver = self._resolver() if manifest["dns"].get("enabled") else "resolvconf"
            preliminary_files = render_files(
                manifest,
                resolver=resolver,
                existing_dns_text=self._existing_dns_text(resolver),
                routing_material=routing_material,
            )
            preliminary_backup = create_backup(
                self.fs,
                preliminary_files,
                run_id + "-pre",
                extra_targets=[
                    STATE_PATH,
                    "/etc/nginx/sites-enabled/default",
                    *removal_targets,
                ],
                directory_targets=managed_directories,
            )
            preliminary_database = backup_lucx_database(
                self.fs, preliminary_backup, manifest["lucx"]["db_path"]
            )
            # From this point even a partial APT transaction can be brought back
            # to the preliminary managed-file baseline.
            backup = preliminary_backup
            rollback_backup = preliminary_backup
            generated = preliminary_files
            report["phases"].append(
                {
                    "name": "pre-change-backup",
                    "status": "ok",
                    "at": _utc_now(),
                    "directory": str(preliminary_backup.directory),
                    "lucx_database_snapshot": {
                        "path": preliminary_database["path"],
                        "size": preliminary_database["size"],
                        "sha256": preliminary_database["sha256"],
                        "restore_policy": preliminary_database["restore_policy"],
                    },
                }
            )
            inbound_changes_requested = list(
                (manifest.get("lucx", {}).get("inbound_changes") or [])
            )
            if inbound_changes_requested:
                inbound_changes = synchronize_lucx_inbound_changes(
                    self.fs,
                    manifest["lucx"]["db_path"],
                    inbound_changes_requested,
                )
                database_changes.extend(inbound_changes)
                self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
                self.runner.run(
                    ["systemctl", "is-active", "--quiet", "x-ui.service"], timeout=20
                )
                audit = self.audit(manifest["lucx"]["db_path"])
                report["phases"].append(
                    {
                        "name": "lucx-inbound-sync",
                        "status": "ok",
                        "at": _utc_now(),
                        "updated_targets": [
                            f"inbound #{change['inbound_id']} transport_path"
                            for change in inbound_changes
                        ],
                    }
                )
                # Inbound transport metadata is now authoritative. Rebuild
                # the staged configuration from the fresh audit so an XHTTP
                # path change is reflected in HAProxy and health checks.
                audit = self.audit(manifest["lucx"]["db_path"])
                routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
                generated = render_files(
                    manifest,
                    resolver=resolver,
                    existing_dns_text=self._existing_dns_text(resolver),
                    routing_material=routing_material,
                )
            settings_management = manifest.get("lucx", {}).get("settings_management") or {}
            if any(
                settings_management.get(key)
                for key in (
                    "sync_domains",
                    "sync_panel_path",
                    "sync_subscription_urls",
                    "sync_naive_share_addr",
                    "sync_public_endpoints",
                    "sync_certificate_paths",
                    "sync_naive_endpoint",
                )
            ):
                public_publications = [
                    {
                        "inbound_id": protocol["inbound_id"],
                        "domain": protocol["domain"],
                        "public_port": protocol["public_port"],
                    }
                    for protocol in manifest.get("protocols", [])
                    if protocol.get("sync_public_endpoint")
                ]
                naive_endpoint_updates = [
                    {
                        "inbound_id": protocol["inbound_id"],
                        "domain": protocol["domain"],
                        "cert_path": manifest["certificates"]["cert_path"],
                        "key_path": manifest["certificates"]["key_path"],
                    }
                    for protocol in manifest.get("protocols", [])
                    if protocol.get("protocol") == "naive"
                    and protocol.get("sync_naive_endpoint")
                ]
                database_changes.extend(synchronize_lucx_publication(
                    self.fs,
                    manifest["lucx"]["db_path"],
                    panel_domain=(
                        manifest["lucx"]["panel"]["domain"]
                        if settings_management.get("sync_domains")
                        else None
                    ),
                    subscription_domain=(
                        manifest["lucx"]["subscription"]["domain"]
                        if settings_management.get("sync_domains")
                        else None
                    ),
                    panel_path=(
                        manifest["lucx"]["panel"].get("path_prefix", "/")
                        if settings_management.get("sync_panel_path")
                        else None
                    ),
                    subscription_base_url=(
                        manifest["lucx"].get("subscription", {}).get("public_base_url")
                        if settings_management.get("sync_subscription_urls")
                        else None
                    ),
                    public_publications=public_publications,
                    naive_endpoint_updates=naive_endpoint_updates,
                    certificate_paths=(
                        {
                            "cert_path": manifest["certificates"]["cert_path"],
                            "key_path": manifest["certificates"]["key_path"],
                        }
                        if settings_management.get("sync_certificate_paths")
                        else None
                    ),
                ))
                if database_changes:
                    self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
                    self.runner.run(
                        ["systemctl", "is-active", "--quiet", "x-ui.service"],
                        timeout=20,
                    )
                audit = self.audit(manifest["lucx"]["db_path"])
                domain_errors = validate_audit_against_manifest(audit, manifest)
                if domain_errors:
                    raise ApplyError(
                        "LucX domain synchronization verification failed:\n- "
                        + "\n- ".join(domain_errors)
                    )
                if database_changes:
                    # The x-ui restart above makes LucX regenerate its Naive
                    # Caddyfile. That regeneration is expected, not tampering:
                    # re-baseline the Naive snapshot so the post-commit
                    # integrity check does not roll back a healthy apply.
                    integrity_before["naive_caddyfile"] = capture_integrity(
                        self.fs,
                        manifest["lucx"]["db_path"],
                        audit.naive_caddyfile,
                    )["naive_caddyfile"]
                    report["warnings"].append(
                        "Naive Caddyfile was regenerated by LucX after publication sync; integrity baseline was updated"
                    )
                routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
                report["phases"].append(
                    {
                        "name": "lucx-publication-sync",
                        "status": "ok",
                        "at": _utc_now(),
                        "updated_targets": [
                            (
                                change.get("key")
                                or (
                                    f"host #{change.get('host_id')} for inbound #{change.get('inbound_id')} endpoint"
                                    if change.get("kind") == "inbound_host_endpoint"
                                    else f"inbound #{change.get('inbound_id')} share_addr"
                                )
                            )
                            for change in database_changes
                        ],
                    }
                )
            if manifest["components"].get("install_packages"):
                planned_missing = missing_packages(plan["packages"], self.runner)
                report["installed_packages"] = planned_missing
                report["installed_packages"] = install_packages(
                    plan["packages"], self.runner, missing=planned_missing
                )
                # Debian package post-install scripts may auto-start stock listeners.
                # Keep newly installed frontends stopped until their staged configs pass.
                for service in ("nginx", "haproxy"):
                    if service in report["installed_packages"]:
                        self.runner.run(
                            ["systemctl", "disable", "--now", f"{service}.service"],
                            check=False,
                        )
            report["phases"].append({"name": "prerequisites", "status": "ok", "at": _utc_now()})

            # Re-read the database immediately before final rendering. Package
            # hooks or a concurrent LucX update must not leave us rendering an
            # old listener/SNI/ClientHello plan.
            audit = self.audit(manifest["lucx"]["db_path"])
            topology_errors = validate_audit_against_manifest(audit, manifest)
            if topology_errors:
                raise ApplyError(
                    "LucX topology changed before final rendering:\n- "
                    + "\n- ".join(topology_errors)
                )
            routing_material = _ephemeral_routing_material(self.fs, audit, manifest)
            report["phases"].append(
                {
                    "name": "final-read-only-audit",
                    "status": "ok",
                    "at": _utc_now(),
                }
            )

            cert_errors = validate_certificate(self.fs, manifest, self.runner)
            cert_errors.extend(
                validate_lucx_tls_coverage(self.fs, audit, manifest, self.runner)
            )
            if cert_errors:
                raise ApplyError("certificate validation failed:\n- " + "\n- ".join(cert_errors))
            resolver = self._resolver() if manifest["dns"].get("enabled") else "resolvconf"
            generated = render_files(
                manifest,
                resolver=resolver,
                existing_dns_text=self._existing_dns_text(resolver),
                routing_material=routing_material,
            )
            if "nginx" in report["installed_packages"]:
                default_site = self.fs.path("/etc/nginx/sites-enabled/default")
                if default_site.exists() or default_site.is_symlink():
                    generated["/etc/nginx/sites-enabled/default"] = GeneratedFile(
                        b"# Disabled by lucx-post-configurator: no public stock Nginx listener.\n",
                        component="nginx",
                    )
                    report["warnings"].append(
                        "the stock Nginx default site was disabled because this run installed Nginx"
                    )
            self._preserve_existing_decoy_content(generated, manifest, report)
            report["phases"].append({"name": "render", "status": "ok", "at": _utc_now(), "files": sorted(generated)})

            backup = create_backup(
                self.fs,
                generated,
                run_id,
                extra_targets=[STATE_PATH, *removal_targets],
                directory_targets=managed_directories,
            )
            database_snapshot = backup_lucx_database(
                self.fs, backup, manifest["lucx"]["db_path"]
            )
            report["phases"].append({"name": "backup", "status": "ok", "at": _utc_now(), "directory": str(backup.directory)})
            report["phases"][-1]["lucx_database_snapshot"] = {
                "path": database_snapshot["path"],
                "size": database_snapshot["size"],
                "sha256": database_snapshot["sha256"],
                "restore_policy": database_snapshot["restore_policy"],
            }
            staged = stage_files(self.fs, generated, run_id)
            generated_errors = validate_generated(self.fs, generated, staged, manifest, self.runner)
            if generated_errors:
                raise ApplyError("staged validation failed:\n- " + "\n- ".join(generated_errors))
            report["phases"].append({"name": "validate-staged", "status": "ok", "at": _utc_now()})

            if "/etc/systemd/system/lucx-sub-sidecar.service" in removal_targets:
                self.runner.run(
                    ["systemctl", "disable", "--now", "lucx-sub-sidecar.service"]
                )
            for service in _managed_naive_services_from_targets(removal_targets):
                self.runner.run(["systemctl", "disable", "--now", service])
            installed_hashes = commit_managed_transition(
                self.fs,
                generated,
                removal_targets,
                previous_installed_hashes,
                directory_targets=managed_directories,
            )
            if removal_targets:
                self.runner.run(["systemctl", "daemon-reload"])
            report["phases"].append({"name": "commit", "status": "ok", "at": _utc_now()})
            if removal_targets:
                report["phases"].append(
                    {
                        "name": "remove-disabled-components",
                        "status": "ok",
                        "at": _utc_now(),
                        "files": removal_targets,
                    }
                )
            self._activate(generated, resolver)
            decoy_results: list[dict[str, Any]] = []
            live_audit = self.audit(manifest["lucx"]["db_path"])
            live_errors = validate_live_configuration(
                manifest,
                self.runner,
                fs=self.fs,
                audit=live_audit,
                decoy_results=decoy_results,
            )
            if live_errors:
                raise ApplyError("health checks failed:\n- " + "\n- ".join(live_errors))
            for item in decoy_results:
                if not item["managed"] and item["state"] not in {"site_observed", "skipped"}:
                    report["warnings"].append(
                        f"passive decoy observation for {item['domain']} did not confirm a site: {item['detail']}"
                    )
            report["phases"].append(
                {
                    "name": "health",
                    "status": "ok",
                    "at": _utc_now(),
                    "decoys": decoy_results,
                }
            )
            integrity_after = capture_integrity(
                self.fs,
                manifest["lucx"]["db_path"],
                audit.naive_caddyfile,
            )
            integrity_errors = compare_integrity(
                integrity_before,
                integrity_after,
                database_changes,
                naive_content_volatile=bool(
                    (manifest.get("lucx", {}).get("settings_management") or {}).get(
                        "sync_public_endpoints"
                    )
                ),
            )
            if integrity_errors:
                raise ApplyError(
                    "protected LucX/Naive integrity check failed:\n- "
                    + "\n- ".join(integrity_errors)
                )
            manifest["integrity"] = integrity_after
            report["manifest"] = manifest
            report["phases"].append(
                {"name": "integrity-final", "status": "ok", "at": _utc_now()}
            )
            report["warnings"].extend(self._register_acme_hook(manifest))
            report["status"] = "complete"
            report["completed_at"] = _utc_now()
            state = {
                "schema_version": 1,
                "status": "complete",
                "run_id": run_id,
                "manifest": manifest,
                "installed_hashes": installed_hashes,
                "installed_packages": report["installed_packages"],
                "lucx_database_path": manifest["lucx"]["db_path"],
                "lucx_publication_changes": database_changes,
                "rollback_backup_id": rollback_backup.run_id if rollback_backup else run_id,
                "completed_at": report["completed_at"],
            }
            save_state(self.fs, state)
            clear_failed_state(self.fs)
            self._write_report(run_id, report)
            return report
        except Exception as exc:
            report["status"] = "failed"
            report["error"] = redact(str(exc))
            report["failed_at"] = _utc_now()
            selected_rollback = rollback_backup or backup
            if selected_rollback is not None:
                try:
                    restore_backup(self.fs, selected_rollback)
                    if database_changes:
                        rollback_lucx_publication(
                            self.fs,
                            manifest["lucx"]["db_path"],
                            database_changes,
                        )
                        self.runner.run(
                            ["systemctl", "restart", "x-ui.service"],
                            check=False,
                            timeout=60,
                        )
                    rollback_service_errors = self._reactivate_after_restore(
                        generated, resolver, report["installed_packages"]
                    )
                    if (
                        "/etc/systemd/system/lucx-sub-sidecar.service" in removal_targets
                        and self.fs.exists("/etc/systemd/system/lucx-sub-sidecar.service")
                    ):
                        self.runner.run(["systemctl", "daemon-reload"], check=False)
                        self.runner.run(
                            ["systemctl", "enable", "lucx-sub-sidecar.service"],
                            check=False,
                        )
                        self.runner.run(
                            ["systemctl", "restart", "lucx-sub-sidecar.service"],
                            check=False,
                        )
                    for service in _managed_naive_services_from_targets(removal_targets):
                        unit = f"/etc/systemd/system/{service}"
                        if self.fs.exists(unit):
                            self.runner.run(["systemctl", "daemon-reload"], check=False)
                            self.runner.run(["systemctl", "enable", service], check=False)
                            self.runner.run(["systemctl", "restart", service], check=False)
                    if rollback_service_errors:
                        report["rollback"] = "files-restored-service-errors"
                        report["rollback_service_errors"] = rollback_service_errors
                    else:
                        report["rollback"] = "complete"
                    rollback_integrity = capture_integrity(
                        self.fs,
                        manifest["lucx"]["db_path"],
                        audit.naive_caddyfile,
                    )
                    rollback_integrity_errors = compare_integrity(
                        integrity_before,
                        rollback_integrity,
                        [],
                    )
                    if rollback_integrity_errors:
                        report["rollback_integrity_errors"] = rollback_integrity_errors
                except Exception as rollback_exc:
                    report["rollback"] = "failed"
                    report["rollback_error"] = str(rollback_exc)
            try:
                self._write_report(run_id, report)
            except OSError:
                pass
            try:
                save_failed_state(
                    self.fs,
                    {
                        "schema_version": 1,
                        "status": "failed",
                        "run_id": run_id,
                        "manifest": manifest,
                        "error": redact(str(exc)),
                        "rollback": report.get("rollback", "not-needed"),
                    },
                )
            except OSError:
                pass
            if isinstance(exc, ApplyError):
                raise
            raise ApplyError(str(exc)) from exc
        finally:
            try:
                remove_staging(self.fs, run_id)
            except OSError:
                pass

    def rollback(self, *, force: bool = False) -> str:
        with self._exclusive_lock():
            return self._rollback_locked(force=force)

    def _rollback_locked(self, *, force: bool = False) -> str:
        state = load_state(self.fs)
        manifest = state["manifest"]
        backup = load_backup(self.fs, state.get("rollback_backup_id", state["run_id"]))
        entries = {entry["target"]: entry for entry in backup.metadata["entries"]}
        run_id = rollback_latest(self.fs, force=force)
        database_changes = list(
            state.get("lucx_publication_changes")
            or state.get("lucx_domain_changes")
            or []
        )
        if database_changes:
            rollback_lucx_publication(
                self.fs,
                str(state.get("lucx_database_path") or manifest["lucx"]["db_path"]),
                database_changes,
            )
            self.runner.run(["systemctl", "restart", "x-ui.service"], timeout=60)
        newly_installed_services = {
            service for service in ("nginx", "haproxy") if service in state.get("installed_packages", [])
        }
        for service in newly_installed_services:
            self.runner.run(["systemctl", "disable", "--now", f"{service}.service"], check=False)

        firewall_existed = entries.get("/etc/systemd/system/lucx-post-firewall.service", {}).get("existed", False)
        sidecar_existed = entries.get("/etc/systemd/system/lucx-sub-sidecar.service", {}).get("existed", False)
        cloudflare_timer_existed = entries.get(
            "/etc/systemd/system/lucx-cloudflare-ips-update.timer", {}
        ).get("existed", False)
        naive_units = [
            (target, bool(entry.get("existed")))
            for target, entry in sorted(entries.items())
            if re.fullmatch(
                r"/etc/systemd/system/lucx-naive-decoy-\d+\.service", target
            )
        ]
        self.runner.run(["nft", "delete", "table", "inet", "lucx_post"], check=False)
        if not firewall_existed:
            self.runner.run(["systemctl", "disable", "--now", "lucx-post-firewall.service"], check=False)
        if not sidecar_existed:
            self.runner.run(["systemctl", "disable", "--now", "lucx-sub-sidecar.service"], check=False)
        if not cloudflare_timer_existed:
            self.runner.run(
                ["systemctl", "disable", "--now", "lucx-cloudflare-ips-update.timer"],
                check=False,
            )
        for target, existed in naive_units:
            if not existed:
                self.runner.run(
                    [
                        "systemctl",
                        "disable",
                        "--now",
                        target.removeprefix("/etc/systemd/system/"),
                    ],
                    check=False,
                )
        self.runner.run(["systemctl", "daemon-reload"])
        if (
            manifest["components"].get("haproxy")
            and "haproxy" not in newly_installed_services
            and self.fs.exists("/etc/haproxy/haproxy.cfg")
        ):
            self.runner.run(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"])
            self.runner.run(["systemctl", "reload-or-restart", "haproxy.service"])
        if manifest["components"].get("nginx") and "nginx" not in newly_installed_services:
            self.runner.run(["nginx", "-t"])
            self.runner.run(["systemctl", "reload-or-restart", "nginx.service"])
        for target, existed in naive_units:
            service = target.removeprefix("/etc/systemd/system/")
            if existed and self.fs.exists(target):
                self.runner.run(["systemctl", "enable", service])
                self.runner.run(["systemctl", "restart", service])
        if firewall_existed:
            self.runner.run(["systemctl", "restart", "lucx-post-firewall.service"])
        if sidecar_existed:
            self.runner.run(["systemctl", "restart", "lucx-sub-sidecar.service"])
        if cloudflare_timer_existed:
            self.runner.run(["systemctl", "restart", "lucx-cloudflare-ips-update.timer"])
        if manifest["dns"].get("enabled"):
            if self.runner.available("resolvconf"):
                self.runner.run(["resolvconf", "-u"])
            elif self.runner.run(["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False).returncode == 0:
                self.runner.run(["systemctl", "reload-or-restart", "systemd-resolved.service"])
        return run_id

    def validate_installed(self, *, include_live: bool = True) -> dict[str, Any]:
        state = load_state(self.fs)
        manifest = state["manifest"]
        audit = self.audit(manifest["lucx"]["db_path"])
        errors = validate_audit_against_manifest(audit, manifest)
        errors.extend(validate_certificate(self.fs, manifest, self.runner))
        errors.extend(validate_lucx_tls_coverage(self.fs, audit, manifest, self.runner))
        if self.fs.is_live and include_live:
            errors.extend(validate_live_configuration(manifest, self.runner, fs=self.fs, audit=audit))
        changed = []
        for target, expected in (state.get("installed_hashes") or {}).items():
            path = self.fs.path(target)
            if not (path.exists() or path.is_symlink()) or managed_target_digest(self.fs, target) != expected:
                changed.append(target)
        return {"ok": not errors and not changed, "errors": errors, "changed_managed_files": changed, "run_id": state["run_id"]}
