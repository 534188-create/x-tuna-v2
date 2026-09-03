from __future__ import annotations

import tempfile
import unittest
import os
import json
import sqlite3
from pathlib import Path
from unittest import mock

from lucx_post_configurator.renderers import GeneratedFile
from lucx_post_configurator.targetfs import TargetFS
from lucx_post_configurator.transaction import (
    backup_lucx_database,
    commit_files,
    create_backup,
    managed_target_digest,
    rollback_lucx_publication,
    synchronize_lucx_inbound_changes,
    restore_backup,
    synchronize_lucx_publication,
    stage_files,
)

from helpers import make_target


class TransactionTests(unittest.TestCase):
    def test_state_does_not_persist_backend_passwords(self) -> None:
        from lucx_post_configurator.transaction import load_state, save_state

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "var/lib/lucx-post-configurator").mkdir(parents=True)
            fs = TargetFS(root)
            state = {
                "manifest": {
                    "trusttunnel_backend": {
                        "credentials": [{"username": "alice", "password": "secret"}],
                    }
                }
            }
            save_state(fs, state)
            saved = (root / "var/lib/lucx-post-configurator/state.json").read_text(encoding="utf-8")
            self.assertNotIn("secret", saved)
            self.assertIn('"credentials": []', saved)
            self.assertIn('"credentials_file": "/etc/x-tuna/trusttunnel/credentials.toml"', saved)
    def test_xhttp_path_change_preserves_clients_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            original_settings = connection.execute(
                "SELECT settings FROM inbounds WHERE id = 1"
            ).fetchone()[0]
            original_stream = '{"network":"xhttp","security":"tls","xhttpSettings":{"path":"/","mode":"auto"},"tlsSettings":{"serverName":"example.com"}}'
            connection.execute(
                "UPDATE inbounds SET protocol = 'vless', stream_settings = ? WHERE id = 1",
                (original_stream,),
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_inbound_changes(
                fs,
                "/etc/x-ui/x-ui.db",
                [{"inbound_id": 1, "field": "transport_path", "value": "/xhttp-1"}],
            )
            connection = sqlite3.connect(db)
            changed_stream, changed_settings = connection.execute(
                "SELECT stream_settings, settings FROM inbounds WHERE id = 1"
            ).fetchone()
            connection.close()
            self.assertEqual(changed_settings, original_settings)
            self.assertEqual(json.loads(changed_stream)["xhttpSettings"]["path"], "/xhttp-1")
            self.assertEqual(json.loads(changed_stream)["tlsSettings"]["serverName"], "example.com")
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            restored = connection.execute(
                "SELECT stream_settings FROM inbounds WHERE id = 1"
            ).fetchone()[0]
            connection.close()
            self.assertEqual(restored, original_stream)

    def test_inbound_and_publication_changes_can_share_one_rollback_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            connection.execute(
                "UPDATE inbounds SET protocol = 'vless', stream_settings = ? WHERE id = 1",
                ('{"xhttpSettings":{"path":"/"}}',),
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_inbound_changes(
                fs,
                "/etc/x-ui/x-ui.db",
                [{"inbound_id": 1, "field": "transport_path", "value": "/xhttp-1"}],
            )
            changes.extend(
                synchronize_lucx_publication(
                    fs,
                    "/etc/x-ui/x-ui.db",
                    panel_domain="panel.example.com",
                    subscription_domain="sub.example.com",
                    public_publications=[
                        {"inbound_id": 1, "domain": "new.example.com", "public_port": 443}
                    ],
                )
            )
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            try:
                stream, share_addr = connection.execute(
                    "SELECT stream_settings, share_addr FROM inbounds WHERE id = 1"
                ).fetchone()
            finally:
                connection.close()
            self.assertEqual(stream, '{"xhttpSettings":{"path":"/"}}')
            self.assertEqual(share_addr, "api.example.com")

    def test_public_endpoint_sync_updates_all_selected_inbounds_and_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            connection = sqlite3.connect(db)
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (11, 1, 0, 0, 'api.example.com', 443)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (12, 2, 0, 0, 'cloud.example.com', 443)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (13, 2, 1, 1, 'disabled.example.com', 8443)"
            )
            connection.commit()
            connection.close()
            fs = TargetFS(root)
            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                public_publications=[
                    {"inbound_id": 1, "domain": "one.new.example", "public_port": 443},
                    {"inbound_id": 2, "domain": "two.new.example", "public_port": 443},
                ],
            )
            connection = sqlite3.connect(db)
            try:
                values = dict(connection.execute("SELECT id, share_addr FROM inbounds WHERE id IN (1,2)"))
                hosts = list(connection.execute("SELECT id, address, port FROM hosts ORDER BY id"))
                ports = dict(connection.execute("SELECT id, port FROM inbounds WHERE id IN (1,2)"))
            finally:
                connection.close()
            self.assertEqual(values, {1: "one.new.example:443", 2: "two.new.example:443"})
            self.assertEqual(hosts, [(11, "one.new.example", 443), (12, "two.new.example", 443), (13, "disabled.example.com", 8443)])
            self.assertEqual(ports, {1: 54703, 2: 443})
            self.assertEqual(
                {change["kind"] for change in changes},
                {"inbound_share_addr", "inbound_host_endpoint"},
            )

    def test_certificate_path_sync_is_targeted_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            db = make_target(root)
            fs = TargetFS(root)
            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                certificate_paths={
                    "cert_path": "/etc/letsencrypt/live/example.com/fullchain.pem",
                    "key_path": "/etc/letsencrypt/live/example.com/privkey.pem",
                },
            )
            connection = sqlite3.connect(db)
            try:
                values = dict(connection.execute("SELECT key, value FROM settings"))
            finally:
                connection.close()
            self.assertEqual(values["webCertFile"], "/etc/letsencrypt/live/example.com/fullchain.pem")
            self.assertEqual(values["subKeyFile"], "/etc/letsencrypt/live/example.com/privkey.pem")
            self.assertEqual(
                {item["key"] for item in changes},
                {"webCertFile", "webKeyFile", "subCertFile", "subKeyFile"},
            )
            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = sqlite3.connect(db)
            try:
                restored = dict(connection.execute("SELECT key, value FROM settings"))
            finally:
                connection.close()
            self.assertEqual(restored["webCertFile"], "/cert/fullchain.pem")
            self.assertEqual(restored["subKeyFile"], "/cert/privkey.pem")

    def test_backup_commit_and_restore_existing_and_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fs = TargetFS(temporary)
            fs.atomic_write_text("/etc/existing.conf", "old\n", mode=0o600)
            generated = {
                "/etc/existing.conf": GeneratedFile(b"new\n", 0o644),
                "/etc/new.conf": GeneratedFile(b"created\n", 0o640),
            }
            backup = create_backup(fs, generated, "run-test")
            commit_files(fs, generated)
            self.assertEqual(fs.read_text("/etc/existing.conf"), "new\n")
            self.assertTrue(fs.exists("/etc/new.conf"))
            restore_backup(fs, backup)
            self.assertEqual(fs.read_text("/etc/existing.conf"), "old\n")
            self.assertFalse(fs.exists("/etc/new.conf"))

    def test_managed_decoy_directory_modes_are_committed_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "var/www/lucx-decoys/existing.example.net").mkdir(parents=True)
            existing = root / "var/www/lucx-decoys/existing.example.net"
            os.chmod(root / "var/www/lucx-decoys", 0o700)
            os.chmod(existing, 0o700)
            fs = TargetFS(root)
            generated = {
                "/var/www/lucx-decoys/existing.example.net/index.html": GeneratedFile(
                    b"existing\n"
                ),
                "/var/www/lucx-decoys/new.example.net/index.html": GeneratedFile(b"new\n"),
            }
            directories = {
                "/var/www/lucx-decoys": 0o755,
                "/var/www/lucx-decoys/existing.example.net": 0o755,
                "/var/www/lucx-decoys/new.example.net": 0o755,
            }

            backup = create_backup(
                fs,
                generated,
                "directory-run",
                directory_targets=directories,
            )
            with mock.patch(
                "lucx_post_configurator.transaction.os.chmod", wraps=os.chmod
            ) as chmod:
                commit_files(fs, generated, directory_targets=directories)
                for target in directories:
                    chmod.assert_any_call(fs.path(target), 0o755)

                if os.name != "nt":
                    self.assertEqual(
                        (root / "var/www/lucx-decoys").stat().st_mode & 0o777,
                        0o755,
                    )
                    self.assertEqual(existing.stat().st_mode & 0o777, 0o755)

                restore_backup(fs, backup)

            if os.name != "nt":
                self.assertEqual((root / "var/www/lucx-decoys").stat().st_mode & 0o777, 0o700)
                self.assertEqual(existing.stat().st_mode & 0o777, 0o700)
            self.assertFalse((root / "var/www/lucx-decoys/new.example.net").exists())

    def test_backup_and_restore_preserves_a_symlink_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            available = root / "etc/nginx/sites-available"
            enabled = root / "etc/nginx/sites-enabled"
            available.mkdir(parents=True)
            enabled.mkdir(parents=True)
            (available / "default").write_text("stock\n", encoding="utf-8")
            link = enabled / "default"
            try:
                os.symlink("../sites-available/default", link)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            fs = TargetFS(root)
            generated = {"/etc/nginx/sites-enabled/default": GeneratedFile(b"disabled\n")}
            backup = create_backup(fs, generated, "symlink-run")
            commit_files(fs, generated)
            self.assertFalse(link.is_symlink())
            restore_backup(fs, backup)
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "../sites-available/default")

    def test_managed_tls_symlinks_are_staged_committed_and_rollback_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cert").mkdir(parents=True)
            (root / "cert/fullchain.pem").write_text("certificate-one\n", encoding="utf-8")
            (root / "cert/privkey.pem").write_text("key-one\n", encoding="utf-8")
            fs = TargetFS(root)
            generated = {
                "/etc/lucx-post-configurator/tls/certificate.pem": GeneratedFile(
                    symlink_target="/cert/fullchain.pem", mode=0o640, component="haproxy"
                ),
                "/etc/lucx-post-configurator/tls/certificate.pem.key": GeneratedFile(
                    symlink_target="/cert/privkey.pem", mode=0o640, component="haproxy"
                ),
            }
            backup = create_backup(fs, generated, "tls-links")
            try:
                staged = stage_files(fs, generated, "tls-links-stage")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            self.assertTrue(staged["/etc/lucx-post-configurator/tls/certificate.pem"].is_symlink())

            installed = commit_files(fs, generated)
            cert_link = fs.path("/etc/lucx-post-configurator/tls/certificate.pem")
            key_link = fs.path("/etc/lucx-post-configurator/tls/certificate.pem.key")
            self.assertTrue(cert_link.is_symlink())
            self.assertTrue(key_link.is_symlink())
            self.assertEqual(os.readlink(cert_link), "/cert/fullchain.pem")
            before = installed["/etc/lucx-post-configurator/tls/certificate.pem"]
            (root / "cert/fullchain.pem").write_text("certificate-renewed\n", encoding="utf-8")
            self.assertEqual(
                managed_target_digest(fs, "/etc/lucx-post-configurator/tls/certificate.pem"),
                before,
            )

            restore_backup(fs, backup)
            self.assertFalse(cert_link.exists() or cert_link.is_symlink())
            self.assertFalse(key_link.exists() or key_link.is_symlink())

    def test_consistent_lucx_database_snapshot_is_sensitive_and_manual_restore_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            fs = TargetFS(root)
            backup = create_backup(fs, {}, "db-run")
            record = backup_lucx_database(fs, backup, "/etc/x-ui/x-ui.db")
            snapshot = backup.directory / record["path"]
            self.assertTrue(snapshot.is_file())
            self.assertTrue(record["sensitive"])
            self.assertIn("manual", record["restore_policy"])
            self.assertGreater(record["size"], 0)

    def test_domain_synchronization_touches_only_two_settings_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute("UPDATE settings SET value = '' WHERE key = 'subDomain'")
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', share_addr = 'old-naive.example.com' WHERE id = 1"
            )
            before_other = connection.execute(
                "SELECT value FROM settings WHERE key = 'webPort'"
            ).fetchone()[0]
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="new-panel.example.com",
                subscription_domain="new-sub.example.com",
                panel_path="/",
                naive_publications=[
                    {"inbound_id": 1, "domain": "naive.example.com", "public_port": 443}
                ],
            )
            self.assertEqual(
                {item.get("key") for item in changes if item["kind"] == "setting"},
                {"webDomain", "subDomain", "webBasePath"},
            )
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["webDomain"], "new-panel.example.com")
            self.assertEqual(values["subDomain"], "new-sub.example.com")
            self.assertEqual(values["webPort"], before_other)
            connection = __import__("sqlite3").connect(database)
            try:
                self.assertEqual(
                    connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0],
                    "naive.example.com:443",
                )
            finally:
                connection.close()

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["webDomain"], "panel.example.com")
            self.assertEqual(values["subDomain"], "")
            connection = __import__("sqlite3").connect(database)
            try:
                self.assertEqual(
                    connection.execute("SELECT share_addr FROM inbounds WHERE id=1").fetchone()[0],
                    "old-naive.example.com",
                )
            finally:
                connection.close()

    def test_subscription_base_url_sync_writes_sub_uris_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute("UPDATE settings SET value = '' WHERE key = 'subURI'")
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain=None,
                subscription_domain=None,
                subscription_base_url="https://sub.example.com/",
            )
            self.assertEqual(
                {item.get("key") for item in changes if item["kind"] == "setting"},
                {"subURI", "subJsonURI", "subClashURI"},
            )
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertEqual(values["subURI"], "https://sub.example.com/sub/")
            self.assertEqual(values["subJsonURI"], "https://sub.example.com/json/")
            self.assertEqual(values["subClashURI"], "https://sub.example.com/clash/")

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            values = dict(connection.execute("SELECT key, value FROM settings"))
            connection.close()
            self.assertNotIn("subURI", values)

    def test_subscription_base_url_requires_absolute_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_target(root)
            fs = TargetFS(root)
            for bad in ("sub.example.com", "ftp://sub.example.com/", "https://"):
                with self.assertRaises(RuntimeError):
                    synchronize_lucx_publication(
                        fs,
                        "/etc/x-ui/x-ui.db",
                        panel_domain=None,
                        subscription_domain=None,
                        subscription_base_url=bad,
                    )

    def test_naive_sync_updates_enabled_hosts_and_rolls_them_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = make_target(root)
            fs = TargetFS(root)
            connection = __import__("sqlite3").connect(database)
            connection.execute(
                "UPDATE inbounds SET protocol = 'naive', share_addr = 'old.example.com:8443' WHERE id = 1"
            )
            connection.execute(
                "CREATE TABLE hosts (id INTEGER PRIMARY KEY, inbound_id INTEGER, sort_order INTEGER, is_disabled INTEGER, address TEXT, port INTEGER, remark TEXT)"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (10,1,0,0,'old.example.com',8443,'keep-me')"
            )
            connection.execute(
                "INSERT INTO hosts VALUES (11,1,1,1,'disabled.example.com',2053,'disabled')"
            )
            connection.commit()
            connection.close()

            changes = synchronize_lucx_publication(
                fs,
                "/etc/x-ui/x-ui.db",
                panel_domain="panel.example.com",
                subscription_domain="sub.example.com",
                naive_publications=[
                    {"inbound_id": 1, "domain": "naive.example.com", "public_port": 443}
                ],
            )
            self.assertEqual(
                len([item for item in changes if item["kind"] == "inbound_host_endpoint"]),
                1,
            )
            connection = __import__("sqlite3").connect(database)
            try:
                enabled = connection.execute(
                    "SELECT address, port, remark FROM hosts WHERE id = 10"
                ).fetchone()
                disabled = connection.execute(
                    "SELECT address, port FROM hosts WHERE id = 11"
                ).fetchone()
                self.assertEqual(enabled, ("naive.example.com", 443, "keep-me"))
                self.assertEqual(disabled, ("disabled.example.com", 2053))
            finally:
                connection.close()

            rollback_lucx_publication(fs, "/etc/x-ui/x-ui.db", changes)
            connection = __import__("sqlite3").connect(database)
            try:
                enabled = connection.execute(
                    "SELECT address, port, remark FROM hosts WHERE id = 10"
                ).fetchone()
                self.assertEqual(enabled, ("old.example.com", 8443, "keep-me"))
            finally:
                connection.close()


if __name__ == "__main__":
    unittest.main()
