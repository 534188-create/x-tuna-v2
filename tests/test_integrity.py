from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lucx_post_configurator.integrity import (
    capture_integrity,
    compare_caddy,
    compare_integrity,
    compare_lucx,
)
from lucx_post_configurator.targetfs import TargetFS

from helpers import make_target


class IntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = make_target(self.root)
        caddy = self.root / "etc/caddy/Caddyfile"
        caddy.parent.mkdir(parents=True)
        caddy.write_text("naive.example.com { respond ok }\n", encoding="utf-8")
        os.chmod(caddy, 0o640)
        self.fs = TargetFS(self.root)
        self.caddy_info = {"found": True, "path": "/etc/caddy/Caddyfile"}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def capture(self) -> dict:
        return capture_integrity(self.fs, "/etc/x-ui/x-ui.db", self.caddy_info)

    def test_caddy_content_change_is_rejected(self) -> None:
        before = self.capture()["naive_caddyfile"]
        (self.root / "etc/caddy/Caddyfile").write_text("changed\n", encoding="utf-8")
        after = self.capture()["naive_caddyfile"]

        errors = compare_caddy(before, after)

        self.assertIn("Naive Caddyfile content sha256 changed", errors)

    def test_every_discovered_naive_caddyfile_is_hash_guarded(self) -> None:
        second = self.root / "usr/local/x-ui/bin/tunnel/naive-12.caddyfile"
        second.parent.mkdir(parents=True)
        second.write_text("second.example.com {}\n", encoding="utf-8")
        self.caddy_info = {
            "found": True,
            "path": "/etc/caddy/Caddyfile",
            "files": [
                {"found": True, "path": "/etc/caddy/Caddyfile"},
                {"found": True, "path": "/usr/local/x-ui/bin/tunnel/naive-12.caddyfile"},
            ],
        }
        before = self.capture()["naive_caddyfile"]
        second.write_text("changed\n", encoding="utf-8")
        after = self.capture()["naive_caddyfile"]

        errors = compare_caddy(before, after)

        self.assertTrue(
            any(
                "naive-12.caddyfile content sha256 changed" in error
                for error in errors
            ),
            errors,
        )

    def test_unapproved_inbound_port_change_is_rejected(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET port = 443 WHERE id = 5")
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]

        errors = compare_lucx(before, after, [])

        self.assertIn("inbound #5 port changed", errors)

    def test_approved_share_address_change_is_the_only_allowed_inbound_difference(self) -> None:
        before = self.capture()["protected_lucx"]
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(
                "UPDATE inbounds SET share_addr = ? WHERE id = 5",
                ("new.example.com:443",),
            )
            connection.commit()
        finally:
            connection.close()
        after = self.capture()["protected_lucx"]
        changes = [
            {
                "kind": "inbound_share_addr",
                "inbound_id": 5,
                "old_value": "userapi.example.com",
                "new_value": "new.example.com:443",
            }
        ]

        self.assertEqual(compare_lucx(before, after, changes), [])

    def test_snapshot_contains_hashes_but_no_database_secrets(self) -> None:
        snapshot = self.capture()
        serialized = json.dumps(snapshot, sort_keys=True)

        self.assertNotIn("must-not-leak", serialized)
        self.assertIn("sha256", serialized)

    def test_combined_comparison_reports_caddy_and_lucx_drift(self) -> None:
        before = self.capture()
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("UPDATE inbounds SET remark = 'changed' WHERE id = 1")
            connection.commit()
        finally:
            connection.close()
        (self.root / "etc/caddy/Caddyfile").write_text("changed\n", encoding="utf-8")
        after = self.capture()

        errors = compare_integrity(before, after, [])

        self.assertIn("inbound #1 remark changed", errors)
        self.assertIn("Naive Caddyfile content sha256 changed", errors)


if __name__ == "__main__":
    unittest.main()
