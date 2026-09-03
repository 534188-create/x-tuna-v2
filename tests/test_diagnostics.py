from __future__ import annotations

import json
import unittest

from lucx_post_configurator.diagnostics import redact, stable_fingerprint


class DiagnosticsTests(unittest.TestCase):
    def test_nested_secrets_commands_and_subscription_ids_are_removed(self) -> None:
        source = {
            "private_key": "SECRET-PRIVATE-KEY",
            "nested": {"password": "SECRET-PASSWORD"},
            "url": "https://user:pass@sub.example.com/sub/client-secret?token=SECRET-TOKEN",
            "command": ["tool", "--token", "SECRET-ARGV", "--mode=safe"],
        }

        serialized = json.dumps(redact(source), ensure_ascii=False)

        for forbidden in (
            "SECRET-PRIVATE-KEY",
            "SECRET-PASSWORD",
            "client-secret",
            "SECRET-TOKEN",
            "SECRET-ARGV",
            "user:pass",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("sha256:", serialized)

    def test_connection_uris_and_uuids_inside_error_text_are_removed(self) -> None:
        source = (
            "failed vless://user-secret@example.com:443?security=tls#Name "
            "for 550e8400-e29b-41d4-a716-446655440000"
        )

        redacted = redact(source)

        self.assertNotIn("user-secret", redacted)
        self.assertNotIn("550e8400-e29b-41d4-a716-446655440000", redacted)
        self.assertIn("redacted-uri", redacted)

    def test_oversized_payload_is_replaced_by_fingerprint(self) -> None:
        value = "A" * 5000
        result = redact({"payload": value})
        self.assertNotIn(value, json.dumps(result))
        self.assertIn("redacted-large-value", result["payload"])

    def test_fingerprint_is_short_stable_and_does_not_include_input(self) -> None:
        first = stable_fingerprint("client-secret")
        second = stable_fingerprint("client-secret")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^sha256:[0-9a-f]{12}$")
        self.assertNotIn("client-secret", first)


if __name__ == "__main__":
    unittest.main()
