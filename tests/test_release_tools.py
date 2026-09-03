from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.check_documentation import check
from tools.scan_secrets import scan


class ReleaseToolTests(unittest.TestCase):
    def test_secret_scan_accepts_synthetic_examples_and_rejects_real_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe = root / "safe.md"
            safe.write_text(
                "password=example\nsubId=\"subscription-example\"\n",
                encoding="utf-8",
            )
            self.assertEqual(scan(root), [])

            unsafe = root / "unsafe.py"
            flag = "-" + "pw"
            unsafe.write_text("ssh " + flag + " " + ("x" * 24) + "\n", encoding="utf-8")
            self.assertTrue(scan(root))

    def test_documentation_checker_accepts_local_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "# Проект\n\n[Документ](docs.md)\n", encoding="utf-8"
            )
            (root / "docs.md").write_text("# Документ\n", encoding="utf-8")
            self.assertEqual(check(root), [])


if __name__ == "__main__":
    unittest.main()
