from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path


class TargetFS:
    """Maps absolute target paths into a test root without weakening path checks."""

    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root).resolve()

    @property
    def is_live(self) -> bool:
        return self.root == Path("/").resolve()

    def path(self, target: str | Path) -> Path:
        raw = str(target)
        if not raw.startswith("/"):
            raise ValueError(f"target path must be absolute: {raw}")
        relative = raw.lstrip("/")
        # Normalize lexical '..' components without following the final symlink.
        # Backups must be able to record and restore a symlink as a symlink (for
        # example Certbot live paths or Debian's stock Nginx default site).
        lexical = Path(os.path.abspath(self.root / relative))
        if lexical != self.root and self.root not in lexical.parents:
            raise ValueError(f"target escapes root: {raw}")
        resolved_parent = lexical.parent.resolve(strict=False)
        if resolved_parent != self.root and self.root not in resolved_parent.parents:
            raise ValueError(f"target parent escapes root through a symlink: {raw}")
        return lexical

    def exists(self, target: str | Path) -> bool:
        return self.path(target).exists()

    def read_text(self, target: str | Path, default: str = "") -> str:
        path = self.path(target)
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return default

    def read_bytes(self, target: str | Path) -> bytes:
        return self.path(target).read_bytes()

    def sha256(self, target: str | Path) -> str:
        digest = hashlib.sha256()
        with self.path(target).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def atomic_write(self, target: str | Path, data: bytes, mode: int = 0o644) -> None:
        path = self.path(target)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temp_path = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, mode)
            os.replace(temp_path, path)
        finally:
            temp_path.unlink(missing_ok=True)

    def atomic_write_text(self, target: str | Path, text: str, mode: int = 0o644) -> None:
        self.atomic_write(target, text.encode("utf-8"), mode=mode)
