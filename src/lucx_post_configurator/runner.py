from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path


@dataclasses.dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        rendered = " ".join(result.args)
        detail = (result.stderr or result.stdout).strip()
        super().__init__(f"command failed ({result.returncode}): {rendered}: {detail}")


class Runner:
    def __init__(self, *, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.history: list[list[str]] = []

    def available(self, command: str) -> bool:
        return shutil.which(command) is not None

    def run(
        self,
        args: Sequence[str | Path],
        *,
        check: bool = True,
        timeout: int = 30,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        command = [str(value) for value in args]
        self.history.append(command)
        if self.dry_run:
            return CommandResult(command, 0, "", "")
        merged_env = os.environ.copy()
        merged_env.setdefault("LC_ALL", "C.UTF-8")
        merged_env.setdefault("LANG", "C.UTF-8")
        if env:
            merged_env.update(env)
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=input_text,
            timeout=timeout,
            env=merged_env,
        )
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr)
        if check and result.returncode != 0:
            raise CommandError(result)
        return result


def missing_packages(packages: list[str], runner: Runner) -> list[str]:
    missing: list[str] = []
    if not runner.available("dpkg-query"):
        return packages
    for package in packages:
        result = runner.run(
            ["dpkg-query", "-W", "-f=${Status}", package], check=False, timeout=10
        )
        if result.returncode != 0 or "install ok installed" not in result.stdout:
            missing.append(package)
    return missing


def install_packages(
    packages: list[str], runner: Runner, *, missing: list[str] | None = None
) -> list[str]:
    missing = missing_packages(packages, runner) if missing is None else list(missing)
    if not missing:
        return []
    runner.run(["apt-get", "update"], timeout=300, env={"DEBIAN_FRONTEND": "noninteractive"})
    runner.run(
        ["apt-get", "install", "-y", "--no-install-recommends", *missing],
        timeout=600,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    return missing
