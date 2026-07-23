"""Create a reproducible local development environment on macOS or Windows."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NoReturn


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
MIN_PYTHON = (3, 11)
MIN_NODE = (22, 23, 1)
PINNED_PNPM = (11, 9, 0)


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(command: list[str]) -> None:
    print(f"\n> {' '.join(command)}")
    subprocess.run(command, cwd=ROOT, check=True)


def venv_python() -> Path:
    suffix = Path("Scripts/python.exe") if os.name == "nt" else Path("bin/python")
    return VENV / suffix


def parse_version(raw: str, *, label: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+).*", raw.strip())
    if not match:
        fail(f"could not understand {label} version: {raw.strip()!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def select_pnpm_command(
    pnpm: str | None,
    corepack: str | None,
) -> list[str]:
    """Use pnpm 11.9.0 directly or through the repository-aware Corepack shim."""

    direct_version: tuple[int, int, int] | None = None
    if pnpm:
        direct_version = parse_version(
            subprocess.check_output([pnpm, "--version"], cwd=ROOT, text=True),
            label="pnpm",
        )
        if direct_version == PINNED_PNPM:
            return [pnpm]

    if corepack:
        corepack_command = [corepack, "pnpm"]
        corepack_version = parse_version(
            subprocess.check_output(
                [*corepack_command, "--version"],
                cwd=ROOT,
                text=True,
            ),
            label="pnpm",
        )
        if corepack_version == PINNED_PNPM:
            return corepack_command

    found = (
        ".".join(str(part) for part in direct_version)
        if direct_version is not None
        else "not installed"
    )
    fail(
        "pnpm 11.9.0 is required; "
        f"the direct pnpm version is {found} and Corepack could not provide it"
    )


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        fail("Python 3.11 or newer is required")

    node = shutil.which("node")
    pnpm = shutil.which("pnpm")
    corepack = shutil.which("corepack")
    if not node or (not pnpm and not corepack):
        fail(
            "Node.js 22.23.1 or newer and pnpm are required "
            "(Corepack may provide the pinned pnpm version)"
        )

    node_version = parse_version(
        subprocess.check_output([node, "--version"], text=True),
        label="Node.js",
    )
    if node_version < MIN_NODE:
        fail("Node.js 22.23.1 or newer is required")

    backend_project = ROOT / "backend" / "pyproject.toml"
    if not backend_project.is_file():
        fail("backend/pyproject.toml is missing")

    if not venv_python().is_file():
        print(f"Creating virtual environment at {VENV}")
        run([sys.executable, "-m", "venv", str(VENV)])

    python_lock = ROOT / "backend" / "requirements.lock"
    if not python_lock.is_file():
        fail("backend/requirements.lock is missing")

    run(
        [
            str(venv_python()),
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            str(python_lock),
        ]
    )
    run(
        [
            str(venv_python()),
            "-m",
            "pip",
            "install",
            "--no-build-isolation",
            "--no-deps",
            "-e",
            "backend",
        ]
    )

    package_command = select_pnpm_command(pnpm, corepack)
    run([*package_command, "install", "--frozen-lockfile"])

    env_file = ROOT / ".env"
    if not env_file.exists():
        shutil.copyfile(ROOT / ".env.example", env_file)
        print("\nCreated .env from .env.example")

    python_command = (
        r".venv\Scripts\python.exe scripts\dev.py"
        if os.name == "nt"
        else ".venv/bin/python scripts/dev.py"
    )
    print(f"\nSetup complete. Start Better Network Tools with:\n  {python_command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
