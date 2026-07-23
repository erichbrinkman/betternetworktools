"""Run the local vinext UI and FastAPI service as one process group."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VENV_PYTHON = ROOT / ".venv" / (
    "Scripts/python.exe" if os.name == "nt" else "bin/python"
)
LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
PINNED_PNPM = (11, 9, 0)


def load_local_env() -> None:
    """Load the simple KEY=VALUE entries used by this repository."""
    env_file = ROOT / ".env"
    if not env_file.is_file():
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


def port(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        parsed = int(raw)
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from None
    if not 1 <= parsed <= 65535:
        raise SystemExit(f"{name} must be between 1 and 65535")
    return parsed


def parse_version(raw: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+).*", raw.strip())
    if not match:
        raise SystemExit(f"Could not understand pnpm version {raw.strip()!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def select_pnpm_command() -> list[str]:
    pnpm = shutil.which("pnpm")
    corepack = shutil.which("corepack")
    if pnpm:
        direct_version = parse_version(
            subprocess.check_output([pnpm, "--version"], cwd=ROOT, text=True)
        )
        if direct_version == PINNED_PNPM:
            return [pnpm]
    if corepack:
        command = [corepack, "pnpm"]
        version = parse_version(
            subprocess.check_output([*command, "--version"], cwd=ROOT, text=True)
        )
        if version == PINNED_PNPM:
            return command
    raise SystemExit(
        "pnpm 11.9.0 is required directly or through Corepack; "
        "run scripts/bootstrap.py again"
    )


def start(command: list[str]) -> subprocess.Popen[bytes]:
    kwargs: dict[str, object] = {"cwd": ROOT, "env": os.environ.copy()}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(command, **kwargs)  # type: ignore[arg-type]


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    try:
        if os.name == "nt":
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def main() -> int:
    load_local_env()

    if not VENV_PYTHON.is_file():
        raise SystemExit("Run scripts/bootstrap.py first; .venv is missing")
    package_command = select_pnpm_command()

    api_host = os.environ.get("BNT_HOST", "127.0.0.1")
    web_host = os.environ.get("BNT_WEB_HOST", "127.0.0.1")
    if api_host not in LOOPBACK_HOSTS:
        raise SystemExit(
            "Refusing to expose the scanner API: BNT_HOST must be a loopback host"
        )
    if web_host not in LOOPBACK_HOSTS:
        raise SystemExit(
            "Refusing to expose the development UI: BNT_WEB_HOST must be a loopback host"
        )

    api_port = port("BNT_PORT", 8766)
    web_port = port("BNT_WEB_PORT", 3000)
    if api_port == web_port:
        raise SystemExit("BNT_PORT and BNT_WEB_PORT must be different")

    # Keep the browser client on the same local API selected above even when a
    # developer changes BNT_PORT without also editing the public web variable.
    os.environ["NEXT_PUBLIC_BNT_API_URL"] = f"http://{api_host}:{api_port}"

    api_command = [
        str(VENV_PYTHON),
        "-m",
        "uvicorn",
        "better_network_tools.main:app",
        "--reload",
        "--reload-dir",
        "backend/src",
        "--host",
        api_host,
        "--port",
        str(api_port),
    ]
    web_command = [
        *package_command,
        "run",
        "dev",
        "--",
        "--hostname",
        web_host,
        "--port",
        str(web_port),
    ]

    print(f"Web UI: http://{web_host}:{web_port}")
    print(f"API:    http://{api_host}:{api_port}")
    print("Press Ctrl+C to stop both services.\n")

    processes: list[subprocess.Popen[bytes]] = []
    exit_code = 0
    try:
        processes.append(start(api_command))
        processes.append(start(web_command))
        while True:
            for process in processes:
                result = process.poll()
                if result is not None:
                    exit_code = result
                    return exit_code
            time.sleep(0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        for process in reversed(processes):
            stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
