from __future__ import annotations

import asyncio
import importlib.util
import io
import socket
from ftplib import FTP, error_perm
from pathlib import Path

import pytest

from better_network_tools.ftp_service import FtpServerRuntime
from better_network_tools.transfer_runtime import RuntimeTransferEvent


PYFTPDLIB_AVAILABLE = importlib.util.find_spec("pyftpdlib") is not None
requires_pyftpdlib = pytest.mark.skipif(
    not PYFTPDLIB_AVAILABLE,
    reason="pyftpdlib is not installed in this test environment",
)


def _available_passive_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _runtime(
    root: Path,
    events: list[RuntimeTransferEvent],
    *,
    max_file_bytes: int = 1024,
) -> FtpServerRuntime:
    passive_port = _available_passive_port()
    return FtpServerRuntime(
        root=root,
        max_file_bytes=max_file_bytes,
        active_transfer_limit=4,
        per_client_transfer_limit=2,
        passive_port_start=passive_port,
        passive_port_end=passive_port,
        event_callback=events.append,
    )


def test_ftp_runtime_validates_limits_without_importing_pyftpdlib(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="max_file_bytes"):
        FtpServerRuntime(
            root=tmp_path,
            max_file_bytes=0,
            active_transfer_limit=1,
            per_client_transfer_limit=1,
            passive_port_start=50000,
            passive_port_end=50000,
            event_callback=lambda event: None,
        )

    with pytest.raises(ValueError, match="unprivileged"):
        FtpServerRuntime(
            root=tmp_path,
            max_file_bytes=1,
            active_transfer_limit=1,
            per_client_transfer_limit=1,
            passive_port_start=21,
            passive_port_end=21,
            event_callback=lambda event: None,
        )


@pytest.mark.asyncio
async def test_ftp_runtime_rejects_symlink_root_before_loading_dependency(
    tmp_path: Path,
) -> None:
    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    try:
        linked_root.symlink_to(real_root, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not available on this platform")

    runtime = FtpServerRuntime(
        root=linked_root,
        max_file_bytes=1024,
        active_transfer_limit=1,
        per_client_transfer_limit=1,
        passive_port_start=50000,
        passive_port_end=50000,
        event_callback=lambda event: None,
    )
    with pytest.raises(RuntimeError, match="symbolic link"):
        await runtime.start(
            bind_address="127.0.0.1",
            port=0,
            username="nettransfer",
            password="a sufficiently long password",
            allow_read=True,
            allow_write=False,
            allow_overwrite=False,
            allowed_networks=[],
        )


@requires_pyftpdlib
@pytest.mark.asyncio
async def test_ftp_runtime_download_upload_no_overwrite_and_events(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"download payload")
    events: list[RuntimeTransferEvent] = []
    runtime = _runtime(root, events)

    started = await runtime.start(
        bind_address="127.0.0.1",
        port=0,
        username="nettransfer",
        password="correct horse battery staple",
        allow_read=True,
        allow_write=True,
        allow_overwrite=False,
        allowed_networks=["127.0.0.0/8"],
    )

    def exercise_client() -> tuple[bytes, list[str]]:
        downloaded = io.BytesIO()
        with FTP() as client:
            client.connect("127.0.0.1", started["bound_port"], timeout=5)
            client.login("nettransfer", "correct horse battery staple")
            listing = client.nlst()
            client.retrbinary("RETR sample.bin", downloaded.write)
            client.storbinary("STOR uploaded.bin", io.BytesIO(b"upload payload"))
            with pytest.raises(error_perm):
                client.storbinary("STOR sample.bin", io.BytesIO(b"replacement"))
            with pytest.raises(error_perm):
                client.sendcmd("PORT 127,0,0,1,200,1")
        return downloaded.getvalue(), listing

    try:
        downloaded, listing = await asyncio.to_thread(exercise_client)
        assert downloaded == b"download payload"
        assert "sample.bin" in listing
        assert (root / "sample.bin").read_bytes() == b"download payload"
        assert (root / "uploaded.bin").read_bytes() == b"upload payload"
        assert not list(root.glob(f".nettransfer-upload-*.part"))

        completed = [event for event in events if event.status == "completed"]
        assert {(event.direction, event.filename) for event in completed} == {
            ("download", "sample.bin"),
            ("upload", "uploaded.bin"),
        }
        for terminal in [event for event in events if event.status != "active"]:
            active = [
                event
                for event in events
                if event.id == terminal.id and event.status == "active"
            ]
            assert len(active) == 1
            assert terminal.protocol == "ftp"
            assert terminal.username == "nettransfer"
    finally:
        await runtime.shutdown()


@requires_pyftpdlib
@pytest.mark.asyncio
async def test_ftp_runtime_rejects_oversize_upload_and_symlink_escape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    link = root / "outside-link.bin"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not available on this platform")

    events: list[RuntimeTransferEvent] = []
    runtime = _runtime(root, events, max_file_bytes=4)
    started = await runtime.start(
        bind_address="127.0.0.1",
        port=0,
        username="nettransfer",
        password="secret",
        allow_read=True,
        allow_write=True,
        allow_overwrite=False,
        allowed_networks=[],  # Loopback defaults safely to 127.0.0.0/8.
    )

    def exercise_client() -> list[str]:
        with FTP() as client:
            client.connect("127.0.0.1", started["bound_port"], timeout=5)
            client.login("nettransfer", "secret")
            listing = client.nlst()
            with pytest.raises(error_perm):
                client.retrbinary("RETR outside-link.bin", lambda data: None)
            with pytest.raises(error_perm):
                client.storbinary("STOR too-large.bin", io.BytesIO(b"12345"))
        return listing

    try:
        listing = await asyncio.to_thread(exercise_client)
        assert "outside-link.bin" not in listing
        assert not (root / "too-large.bin").exists()
        assert not list(root.glob(f".nettransfer-upload-*.part"))
        failed_uploads = [
            event
            for event in events
            if event.direction == "upload" and event.status == "failed"
        ]
        assert len(failed_uploads) == 1
        assert "size limit" in (failed_uploads[0].error or "")
    finally:
        await runtime.shutdown()
