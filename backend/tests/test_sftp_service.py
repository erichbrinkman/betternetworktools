from __future__ import annotations

import ipaddress
import os
import stat
from pathlib import Path

import asyncssh
import pytest

from better_network_tools.sftp_service import SftpServerRuntime
from better_network_tools.transfer_runtime import RuntimeTransferEvent


PASSWORD = "correct horse battery staple"
LOOPBACK_NETWORKS = (ipaddress.IPv4Network("127.0.0.0/8"),)


def make_runtime(
    tmp_path: Path,
    events: list[RuntimeTransferEvent],
    *,
    max_file_bytes: int = 16_384,
    active_transfer_limit: int = 4,
    per_client_transfer_limit: int = 2,
) -> SftpServerRuntime:
    return SftpServerRuntime(
        root=tmp_path / "root",
        max_file_bytes=max_file_bytes,
        active_transfer_limit=active_transfer_limit,
        per_client_transfer_limit=per_client_transfer_limit,
        host_key_path=tmp_path / "keys" / "sftp_ed25519",
        event_callback=events.append,
    )


async def start_runtime(
    runtime: SftpServerRuntime,
    *,
    allow_read: bool = True,
    allow_write: bool = True,
    allow_overwrite: bool = False,
) -> dict[str, object]:
    return await runtime.start(
        bind_address="127.0.0.1",
        port=0,
        username="nettransfer",
        password=PASSWORD,
        allow_read=allow_read,
        allow_write=allow_write,
        allow_overwrite=allow_overwrite,
        allowed_networks=LOOPBACK_NETWORKS,
    )


async def connect(details: dict[str, object]) -> asyncssh.SSHClientConnection:
    return await asyncssh.connect(
        "127.0.0.1",
        port=int(details["bound_port"]),
        username="nettransfer",
        password=PASSWORD,
        known_hosts=None,
    )


@pytest.mark.asyncio
async def test_sftp_round_trip_persistent_key_permissions_and_events(
    tmp_path: Path,
) -> None:
    events: list[RuntimeTransferEvent] = []
    runtime = make_runtime(tmp_path, events)
    root = tmp_path / "root"
    root.mkdir()
    (root / "download.bin").write_bytes(b"download payload")

    details = await start_runtime(runtime)
    fingerprint = str(details["fingerprint"])
    assert fingerprint.startswith("SHA256:")
    assert int(details["bound_port"]) > 0
    assert details["host_key_algorithm"] == "ssh-ed25519"
    host_key = tmp_path / "keys" / "sftp_ed25519"
    assert host_key.is_file()
    # Windows reports synthesized mode bits rather than the file's ACL.
    if os.name == "posix":
        assert stat.S_IMODE(host_key.stat().st_mode) == 0o600

    try:
        async with await connect(details) as connection:
            with pytest.raises(asyncssh.ChannelOpenError):
                await connection.run("whoami", check=True)

            async with connection.start_sftp_client() as client:
                assert await client.listdir(".") == ["download.bin"]
                async with client.open("download.bin", "rb") as source:
                    assert await source.read() == b"download payload"
                async with client.open("upload.bin", "wb") as destination:
                    await destination.write(b"uploaded payload")

                with pytest.raises(asyncssh.SFTPError):
                    await client.open("upload.bin", "wb")
                with pytest.raises(asyncssh.SFTPError):
                    await client.remove("download.bin")
    finally:
        await runtime.stop()

    assert (root / "upload.bin").read_bytes() == b"uploaded payload"
    assert [event.status for event in events] == [
        "active",
        "completed",
        "active",
        "completed",
    ]
    assert events[0].id == events[1].id
    assert events[2].id == events[3].id
    assert all(event.protocol == "sftp" for event in events)
    assert events[1].bytes_transferred == len(b"download payload")
    assert events[3].bytes_transferred == len(b"uploaded payload")

    restarted = await start_runtime(runtime)
    try:
        assert restarted["fingerprint"] == fingerprint
    finally:
        await runtime.shutdown()


@pytest.mark.asyncio
async def test_sftp_confines_paths_rejects_symlinks_and_cleans_partial_uploads(
    tmp_path: Path,
) -> None:
    events: list[RuntimeTransferEvent] = []
    runtime = make_runtime(tmp_path, events, per_client_transfer_limit=1)
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    try:
        (root / "outside-link.bin").symlink_to(outside)
    except OSError as exc:  # pragma: no cover - platform policy dependent
        pytest.skip(f"symlinks are unavailable: {exc}")

    details = await start_runtime(runtime)
    connection = await connect(details)
    client = await connection.start_sftp_client()
    upload = None
    try:
        for hostile_path in (
            "../outside.bin",
            "/outside.bin",
            "outside-link.bin",
            "CON",
            "nested\\file.bin",
        ):
            with pytest.raises(asyncssh.SFTPError):
                await client.stat(hostile_path)

        upload = await client.open("unfinished.bin", "wb")
        await upload.write(b"partial")
        with pytest.raises(asyncssh.SFTPError):
            await client.open("second.bin", "wb")

        await runtime.stop()
    finally:
        if upload is not None:
            try:
                await upload.close()
            except (asyncssh.Error, OSError):
                pass
        client.exit()
        connection.abort()
        await connection.wait_closed()
        await runtime.shutdown()

    assert outside.read_bytes() == b"secret"
    assert not (root / "unfinished.bin").exists()
    assert list(root.glob(".nettransfer-upload-*.part")) == []
    assert [event.status for event in events] == ["active", "cancelled"]
    assert events[0].id == events[1].id
    assert events[1].error == "Server stopped"


@pytest.mark.asyncio
async def test_sftp_rejects_bad_auth_and_enforces_actual_upload_size(
    tmp_path: Path,
) -> None:
    events: list[RuntimeTransferEvent] = []
    runtime = make_runtime(tmp_path, events, max_file_bytes=8)
    details = await start_runtime(runtime)
    try:
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect(
                "127.0.0.1",
                port=int(details["bound_port"]),
                username="nettransfer",
                password="wrong password",
                known_hosts=None,
            )

        async with await connect(details) as connection:
            async with connection.start_sftp_client() as client:
                upload = await client.open("oversized.bin", "wb")
                with pytest.raises(asyncssh.SFTPError):
                    await upload.write(b"123456789")
                await upload.close()
    finally:
        await runtime.stop()

    root = tmp_path / "root"
    assert not (root / "oversized.bin").exists()
    assert list(root.glob(".nettransfer-upload-*.part")) == []
    assert [event.status for event in events] == ["active", "failed"]
    assert events[1].bytes_transferred == 0
    assert events[1].error == "File exceeds the server size limit"
