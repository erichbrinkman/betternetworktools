from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import asyncssh
import pytest

from better_network_tools.config import Settings, load_settings
from better_network_tools.tftp_models import TftpServerStatusResponse
from better_network_tools.transfer_models import TransferServerStartRequest
from better_network_tools.transfer_service import (
    TransferConfigurationError,
    TransferServerAlreadyRunningError,
    TransferServerService,
)


class FakeTftpRuntime:
    instances: list["FakeTftpRuntime"] = []

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.running = False
        self.stop_gate: asyncio.Event | None = None
        FakeTftpRuntime.instances.append(self)

    async def start(self, request: object) -> None:
        self.running = True

    async def stop(self) -> None:
        if self.stop_gate is not None:
            await self.stop_gate.wait()
        self.running = False

    async def status(self) -> TftpServerStatusResponse:
        return TftpServerStatusResponse(
            state="running" if self.running else "stopped",
            running=self.running,
            bind_address="127.0.0.1",
            port=6969,
            root_directory=self.settings.transfer_root_directory,
            allow_read=True,
            allow_write=False,
            allow_overwrite=False,
            allowed_client_cidrs=["127.0.0.0/8"],
            started_at=None,
            active_transfer_count=0,
            completed_transfer_count=0,
            failed_transfer_count=0,
            bytes_sent=0,
            bytes_received=0,
            recent_transfers=[],
        )


def unused_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


@pytest.mark.asyncio
async def test_transfer_service_serializes_stop_before_another_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "better_network_tools.transfer_service.TftpServerService", FakeTftpRuntime
    )
    FakeTftpRuntime.instances.clear()
    service = TransferServerService(
        Settings(
            transfer_root_directory=str(tmp_path / "root"),
            tftp_root_directory=str(tmp_path / "root"),
        )
    )
    request = TransferServerStartRequest(protocol="tftp")

    started = await service.start(request)
    assert started.protocol == "tftp"
    with pytest.raises(TransferServerAlreadyRunningError):
        await service.start(request)

    gate = asyncio.Event()
    FakeTftpRuntime.instances[0].stop_gate = gate
    stopping = asyncio.create_task(service.stop())
    await asyncio.sleep(0)
    restarting = asyncio.create_task(service.start(request))
    await asyncio.sleep(0)
    assert not restarting.done()
    gate.set()
    await stopping
    restarted = await restarting
    assert restarted.running is True
    assert len(FakeTftpRuntime.instances) == 2
    await service.shutdown()


def test_transfer_service_requires_cidr_and_plaintext_ack_for_lan_ftp(
    tmp_path: Path,
) -> None:
    service = TransferServerService(
        Settings(transfer_root_directory=str(tmp_path / "root"))
    )
    base = {
        "protocol": "ftp",
        "bind_address": "0.0.0.0",
        "username": "nettransfer",
        "password": "a-long-local-password",
    }
    with pytest.raises(TransferConfigurationError, match="allowed IPv4"):
        service._validate_configuration(TransferServerStartRequest(**base))
    with pytest.raises(TransferConfigurationError, match="Acknowledge"):
        service._validate_configuration(
            TransferServerStartRequest(
                **base, allowed_client_cidrs=["192.168.10.0/24"]
            )
        )
    config = service._validate_configuration(
        TransferServerStartRequest(
            **base,
            allowed_client_cidrs=["192.168.10.0/24"],
            acknowledge_plaintext_ftp=True,
        )
    )
    assert config.port == 2121

    overlapping = TransferServerService(
        Settings(
            transfer_root_directory=str(tmp_path / "other-root"),
            transfer_ftp_passive_port_start=2121,
            transfer_ftp_passive_port_end=2136,
        )
    )
    with pytest.raises(TransferConfigurationError, match="outside"):
        overlapping._validate_configuration(
            TransferServerStartRequest(
                protocol="ftp",
                username="nettransfer",
                password="a-long-local-password",
            )
        )


def test_transfer_settings_honor_legacy_tftp_fallbacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("BNT_TRANSFER_ROOT", raising=False)
    monkeypatch.delenv("BNT_TRANSFER_TFTP_PORT", raising=False)
    monkeypatch.setenv("BNT_TFTP_ROOT", str(tmp_path / "legacy-root"))
    monkeypatch.setenv("BNT_TFTP_PORT", "1069")

    settings = load_settings()

    assert settings.transfer_root_directory == str(tmp_path / "legacy-root")
    assert settings.tftp_root_directory == settings.transfer_root_directory
    assert settings.transfer_tftp_default_port == 1069
    assert settings.tftp_default_port == 1069


def test_transfer_settings_reject_reversed_ftp_passive_range(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_TRANSFER_FTP_PASSIVE_PORT_START", "50010")
    monkeypatch.setenv("BNT_TRANSFER_FTP_PASSIVE_PORT_END", "50000")

    with pytest.raises(ValueError, match="must not exceed"):
        load_settings()


def test_transfer_settings_require_enough_ftp_passive_ports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_TRANSFER_ACTIVE_TRANSFER_LIMIT", "4")
    monkeypatch.setenv("BNT_TRANSFER_FTP_PASSIVE_PORT_START", "50000")
    monkeypatch.setenv("BNT_TRANSFER_FTP_PASSIVE_PORT_END", "50002")

    with pytest.raises(ValueError, match="at least one port"):
        load_settings()


@pytest.mark.asyncio
async def test_transfer_service_runs_sftp_and_keeps_a_stable_fingerprint(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    key_path = tmp_path / "keys" / "nettransfer-ed25519"
    port = unused_tcp_port()
    service = TransferServerService(
        Settings(
            transfer_root_directory=str(root),
            transfer_sftp_host_key_path=str(key_path),
        )
    )
    request = TransferServerStartRequest(
        protocol="sftp",
        port=port,
        username="nettransfer",
        password="a-long-local-password",
    )

    first = await service.start(request)
    try:
        assert first.running is True
        assert first.sftp_host_key_fingerprint is not None
        assert "password" not in first.model_dump()
        async with asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="nettransfer",
            password="a-long-local-password",
            known_hosts=None,
        ) as connection:
            async with connection.start_sftp_client() as client:
                assert await client.listdir(".") == []
    finally:
        await service.stop()

    second = await service.start(request)
    try:
        assert second.sftp_host_key_fingerprint == first.sftp_host_key_fingerprint
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_transfer_service_keeps_sftp_host_key_outside_shared_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    service = TransferServerService(
        Settings(
            transfer_root_directory=str(root),
            transfer_sftp_host_key_path=str(root / "host-key"),
        )
    )

    with pytest.raises(TransferConfigurationError, match="outside"):
        await service.start(
            TransferServerStartRequest(
                protocol="sftp",
                port=unused_tcp_port(),
                username="nettransfer",
                password="a-long-local-password",
            )
        )

    assert (await service.status()).state == "stopped"
