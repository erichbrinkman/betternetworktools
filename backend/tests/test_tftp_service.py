from __future__ import annotations

import asyncio
import os
import socket
import struct
from pathlib import Path

import pytest

from better_network_tools import tftp_service as tftp_module
from better_network_tools.config import Settings
from better_network_tools.tftp_models import TftpServerStartRequest
from better_network_tools.tftp_service import (
    ERR_ACCESS_VIOLATION,
    ERR_FILE_EXISTS,
    ERR_ILLEGAL_OPERATION,
    ERR_OPTION_NEGOTIATION,
    OP_ACK,
    OP_DATA,
    OP_ERROR,
    OP_OACK,
    OP_RRQ,
    OP_WRQ,
    TftpConfigurationError,
    TftpPacketError,
    TftpServerService,
    parse_tftp_request,
)


def tftp_settings(root: Path, **overrides: object) -> Settings:
    values: dict[str, object] = {
        "tftp_root_directory": str(root),
        "tftp_default_bind_address": "127.0.0.1",
        "tftp_default_port": 6969,
        "tftp_max_file_bytes": 16_384,
        "tftp_active_transfer_limit": 4,
        "tftp_per_client_transfer_limit": 2,
        "tftp_retry_timeout_seconds": 0.03,
        "tftp_max_retries": 1,
        "tftp_transfer_timeout_seconds": 0.5,
        "tftp_max_block_size": 512,
        "tftp_allowed_network_host_limit": 65_536,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def unused_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def request_packet(
    opcode: int,
    filename: str,
    *,
    mode: str = "octet",
    options: dict[str, str] | None = None,
) -> bytes:
    packet = bytearray(struct.pack("!H", opcode))
    packet.extend(filename.encode("utf-8"))
    packet.append(0)
    packet.extend(mode.encode("ascii"))
    packet.append(0)
    for name, value in (options or {}).items():
        packet.extend(name.encode("ascii"))
        packet.append(0)
        packet.extend(value.encode("ascii"))
        packet.append(0)
    return bytes(packet)


def ack_packet(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block)


def data_packet(block: int, payload: bytes) -> bytes:
    return struct.pack("!HH", OP_DATA, block) + payload


def decode_error(packet: bytes) -> tuple[int, str]:
    opcode, code = struct.unpack("!HH", packet[:4])
    assert opcode == OP_ERROR
    return code, packet[4:].split(b"\0", 1)[0].decode("utf-8")


def decode_oack(packet: bytes) -> dict[str, str]:
    (opcode,) = struct.unpack("!H", packet[:2])
    assert opcode == OP_OACK
    fields = packet[2:].split(b"\0")
    assert fields[-1] == b""
    return {
        fields[index].decode("ascii"): fields[index + 1].decode("ascii")
        for index in range(0, len(fields) - 1, 2)
    }


def udp_client() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(("127.0.0.1", 0))
    return sock


async def sendto(
    sock: socket.socket, packet: bytes, address: tuple[str, int]
) -> None:
    await asyncio.get_running_loop().sock_sendto(sock, packet, address)


async def recvfrom(
    sock: socket.socket, *, timeout: float = 0.75
) -> tuple[bytes, tuple[str, int]]:
    packet, peer = await asyncio.wait_for(
        asyncio.get_running_loop().sock_recvfrom(sock, 65_535), timeout=timeout
    )
    return packet, (str(peer[0]), int(peer[1]))


async def wait_for_idle(
    service: TftpServerService, *, recent_count: int | None = None
):
    for _ in range(200):
        status = await service.status()
        if status.active_transfer_count == 0 and (
            recent_count is None or len(status.recent_transfers) >= recent_count
        ):
            return status
        await asyncio.sleep(0.005)
    raise AssertionError("TFTP transfer did not become idle")


async def start_loopback_service(
    root: Path,
    *,
    allow_read: bool = True,
    allow_write: bool = False,
    allow_overwrite: bool = False,
    allowed_client_cidrs: list[str] | None = None,
    **settings_overrides: object,
) -> tuple[TftpServerService, int]:
    port = unused_udp_port()
    service = TftpServerService(tftp_settings(root, **settings_overrides))
    await service.start(
        TftpServerStartRequest(
            bind_address="127.0.0.1",
            port=port,
            allow_read=allow_read,
            allow_write=allow_write,
            allow_overwrite=allow_overwrite,
            allowed_client_cidrs=allowed_client_cidrs or [],
        )
    )
    return service, port


async def upload(
    port: int,
    filename: str,
    chunks: list[bytes],
    *,
    options: dict[str, str] | None = None,
) -> bytes:
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_WRQ, filename, options=options),
            ("127.0.0.1", port),
        )
        initial, transfer_peer = await recvfrom(client)
        initial_opcode = struct.unpack("!H", initial[:2])[0]
        assert initial_opcode == (OP_OACK if options else OP_ACK)
        if initial_opcode == OP_ACK:
            assert initial == ack_packet(0)
        for block, payload in enumerate(chunks, start=1):
            await sendto(client, data_packet(block, payload), transfer_peer)
            acknowledgement, peer = await recvfrom(client)
            assert peer == transfer_peer
            assert acknowledgement == ack_packet(block)
        return initial
    finally:
        client.close()


def test_parse_request_normalizes_mode_and_options() -> None:
    parsed = parse_tftp_request(
        request_packet(
            OP_RRQ,
            "images/café.bin",
            mode="OcTeT",
            options={"BLKSIZE": "1024", "TSIZE": "0"},
        )
    )

    assert parsed.opcode == OP_RRQ
    assert parsed.filename == "images/café.bin"
    assert parsed.mode == "octet"
    assert parsed.options == {"blksize": "1024", "tsize": "0"}


@pytest.mark.parametrize(
    ("packet", "message"),
    [
        (b"", "truncated"),
        (struct.pack("!H", OP_DATA) + b"x\0octet\0", "only read and write"),
        (struct.pack("!H", OP_RRQ) + b"file\0octet", "NUL terminated"),
        (struct.pack("!H", OP_RRQ) + b"\0octet\0", "required"),
        (
            struct.pack("!H", OP_RRQ) + b"file\0octet\0blksize\0",
            "incomplete option",
        ),
        (
            request_packet(
                OP_RRQ,
                "file",
                options={"blksize": "8", "BLKSIZE": "16"},
            ),
            "duplicate option",
        ),
        (
            struct.pack("!H", OP_RRQ) + b"\xff\0octet\0",
            "not valid UTF-8/ASCII",
        ),
        (
            request_packet(OP_RRQ, "x" * 256),
            "filename exceeds 255 bytes",
        ),
        (b"x" * 513, "exceeds 512 bytes"),
    ],
)
def test_parse_request_rejects_malformed_or_unbounded_packets(
    packet: bytes, message: str
) -> None:
    with pytest.raises(TftpPacketError, match=message):
        parse_tftp_request(packet)


def test_configuration_guards_permissions_and_lan_allowlists(tmp_path: Path) -> None:
    service = TftpServerService(tftp_settings(tmp_path / "root"))

    loopback = service._validate_configuration(TftpServerStartRequest())
    assert [str(network) for network in loopback.allowed_networks] == ["127.0.0.0/8"]

    with pytest.raises(TftpConfigurationError, match="downloads, uploads, or both"):
        service._validate_configuration(
            TftpServerStartRequest(allow_read=False, allow_write=False)
        )
    with pytest.raises(TftpConfigurationError, match="Overwrite can only"):
        service._validate_configuration(
            TftpServerStartRequest(allow_write=False, allow_overwrite=True)
        )
    with pytest.raises(TftpConfigurationError, match="requires at least one"):
        service._validate_configuration(
            TftpServerStartRequest(bind_address="0.0.0.0")
        )
    with pytest.raises(TftpConfigurationError, match="must be IPv4"):
        service._validate_configuration(
            TftpServerStartRequest(
                bind_address="0.0.0.0", allowed_client_cidrs=["::1/128"]
            )
        )
    with pytest.raises(
        TftpConfigurationError, match="exceeding the configured limit|too broad"
    ):
        service._validate_configuration(
            TftpServerStartRequest(
                bind_address="0.0.0.0", allowed_client_cidrs=["0.0.0.0/0"]
            )
        )

    limited = TftpServerService(
        tftp_settings(tmp_path / "limited", tftp_allowed_network_host_limit=16)
    )
    with pytest.raises(TftpConfigurationError, match="exceeding the configured limit"):
        limited._validate_configuration(
            TftpServerStartRequest(
                bind_address="0.0.0.0", allowed_client_cidrs=["192.0.2.0/24"]
            )
        )

    lan = service._validate_configuration(
        TftpServerStartRequest(
            bind_address="0.0.0.0",
            allowed_client_cidrs=["192.168.20.44/24", "192.168.20.0/24"],
        )
    )
    service._config = lan
    assert [str(network) for network in lan.allowed_networks] == ["192.168.20.0/24"]
    assert service._client_is_allowed("192.168.20.99") is True
    assert service._client_is_allowed("192.168.21.1") is False


@pytest.mark.asyncio
async def test_start_requires_a_loopback_bound_management_api(tmp_path: Path) -> None:
    root = tmp_path / "root"
    service = TftpServerService(tftp_settings(root, host="0.0.0.0"))

    with pytest.raises(TftpConfigurationError, match="loopback-bound local API"):
        await service.start(TftpServerStartRequest(port=unused_udp_port()))

    assert not root.exists()
    assert (await service.status()).running is False


@pytest.mark.asyncio
async def test_listener_enforces_client_allowlist_and_transfer_permissions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "read.bin").write_bytes(b"readable")

    service, port = await start_loopback_service(
        root, allowed_client_cidrs=["192.0.2.0/24"]
    )
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_RRQ, "read.bin"),
            ("127.0.0.1", port),
        )
        packet, _ = await recvfrom(client)
        assert decode_error(packet) == (ERR_ACCESS_VIOLATION, "Client is not allowed")
        assert (await service.status()).recent_transfers == []
    finally:
        client.close()
        await service.stop()

    service, port = await start_loopback_service(
        root, allow_read=False, allow_write=True
    )
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_RRQ, "read.bin"),
            ("127.0.0.1", port),
        )
        packet, _ = await recvfrom(client)
        assert decode_error(packet) == (ERR_ACCESS_VIOLATION, "Downloads are disabled")
        status = await wait_for_idle(service, recent_count=1)
        assert status.failed_transfer_count == 1
    finally:
        client.close()
        await service.stop()

    service, port = await start_loopback_service(root, allow_write=False)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_WRQ, "upload.bin"),
            ("127.0.0.1", port),
        )
        packet, _ = await recvfrom(client)
        assert decode_error(packet) == (ERR_ACCESS_VIOLATION, "Uploads are disabled")
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
async def test_rrq_rejects_traversal_absolute_paths_and_symlinks(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside_file = tmp_path / "outside.bin"
    outside_file.write_bytes(b"secret")
    outside_directory = tmp_path / "outside"
    outside_directory.mkdir()
    (outside_directory / "nested.bin").write_bytes(b"nested secret")
    try:
        (root / "linked.bin").symlink_to(outside_file)
        (root / "linked-dir").symlink_to(outside_directory, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform policy dependent
        pytest.skip(f"symlinks are unavailable: {exc}")

    service, port = await start_loopback_service(root)
    client = udp_client()
    try:
        for filename in (
            "../outside.bin",
            "/etc/passwd",
            "linked.bin",
            "linked-dir/nested.bin",
        ):
            await sendto(
                client,
                request_packet(OP_RRQ, filename),
                ("127.0.0.1", port),
            )
            packet, _ = await recvfrom(client)
            code, _message = decode_error(packet)
            assert code == ERR_ACCESS_VIOLATION
            await wait_for_idle(service)

        assert outside_file.read_bytes() == b"secret"
        status = await service.status()
        assert status.failed_transfer_count == 4
        assert all(item.status == "failed" for item in status.recent_transfers)
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
async def test_rrq_exact_512_byte_file_ends_with_zero_length_data_block(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = bytes(range(256)) * 2
    (root / "exact.bin").write_bytes(payload)
    service, port = await start_loopback_service(root)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_RRQ, "exact.bin"),
            ("127.0.0.1", port),
        )

        first, transfer_peer = await recvfrom(client)
        assert transfer_peer[1] != port
        assert first[:4] == struct.pack("!HH", OP_DATA, 1)
        assert first[4:] == payload
        await sendto(client, ack_packet(1), transfer_peer)

        final, peer = await recvfrom(client)
        assert peer == transfer_peer
        assert final == struct.pack("!HH", OP_DATA, 2)
        await sendto(client, ack_packet(2), transfer_peer)

        status = await wait_for_idle(service, recent_count=1)
        assert status.completed_transfer_count == 1
        assert status.bytes_sent == 512
        assert status.recent_transfers[0].bytes_transferred == 512
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
async def test_rrq_negotiates_bounded_options_and_ignores_unknown_options(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    payload = bytes(index % 251 for index in range(300))
    (root / "options.bin").write_bytes(payload)
    service, port = await start_loopback_service(root, tftp_max_block_size=128)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(
                OP_RRQ,
                "options.bin",
                options={
                    "blksize": "1024",
                    "timeout": "1",
                    "tsize": "0",
                    "vendor-extension": "ignored",
                },
            ),
            ("127.0.0.1", port),
        )

        oack, transfer_peer = await recvfrom(client)
        assert decode_oack(oack) == {
            "blksize": "128",
            "timeout": "1",
            "tsize": "300",
        }
        await sendto(client, ack_packet(0), transfer_peer)

        received = bytearray()
        block = 1
        while True:
            packet, peer = await recvfrom(client)
            assert peer == transfer_peer
            opcode, received_block = struct.unpack("!HH", packet[:4])
            assert (opcode, received_block) == (OP_DATA, block)
            chunk = packet[4:]
            assert len(chunk) <= 128
            received.extend(chunk)
            await sendto(client, ack_packet(block), transfer_peer)
            if len(chunk) < 128:
                break
            block += 1

        assert bytes(received) == payload
        status = await wait_for_idle(service, recent_count=1)
        assert status.completed_transfer_count == 1
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "options",
    [
        {"blksize": "7"},
        {"timeout": "0"},
        {"tsize": "1"},
    ],
)
async def test_rrq_rejects_invalid_option_negotiation(
    tmp_path: Path, options: dict[str, str]
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "file.bin").write_bytes(b"content")
    service, port = await start_loopback_service(root)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_RRQ, "file.bin", options=options),
            ("127.0.0.1", port),
        )
        packet, _ = await recvfrom(client)
        code, _message = decode_error(packet)
        assert code == ERR_OPTION_NEGOTIATION
        status = await wait_for_idle(service, recent_count=1)
        assert status.failed_transfer_count == 1
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
async def test_non_octet_mode_is_rejected_as_an_illegal_operation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "file.txt").write_text("hello")
    service, port = await start_loopback_service(root)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_RRQ, "file.txt", mode="netascii"),
            ("127.0.0.1", port),
        )
        packet, _ = await recvfrom(client)
        assert decode_error(packet) == (
            ERR_ILLEGAL_OPERATION,
            "Only octet (binary) transfer mode is supported",
        )
    finally:
        client.close()
        await service.stop()


@pytest.mark.asyncio
async def test_wrq_creates_file_with_options_and_enforces_overwrite_policy(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    service, port = await start_loopback_service(
        root, allow_write=True, allow_overwrite=False
    )
    try:
        initial = await upload(
            port,
            "created.bin",
            [b"abcdefgh", b"ijk"],
            options={"blksize": "8", "tsize": "11"},
        )
        assert decode_oack(initial) == {"blksize": "8", "tsize": "11"}
        status = await wait_for_idle(service, recent_count=1)
        assert (root / "created.bin").read_bytes() == b"abcdefghijk"
        assert status.completed_transfer_count == 1
        assert status.bytes_received == 11

        client = udp_client()
        try:
            await sendto(
                client,
                request_packet(OP_WRQ, "created.bin"),
                ("127.0.0.1", port),
            )
            packet, _ = await recvfrom(client)
            assert decode_error(packet) == (ERR_FILE_EXISTS, "File already exists")
        finally:
            client.close()
        status = await wait_for_idle(service, recent_count=2)
        assert status.failed_transfer_count == 1
        assert (root / "created.bin").read_bytes() == b"abcdefghijk"
    finally:
        await service.stop()

    service, port = await start_loopback_service(
        root, allow_write=True, allow_overwrite=True
    )
    try:
        await upload(port, "created.bin", [b"replacement"])
        status = await wait_for_idle(service, recent_count=1)
        assert (root / "created.bin").read_bytes() == b"replacement"
        assert status.completed_transfer_count == 1
    finally:
        await service.stop()


@pytest.mark.asyncio
async def test_stop_cancels_upload_removes_temp_file_and_releases_port(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    service, port = await start_loopback_service(root, allow_write=True)
    client = udp_client()
    try:
        await sendto(
            client,
            request_packet(OP_WRQ, "unfinished.bin"),
            ("127.0.0.1", port),
        )
        initial, transfer_peer = await recvfrom(client)
        assert initial == ack_packet(0)

        await sendto(client, data_packet(1, b"x" * 512), transfer_peer)
        acknowledgement, _ = await recvfrom(client)
        assert acknowledgement == ack_packet(1)
        assert len(list(root.glob(".nettransfer-upload-*.part"))) == 1

        stopped = await service.stop()
        assert stopped.running is False
        assert stopped.state == "stopped"
        assert stopped.active_transfer_count == 0
        assert stopped.recent_transfers[0].status == "cancelled"
        assert stopped.recent_transfers[0].error == "Server stopped"
        assert not (root / "unfinished.bin").exists()
        assert list(root.glob(".nettransfer-upload-*.part")) == []

        await service.shutdown()
        rebound = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rebound.bind(("127.0.0.1", port))
        finally:
            rebound.close()
    finally:
        client.close()
        await service.shutdown()


@pytest.mark.asyncio
async def test_file_listing_is_sorted_confined_and_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "Beta.bin").write_bytes(b"bb")
    (root / "alpha.bin").write_bytes(b"a")
    (nested / "gamma.bin").write_bytes(b"ggg")
    (root / ".nettftp-upload-stale.part").write_bytes(b"partial")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    try:
        (root / "outside-link.bin").symlink_to(outside)
        (root / "outside-dir").symlink_to(tmp_path, target_is_directory=True)
    except OSError as exc:  # pragma: no cover - platform policy dependent
        pytest.skip(f"symlinks are unavailable: {exc}")

    service = TftpServerService(tftp_settings(root))
    listing = await service.list_files()
    assert listing.root_directory == str(root.resolve())
    assert [item.filename for item in listing.files] == [
        "alpha.bin",
        "Beta.bin",
        "nested/gamma.bin",
    ]
    assert [item.size for item in listing.files] == [1, 2, 3]
    assert listing.truncated is False
    assert all(item.modified_at.tzinfo is not None for item in listing.files)

    monkeypatch.setattr(tftp_module, "FILE_LIST_LIMIT", 2)
    bounded = await service.list_files()
    assert len(bounded.files) == 2
    assert bounded.truncated is True
    assert all(
        not item.filename.startswith((".nettransfer-upload-", ".nettftp-upload-"))
        for item in bounded.files
    )
