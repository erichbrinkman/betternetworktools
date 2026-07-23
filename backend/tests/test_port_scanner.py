from __future__ import annotations

import asyncio
import errno
import socket

import pytest

from better_network_tools.port_scanner import (
    BoundedSystemPortResolver,
    TcpConnectPortProbe,
)


class FakeReader:
    def __init__(self, data: bytes = b"") -> None:
        self.data = data
        self.read_sizes: list[int] = []

    async def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        return self.data[:size]


class FakeWriter:
    def __init__(self) -> None:
        self.written = b""
        self.drain_calls = 0
        self.closed = False
        self.waited_closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        self.drain_calls += 1

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited_closed = True


@pytest.mark.asyncio
async def test_bounded_resolver_uses_stream_records_and_canonicalizes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    def fake_getaddrinfo(*args: object) -> list[tuple[object, ...]]:
        calls.append(args)
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:0db8::8", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.8", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    resolver = BoundedSystemPortResolver(workers=1)
    try:
        resolved = await resolver.resolve("router.example")
    finally:
        resolver.close()

    assert resolved.address == "2001:db8::8"
    assert resolved.address_family == "IPv6"
    assert calls == [
        ("router.example", None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    ]


@pytest.mark.asyncio
async def test_open_probe_uses_numeric_family_and_returns_bounded_sanitized_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = (
        b"HTTP/1.1 204\x00 No Content\r\nServer: edge\x00"
        + (b"x" * 400)
        + b"\r\n\r\n"
    )
    reader = FakeReader(response)
    writer = FakeWriter()
    connection_calls: list[tuple[object, ...]] = []

    async def fake_open_connection(
        address: str,
        port: int,
        *,
        family: socket.AddressFamily,
        flags: socket.AddressInfo,
    ) -> tuple[FakeReader, FakeWriter]:
        connection_calls.append((address, port, family, flags))
        return reader, writer

    timestamps = iter((10.0, 10.012345))
    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    monkeypatch.setattr(
        "better_network_tools.port_scanner.time.perf_counter",
        lambda: next(timestamps),
    )

    observation = await TcpConnectPortProbe().probe(
        "192.0.2.10",
        "IPv4",
        80,
        timeout=0.2,
        banner_timeout=0.1,
        collect_banner=True,
    )

    assert connection_calls == [
        ("192.0.2.10", 80, socket.AF_INET, socket.AI_NUMERICHOST)
    ]
    assert observation.state == "open"
    assert observation.result is not None
    assert observation.result.port == 80
    assert observation.result.service == "http"
    assert observation.result.banner == "HTTP/1.1 204  No Content"
    assert "\x00" not in observation.result.banner
    assert observation.result.http_status == 204
    assert observation.result.http_server is not None
    assert observation.result.http_server.startswith("edge ")
    assert len(observation.result.http_server) == 240
    assert "\x00" not in observation.result.http_server
    assert observation.result.latency_ms == pytest.approx(12.345)
    assert reader.read_sizes == [1024]
    assert writer.written.startswith(b"HEAD / HTTP/1.0\r\n")
    assert b"Host: 192.0.2.10\r\n" in writer.written
    assert writer.drain_calls == 1
    assert writer.closed is True
    assert writer.waited_closed is True


@pytest.mark.asyncio
async def test_open_probe_skips_banner_io_when_collection_is_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = FakeReader(b"SSH-2.0-should-not-be-read\r\n")
    writer = FakeWriter()

    async def fake_open_connection(*args: object, **kwargs: object):
        assert kwargs["family"] == socket.AF_INET6
        assert kwargs["flags"] == socket.AI_NUMERICHOST
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    observation = await TcpConnectPortProbe().probe(
        "2001:db8::10",
        "IPv6",
        22,
        timeout=0.2,
        banner_timeout=0.1,
        collect_banner=False,
    )

    assert observation.state == "open"
    assert observation.result is not None
    assert observation.result.service == "ssh"
    assert observation.result.banner is None
    assert observation.result.http_status is None
    assert observation.result.http_server is None
    assert reader.read_sizes == []
    assert writer.written == b""
    assert writer.closed is True
    assert writer.waited_closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_state"),
    [
        (TimeoutError(), "timed_out"),
        (ConnectionRefusedError(), "closed"),
        (ConnectionResetError(), "closed"),
        (OSError(errno.ECONNREFUSED, "refused"), "closed"),
        (OSError(errno.ECONNRESET, "reset"), "closed"),
        (OSError(errno.ETIMEDOUT, "timed out"), "timed_out"),
        (OSError(errno.EHOSTUNREACH, "unreachable"), "error"),
    ],
)
async def test_probe_classifies_bounded_connection_failures(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected_state: str,
) -> None:
    async def failing_open_connection(*args: object, **kwargs: object):
        raise failure

    monkeypatch.setattr(asyncio, "open_connection", failing_open_connection)

    observation = await TcpConnectPortProbe().probe(
        "192.0.2.10",
        "IPv4",
        443,
        timeout=0.05,
        banner_timeout=0.05,
        collect_banner=False,
    )

    assert observation.state == expected_state
    assert observation.result is None


@pytest.mark.asyncio
async def test_banner_timeout_preserves_open_classification_and_closes_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockingReader(FakeReader):
        async def read(self, size: int) -> bytes:
            self.read_sizes.append(size)
            await asyncio.Event().wait()
            raise AssertionError("bounded banner read must not finish")

    reader = BlockingReader()
    writer = FakeWriter()

    async def fake_open_connection(*args: object, **kwargs: object):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    observation = await asyncio.wait_for(
        TcpConnectPortProbe().probe(
            "192.0.2.10",
            "IPv4",
            22,
            timeout=0.05,
            banner_timeout=0.01,
            collect_banner=True,
        ),
        timeout=0.2,
    )

    assert observation.state == "open"
    assert observation.result is not None
    assert observation.result.service == "ssh"
    assert observation.result.banner is None
    assert reader.read_sizes == [1024]
    assert writer.closed is True
    assert writer.waited_closed is True


@pytest.mark.asyncio
async def test_invalid_http_metadata_cannot_downgrade_an_open_ipv6_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = FakeReader(b"HTTP/1.1 999 Strange\r\nServer: test\r\n\r\n")
    writer = FakeWriter()

    async def fake_open_connection(*args: object, **kwargs: object):
        return reader, writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)

    observation = await TcpConnectPortProbe().probe(
        "2001:db8::10",
        "IPv6",
        80,
        timeout=0.2,
        banner_timeout=0.1,
        collect_banner=True,
    )

    assert observation.state == "open"
    assert observation.result is not None
    assert observation.result.http_status is None
    assert observation.result.banner == "HTTP/1.1 999 Strange"
    assert b"Host: [2001:db8::10]\r\n" in writer.written
