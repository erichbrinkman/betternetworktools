from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Iterable
from typing import Any

import pytest

from better_network_tools.config import Settings, load_settings
from better_network_tools.telnet_models import TelnetConnectMessage
from better_network_tools.telnet_service import (
    DO,
    DONT,
    IAC,
    SB,
    SE,
    WILL,
    WONT,
    AsyncioTelnetSession,
    AsyncioTelnetTransport,
    TELNET_BINARY,
    TELNET_ECHO,
    TELNET_NAWS,
    TELNET_TERMINAL_TYPE,
    TELNET_TERMINAL_TYPE_IS,
    TELNET_TERMINAL_TYPE_SEND,
    TelnetNegotiator,
    TelnetProtocolError,
    TelnetSessionService,
    encode_telnet_data,
    encode_naws,
    escape_telnet_data,
    local_echo_bytes,
    telnet_bind_is_loopback,
    telnet_origin_allowed,
    telnet_scope_is_loopback,
)
from better_network_tools.terminal_sessions import InteractiveSessionLimiter


def connect_message() -> dict[str, object]:
    return {
        "type": "connect",
        "host": "router.example",
        "port": 23,
        "cols": 80,
        "rows": 24,
    }


class FakePeer:
    def __init__(self, messages: Iterable[dict[str, object]] = ()) -> None:
        self.incoming: asyncio.Queue[str] = asyncio.Queue()
        for message in messages:
            self.incoming.put_nowait(json.dumps(message))
        self.sent: list[dict[str, object]] = []
        self.close_calls: list[tuple[int, str | None]] = []

    async def receive_text(self) -> str:
        return await self.incoming.get()

    async def send_json(self, data: Any) -> None:
        assert isinstance(data, dict)
        self.sent.append(data.copy())

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        self.close_calls.append((code, reason))


class FakeRemoteSession:
    def __init__(
        self,
        output: Iterable[bytes] = (),
        *,
        local_echo_enabled: bool = False,
    ) -> None:
        self.output: asyncio.Queue[bytes] = asyncio.Queue()
        for chunk in output:
            self.output.put_nowait(chunk)
        self.writes: list[bytes] = []
        self.resizes: list[tuple[int, int]] = []
        self.close_calls = 0
        self.local_echo_enabled = local_echo_enabled

    async def read(self, _max_bytes: int) -> bytes:
        return await self.output.get()

    async def write(self, data: bytes) -> None:
        self.writes.append(data)
        await asyncio.sleep(0)

    async def resize(self, cols: int, rows: int) -> None:
        self.resizes.append((cols, rows))
        await asyncio.sleep(0)

    async def close(self) -> None:
        self.close_calls += 1
        self.output.put_nowait(b"")


class FakeTransport:
    def __init__(self, remote: FakeRemoteSession | None = None) -> None:
        self.remote = remote or FakeRemoteSession()
        self.open_calls: list[tuple[str, int, int, int, float]] = []
        self.opened = asyncio.Event()

    async def open_session(
        self, request: TelnetConnectMessage, timeout: float
    ) -> FakeRemoteSession:
        self.open_calls.append(
            (request.host, request.port, request.cols, request.rows, timeout)
        )
        self.opened.set()
        return self.remote


def test_telnet_negotiation_is_fragment_safe_and_does_not_loop() -> None:
    negotiator = TelnetNegotiator(cols=255, rows=511)
    initial = negotiator.initial_bytes()
    assert bytes((IAC, WILL, TELNET_NAWS)) in initial
    assert encode_naws(255, 511) not in initial

    application = bytearray()
    replies = bytearray()
    transcript = (
        bytes((IAC, DO, TELNET_TERMINAL_TYPE))
        + bytes((IAC, SB, TELNET_TERMINAL_TYPE, TELNET_TERMINAL_TYPE_SEND, IAC, SE))
    )
    for value in transcript:
        output, response = negotiator.feed(bytes((value,)))
        application.extend(output)
        replies.extend(response)

    assert application == b""
    assert replies == (
        bytes((IAC, SB, TELNET_TERMINAL_TYPE, TELNET_TERMINAL_TYPE_IS))
        + b"xterm-256color"
        + bytes((IAC, SE))
    )
    assert negotiator.feed(bytes((IAC, DO, TELNET_TERMINAL_TYPE))) == (
        b"",
        b"",
    )

    # ECHO was already requested in the initial negotiation. Its WILL is an
    # acknowledgement and repeated acknowledgements must not generate DO loops.
    assert negotiator.feed(bytes((IAC, WILL, TELNET_ECHO))) == (b"", b"")
    assert negotiator.feed(bytes((IAC, WILL, TELNET_ECHO))) == (b"", b"")

    unknown = 99
    assert negotiator.feed(bytes((IAC, WILL, unknown))) == (
        b"",
        bytes((IAC, DONT, unknown)),
    )
    assert negotiator.feed(bytes((IAC, WILL, unknown))) == (b"", b"")
    assert negotiator.feed(bytes((IAC, DO, unknown))) == (
        b"",
        bytes((IAC, WONT, unknown)),
    )
    assert negotiator.feed(bytes((IAC, DO, unknown))) == (b"", b"")
    assert negotiator.feed(bytes((IAC, DONT, unknown))) == (b"", b"")
    assert negotiator.feed(bytes((IAC, DO, unknown))) == (
        b"",
        bytes((IAC, WONT, unknown)),
    )


def test_ttype_and_naws_are_sent_only_after_option_agreement() -> None:
    negotiator = TelnetNegotiator(cols=255, rows=511)
    negotiator.initial_bytes()
    send_ttype = bytes(
        (IAC, SB, TELNET_TERMINAL_TYPE, TELNET_TERMINAL_TYPE_SEND, IAC, SE)
    )
    assert negotiator.feed(send_ttype) == (b"", b"")
    assert negotiator.resize_bytes(132, 44) == b""

    assert negotiator.feed(bytes((IAC, DO, TELNET_NAWS))) == (
        b"",
        encode_naws(132, 44),
    )
    assert negotiator.feed(bytes((IAC, DO, TELNET_NAWS))) == (b"", b"")
    assert negotiator.resize_bytes(255, 511) == encode_naws(255, 511)

    negotiator.feed(bytes((IAC, DO, TELNET_TERMINAL_TYPE)))
    _output, reply = negotiator.feed(send_ttype)
    assert reply.endswith(b"xterm-256color" + bytes((IAC, SE)))


def test_remote_echo_and_outbound_binary_follow_negotiation_state() -> None:
    negotiator = TelnetNegotiator(cols=80, rows=24)
    negotiator.initial_bytes()
    assert not negotiator.remote_echo_enabled
    assert not negotiator.outbound_binary_enabled

    negotiator.feed(bytes((IAC, WILL, TELNET_ECHO)))
    negotiator.feed(bytes((IAC, DO, TELNET_BINARY)))
    assert negotiator.remote_echo_enabled
    assert negotiator.outbound_binary_enabled

    negotiator.feed(bytes((IAC, WONT, TELNET_ECHO)))
    negotiator.feed(bytes((IAC, DONT, TELNET_BINARY)))
    assert not negotiator.remote_echo_enabled
    assert not negotiator.outbound_binary_enabled


def test_iac_and_nvt_cr_sequences_survive_fragmented_reads() -> None:
    negotiator = TelnetNegotiator(cols=80, rows=24)
    negotiator.initial_bytes()

    output, replies = negotiator.feed(b"one\r")
    assert output == b"one"
    assert replies == b""
    output, _ = negotiator.feed(b"\x00two\r")
    assert output == b"\rtwo"
    output, _ = negotiator.feed(b"\nthree" + bytes((IAC,)))
    assert output == b"\r\nthree"
    output, _ = negotiator.feed(bytes((IAC,)) + b"four")
    assert output == bytes((IAC,)) + b"four"

    # Once the remote endpoint's BINARY WILL is acknowledged, CR/NUL bytes are
    # application data and no NVT CR-NUL reduction is applied.
    negotiator.feed(bytes((IAC, WILL, TELNET_BINARY)))
    output, _ = negotiator.feed(b"\r\x00\r\n")
    assert output == b"\r\x00\r\n"


def test_final_bare_cr_is_flushed_and_subnegotiation_is_bounded() -> None:
    negotiator = TelnetNegotiator(cols=80, rows=24)
    output, _ = negotiator.feed(b"prompt\r")
    assert output == b"prompt"
    assert negotiator.finish() == b"\r"
    assert negotiator.finish() == b""

    overflow = TelnetNegotiator(cols=80, rows=24)
    with pytest.raises(TelnetProtocolError):
        overflow.feed(bytes((IAC, SB, 99)) + b"x" * 4097)


def test_outbound_terminal_data_obeys_nvt_binary_and_iac_rules() -> None:
    raw = b"\r\n\r\x00" + bytes((IAC,)) + b"end"
    assert escape_telnet_data(raw) == b"\r\n\r\x00" + bytes(
        (IAC, IAC)
    ) + b"end"
    assert encode_telnet_data(b"show\r", binary=False) == b"show\r\x00"
    assert encode_telnet_data(b"one\r\ntwo\r\x00", binary=False) == (
        b"one\r\ntwo\r\x00"
    )
    assert encode_telnet_data(b"show\r", binary=True) == b"show\r"
    assert local_echo_bytes(b"one\r\ntwo\rthree\x7f") == (
        b"one\r\ntwo\r\nthree\b \b"
    )
    assert encode_naws(255, 511) == bytes(
        (IAC, SB, TELNET_NAWS, 0, IAC, IAC, 1, IAC, IAC, IAC, SE)
    )


class FakeWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.drain_calls = 0
        self.close_calls = 0
        self.transport = FakeAbortTransport()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1

    def close(self) -> None:
        self.close_calls += 1

    async def wait_closed(self) -> None:
        return None


class FakeAbortTransport:
    def __init__(self) -> None:
        self.abort_calls = 0

    def abort(self) -> None:
        self.abort_calls += 1


@pytest.mark.asyncio
async def test_asyncio_session_preserves_terminal_input_and_negotiated_resize() -> None:
    reader = asyncio.StreamReader()
    writer = FakeWriter()
    session = AsyncioTelnetSession(reader, writer, 80, 24)  # type: ignore[arg-type]
    await session.initialize()
    initial = bytes(writer.data)
    assert bytes((IAC, WILL, TELNET_NAWS)) in initial
    assert encode_naws(80, 24) not in initial

    writer.data.clear()
    terminal = b"user\r\npassword\r\n" + bytes((IAC,))
    await session.write(terminal)
    assert bytes(writer.data) == escape_telnet_data(terminal)

    writer.data.clear()
    await session.write(b"show\r")
    assert bytes(writer.data) == b"show\r\x00"

    writer.data.clear()
    await session.resize(132, 44)
    assert writer.data == b""
    reader.feed_data(
        bytes((IAC, DO, TELNET_NAWS, IAC, DO, TELNET_BINARY))
    )
    reader.feed_data(b"ready")
    assert await session.read(1024) == b"ready"
    assert bytes(writer.data) == encode_naws(132, 44)

    writer.data.clear()
    await session.write(b"show\r")
    assert bytes(writer.data) == b"show\r"

    writer.data.clear()
    await session.resize(255, 511)
    assert bytes(writer.data) == encode_naws(255, 511)
    await session.close()
    assert writer.close_calls == 1


@pytest.mark.asyncio
async def test_service_bridges_binary_messages_resize_and_disconnect() -> None:
    remote = FakeRemoteSession(output=(b"login: ",))
    transport = FakeTransport(remote)
    service = TelnetSessionService(Settings(), transport=transport)
    terminal_input = b"admin\r\n" + bytes((IAC,))
    peer = FakePeer(
        [
            connect_message(),
            {
                "type": "input",
                "data": base64.b64encode(terminal_input).decode("ascii"),
            },
            {
                "type": "resize",
                "cols": 132,
                "rows": 44,
                "pixel_width": 1200,
                "pixel_height": 800,
            },
            {"type": "disconnect"},
        ]
    )

    await service.handle(peer)

    assert transport.open_calls == [("router.example", 23, 80, 24, 15.0)]
    assert remote.writes == [terminal_input]
    assert remote.resizes == [(132, 44)]
    assert remote.close_calls >= 1
    assert [event["status"] for event in peer.sent if event["type"] == "status"] == [
        "connecting",
        "connected",
        "disconnected",
    ]
    output = [event for event in peer.sent if event["type"] == "output"]
    assert output
    assert base64.b64decode(str(output[0]["data"])) == b"login: "
    assert not any(event["type"] == "exit" for event in peer.sent)
    assert peer.close_calls[-1][0] == 1000
    assert service.active_session_count == 0


@pytest.mark.asyncio
async def test_service_locally_echoes_when_server_declines_remote_echo() -> None:
    remote = FakeRemoteSession(local_echo_enabled=True)
    service = TelnetSessionService(Settings(), transport=FakeTransport(remote))
    terminal_input = b"admin\r"
    peer = FakePeer(
        [
            connect_message(),
            {
                "type": "input",
                "data": base64.b64encode(terminal_input).decode("ascii"),
            },
            {"type": "disconnect"},
        ]
    )

    await service.handle(peer)

    output = [event for event in peer.sent if event["type"] == "output"]
    assert [base64.b64decode(str(event["data"])) for event in output] == [
        b"admin\r\n"
    ]


@pytest.mark.asyncio
async def test_remote_eof_emits_null_exit_and_disconnected_status() -> None:
    remote = FakeRemoteSession(output=(b"bye\r\n", b""))
    service = TelnetSessionService(Settings(), transport=FakeTransport(remote))
    peer = FakePeer([connect_message()])

    await service.handle(peer)

    assert {
        "type": "exit",
        "exit_status": None,
        "signal": None,
    } in peer.sent
    assert base64.b64decode(
        str(next(event for event in peer.sent if event["type"] == "output")["data"])
    ) == b"bye\r\n"
    assert [event["status"] for event in peer.sent if event["type"] == "status"] == [
        "connecting",
        "connected",
        "disconnected",
    ]
    assert remote.close_calls >= 1


@pytest.mark.asyncio
async def test_invalid_message_is_fatal_generic_and_never_opens_tcp() -> None:
    transport = FakeTransport()
    service = TelnetSessionService(Settings(), transport=transport)
    invalid = connect_message()
    invalid["password"] = "must-not-be-collected"
    peer = FakePeer([invalid])

    await service.handle(peer)

    assert transport.open_calls == []
    assert "must-not-be-collected" not in json.dumps(peer.sent)
    assert peer.sent == [
        {
            "type": "error",
            "code": "telnet_invalid_message",
            "message": "Expected a valid connect message.",
            "fatal": True,
        }
    ]
    assert peer.close_calls[-1][0] == 1008


@pytest.mark.asyncio
async def test_shared_ssh_telnet_limiter_rejects_aggregate_overflow() -> None:
    limiter = InteractiveSessionLimiter(1)
    first_remote = FakeRemoteSession()
    first_transport = FakeTransport(first_remote)
    first = TelnetSessionService(
        Settings(telnet_active_session_limit=4),
        transport=first_transport,
        session_limiter=limiter,
    )
    first_peer = FakePeer([connect_message()])
    first_task = asyncio.create_task(first.handle(first_peer))
    await asyncio.wait_for(first_transport.opened.wait(), timeout=0.2)
    assert limiter.active == 1

    second = TelnetSessionService(
        Settings(telnet_active_session_limit=4),
        transport=FakeTransport(),
        session_limiter=limiter,
    )
    second_peer = FakePeer()
    await second.handle(second_peer)
    assert second_peer.sent[0]["code"] == "telnet_session_capacity_exceeded"
    assert limiter.active == 1

    await first.shutdown()
    await asyncio.gather(first_task, return_exceptions=True)
    assert limiter.active == 0
    assert first_remote.close_calls >= 1


@pytest.mark.asyncio
async def test_asyncio_transport_uses_only_a_loopback_tcp_server() -> None:
    accepted: list[tuple[str, bytes]] = []
    server_tasks: set[asyncio.Task[None]] = set()
    user_received = asyncio.Event()

    async def handle_client(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            initial = await asyncio.wait_for(reader.read(4096), timeout=0.5)
            accepted.append((str(writer.get_extra_info("sockname")[0]), initial))
            writer.write(b"login:" + bytes((IAC,)))
            await writer.drain()
            await asyncio.sleep(0)
            writer.write(bytes((WILL, TELNET_ECHO)) + b" ")
            await writer.drain()
            terminal = await asyncio.wait_for(reader.read(4096), timeout=0.5)
            accepted.append(("terminal", terminal))
            user_received.set()
        finally:
            writer.close()
            await writer.wait_closed()

    def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(handle_client(reader, writer))
        server_tasks.add(task)
        task.add_done_callback(server_tasks.discard)

    try:
        server = await asyncio.start_server(client_connected, "127.0.0.1", 0)
    except PermissionError:
        pytest.skip("sandbox does not permit an ephemeral loopback listener")
    port = int(server.sockets[0].getsockname()[1])
    request = TelnetConnectMessage(
        type="connect", host="127.0.0.1", port=port, cols=80, rows=24
    )
    remote = await AsyncioTelnetTransport().open_session(request, 1.0)
    try:
        output = bytearray()
        while len(output) < len(b"login: "):
            output.extend(
                await asyncio.wait_for(remote.read(1024), timeout=0.5)
            )
        assert output == b"login: "
        await remote.write(b"admin\r\n" + bytes((IAC,)))
        await asyncio.wait_for(user_received.wait(), timeout=0.5)
        assert await asyncio.wait_for(remote.read(1024), timeout=0.5) == b""
    finally:
        await remote.close()
        server.close()
        await server.wait_closed()
        if server_tasks:
            await asyncio.gather(*server_tasks)

    assert accepted[0][0] == "127.0.0.1"
    assert bytes((IAC, WILL, TELNET_NAWS)) in accepted[0][1]
    assert encode_naws(80, 24) not in accepted[0][1]
    assert accepted[1][1].endswith(b"admin\r\n" + bytes((IAC, IAC)))


def test_telnet_endpoint_authorization_helpers_are_exact() -> None:
    allowed = ("http://127.0.0.1:3000", "https://localhost:4173")
    assert telnet_origin_allowed("http://127.0.0.1:3000", allowed)
    assert telnet_origin_allowed("https://LOCALHOST:4173/", allowed)
    assert not telnet_origin_allowed(None, allowed)
    assert not telnet_origin_allowed("null", allowed)
    assert not telnet_origin_allowed("http://127.0.0.1:3001", allowed)
    assert not telnet_origin_allowed("http://127.0.0.1:3000/path", allowed)

    assert telnet_bind_is_loopback("127.0.0.1")
    assert telnet_bind_is_loopback("::1")
    assert telnet_bind_is_loopback("localhost")
    assert not telnet_bind_is_loopback("0.0.0.0")
    assert not telnet_bind_is_loopback("192.168.1.10")
    assert telnet_scope_is_loopback(
        {"server": ("127.0.0.1", 8766), "client": ("::1", 54321)}
    )
    assert not telnet_scope_is_loopback(
        {"server": ("192.0.2.10", 8766), "client": ("127.0.0.1", 54321)}
    )
    assert not telnet_scope_is_loopback(
        {"server": ("127.0.0.1", 8766), "client": ("192.0.2.20", 54321)}
    )


def test_telnet_resource_limits_are_loaded_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("BNT_TELNET_ACTIVE_SESSION_LIMIT", "6")
    monkeypatch.setenv("BNT_TELNET_CONNECT_TIMEOUT_SECONDS", "12.5")
    monkeypatch.setenv("BNT_TELNET_HANDSHAKE_TIMEOUT_SECONDS", "90")

    settings = load_settings()
    assert settings.telnet_active_session_limit == 6
    assert settings.telnet_connect_timeout_seconds == 12.5
    assert settings.telnet_handshake_timeout_seconds == 90.0
