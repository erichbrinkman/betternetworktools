"""Bounded loopback WebSocket bridge for interactive Telnet sessions."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import ipaddress
import json
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import TypeAdapter, ValidationError
from starlette.websockets import WebSocketDisconnect

from .config import Settings
from .telnet_models import (
    CONNECTED_ADAPTER,
    CONNECT_ADAPTER,
    TELNET_MESSAGE_LIMIT_CHARS,
    TelnetConnectMessage,
    TelnetDisconnectMessage,
    TelnetInputMessage,
    TelnetResizeMessage,
)
from .terminal_sessions import InteractiveSessionLimiter


IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

TELNET_BINARY = 0
TELNET_ECHO = 1
TELNET_SUPPRESS_GO_AHEAD = 3
TELNET_TERMINAL_TYPE = 24
TELNET_NAWS = 31
TELNET_TERMINAL_TYPE_IS = 0
TELNET_TERMINAL_TYPE_SEND = 1

_OUTPUT_CHUNK_BYTES = 32 * 1024
_SUBNEGOTIATION_LIMIT_BYTES = 4 * 1024
_STREAM_READER_LIMIT_BYTES = 64 * 1024
_DRAIN_TIMEOUT_SECONDS = 1.0
_REMOTE_CLOSE_TIMEOUT_SECONDS = 1.0
_TASK_CLEANUP_TIMEOUT_SECONDS = 0.25
_SHUTDOWN_TIMEOUT_SECONDS = 2.0
_WEBSOCKET_CLOSE_TIMEOUT_SECONDS = 0.25


def _observe_task(task: asyncio.Task[Any]) -> bool:
    try:
        task.result()
    except (asyncio.CancelledError, Exception):
        return False
    return True


async def _wait_tasks_bounded(
    tasks: set[asyncio.Task[Any]],
    timeout: float,
    *,
    cancel_pending: bool,
) -> bool:
    if not tasks:
        return True
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout)
    except asyncio.CancelledError:
        for task in tasks:
            if not task.done():
                task.cancel()
                task.add_done_callback(_observe_task)
        raise

    succeeded = all(_observe_task(task) for task in done)
    if cancel_pending:
        for task in pending:
            task.cancel()
            task.add_done_callback(_observe_task)
    return not pending and succeeded


class TelnetWebSocketPeer(Protocol):
    async def receive_text(self) -> str: ...

    async def send_json(self, data: Any) -> None: ...

    async def close(self, code: int = 1000, reason: str | None = None) -> None: ...


class TelnetRemoteSession(Protocol):
    @property
    def local_echo_enabled(self) -> bool: ...

    async def read(self, max_bytes: int) -> bytes: ...

    async def write(self, data: bytes) -> None: ...

    async def resize(self, cols: int, rows: int) -> None: ...

    async def close(self) -> None: ...


class TelnetTransport(Protocol):
    async def open_session(
        self, request: TelnetConnectMessage, timeout: float
    ) -> TelnetRemoteSession: ...


class TelnetSessionHandler(Protocol):
    async def handle(self, peer: TelnetWebSocketPeer) -> None: ...

    async def shutdown(self) -> None: ...


class TelnetProtocolError(ValueError):
    pass


class _ProtocolViolation(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class _HandshakeTimeout(Exception):
    pass


class _PeerClosed(Exception):
    pass


class _SerializedSender:
    def __init__(self, peer: TelnetWebSocketPeer) -> None:
        self.peer = peer
        self._lock = asyncio.Lock()
        self.closed = False

    async def send(self, data: dict[str, object]) -> None:
        async with self._lock:
            if self.closed:
                return
            try:
                await self.peer.send_json(data)
            except (WebSocketDisconnect, RuntimeError, OSError) as exc:
                self.closed = True
                raise _PeerClosed from exc

    async def close(self, code: int, reason: str) -> None:
        async with self._lock:
            if self.closed:
                return
            self.closed = True
            close_task = asyncio.create_task(
                self.peer.close(code=code, reason=reason[:123])
            )
            await _wait_tasks_bounded(
                {close_task},
                _WEBSOCKET_CLOSE_TIMEOUT_SECONDS,
                cancel_pending=True,
            )


def telnet_origin_allowed(
    origin: str | None, allowed_origins: tuple[str, ...]
) -> bool:
    """Require an exact configured HTTP(S) origin for the Telnet WebSocket."""

    if not origin:
        return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return False
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    configured = {value.rstrip("/").lower() for value in allowed_origins}
    return normalized in configured


def telnet_bind_is_loopback(host: str) -> bool:
    """Keep the plaintext Telnet bridge unavailable on non-loopback binds."""

    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def telnet_scope_is_loopback(scope: Mapping[str, object]) -> bool:
    """Verify both actual ASGI socket endpoints are loopback addresses."""

    for name in ("server", "client"):
        endpoint = scope.get(name)
        if not isinstance(endpoint, (list, tuple)) or not endpoint:
            return False
        address = endpoint[0]
        if not isinstance(address, str):
            return False
        try:
            if not ipaddress.ip_address(address.split("%", 1)[0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def _command(verb: int, option: int) -> bytes:
    return bytes((IAC, verb, option))


def _escape_subnegotiation_data(data: bytes) -> bytes:
    return data.replace(bytes((IAC,)), bytes((IAC, IAC)))


def encode_naws(cols: int, rows: int) -> bytes:
    """Encode NAWS with 16-bit network byte order and quoted IAC octets."""

    dimensions = cols.to_bytes(2, "big") + rows.to_bytes(2, "big")
    return (
        bytes((IAC, SB, TELNET_NAWS))
        + _escape_subnegotiation_data(dimensions)
        + bytes((IAC, SE))
    )


def escape_telnet_data(data: bytes) -> bytes:
    """Quote literal IAC bytes without changing CR, LF, NUL, or other data."""

    return data.replace(bytes((IAC,)), bytes((IAC, IAC)))


def encode_telnet_data(data: bytes, *, binary: bool) -> bytes:
    """Encode browser input for the negotiated client-to-server data mode."""

    if binary:
        return escape_telnet_data(data)

    nvt = bytearray()
    index = 0
    while index < len(data):
        value = data[index]
        nvt.append(value)
        if value == 13:
            following = data[index + 1] if index + 1 < len(data) else None
            if following not in {0, 10}:
                nvt.append(0)
        index += 1
    return escape_telnet_data(bytes(nvt))


def local_echo_bytes(data: bytes) -> bytes:
    """Render basic line-at-a-time input when the peer declines remote echo."""

    echoed = bytearray()
    index = 0
    while index < len(data):
        value = data[index]
        if value == 13:
            echoed.extend(b"\r\n")
            if index + 1 < len(data) and data[index + 1] == 10:
                index += 1
        elif value == 10:
            echoed.extend(b"\r\n")
        elif value in {8, 127}:
            echoed.extend(b"\b \b")
        elif value != 0:
            echoed.append(value)
        index += 1
    return bytes(echoed)


class TelnetNegotiator:
    """Incremental Telnet command parser with bounded RFC 1143-style state."""

    _LOCAL_OPTIONS = {
        TELNET_BINARY,
        TELNET_SUPPRESS_GO_AHEAD,
        TELNET_TERMINAL_TYPE,
        TELNET_NAWS,
    }
    _REMOTE_OPTIONS = {
        TELNET_BINARY,
        TELNET_ECHO,
        TELNET_SUPPRESS_GO_AHEAD,
    }

    def __init__(self, cols: int, rows: int) -> None:
        self.cols = cols
        self.rows = rows
        self._state = "data"
        self._negotiation_verb: int | None = None
        self._subnegotiation_option: int | None = None
        self._subnegotiation = bytearray()
        self._subnegotiation_size = 0
        self._local_pending = set(self._LOCAL_OPTIONS)
        self._local_enabled: set[int] = set()
        self._local_rejected: set[int] = set()
        self._remote_pending = set(self._REMOTE_OPTIONS)
        self._remote_enabled: set[int] = set()
        self._remote_rejected: set[int] = set()
        self._inbound_cr_pending = False
        self._finished = False

    def initial_bytes(self) -> bytes:
        """Advertise supported options without premature subnegotiation."""

        local = b"".join(
            _command(WILL, option)
            for option in (
                TELNET_BINARY,
                TELNET_SUPPRESS_GO_AHEAD,
                TELNET_TERMINAL_TYPE,
                TELNET_NAWS,
            )
        )
        remote = b"".join(
            _command(DO, option)
            for option in (
                TELNET_BINARY,
                TELNET_ECHO,
                TELNET_SUPPRESS_GO_AHEAD,
            )
        )
        return local + remote

    def resize_bytes(self, cols: int, rows: int) -> bytes:
        self.cols = cols
        self.rows = rows
        if TELNET_NAWS not in self._local_enabled:
            return b""
        return encode_naws(cols, rows)

    @property
    def outbound_binary_enabled(self) -> bool:
        return TELNET_BINARY in self._local_enabled

    @property
    def remote_echo_enabled(self) -> bool:
        return TELNET_ECHO in self._remote_enabled

    def feed(self, data: bytes) -> tuple[bytes, bytes]:
        """Return application data and negotiation replies from one fragment."""

        application = bytearray()
        replies = bytearray()
        for value in data:
            if self._state == "data":
                if value == IAC:
                    self._state = "iac"
                else:
                    self._append_application(application, value)
            elif self._state == "iac":
                if value == IAC:
                    self._append_application(application, IAC)
                    self._state = "data"
                elif value in {DO, DONT, WILL, WONT}:
                    self._negotiation_verb = value
                    self._state = "option"
                elif value == SB:
                    self._state = "subnegotiation_option"
                else:
                    # Other one-byte Telnet commands do not carry user data.
                    self._state = "data"
            elif self._state == "option":
                assert self._negotiation_verb is not None
                replies.extend(self._negotiate(self._negotiation_verb, value))
                self._negotiation_verb = None
                self._state = "data"
            elif self._state == "subnegotiation_option":
                self._subnegotiation_option = value
                self._subnegotiation.clear()
                self._subnegotiation_size = 0
                self._state = "subnegotiation"
            elif self._state == "subnegotiation":
                if value == IAC:
                    self._state = "subnegotiation_iac"
                else:
                    self._append_subnegotiation(value)
            else:
                assert self._state == "subnegotiation_iac"
                if value == IAC:
                    self._append_subnegotiation(IAC)
                    self._state = "subnegotiation"
                elif value == SE:
                    replies.extend(self._finish_subnegotiation())
                    self._state = "data"
                else:
                    # Ignore an embedded command and continue consuming the
                    # subnegotiation until an unambiguous IAC SE terminator.
                    self._state = "subnegotiation"
        return bytes(application), bytes(replies)

    def finish(self) -> bytes:
        """Flush a final bare CR when the TCP peer closes in NVT mode."""

        if self._finished:
            return b""
        self._finished = True
        if self._inbound_cr_pending:
            self._inbound_cr_pending = False
            return b"\r"
        return b""

    def _append_application(self, application: bytearray, value: int) -> None:
        if TELNET_BINARY in self._remote_enabled:
            if self._inbound_cr_pending:
                application.append(13)
                self._inbound_cr_pending = False
            application.append(value)
            return

        if self._inbound_cr_pending:
            self._inbound_cr_pending = False
            application.append(13)
            if value == 0:
                return
        if value == 13:
            self._inbound_cr_pending = True
        else:
            application.append(value)

    def _append_subnegotiation(self, value: int) -> None:
        self._subnegotiation_size += 1
        if self._subnegotiation_size > _SUBNEGOTIATION_LIMIT_BYTES:
            raise TelnetProtocolError("Telnet subnegotiation exceeded its limit")
        self._subnegotiation.append(value)

    def _finish_subnegotiation(self) -> bytes:
        option = self._subnegotiation_option
        payload = bytes(self._subnegotiation)
        self._subnegotiation_option = None
        self._subnegotiation.clear()
        self._subnegotiation_size = 0
        if (
            option == TELNET_TERMINAL_TYPE
            and TELNET_TERMINAL_TYPE in self._local_enabled
            and payload == bytes((TELNET_TERMINAL_TYPE_SEND,))
        ):
            terminal = bytes((TELNET_TERMINAL_TYPE_IS,)) + b"xterm-256color"
            return (
                bytes((IAC, SB, TELNET_TERMINAL_TYPE))
                + _escape_subnegotiation_data(terminal)
                + bytes((IAC, SE))
            )
        return b""

    def _negotiate(self, verb: int, option: int) -> bytes:
        if verb == DO:
            if option not in self._LOCAL_OPTIONS:
                if option in self._local_rejected:
                    return b""
                self._local_rejected.add(option)
                return _command(WONT, option)
            if option in self._local_enabled:
                return b""
            if option in self._local_pending:
                self._local_pending.remove(option)
                self._local_enabled.add(option)
                reply = b""
            else:
                self._local_enabled.add(option)
                reply = _command(WILL, option)
            if option == TELNET_NAWS:
                reply += encode_naws(self.cols, self.rows)
            return reply

        if verb == DONT:
            if option in self._local_rejected:
                self._local_rejected.remove(option)
                return b""
            if option in self._local_pending:
                self._local_pending.remove(option)
                return b""
            if option in self._local_enabled:
                self._local_enabled.remove(option)
                return _command(WONT, option)
            return b""

        if verb == WILL:
            if option not in self._REMOTE_OPTIONS:
                if option in self._remote_rejected:
                    return b""
                self._remote_rejected.add(option)
                return _command(DONT, option)
            if option in self._remote_enabled:
                return b""
            if option in self._remote_pending:
                self._remote_pending.remove(option)
                self._remote_enabled.add(option)
                return b""
            self._remote_enabled.add(option)
            return _command(DO, option)

        assert verb == WONT
        self._remote_rejected.discard(option)
        self._remote_pending.discard(option)
        self._remote_enabled.discard(option)
        return b""


class AsyncioTelnetSession:
    """Asyncio stream adapter which applies Telnet framing and negotiation."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        cols: int,
        rows: int,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._negotiator = TelnetNegotiator(cols, rows)
        self._write_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._closed = False

    async def initialize(self) -> None:
        await self._write_protocol(self._negotiator.initial_bytes())

    @property
    def local_echo_enabled(self) -> bool:
        return not self._negotiator.remote_echo_enabled

    async def read(self, max_bytes: int) -> bytes:
        while True:
            raw = await self._reader.read(min(max_bytes, _OUTPUT_CHUNK_BYTES))
            if not raw:
                return self._negotiator.finish()
            application, replies = self._negotiator.feed(raw)
            if replies:
                await self._write_protocol(replies)
            if application:
                return application

    async def write(self, data: bytes) -> None:
        await self._write_protocol(
            encode_telnet_data(
                data,
                binary=self._negotiator.outbound_binary_enabled,
            )
        )

    async def resize(self, cols: int, rows: int) -> None:
        payload = self._negotiator.resize_bytes(cols, rows)
        if payload:
            await self._write_protocol(payload)

    async def _write_protocol(self, data: bytes) -> None:
        async with self._write_lock:
            if self._closed:
                raise ConnectionError("Telnet session is closed")
            self._writer.write(data)
            async with asyncio.timeout(_DRAIN_TIMEOUT_SECONDS):
                await self._writer.drain()

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            with contextlib.suppress(Exception):
                self._writer.close()
            wait_task = asyncio.create_task(self._writer.wait_closed())
            try:
                closed = await _wait_tasks_bounded(
                    {wait_task},
                    _REMOTE_CLOSE_TIMEOUT_SECONDS,
                    cancel_pending=True,
                )
            except asyncio.CancelledError:
                self._abort_transport()
                raise
            if not closed:
                self._abort_transport()

    def _abort_transport(self) -> None:
        transport = getattr(self._writer, "transport", None)
        abort = getattr(transport, "abort", None)
        if callable(abort):
            with contextlib.suppress(Exception):
                abort()


class AsyncioTelnetTransport:
    async def open_session(
        self, request: TelnetConnectMessage, timeout: float
    ) -> TelnetRemoteSession:
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(timeout):
                reader, writer = await asyncio.open_connection(
                    request.host,
                    request.port,
                    limit=_STREAM_READER_LIMIT_BYTES,
                    happy_eyeballs_delay=0.25,
                    interleave=1,
                )
                session = AsyncioTelnetSession(
                    reader, writer, request.cols, request.rows
                )
                await session.initialize()
            return session
        except (Exception, asyncio.CancelledError):
            if writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
                wait_task = asyncio.create_task(writer.wait_closed())
                await _wait_tasks_bounded(
                    {wait_task}, _REMOTE_CLOSE_TIMEOUT_SECONDS, cancel_pending=True
                )
            raise


class TelnetSessionService:
    """Own active Telnet bridges and enforce bounded shared capacity."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: TelnetTransport | None = None,
        session_limiter: InteractiveSessionLimiter | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or AsyncioTelnetTransport()
        self._session_limiter = session_limiter or InteractiveSessionLimiter(
            settings.telnet_active_session_limit
        )
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._shutting_down = False

    @property
    def active_session_count(self) -> int:
        return len(self._tasks)

    async def handle(self, peer: TelnetWebSocketPeer) -> None:
        task = asyncio.current_task()
        if task is None:  # pragma: no cover
            raise RuntimeError("Telnet session has no owning task")
        aggregate_acquired = False
        async with self._lock:
            rejected = self._shutting_down or (
                len(self._tasks) >= self.settings.telnet_active_session_limit
            )
            if not rejected:
                aggregate_acquired = await self._session_limiter.try_acquire()
                rejected = not aggregate_acquired
                if aggregate_acquired:
                    self._tasks.add(task)

        sender = _SerializedSender(peer)
        if rejected:
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": "telnet_session_capacity_exceeded",
                        "message": "The active Telnet session limit has been reached.",
                        "fatal": True,
                    }
                )
            await sender.close(1013, "Telnet session capacity reached")
            return

        try:
            await self._serve(peer, sender)
        except _PeerClosed:
            pass
        except _ProtocolViolation as exc:
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": exc.code,
                        "message": exc.message,
                        "fatal": True,
                    }
                )
            await sender.close(1008, exc.message)
        except _HandshakeTimeout:
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": "telnet_handshake_timeout",
                        "message": "The Telnet handshake timed out.",
                        "fatal": True,
                    }
                )
            await sender.close(1008, "Telnet handshake timed out")
        except asyncio.CancelledError:
            await sender.close(1012, "Local Telnet service is shutting down")
            raise
        except Exception:
            # Remote banners and protocol errors must never be echoed into an
            # error response. Login data travels only as opaque terminal bytes.
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": "telnet_connection_failed",
                        "message": "The Telnet connection could not be established.",
                        "fatal": True,
                    }
                )
            await sender.close(1011, "Telnet connection failed")
        finally:
            async with self._lock:
                self._tasks.discard(task)
            if aggregate_acquired:
                await self._session_limiter.release()

    async def shutdown(self) -> None:
        async with self._lock:
            self._shutting_down = True
            current = asyncio.current_task()
            tasks = [task for task in self._tasks if task is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await _wait_tasks_bounded(
                set(tasks), _SHUTDOWN_TIMEOUT_SECONDS, cancel_pending=True
            )
        async with self._lock:
            self._tasks.difference_update(tasks)

    async def _serve(
        self, peer: TelnetWebSocketPeer, sender: _SerializedSender
    ) -> None:
        try:
            request = await self._receive(
                peer,
                CONNECT_ADAPTER,
                timeout=self.settings.telnet_handshake_timeout_seconds,
                expected="connect",
            )
        except asyncio.TimeoutError as exc:
            raise _HandshakeTimeout from exc
        assert isinstance(request, TelnetConnectMessage)

        await sender.send({"type": "status", "status": "connecting"})
        remote: TelnetRemoteSession | None = None
        try:
            remote = await self.transport.open_session(
                request, self.settings.telnet_connect_timeout_seconds
            )
            del request
            await sender.send({"type": "status", "status": "connected"})
            remote_closed = await self._bridge(peer, sender, remote)
            if remote_closed:
                await sender.send(
                    {
                        "type": "exit",
                        "exit_status": None,
                        "signal": None,
                    }
                )
            await sender.send({"type": "status", "status": "disconnected"})
            await sender.close(1000, "Telnet session ended")
        finally:
            if remote is not None:
                await self._close_remote(remote)

    async def _bridge(
        self,
        peer: TelnetWebSocketPeer,
        sender: _SerializedSender,
        remote: TelnetRemoteSession,
    ) -> bool:
        client_task = asyncio.create_task(
            self._consume_client(peer, sender, remote),
            name="telnet-client-input",
        )
        output_task = asyncio.create_task(
            self._forward_output(sender, remote), name="telnet-output"
        )
        try:
            done, _pending = await asyncio.wait(
                {client_task, output_task}, return_when=asyncio.FIRST_COMPLETED
            )
            if output_task in done:
                output_task.result()
                client_task.cancel()
                await _wait_tasks_bounded(
                    {client_task},
                    _TASK_CLEANUP_TIMEOUT_SECONDS,
                    cancel_pending=True,
                )
                return True

            client_task.result()
            await self._close_remote(remote)
            output_task.cancel()
            await _wait_tasks_bounded(
                {output_task},
                _TASK_CLEANUP_TIMEOUT_SECONDS,
                cancel_pending=True,
            )
            return False
        finally:
            for task in (client_task, output_task):
                if not task.done():
                    task.cancel()
            await _wait_tasks_bounded(
                {client_task, output_task},
                _TASK_CLEANUP_TIMEOUT_SECONDS,
                cancel_pending=True,
            )

    async def _close_remote(self, remote: TelnetRemoteSession) -> None:
        close_task = asyncio.create_task(remote.close(), name="telnet-remote-close")
        await _wait_tasks_bounded(
            {close_task}, _REMOTE_CLOSE_TIMEOUT_SECONDS, cancel_pending=True
        )

    async def _consume_client(
        self,
        peer: TelnetWebSocketPeer,
        sender: _SerializedSender,
        remote: TelnetRemoteSession,
    ) -> None:
        while True:
            message = await self._receive(
                peer,
                CONNECTED_ADAPTER,
                timeout=None,
                expected="input, resize, or disconnect",
            )
            if isinstance(message, TelnetDisconnectMessage):
                return
            if isinstance(message, TelnetInputMessage):
                data = message.decode()
                local_echo = remote.local_echo_enabled
                await remote.write(data)
                if local_echo:
                    await self._send_output(sender, local_echo_bytes(data))
            elif isinstance(message, TelnetResizeMessage):
                await remote.resize(message.cols, message.rows)

    async def _forward_output(
        self, sender: _SerializedSender, remote: TelnetRemoteSession
    ) -> None:
        while True:
            data = await remote.read(_OUTPUT_CHUNK_BYTES)
            if not data:
                return
            if not isinstance(data, bytes):
                raise TypeError("Telnet output must be bytes")
            await self._send_output(sender, data)

    async def _send_output(
        self, sender: _SerializedSender, data: bytes
    ) -> None:
        for offset in range(0, len(data), _OUTPUT_CHUNK_BYTES):
            encoded = base64.b64encode(
                data[offset : offset + _OUTPUT_CHUNK_BYTES]
            ).decode("ascii")
            await sender.send(
                {
                    "type": "output",
                    "stream": "stdout",
                    "data": encoded,
                }
            )

    async def _receive(
        self,
        peer: TelnetWebSocketPeer,
        adapter: TypeAdapter[Any],
        *,
        timeout: float | None,
        expected: str,
    ) -> object:
        try:
            if timeout is None:
                raw = await peer.receive_text()
            else:
                async with asyncio.timeout(timeout):
                    raw = await peer.receive_text()
        except (WebSocketDisconnect, RuntimeError, OSError) as exc:
            raise _PeerClosed from exc
        if len(raw) > TELNET_MESSAGE_LIMIT_CHARS:
            raise _ProtocolViolation(
                "telnet_message_too_large", "The Telnet message is too large."
            )
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise _ProtocolViolation(
                "telnet_invalid_message",
                "Telnet messages must be valid JSON objects.",
            ) from exc
        if not isinstance(payload, dict):
            raise _ProtocolViolation(
                "telnet_invalid_message", "Telnet messages must be JSON objects."
            )
        try:
            return adapter.validate_python(payload)
        except ValidationError as exc:
            raise _ProtocolViolation(
                "telnet_invalid_message", f"Expected a valid {expected} message."
            ) from exc
