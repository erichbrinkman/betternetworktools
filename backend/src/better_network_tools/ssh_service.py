"""Bounded, host-key-verifying QuickSSH WebSocket bridge."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import importlib
import ipaddress
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import TypeAdapter, ValidationError
from starlette.websockets import WebSocketDisconnect

from .config import Settings
from .ssh_models import (
    CONNECTED_ADAPTER,
    CONNECT_ADAPTER,
    SSH_MESSAGE_LIMIT_CHARS,
    TRUST_PHASE_ADAPTER,
    SshConnectMessage,
    SshDisconnectMessage,
    SshInputMessage,
    SshPasswordAuth,
    SshResizeMessage,
    SshTrustHostKeyMessage,
)
from .terminal_sessions import InteractiveSessionLimiter


_OUTPUT_CHUNK_BYTES = 32 * 1024
_OUTPUT_DRAIN_TIMEOUT_SECONDS = 0.5
_ASYNCSSH_CLOSE_TIMEOUT_SECONDS = 0.5
_ASYNCSSH_ABORT_TIMEOUT_SECONDS = 0.25
_REMOTE_CLOSE_TIMEOUT_SECONDS = 1.0
_TASK_CLEANUP_TIMEOUT_SECONDS = 0.25
_SHUTDOWN_TIMEOUT_SECONDS = 2.0
_WEBSOCKET_CLOSE_TIMEOUT_SECONDS = 0.25


def _observe_task(task: asyncio.Task[Any]) -> bool:
    """Consume a task result and return whether it completed successfully."""

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
    """Wait no longer than ``timeout`` and never block on cancellation."""

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

    results = [_observe_task(task) for task in done]
    succeeded = all(results)
    if cancel_pending:
        for task in pending:
            task.cancel()
            task.add_done_callback(_observe_task)
    return not pending and succeeded


async def _run_cleanup_awaitables(
    awaitables: list[Awaitable[object]], timeout: float
) -> bool:
    tasks = {asyncio.create_task(awaitable) for awaitable in awaitables}
    return await _wait_tasks_bounded(tasks, timeout, cancel_pending=True)


def _abort_connection(connection: Any) -> None:
    abort = getattr(connection, "abort", None)
    if callable(abort):
        with contextlib.suppress(Exception):
            abort()


async def _close_asyncssh_resources(
    connection: Any,
    process: Any | None = None,
) -> None:
    """Gracefully close AsyncSSH resources, then abort on a bounded timeout."""

    if process is not None:
        with contextlib.suppress(Exception):
            process.close()
    with contextlib.suppress(Exception):
        connection.close()

    try:
        waiters: list[Awaitable[object]] = []
        if process is not None:
            waiters.append(process.wait_closed())
        waiters.append(connection.wait_closed())
        closed = await _run_cleanup_awaitables(
            waiters, _ASYNCSSH_CLOSE_TIMEOUT_SECONDS
        )
        if closed:
            return

        _abort_connection(connection)
        abort_waiters: list[Awaitable[object]] = []
        if process is not None:
            abort_waiters.append(process.wait_closed())
        abort_waiters.append(connection.wait_closed())
        await _run_cleanup_awaitables(
            abort_waiters, _ASYNCSSH_ABORT_TIMEOUT_SECONDS
        )
    except asyncio.CancelledError:
        _abort_connection(connection)
        raise


class SshWebSocketPeer(Protocol):
    async def receive_text(self) -> str: ...

    async def send_json(self, data: Any) -> None: ...

    async def close(self, code: int = 1000, reason: str | None = None) -> None: ...


@dataclass(frozen=True, slots=True)
class SshHostKey:
    algorithm: str
    fingerprint: str
    public_key: str
    verifier: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class SshExit:
    exit_status: int | None = None
    signal: str | None = None


class SshRemoteSession(Protocol):
    async def read_stdout(self, max_bytes: int) -> bytes: ...

    async def read_stderr(self, max_bytes: int) -> bytes: ...

    async def write(self, data: bytes) -> None: ...

    async def resize(
        self, cols: int, rows: int, pixel_width: int, pixel_height: int
    ) -> None: ...

    async def wait(self) -> SshExit: ...

    async def close(self) -> None: ...


class SshTransport(Protocol):
    async def fetch_host_key(
        self, host: str, port: int, timeout: float
    ) -> SshHostKey: ...

    async def open_session(
        self,
        request: SshConnectMessage,
        host_key: SshHostKey,
        timeout: float,
    ) -> SshRemoteSession: ...


class SshSessionHandler(Protocol):
    async def handle(self, peer: SshWebSocketPeer) -> None: ...

    async def shutdown(self) -> None: ...


class SshTransportUnavailableError(RuntimeError):
    pass


class _ProtocolViolation(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


class _PeerClosed(Exception):
    pass


class _SerializedSender:
    def __init__(self, peer: SshWebSocketPeer) -> None:
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


def websocket_origin_allowed(
    origin: str | None, allowed_origins: tuple[str, ...]
) -> bool:
    """Return whether a browser WebSocket Origin exactly matches local config."""

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


def quickssh_bind_is_loopback(host: str) -> bool:
    """Keep the credential-bearing SSH bridge unavailable on LAN binds."""

    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def quickssh_scope_is_loopback(scope: Mapping[str, object]) -> bool:
    """Verify both live socket endpoints recorded by the ASGI server."""

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


class AsyncSshRemoteSession:
    """Small adapter around an AsyncSSH connection and interactive process."""

    def __init__(self, connection: Any, process: Any) -> None:
        self._connection = connection
        self._process = process
        self._close_lock = asyncio.Lock()
        self._closed = False

    async def read_stdout(self, max_bytes: int) -> bytes:
        data = await self._process.stdout.read(max_bytes)
        if not isinstance(data, bytes):
            raise TypeError("AsyncSSH stdout was not opened in byte mode")
        return data

    async def read_stderr(self, max_bytes: int) -> bytes:
        data = await self._process.stderr.read(max_bytes)
        if not isinstance(data, bytes):
            raise TypeError("AsyncSSH stderr was not opened in byte mode")
        return data

    async def write(self, data: bytes) -> None:
        self._process.stdin.write(data)
        await self._process.stdin.drain()

    async def resize(
        self, cols: int, rows: int, pixel_width: int, pixel_height: int
    ) -> None:
        self._process.change_terminal_size(cols, rows, pixel_width, pixel_height)

    async def wait(self) -> SshExit:
        await self._process.wait_closed()
        signal_info = self._process.exit_signal
        signal = signal_info[0] if signal_info else None
        exit_status = self._process.exit_status
        if exit_status is not None and exit_status < 0:
            exit_status = None
        return SshExit(exit_status=exit_status, signal=signal)

    async def close(self) -> None:
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            await _close_asyncssh_resources(self._connection, self._process)


class AsyncSshTransport:
    """AsyncSSH transport which always pins the separately fetched host key."""

    def __init__(self, library: Any | None = None) -> None:
        self._library = library

    def _get_library(self) -> Any:
        if self._library is not None:
            return self._library
        try:
            self._library = importlib.import_module("asyncssh")
        except ModuleNotFoundError as exc:  # pragma: no cover - packaging guard
            raise SshTransportUnavailableError(
                "AsyncSSH is unavailable in the local service environment"
            ) from exc
        return self._library

    async def fetch_host_key(
        self, host: str, port: int, timeout: float
    ) -> SshHostKey:
        asyncssh = self._get_library()
        async with asyncio.timeout(timeout):
            key = await asyncssh.get_server_host_key(
                host,
                port,
                config=None,
            )
        if key is None:
            raise OSError("the SSH server did not present a host key")
        exported = key.export_public_key("openssh").decode("ascii").strip().split()
        if len(exported) < 2:
            raise OSError("the SSH server returned an invalid host key")
        public_key = f"{exported[0]} {exported[1]}"
        return SshHostKey(
            algorithm=key.get_algorithm(),
            fingerprint=key.get_fingerprint("sha256"),
            public_key=public_key,
            verifier=key,
        )

    async def open_session(
        self,
        request: SshConnectMessage,
        host_key: SshHostKey,
        timeout: float,
    ) -> SshRemoteSession:
        asyncssh = self._get_library()
        # A three-list known_hosts tuple is the AsyncSSH form for exact trusted
        # host keys, trusted CA keys, and revoked keys. The fetched key is the
        # only trusted key. ``known_hosts=None`` is intentionally never used.
        options: dict[str, object] = {
            "port": request.port,
            "username": request.username,
            "known_hosts": ([host_key.verifier], [], []),
            "config": None,
            "gss_kex": False,
            "gss_auth": False,
            "host_based_auth": False,
            "kbdint_auth": False,
            "agent_forwarding": False,
        }
        if isinstance(request.auth, SshPasswordAuth):
            options.update(
                {
                    "password": request.auth.password.get_secret_value(),
                    "client_keys": None,
                    "agent_path": None,
                    "public_key_auth": False,
                    "password_auth": True,
                    "preferred_auth": ["password"],
                }
            )
        else:
            # Omitting client_keys loads the user's standard key files, while
            # omitting agent_path allows the local SSH_AUTH_SOCK to be used.
            options.update(
                {
                    "password_auth": False,
                    "public_key_auth": True,
                    "preferred_auth": ["publickey"],
                }
            )

        connection: Any | None = None
        try:
            async with asyncio.timeout(timeout):
                connection = await asyncssh.connect(request.host, **options)
                process = await connection.create_process(
                    term_type="xterm-256color",
                    term_size=(request.cols, request.rows),
                    encoding=None,
                )
        except (Exception, asyncio.CancelledError):
            if connection is not None:
                await _close_asyncssh_resources(connection)
            raise
        return AsyncSshRemoteSession(connection, process)


class SshSessionService:
    """Own active WebSocket bridges and enforce the global session ceiling."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: SshTransport | None = None,
        session_limiter: InteractiveSessionLimiter | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or AsyncSshTransport()
        self._session_limiter = session_limiter or InteractiveSessionLimiter(
            settings.ssh_active_session_limit
        )
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._shutting_down = False

    @property
    def active_session_count(self) -> int:
        return len(self._tasks)

    async def handle(self, peer: SshWebSocketPeer) -> None:
        task = asyncio.current_task()
        if task is None:  # pragma: no cover - async methods always have a task
            raise RuntimeError("QuickSSH session has no owning task")
        aggregate_acquired = False
        async with self._lock:
            rejected = self._shutting_down or (
                len(self._tasks) >= self.settings.ssh_active_session_limit
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
                        "code": "ssh_session_capacity_exceeded",
                        "message": "The active QuickSSH session limit has been reached.",
                        "fatal": True,
                    }
                )
            await sender.close(1013, "SSH session capacity reached")
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
        except asyncio.TimeoutError:
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": "ssh_handshake_timeout",
                        "message": "The QuickSSH handshake timed out.",
                        "fatal": True,
                    }
                )
            await sender.close(1008, "SSH handshake timed out")
        except asyncio.CancelledError:
            await sender.close(1012, "Local SSH service is shutting down")
            raise
        except Exception:
            # Never serialize exception details: authentication exceptions can
            # contain server-provided text and connect models contain secrets.
            with contextlib.suppress(_PeerClosed):
                await sender.send(
                    {
                        "type": "error",
                        "code": "ssh_connection_failed",
                        "message": "The SSH connection could not be established.",
                        "fatal": True,
                    }
                )
            await sender.close(1011, "SSH connection failed")
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
        self, peer: SshWebSocketPeer, sender: _SerializedSender
    ) -> None:
        request = await self._receive(
            peer,
            CONNECT_ADAPTER,
            timeout=self.settings.ssh_handshake_timeout_seconds,
            expected="connect",
        )
        assert isinstance(request, SshConnectMessage)

        await sender.send({"type": "status", "status": "checking_host_key"})
        try:
            host_key = await self.transport.fetch_host_key(
                request.host,
                request.port,
                self.settings.ssh_connect_timeout_seconds,
            )
        except asyncio.TimeoutError:
            raise
        except Exception as exc:
            raise _ProtocolViolation(
                "ssh_host_key_unavailable",
                "The SSH server's host key could not be retrieved.",
            ) from exc

        if request.known_host_key != host_key.public_key:
            host_key_status = (
                "unknown" if request.known_host_key is None else "changed"
            )
            await sender.send(
                {
                    "type": "host_key",
                    "status": host_key_status,
                    "algorithm": host_key.algorithm,
                    "fingerprint": host_key.fingerprint,
                    "public_key": host_key.public_key,
                }
            )
            trust_message = await self._receive(
                peer,
                TRUST_PHASE_ADAPTER,
                timeout=self.settings.ssh_handshake_timeout_seconds,
                expected="trust_host_key or disconnect",
            )
            if isinstance(trust_message, SshDisconnectMessage):
                await sender.send({"type": "status", "status": "disconnected"})
                await sender.close(1000, "SSH connection cancelled")
                return
            assert isinstance(trust_message, SshTrustHostKeyMessage)
            if trust_message.fingerprint != host_key.fingerprint:
                raise _ProtocolViolation(
                    "ssh_host_key_confirmation_mismatch",
                    "The trusted fingerprint does not match the current SSH host key.",
                )

        await sender.send({"type": "status", "status": "connecting"})
        remote: SshRemoteSession | None = None
        try:
            remote = await self.transport.open_session(
                request,
                host_key,
                self.settings.ssh_connect_timeout_seconds,
            )
            # Do not retain a second reference to the connect model beyond the
            # authentication call. In particular, password auth remains memory-only.
            del request
            await sender.send({"type": "status", "status": "connected"})
            remote_exit = await self._bridge(peer, sender, remote)
            if remote_exit is not None:
                await sender.send(
                    {
                        "type": "exit",
                        "exit_status": remote_exit.exit_status,
                        "signal": remote_exit.signal,
                    }
                )
            await sender.send({"type": "status", "status": "disconnected"})
            await sender.close(1000, "SSH session ended")
        finally:
            if remote is not None:
                await self._close_remote(remote)

    async def _bridge(
        self,
        peer: SshWebSocketPeer,
        sender: _SerializedSender,
        remote: SshRemoteSession,
    ) -> SshExit | None:
        client_task = asyncio.create_task(
            self._consume_client(peer, remote), name="quickssh-client-input"
        )
        wait_task = asyncio.create_task(remote.wait(), name="quickssh-remote-wait")
        stdout_task = asyncio.create_task(
            self._forward_output(sender, remote.read_stdout, "stdout"),
            name="quickssh-stdout",
        )
        stderr_task = asyncio.create_task(
            self._forward_output(sender, remote.read_stderr, "stderr"),
            name="quickssh-stderr",
        )
        output_tasks = {stdout_task, stderr_task}
        try:
            while True:
                watched = {client_task, wait_task, *output_tasks}
                done, _pending = await asyncio.wait(
                    watched, return_when=asyncio.FIRST_COMPLETED
                )
                for output_task in done & output_tasks:
                    output_tasks.remove(output_task)
                    output_task.result()

                if wait_task in done:
                    remote_exit = wait_task.result()
                    client_task.cancel()
                    await _wait_tasks_bounded(
                        {client_task},
                        _TASK_CLEANUP_TIMEOUT_SECONDS,
                        cancel_pending=True,
                    )
                    await self._drain_output_tasks(output_tasks)
                    return remote_exit

                if client_task in done:
                    client_task.result()
                    await self._close_remote(remote)
                    wait_task.cancel()
                    await _wait_tasks_bounded(
                        {wait_task},
                        _TASK_CLEANUP_TIMEOUT_SECONDS,
                        cancel_pending=True,
                    )
                    await self._drain_output_tasks(output_tasks)
                    return None
        finally:
            tasks = {client_task, wait_task, stdout_task, stderr_task}
            for task in tasks:
                if not task.done():
                    task.cancel()
            await _wait_tasks_bounded(
                tasks, _TASK_CLEANUP_TIMEOUT_SECONDS, cancel_pending=True
            )

    async def _close_remote(self, remote: SshRemoteSession) -> None:
        close_task = asyncio.create_task(remote.close(), name="quickssh-remote-close")
        await _wait_tasks_bounded(
            {close_task}, _REMOTE_CLOSE_TIMEOUT_SECONDS, cancel_pending=True
        )

    async def _drain_output_tasks(
        self, output_tasks: set[asyncio.Task[None]]
    ) -> None:
        if not output_tasks:
            return
        await _wait_tasks_bounded(
            output_tasks, _OUTPUT_DRAIN_TIMEOUT_SECONDS, cancel_pending=True
        )

    async def _consume_client(
        self, peer: SshWebSocketPeer, remote: SshRemoteSession
    ) -> None:
        while True:
            message = await self._receive(
                peer,
                CONNECTED_ADAPTER,
                timeout=None,
                expected="input, resize, or disconnect",
            )
            if isinstance(message, SshDisconnectMessage):
                return
            if isinstance(message, SshInputMessage):
                await remote.write(message.decode())
            elif isinstance(message, SshResizeMessage):
                await remote.resize(
                    message.cols,
                    message.rows,
                    message.pixel_width,
                    message.pixel_height,
                )

    async def _forward_output(
        self,
        sender: _SerializedSender,
        reader: Callable[[int], Awaitable[bytes]],
        stream: str,
    ) -> None:
        while True:
            data = await reader(_OUTPUT_CHUNK_BYTES)
            if not data:
                return
            if not isinstance(data, bytes):
                raise TypeError("SSH output must be bytes")
            for offset in range(0, len(data), _OUTPUT_CHUNK_BYTES):
                encoded = base64.b64encode(
                    data[offset : offset + _OUTPUT_CHUNK_BYTES]
                ).decode("ascii")
                await sender.send(
                    {
                        "type": "output",
                        "stream": stream,
                        "data": encoded,
                    }
                )

    async def _receive(
        self,
        peer: SshWebSocketPeer,
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
        if len(raw) > SSH_MESSAGE_LIMIT_CHARS:
            raise _ProtocolViolation(
                "ssh_message_too_large", "The QuickSSH message is too large."
            )
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise _ProtocolViolation(
                "ssh_invalid_message", "QuickSSH messages must be valid JSON objects."
            ) from exc
        if not isinstance(payload, dict):
            raise _ProtocolViolation(
                "ssh_invalid_message", "QuickSSH messages must be JSON objects."
            )
        try:
            return adapter.validate_python(payload)
        except ValidationError as exc:
            # Do not include validation details: Pydantic errors can echo the
            # rejected input, including a password from the connect message.
            raise _ProtocolViolation(
                "ssh_invalid_message", f"Expected a valid {expected} message."
            ) from exc
