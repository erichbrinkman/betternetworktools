from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Iterable
from typing import Any

import pytest

from better_network_tools.config import Settings, load_settings
from better_network_tools.ssh_models import SshConnectMessage, SshPasswordAuth
from better_network_tools.ssh_service import (
    AsyncSshTransport,
    SshExit,
    SshHostKey,
    SshSessionService,
    quickssh_bind_is_loopback,
    quickssh_scope_is_loopback,
    websocket_origin_allowed,
)


CURRENT_PUBLIC_KEY = "ssh-ed25519 Y3VycmVudC1ob3N0LWtleQ=="
OLD_PUBLIC_KEY = "ssh-ed25519 b2xkLWhvc3Qta2V5"
CURRENT_FINGERPRINT = "SHA256:abcdefghijklmnopqrstuvwx"


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

    def send(self, message: dict[str, object]) -> None:
        self.incoming.put_nowait(json.dumps(message))


class FakeRemoteSession:
    def __init__(
        self,
        *,
        stdout: Iterable[bytes] = (b"",),
        stderr: Iterable[bytes] = (b"",),
    ) -> None:
        self.stdout: asyncio.Queue[bytes] = asyncio.Queue()
        self.stderr: asyncio.Queue[bytes] = asyncio.Queue()
        for chunk in stdout:
            self.stdout.put_nowait(chunk)
        for chunk in stderr:
            self.stderr.put_nowait(chunk)
        self.writes: list[bytes] = []
        self.resizes: list[tuple[int, int, int, int]] = []
        self.exit_ready = asyncio.Event()
        self.exit = SshExit(exit_status=0)
        self.close_calls = 0

    async def read_stdout(self, _max_bytes: int) -> bytes:
        return await self.stdout.get()

    async def read_stderr(self, _max_bytes: int) -> bytes:
        return await self.stderr.get()

    async def write(self, data: bytes) -> None:
        self.writes.append(data)
        await asyncio.sleep(0)

    async def resize(
        self, cols: int, rows: int, pixel_width: int, pixel_height: int
    ) -> None:
        self.resizes.append((cols, rows, pixel_width, pixel_height))
        await asyncio.sleep(0)

    async def wait(self) -> SshExit:
        await self.exit_ready.wait()
        return self.exit

    async def close(self) -> None:
        self.close_calls += 1
        self.exit_ready.set()


class FakeTransport:
    def __init__(
        self, remote: FakeRemoteSession | None = None, host_key: SshHostKey | None = None
    ) -> None:
        self.remote = remote or FakeRemoteSession()
        self.host_key = host_key or SshHostKey(
            algorithm="ssh-ed25519",
            fingerprint=CURRENT_FINGERPRINT,
            public_key=CURRENT_PUBLIC_KEY,
            verifier=object(),
        )
        self.fetch_calls: list[tuple[str, int, float]] = []
        self.open_calls: list[tuple[str, int, str, str, SshHostKey, float]] = []
        self.opened = asyncio.Event()

    async def fetch_host_key(
        self, host: str, port: int, timeout: float
    ) -> SshHostKey:
        self.fetch_calls.append((host, port, timeout))
        return self.host_key

    async def open_session(
        self, request: SshConnectMessage, host_key: SshHostKey, timeout: float
    ) -> FakeRemoteSession:
        # Record only non-secret fields. Production and test transports never
        # need to persist a password after authentication starts.
        self.open_calls.append(
            (
                request.host,
                request.port,
                request.username,
                request.auth.type,
                host_key,
                timeout,
            )
        )
        self.opened.set()
        return self.remote


def connect_message(
    *, known_host_key: str | None = None, password: str | None = None
) -> dict[str, object]:
    auth: dict[str, object]
    if password is None:
        auth = {"type": "agent"}
    else:
        auth = {"type": "password", "password": password}
    return {
        "type": "connect",
        "host": "router.example",
        "port": 22,
        "username": "admin",
        "auth": auth,
        "known_host_key": known_host_key,
        "cols": 80,
        "rows": 24,
    }


@pytest.mark.asyncio
async def test_unknown_host_requires_trust_then_bridges_binary_io_and_resize() -> None:
    remote = FakeRemoteSession(stdout=(b"\xffhello", b""), stderr=(b"warn", b""))
    transport = FakeTransport(remote)
    service = SshSessionService(Settings(), transport=transport)
    terminal_input = b"\x00\xff\r"
    peer = FakePeer(
        [
            connect_message(),
            {"type": "trust_host_key", "fingerprint": CURRENT_FINGERPRINT},
            {
                "type": "input",
                "data": base64.b64encode(terminal_input).decode("ascii"),
            },
            {
                "type": "resize",
                "cols": 132,
                "rows": 44,
                "pixel_width": 1400,
                "pixel_height": 900,
            },
            {"type": "disconnect"},
        ]
    )

    await service.handle(peer)

    host_key_events = [event for event in peer.sent if event["type"] == "host_key"]
    assert host_key_events == [
        {
            "type": "host_key",
            "status": "unknown",
            "algorithm": "ssh-ed25519",
            "fingerprint": CURRENT_FINGERPRINT,
            "public_key": CURRENT_PUBLIC_KEY,
        }
    ]
    assert remote.writes == [terminal_input]
    assert remote.resizes == [(132, 44, 1400, 900)]
    assert remote.close_calls >= 1
    assert transport.open_calls[0][4] is transport.host_key
    assert transport.open_calls[0][3] == "agent"
    output = [event for event in peer.sent if event["type"] == "output"]
    assert {
        (event["stream"], base64.b64decode(str(event["data"]))) for event in output
    } == {("stdout", b"\xffhello"), ("stderr", b"warn")}
    assert [
        event["status"] for event in peer.sent if event["type"] == "status"
    ] == ["checking_host_key", "connecting", "connected", "disconnected"]
    assert peer.close_calls[-1][0] == 1000
    assert service.active_session_count == 0


@pytest.mark.asyncio
async def test_changed_host_key_is_reported_and_mismatched_trust_never_connects() -> None:
    transport = FakeTransport()
    service = SshSessionService(Settings(), transport=transport)
    peer = FakePeer(
        [
            connect_message(known_host_key=OLD_PUBLIC_KEY),
            {
                "type": "trust_host_key",
                "fingerprint": "SHA256:zyxwvutsrqponmlkjihgfedc",
            },
        ]
    )

    await service.handle(peer)

    host_key_event = next(event for event in peer.sent if event["type"] == "host_key")
    assert host_key_event["status"] == "changed"
    assert transport.open_calls == []
    error = next(event for event in peer.sent if event["type"] == "error")
    assert error["code"] == "ssh_host_key_confirmation_mismatch"
    assert peer.close_calls[-1][0] == 1008


@pytest.mark.asyncio
async def test_matching_stored_key_skips_prompt_and_remote_exit_is_reported() -> None:
    remote = FakeRemoteSession(stdout=(b"goodbye", b""))
    remote.exit = SshExit(exit_status=7, signal=None)
    remote.exit_ready.set()
    transport = FakeTransport(remote)
    service = SshSessionService(Settings(), transport=transport)
    peer = FakePeer([connect_message(known_host_key=CURRENT_PUBLIC_KEY)])

    await service.handle(peer)

    assert not any(event["type"] == "host_key" for event in peer.sent)
    assert {
        "type": "exit",
        "exit_status": 7,
        "signal": None,
    } in peer.sent
    assert any(
        event["type"] == "output"
        and base64.b64decode(str(event["data"])) == b"goodbye"
        for event in peer.sent
    )


@pytest.mark.asyncio
async def test_remote_exit_cancels_output_readers_which_never_reach_eof(
    monkeypatch,
) -> None:
    import better_network_tools.ssh_service as ssh_service_module

    class HangingOutputRemote(FakeRemoteSession):
        def __init__(self) -> None:
            super().__init__()
            self.never = asyncio.Event()
            self.cancelled_readers = 0
            self.exit_ready.set()

        async def _read_forever(self) -> bytes:
            try:
                await self.never.wait()
            except asyncio.CancelledError:
                self.cancelled_readers += 1
                raise
            raise AssertionError("hanging reader must be cancelled")

        async def read_stdout(self, _max_bytes: int) -> bytes:
            return await self._read_forever()

        async def read_stderr(self, _max_bytes: int) -> bytes:
            return await self._read_forever()

    monkeypatch.setattr(ssh_service_module, "_OUTPUT_DRAIN_TIMEOUT_SECONDS", 0.01)
    remote = HangingOutputRemote()
    service = SshSessionService(Settings(), transport=FakeTransport(remote))
    peer = FakePeer([connect_message(known_host_key=CURRENT_PUBLIC_KEY)])

    await asyncio.wait_for(service.handle(peer), timeout=0.2)

    assert remote.cancelled_readers == 2
    assert any(event["type"] == "exit" for event in peer.sent)
    assert service.active_session_count == 0


@pytest.mark.asyncio
async def test_invalid_connect_does_not_echo_or_logically_retain_password() -> None:
    secret = "top-secret-do-not-echo"
    transport = FakeTransport()
    service = SshSessionService(Settings(), transport=transport)
    invalid = connect_message(password=secret)
    invalid["unexpected"] = "field"
    peer = FakePeer([invalid])

    await service.handle(peer)

    serialized_events = json.dumps(peer.sent)
    assert secret not in serialized_events
    assert transport.fetch_calls == []
    assert transport.open_calls == []
    assert next(event for event in peer.sent if event["type"] == "error")[
        "code"
    ] == "ssh_invalid_message"


@pytest.mark.asyncio
async def test_authentication_exception_details_never_echo_a_password() -> None:
    secret = "server-must-not-return-this"

    class FailingTransport(FakeTransport):
        async def open_session(
            self,
            request: SshConnectMessage,
            host_key: SshHostKey,
            timeout: float,
        ) -> FakeRemoteSession:
            assert isinstance(request.auth, SshPasswordAuth)
            raise RuntimeError(
                f"authentication rejected for password "
                f"{request.auth.password.get_secret_value()}"
            )

    service = SshSessionService(Settings(), transport=FailingTransport())
    peer = FakePeer(
        [
            connect_message(known_host_key=CURRENT_PUBLIC_KEY, password=secret),
        ]
    )

    await service.handle(peer)

    assert secret not in json.dumps(peer.sent)
    assert next(event for event in peer.sent if event["type"] == "error") == {
        "type": "error",
        "code": "ssh_connection_failed",
        "message": "The SSH connection could not be established.",
        "fatal": True,
    }


@pytest.mark.asyncio
async def test_active_session_limit_and_shutdown_cleanup_are_enforced() -> None:
    remote = FakeRemoteSession()
    transport = FakeTransport(remote)
    service = SshSessionService(
        Settings(ssh_active_session_limit=1), transport=transport
    )
    first_peer = FakePeer([connect_message(known_host_key=CURRENT_PUBLIC_KEY)])
    first_task = asyncio.create_task(service.handle(first_peer))
    await asyncio.wait_for(transport.opened.wait(), timeout=0.5)
    assert service.active_session_count == 1

    rejected_peer = FakePeer()
    await service.handle(rejected_peer)
    assert rejected_peer.sent == [
        {
            "type": "error",
            "code": "ssh_session_capacity_exceeded",
            "message": "The active QuickSSH session limit has been reached.",
            "fatal": True,
        }
    ]
    assert rejected_peer.close_calls[-1][0] == 1013

    await service.shutdown()
    await asyncio.gather(first_task, return_exceptions=True)
    assert remote.close_calls >= 1
    assert first_peer.close_calls[-1][0] == 1012
    assert service.active_session_count == 0


@pytest.mark.asyncio
async def test_shutdown_is_bounded_when_injected_remote_close_hangs(
    monkeypatch,
) -> None:
    import better_network_tools.ssh_service as ssh_service_module

    class HangingCloseRemote(FakeRemoteSession):
        def __init__(self) -> None:
            super().__init__()
            self.never = asyncio.Event()
            self.cancelled_closes = 0

        async def close(self) -> None:
            self.close_calls += 1
            try:
                await self.never.wait()
            except asyncio.CancelledError:
                self.cancelled_closes += 1
                raise

    monkeypatch.setattr(ssh_service_module, "_REMOTE_CLOSE_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(ssh_service_module, "_TASK_CLEANUP_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(ssh_service_module, "_SHUTDOWN_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(
        ssh_service_module, "_WEBSOCKET_CLOSE_TIMEOUT_SECONDS", 0.01
    )
    remote = HangingCloseRemote()
    transport = FakeTransport(remote)
    service = SshSessionService(Settings(), transport=transport)
    peer = FakePeer([connect_message(known_host_key=CURRENT_PUBLIC_KEY)])
    handle_task = asyncio.create_task(service.handle(peer))
    await asyncio.wait_for(transport.opened.wait(), timeout=0.2)

    await asyncio.wait_for(service.shutdown(), timeout=0.2)
    await asyncio.sleep(0)

    assert handle_task.done()
    assert remote.cancelled_closes >= 1
    assert service.active_session_count == 0


def test_websocket_origin_requires_an_exact_configured_http_origin() -> None:
    allowed = ("http://127.0.0.1:3000", "https://localhost:4173")
    assert websocket_origin_allowed("http://127.0.0.1:3000", allowed)
    assert websocket_origin_allowed("https://LOCALHOST:4173/", allowed)
    assert not websocket_origin_allowed(None, allowed)
    assert not websocket_origin_allowed("null", allowed)
    assert not websocket_origin_allowed("http://127.0.0.1:3001", allowed)
    assert not websocket_origin_allowed("https://attacker.example", allowed)
    assert not websocket_origin_allowed(
        "http://127.0.0.1:3000/path", allowed
    )


def test_quickssh_requires_the_python_service_to_be_loopback_bound() -> None:
    assert quickssh_bind_is_loopback("127.0.0.1")
    assert quickssh_bind_is_loopback("127.12.34.56")
    assert quickssh_bind_is_loopback("::1")
    assert quickssh_bind_is_loopback("[::1]")
    assert quickssh_bind_is_loopback("localhost")
    assert not quickssh_bind_is_loopback("0.0.0.0")
    assert not quickssh_bind_is_loopback("::")
    assert not quickssh_bind_is_loopback("192.168.1.10")
    assert not quickssh_bind_is_loopback("service.internal")

    assert quickssh_scope_is_loopback(
        {"server": ("127.0.0.1", 8766), "client": ("::1", 54321)}
    )
    assert not quickssh_scope_is_loopback(
        {"server": ("192.0.2.10", 8766), "client": ("127.0.0.1", 54321)}
    )
    assert not quickssh_scope_is_loopback(
        {"server": ("127.0.0.1", 8766), "client": ("192.0.2.20", 54321)}
    )
    assert not quickssh_scope_is_loopback(
        {"server": ("127.0.0.1", 8766), "client": None}
    )


def test_ssh_resource_limits_are_loaded_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("BNT_SSH_ACTIVE_SESSION_LIMIT", "6")
    monkeypatch.setenv("BNT_SSH_CONNECT_TIMEOUT_SECONDS", "12.5")
    monkeypatch.setenv("BNT_SSH_HANDSHAKE_TIMEOUT_SECONDS", "90")

    settings = load_settings()
    assert settings.ssh_active_session_limit == 6
    assert settings.ssh_connect_timeout_seconds == 12.5
    assert settings.ssh_handshake_timeout_seconds == 90.0


class FakeAsyncSshKey:
    def export_public_key(self, _format: str) -> bytes:
        return f"{CURRENT_PUBLIC_KEY} ignored-comment\n".encode("ascii")

    def get_algorithm(self) -> str:
        return "ssh-ed25519"

    def get_fingerprint(self, _hash: str) -> str:
        return CURRENT_FINGERPRINT


class FakeAsyncReader:
    async def read(self, _max_bytes: int) -> bytes:
        return b""


class FakeAsyncWriter:
    def write(self, _data: bytes) -> None:
        pass

    async def drain(self) -> None:
        pass


class FakeAsyncProcess:
    def __init__(self) -> None:
        self.stdout = FakeAsyncReader()
        self.stderr = FakeAsyncReader()
        self.stdin = FakeAsyncWriter()
        self.exit_signal = None
        self.exit_status = 0

    def change_terminal_size(self, *_size: int) -> None:
        pass

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class FakeAsyncConnection:
    def __init__(self) -> None:
        self.process_options: dict[str, object] | None = None

    async def create_process(self, **options: object) -> FakeAsyncProcess:
        self.process_options = options
        return FakeAsyncProcess()

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class FakeAsyncSshLibrary:
    def __init__(self) -> None:
        self.key = FakeAsyncSshKey()
        self.host_key_call: tuple[str, int, dict[str, object]] | None = None
        self.connect_calls: list[tuple[str, dict[str, object]]] = []

    async def get_server_host_key(
        self, host: str, port: int, *, config: None
    ) -> FakeAsyncSshKey:
        self.host_key_call = (host, port, {"config": config})
        return self.key

    async def connect(self, host: str, **options: object) -> FakeAsyncConnection:
        self.connect_calls.append((host, options))
        return FakeAsyncConnection()


@pytest.mark.asyncio
async def test_asyncssh_transport_pins_exact_key_and_separates_auth_modes() -> None:
    library = FakeAsyncSshLibrary()
    transport = AsyncSshTransport(library)
    key = await transport.fetch_host_key("router.example", 22, 1.0)
    assert key.public_key == CURRENT_PUBLIC_KEY
    assert key.verifier is library.key
    assert library.host_key_call == (
        "router.example",
        22,
        {"config": None},
    )

    password_request = SshConnectMessage.model_validate(
        connect_message(known_host_key=CURRENT_PUBLIC_KEY, password="memory-only")
    )
    password_session = await transport.open_session(password_request, key, 1.0)
    _host, password_options = library.connect_calls[-1]
    assert password_options["known_hosts"] == ([library.key], [], [])
    assert password_options["known_hosts"] is not None
    assert password_options["config"] is None
    assert password_options["password"] == "memory-only"
    assert password_options["client_keys"] is None
    assert password_options["agent_path"] is None
    assert password_options["preferred_auth"] == ["password"]
    await password_session.close()

    agent_request = SshConnectMessage.model_validate(
        connect_message(known_host_key=CURRENT_PUBLIC_KEY)
    )
    agent_session = await transport.open_session(agent_request, key, 1.0)
    _host, agent_options = library.connect_calls[-1]
    assert agent_options["known_hosts"] == ([library.key], [], [])
    assert agent_options["preferred_auth"] == ["publickey"]
    assert "client_keys" not in agent_options
    assert "agent_path" not in agent_options
    assert agent_options["agent_forwarding"] is False
    await agent_session.close()


class HangingAsyncProcess(FakeAsyncProcess):
    def __init__(self) -> None:
        super().__init__()
        self.never = asyncio.Event()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1

    async def wait_closed(self) -> None:
        await self.never.wait()


class HangingAsyncConnection(FakeAsyncConnection):
    def __init__(
        self,
        *,
        process: HangingAsyncProcess | None = None,
        create_error: Exception | None = None,
    ) -> None:
        super().__init__()
        self.process = process or HangingAsyncProcess()
        self.create_error = create_error
        self.never = asyncio.Event()
        self.close_calls = 0
        self.abort_calls = 0

    async def create_process(self, **options: object) -> FakeAsyncProcess:
        self.process_options = options
        if self.create_error is not None:
            raise self.create_error
        return self.process

    def close(self) -> None:
        self.close_calls += 1

    def abort(self) -> None:
        self.abort_calls += 1

    async def wait_closed(self) -> None:
        await self.never.wait()


class FixedConnectionAsyncSshLibrary(FakeAsyncSshLibrary):
    def __init__(self, connection: HangingAsyncConnection) -> None:
        super().__init__()
        self.connection = connection

    async def connect(self, host: str, **options: object) -> FakeAsyncConnection:
        self.connect_calls.append((host, options))
        return self.connection


@pytest.mark.asyncio
async def test_asyncssh_remote_close_aborts_after_bounded_wait_closed_timeout(
    monkeypatch,
) -> None:
    import better_network_tools.ssh_service as ssh_service_module

    monkeypatch.setattr(
        ssh_service_module, "_ASYNCSSH_CLOSE_TIMEOUT_SECONDS", 0.01
    )
    monkeypatch.setattr(
        ssh_service_module, "_ASYNCSSH_ABORT_TIMEOUT_SECONDS", 0.01
    )
    connection = HangingAsyncConnection()
    transport = AsyncSshTransport(FixedConnectionAsyncSshLibrary(connection))
    request = SshConnectMessage.model_validate(
        connect_message(known_host_key=CURRENT_PUBLIC_KEY)
    )
    key = SshHostKey(
        algorithm="ssh-ed25519",
        fingerprint=CURRENT_FINGERPRINT,
        public_key=CURRENT_PUBLIC_KEY,
        verifier=FakeAsyncSshKey(),
    )
    remote = await transport.open_session(request, key, 1.0)

    await asyncio.wait_for(remote.close(), timeout=0.1)

    assert connection.close_calls == 1
    assert connection.process.close_calls == 1
    assert connection.abort_calls == 1


@pytest.mark.asyncio
async def test_failed_open_session_aborts_hanging_connection_cleanup(
    monkeypatch,
) -> None:
    import better_network_tools.ssh_service as ssh_service_module

    monkeypatch.setattr(
        ssh_service_module, "_ASYNCSSH_CLOSE_TIMEOUT_SECONDS", 0.01
    )
    monkeypatch.setattr(
        ssh_service_module, "_ASYNCSSH_ABORT_TIMEOUT_SECONDS", 0.01
    )
    connection = HangingAsyncConnection(create_error=RuntimeError("pty rejected"))
    transport = AsyncSshTransport(FixedConnectionAsyncSshLibrary(connection))
    request = SshConnectMessage.model_validate(
        connect_message(known_host_key=CURRENT_PUBLIC_KEY)
    )
    key = SshHostKey(
        algorithm="ssh-ed25519",
        fingerprint=CURRENT_FINGERPRINT,
        public_key=CURRENT_PUBLIC_KEY,
        verifier=FakeAsyncSshKey(),
    )

    with pytest.raises(RuntimeError, match="pty rejected"):
        await asyncio.wait_for(
            transport.open_session(request, key, 1.0), timeout=0.1
        )

    assert connection.close_calls == 1
    assert connection.abort_calls == 1
