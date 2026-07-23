from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from better_network_tools.config import Settings
from better_network_tools.main import create_app


class RecordingTelnetHandler:
    def __init__(self) -> None:
        self.handle_calls = 0
        self.shutdown_calls = 0

    async def handle(self, websocket) -> None:
        self.handle_calls += 1
        await websocket.send_json({"type": "status", "status": "disconnected"})
        await websocket.close(code=1000)

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


def test_default_ssh_and_telnet_services_share_one_aggregate_ceiling() -> None:
    app = create_app(
        Settings(ssh_active_session_limit=3, telnet_active_session_limit=4)
    )
    ssh_service = app.state.ssh_session_service
    telnet_service = app.state.telnet_session_service

    assert ssh_service._session_limiter is telnet_service._session_limiter
    assert app.state.terminal_session_limiter.limit == 4


def test_telnet_websocket_checks_exact_origin_and_uses_injected_service() -> None:
    handler = RecordingTelnetHandler()
    app = create_app(
        Settings(cors_origins=("http://127.0.0.1:3000",)),
        telnet_session_service=handler,
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        with client.websocket_connect(
            "ws://127.0.0.1:8766/api/telnet",
            headers={"origin": "http://127.0.0.1:3000"},
        ) as websocket:
            assert websocket.receive_json() == {
                "type": "status",
                "status": "disconnected",
            }

        for origin in (
            "https://attacker.example",
            "http://127.0.0.1:3000.attacker.example",
            "http://127.0.0.1:3000/path",
        ):
            with pytest.raises(WebSocketDisconnect) as rejected:
                with client.websocket_connect(
                    "ws://127.0.0.1:8766/api/telnet",
                    headers={"origin": origin},
                ):
                    pass
            assert rejected.value.code == 1008

    assert handler.handle_calls == 1
    assert handler.shutdown_calls == 1


@pytest.mark.parametrize(
    ("api_host", "websocket_url", "client_address"),
    [
        (
            "0.0.0.0",
            "ws://127.0.0.1:8766/api/telnet",
            ("127.0.0.1", 50000),
        ),
        (
            "127.0.0.1",
            "ws://192.0.2.10:8766/api/telnet",
            ("127.0.0.1", 50000),
        ),
        (
            "127.0.0.1",
            "ws://127.0.0.1:8766/api/telnet",
            ("192.0.2.20", 50000),
        ),
    ],
)
def test_telnet_websocket_requires_configured_and_live_loopback_endpoints(
    api_host: str,
    websocket_url: str,
    client_address: tuple[str, int],
) -> None:
    handler = RecordingTelnetHandler()
    app = create_app(
        Settings(
            host=api_host,
            cors_origins=("http://127.0.0.1:3000",),
        ),
        telnet_session_service=handler,
    )

    with TestClient(app, client=client_address) as client:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(
                websocket_url,
                headers={"origin": "http://127.0.0.1:3000"},
            ):
                pass
        assert rejected.value.code == 1008

    assert handler.handle_calls == 0
