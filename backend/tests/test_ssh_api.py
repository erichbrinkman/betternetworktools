from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from better_network_tools.config import Settings
from better_network_tools.main import create_app


class RecordingSshHandler:
    def __init__(self) -> None:
        self.handle_calls = 0
        self.shutdown_calls = 0

    async def handle(self, websocket) -> None:
        self.handle_calls += 1
        await websocket.send_json({"type": "status", "status": "disconnected"})
        await websocket.close(code=1000)

    async def shutdown(self) -> None:
        self.shutdown_calls += 1


def test_quickssh_websocket_checks_origin_and_uses_injected_python_service() -> None:
    ssh_handler = RecordingSshHandler()
    app = create_app(
        Settings(cors_origins=("http://127.0.0.1:3000",)),
        ssh_session_service=ssh_handler,
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        with client.websocket_connect(
            "ws://127.0.0.1:8766/api/ssh",
            headers={"origin": "http://127.0.0.1:3000"},
        ) as websocket:
            assert websocket.receive_json() == {
                "type": "status",
                "status": "disconnected",
            }

        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(
                "ws://127.0.0.1:8766/api/ssh",
                headers={"origin": "https://attacker.example"},
            ):
                pass
        assert rejected.value.code == 1008

    assert ssh_handler.handle_calls == 1
    assert ssh_handler.shutdown_calls == 1


def test_quickssh_websocket_is_disabled_when_python_api_is_not_loopback_bound() -> None:
    ssh_handler = RecordingSshHandler()
    app = create_app(
        Settings(
            host="0.0.0.0",
            cors_origins=("http://127.0.0.1:3000",),
        ),
        ssh_session_service=ssh_handler,
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(
                "ws://127.0.0.1:8766/api/ssh",
                headers={"origin": "http://127.0.0.1:3000"},
            ):
                pass
        assert rejected.value.code == 1008

    assert ssh_handler.handle_calls == 0


@pytest.mark.parametrize(
    ("websocket_url", "client_address"),
    [
        ("ws://192.0.2.10:8766/api/ssh", ("127.0.0.1", 50000)),
        ("ws://127.0.0.1:8766/api/ssh", ("192.0.2.20", 50000)),
    ],
)
def test_quickssh_websocket_rejects_non_loopback_live_socket_scope(
    websocket_url: str, client_address: tuple[str, int]
) -> None:
    ssh_handler = RecordingSshHandler()
    app = create_app(
        Settings(cors_origins=("http://127.0.0.1:3000",)),
        ssh_session_service=ssh_handler,
    )

    with TestClient(app, client=client_address) as client:
        with pytest.raises(WebSocketDisconnect) as rejected:
            with client.websocket_connect(
                websocket_url,
                headers={"origin": "http://127.0.0.1:3000"},
            ):
                pass
        assert rejected.value.code == 1008

    assert ssh_handler.handle_calls == 0
