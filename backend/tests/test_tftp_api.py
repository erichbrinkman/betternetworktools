from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.tftp_models import (
    TftpFileListResponse,
    TftpFileResponse,
    TftpServerStartRequest,
    TftpServerStatusResponse,
)
from better_network_tools.tftp_service import (
    TftpConfigurationError,
    TftpServerAlreadyRunningError,
    TftpServerBindError,
)


NOW = datetime(2026, 7, 10, 20, 30, tzinfo=UTC)


class FakeTftpService:
    def __init__(self) -> None:
        self.running = False
        self.start_calls: list[TftpServerStartRequest] = []
        self.stop_calls = 0
        self.status_calls = 0
        self.list_files_calls = 0
        self.shutdown_calls = 0
        self.next_start_error: Exception | None = None
        self.bind_address = "127.0.0.1"
        self.port = 6969
        self.allow_read = True
        self.allow_write = False
        self.allow_overwrite = False
        self.allowed_client_cidrs = ["127.0.0.0/8"]

    def snapshot(self) -> TftpServerStatusResponse:
        return TftpServerStatusResponse(
            state="running" if self.running else "stopped",
            running=self.running,
            bind_address=self.bind_address,
            port=self.port,
            root_directory="/tmp/nettftp-test",
            allow_read=self.allow_read,
            allow_write=self.allow_write,
            allow_overwrite=self.allow_overwrite,
            allowed_client_cidrs=self.allowed_client_cidrs,
            started_at=NOW if self.running else None,
            active_transfer_count=0,
            completed_transfer_count=2,
            failed_transfer_count=1,
            bytes_sent=512,
            bytes_received=11,
            recent_transfers=[],
        )

    async def status(self) -> TftpServerStatusResponse:
        self.status_calls += 1
        return self.snapshot()

    async def start(
        self, request: TftpServerStartRequest
    ) -> TftpServerStatusResponse:
        if self.next_start_error is not None:
            error = self.next_start_error
            self.next_start_error = None
            raise error
        self.start_calls.append(request)
        self.running = True
        self.bind_address = request.bind_address
        self.port = request.port
        self.allow_read = request.allow_read
        self.allow_write = request.allow_write
        self.allow_overwrite = request.allow_overwrite
        self.allowed_client_cidrs = request.allowed_client_cidrs
        return self.snapshot()

    async def stop(self) -> TftpServerStatusResponse:
        self.stop_calls += 1
        self.running = False
        return self.snapshot()

    async def list_files(self) -> TftpFileListResponse:
        self.list_files_calls += 1
        return TftpFileListResponse(
            root_directory="/tmp/nettftp-test",
            files=[
                TftpFileResponse(
                    filename="firmware/router.bin", size=4096, modified_at=NOW
                )
            ],
            truncated=False,
        )

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.running = False


def test_tftp_api_get_post_delete_files_and_openapi_contract() -> None:
    service = FakeTftpService()
    app = create_app(Settings(), tftp_server_service=service)  # type: ignore[arg-type]

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        initial_response = client.get("/api/tftp-server")
        assert initial_response.status_code == 200
        initial = initial_response.json()
        assert set(initial) == {
            "state",
            "running",
            "bind_address",
            "port",
            "root_directory",
            "allow_read",
            "allow_write",
            "allow_overwrite",
            "allowed_client_cidrs",
            "started_at",
            "active_transfer_count",
            "completed_transfer_count",
            "failed_transfer_count",
            "bytes_sent",
            "bytes_received",
            "recent_transfers",
        }
        assert initial["state"] == "stopped"
        assert initial["running"] is False

        started_response = client.post(
            "/api/tftp-server",
            json={
                "bind_address": "127.0.0.1",
                "port": 1069,
                "allow_read": True,
                "allow_write": True,
                "allow_overwrite": True,
                "allowed_client_cidrs": [
                    " 127.0.0.1/32 ",
                    "127.0.0.1/32",
                ],
            },
        )
        assert started_response.status_code == 201
        started = started_response.json()
        assert started["state"] == "running"
        assert started["running"] is True
        assert started["port"] == 1069
        assert started["allow_write"] is True
        assert started["allow_overwrite"] is True
        assert started["allowed_client_cidrs"] == ["127.0.0.1/32"]
        assert started["started_at"] == "2026-07-10T20:30:00Z"
        assert len(service.start_calls) == 1
        assert service.start_calls[0].model_dump() == {
            "bind_address": "127.0.0.1",
            "port": 1069,
            "allow_read": True,
            "allow_write": True,
            "allow_overwrite": True,
            "allowed_client_cidrs": ["127.0.0.1/32"],
        }

        files_response = client.get("/api/tftp-server/files")
        assert files_response.status_code == 200
        assert files_response.json() == {
            "root_directory": "/tmp/nettftp-test",
            "files": [
                {
                    "filename": "firmware/router.bin",
                    "size": 4096,
                    "modified_at": "2026-07-10T20:30:00Z",
                }
            ],
            "truncated": False,
        }

        stopped_response = client.delete("/api/tftp-server")
        assert stopped_response.status_code == 200
        assert stopped_response.json()["state"] == "stopped"
        assert stopped_response.json()["running"] is False

        system = client.get("/api/system").json()
        assert system["capabilities"]["tftp_server"] is True

        openapi = client.get("/openapi.json").json()
        assert set(openapi["paths"]["/api/tftp-server"]) == {
            "get",
            "post",
            "delete",
        }
        assert set(openapi["paths"]["/api/tftp-server/files"]) == {"get"}
        request_schema = openapi["components"]["schemas"]["TftpServerStartRequest"]
        assert request_schema["additionalProperties"] is False
        assert request_schema["properties"]["bind_address"]["default"] == "127.0.0.1"
        assert request_schema["properties"]["port"] == {
            "default": 6969,
            "maximum": 65535.0,
            "minimum": 1.0,
            "title": "Port",
            "type": "integer",
        }
        assert request_schema["properties"]["allow_read"]["default"] is True
        assert request_schema["properties"]["allow_write"]["default"] is False
        assert "TftpServerStatusResponse" in openapi["components"]["schemas"]
        assert "TftpFileListResponse" in openapi["components"]["schemas"]

    assert service.status_calls == 1
    assert service.stop_calls == 1
    assert service.list_files_calls == 1
    assert service.shutdown_calls == 1


def test_tftp_api_strict_request_validation_never_calls_service() -> None:
    service = FakeTftpService()
    app = create_app(Settings(), tftp_server_service=service)  # type: ignore[arg-type]
    invalid_payloads = [
        {"port": "6969"},
        {"allow_write": 1},
        {"allowed_client_cidrs": [""]},
        {"unexpected": True},
    ]

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        for payload in invalid_payloads:
            response = client.post("/api/tftp-server", json=payload)
            assert response.status_code == 422
            assert response.json()["detail"]

    assert service.start_calls == []


def test_tftp_api_maps_configuration_and_listener_conflicts() -> None:
    service = FakeTftpService()
    app = create_app(Settings(), tftp_server_service=service)  # type: ignore[arg-type]

    cases = [
        (
            TftpConfigurationError("bad configuration"),
            422,
            "invalid_tftp_configuration",
        ),
        (
            TftpServerAlreadyRunningError("already running"),
            409,
            "tftp_server_already_running",
        ),
        (TftpServerBindError("address in use"), 409, "tftp_server_bind_failed"),
    ]

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        for error, status_code, code in cases:
            service.next_start_error = error
            response = client.post("/api/tftp-server", json={})
            assert response.status_code == status_code
            assert response.json() == {
                "detail": {"code": code, "message": str(error)}
            }

    assert service.start_calls == []
