from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.transfer_models import (
    TransferFileListResponse,
    TransferServerStartRequest,
    TransferServerStatusResponse,
)


NOW = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)


class FakeTransferService:
    def __init__(self) -> None:
        self.running = False
        self.protocol: str | None = None
        self.start_calls: list[TransferServerStartRequest] = []
        self.shutdown_calls = 0

    async def status(self) -> TransferServerStatusResponse:
        protocol = self.protocol if self.running else None
        return TransferServerStatusResponse(
            state="running" if self.running else "stopped",
            running=self.running,
            protocol=protocol,
            transport="udp" if protocol == "tftp" else "tcp" if protocol else None,
            bind_address="127.0.0.1",
            port=2222 if self.running else None,
            root_directory="/tmp/nettransfer-test",
            allow_read=True,
            allow_write=False,
            allow_overwrite=False,
            allowed_client_cidrs=["127.0.0.0/8"],
            authentication="password" if protocol in {"sftp", "ftp"} else "none",
            username="nettransfer" if protocol in {"sftp", "ftp"} else None,
            sftp_host_key_fingerprint=(
                "SHA256:example" if protocol == "sftp" else None
            ),
            ftp_passive_port_start=50000 if protocol == "ftp" else None,
            ftp_passive_port_end=50019 if protocol == "ftp" else None,
            default_ports={"tftp": 6969, "sftp": 2222, "ftp": 2121},
            started_at=NOW if self.running else None,
            active_transfer_count=0,
            completed_transfer_count=0,
            failed_transfer_count=0,
            bytes_sent=0,
            bytes_received=0,
            recent_transfers=[],
        )

    async def start(
        self, request: TransferServerStartRequest
    ) -> TransferServerStatusResponse:
        self.start_calls.append(request)
        self.running = True
        self.protocol = request.protocol
        return await self.status()

    async def stop(self) -> TransferServerStatusResponse:
        self.running = False
        return await self.status()

    async def list_files(self) -> TransferFileListResponse:
        return TransferFileListResponse(
            root_directory="/tmp/nettransfer-test", files=[], truncated=False
        )

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.running = False


def test_transfer_api_supports_all_protocol_fields_without_returning_secrets() -> None:
    service = FakeTransferService()
    app = create_app(
        Settings(), transfer_server_service=service  # type: ignore[arg-type]
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        initial = client.get("/api/transfer-server")
        assert initial.status_code == 200
        assert initial.json()["default_ports"] == {
            "tftp": 6969,
            "sftp": 2222,
            "ftp": 2121,
        }

        secret = "a-long-local-password"
        started = client.post(
            "/api/transfer-server",
            json={
                "protocol": "sftp",
                "username": "nettransfer",
                "password": secret,
                "port": 2222,
            },
        )
        assert started.status_code == 201
        payload = started.json()
        assert payload["protocol"] == "sftp"
        assert payload["authentication"] == "password"
        assert payload["username"] == "nettransfer"
        assert "password" not in payload
        assert secret not in started.text
        assert service.start_calls[0].password is not None
        assert service.start_calls[0].password.get_secret_value() == secret

        listing = client.get("/api/transfer-server/files")
        assert listing.status_code == 200
        assert listing.json()["root_directory"] == "/tmp/nettransfer-test"

        stopped = client.delete("/api/transfer-server")
        assert stopped.status_code == 200
        assert stopped.json()["running"] is False

        system = client.get("/api/system").json()
        capabilities = system["capabilities"]
        assert capabilities["transfer_server"] is True
        assert capabilities["tftp_server"] is True
        assert capabilities["sftp_server"] is True
        assert capabilities["ftp_server"] is True

        openapi = client.get("/openapi.json").json()
        assert set(openapi["paths"]["/api/transfer-server"]) == {
            "get",
            "post",
            "delete",
        }
        request_schema = openapi["components"]["schemas"][
            "TransferServerStartRequest"
        ]
        assert request_schema["additionalProperties"] is False
        assert request_schema["properties"]["password"]["anyOf"][0][
            "writeOnly"
        ] is True
        response_schema = openapi["components"]["schemas"][
            "TransferServerStatusResponse"
        ]
        assert "password" not in response_schema["properties"]

    assert service.shutdown_calls == 1


def test_transfer_api_rejects_missing_credentials_and_tftp_credentials() -> None:
    service = FakeTransferService()
    app = create_app(
        Settings(), transfer_server_service=service  # type: ignore[arg-type]
    )

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        for payload in (
            {"protocol": "sftp"},
            {"protocol": "ftp", "username": "nettransfer"},
            {
                "protocol": "tftp",
                "username": "nettransfer",
                "password": "a-long-local-password",
            },
            {"protocol": "tftp", "allow_read": False, "allow_write": False},
        ):
            response = client.post("/api/transfer-server", json=payload)
            assert response.status_code == 422

    assert service.start_calls == []
