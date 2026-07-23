from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import httpx
import pytest

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.models import DeviceResult, OpenPort
from better_network_tools.network import ProbeOptions
from better_network_tools.service import ScanService
from better_network_tools.update_models import (
    UpdateApplyRequest,
    UpdateApplyResponse,
    UpdateCheckResponse,
    UpdateCheckState,
    UpdateInstallKind,
    UpdateOperationResponse,
    UpdateOperationState,
)


class FakeInspector:
    async def inspect_host(
        self, ip_address: str, options: ProbeOptions
    ) -> DeviceResult | None:
        await asyncio.sleep(0)
        if not ip_address.endswith(".0"):
            return None
        return DeviceResult(
            ip_address=ip_address,
            hostname=None,
            mac_address=None,
            icmp_reachable=True,
            reachable=True,
            open_ports=[OpenPort(port=80, service="http", http_status=200)],
            discovery_methods=["icmp", "tcp"],
            confidence_score=80,
            confidence="high",
        )


class FakeUpdateService:
    def __init__(self) -> None:
        self.apply_calls = 0

    async def check(self) -> UpdateCheckResponse:
        return UpdateCheckResponse(
            state=UpdateCheckState.AVAILABLE,
            install_kind=UpdateInstallKind.GIT_CHECKOUT,
            current_version="0.1.0",
            current_commit="1" * 40,
            latest_version="0.2.0",
            candidate_commit="2" * 40,
            release_tag="v0.2.0",
            release_url=(
                "https://github.com/erichbrinkman/betternetworktools/"
                "releases/tag/v0.2.0"
            ),
            can_apply=True,
            message="Better Network Tools 0.2.0 is available.",
            checked_at=datetime.now(UTC),
        )

    async def apply(self, request: UpdateApplyRequest) -> UpdateApplyResponse:
        assert request.confirm is True
        self.apply_calls += 1
        return UpdateApplyResponse(
            previous_commit=request.expected_current_commit,
            applied_commit=request.expected_candidate_commit,
            applied_version="0.2.0",
            release_tag=request.expected_release_tag,
            release_url=(
                "https://github.com/erichbrinkman/betternetworktools/"
                "releases/tag/v0.2.0"
            ),
            bootstrap_required=False,
            message="Update applied. Restart Better Network Tools.",
        )

    def operation_status(self) -> UpdateOperationResponse:
        return UpdateOperationResponse(
            state=UpdateOperationState.IDLE,
            message="No update installation is running.",
        )

    async def shutdown(self) -> None:
        return None


def make_settings() -> Settings:
    return Settings(
        scan_host_limit=4,
        scan_concurrency=2,
        max_ports=3,
        default_ports=(80,),
        ping_timeout_seconds=0.1,
        tcp_timeout_seconds=0.1,
        banner_timeout_seconds=0.1,
    )


async def terminal_response(client: httpx.AsyncClient, scan_id: str) -> dict[str, object]:
    for _ in range(100):
        response = await client.get(f"/api/scans/{scan_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"completed", "cancelled", "failed"}:
            return payload
        await asyncio.sleep(0)
    raise AssertionError("scan did not reach a terminal state")


@pytest.mark.asyncio
async def test_health_system_and_scan_contract_use_no_real_network() -> None:
    configured = make_settings()
    service = ScanService(configured, inspector=FakeInspector())
    app = create_app(configured, scan_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        system = await client.get("/api/system")
        assert system.status_code == 200
        assert system.json()["limits"] == {
            "max_hosts": 4,
            "max_ports": 3,
            "max_concurrency": 2,
            "max_ssh_sessions": 4,
            "max_telnet_sessions": 4,
            "max_trace_hops": 64,
            "max_trace_jobs": 2,
            "max_speed_jobs": 1,
            "max_speed_test_seconds": 90.0,
            "min_speed_download_bytes": 25_000_000,
            "default_speed_download_bytes": 250_000_000,
            "max_speed_download_bytes": 2_000_000_000,
            "min_speed_upload_bytes": 10_000_000,
            "default_speed_upload_bytes": 100_000_000,
            "max_speed_upload_bytes": 1_000_000_000,
            "max_port_scan_ports": 65_535,
            "max_port_scan_concurrency": 128,
            "max_port_scan_jobs": 2,
            "max_port_scan_connect_seconds": 5.0,
            "max_port_scan_seconds": 900.0,
            "max_port_scan_results": 2_048,
            "max_retained_port_scan_jobs": 64,
        }
        assert system.json()["capabilities"]["ssh_client"] is True
        assert system.json()["capabilities"]["telnet_client"] is True

        created_response = await client.post(
            "/api/scans",
            json={
                "subnet": "192.0.2.0/31",
                "ports": [80],
                "timeout": 0.1,
                "concurrency": 1,
            },
        )
        assert created_response.status_code == 202
        created = created_response.json()
        assert created["subnet"] == "192.0.2.0/31"
        assert created["options"]["ports"] == [80]

        finished = await terminal_response(client, created["id"])
        assert finished["status"] == "completed"
        assert finished["progress"] == {
            "total_hosts": 2,
            "scanned_hosts": 2,
            "discovered_hosts": 1,
            "percent": 100.0,
        }

        results = await client.get(f"/api/scans/{created['id']}/results")
        assert results.status_code == 200
        assert results.json()["count"] == 1

        recent = await client.get("/api/scans", params={"limit": 1})
        assert recent.status_code == 200
        summaries = recent.json()
        assert len(summaries) == 1
        assert summaries[0]["id"] == created["id"]
        assert summaries[0]["subnet"] == "192.0.2.0/31"
        assert summaries[0]["progress"]["discovered_hosts"] == 1
        assert "results" not in summaries[0]
        assert "options" not in summaries[0]

        missing = await client.get("/api/scans/not-a-real-id")
        assert missing.status_code == 404
        assert missing.json()["detail"]["code"] == "scan_not_found"

    await service.shutdown()


@pytest.mark.asyncio
async def test_api_validation_and_local_cors() -> None:
    configured = make_settings()
    service = ScanService(configured, inspector=FakeInspector())
    app = create_app(configured, scan_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        oversized = await client.post(
            "/api/scans", json={"subnet": "192.0.2.0/28"}
        )
        assert oversized.status_code == 422
        assert oversized.json()["detail"] == {
            "code": "host_limit_exceeded",
            "message": "subnet contains 14 usable hosts; the configured limit is 4",
            "limit": 4,
            "actual": 14,
        }

        too_concurrent = await client.post(
            "/api/scans",
            json={"subnet": "192.0.2.0/31", "concurrency": 3},
        )
        assert too_concurrent.status_code == 422
        assert too_concurrent.json()["detail"]["code"] == "concurrency_limit_exceeded"

        for invalid_limit in (0, 51):
            invalid_history = await client.get(
                "/api/scans", params={"limit": invalid_limit}
            )
            assert invalid_history.status_code == 422

        preflight = await client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:9999",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        assert preflight.status_code == 400
        assert "access-control-allow-origin" not in preflight.headers

    await service.shutdown()


@pytest.mark.asyncio
async def test_update_api_requires_local_confirmation_and_pins_release() -> None:
    configured = make_settings()
    service = ScanService(configured, inspector=FakeInspector())
    updater = FakeUpdateService()
    app = create_app(configured, scan_service=service, update_service=updater)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 54321))

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        missing_origin = await client.post("/api/updates/check")
        assert missing_origin.status_code == 403
        assert missing_origin.json()["detail"]["code"] == "update_origin_not_allowed"

        foreign_origin = await client.post(
            "/api/updates/check", headers={"Origin": "https://example.com"}
        )
        assert foreign_origin.status_code == 403

        checked = await client.post(
            "/api/updates/check", headers={"Origin": "http://localhost:3000"}
        )
        assert checked.status_code == 200
        assert checked.json()["state"] == "available"
        assert checked.json()["candidate_commit"] == "2" * 40

        operation = await client.get("/api/updates/status")
        assert operation.status_code == 200
        assert operation.json()["state"] == "idle"

        body = {
            "confirm": True,
            "expected_current_commit": "1" * 40,
            "expected_candidate_commit": "2" * 40,
            "expected_release_tag": "v0.2.0",
        }
        applied = await client.post(
            "/api/updates/apply",
            json=body,
            headers={"Origin": "http://localhost:3000"},
        )
        assert applied.status_code == 200
        assert applied.json()["state"] == "updated"
        assert applied.json()["restart_required"] is True
        assert updater.apply_calls == 1

        rejected = await client.post(
            "/api/updates/apply",
            json=body,
            headers={"Origin": "http://localhost:9999"},
        )
        assert rejected.status_code == 403
        assert rejected.json()["detail"]["code"] == "update_origin_not_allowed"
        assert updater.apply_calls == 1

    remote_transport = httpx.ASGITransport(
        app=app, client=("192.0.2.10", 54321)
    )
    async with httpx.AsyncClient(
        transport=remote_transport, base_url="http://test"
    ) as remote_client:
        rejected_remote = await remote_client.post(
            "/api/updates/check", headers={"Origin": "http://localhost:3000"}
        )
        assert rejected_remote.status_code == 403
        assert rejected_remote.json()["detail"]["code"] == "api_requires_loopback"

    await service.shutdown()
