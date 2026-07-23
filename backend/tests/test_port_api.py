from __future__ import annotations

import asyncio

import httpx
import pytest

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.models import PortResult
from better_network_tools.pinger import ResolvedPingTarget
from better_network_tools.port_scanner import PortProbeObservation
from better_network_tools.port_service import PortJobService


async def terminal_payload(client: httpx.AsyncClient, job_id: str) -> dict:
    for _ in range(1000):
        response = await client.get(f"/api/port-jobs/{job_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"completed", "cancelled", "failed"}:
            return payload
        await asyncio.sleep(0.001)
    raise AssertionError("NetPorts API job did not reach a terminal state")


async def shutdown_app(app) -> None:
    await app.state.port_job_service.shutdown()
    await app.state.speed_job_service.shutdown()
    await app.state.trace_job_service.shutdown()
    await app.state.ping_job_service.shutdown()
    await app.state.scan_service.shutdown()
    await app.state.ssh_session_service.shutdown()


@pytest.mark.asyncio
async def test_port_job_api_contract_system_limits_and_openapi_use_only_fakes() -> None:
    class ApiResolver:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            self.calls.append(hostname)
            return ResolvedPingTarget("192.0.2.100", "IPv4")

    class ApiProbe:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, int, dict[str, object]]] = []

        async def probe(
            self,
            address: str,
            address_family: str,
            port: int,
            **kwargs: object,
        ) -> PortProbeObservation:
            self.calls.append((address, address_family, port, kwargs))
            if port == 81:
                return PortProbeObservation(state="closed")
            return PortProbeObservation(
                state="open",
                result=PortResult(
                    port=port,
                    service={80: "http", 443: "https"}.get(port),
                    banner="test banner" if kwargs["collect_banner"] else None,
                    latency_ms=float(port) / 100,
                ),
            )

    configured = Settings(
        port_scan_port_limit=10,
        port_scan_concurrency=4,
        port_scan_active_job_limit=2,
        port_scan_timeout_limit_seconds=1.0,
        port_scan_total_timeout_seconds=30.0,
        banner_timeout_seconds=0.05,
    )
    resolver = ApiResolver()
    probe = ApiProbe()
    port_service = PortJobService(configured, resolver=resolver, probe=probe)
    app = create_app(configured, port_job_service=port_service)
    transport = httpx.ASGITransport(app=app)

    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            created_response = await client.post(
                "/api/port-jobs",
                json={
                    "target": "Router.Example.",
                    "ports": "443,80-81,80",
                    "timeout": 0.2,
                    "concurrency": 2,
                    "collect_banners": True,
                },
            )
            assert created_response.status_code == 202
            created = created_response.json()
            assert set(created) == {
                "id",
                "status",
                "target",
                "resolved_address",
                "address_family",
                "created_at",
                "started_at",
                "finished_at",
                "options",
                "progress",
                "results",
                "results_truncated",
                "error",
                "cancel_requested",
            }
            assert created["target"] == "Router.Example."
            assert created["options"] == {
                "port_spec": "80-81,443",
                "total_ports": 3,
                "timeout": 0.2,
                "concurrency": 2,
                "collect_banners": True,
            }
            assert created["progress"] == {
                "total_ports": 3,
                "scanned_ports": 0,
                "open_ports": 0,
                "closed_ports": 0,
                "timed_out_ports": 0,
                "error_ports": 0,
                "percent": 0.0,
            }
            assert created["results_truncated"] is False

            finished = await terminal_payload(client, created["id"])
            assert finished["status"] == "completed"
            assert finished["resolved_address"] == "192.0.2.100"
            assert finished["address_family"] == "IPv4"
            assert finished["progress"] == {
                "total_ports": 3,
                "scanned_ports": 3,
                "open_ports": 2,
                "closed_ports": 1,
                "timed_out_ports": 0,
                "error_ports": 0,
                "percent": 100.0,
            }
            assert [result["port"] for result in finished["results"]] == [80, 443]
            assert resolver.calls == ["router.example"]
            assert sorted(call[2] for call in probe.calls) == [80, 81, 443]

            terminal_delete = await client.delete(
                f"/api/port-jobs/{created['id']}"
            )
            assert terminal_delete.status_code == 200
            assert terminal_delete.json()["status"] == "completed"

            missing_get = await client.get("/api/port-jobs/not-a-real-id")
            assert missing_get.status_code == 404
            assert missing_get.json() == {
                "detail": {
                    "code": "port_job_not_found",
                    "message": "NetPorts job not-a-real-id was not found",
                }
            }
            missing_delete = await client.delete("/api/port-jobs/not-a-real-id")
            assert missing_delete.status_code == 404
            assert missing_delete.json()["detail"]["code"] == "port_job_not_found"

            system = (await client.get("/api/system")).json()
            assert system["capabilities"]["port_scan"] is True
            assert system["limits"]["max_port_scan_ports"] == 10
            assert system["limits"]["max_port_scan_concurrency"] == 4
            assert system["limits"]["max_port_scan_jobs"] == 2
            assert system["limits"]["max_port_scan_connect_seconds"] == 1.0
            assert system["limits"]["max_port_scan_seconds"] == 30.0
            assert system["limits"]["max_port_scan_results"] == 2048
            assert system["limits"]["max_retained_port_scan_jobs"] == 64

            openapi = (await client.get("/openapi.json")).json()
            assert "/api/port-jobs" in openapi["paths"]
            assert "/api/port-jobs/{job_id}" in openapi["paths"]
            assert set(openapi["paths"]["/api/port-jobs/{job_id}"]) == {
                "get",
                "delete",
            }
            request_schema = openapi["components"]["schemas"]["PortJobRequest"]
            assert request_schema["additionalProperties"] is False
            assert request_schema["properties"]["target"]["maxLength"] == 253
            assert request_schema["properties"]["ports"]["maxLength"] == 4096
            assert request_schema["properties"]["timeout"]["default"] == 0.75
            assert request_schema["properties"]["concurrency"]["default"] == 128
            assert request_schema["properties"]["collect_banners"]["default"] is False
            assert "PortJobResponse" in openapi["components"]["schemas"]
            assert "PortResult" in openapi["components"]["schemas"]
    finally:
        await shutdown_app(app)


@pytest.mark.asyncio
async def test_port_job_api_maps_validation_to_stable_422_responses() -> None:
    configured = Settings(
        port_scan_port_limit=2,
        port_scan_concurrency=1,
        port_scan_timeout_limit_seconds=0.1,
    )
    app = create_app(configured)
    transport = httpx.ASGITransport(app=app)

    cases = [
        (
            {
                "target": "https://router.example",
                "ports": "80",
                "timeout": 0.1,
                "concurrency": 1,
            },
            "invalid_port_target",
        ),
        (
            {
                "target": "192.0.2.1",
                "ports": "80,invalid",
                "timeout": 0.1,
                "concurrency": 1,
            },
            "invalid_port_spec",
        ),
        (
            {
                "target": "192.0.2.1",
                "ports": "1-3",
                "timeout": 0.1,
                "concurrency": 1,
            },
            "port_limit_exceeded",
        ),
        (
            {
                "target": "192.0.2.1",
                "ports": "80",
                "timeout": 0.2,
                "concurrency": 1,
            },
            "port_timeout_limit_exceeded",
        ),
        (
            {
                "target": "192.0.2.1",
                "ports": "80",
                "timeout": 0.1,
                "concurrency": 2,
            },
            "port_concurrency_limit_exceeded",
        ),
    ]

    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            for payload, expected_code in cases:
                response = await client.post("/api/port-jobs", json=payload)
                assert response.status_code == 422
                assert response.json()["detail"]["code"] == expected_code

            strict_boolean = await client.post(
                "/api/port-jobs",
                json={
                    "target": "192.0.2.1",
                    "ports": "80",
                    "timeout": 0.1,
                    "concurrency": 1,
                    "collect_banners": 1,
                },
            )
            assert strict_boolean.status_code == 422
            assert isinstance(strict_boolean.json()["detail"], list)
    finally:
        await shutdown_app(app)


@pytest.mark.asyncio
async def test_port_job_api_returns_429_and_delete_cancels_live_work() -> None:
    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            raise AssertionError("blocked API probe must be cancelled")

    configured = Settings(
        port_scan_port_limit=4,
        port_scan_concurrency=1,
        port_scan_active_job_limit=1,
        port_scan_timeout_limit_seconds=1.0,
        port_scan_total_timeout_seconds=30.0,
    )
    probe = BlockingProbe()
    port_service = PortJobService(configured, probe=probe)
    app = create_app(configured, port_job_service=port_service)
    transport = httpx.ASGITransport(app=app)
    payload = {
        "target": "192.0.2.110",
        "ports": "80",
        "timeout": 0.1,
        "concurrency": 1,
    }

    try:
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            first_response = await client.post("/api/port-jobs", json=payload)
            assert first_response.status_code == 202
            first = first_response.json()
            await asyncio.wait_for(probe.started.wait(), timeout=0.2)

            rejected = await client.post("/api/port-jobs", json=payload)
            assert rejected.status_code == 429
            assert rejected.json() == {
                "detail": {
                    "code": "port_job_capacity_exceeded",
                    "message": "the active NetPorts job limit of 1 has been reached",
                    "limit": 1,
                    "active": 1,
                }
            }

            stopped_response = await client.delete(
                f"/api/port-jobs/{first['id']}"
            )
            assert stopped_response.status_code == 200
            stopped = stopped_response.json()
            assert stopped["status"] == "cancelled"
            assert stopped["cancel_requested"] is True
            assert stopped["progress"]["scanned_ports"] == 0
            await asyncio.wait_for(probe.cancelled.wait(), timeout=0.2)
    finally:
        await shutdown_app(app)
