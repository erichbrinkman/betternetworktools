from __future__ import annotations

import asyncio

import httpx
import pytest

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.ping_service import PingJobService
from better_network_tools.pinger import PingProbeResult


class MockReverseResolver:
    async def resolve(self, address: str, address_family: str) -> str:
        assert address == "192.0.2.1"
        assert address_family == "IPv4"
        return "router.example"


@pytest.mark.asyncio
async def test_ping_job_api_contract_and_openapi_use_only_mocked_probes() -> None:
    class FakeProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            assert address == "192.0.2.1"
            assert address_family == "IPv4"
            return PingProbeResult(received=True, latency_ms=3.25)

    settings = Settings()
    ping_service = PingJobService(
        settings, probe=FakeProbe(), reverse_resolver=MockReverseResolver()
    )
    app = create_app(settings, ping_job_service=ping_service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created_response = await client.post(
            "/api/ping-jobs", json={"targets": ["192.0.2.1"], "count": 1}
        )
        assert created_response.status_code == 202
        created = created_response.json()
        assert created["options"] == {
            "count": 1,
            "interval": 1.0,
            "timeout": 1.0,
            "continuous": False,
        }
        assert set(created) == {
            "id",
            "status",
            "created_at",
            "started_at",
            "finished_at",
            "options",
            "progress",
            "targets",
            "error",
            "cancel_requested",
        }

        for _ in range(100):
            response = await client.get(f"/api/ping-jobs/{created['id']}")
            payload = response.json()
            if payload["status"] == "completed":
                break
            await asyncio.sleep(0)
        else:
            raise AssertionError("ping job did not complete")

        assert payload["progress"] == {
            "total_probes": 1,
            "completed_probes": 1,
            "percent": 100.0,
        }
        assert payload["targets"][0] == {
            "target": "192.0.2.1",
            "resolved_address": "192.0.2.1",
            "address_family": "IPv4",
            "reverse_hostname": "router.example",
            "reverse_dns_status": "resolved",
            "status": "up",
            "sent": 1,
            "received": 1,
            "failed": 0,
            "consecutive_successes": 1,
            "max_consecutive_successes": 1,
            "consecutive_failures": 0,
            "max_consecutive_failures": 0,
            "reply_time_history_ms": [3.25],
            "latency_samples": 1,
            "success_rate": 100.0,
            "loss_percent": 0.0,
            "last_ms": 3.25,
            "avg_ms": 3.25,
            "min_ms": 3.25,
            "max_ms": 3.25,
            "last_checked": payload["targets"][0]["last_checked"],
            "error": None,
        }

        deleted = await client.delete(f"/api/ping-jobs/{created['id']}")
        assert deleted.status_code == 200
        assert deleted.json()["status"] == "completed"

        missing = await client.get("/api/ping-jobs/not-a-real-id")
        assert missing.status_code == 404
        assert missing.json()["detail"]["code"] == "ping_job_not_found"

        invalid = await client.post(
            "/api/ping-jobs", json={"targets": ["https://router.example"]}
        )
        assert invalid.status_code == 422
        assert invalid.json()["detail"]["code"] == "invalid_ping_target"

        openapi = (await client.get("/openapi.json")).json()
        assert "/api/ping-jobs" in openapi["paths"]
        assert "/api/ping-jobs/{job_id}" in openapi["paths"]
        assert "PingJobResponse" in openapi["components"]["schemas"]
        target_schema = openapi["components"]["schemas"]["PingTargetResponse"]
        assert target_schema["properties"]["reply_time_history_ms"]["maxItems"] == 60
        reverse_hostname_schema = target_schema["properties"]["reverse_hostname"]
        assert any(
            option.get("maxLength") == 253
            for option in reverse_hostname_schema["anyOf"]
        )
        assert target_schema["properties"]["reverse_dns_status"]["enum"] == [
            "not_requested",
            "pending",
            "resolved",
            "not_found",
            "unavailable",
        ]

    await ping_service.shutdown()
    await app.state.scan_service.shutdown()


@pytest.mark.asyncio
async def test_continuous_ping_api_reports_unbounded_progress_and_stops() -> None:
    class BlockingSecondProbe:
        def __init__(self) -> None:
            self.calls = 0
            self.second_started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.calls += 1
            if self.calls == 1:
                return PingProbeResult(received=True, latency_ms=4.0)
            self.second_started.set()
            await self.never.wait()
            raise AssertionError("cancelled probe must not finish")

    settings = Settings()
    probe = BlockingSecondProbe()
    ping_service = PingJobService(
        settings, probe=probe, reverse_resolver=MockReverseResolver()
    )
    app = create_app(settings, ping_job_service=ping_service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created_response = await client.post(
            "/api/ping-jobs",
            json={
                "targets": ["192.0.2.1"],
                "continuous": True,
                "interval": 0.2,
            },
        )
        assert created_response.status_code == 202
        created = created_response.json()
        assert created["options"]["continuous"] is True
        assert created["progress"]["total_probes"] is None
        assert created["progress"]["percent"] is None

        await asyncio.wait_for(probe.second_started.wait(), timeout=0.5)
        stopped_response = await client.delete(
            f"/api/ping-jobs/{created['id']}"
        )
        assert stopped_response.status_code == 200
        stopped = stopped_response.json()
        assert stopped["status"] == "cancelled"
        assert stopped["cancel_requested"] is True
        assert stopped["progress"] == {
            "total_probes": None,
            "completed_probes": 1,
            "percent": None,
        }
        assert stopped["targets"][0]["avg_ms"] == 4.0
        assert stopped["targets"][0]["latency_samples"] == 1
        assert stopped["targets"][0]["consecutive_successes"] == 1
        assert stopped["targets"][0]["max_consecutive_successes"] == 1
        assert stopped["targets"][0]["consecutive_failures"] == 0
        assert stopped["targets"][0]["max_consecutive_failures"] == 0
        assert stopped["targets"][0]["reply_time_history_ms"] == [4.0]

    await ping_service.shutdown()
    await app.state.scan_service.shutdown()


@pytest.mark.asyncio
async def test_ping_job_capacity_api_returns_stable_429_contract() -> None:
    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            await self.never.wait()
            raise AssertionError("cancelled probe must not finish")

    settings = Settings(ping_active_job_limit=1)
    probe = BlockingProbe()
    ping_service = PingJobService(
        settings, probe=probe, reverse_resolver=MockReverseResolver()
    )
    app = create_app(settings, ping_job_service=ping_service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first_response = await client.post(
            "/api/ping-jobs",
            json={"targets": ["192.0.2.1"], "continuous": True},
        )
        assert first_response.status_code == 202
        first = first_response.json()
        await asyncio.wait_for(probe.started.wait(), timeout=0.5)

        rejected = await client.post(
            "/api/ping-jobs",
            json={"targets": ["192.0.2.2"], "continuous": True},
        )
        assert rejected.status_code == 429
        assert rejected.json() == {
            "detail": {
                "code": "ping_job_capacity_exceeded",
                "message": "the active ping-job limit of 1 has been reached",
                "limit": 1,
                "active": 1,
            }
        }

        stopped = await client.delete(f"/api/ping-jobs/{first['id']}")
        assert stopped.status_code == 200

    await ping_service.shutdown()
    await app.state.scan_service.shutdown()
