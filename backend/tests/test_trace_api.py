from __future__ import annotations

import asyncio

import httpx
import pytest

from better_network_tools.config import Settings
from better_network_tools.main import create_app
from better_network_tools.models import TraceAsnRecord
from better_network_tools.trace_service import TraceJobService
from better_network_tools.tracer import (
    NativeTraceResult,
    TraceHopObservation,
    TraceProbeObservation,
)


class ApiTracer:
    async def trace(self, address: str, address_family: str, **kwargs):
        assert address == "8.8.8.8"
        assert address_family == "IPv4"
        return NativeTraceResult(
            hops=(
                TraceHopObservation(
                    number=1,
                    probes=(
                        TraceProbeObservation(1, "8.8.8.8", 3.25, "reply"),
                        TraceProbeObservation(2, "8.8.8.8", 3.5, "reply"),
                        TraceProbeObservation(3, None, None, "timeout"),
                    ),
                ),
            ),
            returncode=0,
        )


class ApiReverseResolver:
    async def resolve(self, address: str, address_family: str) -> str:
        return "dns.google."


class ApiAsnProvider:
    async def lookup_many(self, addresses):
        assert list(addresses) == ["8.8.8.8"]
        return {
            "8.8.8.8": TraceAsnRecord(
                number=15169,
                name="GOOGLE",
                organization="Google LLC",
                prefix="8.8.8.0/24",
                country_code="US",
                registry="arin",
                source="team_cymru_whois",
            )
        }


async def terminal_payload(client: httpx.AsyncClient, job_id: str) -> dict:
    for _ in range(100):
        response = await client.get(f"/api/trace-jobs/{job_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"completed", "cancelled", "failed"}:
            return payload
        await asyncio.sleep(0)
    raise AssertionError("trace job did not complete")


async def shutdown_app(app) -> None:
    await app.state.trace_job_service.shutdown()
    await app.state.ping_job_service.shutdown()
    await app.state.scan_service.shutdown()
    await app.state.ssh_session_service.shutdown()


@pytest.mark.asyncio
async def test_trace_job_api_contract_and_openapi_use_only_mocked_network() -> None:
    settings = Settings(trace_hop_limit=12, trace_active_job_limit=1)
    trace_service = TraceJobService(
        settings,
        tracer=ApiTracer(),
        reverse_resolver=ApiReverseResolver(),
        asn_provider=ApiAsnProvider(),
    )
    app = create_app(settings, trace_job_service=trace_service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        created_response = await client.post(
            "/api/trace-jobs",
            json={
                "target": "8.8.8.8",
                "max_hops": 12,
                "timeout": 0.5,
                "resolve_dns": True,
                "lookup_asn": True,
            },
        )
        assert created_response.status_code == 202
        created = created_response.json()
        assert created["options"] == {
            "max_hops": 12,
            "timeout": 0.5,
            "probes_per_hop": 3,
            "resolve_dns": True,
            "lookup_asn": True,
        }
        assert set(created) == {
            "id",
            "status",
            "phase",
            "target",
            "resolved_address",
            "address_family",
            "created_at",
            "started_at",
            "finished_at",
            "options",
            "progress",
            "hops",
            "as_path",
            "reached_destination",
            "error",
            "warnings",
            "cancel_requested",
        }

        finished = await terminal_payload(client, created["id"])
        assert finished["status"] == "completed"
        assert finished["phase"] == "complete"
        assert finished["progress"] == {"last_hop": 1, "max_hops": 12}
        assert finished["reached_destination"] is True
        assert finished["hops"][0]["probes"] == [
            {
                "sequence": 1,
                "address": "8.8.8.8",
                "latency_ms": 3.25,
                "status": "reply",
                "annotation": None,
            },
            {
                "sequence": 2,
                "address": "8.8.8.8",
                "latency_ms": 3.5,
                "status": "reply",
                "annotation": None,
            },
            {
                "sequence": 3,
                "address": None,
                "latency_ms": None,
                "status": "timeout",
                "annotation": None,
            },
        ]
        responder = finished["hops"][0]["responders"][0]
        assert responder["hostname"] == "dns.google"
        assert responder["asn"]["number"] == 15169
        assert responder["asn"]["source"] == "team_cymru_whois"

        terminal_delete = await client.delete(
            f"/api/trace-jobs/{created['id']}"
        )
        assert terminal_delete.status_code == 200
        assert terminal_delete.json()["status"] == "completed"

        missing = await client.get("/api/trace-jobs/not-a-real-id")
        assert missing.status_code == 404
        assert missing.json()["detail"]["code"] == "trace_job_not_found"

        invalid = await client.post(
            "/api/trace-jobs", json={"target": "https://router.example"}
        )
        assert invalid.status_code == 422
        assert invalid.json()["detail"]["code"] == "invalid_trace_target"

        for non_boolean in (1, "yes"):
            invalid_opt_in = await client.post(
                "/api/trace-jobs",
                json={"target": "8.8.8.8", "lookup_asn": non_boolean},
            )
            assert invalid_opt_in.status_code == 422

        too_many_hops = await client.post(
            "/api/trace-jobs", json={"target": "8.8.8.8", "max_hops": 13}
        )
        assert too_many_hops.status_code == 422
        assert too_many_hops.json()["detail"] == {
            "code": "trace_hop_limit_exceeded",
            "message": "trace jobs may request at most 12 hops",
            "limit": 12,
            "actual": 13,
        }

        openapi = (await client.get("/openapi.json")).json()
        assert "/api/trace-jobs" in openapi["paths"]
        assert "/api/trace-jobs/{job_id}" in openapi["paths"]
        request_schema = openapi["components"]["schemas"]["TraceJobRequest"]
        assert request_schema["properties"]["lookup_asn"]["default"] is False
        hop_schema = openapi["components"]["schemas"]["TraceHopResponse"]
        assert hop_schema["properties"]["probes"]["maxItems"] == 3

    await shutdown_app(app)


@pytest.mark.asyncio
async def test_trace_capacity_api_returns_stable_429_and_delete_cancels() -> None:
    class BlockingTracer:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def trace(self, *args, **kwargs):
            self.started.set()
            await asyncio.Event().wait()

    settings = Settings(trace_active_job_limit=1)
    tracer = BlockingTracer()
    service = TraceJobService(settings, tracer=tracer)
    app = create_app(settings, trace_job_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first_response = await client.post(
            "/api/trace-jobs",
            json={"target": "8.8.8.8", "resolve_dns": False},
        )
        assert first_response.status_code == 202
        first = first_response.json()
        await asyncio.wait_for(tracer.started.wait(), timeout=0.5)

        rejected = await client.post(
            "/api/trace-jobs",
            json={"target": "1.1.1.1", "resolve_dns": False},
        )
        assert rejected.status_code == 429
        assert rejected.json() == {
            "detail": {
                "code": "trace_job_capacity_exceeded",
                "message": "the active trace-job limit of 1 has been reached",
                "limit": 1,
                "active": 1,
            }
        }

        stopped = await client.delete(f"/api/trace-jobs/{first['id']}")
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "cancelled"
        assert stopped.json()["cancel_requested"] is True

    await shutdown_app(app)
