from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import ValidationError

import better_network_tools.speed_service as speed_service_module
from better_network_tools.config import Settings, load_settings
from better_network_tools.main import create_app
from better_network_tools.models import (
    SpeedJobProgress,
    SpeedJobRequest,
    SpeedJobStatus,
    SpeedServerListResponse,
    SpeedServerResponse,
    SpeedThroughputSample,
    TERMINAL_SPEED_JOB_STATUSES,
)
from better_network_tools.speed_service import (
    SpeedJobCapacityError,
    SpeedJobNotFoundError,
    SpeedJobService,
)
from better_network_tools.speedtest import (
    SpeedRunError,
    SpeedRunnerResult,
    SpeedServerNotFoundError,
    SpeedServerTarget,
    SpeedTestOptions,
)


SERVER = SpeedServerResponse(
    id="7",
    name="Mock public server",
    provider="librespeed",
    location="New York",
    country="US",
    sponsor="Example ISP",
    automatic=False,
)
TARGET = SpeedServerTarget(
    public=SERVER,
    ping_url="https://speed.example.test/ping",
    download_url="https://speed.example.test/download",
    upload_url="https://speed.example.test/upload",
)


class FakeCatalog:
    def __init__(self) -> None:
        self.shutdown_called = False

    async def list_servers(self) -> SpeedServerListResponse:
        return SpeedServerListResponse(
            servers=[SERVER],
            refreshed_at=datetime.now(UTC),
            directory_status="fresh",
        )

    async def resolve(self, server_id: str) -> SpeedServerTarget:
        if server_id != SERVER.id:
            raise SpeedServerNotFoundError(server_id)
        return TARGET

    async def shutdown(self) -> None:
        self.shutdown_called = True


class ImmediateRunner:
    def __init__(self) -> None:
        self.shutdown_called = False
        self.options_seen: list[SpeedTestOptions] = []

    async def run(self, server, on_progress, options):
        assert server is TARGET
        self.options_seen.append(options)
        await on_progress("ping", 20.0, 0, 0)
        await on_progress("download", 65.0, 2_000_000, 0)
        await on_progress("upload", 95.0, 2_000_000, 1_000_000)
        return SpeedRunnerResult(
            ping_ms=8.5,
            jitter_ms=1.25,
            download_mbps=80.0,
            upload_mbps=40.0,
            download_bytes=2_000_000,
            upload_bytes=1_000_000,
            duration_seconds=1.5,
        )

    async def shutdown(self) -> None:
        self.shutdown_called = True


async def wait_for_terminal(service: SpeedJobService, job_id: str):
    for _ in range(100):
        snapshot = await service.get_job(job_id)
        if snapshot.status in TERMINAL_SPEED_JOB_STATUSES:
            return snapshot
        await asyncio.sleep(0)
    raise AssertionError("speed job did not become terminal")


@pytest.mark.asyncio
async def test_speed_job_lifecycle_records_result_and_server_identity() -> None:
    catalog = FakeCatalog()
    runner = ImmediateRunner()
    service = SpeedJobService(Settings(), catalog=catalog, runner=runner)

    created = await service.create_job(SpeedJobRequest(server_id="7"))
    finished = await wait_for_terminal(service, created.id)

    assert created.status == SpeedJobStatus.QUEUED
    assert created.phase == "queued"
    assert created.options.model_dump() == {
        "download_bytes": 250_000_000,
        "upload_bytes": 100_000_000,
    }
    assert finished.status == SpeedJobStatus.COMPLETED
    assert finished.phase == "complete"
    assert finished.progress.model_dump() == {
        "percent": 100.0,
        "download_bytes": 2_000_000,
        "upload_bytes": 1_000_000,
        "current_mbps": None,
        "samples": [],
    }
    assert finished.result is not None
    assert finished.result.server == SERVER
    assert finished.result.ping_ms == 8.5
    assert finished.result.jitter_ms == 1.25
    assert finished.result.download_mbps == 80.0
    assert finished.result.upload_mbps == 40.0
    assert finished.result.transferred_bytes == 3_000_000
    assert finished.result.duration_seconds == 1.5
    assert runner.options_seen == [
        SpeedTestOptions(download_bytes=250_000_000, upload_bytes=100_000_000)
    ]
    await service.shutdown()
    assert catalog.shutdown_called is True
    assert runner.shutdown_called is True


def test_speed_server_latency_contract_is_nullable_finite_and_nonnegative() -> None:
    assert SERVER.latency_ms is None
    measured = SpeedServerResponse(
        **{**SERVER.model_dump(), "latency_ms": 8.25}
    )
    assert measured.latency_ms == 8.25

    for invalid in (-0.1, float("inf"), float("nan")):
        with pytest.raises(ValidationError):
            SpeedServerResponse(
                **{**SERVER.model_dump(), "latency_ms": invalid}
            )


def test_throughput_sample_contract_rejects_unbounded_or_non_finite_data() -> None:
    sample = SpeedThroughputSample(
        phase="download", elapsed_seconds=0.5, mbps=80.0
    )
    assert sample.model_dump() == {
        "phase": "download",
        "elapsed_seconds": 0.5,
        "mbps": 80.0,
    }

    for field_name, value in (
        ("elapsed_seconds", -0.1),
        ("elapsed_seconds", float("inf")),
        ("mbps", -1.0),
        ("mbps", float("nan")),
    ):
        values = {
            "phase": "download",
            "elapsed_seconds": 0.5,
            "mbps": 80.0,
            field_name: value,
        }
        with pytest.raises(ValidationError):
            SpeedThroughputSample(**values)

    with pytest.raises(ValidationError):
        SpeedJobProgress(
            percent=50,
            download_bytes=1,
            upload_bytes=0,
            current_mbps=None,
            samples=[sample] * 161,
        )
    with pytest.raises(ValidationError):
        SpeedJobProgress(
            percent=50,
            download_bytes=1,
            upload_bytes=0,
            current_mbps=float("inf"),
            samples=[],
        )


@pytest.mark.asyncio
async def test_throughput_samples_use_one_job_elapsed_timeline() -> None:
    clock = [100.0]

    class SeriesRunner:
        async def run(self, server, on_progress, options):
            await on_progress("ping", 20.0, 0, 0)
            clock[0] = 101.0
            await on_progress("download", 30.0, 0, 0)
            clock[0] = 101.25
            await on_progress("download", 45.0, 5_000_000, 0)
            clock[0] = 101.5
            await on_progress("download", 55.0, 10_000_000, 0)
            clock[0] = 101.75
            await on_progress("download", 62.0, 15_000_000, 0)
            clock[0] = 102.0
            await on_progress("upload", 70.0, 15_000_000, 0)
            clock[0] = 102.5
            await on_progress("upload", 95.0, 15_000_000, 5_000_000)
            return SpeedRunnerResult(
                ping_ms=5.0,
                jitter_ms=0.5,
                download_mbps=120.0,
                upload_mbps=80.0,
                download_bytes=15_000_000,
                upload_bytes=5_000_000,
                duration_seconds=2.5,
            )

    service = SpeedJobService(
        Settings(),
        catalog=FakeCatalog(),
        runner=SeriesRunner(),
        monotonic_clock=lambda: clock[0],
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    finished = await wait_for_terminal(service, created.id)

    assert finished.progress.current_mbps is None
    assert [sample.model_dump() for sample in finished.progress.samples] == [
        {"phase": "download", "elapsed_seconds": 1.5, "mbps": 160.0},
        {"phase": "download", "elapsed_seconds": 2.0, "mbps": 80.0},
        {"phase": "upload", "elapsed_seconds": 2.5, "mbps": 80.0},
    ]
    await service.shutdown()


@pytest.mark.asyncio
async def test_live_rate_is_cleared_on_cancel_while_partial_series_is_retained(
) -> None:
    clock = [200.0]

    class BlockingSeriesRunner:
        def __init__(self) -> None:
            self.sampled = asyncio.Event()

        async def run(self, server, on_progress, options):
            await on_progress("download", 30.0, 0, 0)
            clock[0] = 200.5
            await on_progress("download", 40.0, 5_000_000, 0)
            self.sampled.set()
            await asyncio.Event().wait()

    runner = BlockingSeriesRunner()
    service = SpeedJobService(
        Settings(),
        catalog=FakeCatalog(),
        runner=runner,
        monotonic_clock=lambda: clock[0],
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    await asyncio.wait_for(runner.sampled.wait(), timeout=0.5)

    active = await service.get_job(created.id)
    assert active.progress.current_mbps == 80.0
    assert [sample.model_dump() for sample in active.progress.samples] == [
        {"phase": "download", "elapsed_seconds": 0.5, "mbps": 80.0}
    ]

    cancelled = await service.cancel_job(created.id)
    assert cancelled.status == SpeedJobStatus.CANCELLED
    assert cancelled.progress.current_mbps is None
    assert cancelled.progress.samples == active.progress.samples
    await service.shutdown()


@pytest.mark.asyncio
async def test_throughput_history_is_capped_at_160_and_keeps_latest_sample() -> None:
    clock = [0.0]

    class LongSeriesRunner:
        async def run(self, server, on_progress, options):
            await on_progress("download", 30.0, 0, 0)
            for index in range(1, 166):
                clock[0] = index * 0.5
                await on_progress(
                    "download", 30.0, index * 1_000_000, 0
                )
            await on_progress("upload", 70.0, 165_000_000, 0)
            return SpeedRunnerResult(
                ping_ms=1.0,
                jitter_ms=0.0,
                download_mbps=16.0,
                upload_mbps=0.0,
                download_bytes=165_000_000,
                upload_bytes=0,
                duration_seconds=82.5,
            )

    service = SpeedJobService(
        Settings(),
        catalog=FakeCatalog(),
        runner=LongSeriesRunner(),
        monotonic_clock=lambda: clock[0],
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    finished = await wait_for_terminal(service, created.id)

    assert len(finished.progress.samples) == 160
    assert finished.progress.samples[-1].model_dump() == {
        "phase": "download",
        "elapsed_seconds": 82.5,
        "mbps": 16.0,
    }
    assert finished.progress.samples[0].elapsed_seconds == 3.0
    await service.shutdown()


@pytest.mark.asyncio
async def test_speed_run_failure_reports_server_and_keeps_partial_series() -> None:
    clock = [300.0]

    class ReportingCatalog(FakeCatalog):
        def __init__(self) -> None:
            super().__init__()
            self.reported: list[str] = []

        async def report_failure(self, server_id: str) -> None:
            self.reported.append(server_id)

    class PartialFailureRunner:
        async def run(self, server, on_progress, options):
            await on_progress("download", 30.0, 0, 0)
            clock[0] = 300.25
            await on_progress("download", 35.0, 4_000_000, 0)
            clock[0] = 300.3
            raise SpeedRunError(
                "The selected speed-test server did not respond successfully."
            )

    catalog = ReportingCatalog()
    service = SpeedJobService(
        Settings(),
        catalog=catalog,
        runner=PartialFailureRunner(),
        monotonic_clock=lambda: clock[0],
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    failed = await wait_for_terminal(service, created.id)

    assert failed.status == SpeedJobStatus.FAILED
    assert failed.progress.current_mbps is None
    assert [sample.model_dump() for sample in failed.progress.samples] == [
        {
            "phase": "download",
            "elapsed_seconds": 0.3,
            "mbps": 106.67,
        }
    ]
    assert catalog.reported == ["7"]
    await service.shutdown()


@pytest.mark.asyncio
async def test_server_quarantine_finishes_before_failed_status_is_visible() -> None:
    class BlockingReporterCatalog(FakeCatalog):
        def __init__(self) -> None:
            super().__init__()
            self.reporting = asyncio.Event()
            self.release = asyncio.Event()

        async def report_failure(self, server_id: str) -> None:
            assert server_id == "7"
            self.reporting.set()
            await self.release.wait()

    class FailedRunner:
        async def run(self, server, on_progress, options):
            raise SpeedRunError(
                "The selected speed-test server did not respond successfully."
            )

    catalog = BlockingReporterCatalog()
    service = SpeedJobService(
        Settings(), catalog=catalog, runner=FailedRunner()
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    await asyncio.wait_for(catalog.reporting.wait(), timeout=0.5)

    while_reporting = await service.get_job(created.id)
    assert while_reporting.status == SpeedJobStatus.RUNNING

    catalog.release.set()
    failed = await wait_for_terminal(service, created.id)
    assert failed.status == SpeedJobStatus.FAILED
    await service.shutdown()


@pytest.mark.asyncio
async def test_cancellation_capacity_not_found_and_shutdown_are_bounded() -> None:
    class BlockingRunner:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()
            self.shutdown_called = False

        async def run(self, server, on_progress, options):
            await on_progress("ping", 5.0, 0, 0)
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise

        async def shutdown(self) -> None:
            self.shutdown_called = True

    catalog = FakeCatalog()
    runner = BlockingRunner()
    service = SpeedJobService(
        Settings(speed_active_job_limit=1), catalog=catalog, runner=runner
    )
    first = await service.create_job(SpeedJobRequest(server_id="7"))
    await asyncio.wait_for(runner.started.wait(), timeout=0.5)

    with pytest.raises(SpeedJobCapacityError) as capacity:
        await service.create_job(SpeedJobRequest(server_id="7"))
    assert capacity.value.as_detail() == {
        "code": "speed_job_capacity_exceeded",
        "message": "the active speed-job limit of 1 has been reached",
        "limit": 1,
        "active": 1,
    }

    with pytest.raises(SpeedJobNotFoundError):
        await service.get_job("missing")

    cancelled = await service.cancel_job(first.id)
    assert cancelled.status == SpeedJobStatus.CANCELLED
    assert cancelled.phase == "complete"
    assert cancelled.cancel_requested is True
    assert runner.cancelled.is_set()

    second = await service.create_job(SpeedJobRequest(server_id="7"))
    await asyncio.wait_for(runner.started.wait(), timeout=0.5)
    await service.shutdown()
    stopped = await service.get_job(second.id)
    assert stopped.status == SpeedJobStatus.CANCELLED
    assert runner.shutdown_called is True
    assert catalog.shutdown_called is True


@pytest.mark.asyncio
async def test_unexpected_runner_errors_are_sanitized() -> None:
    class FailingRunner:
        async def run(self, server, on_progress, options):
            raise RuntimeError(
                "token=secret https://speed.example.test/private?credential=secret\x00"
            )

    service = SpeedJobService(
        Settings(), catalog=FakeCatalog(), runner=FailingRunner()
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    failed = await wait_for_terminal(service, created.id)
    assert failed.status == SpeedJobStatus.FAILED
    assert failed.error == "The speed test could not be completed."
    assert "secret" not in failed.error
    await service.shutdown()


@pytest.mark.asyncio
async def test_finished_speed_jobs_expire_after_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = [now]
    monkeypatch.setattr(speed_service_module, "_utc_now", lambda: clock[0])
    service = SpeedJobService(
        Settings(job_retention_seconds=60),
        catalog=FakeCatalog(),
        runner=ImmediateRunner(),
    )
    created = await service.create_job(SpeedJobRequest(server_id="7"))
    finished = await wait_for_terminal(service, created.id)
    assert finished.status == SpeedJobStatus.COMPLETED

    clock[0] = now + timedelta(seconds=61)
    with pytest.raises(SpeedJobNotFoundError):
        await service.get_job(created.id)
    await service.shutdown()


def test_speed_resource_limits_are_environment_backed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_SPEED_ACTIVE_JOB_LIMIT", "3")
    monkeypatch.setenv("BNT_SPEED_TOTAL_TIMEOUT_SECONDS", "60")
    monkeypatch.setenv("BNT_SPEED_DNS_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("BNT_SPEED_DOWNLOAD_BYTE_MINIMUM", "25000000")
    monkeypatch.setenv("BNT_SPEED_DOWNLOAD_BYTE_DEFAULT", "28000000")
    monkeypatch.setenv("BNT_SPEED_DOWNLOAD_BYTE_LIMIT", "30000000")
    monkeypatch.setenv("BNT_SPEED_UPLOAD_BYTE_MINIMUM", "10000000")
    monkeypatch.setenv("BNT_SPEED_UPLOAD_BYTE_DEFAULT", "11000000")
    monkeypatch.setenv("BNT_SPEED_UPLOAD_BYTE_LIMIT", "12000000")

    settings = load_settings()

    assert settings.speed_active_job_limit == 3
    assert settings.speed_total_timeout_seconds == 60.0
    assert settings.speed_dns_timeout_seconds == 2.5
    assert settings.speed_download_byte_minimum == 25_000_000
    assert settings.speed_download_byte_default == 28_000_000
    assert settings.speed_download_byte_limit == 30_000_000
    assert settings.speed_upload_byte_minimum == 10_000_000
    assert settings.speed_upload_byte_default == 11_000_000
    assert settings.speed_upload_byte_limit == 12_000_000


def test_speed_size_environment_requires_minimum_default_limit_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_SPEED_DOWNLOAD_BYTE_MINIMUM", "50000000")
    monkeypatch.setenv("BNT_SPEED_DOWNLOAD_BYTE_DEFAULT", "25000000")

    with pytest.raises(ValueError, match="minimum <= default <= limit"):
        load_settings()


async def shutdown_app(app) -> None:
    await app.state.speed_job_service.shutdown()
    await app.state.trace_job_service.shutdown()
    await app.state.ping_job_service.shutdown()
    await app.state.scan_service.shutdown()
    await app.state.ssh_session_service.shutdown()


@pytest.mark.asyncio
async def test_speed_api_contract_openapi_and_system_limits_use_only_fakes() -> None:
    settings = Settings(
        speed_active_job_limit=2,
        speed_total_timeout_seconds=30.0,
        speed_download_byte_minimum=1_000_000,
        speed_download_byte_default=2_000_000,
        speed_download_byte_limit=4_000_000,
        speed_upload_byte_minimum=500_000,
        speed_upload_byte_default=1_000_000,
        speed_upload_byte_limit=2_000_000,
    )
    service = SpeedJobService(
        settings, catalog=FakeCatalog(), runner=ImmediateRunner()
    )
    app = create_app(settings, speed_job_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        servers = await client.get("/api/speed-servers")
        assert servers.status_code == 200
        assert servers.json()["directory_status"] == "fresh"
        assert servers.json()["servers"] == [SERVER.model_dump(mode="json")]
        assert servers.json()["servers"][0]["latency_ms"] is None
        assert all("url" not in key for key in servers.json()["servers"][0])

        created_response = await client.post(
            "/api/speed-jobs",
            json={
                "server_id": "7",
                "download_bytes": 3_000_000,
                "upload_bytes": 1_500_000,
            },
        )
        assert created_response.status_code == 202
        created = created_response.json()
        assert set(created) == {
            "id",
            "status",
            "phase",
            "server",
            "created_at",
            "started_at",
            "finished_at",
            "options",
            "progress",
            "result",
            "error",
            "cancel_requested",
        }
        assert created["options"] == {
            "download_bytes": 3_000_000,
            "upload_bytes": 1_500_000,
        }
        assert created["progress"] == {
            "percent": 0.0,
            "download_bytes": 0,
            "upload_bytes": 0,
            "current_mbps": None,
            "samples": [],
        }

        for _ in range(100):
            response = await client.get(f"/api/speed-jobs/{created['id']}")
            payload = response.json()
            if payload["status"] == "completed":
                break
            await asyncio.sleep(0)
        else:
            raise AssertionError("speed API job did not finish")

        assert payload["phase"] == "complete"
        assert payload["progress"]["current_mbps"] is None
        assert payload["progress"]["samples"] == []
        assert payload["result"]["server"]["id"] == "7"
        assert payload["result"]["transferred_bytes"] == 3_000_000

        terminal_delete = await client.delete(
            f"/api/speed-jobs/{created['id']}"
        )
        assert terminal_delete.status_code == 200
        assert terminal_delete.json()["status"] == "completed"

        missing = await client.get("/api/speed-jobs/not-real")
        assert missing.status_code == 404
        assert missing.json()["detail"]["code"] == "speed_job_not_found"

        unknown_server = await client.post(
            "/api/speed-jobs", json={"server_id": "unknown"}
        )
        assert unknown_server.status_code == 422
        assert unknown_server.json() == {
            "detail": {
                "code": "speed_server_not_found",
                "message": "the selected speed-test server is not available",
            }
        }

        arbitrary_url = await client.post(
            "/api/speed-jobs", json={"server_id": "https://attacker.example"}
        )
        assert arbitrary_url.status_code == 422

        too_small = await client.post(
            "/api/speed-jobs",
            json={"server_id": "7", "download_bytes": 999_999},
        )
        assert too_small.status_code == 422
        assert too_small.json() == {
            "detail": {
                "code": "speed_transfer_size_out_of_range",
                "message": (
                    "download_bytes must be between 1000000 and 4000000 bytes"
                ),
                "field": "download_bytes",
                "actual": 999_999,
                "minimum": 1_000_000,
                "maximum": 4_000_000,
            }
        }

        too_large = await client.post(
            "/api/speed-jobs",
            json={"server_id": "7", "upload_bytes": 2_000_001},
        )
        assert too_large.status_code == 422
        assert too_large.json()["detail"] == {
            "code": "speed_transfer_size_out_of_range",
            "message": "upload_bytes must be between 500000 and 2000000 bytes",
            "field": "upload_bytes",
            "actual": 2_000_001,
            "minimum": 500_000,
            "maximum": 2_000_000,
        }

        for invalid_body in (
            {"server_id": "7", "download_bytes": "3000000"},
            {"server_id": "7", "upload_bytes": True},
            {"server_id": "7", "download_bytes": 3_000_000, "streams": 8},
        ):
            rejected_body = await client.post(
                "/api/speed-jobs", json=invalid_body
            )
            assert rejected_body.status_code == 422

        system = (await client.get("/api/system")).json()
        assert system["capabilities"]["speed_test"] is True
        assert system["capabilities"]["internet_speed_test"] is True
        assert system["capabilities"]["public_speed_servers"] is True
        assert system["limits"]["max_speed_jobs"] == 2
        assert system["limits"]["max_speed_test_seconds"] == 30.0
        assert system["limits"]["min_speed_download_bytes"] == 1_000_000
        assert system["limits"]["default_speed_download_bytes"] == 2_000_000
        assert system["limits"]["max_speed_download_bytes"] == 4_000_000
        assert system["limits"]["min_speed_upload_bytes"] == 500_000
        assert system["limits"]["default_speed_upload_bytes"] == 1_000_000
        assert system["limits"]["max_speed_upload_bytes"] == 2_000_000

        openapi = (await client.get("/openapi.json")).json()
        assert "/api/speed-servers" in openapi["paths"]
        assert "/api/speed-jobs" in openapi["paths"]
        assert "/api/speed-jobs/{job_id}" in openapi["paths"]
        assert "SpeedTestResult" in openapi["components"]["schemas"]
        assert "SpeedThroughputSample" in openapi["components"]["schemas"]
        server_schema = openapi["components"]["schemas"]["SpeedServerResponse"]
        assert "latency_ms" in server_schema["properties"]
        progress_schema = openapi["components"]["schemas"]["SpeedJobProgress"]
        assert set(progress_schema["properties"]) == {
            "percent",
            "download_bytes",
            "upload_bytes",
            "current_mbps",
            "samples",
        }
        assert progress_schema["properties"]["samples"]["maxItems"] == 160
        assert set(progress_schema["required"]) == {
            "percent",
            "download_bytes",
            "upload_bytes",
            "current_mbps",
            "samples",
        }
        request_schema = openapi["components"]["schemas"]["SpeedJobRequest"]
        assert set(request_schema["properties"]) == {
            "server_id",
            "download_bytes",
            "upload_bytes",
        }

    await shutdown_app(app)


@pytest.mark.asyncio
async def test_speed_api_maps_live_cancellation_capacity_and_not_found() -> None:
    class BlockingRunner:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def run(self, server, on_progress, options):
            await on_progress("download", 30.0, 0, 0)
            self.started.set()
            await asyncio.Event().wait()

    settings = Settings(speed_active_job_limit=1)
    runner = BlockingRunner()
    service = SpeedJobService(settings, catalog=FakeCatalog(), runner=runner)
    app = create_app(settings, speed_job_service=service)
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        first_response = await client.post(
            "/api/speed-jobs", json={"server_id": "7"}
        )
        assert first_response.status_code == 202
        first = first_response.json()
        await asyncio.wait_for(runner.started.wait(), timeout=0.5)

        rejected = await client.post(
            "/api/speed-jobs", json={"server_id": "7"}
        )
        assert rejected.status_code == 429
        assert rejected.json() == {
            "detail": {
                "code": "speed_job_capacity_exceeded",
                "message": "the active speed-job limit of 1 has been reached",
                "limit": 1,
                "active": 1,
            }
        }

        stopped = await client.delete(f"/api/speed-jobs/{first['id']}")
        assert stopped.status_code == 200
        assert stopped.json()["status"] == "cancelled"
        assert stopped.json()["cancel_requested"] is True

        missing = await client.delete("/api/speed-jobs/missing")
        assert missing.status_code == 404
        assert missing.json()["detail"]["code"] == "speed_job_not_found"

    await shutdown_app(app)
