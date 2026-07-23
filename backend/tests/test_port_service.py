from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from better_network_tools.config import Settings
from better_network_tools.models import (
    TERMINAL_PORT_JOB_STATUSES,
    PortJobRequest,
    PortJobResponse,
    PortJobStatus,
    PortResult,
)
from better_network_tools.pinger import ResolvedPingTarget
from better_network_tools.port_scanner import PortProbeObservation
from better_network_tools.port_service import (
    PortJobCapacityError,
    PortJobNotFoundError,
    PortJobService,
)
from better_network_tools.port_validation import PortValidationError


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "port_scan_port_limit": 32,
        "port_scan_concurrency": 4,
        "port_scan_active_job_limit": 2,
        "port_scan_timeout_limit_seconds": 0.5,
        "port_scan_resolve_timeout_seconds": 0.1,
        "port_scan_total_timeout_seconds": 0.5,
        "banner_timeout_seconds": 0.05,
        "job_retention_seconds": 60,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def open_result(port: int, *, latency_ms: float | None = None) -> PortProbeObservation:
    return PortProbeObservation(
        state="open",
        result=PortResult(
            port=port,
            service={22: "ssh", 80: "http", 443: "https"}.get(port),
            latency_ms=latency_ms if latency_ms is not None else float(port) / 10,
        ),
    )


async def wait_for_terminal(
    service: PortJobService, job_id: str
) -> PortJobResponse:
    for _ in range(1000):
        snapshot = await service.get_job(job_id)
        if snapshot.status in TERMINAL_PORT_JOB_STATUSES:
            return snapshot
        await asyncio.sleep(0.001)
    raise AssertionError("NetPorts job did not reach a terminal state")


@pytest.mark.asyncio
async def test_job_resolves_hostname_once_and_records_sorted_progress() -> None:
    class RecordingResolver:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            self.calls.append(hostname)
            return ResolvedPingTarget("192.0.2.40", "IPv4")

    class MixedProbe:
        def __init__(self) -> None:
            self.calls: list[tuple[object, ...]] = []

        async def probe(
            self,
            address: str,
            address_family: str,
            port: int,
            **kwargs: object,
        ) -> PortProbeObservation:
            self.calls.append((address, address_family, port, kwargs))
            if port == 22:
                raise OSError("per-port failure is counted, not fatal")
            if port == 80:
                await asyncio.sleep(0.005)
                return open_result(80, latency_ms=1.25)
            if port == 81:
                return PortProbeObservation(state="closed")
            if port == 82:
                return PortProbeObservation(state="timed_out")
            if port == 443:
                return open_result(443, latency_ms=2.5)
            raise AssertionError(f"unexpected port {port}")

    resolver = RecordingResolver()
    probe = MixedProbe()
    service = PortJobService(settings(), resolver=resolver, probe=probe)
    try:
        created = await service.create_job(
            PortJobRequest(
                target="Router.Example.",
                ports="443,80-82,80,22",
                timeout=0.2,
                concurrency=3,
                collect_banners=True,
            )
        )
        assert created.status == PortJobStatus.QUEUED
        assert created.target == "Router.Example."
        assert created.options.port_spec == "22,80-82,443"
        assert created.options.total_ports == 5
        assert created.progress.percent == 0

        finished = await wait_for_terminal(service, created.id)

        assert resolver.calls == ["router.example"]
        assert finished.status == PortJobStatus.COMPLETED
        assert finished.resolved_address == "192.0.2.40"
        assert finished.address_family == "IPv4"
        assert finished.progress.model_dump() == {
            "total_ports": 5,
            "scanned_ports": 5,
            "open_ports": 2,
            "closed_ports": 1,
            "timed_out_ports": 1,
            "error_ports": 1,
            "percent": 100.0,
        }
        assert [result.port for result in finished.results] == [80, 443]
        assert [result.latency_ms for result in finished.results] == [1.25, 2.5]
        assert finished.error is None
        assert finished.started_at is not None
        assert finished.finished_at is not None
        assert finished.cancel_requested is False
        assert service._jobs[created.id].ports == ()

        assert sorted(call[2] for call in probe.calls) == [22, 80, 81, 82, 443]
        for address, family, _port, kwargs in probe.calls:
            assert address == "192.0.2.40"
            assert family == "IPv4"
            assert kwargs == {
                "timeout": 0.2,
                "banner_timeout": 0.05,
                "collect_banner": True,
            }
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_requested_concurrency_bounds_simultaneous_probes() -> None:
    class NeverResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            raise AssertionError("numeric targets must bypass DNS")

    class GatedProbe:
        def __init__(self) -> None:
            self.active = 0
            self.maximum_active = 0
            self.calls = 0
            self.two_started = asyncio.Event()
            self.release = asyncio.Event()

        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            self.calls += 1
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
            if self.active == 2:
                self.two_started.set()
            try:
                await self.release.wait()
                return PortProbeObservation(state="closed")
            finally:
                self.active -= 1

    probe = GatedProbe()
    service = PortJobService(settings(port_scan_concurrency=4), probe=probe, resolver=NeverResolver())
    try:
        created = await service.create_job(
            PortJobRequest(
                target="192.0.2.50",
                ports="1-4",
                timeout=0.1,
                concurrency=2,
            )
        )
        await asyncio.wait_for(probe.two_started.wait(), timeout=0.2)

        assert probe.calls == 2
        assert probe.maximum_active == 2

        probe.release.set()
        finished = await wait_for_terminal(service, created.id)
        assert finished.status == PortJobStatus.COMPLETED
        assert finished.progress.closed_ports == 4
        assert probe.calls == 4
        assert probe.maximum_active == 2
    finally:
        probe.release.set()
        await service.shutdown()


@pytest.mark.asyncio
async def test_active_job_capacity_is_atomic_and_released_by_cancellation() -> None:
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
            raise AssertionError("blocking probe must be cancelled")

    probe = BlockingProbe()
    service = PortJobService(
        settings(port_scan_active_job_limit=1),
        probe=probe,
    )
    request = PortJobRequest(
        target="192.0.2.60", ports="80", timeout=0.1, concurrency=1
    )
    try:
        outcomes = await asyncio.gather(
            service.create_job(request),
            service.create_job(request),
            return_exceptions=True,
        )
        created = [item for item in outcomes if isinstance(item, PortJobResponse)]
        rejected = [item for item in outcomes if isinstance(item, PortJobCapacityError)]
        assert len(created) == 1
        assert len(rejected) == 1
        assert rejected[0].as_detail() == {
            "code": "port_job_capacity_exceeded",
            "message": "the active NetPorts job limit of 1 has been reached",
            "limit": 1,
            "active": 1,
        }

        await asyncio.wait_for(probe.started.wait(), timeout=0.2)
        cancelled = await service.cancel_job(created[0].id)
        assert cancelled.status == PortJobStatus.CANCELLED
        assert cancelled.cancel_requested is True
        assert cancelled.progress.scanned_ports == 0
        assert cancelled.finished_at is not None
        await asyncio.wait_for(probe.cancelled.wait(), timeout=0.2)

        replacement = await service.create_job(request)
        assert replacement.id != created[0].id
        await service.cancel_job(replacement.id)
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_total_timeout_cancels_workers_and_retains_partial_open_results() -> None:
    class PartialThenBlockingProbe:
        def __init__(self) -> None:
            self.second_started = asyncio.Event()
            self.second_cancelled = asyncio.Event()

        async def probe(
            self, address: str, address_family: str, port: int, **kwargs: object
        ) -> PortProbeObservation:
            if port == 1:
                return open_result(1, latency_ms=0.5)
            self.second_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.second_cancelled.set()
                raise
            raise AssertionError("second probe must be cancelled by total timeout")

    probe = PartialThenBlockingProbe()
    service = PortJobService(
        settings(port_scan_total_timeout_seconds=0.02),
        probe=probe,
    )
    try:
        created = await service.create_job(
            PortJobRequest(
                target="192.0.2.70",
                ports="1-2",
                timeout=0.1,
                concurrency=1,
            )
        )
        await asyncio.wait_for(probe.second_started.wait(), timeout=0.2)
        finished = await wait_for_terminal(service, created.id)

        assert finished.status == PortJobStatus.FAILED
        assert finished.progress.scanned_ports == 1
        assert finished.progress.open_ports == 1
        assert finished.progress.percent == 50.0
        assert [result.port for result in finished.results] == [1]
        assert finished.error is not None
        assert "configured total time limit" in finished.error
        assert finished.cancel_requested is False
        await asyncio.wait_for(probe.second_cancelled.wait(), timeout=0.2)
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_resolution_timeout_fails_before_any_probe() -> None:
    class BlockingResolver:
        def __init__(self) -> None:
            self.cancelled = asyncio.Event()

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise
            raise AssertionError("resolver must be cancelled by its deadline")

    class NeverProbe:
        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            raise AssertionError("resolution failure must prevent probing")

    resolver = BlockingResolver()
    service = PortJobService(
        settings(port_scan_resolve_timeout_seconds=0.01),
        resolver=resolver,
        probe=NeverProbe(),
    )
    try:
        created = await service.create_job(
            PortJobRequest(
                target="router.example",
                ports="80",
                timeout=0.1,
                concurrency=1,
            )
        )
        finished = await wait_for_terminal(service, created.id)

        assert finished.status == PortJobStatus.FAILED
        assert finished.resolved_address is None
        assert finished.progress.scanned_ports == 0
        assert finished.error == (
            "NetPorts could not complete the scan: "
            "resolution timed out for router.example"
        )
        await asyncio.wait_for(resolver.cancelled.wait(), timeout=0.2)
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_job_errors_are_control_sanitized_and_bounded() -> None:
    class FailingResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            raise OSError("resolver\x00detail\n" + ("x" * 400))

    service = PortJobService(settings(), resolver=FailingResolver())
    try:
        created = await service.create_job(
            PortJobRequest(
                target="router.example",
                ports="80",
                timeout=0.1,
                concurrency=1,
            )
        )
        finished = await wait_for_terminal(service, created.id)

        assert finished.status == PortJobStatus.FAILED
        assert finished.error is not None
        assert finished.error.startswith(
            "NetPorts could not complete the scan: resolver detail "
        )
        assert "\x00" not in finished.error
        assert "\n" not in finished.error
        assert len(finished.error) <= 240
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_finished_jobs_expire_after_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(
        "better_network_tools.port_service._utc_now",
        lambda: current,
    )

    class ClosedProbe:
        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            return PortProbeObservation(state="closed")

    service = PortJobService(settings(job_retention_seconds=60), probe=ClosedProbe())
    try:
        created = await service.create_job(
            PortJobRequest(
                target="192.0.2.80",
                ports="80",
                timeout=0.1,
                concurrency=1,
            )
        )
        finished = await wait_for_terminal(service, created.id)
        assert finished.status == PortJobStatus.COMPLETED

        current += timedelta(seconds=61)
        with pytest.raises(PortJobNotFoundError):
            await service.get_job(created.id)
    finally:
        await service.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("configured", "job_request", "expected_code"),
    [
        (
            {"port_scan_port_limit": 2},
            PortJobRequest(
                target="192.0.2.90",
                ports="1-3",
                timeout=0.1,
                concurrency=1,
            ),
            "port_limit_exceeded",
        ),
        (
            {"port_scan_timeout_limit_seconds": 0.1},
            PortJobRequest(
                target="192.0.2.90",
                ports="80",
                timeout=0.2,
                concurrency=1,
            ),
            "port_timeout_limit_exceeded",
        ),
        (
            {"port_scan_concurrency": 1},
            PortJobRequest(
                target="192.0.2.90",
                ports="80",
                timeout=0.1,
                concurrency=2,
            ),
            "port_concurrency_limit_exceeded",
        ),
    ],
)
async def test_configured_limits_are_rejected_before_resolution_or_probing(
    configured: dict[str, object],
    job_request: PortJobRequest,
    expected_code: str,
) -> None:
    class NeverResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            raise AssertionError("validation must happen before DNS")

    class NeverProbe:
        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            raise AssertionError("validation must happen before probing")

    service = PortJobService(
        settings(**configured), resolver=NeverResolver(), probe=NeverProbe()
    )
    try:
        with pytest.raises(PortValidationError) as raised:
            await service.create_job(job_request)
        assert raised.value.code == expected_code
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_omitted_options_adapt_to_lower_configured_ceilings() -> None:
    class ClosedProbe:
        async def probe(self, *args: object, **kwargs: object) -> PortProbeObservation:
            assert kwargs["timeout"] == 0.05
            return PortProbeObservation(state="closed")

    service = PortJobService(
        settings(
            port_scan_port_limit=1,
            port_scan_concurrency=1,
            port_scan_timeout_limit_seconds=0.05,
        ),
        probe=ClosedProbe(),
    )
    try:
        created = await service.create_job(PortJobRequest(target="192.0.2.91"))
        assert created.options.total_ports == 1
        assert created.options.concurrency == 1
        assert created.options.timeout == 0.05
        finished = await wait_for_terminal(service, created.id)
        assert finished.status == PortJobStatus.COMPLETED
        assert finished.progress.scanned_ports == 1
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_open_result_details_and_terminal_job_retention_are_count_bounded() -> None:
    class OpenProbe:
        async def probe(
            self, address: str, address_family: str, port: int, **kwargs: object
        ) -> PortProbeObservation:
            return open_result(port)

    service = PortJobService(
        settings(port_scan_result_limit=2, port_scan_retained_job_limit=2),
        probe=OpenProbe(),
    )
    try:
        wide = await service.create_job(
            PortJobRequest(
                target="192.0.2.92", ports="1-3", timeout=0.1, concurrency=2
            )
        )
        wide_finished = await wait_for_terminal(service, wide.id)
        assert wide_finished.progress.open_ports == 3
        assert len(wide_finished.results) == 2
        assert wide_finished.results_truncated is True

        second = await service.create_job(
            PortJobRequest(
                target="192.0.2.92", ports="4", timeout=0.1, concurrency=1
            )
        )
        await wait_for_terminal(service, second.id)
        third = await service.create_job(
            PortJobRequest(
                target="192.0.2.92", ports="5", timeout=0.1, concurrency=1
            )
        )
        await wait_for_terminal(service, third.id)

        with pytest.raises(PortJobNotFoundError):
            await service.get_job(wide.id)
        assert (await service.get_job(second.id)).status == PortJobStatus.COMPLETED
        assert (await service.get_job(third.id)).status == PortJobStatus.COMPLETED
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_capacity_rejection_does_not_evict_a_retained_terminal_job() -> None:
    class SelectiveProbe:
        def __init__(self) -> None:
            self.blocked = asyncio.Event()
            self.release = asyncio.Event()

        async def probe(
            self, address: str, address_family: str, port: int, **kwargs: object
        ) -> PortProbeObservation:
            if port != 3:
                return PortProbeObservation(state="closed")
            self.blocked.set()
            await self.release.wait()
            return PortProbeObservation(state="closed")

    probe = SelectiveProbe()
    service = PortJobService(
        settings(port_scan_active_job_limit=1, port_scan_retained_job_limit=3),
        probe=probe,
    )

    def request(port: int) -> PortJobRequest:
        return PortJobRequest(
            target="192.0.2.93",
            ports=str(port),
            timeout=0.1,
            concurrency=1,
        )

    try:
        first = await service.create_job(request(1))
        await wait_for_terminal(service, first.id)
        second = await service.create_job(request(2))
        await wait_for_terminal(service, second.id)
        active = await service.create_job(request(3))
        await asyncio.wait_for(probe.blocked.wait(), timeout=0.2)

        with pytest.raises(PortJobCapacityError):
            await service.create_job(request(4))

        assert (await service.get_job(first.id)).status == PortJobStatus.COMPLETED
        assert (await service.get_job(second.id)).status == PortJobStatus.COMPLETED
        probe.release.set()
        await wait_for_terminal(service, active.id)
    finally:
        probe.release.set()
        await service.shutdown()
