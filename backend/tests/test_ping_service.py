from __future__ import annotations

import asyncio
import socket
from collections import defaultdict

import pytest

from better_network_tools.config import Settings, load_settings
from better_network_tools.models import (
    TERMINAL_PING_JOB_STATUSES,
    PingJobRequest,
    PingJobStatus,
)
from better_network_tools.ping_service import PingJobCapacityError, PingJobService
from better_network_tools.ping_validation import PingValidationError
from better_network_tools.pinger import PingProbeResult, ResolvedPingTarget


class NoReverseResolver:
    async def resolve(self, address: str, address_family: str) -> str:
        raise OSError("mock PTR record not found")


NO_REVERSE = NoReverseResolver()


async def wait_for_terminal(service: PingJobService, job_id: str):
    for _ in range(200):
        snapshot = await service.get_job(job_id)
        if snapshot.status in TERMINAL_PING_JOB_STATUSES:
            return snapshot
        await asyncio.sleep(0.01)
    raise AssertionError("ping job did not reach a terminal state")


async def wait_for_reverse_dns(service: PingJobService, job_id: str):
    for _ in range(200):
        snapshot = await service.get_job(job_id)
        if all(
            target.reverse_dns_status != "pending"
            for target in snapshot.targets
        ):
            return snapshot
        await asyncio.sleep(0.01)
    raise AssertionError("reverse DNS did not settle")


@pytest.mark.asyncio
async def test_reverse_dns_runs_only_for_literal_ips_without_delaying_probes() -> None:
    class ForwardResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            assert hostname == "router.example"
            return ResolvedPingTarget("203.0.113.9", "IPv4")

    class ControlledReverseResolver:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str]] = []
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def resolve(self, address: str, address_family: str) -> str:
            self.calls.append((address, address_family))
            self.started.set()
            await self.release.wait()
            return "router-01.example"

    class ImmediateProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            return PingProbeResult(received=True, latency_ms=1.0)

    reverse_resolver = ControlledReverseResolver()
    probe = ImmediateProbe()
    service = PingJobService(
        Settings(),
        probe=probe,
        resolver=ForwardResolver(),
        reverse_resolver=reverse_resolver,
    )
    created = await service.create_job(
        PingJobRequest(targets=["192.0.2.1", "router.example"], count=1)
    )

    await asyncio.wait_for(reverse_resolver.started.wait(), timeout=0.5)
    await asyncio.wait_for(probe.started.wait(), timeout=0.5)
    running = await service.get_job(created.id)
    by_target = {target.target: target for target in running.targets}
    assert running.status == PingJobStatus.RUNNING
    assert by_target["192.0.2.1"].status == "up"
    assert by_target["192.0.2.1"].reverse_dns_status == "pending"
    assert by_target["router.example"].reverse_dns_status == "not_requested"
    assert by_target["router.example"].reverse_hostname is None
    assert reverse_resolver.calls == [("192.0.2.1", "IPv4")]

    reverse_resolver.release.set()
    settled = await wait_for_terminal(service, created.id)
    literal = {target.target: target for target in settled.targets}["192.0.2.1"]
    assert literal.reverse_dns_status == "resolved"
    assert literal.reverse_hostname == "router-01.example"
    await service.shutdown()


@pytest.mark.asyncio
async def test_blocked_ptr_does_not_consume_forward_resolver_capacity() -> None:
    class BlockingReverseResolver:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def resolve(self, address: str, address_family: str) -> str:
            self.started.set()
            await asyncio.Event().wait()
            raise AssertionError("cancelled reverse lookup must not finish")

    class ForwardResolver:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            self.started.set()
            return ResolvedPingTarget("203.0.113.9", "IPv4")

    class BlockingProbe:
        def __init__(self) -> None:
            self.hostname_probe_started = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            if address == "203.0.113.9":
                self.hostname_probe_started.set()
            await asyncio.Event().wait()
            raise AssertionError("cancelled probe must not finish")

    reverse_resolver = BlockingReverseResolver()
    forward_resolver = ForwardResolver()
    probe = BlockingProbe()
    service = PingJobService(
        Settings(ping_resolver_concurrency=1),
        probe=probe,
        resolver=forward_resolver,
        reverse_resolver=reverse_resolver,
    )
    created = await service.create_job(
        PingJobRequest(
            targets=["192.0.2.1", "router.example"], continuous=True
        )
    )

    await asyncio.wait_for(reverse_resolver.started.wait(), timeout=0.5)
    await asyncio.wait_for(forward_resolver.started.wait(), timeout=0.5)
    await asyncio.wait_for(probe.hostname_probe_started.wait(), timeout=0.5)

    stopped = await service.cancel_job(created.id)
    assert stopped.status == PingJobStatus.CANCELLED
    assert stopped.targets[0].reverse_dns_status == "unavailable"
    await service.shutdown()


@pytest.mark.asyncio
async def test_reverse_dns_timeout_and_numeric_fallback_do_not_fail_monitoring() -> None:
    class HangingReverseResolver:
        def __init__(self) -> None:
            self.calls = 0

        async def resolve(self, address: str, address_family: str) -> str:
            self.calls += 1
            if self.calls == 1:
                await asyncio.Event().wait()
            return address

    class SuccessfulProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            return PingProbeResult(received=True, latency_ms=2.0)

    reverse_resolver = HangingReverseResolver()
    service = PingJobService(
        Settings(ping_resolve_timeout_seconds=0.05),
        probe=SuccessfulProbe(),
        reverse_resolver=reverse_resolver,
    )
    created = await service.create_job(
        PingJobRequest(targets=["192.0.2.1", "192.0.2.2"], count=1)
    )
    finished = await wait_for_terminal(service, created.id)
    assert finished.status == PingJobStatus.COMPLETED
    assert all(target.status == "up" for target in finished.targets)

    settled = await wait_for_reverse_dns(service, created.id)
    assert all(target.reverse_hostname is None for target in settled.targets)
    by_target = {target.target: target for target in settled.targets}
    assert by_target["192.0.2.1"].reverse_dns_status == "unavailable"
    assert by_target["192.0.2.2"].reverse_dns_status == "not_found"
    await service.shutdown()


@pytest.mark.asyncio
async def test_reverse_dns_distinguishes_missing_records_from_resolver_errors() -> None:
    class ErrorReverseResolver:
        async def resolve(self, address: str, address_family: str) -> str:
            if address == "192.0.2.1":
                raise socket.gaierror(socket.EAI_NONAME, "no PTR record")
            if address == "192.0.2.2":
                raise socket.gaierror(socket.EAI_AGAIN, "temporary failure")
            if address == "192.0.2.3":
                raise socket.gaierror(
                    getattr(socket, "EAI_NODATA", socket.EAI_NONAME),
                    "no PTR data",
                )
            raise OSError("resolver unavailable")

    class SuccessfulProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            return PingProbeResult(received=True)

    service = PingJobService(
        Settings(),
        probe=SuccessfulProbe(),
        reverse_resolver=ErrorReverseResolver(),
    )
    created = await service.create_job(
        PingJobRequest(
            targets=[
                "192.0.2.1",
                "192.0.2.2",
                "192.0.2.3",
                "192.0.2.4",
            ],
            count=1,
        )
    )
    finished = await wait_for_terminal(service, created.id)
    by_target = {target.target: target for target in finished.targets}

    assert by_target["192.0.2.1"].reverse_dns_status == "not_found"
    assert by_target["192.0.2.2"].reverse_dns_status == "unavailable"
    assert by_target["192.0.2.3"].reverse_dns_status == "not_found"
    assert by_target["192.0.2.4"].reverse_dns_status == "unavailable"
    assert all(target.status == "up" for target in finished.targets)
    await service.shutdown()


@pytest.mark.asyncio
async def test_reverse_dns_rejects_unsafe_or_oversized_names() -> None:
    responses = {
        "192.0.2.1": ("r" * 245) + ".example.",
        "192.0.2.2": "bad\x00name.example",
        "192.0.2.3": "bad name.example",
        "192.0.2.4": "x" * 254,
        "192.0.2.5": "192.0.2.5",
        "192.0.2.6": "bad\u202ename.example",
        "192.0.2.7": "bad\ue000name.example",
    }

    class MappingReverseResolver:
        async def resolve(self, address: str, address_family: str) -> str:
            return responses[address]

    class SuccessfulProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            return PingProbeResult(received=True)

    service = PingJobService(
        Settings(),
        probe=SuccessfulProbe(),
        reverse_resolver=MappingReverseResolver(),
    )
    created = await service.create_job(
        PingJobRequest(targets=list(responses), count=1)
    )
    finished = await wait_for_terminal(service, created.id)
    by_target = {target.target: target for target in finished.targets}

    assert by_target["192.0.2.1"].reverse_hostname == ("r" * 245) + ".example"
    assert by_target["192.0.2.1"].reverse_dns_status == "resolved"
    unsafe_addresses = (
        "192.0.2.2",
        "192.0.2.3",
        "192.0.2.4",
        "192.0.2.6",
        "192.0.2.7",
    )
    for address in unsafe_addresses:
        assert by_target[address].reverse_hostname is None
        assert by_target[address].reverse_dns_status == "unavailable"
        assert by_target[address].status == "up"
    assert by_target["192.0.2.5"].reverse_hostname is None
    assert by_target["192.0.2.5"].reverse_dns_status == "not_found"
    await service.shutdown()


@pytest.mark.asyncio
async def test_queued_cancellation_settles_pending_reverse_dns() -> None:
    class NeverReverseResolver:
        async def resolve(self, address: str, address_family: str) -> str:
            raise AssertionError("queued job must not start reverse DNS")

    class NeverProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            raise AssertionError("queued job must not start probing")

    service = PingJobService(
        Settings(),
        probe=NeverProbe(),
        reverse_resolver=NeverReverseResolver(),
    )
    created = await service.create_job(
        PingJobRequest(targets=["192.0.2.1"], continuous=True)
    )
    assert created.status == PingJobStatus.QUEUED
    assert created.targets[0].reverse_dns_status == "pending"

    cancelled = await service.cancel_job(created.id)

    assert cancelled.status == PingJobStatus.CANCELLED
    assert cancelled.targets[0].reverse_dns_status == "unavailable"
    assert cancelled.targets[0].reverse_hostname is None
    await service.shutdown()


@pytest.mark.asyncio
async def test_shutdown_cancels_a_tracked_reverse_dns_lookup() -> None:
    class BlockingReverseResolver:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def resolve(self, address: str, address_family: str) -> str:
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise

    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            await asyncio.Event().wait()
            raise AssertionError("shutdown must cancel the active probe")

    reverse_resolver = BlockingReverseResolver()
    probe = BlockingProbe()
    service = PingJobService(
        Settings(), probe=probe, reverse_resolver=reverse_resolver
    )
    created = await service.create_job(
        PingJobRequest(targets=["2001:db8::1"], continuous=True)
    )
    await asyncio.wait_for(reverse_resolver.started.wait(), timeout=0.5)
    await asyncio.wait_for(probe.started.wait(), timeout=0.5)

    await service.shutdown()

    assert reverse_resolver.cancelled.is_set()
    stopped = await service.get_job(created.id)
    assert stopped.status == PingJobStatus.CANCELLED
    assert stopped.targets[0].reverse_dns_status == "unavailable"


@pytest.mark.asyncio
async def test_job_runs_targets_together_and_calculates_live_statistics() -> None:
    class FakeResolver:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            self.calls.append(hostname)
            return ResolvedPingTarget("203.0.113.9", "IPv4")

    class CoordinatedProbe:
        def __init__(self) -> None:
            self.calls: defaultdict[str, int] = defaultdict(int)
            self.first_started: set[str] = set()
            self.all_started = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            call_index = self.calls[address]
            self.calls[address] += 1
            if call_index == 0:
                self.first_started.add(address)
                if len(self.first_started) == 3:
                    self.all_started.set()
                await asyncio.wait_for(self.all_started.wait(), timeout=0.5)

            if address == "192.0.2.1":
                return PingProbeResult(received=True, latency_ms=10.0 + call_index * 10)
            if address == "203.0.113.9":
                return PingProbeResult(received=call_index == 1)
            return PingProbeResult(received=False)

    resolver = FakeResolver()
    probe = CoordinatedProbe()
    service = PingJobService(
        Settings(),
        probe=probe,
        resolver=resolver,
        reverse_resolver=NO_REVERSE,
    )
    created = await service.create_job(
        PingJobRequest(
            targets=[
                "Router.Example",
                "router.example.",
                "192.0.2.1",
                "2001:db8::1",
            ],
            count=2,
            interval=0.2,
            timeout=0.1,
        )
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.status == PingJobStatus.COMPLETED
    assert finished.progress.total_probes == 6
    assert finished.progress.completed_probes == 6
    assert finished.progress.percent == 100.0
    assert resolver.calls == ["router.example"]
    assert probe.first_started == {"203.0.113.9", "192.0.2.1", "2001:db8::1"}

    by_target = {target.target: target for target in finished.targets}
    ipv4 = by_target["192.0.2.1"]
    assert (ipv4.sent, ipv4.received, ipv4.failed) == (2, 2, 0)
    assert (
        ipv4.consecutive_successes,
        ipv4.max_consecutive_successes,
        ipv4.consecutive_failures,
        ipv4.max_consecutive_failures,
    ) == (2, 2, 0, 0)
    assert ipv4.latency_samples == 2
    assert ipv4.success_rate == 100.0 and ipv4.loss_percent == 0.0
    assert (ipv4.last_ms, ipv4.avg_ms, ipv4.min_ms, ipv4.max_ms) == (
        20.0,
        15.0,
        10.0,
        20.0,
    )

    hostname = by_target["Router.Example"]
    assert hostname.resolved_address == "203.0.113.9"
    assert hostname.address_family == "IPv4"
    assert hostname.status == "up"
    assert hostname.success_rate == 50.0
    assert hostname.last_ms is None and hostname.avg_ms is None
    assert hostname.received == 1 and hostname.latency_samples == 0
    assert (
        hostname.consecutive_successes,
        hostname.max_consecutive_successes,
        hostname.consecutive_failures,
        hostname.max_consecutive_failures,
    ) == (1, 1, 0, 1)
    ipv6 = by_target["2001:db8::1"]
    assert (
        ipv6.consecutive_successes,
        ipv6.max_consecutive_successes,
        ipv6.consecutive_failures,
        ipv6.max_consecutive_failures,
    ) == (0, 0, 2, 2)
    assert all(target.last_checked is not None for target in finished.targets)
    await service.shutdown()


@pytest.mark.asyncio
async def test_job_cancellation_interrupts_blocked_mock_probes() -> None:
    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            await self.never.wait()
            return PingProbeResult(received=True)

    probe = BlockingProbe()
    service = PingJobService(
        Settings(), probe=probe, reverse_resolver=NO_REVERSE
    )
    created = await service.create_job(
        PingJobRequest(targets=["192.0.2.1"], count=10)
    )
    await asyncio.wait_for(probe.started.wait(), timeout=0.5)

    cancelled = await service.cancel_job(created.id)

    assert cancelled.status == PingJobStatus.CANCELLED
    assert cancelled.cancel_requested is True
    assert cancelled.finished_at is not None
    assert cancelled.progress.completed_probes == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_resolution_has_hard_timeout_and_marks_all_samples_failed() -> None:
    class HangingResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    class NeverProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            raise AssertionError("probe must not run when resolution fails")

    service = PingJobService(
        Settings(ping_resolve_timeout_seconds=0.1),
        probe=NeverProbe(),
        resolver=HangingResolver(),
        reverse_resolver=NO_REVERSE,
    )
    created = await service.create_job(
        PingJobRequest(targets=["unresolved.example"], count=3)
    )
    finished = await asyncio.wait_for(
        wait_for_terminal(service, created.id), timeout=0.5
    )

    target = finished.targets[0]
    assert finished.status == PingJobStatus.COMPLETED
    assert finished.progress.completed_probes == 3
    assert target.status == "error"
    assert (target.sent, target.received, target.failed) == (3, 0, 3)
    assert target.loss_percent == 100.0
    assert target.error == "resolution timed out for unresolved.example"
    # Resolution never produced an address, so the historical finite-job
    # accounting above must not fabricate a probe streak.
    assert (
        target.consecutive_successes,
        target.max_consecutive_successes,
        target.consecutive_failures,
        target.max_consecutive_failures,
    ) == (0, 0, 0, 0)
    assert target.reply_time_history_ms == []
    await service.shutdown()


@pytest.mark.asyncio
async def test_probe_streaks_include_null_rtt_and_probe_errors() -> None:
    results = iter(
        [
            PingProbeResult(received=True),
            PingProbeResult(received=True, latency_ms=2.5),
            PingProbeResult(received=False),
            PingProbeResult(received=False, error="mock probe error"),
            PingProbeResult(received=True),
        ]
    )

    class SequencedProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            return next(results)

    service = PingJobService(
        Settings(), probe=SequencedProbe(), reverse_resolver=NO_REVERSE
    )
    created = await service.create_job(
        PingJobRequest(
            targets=["192.0.2.1"], count=5, interval=0.2, timeout=0.1
        )
    )
    finished = await wait_for_terminal(service, created.id)

    target = finished.targets[0]
    assert (target.sent, target.received, target.failed) == (5, 3, 2)
    assert target.latency_samples == 1
    assert (
        target.consecutive_successes,
        target.max_consecutive_successes,
        target.consecutive_failures,
        target.max_consecutive_failures,
    ) == (1, 2, 0, 2)
    assert target.reply_time_history_ms == [None, 2.5, None, None, None]

    # Response snapshots must not share their mutable history list with either
    # service state or later snapshots.
    target.reply_time_history_ms.append(999.0)
    fresh = await service.get_job(created.id)
    assert fresh.targets[0].reply_time_history_ms == [
        None,
        2.5,
        None,
        None,
        None,
    ]
    await service.shutdown()


@pytest.mark.asyncio
async def test_reply_time_history_evicts_oldest_samples_after_sixty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_sleep = asyncio.sleep

    async def fast_sleep(delay: float) -> None:
        del delay
        await original_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)

    class IncreasingProbe:
        def __init__(self) -> None:
            self.calls = 0

        async def probe(self, address: str, address_family: str, timeout: float):
            self.calls += 1
            return PingProbeResult(received=True, latency_ms=float(self.calls))

    service = PingJobService(
        Settings(), probe=IncreasingProbe(), reverse_resolver=NO_REVERSE
    )
    created = await service.create_job(
        PingJobRequest(
            targets=["192.0.2.1"], count=65, interval=0.2, timeout=0.1
        )
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.targets[0].reply_time_history_ms == [
        float(value) for value in range(6, 66)
    ]
    target_state = service._jobs[created.id].targets[0]
    assert target_state.reply_time_history_ms.maxlen == 60
    assert len(target_state.reply_time_history_ms) == 60
    await service.shutdown()


@pytest.mark.asyncio
async def test_configured_unique_target_and_sample_limits_are_enforced() -> None:
    service = PingJobService(
        Settings(ping_target_limit=1, ping_sample_limit=2),
        reverse_resolver=NO_REVERSE,
    )

    with pytest.raises(PingValidationError) as target_error:
        await service.create_job(
            PingJobRequest(targets=["192.0.2.1", "192.0.2.2"])
        )
    assert target_error.value.code == "ping_target_limit_exceeded"

    with pytest.raises(PingValidationError) as sample_error:
        await service.create_job(
            PingJobRequest(targets=["192.0.2.1"], count=3)
        )
    assert sample_error.value.code == "ping_sample_limit_exceeded"
    await service.shutdown()


@pytest.mark.asyncio
async def test_continuous_job_runs_until_cancelled_with_constant_memory_stats() -> None:
    class ThreeRepliesThenBlock:
        def __init__(self) -> None:
            self.calls = 0
            self.fourth_started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.calls += 1
            if self.calls <= 3:
                return PingProbeResult(
                    received=True, latency_ms=float(self.calls)
                )
            self.fourth_started.set()
            await self.never.wait()
            raise AssertionError("cancelled probe must not finish")

    probe = ThreeRepliesThenBlock()
    service = PingJobService(
        Settings(), probe=probe, reverse_resolver=NO_REVERSE
    )
    created = await service.create_job(
        PingJobRequest(
            targets=["192.0.2.1"],
            count=100,
            interval=0.2,
            timeout=0.1,
            continuous=True,
        )
    )

    await asyncio.wait_for(probe.fourth_started.wait(), timeout=1.0)
    running = await service.get_job(created.id)
    assert running.status == PingJobStatus.RUNNING
    assert running.options.continuous is True
    assert running.progress.total_probes is None
    assert running.progress.completed_probes == 3
    assert running.progress.percent is None
    target = running.targets[0]
    assert (target.sent, target.received, target.failed) == (3, 3, 0)
    assert (
        target.consecutive_successes,
        target.max_consecutive_successes,
        target.consecutive_failures,
        target.max_consecutive_failures,
    ) == (3, 3, 0, 0)
    assert target.latency_samples == 3
    assert (target.avg_ms, target.min_ms, target.max_ms) == (2.0, 1.0, 3.0)

    # Latency aggregation must remain constant-size however long the job runs.
    target_state = service._jobs[created.id].targets[0]
    assert target_state.latency_count == 3
    assert target_state.latency_total_ms == 6.0
    assert not hasattr(target_state, "latencies")
    assert not hasattr(target_state, "success_history")
    assert not hasattr(target_state, "failure_history")

    stopped = await service.cancel_job(created.id)
    assert stopped.status == PingJobStatus.CANCELLED
    assert stopped.progress.completed_probes == 3
    assert stopped.finished_at is not None
    await service.shutdown()


@pytest.mark.asyncio
async def test_continuous_resolution_failure_terminates_without_fake_probes() -> None:
    class FailingResolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            raise OSError("host could not be resolved")

    class NeverProbe:
        async def probe(self, address: str, address_family: str, timeout: float):
            raise AssertionError("probe must not run when resolution fails")

    service = PingJobService(
        Settings(),
        probe=NeverProbe(),
        resolver=FailingResolver(),
        reverse_resolver=NO_REVERSE,
    )
    created = await service.create_job(
        PingJobRequest(targets=["unresolved.example"], continuous=True)
    )
    finished = await asyncio.wait_for(
        wait_for_terminal(service, created.id), timeout=0.5
    )

    assert finished.status == PingJobStatus.COMPLETED
    assert finished.progress.total_probes is None
    assert finished.progress.completed_probes == 0
    assert finished.progress.percent is None
    target = finished.targets[0]
    assert target.status == "error"
    assert (target.sent, target.received, target.failed) == (0, 0, 0)
    assert (
        target.consecutive_successes,
        target.max_consecutive_successes,
        target.consecutive_failures,
        target.max_consecutive_failures,
    ) == (0, 0, 0, 0)
    assert target.reply_time_history_ms == []
    assert target.error == "host could not be resolved"
    await service.shutdown()


@pytest.mark.asyncio
async def test_continuous_jobs_ignore_finite_sample_setting() -> None:
    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            await self.never.wait()
            raise AssertionError("cancelled probe must not finish")

    probe = BlockingProbe()
    service = PingJobService(
        Settings(ping_sample_limit=1),
        probe=probe,
        reverse_resolver=NO_REVERSE,
    )
    created = await service.create_job(
        PingJobRequest(
            targets=["192.0.2.1"], count=100, continuous=True
        )
    )
    await asyncio.wait_for(probe.started.wait(), timeout=0.5)
    stopped = await service.cancel_job(created.id)
    assert stopped.status == PingJobStatus.CANCELLED
    await service.shutdown()


@pytest.mark.asyncio
async def test_active_job_cap_is_atomic_under_concurrent_creation() -> None:
    class BlockingProbe:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.never = asyncio.Event()

        async def probe(self, address: str, address_family: str, timeout: float):
            self.started.set()
            await self.never.wait()
            raise AssertionError("cancelled probe must not finish")

    service = PingJobService(
        Settings(ping_active_job_limit=3),
        probe=BlockingProbe(),
        reverse_resolver=NO_REVERSE,
    )
    attempts = await asyncio.gather(
        *(
            service.create_job(
                PingJobRequest(
                    targets=[f"192.0.2.{index}"], continuous=True
                )
            )
            for index in range(1, 11)
        ),
        return_exceptions=True,
    )

    created = [result for result in attempts if not isinstance(result, BaseException)]
    rejected = [result for result in attempts if isinstance(result, BaseException)]
    assert len(created) == 3
    assert len(rejected) == 7
    assert all(
        isinstance(result, PingJobCapacityError) for result in rejected
    )
    assert all(result.limit == 3 and result.active == 3 for result in rejected)

    await service.cancel_job(created[0].id)
    replacement = await service.create_job(
        PingJobRequest(targets=["198.51.100.1"], continuous=True)
    )
    assert replacement.status in {PingJobStatus.QUEUED, PingJobStatus.RUNNING}
    await service.shutdown()


def test_active_ping_job_limit_is_environment_backed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BNT_PING_ACTIVE_JOB_LIMIT", "7")
    assert load_settings().ping_active_job_limit == 7
