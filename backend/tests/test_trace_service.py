from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

import better_network_tools.trace_service as trace_service_module
from better_network_tools.config import Settings
from better_network_tools.models import (
    TraceAsnRecord,
    TraceHopResponse,
    TraceJobRequest,
    TraceJobStatus,
    TraceProbeResponse,
    TraceResponderResponse,
)
from better_network_tools.pinger import ResolvedPingTarget
from better_network_tools.trace_service import (
    TraceJobCapacityError,
    TraceJobNotFoundError,
    TraceJobService,
    build_as_path,
)
from better_network_tools.tracer import (
    NativeTracer,
    NativeTraceResult,
    TraceCommandCancelled,
    TraceCommandResult,
    TraceHopObservation,
    TraceProbeObservation,
)


def probe(
    sequence: int,
    address: str | None,
    latency: float | None,
    status: str = "reply",
    annotation: str | None = None,
) -> TraceProbeObservation:
    return TraceProbeObservation(
        sequence=sequence,
        address=address,
        latency_ms=latency,
        status=status,  # type: ignore[arg-type]
        annotation=annotation,
    )


def hop(number: int, *probes: TraceProbeObservation) -> TraceHopObservation:
    return TraceHopObservation(number=number, probes=tuple(probes))


TRACE_RESULT = NativeTraceResult(
    hops=(
        hop(
            1,
            probe(1, "192.168.1.1", 0.5),
            probe(2, "192.168.1.1", 0.7),
            probe(3, "192.168.1.1", 0.6),
        ),
        hop(
            2,
            probe(1, "1.1.1.1", 5.0),
            probe(2, "8.8.4.4", 6.0),
            probe(3, None, None, "timeout"),
        ),
        hop(
            3,
            probe(1, "8.8.8.8", 8.0),
            probe(2, "8.8.8.8", 8.5),
            probe(3, "8.8.8.8", 9.0),
        ),
    ),
    returncode=0,
)


class FakeTracer:
    def __init__(self, result: NativeTraceResult = TRACE_RESULT) -> None:
        self.result = result
        self.calls: list[tuple[object, ...]] = []

    async def trace(
        self,
        address: str,
        address_family: str,
        *,
        max_hops: int,
        timeout: float,
        probes_per_hop: int,
        total_timeout: float,
    ) -> NativeTraceResult:
        self.calls.append(
            (
                address,
                address_family,
                max_hops,
                timeout,
                probes_per_hop,
                total_timeout,
            )
        )
        await asyncio.sleep(0)
        return self.result


class FakeReverseResolver:
    async def resolve(self, address: str, address_family: str) -> str:
        if address == "8.8.4.4":
            raise OSError("no PTR")
        return {
            "192.168.1.1": "router.home.",
            "1.1.1.1": "one.one.one.one.",
            "8.8.8.8": "dns.google.",
        }[address]


class FakeAsnProvider:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    async def lookup_many(self, addresses):
        self.calls.append(list(addresses))
        return {
            "1.1.1.1": TraceAsnRecord(
                number=13335,
                name="CLOUDFLARENET",
                organization="Cloudflare, Inc.",
                prefix="1.1.1.0/24",
                country_code="US",
                registry="arin",
                source="team_cymru_whois",
            ),
            "8.8.4.4": TraceAsnRecord(
                number=15169,
                name="GOOGLE",
                organization="Google LLC",
                prefix="8.8.4.0/24",
                country_code="US",
                registry="arin",
                source="team_cymru_whois",
            ),
            "8.8.8.8": TraceAsnRecord(
                number=15169,
                name="GOOGLE",
                organization="Google LLC",
                prefix="8.8.8.0/24",
                country_code="US",
                registry="arin",
                source="team_cymru_whois",
            ),
        }


async def wait_for_terminal(
    service: TraceJobService, job_id: str
):
    for _ in range(100):
        response = await service.get_job(job_id)
        if response.status in {
            TraceJobStatus.COMPLETED,
            TraceJobStatus.CANCELLED,
            TraceJobStatus.FAILED,
        }:
            return response
        await asyncio.sleep(0)
    raise AssertionError("trace job did not reach a terminal state")


@pytest.mark.asyncio
async def test_trace_service_preserves_ecmp_probes_and_enriches_public_hops_only() -> None:
    tracer = FakeTracer()
    asn_provider = FakeAsnProvider()
    service = TraceJobService(
        Settings(trace_total_timeout_seconds=60.0),
        tracer=tracer,
        reverse_resolver=FakeReverseResolver(),
        asn_provider=asn_provider,
    )

    created = await service.create_job(
        TraceJobRequest(
            target="8.8.8.8",
            max_hops=12,
            timeout=0.5,
            lookup_asn=True,
        )
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.status == TraceJobStatus.COMPLETED
    assert finished.phase == "complete"
    assert finished.reached_destination is True
    assert finished.progress.last_hop == 3
    assert tracer.calls == [("8.8.8.8", "IPv4", 12, 0.5, 3, 23.0)]
    assert asn_provider.calls == [["1.1.1.1", "8.8.4.4", "8.8.8.8"]]

    ecmp = finished.hops[1]
    assert [entry.address for entry in ecmp.probes] == [
        "1.1.1.1",
        "8.8.4.4",
        None,
    ]
    assert [entry.latency_ms for entry in ecmp.probes] == [5.0, 6.0, None]
    assert [entry.address for entry in ecmp.responders] == ["1.1.1.1", "8.8.4.4"]
    assert ecmp.responders[0].hostname == "one.one.one.one"
    assert ecmp.responders[1].hostname is None
    assert finished.hops[0].responders[0].asn is None

    assert [(segment.first_hop, segment.asn, segment.ambiguous) for segment in finished.as_path] == [
        (1, None, False),
        (2, 13335, True),
        (2, 15169, True),
        (3, 15169, False),
    ]
    assert finished.as_path[-1].boundary_confidence == "gap"
    await service.shutdown()


@pytest.mark.asyncio
async def test_hostname_resolution_is_once_and_numeric_output_is_revalidated() -> None:
    class Resolver:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            self.calls.append(hostname)
            return ResolvedPingTarget("8.8.8.8", "IPv4")

    resolver = Resolver()
    tracer = FakeTracer()
    service = TraceJobService(
        Settings(),
        tracer=tracer,
        resolver=resolver,
        reverse_resolver=FakeReverseResolver(),
    )
    created = await service.create_job(
        TraceJobRequest(target="DNS.Google", resolve_dns=False)
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.status == TraceJobStatus.COMPLETED
    assert resolver.calls == ["dns.google"]
    assert tracer.calls[0][0] == "8.8.8.8"
    await service.shutdown()


@pytest.mark.asyncio
async def test_invalid_resolver_result_fails_safely_without_starting_tracer() -> None:
    class Resolver:
        async def resolve(self, hostname: str) -> ResolvedPingTarget:
            return ResolvedPingTarget("-m\n\x00", "IPv4")

    tracer = FakeTracer()
    service = TraceJobService(Settings(), tracer=tracer, resolver=Resolver())
    created = await service.create_job(TraceJobRequest(target="router.example"))
    failed = await wait_for_terminal(service, created.id)

    assert failed.status == TraceJobStatus.FAILED
    assert tracer.calls == []
    assert "\n" not in (failed.error or "") and "\x00" not in (failed.error or "")
    await service.shutdown()


@pytest.mark.asyncio
async def test_asn_failure_is_a_sanitized_warning_not_a_failed_trace() -> None:
    class BrokenAsnProvider:
        async def lookup_many(self, addresses):
            raise OSError("provider\nfailed\x00secret")

    service = TraceJobService(
        Settings(),
        tracer=FakeTracer(),
        reverse_resolver=FakeReverseResolver(),
        asn_provider=BrokenAsnProvider(),
    )
    created = await service.create_job(
        TraceJobRequest(target="8.8.8.8", lookup_asn=True)
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.status == TraceJobStatus.COMPLETED
    assert finished.warnings[0].code == "asn_lookup_failed"
    assert "\n" not in finished.warnings[0].message
    assert "\x00" not in finished.warnings[0].message
    await service.shutdown()


@pytest.mark.asyncio
async def test_cancel_and_shutdown_stop_blocked_traces() -> None:
    class BlockingTracer:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def trace(self, *args, **kwargs):
            self.started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled.set()
                raise

    tracer = BlockingTracer()
    service = TraceJobService(Settings(), tracer=tracer)
    first = await service.create_job(TraceJobRequest(target="8.8.8.8"))
    await asyncio.wait_for(tracer.started.wait(), timeout=0.5)
    cancelled = await service.cancel_job(first.id)
    assert cancelled.status == TraceJobStatus.CANCELLED
    assert cancelled.cancel_requested is True
    assert tracer.cancelled.is_set()

    tracer2 = BlockingTracer()
    service2 = TraceJobService(Settings(), tracer=tracer2)
    second = await service2.create_job(TraceJobRequest(target="8.8.8.8"))
    await asyncio.wait_for(tracer2.started.wait(), timeout=0.5)
    await service2.shutdown()
    stopped = await service2.get_job(second.id)
    assert stopped.status == TraceJobStatus.CANCELLED
    assert tracer2.cancelled.is_set()
    await service.shutdown()


@pytest.mark.asyncio
async def test_cancelling_native_trace_retains_already_emitted_hops() -> None:
    started = asyncio.Event()

    async def runner(arguments, timeout):
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            raise TraceCommandCancelled(
                TraceCommandResult(
                    returncode=130,
                    stdout="1  192.168.1.1  1 ms  2 ms  3 ms\n",
                )
            ) from None

    service = TraceJobService(
        Settings(),
        tracer=NativeTracer(platform_name="darwin", command_runner=runner),
    )
    created = await service.create_job(TraceJobRequest(target="8.8.8.8"))
    await asyncio.wait_for(started.wait(), timeout=0.5)

    cancelled = await service.cancel_job(created.id)

    assert cancelled.status == TraceJobStatus.CANCELLED
    assert cancelled.progress.last_hop == 1
    assert cancelled.hops[0].responders[0].address == "192.168.1.1"
    await service.shutdown()


@pytest.mark.asyncio
async def test_active_job_capacity_is_atomic_and_released_after_cancel() -> None:
    class BlockingTracer:
        def __init__(self) -> None:
            self.started = asyncio.Event()

        async def trace(self, *args, **kwargs):
            self.started.set()
            await asyncio.Event().wait()

    tracer = BlockingTracer()
    service = TraceJobService(
        Settings(trace_active_job_limit=1), tracer=tracer
    )
    first = await service.create_job(TraceJobRequest(target="8.8.8.8"))
    await asyncio.wait_for(tracer.started.wait(), timeout=0.5)

    with pytest.raises(TraceJobCapacityError) as raised:
        await service.create_job(TraceJobRequest(target="1.1.1.1"))
    assert raised.value.limit == 1 and raised.value.active == 1

    await service.cancel_job(first.id)
    replacement = await service.create_job(TraceJobRequest(target="1.1.1.1"))
    await service.cancel_job(replacement.id)
    await service.shutdown()


@pytest.mark.asyncio
async def test_finished_jobs_expire_after_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    clock = [now]
    monkeypatch.setattr(trace_service_module, "_utc_now", lambda: clock[0])
    service = TraceJobService(
        Settings(job_retention_seconds=60), tracer=FakeTracer()
    )
    created = await service.create_job(
        TraceJobRequest(target="8.8.8.8", resolve_dns=False)
    )
    finished = await wait_for_terminal(service, created.id)
    assert finished.status == TraceJobStatus.COMPLETED

    clock[0] = now + timedelta(seconds=61)
    with pytest.raises(TraceJobNotFoundError):
        await service.get_job(created.id)
    await service.shutdown()


def test_as_path_marks_partial_public_ecmp_as_ambiguous() -> None:
    asn = TraceAsnRecord(
        number=15169,
        name="GOOGLE",
        organization="Google LLC",
        prefix="8.8.8.0/24",
        country_code="US",
        registry="arin",
        source="team_cymru_whois",
    )
    mixed = TraceHopResponse(
        number=1,
        probes=[
            TraceProbeResponse(
                sequence=1,
                address="8.8.8.8",
                latency_ms=1.0,
                status="reply",
            ),
            TraceProbeResponse(
                sequence=2,
                address="9.9.9.9",
                latency_ms=1.1,
                status="reply",
            ),
            TraceProbeResponse(sequence=3, status="timeout"),
        ],
        responders=[
            TraceResponderResponse(
                address="8.8.8.8", scope="public", asn=asn
            ),
            TraceResponderResponse(
                address="9.9.9.9", scope="public", asn=None
            ),
        ],
        reached_destination=False,
    )
    mapped = TraceHopResponse(
        number=2,
        probes=[
            TraceProbeResponse(
                sequence=1,
                address="8.8.8.8",
                latency_ms=2.0,
                status="reply",
            )
        ],
        responders=[
            TraceResponderResponse(
                address="8.8.8.8", scope="public", asn=asn
            )
        ],
        reached_destination=True,
    )

    path = build_as_path([mixed, mapped])

    assert len(path) == 2
    assert path[0].ambiguous is True
    assert path[0].boundary_confidence == "ecmp"
    assert path[1].ambiguous is False
    assert path[1].boundary_confidence == "gap"


def test_as_path_marks_skipped_numeric_hops_as_a_gap() -> None:
    first_asn = TraceAsnRecord(
        number=13335,
        name="CLOUDFLARENET",
        prefix="1.1.1.0/24",
        source="team_cymru_whois",
    )
    second_asn = TraceAsnRecord(
        number=15169,
        name="GOOGLE",
        prefix="8.8.8.0/24",
        source="team_cymru_whois",
    )

    def mapped_hop(number: int, address: str, asn: TraceAsnRecord):
        return TraceHopResponse(
            number=number,
            probes=[
                TraceProbeResponse(
                    sequence=1,
                    address=address,
                    latency_ms=1.0,
                    status="reply",
                )
            ],
            responders=[
                TraceResponderResponse(address=address, scope="public", asn=asn)
            ],
            reached_destination=False,
        )

    path = build_as_path(
        [mapped_hop(1, "1.1.1.1", first_asn), mapped_hop(3, "8.8.8.8", second_asn)]
    )

    assert path[0].boundary_confidence == "exact"
    assert path[1].first_hop == 3
    assert path[1].boundary_confidence == "gap"
