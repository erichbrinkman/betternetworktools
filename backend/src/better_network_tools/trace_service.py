"""In-memory lifecycle, enrichment, and safety limits for NetTrace jobs."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import unicodedata
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .asn import AsnLookupProvider, TeamCymruAsnProvider
from .config import Settings
from .models import (
    TERMINAL_TRACE_JOB_STATUSES,
    TraceAddressFamily,
    TraceAddressScope,
    TraceAsPathSegment,
    TraceAsnRecord,
    TraceHopResponse,
    TraceJobOptions,
    TraceJobRequest,
    TraceJobResponse,
    TraceJobStatus,
    TracePhase,
    TraceProbeResponse,
    TraceProgress,
    TraceResponderResponse,
    TraceWarning,
)
from .pinger import (
    PingResolver,
    ReverseDNSResolver,
    ResolvedPingTarget,
    SystemPingResolver,
    SystemReverseDNSResolver,
)
from .trace_validation import (
    TraceValidationError,
    ValidatedTraceTarget,
    validate_trace_target,
    validate_traceable_address,
)
from .tracer import (
    NativeTraceCancelled,
    NativeTraceResult,
    NativeTracer,
    TraceHopObservation,
    TraceRunner,
)


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_IPV4_PRIVATE = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_IPV6_PRIVATE = ipaddress.ip_network("fc00::/7")
_SCOPE_NAMES: dict[TraceAddressScope, str] = {
    "public": "Public network",
    "private": "Private network",
    "loopback": "Loopback",
    "link_local": "Link-local network",
    "reserved": "Reserved network",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_error(exc: BaseException | str) -> str:
    cleaned = _CONTROL_CHARACTERS.sub(" ", str(exc)).strip()
    return (cleaned or type(exc).__name__)[:240]


def _safe_hostname(value: object, address: str) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value[:-1] if value.endswith(".") else value
    if not cleaned or len(cleaned) > 253:
        return None
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in cleaned
    ):
        return None
    if cleaned.casefold() == address.casefold():
        return None
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return cleaned
    return None


def classify_trace_scope(address: str) -> TraceAddressScope:
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link_local"
    if parsed.version == 4 and any(parsed in network for network in _IPV4_PRIVATE):
        return "private"
    if parsed.version == 6 and parsed in _IPV6_PRIVATE:
        return "private"
    if parsed.is_global:
        return "public"
    return "reserved"


class TraceJobNotFoundError(KeyError):
    pass


class TraceJobCapacityError(RuntimeError):
    def __init__(self, *, limit: int, active: int) -> None:
        self.limit = limit
        self.active = active
        super().__init__(f"the active trace-job limit of {limit} has been reached")

    def as_detail(self) -> dict[str, str | int]:
        return {
            "code": "trace_job_capacity_exceeded",
            "message": str(self),
            "limit": self.limit,
            "active": self.active,
        }


@dataclass(slots=True)
class _TraceJob:
    id: str
    target: ValidatedTraceTarget
    options: TraceJobOptions
    created_at: datetime = field(default_factory=_utc_now)
    status: TraceJobStatus = TraceJobStatus.QUEUED
    phase: TracePhase = "resolving"
    resolved_address: str | None = None
    address_family: TraceAddressFamily | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    hops: list[TraceHopResponse] = field(default_factory=list)
    as_path: list[TraceAsPathSegment] = field(default_factory=list)
    reached_destination: bool = False
    error: str | None = None
    warnings: list[TraceWarning] = field(default_factory=list)
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _SegmentState:
    key: tuple[str, str]
    asn: int | None
    network_name: str
    first_hop: int
    last_hop: int
    prefixes: list[str]
    ambiguous: bool
    boundary_confidence: str


class TraceJobService:
    """Own bounded traceroute jobs and optional hop enrichment."""

    def __init__(
        self,
        settings: Settings,
        *,
        tracer: TraceRunner | None = None,
        resolver: PingResolver | None = None,
        reverse_resolver: ReverseDNSResolver | None = None,
        asn_provider: AsnLookupProvider | None = None,
    ) -> None:
        self.settings = settings
        self.tracer = tracer or NativeTracer()
        self.resolver = resolver or SystemPingResolver()
        self.reverse_resolver = reverse_resolver or SystemReverseDNSResolver()
        self.asn_provider = asn_provider or TeamCymruAsnProvider(
            timeout=settings.trace_asn_timeout_seconds
        )
        self._jobs: dict[str, _TraceJob] = {}
        self._lock = asyncio.Lock()
        self._resolver_semaphore = asyncio.Semaphore(
            settings.trace_resolver_concurrency
        )
        self._reverse_resolver_semaphore = asyncio.Semaphore(
            settings.trace_resolver_concurrency
        )
        self._asn_semaphore = asyncio.Semaphore(settings.trace_active_job_limit)

    async def create_job(self, request: TraceJobRequest) -> TraceJobResponse:
        target = validate_trace_target(request.target)
        if request.max_hops > self.settings.trace_hop_limit:
            raise TraceValidationError(
                "trace_hop_limit_exceeded",
                f"trace jobs may request at most {self.settings.trace_hop_limit} hops",
                limit=self.settings.trace_hop_limit,
                actual=request.max_hops,
            )
        if request.timeout > self.settings.trace_probe_timeout_limit_seconds:
            raise TraceValidationError(
                "trace_timeout_limit_exceeded",
                "the per-probe trace timeout exceeds the configured limit",
                limit=self.settings.trace_probe_timeout_limit_seconds,
                actual=request.timeout,
            )

        job = _TraceJob(
            id=str(uuid.uuid4()),
            target=target,
            options=TraceJobOptions(
                max_hops=request.max_hops,
                timeout=request.timeout,
                probes_per_hop=3,
                resolve_dns=request.resolve_dns,
                lookup_asn=request.lookup_asn,
            ),
        )
        async with self._lock:
            self._purge_expired_locked()
            active = sum(
                existing.status not in TERMINAL_TRACE_JOB_STATUSES
                for existing in self._jobs.values()
            )
            if active >= self.settings.trace_active_job_limit:
                raise TraceJobCapacityError(
                    limit=self.settings.trace_active_job_limit, active=active
                )
            self._jobs[job.id] = job
            job.task = asyncio.create_task(
                self._run_job(job), name=f"nettrace-{job.id}"
            )
            return self._snapshot_locked(job)

    async def get_job(self, job_id: str) -> TraceJobResponse:
        async with self._lock:
            self._purge_expired_locked()
            job = self._jobs.get(job_id)
            if job is None:
                raise TraceJobNotFoundError(job_id)
            return self._snapshot_locked(job)

    async def cancel_job(self, job_id: str) -> TraceJobResponse:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise TraceJobNotFoundError(job_id)
            terminal = job.status in TERMINAL_TRACE_JOB_STATUSES
            if not terminal:
                job.cancel_requested = True
                if job.status == TraceJobStatus.QUEUED:
                    job.status = TraceJobStatus.CANCELLED
                    job.phase = "complete"
                    job.finished_at = _utc_now()
            task = None if terminal else job.task

        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        async with self._lock:
            if job.status not in TERMINAL_TRACE_JOB_STATUSES:
                job.status = TraceJobStatus.CANCELLED
                job.phase = "complete"
                job.finished_at = _utc_now()
            return self._snapshot_locked(job)

    async def shutdown(self) -> None:
        async with self._lock:
            job_ids = list(self._jobs)
        for job_id in job_ids:
            await self.cancel_job(job_id)

    async def _run_job(self, job: _TraceJob) -> None:
        async with self._lock:
            if job.status == TraceJobStatus.CANCELLED:
                return
            job.status = TraceJobStatus.RUNNING
            job.phase = "resolving"
            job.started_at = _utc_now()

        try:
            resolved = await self._resolve_target(job.target)
            async with self._lock:
                job.resolved_address = resolved.address
                job.address_family = resolved.address_family
                job.phase = "tracing"

            calculated_timeout = (
                job.options.max_hops
                * job.options.probes_per_hop
                * job.options.timeout
                + 5.0
            )
            result = await self.tracer.trace(
                resolved.address,
                resolved.address_family,
                max_hops=job.options.max_hops,
                timeout=job.options.timeout,
                probes_per_hop=job.options.probes_per_hop,
                total_timeout=min(
                    calculated_timeout, self.settings.trace_total_timeout_seconds
                ),
            )
            warnings = self._native_warnings(result)
            if result.returncode == 127:
                raise OSError(result.error_detail or "native traceroute command is unavailable")
            if result.returncode not in {0, 124} and not result.hops:
                raise OSError(
                    result.error_detail
                    or f"native traceroute exited with status {result.returncode}"
                )

            initial_hops = self._build_hops(
                result.hops,
                destination=resolved.address,
                hostnames={},
                asn_records={},
            )
            async with self._lock:
                job.hops = initial_hops
                job.reached_destination = any(
                    hop.reached_destination for hop in initial_hops
                )
                job.warnings = warnings
                job.phase = "enriching"

            hostnames, asn_records, enrichment_warnings = await self._enrich(
                initial_hops, job.options
            )
            enriched_hops = self._build_hops(
                result.hops,
                destination=resolved.address,
                hostnames=hostnames,
                asn_records=asn_records,
            )
            as_path = build_as_path(enriched_hops)
            async with self._lock:
                job.hops = enriched_hops
                job.as_path = as_path
                job.reached_destination = any(
                    hop.reached_destination for hop in enriched_hops
                )
                job.warnings = [*warnings, *enrichment_warnings][:32]
                job.status = (
                    TraceJobStatus.CANCELLED
                    if job.cancel_requested
                    else TraceJobStatus.COMPLETED
                )
                job.phase = "complete"
                job.finished_at = _utc_now()
        except NativeTraceCancelled as exc:
            cancelled_hops = (
                self._build_hops(
                    exc.result.hops,
                    destination=job.resolved_address,
                    hostnames={},
                    asn_records={},
                )
                if job.resolved_address is not None
                else []
            )
            async with self._lock:
                job.hops = cancelled_hops
                job.reached_destination = any(
                    hop.reached_destination for hop in cancelled_hops
                )
                if exc.result.output_truncated:
                    job.warnings = [
                        TraceWarning(
                            code="trace_output_truncated",
                            message="Native traceroute output exceeded the safety limit.",
                        )
                    ]
                job.cancel_requested = True
                job.status = TraceJobStatus.CANCELLED
                job.phase = "complete"
                job.finished_at = _utc_now()
        except asyncio.CancelledError:
            async with self._lock:
                job.cancel_requested = True
                job.status = TraceJobStatus.CANCELLED
                job.phase = "complete"
                job.finished_at = _utc_now()
        except Exception as exc:
            async with self._lock:
                job.status = TraceJobStatus.FAILED
                job.phase = "complete"
                job.error = f"{type(exc).__name__}: {_safe_error(exc)}"
                job.finished_at = _utc_now()

    def _native_warnings(self, result: NativeTraceResult) -> list[TraceWarning]:
        warnings: list[TraceWarning] = []
        if result.timed_out:
            warnings.append(
                TraceWarning(
                    code="trace_timed_out",
                    message="The trace hit its total deadline; partial hops are shown.",
                )
            )
        elif result.returncode != 0 and result.returncode != 127:
            warnings.append(
                TraceWarning(
                    code="native_trace_nonzero",
                    message=(
                        f"The native traceroute exited with status {result.returncode}; "
                        "partial hops are shown."
                    ),
                )
            )
        if result.output_truncated:
            warnings.append(
                TraceWarning(
                    code="trace_output_truncated",
                    message="Native traceroute output exceeded the safety limit.",
                )
            )
        if not result.hops and result.returncode == 0:
            warnings.append(
                TraceWarning(
                    code="no_trace_hops",
                    message="The native traceroute returned no parseable hop rows.",
                )
            )
        return warnings

    async def _resolve_target(
        self, target: ValidatedTraceTarget
    ) -> ResolvedPingTarget:
        if target.address is not None:
            address = validate_traceable_address(target.address, target=target.display)
            return ResolvedPingTarget(
                address=address.compressed,
                address_family="IPv4" if address.version == 4 else "IPv6",
            )
        try:
            async with self._resolver_semaphore:
                async with asyncio.timeout(
                    self.settings.trace_resolve_timeout_seconds
                ):
                    resolved = await self.resolver.resolve(target.lookup)
        except TimeoutError as exc:
            raise OSError(f"resolution timed out for {target.lookup}") from exc
        address = validate_traceable_address(
            resolved.address, target=target.display
        )
        return ResolvedPingTarget(
            address=address.compressed,
            address_family="IPv4" if address.version == 4 else "IPv6",
        )

    async def _enrich(
        self, hops: list[TraceHopResponse], options: TraceJobOptions
    ) -> tuple[dict[str, str], dict[str, TraceAsnRecord], list[TraceWarning]]:
        addresses: list[str] = []
        seen: set[str] = set()
        for hop in hops:
            for responder in hop.responders:
                if responder.address not in seen:
                    seen.add(responder.address)
                    addresses.append(responder.address)

        hostnames: dict[str, str] = {}
        if options.resolve_dns and addresses:
            resolved_names = await asyncio.gather(
                *(self._reverse_lookup(address) for address in addresses)
            )
            hostnames = {
                address: hostname
                for address, hostname in zip(addresses, resolved_names, strict=True)
                if hostname is not None
            }

        asn_records: dict[str, TraceAsnRecord] = {}
        warnings: list[TraceWarning] = []
        if options.lookup_asn:
            public = [
                address
                for address in addresses
                if classify_trace_scope(address) == "public"
            ]
            if public:
                try:
                    async with self._asn_semaphore:
                        asn_records = await self.asn_provider.lookup_many(public)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    warnings.append(
                        TraceWarning(
                            code="asn_lookup_failed",
                            message=(
                                "ASN enrichment was unavailable: " + _safe_error(exc)
                            )[:240],
                        )
                    )
                    asn_records = {}
        return hostnames, asn_records, warnings

    async def _reverse_lookup(self, address: str) -> str | None:
        parsed = ipaddress.ip_address(address)
        family: TraceAddressFamily = "IPv4" if parsed.version == 4 else "IPv6"
        try:
            async with self._reverse_resolver_semaphore:
                async with asyncio.timeout(
                    self.settings.trace_resolve_timeout_seconds
                ):
                    value = await self.reverse_resolver.resolve(address, family)
        except asyncio.CancelledError:
            raise
        except Exception:
            return None
        return _safe_hostname(value, address)

    def _build_hops(
        self,
        observations: tuple[TraceHopObservation, ...],
        *,
        destination: str,
        hostnames: dict[str, str],
        asn_records: dict[str, TraceAsnRecord],
    ) -> list[TraceHopResponse]:
        responses: list[TraceHopResponse] = []
        for observation in observations:
            probes: list[TraceProbeResponse] = []
            responder_addresses: list[str] = []
            for probe in observation.probes:
                address: str | None = None
                if probe.address is not None:
                    try:
                        address = ipaddress.ip_address(probe.address).compressed
                    except ValueError:
                        address = None
                probes.append(
                    TraceProbeResponse(
                        sequence=probe.sequence,
                        address=address,
                        latency_ms=(
                            round(probe.latency_ms, 3)
                            if probe.latency_ms is not None
                            else None
                        ),
                        status=probe.status,
                        annotation=(
                            _safe_error(probe.annotation)[:32]
                            if probe.annotation
                            else None
                        ),
                    )
                )
                if address is not None and address not in responder_addresses:
                    responder_addresses.append(address)

            responders = [
                TraceResponderResponse(
                    address=address,
                    hostname=hostnames.get(address),
                    scope=classify_trace_scope(address),
                    asn=asn_records.get(address),
                )
                for address in responder_addresses[:3]
            ]
            responses.append(
                TraceHopResponse(
                    number=observation.number,
                    probes=probes,
                    responders=responders,
                    reached_destination=destination in responder_addresses,
                )
            )
        return responses

    def _snapshot_locked(self, job: _TraceJob) -> TraceJobResponse:
        last_hop = max((hop.number for hop in job.hops), default=0)
        return TraceJobResponse(
            id=job.id,
            status=job.status,
            phase=job.phase,
            target=job.target.display,
            resolved_address=job.resolved_address,
            address_family=job.address_family,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            options=job.options.model_copy(deep=True),
            progress=TraceProgress(
                last_hop=last_hop, max_hops=job.options.max_hops
            ),
            hops=[hop.model_copy(deep=True) for hop in job.hops],
            as_path=[segment.model_copy(deep=True) for segment in job.as_path],
            reached_destination=job.reached_destination,
            error=job.error,
            warnings=[warning.model_copy(deep=True) for warning in job.warnings],
            cancel_requested=job.cancel_requested,
        )

    def _purge_expired_locked(self) -> None:
        cutoff = _utc_now() - timedelta(seconds=self.settings.job_retention_seconds)
        expired_ids = [
            job.id
            for job in self._jobs.values()
            if job.finished_at is not None and job.finished_at < cutoff
        ]
        for job_id in expired_ids:
            self._jobs.pop(job_id, None)


def _network_entries(
    hop: TraceHopResponse,
) -> dict[tuple[str, str], tuple[int | None, str, list[str]]]:
    entries: dict[tuple[str, str], tuple[int | None, str, list[str]]] = {}
    for responder in hop.responders:
        if responder.scope == "public":
            if responder.asn is None:
                continue
            key = ("asn", str(responder.asn.number))
            name = responder.asn.organization or responder.asn.name
            existing = entries.get(key)
            prefixes = list(existing[2]) if existing else []
            if responder.asn.prefix not in prefixes and len(prefixes) < 16:
                prefixes.append(responder.asn.prefix)
            entries[key] = (responder.asn.number, name, prefixes)
        else:
            key = ("scope", responder.scope)
            entries.setdefault(key, (None, _SCOPE_NAMES[responder.scope], []))
    return entries


def build_as_path(hops: list[TraceHopResponse]) -> list[TraceAsPathSegment]:
    """Build honest contiguous network observations without flattening ECMP."""

    segments: list[_SegmentState] = []
    current: _SegmentState | None = None
    gap_before = False
    previous_hop_number = 0
    for hop in hops:
        if hop.number > previous_hop_number + 1:
            current = None
            gap_before = True
        previous_hop_number = hop.number
        entries = _network_entries(hop)
        if not entries:
            current = None
            gap_before = True
            continue
        public_responders = [
            responder for responder in hop.responders if responder.scope == "public"
        ]
        partially_mapped_public_ecmp = (
            len(public_responders) > 1
            and any(responder.asn is None for responder in public_responders)
        )
        if len(entries) > 1 or partially_mapped_public_ecmp:
            current = None
            for key, (asn, name, prefixes) in entries.items():
                segments.append(
                    _SegmentState(
                        key=key,
                        asn=asn,
                        network_name=name,
                        first_hop=hop.number,
                        last_hop=hop.number,
                        prefixes=prefixes,
                        ambiguous=True,
                        boundary_confidence="ecmp",
                    )
                )
            gap_before = True
            continue

        key, (asn, name, prefixes) = next(iter(entries.items()))
        if (
            current is not None
            and current.key == key
            and current.last_hop + 1 == hop.number
        ):
            current.last_hop = hop.number
            for prefix in prefixes:
                if prefix not in current.prefixes and len(current.prefixes) < 16:
                    current.prefixes.append(prefix)
        else:
            current = _SegmentState(
                key=key,
                asn=asn,
                network_name=name,
                first_hop=hop.number,
                last_hop=hop.number,
                prefixes=prefixes,
                ambiguous=False,
                boundary_confidence="gap" if gap_before else "exact",
            )
            segments.append(current)
        gap_before = False

    return [
        TraceAsPathSegment(
            asn=segment.asn,
            network_name=segment.network_name,
            first_hop=segment.first_hop,
            last_hop=segment.last_hop,
            prefixes=segment.prefixes,
            ambiguous=segment.ambiguous,
            boundary_confidence=segment.boundary_confidence,  # type: ignore[arg-type]
        )
        for segment in segments[:192]
    ]
