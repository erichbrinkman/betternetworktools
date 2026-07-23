"""Bounded in-memory lifecycle for NetPorts TCP scan jobs."""

from __future__ import annotations

import asyncio
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from .config import Settings
from .models import (
    TERMINAL_PORT_JOB_STATUSES,
    PortJobOptions,
    PortJobProgress,
    PortJobRequest,
    PortJobResponse,
    PortJobStatus,
    PortResult,
)
from .pinger import PingResolver, ResolvedPingTarget
from .port_scanner import (
    BoundedSystemPortResolver,
    PortProbe,
    PortProbeObservation,
    TcpConnectPortProbe,
)
from .port_validation import (
    PortValidationError,
    ValidatedPortSpec,
    ValidatedPortTarget,
    format_port_spec,
    parse_port_spec,
    validate_port_target,
    validate_scannable_address,
)


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_error(exc: BaseException | str) -> str:
    cleaned = _CONTROL_CHARACTERS.sub(" ", str(exc)).strip()
    return (cleaned or type(exc).__name__)[:200]


class PortJobNotFoundError(KeyError):
    pass


class PortJobCapacityError(RuntimeError):
    def __init__(self, *, limit: int, active: int) -> None:
        self.limit = limit
        self.active = active
        super().__init__(f"the active NetPorts job limit of {limit} has been reached")

    def as_detail(self) -> dict[str, str | int]:
        return {
            "code": "port_job_capacity_exceeded",
            "message": str(self),
            "limit": self.limit,
            "active": self.active,
        }


@dataclass(slots=True)
class _PortJob:
    id: str
    target: ValidatedPortTarget
    ports: tuple[int, ...]
    options: PortJobOptions
    created_at: datetime = field(default_factory=_utc_now)
    status: PortJobStatus = PortJobStatus.QUEUED
    resolved_address: str | None = None
    address_family: Literal["IPv4", "IPv6"] | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    scanned_ports: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    timed_out_ports: int = 0
    error_ports: int = 0
    results: list[PortResult] = field(default_factory=list)
    results_truncated: bool = False
    error: str | None = None
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = None


class PortJobService:
    """Resolve one target once, then scan its TCP ports with fixed workers."""

    def __init__(
        self,
        settings: Settings,
        *,
        probe: PortProbe | None = None,
        resolver: PingResolver | None = None,
    ) -> None:
        self.settings = settings
        self.probe = probe or TcpConnectPortProbe()
        self._owns_resolver = resolver is None
        self.resolver = resolver or BoundedSystemPortResolver(
            workers=settings.port_scan_active_job_limit
        )
        self._jobs: dict[str, _PortJob] = {}
        self._lock = asyncio.Lock()
        self._resolver_semaphore = asyncio.Semaphore(
            settings.port_scan_active_job_limit
        )
        self._probe_semaphore = asyncio.Semaphore(settings.port_scan_concurrency)

    async def create_job(self, request: PortJobRequest) -> PortJobResponse:
        target = validate_port_target(request.target)
        if "ports" in request.model_fields_set:
            validated_ports = parse_port_spec(
                request.ports, port_limit=self.settings.port_scan_port_limit
            )
        else:
            default_ports = parse_port_spec(request.ports, port_limit=65535).ports[
                : self.settings.port_scan_port_limit
            ]
            validated_ports = ValidatedPortSpec(
                canonical=format_port_spec(default_ports), ports=default_ports
            )

        timeout = request.timeout
        if "timeout" not in request.model_fields_set:
            timeout = min(timeout, self.settings.port_scan_timeout_limit_seconds)
        elif timeout > self.settings.port_scan_timeout_limit_seconds:
            raise PortValidationError(
                "port_timeout_limit_exceeded",
                "the TCP connection timeout exceeds the configured NetPorts limit",
                limit=self.settings.port_scan_timeout_limit_seconds,
                actual=timeout,
            )

        concurrency = request.concurrency
        if "concurrency" not in request.model_fields_set:
            concurrency = min(concurrency, self.settings.port_scan_concurrency)
        elif concurrency > self.settings.port_scan_concurrency:
            raise PortValidationError(
                "port_concurrency_limit_exceeded",
                "the requested NetPorts concurrency exceeds the configured limit",
                limit=self.settings.port_scan_concurrency,
                actual=concurrency,
            )

        job = _PortJob(
            id=str(uuid.uuid4()),
            target=target,
            ports=validated_ports.ports,
            options=PortJobOptions(
                port_spec=validated_ports.canonical,
                total_ports=len(validated_ports.ports),
                timeout=timeout,
                concurrency=concurrency,
                collect_banners=request.collect_banners,
            ),
        )
        async with self._lock:
            self._purge_expired_locked()
            active = sum(
                existing.status not in TERMINAL_PORT_JOB_STATUSES
                for existing in self._jobs.values()
            )
            if active >= self.settings.port_scan_active_job_limit:
                raise PortJobCapacityError(
                    limit=self.settings.port_scan_active_job_limit,
                    active=active,
                )
            self._evict_terminal_jobs_locked(reserve=1)
            self._jobs[job.id] = job
            job.task = asyncio.create_task(
                self._run_job(job), name=f"netport-{job.id}"
            )
            return self._snapshot_locked(job)

    async def get_job(self, job_id: str) -> PortJobResponse:
        async with self._lock:
            self._purge_expired_locked()
            job = self._jobs.get(job_id)
            if job is None:
                raise PortJobNotFoundError(job_id)
            return self._snapshot_locked(job)

    async def cancel_job(self, job_id: str) -> PortJobResponse:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise PortJobNotFoundError(job_id)
            terminal = job.status in TERMINAL_PORT_JOB_STATUSES
            if not terminal:
                job.cancel_requested = True
                if job.status == PortJobStatus.QUEUED:
                    job.status = PortJobStatus.CANCELLED
                    job.finished_at = _utc_now()
                    job.ports = ()
            task = None if terminal else job.task

        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        async with self._lock:
            if job.status not in TERMINAL_PORT_JOB_STATUSES:
                job.status = PortJobStatus.CANCELLED
                job.finished_at = _utc_now()
                job.ports = ()
            return self._snapshot_locked(job)

    async def shutdown(self) -> None:
        async with self._lock:
            job_ids = list(self._jobs)
        for job_id in job_ids:
            await self.cancel_job(job_id)
        if self._owns_resolver and isinstance(
            self.resolver, BoundedSystemPortResolver
        ):
            self.resolver.close()

    async def _run_job(self, job: _PortJob) -> None:
        async with self._lock:
            if job.status == PortJobStatus.CANCELLED:
                return
            job.status = PortJobStatus.RESOLVING
            job.started_at = _utc_now()

        try:
            resolved = await self._resolve_target(job.target)
            async with self._lock:
                job.resolved_address = resolved.address
                job.address_family = resolved.address_family
                job.status = PortJobStatus.RUNNING

            port_iterator = iter(job.ports)
            worker_count = min(job.options.concurrency, len(job.ports))

            async def worker() -> None:
                while True:
                    try:
                        port = next(port_iterator)
                    except StopIteration:
                        return
                    try:
                        async with self._probe_semaphore:
                            observation = await self.probe.probe(
                                resolved.address,
                                resolved.address_family,
                                port,
                                timeout=job.options.timeout,
                                banner_timeout=self.settings.banner_timeout_seconds,
                                collect_banner=job.options.collect_banners,
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        observation = PortProbeObservation(state="error")
                    async with self._lock:
                        self._record_observation(job, observation)

            workers = [
                asyncio.create_task(worker(), name=f"netport-{job.id}-worker-{index}")
                for index in range(worker_count)
            ]
            try:
                await asyncio.wait_for(
                    asyncio.gather(*workers),
                    timeout=self.settings.port_scan_total_timeout_seconds,
                )
            except TimeoutError:
                for worker_task in workers:
                    worker_task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                async with self._lock:
                    job.status = PortJobStatus.FAILED
                    job.error = (
                        "The NetPorts scan reached its configured total time limit; "
                        "partial open-port results are shown."
                    )
                    job.finished_at = _utc_now()
                    job.ports = ()
                return

            async with self._lock:
                job.status = (
                    PortJobStatus.CANCELLED
                    if job.cancel_requested
                    else PortJobStatus.COMPLETED
                )
                job.finished_at = _utc_now()
                job.ports = ()
        except asyncio.CancelledError:
            async with self._lock:
                job.cancel_requested = True
                job.status = PortJobStatus.CANCELLED
                job.finished_at = _utc_now()
                job.ports = ()
        except Exception as exc:
            async with self._lock:
                job.status = PortJobStatus.FAILED
                job.error = f"NetPorts could not complete the scan: {_safe_error(exc)}"
                job.finished_at = _utc_now()
                job.ports = ()

    async def _resolve_target(
        self, target: ValidatedPortTarget
    ) -> ResolvedPingTarget:
        if target.address is not None:
            address = validate_scannable_address(target.address, target=target.display)
            return ResolvedPingTarget(
                address=address.compressed,
                address_family="IPv4" if address.version == 4 else "IPv6",
            )
        try:
            async with self._resolver_semaphore:
                async with asyncio.timeout(
                    self.settings.port_scan_resolve_timeout_seconds
                ):
                    resolved = await self.resolver.resolve(target.lookup)
        except TimeoutError as exc:
            raise OSError(f"resolution timed out for {target.lookup}") from exc

        address = validate_scannable_address(
            resolved.address, target=target.display
        )
        return ResolvedPingTarget(
            address=address.compressed,
            address_family="IPv4" if address.version == 4 else "IPv6",
        )

    def _record_observation(
        self, job: _PortJob, observation: PortProbeObservation
    ) -> None:
        job.scanned_ports += 1
        if observation.state == "open" and observation.result is not None:
            job.open_ports += 1
            if len(job.results) < self.settings.port_scan_result_limit:
                job.results.append(observation.result)
            else:
                job.results_truncated = True
        elif observation.state == "closed":
            job.closed_ports += 1
        elif observation.state == "timed_out":
            job.timed_out_ports += 1
        else:
            job.error_ports += 1

    def _snapshot_locked(self, job: _PortJob) -> PortJobResponse:
        total = job.options.total_ports
        percent = round((job.scanned_ports / total) * 100, 2)
        return PortJobResponse(
            id=job.id,
            status=job.status,
            target=job.target.display,
            resolved_address=job.resolved_address,
            address_family=job.address_family,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            options=job.options,
            progress=PortJobProgress(
                total_ports=total,
                scanned_ports=job.scanned_ports,
                open_ports=job.open_ports,
                closed_ports=job.closed_ports,
                timed_out_ports=job.timed_out_ports,
                error_ports=job.error_ports,
                percent=percent,
            ),
            results=sorted(job.results, key=lambda result: result.port),
            results_truncated=job.results_truncated,
            error=job.error,
            cancel_requested=job.cancel_requested,
        )

    def _purge_expired_locked(self) -> None:
        cutoff = _utc_now() - timedelta(seconds=self.settings.job_retention_seconds)
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.finished_at is not None and job.finished_at < cutoff
        ]
        for job_id in expired:
            self._jobs.pop(job_id, None)

    def _evict_terminal_jobs_locked(self, *, reserve: int = 0) -> None:
        target_count = max(0, self.settings.port_scan_retained_job_limit - reserve)
        while len(self._jobs) > target_count:
            terminal_jobs = [
                job
                for job in self._jobs.values()
                if job.status in TERMINAL_PORT_JOB_STATUSES
            ]
            if not terminal_jobs:
                return
            oldest = min(
                terminal_jobs,
                key=lambda job: (job.finished_at or job.created_at, job.created_at),
            )
            self._jobs.pop(oldest.id, None)
