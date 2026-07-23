"""In-memory lifecycle and bounded scheduling for NetPinger jobs."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import unicodedata
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .config import Settings
from .models import (
    TERMINAL_PING_JOB_STATUSES,
    PingAddressFamily,
    PingJobOptions,
    PingJobProgress,
    PingJobRequest,
    PingJobResponse,
    PingJobStatus,
    PingReverseDnsStatus,
    PingTargetResponse,
    PingTargetStatus,
)
from .ping_validation import (
    PingValidationError,
    ValidatedPingTarget,
    validate_ping_targets,
)
from .pinger import (
    NativePingProbe,
    PingProbe,
    PingProbeResult,
    PingResolver,
    ReverseDNSResolver,
    ResolvedPingTarget,
    SystemPingResolver,
    SystemReverseDNSResolver,
)


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_error(exc: BaseException | str) -> str:
    value = str(exc)
    cleaned = _CONTROL_CHARACTERS.sub(" ", value).strip()
    return (cleaned or type(exc).__name__)[:240]


def _classify_reverse_hostname(
    value: object, address: str
) -> tuple[str | None, PingReverseDnsStatus]:
    """Validate an untrusted PTR result and classify unusable responses."""

    if not isinstance(value, str):
        return None, "unavailable"
    # A terminal dot represents the DNS root and is not part of the displayed
    # hostname. Remove it before applying the 253-character hostname ceiling.
    cleaned = value[:-1] if value.endswith(".") else value
    if not cleaned or len(cleaned) > 253:
        return None, "unavailable"
    if any(
        character.isspace()
        or unicodedata.category(character).startswith("C")
        for character in cleaned
    ):
        return None, "unavailable"
    if not cleaned or cleaned.casefold() == address.casefold():
        return None, "not_found"
    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return cleaned, "resolved"
    return None, "not_found"


def _is_missing_ptr_error(exc: socket.gaierror) -> bool:
    missing_error_numbers = {socket.EAI_NONAME}
    no_data = getattr(socket, "EAI_NODATA", None)
    if no_data is not None:
        missing_error_numbers.add(no_data)
    return exc.errno in missing_error_numbers


class PingJobNotFoundError(KeyError):
    pass


class PingJobCapacityError(RuntimeError):
    """Raised when the configured active ping-job ceiling is reached."""

    def __init__(self, *, limit: int, active: int) -> None:
        self.limit = limit
        self.active = active
        super().__init__(
            f"the active ping-job limit of {limit} has been reached"
        )

    def as_detail(self) -> dict[str, str | int]:
        return {
            "code": "ping_job_capacity_exceeded",
            "message": str(self),
            "limit": self.limit,
            "active": self.active,
        }


@dataclass(slots=True)
class _PingTargetState:
    validated: ValidatedPingTarget
    resolved_address: str | None = None
    address_family: PingAddressFamily | None = None
    reverse_hostname: str | None = None
    reverse_dns_status: PingReverseDnsStatus = "not_requested"
    status: PingTargetStatus = "pending"
    sent: int = 0
    received: int = 0
    failed: int = 0
    consecutive_successes: int = 0
    max_consecutive_successes: int = 0
    consecutive_failures: int = 0
    max_consecutive_failures: int = 0
    reply_time_history_ms: deque[float | None] = field(
        default_factory=lambda: deque(maxlen=60)
    )
    last_ms: float | None = None
    latency_count: int = 0
    latency_total_ms: float = 0.0
    min_ms: float | None = None
    max_ms: float | None = None
    last_checked: datetime | None = None
    error: str | None = None


@dataclass(slots=True)
class _PingJob:
    id: str
    options: PingJobOptions
    targets: list[_PingTargetState]
    created_at: datetime = field(default_factory=_utc_now)
    status: PingJobStatus = PingJobStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = None
    reverse_tasks: set[asyncio.Task[None]] = field(default_factory=set)


class PingJobService:
    """Own multi-target ping jobs and keep native probes globally bounded."""

    def __init__(
        self,
        settings: Settings,
        *,
        probe: PingProbe | None = None,
        resolver: PingResolver | None = None,
        reverse_resolver: ReverseDNSResolver | None = None,
    ) -> None:
        self.settings = settings
        self.probe = probe or NativePingProbe()
        self.resolver = resolver or SystemPingResolver()
        self.reverse_resolver = reverse_resolver or SystemReverseDNSResolver()
        self._jobs: dict[str, _PingJob] = {}
        self._lock = asyncio.Lock()
        self._probe_semaphore = asyncio.Semaphore(settings.ping_probe_concurrency)
        self._resolver_semaphore = asyncio.Semaphore(
            settings.ping_resolver_concurrency
        )
        # PTR lookups have their own bounded pool so a slow reverse resolver
        # cannot consume the capacity required for forward hostname resolution.
        self._reverse_resolver_semaphore = asyncio.Semaphore(
            settings.ping_resolver_concurrency
        )

    async def create_job(self, request: PingJobRequest) -> PingJobResponse:
        targets = validate_ping_targets(
            request.targets, target_limit=self.settings.ping_target_limit
        )
        if not request.continuous and request.count > self.settings.ping_sample_limit:
            raise PingValidationError(
                "ping_sample_limit_exceeded",
                f"ping jobs may request at most {self.settings.ping_sample_limit} samples",
                limit=self.settings.ping_sample_limit,
                actual=request.count,
            )

        job = _PingJob(
            id=str(uuid.uuid4()),
            options=PingJobOptions(
                count=request.count,
                interval=request.interval,
                timeout=request.timeout,
                continuous=request.continuous,
            ),
            targets=[
                _PingTargetState(
                    validated=target,
                    reverse_dns_status=(
                        "pending" if target.address is not None else "not_requested"
                    ),
                )
                for target in targets
            ],
        )
        async with self._lock:
            self._purge_expired_locked()
            active_job_count = sum(
                existing.status not in TERMINAL_PING_JOB_STATUSES
                for existing in self._jobs.values()
            )
            if active_job_count >= self.settings.ping_active_job_limit:
                raise PingJobCapacityError(
                    limit=self.settings.ping_active_job_limit,
                    active=active_job_count,
                )
            self._jobs[job.id] = job
            job.task = asyncio.create_task(
                self._run_job(job), name=f"netpinger-{job.id}"
            )
            return self._snapshot_locked(job)

    async def get_job(self, job_id: str) -> PingJobResponse:
        async with self._lock:
            self._purge_expired_locked()
            job = self._jobs.get(job_id)
            if job is None:
                raise PingJobNotFoundError(job_id)
            return self._snapshot_locked(job)

    async def cancel_job(self, job_id: str) -> PingJobResponse:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise PingJobNotFoundError(job_id)
            terminal = job.status in TERMINAL_PING_JOB_STATUSES
            if not terminal:
                was_queued = job.status == PingJobStatus.QUEUED
                job.cancel_requested = True
                if was_queued:
                    job.status = PingJobStatus.CANCELLED
                    job.finished_at = _utc_now()
                    for target in job.targets:
                        if target.reverse_dns_status == "pending":
                            target.reverse_dns_status = "unavailable"
            task = None if terminal else job.task
            reverse_tasks = list(job.reverse_tasks)

        tasks_to_cancel = [
            pending_task
            for pending_task in [task, *reverse_tasks]
            if pending_task is not None and not pending_task.done()
        ]
        for pending_task in tasks_to_cancel:
            pending_task.cancel()
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        async with self._lock:
            if job.status not in TERMINAL_PING_JOB_STATUSES:
                job.status = PingJobStatus.CANCELLED
                job.finished_at = _utc_now()
            return self._snapshot_locked(job)

    async def shutdown(self) -> None:
        async with self._lock:
            job_ids = [job.id for job in self._jobs.values()]
        for job_id in job_ids:
            await self.cancel_job(job_id)

    async def _run_job(self, job: _PingJob) -> None:
        workers: list[asyncio.Task[None]] = []
        async with self._lock:
            if job.status == PingJobStatus.CANCELLED:
                return
            job.status = PingJobStatus.RUNNING
            job.started_at = _utc_now()
            job.reverse_tasks = {
                asyncio.create_task(
                    self._populate_reverse_dns(target),
                    name=f"{job.id}-reverse-{index}",
                )
                for index, target in enumerate(job.targets)
                if target.validated.address is not None
            }

        try:
            # Creating every target task before awaiting any of them gives each
            # target a worker immediately; semaphores bound the expensive parts.
            workers = [
                asyncio.create_task(
                    self._run_target(job, target),
                    name=f"{job.id}-target-{index}",
                )
                for index, target in enumerate(job.targets)
            ]
            await asyncio.gather(*workers)
            if not job.options.continuous and job.reverse_tasks:
                # PTR lookup starts with the probes, then finite jobs wait for
                # their owned lookup tasks so terminal snapshots are settled.
                await asyncio.gather(*job.reverse_tasks)
            async with self._lock:
                job.status = (
                    PingJobStatus.CANCELLED
                    if job.cancel_requested
                    else PingJobStatus.COMPLETED
                )
                job.finished_at = _utc_now()
        except asyncio.CancelledError:
            for worker in workers:
                worker.cancel()
            for reverse_task in job.reverse_tasks:
                reverse_task.cancel()
            pending_tasks = [*workers, *job.reverse_tasks]
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            async with self._lock:
                job.cancel_requested = True
                job.status = PingJobStatus.CANCELLED
                job.finished_at = _utc_now()
        except Exception as exc:
            for worker in workers:
                worker.cancel()
            for reverse_task in job.reverse_tasks:
                reverse_task.cancel()
            pending_tasks = [*workers, *job.reverse_tasks]
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            async with self._lock:
                job.status = PingJobStatus.FAILED
                job.error = f"{type(exc).__name__}: {_safe_error(exc)}"
                job.finished_at = _utc_now()

    async def _populate_reverse_dns(self, target: _PingTargetState) -> None:
        """Populate a literal IP target's PTR result without affecting probes."""

        address = target.validated.address
        if address is None:
            return
        parsed_address = ipaddress.ip_address(address)
        address_family: PingAddressFamily = (
            "IPv4" if parsed_address.version == 4 else "IPv6"
        )

        try:
            async with asyncio.timeout(
                self.settings.ping_resolve_timeout_seconds
            ):
                async with self._reverse_resolver_semaphore:
                    hostname = await self.reverse_resolver.resolve(
                        parsed_address.compressed, address_family
                    )
            safe_hostname, reverse_dns_status = _classify_reverse_hostname(
                hostname, parsed_address.compressed
            )
        except asyncio.CancelledError:
            async with self._lock:
                if target.reverse_dns_status == "pending":
                    target.reverse_dns_status = "unavailable"
            raise
        except socket.gaierror as exc:
            safe_hostname = None
            reverse_dns_status = (
                "not_found" if _is_missing_ptr_error(exc) else "unavailable"
            )
        except Exception:
            safe_hostname = None
            reverse_dns_status = "unavailable"

        async with self._lock:
            target.reverse_hostname = safe_hostname
            target.reverse_dns_status = reverse_dns_status

    async def _run_target(
        self, job: _PingJob, target: _PingTargetState
    ) -> None:
        try:
            resolved = await self._resolve_target(target.validated)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            async with self._lock:
                target.status = "error"
                # Finite jobs retain their historical accounting contract: an
                # unresolvable target consumes all requested samples. A
                # continuous job has no finite sample total to synthesize, so it
                # terminates this target worker with zero attempted probes.
                if not job.options.continuous:
                    target.sent = job.options.count
                    target.failed = job.options.count
                target.last_checked = _utc_now()
                target.error = _safe_error(exc)
            return

        async with self._lock:
            target.resolved_address = resolved.address
            target.address_family = resolved.address_family

        loop = asyncio.get_running_loop()
        next_deadline = loop.time()
        sample_index = 0
        while job.options.continuous or sample_index < job.options.count:
            if sample_index:
                next_deadline += job.options.interval
                delay = next_deadline - loop.time()
                if delay > 0:
                    await asyncio.sleep(delay)

            async with self._lock:
                if job.cancel_requested or job.status != PingJobStatus.RUNNING:
                    return

            try:
                async with self._probe_semaphore:
                    result = await self.probe.probe(
                        resolved.address,
                        resolved.address_family,
                        job.options.timeout,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                result = PingProbeResult(received=False, error=_safe_error(exc))

            async with self._lock:
                target.sent += 1
                target.last_checked = _utc_now()
                target.last_ms = result.latency_ms if result.received else None
                target.reply_time_history_ms.append(
                    result.latency_ms
                    if result.received and result.latency_ms is not None
                    else None
                )
                if result.received:
                    target.received += 1
                    target.consecutive_successes += 1
                    target.max_consecutive_successes = max(
                        target.max_consecutive_successes,
                        target.consecutive_successes,
                    )
                    target.consecutive_failures = 0
                    if result.latency_ms is not None:
                        target.latency_count += 1
                        target.latency_total_ms += result.latency_ms
                        target.min_ms = (
                            result.latency_ms
                            if target.min_ms is None
                            else min(target.min_ms, result.latency_ms)
                        )
                        target.max_ms = (
                            result.latency_ms
                            if target.max_ms is None
                            else max(target.max_ms, result.latency_ms)
                        )
                else:
                    target.failed += 1
                    target.consecutive_failures += 1
                    target.max_consecutive_failures = max(
                        target.max_consecutive_failures,
                        target.consecutive_failures,
                    )
                    target.consecutive_successes = 0
                if result.error:
                    target.status = "error"
                    target.error = _safe_error(result.error)
                else:
                    target.status = "up" if result.received else "down"
                    target.error = None
            sample_index += 1

    async def _resolve_target(
        self, target: ValidatedPingTarget
    ) -> ResolvedPingTarget:
        if target.address is not None:
            address = ipaddress.ip_address(target.address)
            return ResolvedPingTarget(
                address=address.compressed,
                address_family="IPv4" if address.version == 4 else "IPv6",
            )

        try:
            async with self._resolver_semaphore:
                async with asyncio.timeout(
                    self.settings.ping_resolve_timeout_seconds
                ):
                    resolved = await self.resolver.resolve(target.lookup)
        except TimeoutError as exc:
            raise OSError(f"resolution timed out for {target.lookup}") from exc

        # Do not trust an injected or OS resolver to return a safe argv value.
        try:
            address = ipaddress.ip_address(resolved.address)
        except ValueError as exc:
            raise OSError(
                f"resolver returned an invalid address for {target.lookup}"
            ) from exc
        return ResolvedPingTarget(
            address=address.compressed,
            address_family="IPv4" if address.version == 4 else "IPv6",
        )

    def _snapshot_locked(self, job: _PingJob) -> PingJobResponse:
        target_responses: list[PingTargetResponse] = []
        for target in job.targets:
            success_rate = (
                round((target.received / target.sent) * 100, 1)
                if target.sent
                else 0.0
            )
            loss_percent = (
                round((target.failed / target.sent) * 100, 1)
                if target.sent
                else 0.0
            )
            target_responses.append(
                PingTargetResponse(
                    target=target.validated.display,
                    resolved_address=target.resolved_address,
                    address_family=target.address_family,
                    reverse_hostname=target.reverse_hostname,
                    reverse_dns_status=target.reverse_dns_status,
                    status=target.status,
                    sent=target.sent,
                    received=target.received,
                    failed=target.failed,
                    consecutive_successes=target.consecutive_successes,
                    max_consecutive_successes=target.max_consecutive_successes,
                    consecutive_failures=target.consecutive_failures,
                    max_consecutive_failures=target.max_consecutive_failures,
                    reply_time_history_ms=list(target.reply_time_history_ms),
                    latency_samples=target.latency_count,
                    success_rate=success_rate,
                    loss_percent=loss_percent,
                    last_ms=target.last_ms,
                    avg_ms=(
                        round(target.latency_total_ms / target.latency_count, 3)
                        if target.latency_count
                        else None
                    ),
                    min_ms=round(target.min_ms, 3) if target.min_ms is not None else None,
                    max_ms=round(target.max_ms, 3) if target.max_ms is not None else None,
                    last_checked=target.last_checked,
                    error=target.error,
                )
            )

        completed_probes = sum(target.sent for target in job.targets)
        total_probes = (
            None if job.options.continuous else len(job.targets) * job.options.count
        )
        percent = (
            None
            if total_probes is None
            else (
                round((completed_probes / total_probes) * 100, 1)
                if total_probes
                else 100.0
            )
        )
        return PingJobResponse(
            id=job.id,
            status=job.status,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            options=job.options.model_copy(deep=True),
            progress=PingJobProgress(
                total_probes=total_probes,
                completed_probes=completed_probes,
                percent=percent,
            ),
            targets=target_responses,
            error=job.error,
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
