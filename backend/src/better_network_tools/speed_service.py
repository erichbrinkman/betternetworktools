"""Bounded in-memory lifecycle for NetSpeed jobs."""

from __future__ import annotations

import asyncio
import inspect
import math
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol, cast

from .config import Settings
from .models import (
    TERMINAL_SPEED_JOB_STATUSES,
    SpeedJobProgress,
    SpeedJobOptions,
    SpeedJobRequest,
    SpeedJobResponse,
    SpeedJobStatus,
    SpeedPhase,
    SpeedServerListResponse,
    SpeedTestResult,
    SpeedThroughputSample,
)
from .speedtest import (
    ProgressCallback,
    SpeedJobRunner,
    SpeedRunError,
    SpeedRunnerResult,
    SpeedServerCatalog,
    SpeedServerTarget,
    SpeedTestRunner,
    SpeedTestOptions,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


_MAX_THROUGHPUT_SAMPLES = 160
_MIN_SAMPLE_CADENCE_SECONDS = 0.5
_SAMPLES_PER_REQUEST_TIMEOUT = 80
TransferPhase = Literal["download", "upload"]


class SpeedCatalog(Protocol):
    async def list_servers(self) -> SpeedServerListResponse: ...

    async def resolve(self, server_id: str) -> SpeedServerTarget: ...


class SpeedFailureReporter(Protocol):
    def report_failure(self, server_id: str) -> Awaitable[None] | None: ...


class SpeedJobNotFoundError(KeyError):
    pass


class SpeedJobCapacityError(RuntimeError):
    def __init__(self, *, limit: int, active: int) -> None:
        self.limit = limit
        self.active = active
        super().__init__(f"the active speed-job limit of {limit} has been reached")

    def as_detail(self) -> dict[str, str | int]:
        return {
            "code": "speed_job_capacity_exceeded",
            "message": str(self),
            "limit": self.limit,
            "active": self.active,
        }


class SpeedJobSizeError(ValueError):
    """A requested transfer size falls outside the active resource limits."""

    def __init__(
        self, *, field_name: str, actual: int, minimum: int, maximum: int
    ) -> None:
        self.field_name = field_name
        self.actual = actual
        self.minimum = minimum
        self.maximum = maximum
        super().__init__(
            f"{field_name} must be between {minimum} and {maximum} bytes"
        )

    def as_detail(self) -> dict[str, str | int]:
        return {
            "code": "speed_transfer_size_out_of_range",
            "message": str(self),
            "field": self.field_name,
            "actual": self.actual,
            "minimum": self.minimum,
            "maximum": self.maximum,
        }


@dataclass(slots=True)
class _SpeedJob:
    id: str
    target: SpeedServerTarget
    options: SpeedTestOptions
    created_at: datetime = field(default_factory=_utc_now)
    status: SpeedJobStatus = SpeedJobStatus.QUEUED
    phase: SpeedPhase = "queued"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    percent: float = 0.0
    download_bytes: int = 0
    upload_bytes: int = 0
    result: SpeedTestResult | None = None
    error: str | None = None
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = None
    started_monotonic: float | None = None
    sample_phase: TransferPhase | None = None
    sample_baseline_at: float | None = None
    sample_baseline_bytes: int = 0
    current_mbps: float | None = None
    samples: deque[SpeedThroughputSample] = field(
        default_factory=lambda: deque(maxlen=_MAX_THROUGHPUT_SAMPLES)
    )


class SpeedJobService:
    """Own speed jobs and ensure only catalog-selected endpoints are measured."""

    def __init__(
        self,
        settings: Settings,
        *,
        catalog: SpeedCatalog | None = None,
        runner: SpeedJobRunner | None = None,
        monotonic_clock: Callable[[], float] | None = None,
    ) -> None:
        self.settings = settings
        self.catalog = catalog or SpeedServerCatalog(settings)
        self.runner = runner or SpeedTestRunner(settings)
        self._monotonic = monotonic_clock or time.monotonic
        self._sample_cadence_seconds = max(
            _MIN_SAMPLE_CADENCE_SECONDS,
            settings.speed_request_timeout_seconds / _SAMPLES_PER_REQUEST_TIMEOUT,
        )
        self._jobs: dict[str, _SpeedJob] = {}
        self._lock = asyncio.Lock()
        self._shutdown_complete = False

    async def list_servers(self) -> SpeedServerListResponse:
        return await self.catalog.list_servers()

    async def create_job(self, request: SpeedJobRequest) -> SpeedJobResponse:
        # Endpoint resolution occurs entirely inside the service. The request
        # model intentionally has no URL-shaped fields.
        options = self._resolve_options(request)
        target = await self.catalog.resolve(request.server_id)
        job = _SpeedJob(id=str(uuid.uuid4()), target=target, options=options)
        async with self._lock:
            self._purge_expired_locked()
            active = sum(
                existing.status not in TERMINAL_SPEED_JOB_STATUSES
                for existing in self._jobs.values()
            )
            if active >= self.settings.speed_active_job_limit:
                raise SpeedJobCapacityError(
                    limit=self.settings.speed_active_job_limit, active=active
                )
            self._jobs[job.id] = job
            job.task = asyncio.create_task(
                self._run_job(job), name=f"netspeed-{job.id}"
            )
            return self._snapshot_locked(job)

    async def get_job(self, job_id: str) -> SpeedJobResponse:
        async with self._lock:
            self._purge_expired_locked()
            job = self._jobs.get(job_id)
            if job is None:
                raise SpeedJobNotFoundError(job_id)
            return self._snapshot_locked(job)

    async def cancel_job(self, job_id: str) -> SpeedJobResponse:
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise SpeedJobNotFoundError(job_id)
            terminal = job.status in TERMINAL_SPEED_JOB_STATUSES
            if not terminal:
                job.cancel_requested = True
                if job.status == SpeedJobStatus.QUEUED:
                    job.status = SpeedJobStatus.CANCELLED
                    job.phase = "complete"
                    job.finished_at = _utc_now()
            task = None if terminal else job.task

        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

        finished_monotonic = self._monotonic()
        async with self._lock:
            if job.status not in TERMINAL_SPEED_JOB_STATUSES:
                self._finish_throughput_locked(job, finished_monotonic)
                job.status = SpeedJobStatus.CANCELLED
                job.phase = "complete"
                job.finished_at = _utc_now()
            return self._snapshot_locked(job)

    async def shutdown(self) -> None:
        async with self._lock:
            job_ids = list(self._jobs)
        for job_id in job_ids:
            await self.cancel_job(job_id)
        if self._shutdown_complete:
            return
        self._shutdown_complete = True
        await self._shutdown_component(self.runner)
        if self.catalog is not self.runner:
            await self._shutdown_component(self.catalog)

    @staticmethod
    async def _shutdown_component(component: object) -> None:
        shutdown = getattr(component, "shutdown", None)
        if shutdown is None:
            return
        result = shutdown()
        if inspect.isawaitable(result):
            await result

    async def _run_job(self, job: _SpeedJob) -> None:
        async with self._lock:
            if job.status == SpeedJobStatus.CANCELLED:
                return
            job.status = SpeedJobStatus.RUNNING
            job.phase = "ping"
            job.started_at = _utc_now()
            job.started_monotonic = self._monotonic()

        async def on_progress(
            phase: SpeedPhase,
            percent: float,
            download_bytes: int,
            upload_bytes: int,
        ) -> None:
            observed_at = self._monotonic()
            async with self._lock:
                if job.status in TERMINAL_SPEED_JOB_STATUSES:
                    return
                job.percent = min(99.0, max(job.percent, percent))
                job.download_bytes = max(job.download_bytes, download_bytes)
                job.upload_bytes = max(job.upload_bytes, upload_bytes)
                self._update_throughput_locked(job, phase, observed_at)
                job.phase = phase

        progress: ProgressCallback = on_progress
        try:
            measured = await self.runner.run(job.target, progress, job.options)
            result = self._result(job.target, measured)
            finished_monotonic = self._monotonic()
            async with self._lock:
                job.result = result
                job.download_bytes = result.download_bytes
                job.upload_bytes = result.upload_bytes
                self._finish_throughput_locked(job, finished_monotonic)
                job.percent = 100.0
                job.phase = "complete"
                job.status = (
                    SpeedJobStatus.CANCELLED
                    if job.cancel_requested
                    else SpeedJobStatus.COMPLETED
                )
                job.finished_at = _utc_now()
        except asyncio.CancelledError:
            finished_monotonic = self._monotonic()
            async with self._lock:
                self._finish_throughput_locked(job, finished_monotonic)
                job.cancel_requested = True
                job.status = SpeedJobStatus.CANCELLED
                job.phase = "complete"
                job.finished_at = _utc_now()
        except SpeedRunError as exc:
            finished_monotonic = self._monotonic()
            # Apply any short catalog quarantine before FAILED becomes visible.
            # A client can immediately refresh the directory after observing a
            # terminal job, so exposing the state first could offer the same bad
            # server again during that race.
            await self._report_server_failure(job.target)
            async with self._lock:
                self._finish_throughput_locked(job, finished_monotonic)
                job.status = SpeedJobStatus.FAILED
                job.phase = "complete"
                job.error = str(exc)[:240]
                job.finished_at = _utc_now()
        except Exception:
            # Remote exceptions can contain request URLs, query strings, proxy
            # details, or control characters. Do not reflect them to the API.
            finished_monotonic = self._monotonic()
            async with self._lock:
                self._finish_throughput_locked(job, finished_monotonic)
                job.status = SpeedJobStatus.FAILED
                job.phase = "complete"
                job.error = "The speed test could not be completed."
                job.finished_at = _utc_now()

    async def _report_server_failure(self, target: SpeedServerTarget) -> None:
        """Best-effort quarantine signal for a failed third-party server."""

        if target.public.provider == "cloudflare":
            return
        report_failure = getattr(self.catalog, "report_failure", None)
        if report_failure is None:
            return
        try:
            reporter = cast(SpeedFailureReporter, self.catalog)
            result = reporter.report_failure(target.public.id)
            if inspect.isawaitable(result):
                await result
        except asyncio.CancelledError:
            raise
        except Exception:
            # Catalog health tracking must never replace the safe job failure or
            # prevent the client from observing a terminal response.
            return

    def _update_throughput_locked(
        self, job: _SpeedJob, phase: SpeedPhase, observed_at: float
    ) -> None:
        """Derive a bounded interval rate from cumulative transfer counters."""

        if phase not in {"download", "upload"}:
            if job.sample_phase in {"download", "upload"}:
                self._record_throughput_locked(job, observed_at, force=True)
            job.sample_phase = None
            job.sample_baseline_at = None
            job.sample_baseline_bytes = 0
            job.current_mbps = None
            return

        if job.sample_phase != phase:
            if job.sample_phase in {"download", "upload"}:
                self._record_throughput_locked(job, observed_at, force=True)
            job.sample_phase = phase
            job.sample_baseline_at = observed_at
            job.sample_baseline_bytes = self._phase_bytes(job, phase)
            job.current_mbps = None
            return

        self._record_throughput_locked(job, observed_at, force=False)

    def _record_throughput_locked(
        self, job: _SpeedJob, observed_at: float, *, force: bool
    ) -> None:
        phase = job.sample_phase
        baseline_at = job.sample_baseline_at
        if (
            phase not in {"download", "upload"}
            or baseline_at is None
            or job.started_monotonic is None
        ):
            return

        duration = observed_at - baseline_at
        current_bytes = self._phase_bytes(job, phase)
        transferred = current_bytes - job.sample_baseline_bytes
        if (
            not math.isfinite(duration)
            or duration <= 0
            or transferred <= 0
            or (not force and duration < self._sample_cadence_seconds)
        ):
            return

        elapsed = observed_at - job.started_monotonic
        if not math.isfinite(elapsed) or elapsed < 0:
            return
        mbps = transferred * 8 / duration / 1_000_000
        if not math.isfinite(mbps) or mbps < 0:
            return

        sample = SpeedThroughputSample(
            phase=phase,
            elapsed_seconds=round(elapsed, 3),
            mbps=round(mbps, 2),
        )
        job.samples.append(sample)
        job.current_mbps = sample.mbps
        job.sample_baseline_at = observed_at
        job.sample_baseline_bytes = current_bytes

    def _finish_throughput_locked(
        self, job: _SpeedJob, observed_at: float
    ) -> None:
        self._record_throughput_locked(job, observed_at, force=True)
        job.sample_phase = None
        job.sample_baseline_at = None
        job.sample_baseline_bytes = 0
        job.current_mbps = None

    @staticmethod
    def _phase_bytes(job: _SpeedJob, phase: TransferPhase) -> int:
        return job.download_bytes if phase == "download" else job.upload_bytes

    @staticmethod
    def _result(
        target: SpeedServerTarget, measured: SpeedRunnerResult
    ) -> SpeedTestResult:
        return SpeedTestResult(
            server=target.public,
            ping_ms=measured.ping_ms,
            jitter_ms=measured.jitter_ms,
            download_mbps=measured.download_mbps,
            upload_mbps=measured.upload_mbps,
            download_bytes=measured.download_bytes,
            upload_bytes=measured.upload_bytes,
            transferred_bytes=measured.download_bytes + measured.upload_bytes,
            duration_seconds=measured.duration_seconds,
        )

    def _snapshot_locked(self, job: _SpeedJob) -> SpeedJobResponse:
        return SpeedJobResponse(
            id=job.id,
            status=job.status,
            phase=job.phase,
            server=job.target.public,
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            options=SpeedJobOptions(
                download_bytes=job.options.download_bytes,
                upload_bytes=job.options.upload_bytes,
            ),
            progress=SpeedJobProgress(
                percent=round(job.percent, 1),
                download_bytes=job.download_bytes,
                upload_bytes=job.upload_bytes,
                current_mbps=job.current_mbps,
                samples=list(job.samples),
            ),
            result=job.result,
            error=job.error,
            cancel_requested=job.cancel_requested,
        )

    def _resolve_options(self, request: SpeedJobRequest) -> SpeedTestOptions:
        download_bytes = (
            self.settings.speed_download_byte_default
            if request.download_bytes is None
            else request.download_bytes
        )
        upload_bytes = (
            self.settings.speed_upload_byte_default
            if request.upload_bytes is None
            else request.upload_bytes
        )
        self._validate_size(
            field_name="download_bytes",
            actual=download_bytes,
            minimum=self.settings.speed_download_byte_minimum,
            maximum=self.settings.speed_download_byte_limit,
        )
        self._validate_size(
            field_name="upload_bytes",
            actual=upload_bytes,
            minimum=self.settings.speed_upload_byte_minimum,
            maximum=self.settings.speed_upload_byte_limit,
        )
        return SpeedTestOptions(
            download_bytes=download_bytes,
            upload_bytes=upload_bytes,
        )

    @staticmethod
    def _validate_size(
        *, field_name: str, actual: int, minimum: int, maximum: int
    ) -> None:
        if not minimum <= actual <= maximum:
            raise SpeedJobSizeError(
                field_name=field_name,
                actual=actual,
                minimum=minimum,
                maximum=maximum,
            )

    def _purge_expired_locked(self) -> None:
        cutoff = _utc_now() - timedelta(seconds=self.settings.job_retention_seconds)
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.finished_at is not None and job.finished_at < cutoff
        ]
        for job_id in expired:
            del self._jobs[job_id]
