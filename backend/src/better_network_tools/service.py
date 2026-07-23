"""In-memory scan job lifecycle and bounded host scheduling."""

from __future__ import annotations

import asyncio
import ipaddress
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .config import Settings
from .models import (
    TERMINAL_SCAN_STATUSES,
    DeviceResult,
    ScanJobResponse,
    ScanOptions,
    ScanProgress,
    ScanRequest,
    ScanResultsResponse,
    ScanStatus,
    ScanSummaryResponse,
)
from .network import HostInspector, NetworkProber, ProbeOptions
from .validation import ScanValidationError, parse_scan_target


DEFAULT_SCAN_LIST_LIMIT = 20
MAX_SCAN_LIST_LIMIT = 50


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ScanNotFoundError(KeyError):
    pass


@dataclass(slots=True)
class _ScanJob:
    id: str
    network: ipaddress.IPv4Network
    total_hosts: int
    options: ScanOptions
    probe_options: ProbeOptions
    created_at: datetime = field(default_factory=_utc_now)
    status: ScanStatus = ScanStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    scanned_hosts: int = 0
    results: dict[str, DeviceResult] = field(default_factory=dict)
    error: str | None = None
    cancel_requested: bool = False
    task: asyncio.Task[None] | None = None


class ScanService:
    """Own scan jobs and coordinate a bounded number of host inspectors."""

    def __init__(
        self, settings: Settings, *, inspector: HostInspector | None = None
    ) -> None:
        self.settings = settings
        self.inspector = inspector or NetworkProber()
        self._jobs: dict[str, _ScanJob] = {}
        self._lock = asyncio.Lock()

    async def create_scan(self, request: ScanRequest) -> ScanJobResponse:
        target = parse_scan_target(request.subnet, self.settings.scan_host_limit)

        ports = sorted(set(request.ports if request.ports is not None else self.settings.default_ports))
        if len(ports) > self.settings.max_ports:
            raise ScanValidationError(
                "port_limit_exceeded",
                f"scan requests may contain at most {self.settings.max_ports} unique ports",
                limit=self.settings.max_ports,
                actual=len(ports),
            )

        if (
            request.concurrency is not None
            and request.concurrency > self.settings.scan_concurrency
        ):
            raise ScanValidationError(
                "concurrency_limit_exceeded",
                f"concurrency may not exceed {self.settings.scan_concurrency}",
                limit=self.settings.scan_concurrency,
                actual=request.concurrency,
            )

        requested_timeout = request.timeout
        tcp_timeout = requested_timeout or self.settings.tcp_timeout_seconds
        ping_timeout = requested_timeout or self.settings.ping_timeout_seconds
        concurrency = min(
            request.concurrency or self.settings.scan_concurrency,
            target.host_count,
        )
        options = ScanOptions(
            ports=ports,
            timeout=tcp_timeout,
            concurrency=concurrency,
            resolve_dns=request.resolve_dns,
            collect_banners=request.collect_banners,
        )
        probe_options = ProbeOptions(
            ports=tuple(ports),
            timeout=tcp_timeout,
            ping_timeout=ping_timeout,
            banner_timeout=min(self.settings.banner_timeout_seconds, tcp_timeout),
            resolve_dns=request.resolve_dns,
            collect_banners=request.collect_banners,
        )
        job = _ScanJob(
            id=str(uuid.uuid4()),
            network=target.network,
            total_hosts=target.host_count,
            options=options,
            probe_options=probe_options,
        )

        async with self._lock:
            self._purge_expired_locked()
            self._jobs[job.id] = job
            job.task = asyncio.create_task(
                self._run_job(job), name=f"netscanner-{job.id}"
            )
            return self._snapshot_locked(job)

    async def get_scan(self, scan_id: str) -> ScanJobResponse:
        async with self._lock:
            self._purge_expired_locked()
            job = self._jobs.get(scan_id)
            if job is None:
                raise ScanNotFoundError(scan_id)
            return self._snapshot_locked(job)

    async def list_scans(
        self, limit: int = DEFAULT_SCAN_LIST_LIMIT
    ) -> list[ScanSummaryResponse]:
        bounded_limit = max(1, min(limit, MAX_SCAN_LIST_LIMIT))
        async with self._lock:
            self._purge_expired_locked()
            newest_jobs = list(self._jobs.values())[-bounded_limit:]
            return [
                self._summary_snapshot_locked(job) for job in reversed(newest_jobs)
            ]

    async def get_results(self, scan_id: str) -> ScanResultsResponse:
        snapshot = await self.get_scan(scan_id)
        return ScanResultsResponse(
            scan_id=snapshot.id,
            status=snapshot.status,
            count=len(snapshot.results),
            results=snapshot.results,
        )

    async def cancel_scan(self, scan_id: str) -> ScanJobResponse:
        task: asyncio.Task[None] | None
        async with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                raise ScanNotFoundError(scan_id)
            if job.status in TERMINAL_SCAN_STATUSES:
                return self._snapshot_locked(job)

            job.cancel_requested = True
            if job.status == ScanStatus.QUEUED:
                job.status = ScanStatus.CANCELLED
                job.finished_at = _utc_now()
            task = job.task

        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                # A task cancelled before its coroutine first ran cannot handle the
                # exception itself; the queued state was finalized above.
                pass

        async with self._lock:
            if job.status not in TERMINAL_SCAN_STATUSES:
                job.status = ScanStatus.CANCELLED
                job.finished_at = _utc_now()
            return self._snapshot_locked(job)

    async def shutdown(self) -> None:
        async with self._lock:
            active_ids = [
                job.id
                for job in self._jobs.values()
                if job.status not in TERMINAL_SCAN_STATUSES
            ]
        for scan_id in active_ids:
            await self.cancel_scan(scan_id)

    async def _run_job(self, job: _ScanJob) -> None:
        workers: list[asyncio.Task[None]] = []
        async with self._lock:
            if job.status == ScanStatus.CANCELLED:
                return
            job.status = ScanStatus.RUNNING
            job.started_at = _utc_now()

        host_iterator = (str(address) for address in job.network.hosts())

        async def worker() -> None:
            while not job.cancel_requested:
                try:
                    ip_address = next(host_iterator)
                except StopIteration:
                    return

                try:
                    device = await self.inspector.inspect_host(
                        ip_address, job.probe_options
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Failure to inspect one device should not fail the entire subnet.
                    device = None

                async with self._lock:
                    if job.status != ScanStatus.RUNNING or job.cancel_requested:
                        return
                    job.scanned_hosts += 1
                    if device is not None:
                        job.results[ip_address] = device

        try:
            workers = [
                asyncio.create_task(worker(), name=f"{job.id}-worker-{index}")
                for index in range(job.options.concurrency)
            ]
            await asyncio.gather(*workers)
            async with self._lock:
                if job.cancel_requested:
                    job.status = ScanStatus.CANCELLED
                else:
                    job.status = ScanStatus.COMPLETED
                job.finished_at = _utc_now()
        except asyncio.CancelledError:
            for worker_task in workers:
                worker_task.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            async with self._lock:
                job.cancel_requested = True
                job.status = ScanStatus.CANCELLED
                job.finished_at = _utc_now()
        except Exception as exc:
            for worker_task in workers:
                worker_task.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            async with self._lock:
                job.status = ScanStatus.FAILED
                job.error = f"{type(exc).__name__}: {exc}"
                job.finished_at = _utc_now()

    def _snapshot_locked(self, job: _ScanJob) -> ScanJobResponse:
        sorted_results = [
            job.results[ip_address].model_copy(deep=True)
            for ip_address in sorted(
                job.results, key=lambda value: int(ipaddress.ip_address(value))
            )
        ]
        percent = (
            round((job.scanned_hosts / job.total_hosts) * 100, 1)
            if job.total_hosts
            else 100.0
        )
        return ScanJobResponse(
            id=job.id,
            status=job.status,
            subnet=str(job.network),
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            progress=ScanProgress(
                total_hosts=job.total_hosts,
                scanned_hosts=job.scanned_hosts,
                discovered_hosts=len(sorted_results),
                percent=percent,
            ),
            options=job.options.model_copy(deep=True),
            results=sorted_results,
            error=job.error,
            cancel_requested=job.cancel_requested,
        )

    def _summary_snapshot_locked(self, job: _ScanJob) -> ScanSummaryResponse:
        percent = (
            round((job.scanned_hosts / job.total_hosts) * 100, 1)
            if job.total_hosts
            else 100.0
        )
        return ScanSummaryResponse(
            id=job.id,
            status=job.status,
            subnet=str(job.network),
            created_at=job.created_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            progress=ScanProgress(
                total_hosts=job.total_hosts,
                scanned_hosts=job.scanned_hosts,
                discovered_hosts=len(job.results),
                percent=percent,
            ),
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
        for scan_id in expired_ids:
            self._jobs.pop(scan_id, None)
