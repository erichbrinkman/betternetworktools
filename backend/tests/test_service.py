from __future__ import annotations

import asyncio

import pytest

from better_network_tools.config import Settings
from better_network_tools.models import (
    TERMINAL_SCAN_STATUSES,
    DeviceResult,
    OpenPort,
    ScanRequest,
    ScanStatus,
)
from better_network_tools.network import ProbeOptions
from better_network_tools.service import ScanService
from better_network_tools.validation import ScanValidationError


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "scan_host_limit": 16,
        "scan_concurrency": 2,
        "max_ports": 3,
        "default_ports": (80,),
        "ping_timeout_seconds": 0.1,
        "tcp_timeout_seconds": 0.1,
        "banner_timeout_seconds": 0.1,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def found_device(ip_address: str) -> DeviceResult:
    return DeviceResult(
        ip_address=ip_address,
        hostname="router.example.test",
        mac_address="00:11:22:33:44:55",
        icmp_reachable=True,
        reachable=True,
        open_ports=[OpenPort(port=80, service="http")],
        discovery_methods=["icmp", "tcp", "arp", "reverse_dns"],
        confidence_score=100,
        confidence="high",
    )


async def wait_for_terminal(service: ScanService, scan_id: str):
    for _ in range(100):
        snapshot = await service.get_scan(scan_id)
        if snapshot.status in TERMINAL_SCAN_STATUSES:
            return snapshot
        await asyncio.sleep(0)
    raise AssertionError("scan did not reach a terminal state")


@pytest.mark.asyncio
async def test_job_lifecycle_records_progress_and_sorted_unique_ports() -> None:
    class FakeInspector:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ProbeOptions]] = []

        async def inspect_host(self, ip_address: str, options: ProbeOptions):
            self.calls.append((ip_address, options))
            await asyncio.sleep(0)
            return found_device(ip_address) if ip_address.endswith(".1") else None

    inspector = FakeInspector()
    service = ScanService(settings(), inspector=inspector)
    created = await service.create_scan(
        ScanRequest(subnet="192.0.2.1/30", ports=[443, 80, 443])
    )
    finished = await wait_for_terminal(service, created.id)

    assert finished.status == ScanStatus.COMPLETED
    assert finished.subnet == "192.0.2.0/30"
    assert finished.options.ports == [80, 443]
    assert finished.progress.total_hosts == 2
    assert finished.progress.scanned_hosts == 2
    assert finished.progress.discovered_hosts == 1
    assert finished.progress.percent == 100.0
    assert [result.ip_address for result in finished.results] == ["192.0.2.1"]
    assert {call[0] for call in inspector.calls} == {"192.0.2.1", "192.0.2.2"}

    results = await service.get_results(created.id)
    assert results.count == 1
    assert results.status == ScanStatus.COMPLETED
    await service.shutdown()


@pytest.mark.asyncio
async def test_list_scans_is_newest_first_limited_and_omits_results() -> None:
    class EmptyInspector:
        async def inspect_host(self, ip_address: str, options: ProbeOptions):
            await asyncio.sleep(0)
            return None

    service = ScanService(settings(), inspector=EmptyInspector())
    try:
        first = await service.create_scan(ScanRequest(subnet="192.0.2.1/32"))
        await wait_for_terminal(service, first.id)
        second = await service.create_scan(ScanRequest(subnet="192.0.2.2/32"))
        await wait_for_terminal(service, second.id)
        third = await service.create_scan(ScanRequest(subnet="192.0.2.3/32"))
        await wait_for_terminal(service, third.id)

        recent = await service.list_scans(limit=2)

        assert [scan.id for scan in recent] == [third.id, second.id]
        assert [scan.subnet for scan in recent] == ["192.0.2.3/32", "192.0.2.2/32"]
        assert all(scan.progress.percent == 100.0 for scan in recent)
        assert "results" not in recent[0].model_dump()
        assert "options" not in recent[0].model_dump()
    finally:
        await service.shutdown()


@pytest.mark.asyncio
async def test_cancellation_stops_blocked_mock_probes() -> None:
    class BlockingInspector:
        def __init__(self) -> None:
            self.started = asyncio.Event()
            self.never_finishes = asyncio.Event()

        async def inspect_host(self, ip_address: str, options: ProbeOptions):
            self.started.set()
            await self.never_finishes.wait()
            return None

    inspector = BlockingInspector()
    service = ScanService(settings(scan_concurrency=1), inspector=inspector)
    created = await service.create_scan(ScanRequest(subnet="198.51.100.0/29"))
    await asyncio.wait_for(inspector.started.wait(), timeout=0.5)

    cancelled = await service.cancel_scan(created.id)

    assert cancelled.status == ScanStatus.CANCELLED
    assert cancelled.cancel_requested is True
    assert cancelled.finished_at is not None
    assert cancelled.progress.scanned_hosts == 0
    await service.shutdown()


@pytest.mark.asyncio
async def test_configured_port_and_concurrency_limits_are_enforced() -> None:
    class NeverCalledInspector:
        async def inspect_host(self, ip_address: str, options: ProbeOptions):
            raise AssertionError("validation should happen before scanning")

    service = ScanService(settings(), inspector=NeverCalledInspector())

    with pytest.raises(ScanValidationError) as ports_error:
        await service.create_scan(
            ScanRequest(subnet="192.0.2.1/32", ports=[1, 2, 3, 4])
        )
    assert ports_error.value.code == "port_limit_exceeded"

    with pytest.raises(ScanValidationError) as concurrency_error:
        await service.create_scan(
            ScanRequest(subnet="192.0.2.0/30", concurrency=3)
        )
    assert concurrency_error.value.code == "concurrency_limit_exceeded"
    await service.shutdown()
