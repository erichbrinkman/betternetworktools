"""Pure-Python TCP connect probes used by NetPorts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import errno
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Literal, Protocol

from .models import PortResult
from .network import collect_open_port_evidence
from .pinger import ResolvedPingTarget


PortProbeState = Literal["open", "closed", "timed_out", "error"]


@dataclass(frozen=True, slots=True)
class PortProbeObservation:
    state: PortProbeState
    result: PortResult | None = None


class PortProbe(Protocol):
    async def probe(
        self,
        address: str,
        address_family: Literal["IPv4", "IPv6"],
        port: int,
        *,
        timeout: float,
        banner_timeout: float,
        collect_banner: bool,
    ) -> PortProbeObservation: ...


class BoundedSystemPortResolver:
    """Resolve NetPorts hostnames in a private, fixed-size executor."""

    def __init__(self, *, workers: int) -> None:
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, workers),
            thread_name_prefix="netport-dns",
        )

    async def resolve(self, hostname: str) -> ResolvedPingTarget:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.run_in_executor(
                self._executor, self._resolve_records, hostname
            )
        except (OSError, socket.gaierror) as exc:
            raise OSError(f"could not resolve {hostname}") from exc

        for family, socket_address in records:
            if family == socket.AF_INET:
                address = ipaddress.ip_address(socket_address[0]).compressed
                return ResolvedPingTarget(address=address, address_family="IPv4")
            if family == socket.AF_INET6:
                parsed_address = ipaddress.ip_address(socket_address[0])
                if parsed_address.is_link_local:
                    continue
                return ResolvedPingTarget(
                    address=parsed_address.compressed,
                    address_family="IPv6",
                )
        raise OSError(f"could not resolve {hostname} to an IPv4 or IPv6 address")

    @staticmethod
    def _resolve_records(hostname: str) -> list[tuple[int, tuple[object, ...]]]:
        records = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )
        return [
            (family, tuple(socket_address))
            for family, _socktype, _protocol, _canonical_name, socket_address in records
            if family in {socket.AF_INET, socket.AF_INET6}
        ]

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class TcpConnectPortProbe:
    """Classify one bounded, unprivileged TCP connection attempt."""

    async def probe(
        self,
        address: str,
        address_family: Literal["IPv4", "IPv6"],
        port: int,
        *,
        timeout: float,
        banner_timeout: float,
        collect_banner: bool,
    ) -> PortProbeObservation:
        family = socket.AF_INET if address_family == "IPv4" else socket.AF_INET6
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    port,
                    family=family,
                    flags=socket.AI_NUMERICHOST,
                ),
                timeout=timeout,
            )
        except TimeoutError:
            return PortProbeObservation(state="timed_out")
        except (ConnectionRefusedError, ConnectionResetError):
            return PortProbeObservation(state="closed")
        except OSError as exc:
            if exc.errno in {errno.ECONNREFUSED, errno.ECONNRESET}:
                return PortProbeObservation(state="closed")
            if exc.errno == errno.ETIMEDOUT:
                return PortProbeObservation(state="timed_out")
            return PortProbeObservation(state="error")

        latency_ms = max(0.0, round((time.perf_counter() - started) * 1000, 3))
        try:
            evidence = await collect_open_port_evidence(
                reader,
                writer,
                address,
                port,
                banner_timeout=banner_timeout,
                collect_banner=collect_banner,
            )
            return PortProbeObservation(
                state="open",
                result=PortResult(
                    port=evidence.port,
                    service=evidence.service,
                    banner=evidence.banner,
                    http_status=evidence.http_status,
                    http_server=evidence.http_server,
                    latency_ms=latency_ms,
                ),
            )
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, TimeoutError):
                await asyncio.wait_for(
                    writer.wait_closed(), timeout=min(1.0, max(0.05, banner_timeout))
                )
