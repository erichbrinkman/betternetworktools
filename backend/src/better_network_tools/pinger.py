"""Cross-platform native ping probing and one-time hostname resolution."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import platform
import re
import socket
from dataclasses import dataclass
from typing import Protocol

from .models import PingAddressFamily
from .network import CommandRunner, run_command
from .ping_output import (
    native_ping_received,
    parse_ping_latency,
    parse_windows_ping_latency,
)


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")


@dataclass(frozen=True, slots=True)
class ResolvedPingTarget:
    address: str
    address_family: PingAddressFamily


@dataclass(frozen=True, slots=True)
class PingProbeResult:
    received: bool
    latency_ms: float | None = None
    error: str | None = None


class PingResolver(Protocol):
    async def resolve(self, hostname: str) -> ResolvedPingTarget: ...


class ReverseDNSResolver(Protocol):
    async def resolve(
        self, address: str, address_family: PingAddressFamily
    ) -> str: ...


class PingProbe(Protocol):
    async def probe(
        self, address: str, address_family: PingAddressFamily, timeout: float
    ) -> PingProbeResult: ...


class SystemPingResolver:
    """Resolve a hostname once, retaining the operating system's address order."""

    async def resolve(self, hostname: str) -> ResolvedPingTarget:
        try:
            records = await asyncio.to_thread(
                socket.getaddrinfo,
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_DGRAM,
            )
        except (OSError, socket.gaierror) as exc:
            raise OSError(f"could not resolve {hostname}") from exc

        for family, _socktype, _protocol, _canonical_name, socket_address in records:
            if family == socket.AF_INET:
                address = ipaddress.ip_address(socket_address[0]).compressed
                return ResolvedPingTarget(address=address, address_family="IPv4")
            if family == socket.AF_INET6:
                parsed_address = ipaddress.ip_address(socket_address[0])
                if parsed_address.is_link_local:
                    # A getaddrinfo sockaddr may require a platform-specific scope
                    # ID. Skip it in favor of a globally usable result.
                    continue
                address = parsed_address.compressed
                return ResolvedPingTarget(address=address, address_family="IPv6")
        raise OSError(f"could not resolve {hostname} to an IPv4 or IPv6 address")


class SystemReverseDNSResolver:
    """Perform a required-name PTR lookup without blocking the event loop."""

    async def resolve(
        self, address: str, address_family: PingAddressFamily
    ) -> str:
        socket_address: tuple[str, int] | tuple[str, int, int, int]
        if address_family == "IPv6":
            socket_address = (address, 0, 0, 0)
        else:
            socket_address = (address, 0)

        hostname, _service = await asyncio.to_thread(
            socket.getnameinfo,
            socket_address,
            socket.NI_NAMEREQD | socket.NI_NUMERICSERV,
        )
        return hostname


def ping_job_arguments(
    address: str,
    address_family: PingAddressFamily,
    timeout: float,
    platform_name: str | None = None,
) -> tuple[str, ...]:
    """Build a fixed one-sample native ping argument vector for an address family."""

    system = (platform_name or platform.system()).lower()
    if system == "windows":
        family_flag = "-6" if address_family == "IPv6" else "-4"
        return (
            "ping",
            family_flag,
            "-n",
            "1",
            "-w",
            str(max(1, math.ceil(timeout * 1000))),
            address,
        )
    if system == "darwin":
        executable = "ping6" if address_family == "IPv6" else "ping"
        if address_family == "IPv6":
            # macOS ping6 uses -W for a Node Information query, not a timeout.
            # The outer subprocess timeout remains the hard echo deadline.
            return (executable, "-n", "-c", "1", address)
        return (
            executable,
            "-n",
            "-c",
            "1",
            "-W",
            str(max(1, math.ceil(timeout * 1000))),
            address,
        )

    family_flag = "-6" if address_family == "IPv6" else "-4"
    return (
        "ping",
        family_flag,
        "-n",
        "-c",
        "1",
        "-W",
        format(timeout, "g"),
        address,
    )


def _clean_command_detail(detail: str) -> str:
    return _CONTROL_CHARACTERS.sub(" ", detail).strip()[:200]


class NativePingProbe:
    """Run one native ping command without invoking a shell."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.platform_name = (platform_name or platform.system()).lower()
        self.command_runner = command_runner or run_command

    async def probe(
        self, address: str, address_family: PingAddressFamily, timeout: float
    ) -> PingProbeResult:
        arguments = ping_job_arguments(
            address, address_family, timeout, self.platform_name
        )
        result = await self.command_runner(arguments, timeout + 0.75)
        output = f"{result.stdout}\n{result.stderr}"
        if result.returncode == 0:
            latency = (
                parse_windows_ping_latency(output)
                if self.platform_name == "windows"
                else parse_ping_latency(output)
            )
            if not native_ping_received(
                returncode=result.returncode,
                output=output,
                platform_name=self.platform_name,
            ):
                return PingProbeResult(received=False)
            return PingProbeResult(
                received=True,
                latency_ms=latency,
            )
        no_reply_codes = {1, 124}
        if self.platform_name == "darwin":
            no_reply_codes.add(2)
        if result.returncode in no_reply_codes:
            return PingProbeResult(received=False)

        detail = _clean_command_detail(result.stderr or result.stdout)
        if result.returncode == 127:
            message = "native ping command is unavailable"
        else:
            message = f"native ping exited with status {result.returncode}"
        if detail:
            message = f"{message}: {detail[:200]}"
        return PingProbeResult(received=False, error=message)
