"""Cross-platform, best-effort asynchronous network fingerprinting primitives."""

from __future__ import annotations

import asyncio
import contextlib
import math
import platform
import re
import socket
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from .models import ConfidenceLevel, DeviceResult, DiscoveryMethod, OpenPort
from .ping_output import native_ping_received


_MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}(?![0-9a-f])"
)
_HTTP_STATUS_PATTERN = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)
_HTTP_SERVER_PATTERN = re.compile(r"^Server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")

_SERVICE_NAMES: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}
_PLAIN_HTTP_PORTS = frozenset({80, 8000, 8080, 8888, 9200})
# DNS traffic is commonly redirected by VPN clients and endpoint network filters.
# A successful TCP/53 connection can therefore identify the local interceptor rather
# than the requested address. Keep the observation for known hosts, but do not let it
# create a host result by itself.
_NON_AUTHORITATIVE_DISCOVERY_PORTS = frozenset({53})


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[Sequence[str], float], Awaitable[CommandResult]]
Resolver = Callable[[str], tuple[str, list[str], list[str]]]


@dataclass(frozen=True, slots=True)
class ProbeOptions:
    ports: tuple[int, ...]
    timeout: float
    ping_timeout: float
    banner_timeout: float
    resolve_dns: bool
    collect_banners: bool


class HostInspector(Protocol):
    async def inspect_host(
        self, ip_address: str, options: ProbeOptions
    ) -> DeviceResult | None: ...


def service_name_for_port(port: int) -> str | None:
    """Return a best-effort conventional TCP service hint for a port."""

    return _SERVICE_NAMES.get(port)


async def collect_open_port_evidence(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ip_address: str,
    port: int,
    *,
    banner_timeout: float,
    collect_banner: bool,
) -> OpenPort:
    """Collect bounded hints from an already-open TCP connection."""

    banner: str | None = None
    http_status: int | None = None
    http_server: str | None = None
    try:
        if collect_banner:
            if port in _PLAIN_HTTP_PORTS:
                host_header = f"[{ip_address}]" if ":" in ip_address else ip_address
                request = (
                    f"HEAD / HTTP/1.0\r\nHost: {host_header}\r\n"
                    "User-Agent: Better-Network-Tools/0.1\r\nConnection: close\r\n\r\n"
                )
                writer.write(request.encode("ascii"))
                await asyncio.wait_for(writer.drain(), timeout=banner_timeout)
            data = await asyncio.wait_for(reader.read(1024), timeout=banner_timeout)
            if data:
                decoded = data.decode("utf-8", errors="replace")
                first_line = decoded.splitlines()[0].strip() if decoded.splitlines() else ""
                cleaned_line = _CONTROL_CHARACTERS.sub(" ", first_line).strip()
                banner = cleaned_line[:240] or None
                status_match = _HTTP_STATUS_PATTERN.search(decoded)
                if status_match:
                    candidate_status = int(status_match.group(1))
                    if 100 <= candidate_status <= 599:
                        http_status = candidate_status
                server_match = _HTTP_SERVER_PATTERN.search(decoded)
                if server_match:
                    cleaned_server = _CONTROL_CHARACTERS.sub(
                        " ", server_match.group(1)
                    ).strip()
                    http_server = cleaned_server[:240] or None
    except (TimeoutError, ConnectionError, OSError, UnicodeError):
        # The successful connection remains useful even if enrichment fails.
        pass

    return OpenPort(
        port=port,
        service=service_name_for_port(port),
        banner=banner,
        http_status=http_status,
        http_server=http_server,
    )


async def run_command(arguments: Sequence[str], timeout: float) -> CommandResult:
    """Execute a fixed argument vector without a shell and with a hard timeout."""

    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as exc:
        return CommandResult(returncode=127, stderr=str(exc))

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        stdout_bytes, stderr_bytes = await process.communicate()
        return CommandResult(
            returncode=124,
            stdout=stdout_bytes[:8192].decode(errors="replace"),
            stderr=stderr_bytes[:8192].decode(errors="replace"),
        )
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise

    return CommandResult(
        returncode=process.returncode or 0,
        stdout=stdout_bytes[:8192].decode(errors="replace"),
        stderr=stderr_bytes[:8192].decode(errors="replace"),
    )


def ping_arguments(
    ip_address: str, timeout: float, platform_name: str | None = None
) -> tuple[str, ...]:
    """Build the native one-packet ping invocation for Windows, macOS, or Linux."""

    system = (platform_name or platform.system()).lower()
    if system == "windows":
        return ("ping", "-n", "1", "-w", str(max(1, math.ceil(timeout * 1000))), ip_address)
    if system == "darwin":
        return ("ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout * 1000))), ip_address)
    return ("ping", "-n", "-c", "1", "-W", str(max(1, math.ceil(timeout))), ip_address)


def parse_mac_address(output: str, ip_address: str | None = None) -> str | None:
    """Extract a usable target-bound MAC address from native ARP output."""

    candidate_output = output
    if ip_address is not None:
        target_pattern = re.compile(
            rf"(?<![0-9.]){re.escape(ip_address)}(?![0-9.])"
        )
        candidate_output = "\n".join(
            line for line in output.splitlines() if target_pattern.search(line)
        )

    match = _MAC_PATTERN.search(candidate_output)
    if not match:
        return None
    normalized = ":".join(
        segment.zfill(2)
        for segment in match.group(0).replace("-", ":").split(":")
    ).upper()
    if normalized in {"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"}:
        return None
    return normalized


def calculate_confidence(
    *, icmp: bool, tcp: bool, arp: bool, reverse_dns: bool
) -> tuple[int, ConfidenceLevel]:
    """Return a deterministic confidence score from independent evidence.

    Weights are deliberately stable API behavior: ICMP=45, TCP=35, ARP=30,
    reverse DNS=10, capped at 100. Scores >=75 are high and >=40 are medium.
    """

    score = min(
        100,
        (45 if icmp else 0)
        + (35 if tcp else 0)
        + (30 if arp else 0)
        + (10 if reverse_dns else 0),
    )
    if score >= 75:
        level: ConfidenceLevel = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"
    return score, level


class NetworkProber:
    """Collect host evidence while treating every probe as best effort."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        command_runner: CommandRunner | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.platform_name = (platform_name or platform.system()).lower()
        self.command_runner = command_runner or run_command
        self.resolver = resolver or socket.gethostbyaddr

    async def icmp_reachable(self, ip_address: str, timeout: float) -> bool:
        arguments = ping_arguments(ip_address, timeout, self.platform_name)
        result = await self.command_runner(arguments, timeout + 0.75)
        return native_ping_received(
            returncode=result.returncode,
            output=f"{result.stdout}\n{result.stderr}",
            platform_name=self.platform_name,
        )

    async def reverse_dns(self, ip_address: str, timeout: float) -> str | None:
        try:
            hostname, _aliases, _addresses = await asyncio.wait_for(
                asyncio.to_thread(self.resolver, ip_address), timeout=timeout
            )
        except (TimeoutError, OSError, socket.herror, socket.gaierror):
            return None
        cleaned = hostname.strip().rstrip(".")
        return cleaned if cleaned and cleaned != ip_address else None

    async def arp_mac(self, ip_address: str, timeout: float) -> str | None:
        if self.platform_name == "windows":
            commands = [("arp", "-a", ip_address)]
        elif self.platform_name == "linux":
            commands = [("ip", "neigh", "show", ip_address), ("arp", "-n", ip_address)]
        else:
            commands = [("arp", "-n", ip_address)]

        for arguments in commands:
            result = await self.command_runner(arguments, timeout)
            mac_address = parse_mac_address(
                f"{result.stdout}\n{result.stderr}", ip_address
            )
            if mac_address is not None:
                return mac_address
        return None

    async def tcp_port(
        self,
        ip_address: str,
        port: int,
        *,
        timeout: float,
        banner_timeout: float,
        collect_banner: bool,
    ) -> OpenPort | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip_address, port), timeout=timeout
            )
        except (TimeoutError, ConnectionError, OSError):
            return None

        try:
            return await collect_open_port_evidence(
                reader,
                writer,
                ip_address,
                port,
                banner_timeout=banner_timeout,
                collect_banner=collect_banner,
            )
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError, TimeoutError):
                await asyncio.wait_for(
                    writer.wait_closed(), timeout=min(1.0, max(0.05, banner_timeout))
                )

    async def inspect_host(
        self, ip_address: str, options: ProbeOptions
    ) -> DeviceResult | None:
        ping_task = asyncio.create_task(
            self.icmp_reachable(ip_address, options.ping_timeout)
        )
        dns_task: asyncio.Task[str | None] | None = None
        if options.resolve_dns:
            dns_task = asyncio.create_task(self.reverse_dns(ip_address, options.timeout))
        port_tasks = [
            asyncio.create_task(
                self.tcp_port(
                    ip_address,
                    port,
                    timeout=options.timeout,
                    banner_timeout=options.banner_timeout,
                    collect_banner=options.collect_banners,
                )
            )
            for port in options.ports
        ]

        all_tasks: list[asyncio.Task[object]] = [ping_task]
        if dns_task is not None:
            all_tasks.append(dns_task)
        all_tasks.extend(port_tasks)
        gathered = await asyncio.gather(*all_tasks, return_exceptions=True)
        icmp_reachable = gathered[0] if isinstance(gathered[0], bool) else False
        port_result_offset = 2 if dns_task is not None else 1
        open_ports = sorted(
            (
                item
                for item in gathered[port_result_offset:]
                if isinstance(item, OpenPort)
            ),
            key=lambda item: item.port,
        )

        hostname: str | None = None
        if dns_task is not None:
            dns_result = gathered[1]
            hostname = dns_result if isinstance(dns_result, str) else None

        mac_address = await self.arp_mac(ip_address, options.timeout)
        has_tcp = any(
            entry.port not in _NON_AUTHORITATIVE_DISCOVERY_PORTS
            for entry in open_ports
        )
        has_arp = mac_address is not None
        if not (icmp_reachable or has_tcp or has_arp):
            return None

        discovery_methods: list[DiscoveryMethod] = []
        if icmp_reachable:
            discovery_methods.append("icmp")
        if has_tcp:
            discovery_methods.append("tcp")
        if has_arp:
            discovery_methods.append("arp")
        if hostname:
            discovery_methods.append("reverse_dns")

        confidence_score, confidence = calculate_confidence(
            icmp=icmp_reachable,
            tcp=has_tcp,
            arp=has_arp,
            reverse_dns=hostname is not None,
        )
        return DeviceResult(
            ip_address=ip_address,
            hostname=hostname,
            mac_address=mac_address,
            icmp_reachable=icmp_reachable,
            reachable=True,
            open_ports=open_ports,
            discovery_methods=cast(list[DiscoveryMethod], discovery_methods),
            confidence_score=confidence_score,
            confidence=confidence,
        )
