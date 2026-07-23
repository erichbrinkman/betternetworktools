"""Cross-platform native traceroute command construction and output parsing."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import math
import platform
import re
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, replace
from typing import Protocol

from .models import TraceAddressFamily, TraceProbeStatus


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_HOP_LINE = re.compile(r"^\s*(\d{1,3})\s+(.+?)\s*$")
_LATENCY_TOKEN = re.compile(
    r"^(?P<censored><)?(?P<value>\d+(?:[.,]\d+)?)(?:ms)?$", re.IGNORECASE
)
_UNREACHABLE_ANNOTATIONS = {
    "!H",
    "!N",
    "!P",
    "!S",
    "!U",
    "!W",
    "!X",
    "!A",
    "!C",
    "!I",
    "!Z",
    "!Q",
    "!T",
    "!V",
}
_UNREACHABLE_ANNOTATION_PATTERN = re.compile(
    r"^(?:!F(?:-\d+)?|!\d+|!<\d+>)$", re.IGNORECASE
)
_OUTPUT_LIMIT = 65_536


@dataclass(frozen=True, slots=True)
class TraceCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False


class TraceCommandCancelled(asyncio.CancelledError):
    """Cancellation carrying the bounded output captured before process exit."""

    def __init__(self, result: TraceCommandResult) -> None:
        super().__init__("native traceroute command was cancelled")
        self.result = result


TraceCommandRunner = Callable[
    [Sequence[str], float], Awaitable[TraceCommandResult]
]


@dataclass(frozen=True, slots=True)
class TraceProbeObservation:
    sequence: int
    address: str | None
    latency_ms: float | None
    status: TraceProbeStatus
    annotation: str | None = None


@dataclass(frozen=True, slots=True)
class TraceHopObservation:
    number: int
    probes: tuple[TraceProbeObservation, ...]


@dataclass(frozen=True, slots=True)
class NativeTraceResult:
    hops: tuple[TraceHopObservation, ...]
    returncode: int
    timed_out: bool = False
    output_truncated: bool = False
    error_detail: str | None = None


class NativeTraceCancelled(asyncio.CancelledError):
    """Cancellation carrying parsed hops emitted before the command was killed."""

    def __init__(self, result: NativeTraceResult) -> None:
        super().__init__("native trace was cancelled")
        self.result = result


class TraceRunner(Protocol):
    async def trace(
        self,
        address: str,
        address_family: TraceAddressFamily,
        *,
        max_hops: int,
        timeout: float,
        probes_per_hop: int,
        total_timeout: float,
    ) -> NativeTraceResult: ...


async def run_trace_command(
    arguments: Sequence[str], timeout: float
) -> TraceCommandResult:
    """Execute a fixed traceroute argv without a shell and with bounded output."""

    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, OSError) as exc:
        return TraceCommandResult(returncode=127, stderr=str(exc))

    async def drain_bounded(
        stream: asyncio.StreamReader | None,
    ) -> tuple[bytes, bool]:
        if stream is None:  # pragma: no cover - PIPE always supplies a reader
            return b"", False
        captured = bytearray()
        truncated = False
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            remaining = _OUTPUT_LIMIT - len(captured)
            if remaining > 0:
                captured.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
        return bytes(captured), truncated

    stdout_task = asyncio.create_task(drain_bounded(process.stdout))
    stderr_task = asyncio.create_task(drain_bounded(process.stderr))
    returncode: int
    try:
        async with asyncio.timeout(timeout):
            await process.wait()
        returncode = process.returncode or 0
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        returncode = 124
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.wait()
        (stdout_bytes, stdout_truncated), (stderr_bytes, stderr_truncated) = (
            await asyncio.gather(stdout_task, stderr_task)
        )
        raise TraceCommandCancelled(
            TraceCommandResult(
                returncode=130,
                stdout=stdout_bytes.decode(errors="replace"),
                stderr=stderr_bytes.decode(errors="replace"),
                output_truncated=stdout_truncated or stderr_truncated,
            )
        ) from None

    (stdout_bytes, stdout_truncated), (stderr_bytes, stderr_truncated) = (
        await asyncio.gather(stdout_task, stderr_task)
    )
    return TraceCommandResult(
        returncode=returncode,
        stdout=stdout_bytes.decode(errors="replace"),
        stderr=stderr_bytes.decode(errors="replace"),
        output_truncated=stdout_truncated or stderr_truncated,
    )


def native_trace_arguments(
    address: str,
    address_family: TraceAddressFamily,
    *,
    max_hops: int,
    timeout: float,
    probes_per_hop: int = 3,
    platform_name: str | None = None,
) -> tuple[str, ...]:
    """Build a fixed numeric-output traceroute argv for macOS, Windows, or Linux."""

    system = (platform_name or platform.system()).lower()
    if system == "windows":
        family_flag = "-6" if address_family == "IPv6" else "-4"
        # tracert always sends three probes at each TTL; probes_per_hop is kept
        # fixed in the public contract so Windows and Unix results match.
        return (
            "tracert",
            "-d",
            family_flag,
            "-h",
            str(max_hops),
            "-w",
            str(max(1, math.ceil(timeout * 1000))),
            address,
        )

    wait_value = (
        str(max(1, math.ceil(timeout)))
        if system == "darwin"
        else format(timeout, "g")
    )
    common = (
        "-n",
        "-m",
        str(max_hops),
        "-q",
        str(probes_per_hop),
        "-w",
        wait_value,
        address,
    )
    if system == "darwin":
        executable = "traceroute6" if address_family == "IPv6" else "traceroute"
        return (executable, *common)
    family_flag = "-6" if address_family == "IPv6" else "-4"
    return ("traceroute", family_flag, *common)


def _parse_address(token: str) -> str | None:
    candidate = token.strip("()[],").partition("%")[0]
    # ipaddress accepts short decimal integers as IPv4 addresses. Native
    # numeric traceroute output always includes a dot or colon, so require one.
    if "." not in candidate and ":" not in candidate:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def _parse_latency(token: str) -> float | None:
    match = _LATENCY_TOKEN.fullmatch(token)
    if not match:
        return None
    value = float(match.group("value").replace(",", "."))
    if match.group("censored"):
        return value / 2
    return value


def parse_trace_line(
    line: str, *, probes_per_hop: int = 3
) -> TraceHopObservation | None:
    """Parse one numeric traceroute/tracert hop line without localized headers."""

    cleaned_line = _CONTROL_CHARACTERS.sub(" ", line[:4096])
    match = _HOP_LINE.match(cleaned_line)
    if not match:
        return None
    hop_number = int(match.group(1))
    if not 1 <= hop_number <= 64:
        return None

    tokens = match.group(2).split()
    probes: list[TraceProbeObservation] = []
    addresses: list[str] = []
    current_address: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        address = _parse_address(token)
        if address is not None:
            current_address = address
            if address not in addresses:
                addresses.append(address)
            index += 1
            continue
        if token == "*":
            if len(probes) < probes_per_hop:
                probes.append(
                    TraceProbeObservation(
                        sequence=len(probes) + 1,
                        address=None,
                        latency_ms=None,
                        status="timeout",
                    )
                )
            index += 1
            continue

        latency = _parse_latency(token)
        if latency is not None:
            if index + 1 < len(tokens) and tokens[index + 1].lower() == "ms":
                index += 1
            if len(probes) < probes_per_hop:
                probes.append(
                    TraceProbeObservation(
                        sequence=len(probes) + 1,
                        address=current_address,
                        latency_ms=latency,
                        status="reply",
                    )
                )
            index += 1
            continue

        annotation = token.rstrip(",")
        if annotation.startswith("!") and probes:
            previous = probes[-1]
            unreachable = (
                annotation.upper() in _UNREACHABLE_ANNOTATIONS
                or _UNREACHABLE_ANNOTATION_PATTERN.fullmatch(annotation) is not None
            )
            status: TraceProbeStatus = (
                "unreachable" if unreachable else previous.status
            )
            probes[-1] = replace(
                previous,
                status=status,
                annotation=annotation[:32],
            )
        index += 1

    if not probes:
        return None

    # Windows prints the single responder after all RTT columns. Backfill only
    # when the line contains one unambiguous address; Unix ECMP lines assign
    # addresses as they are encountered and retain that per-probe distinction.
    if len(addresses) == 1:
        probes = [
            replace(probe, address=addresses[0])
            if probe.status != "timeout" and probe.address is None
            else probe
            for probe in probes
        ]

    while len(probes) < probes_per_hop:
        probes.append(
            TraceProbeObservation(
                sequence=len(probes) + 1,
                address=None,
                latency_ms=None,
                status="timeout",
            )
        )
    return TraceHopObservation(number=hop_number, probes=tuple(probes))


def parse_trace_output(
    output: str, *, probes_per_hop: int = 3
) -> tuple[TraceHopObservation, ...]:
    """Parse native output, replacing duplicate hop lines with their latest value."""

    by_hop: dict[int, TraceHopObservation] = {}
    for line in output.splitlines():
        hop = parse_trace_line(line, probes_per_hop=probes_per_hop)
        if hop is not None:
            by_hop[hop.number] = hop
    return tuple(by_hop[number] for number in sorted(by_hop))


def _clean_detail(value: str) -> str | None:
    cleaned = _CONTROL_CHARACTERS.sub(" ", value).strip()
    return cleaned[:240] or None


class NativeTracer:
    """Run the platform traceroute command and parse its bounded numeric output."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        command_runner: TraceCommandRunner | None = None,
    ) -> None:
        self.platform_name = (platform_name or platform.system()).lower()
        self.command_runner = command_runner or run_trace_command

    async def trace(
        self,
        address: str,
        address_family: TraceAddressFamily,
        *,
        max_hops: int,
        timeout: float,
        probes_per_hop: int,
        total_timeout: float,
    ) -> NativeTraceResult:
        arguments = native_trace_arguments(
            address,
            address_family,
            max_hops=max_hops,
            timeout=timeout,
            probes_per_hop=probes_per_hop,
            platform_name=self.platform_name,
        )
        try:
            result = await self.command_runner(arguments, total_timeout)
        except TraceCommandCancelled as exc:
            cancelled_result = self._parse_result(
                exc.result, probes_per_hop=probes_per_hop
            )
            raise NativeTraceCancelled(cancelled_result) from exc
        return self._parse_result(result, probes_per_hop=probes_per_hop)

    @staticmethod
    def _parse_result(
        result: TraceCommandResult, *, probes_per_hop: int
    ) -> NativeTraceResult:
        hops = parse_trace_output(
            f"{result.stdout}\n{result.stderr}", probes_per_hop=probes_per_hop
        )
        return NativeTraceResult(
            hops=hops,
            returncode=result.returncode,
            timed_out=result.returncode == 124,
            output_truncated=result.output_truncated,
            error_detail=_clean_detail(result.stderr or result.stdout),
        )
