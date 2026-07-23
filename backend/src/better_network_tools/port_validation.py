"""Validation and normalization for NetPorts targets and TCP port expressions."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_LIKE = re.compile(r"^[0-9.]+$")
_PORT_TOKEN = re.compile(r"^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$")


class PortValidationError(ValueError):
    """A stable NetPorts validation failure suitable for an API response."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context

    def as_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.context}


@dataclass(frozen=True, slots=True)
class ValidatedPortTarget:
    display: str
    lookup: str
    address: str | None


@dataclass(frozen=True, slots=True)
class ValidatedPortSpec:
    canonical: str
    ports: tuple[int, ...]


def _invalid_target(target: str, reason: str) -> PortValidationError:
    return PortValidationError(
        "invalid_port_target",
        f"target {reason}",
        target=target,
    )


def validate_scannable_address(
    value: str, *, target: str | None = None
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return a canonical TCP destination while rejecting unusable address scopes."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PortValidationError(
            "invalid_resolved_address",
            "the target resolver returned an invalid IP address",
            target=target or value,
        ) from exc

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped

    unsafe_reason: str | None = None
    if address.is_unspecified:
        unsafe_reason = "must not be an unspecified address"
    elif address.is_multicast:
        unsafe_reason = "must not be a multicast address"
    elif address.version == 4 and int(address) == 0xFFFFFFFF:
        unsafe_reason = "must not be the IPv4 limited broadcast address"
    elif address.version == 6 and address.is_link_local:
        unsafe_reason = "must not be an unscoped IPv6 link-local address"

    if unsafe_reason is not None:
        raise PortValidationError(
            "unsafe_port_target",
            f"target {unsafe_reason}",
            target=target or value,
        )
    return address


def validate_port_target(target: str) -> ValidatedPortTarget:
    """Validate one hostname or IP address without performing DNS resolution."""

    display = target.strip()
    if not display:
        raise _invalid_target(target, "must not be empty")
    if display.startswith("-"):
        raise _invalid_target(display, "must not be option-like")
    if any(character.isspace() for character in display):
        raise _invalid_target(display, "must not contain whitespace")
    if any(marker in display for marker in ("://", "/", "\\", "?", "#", "@")):
        raise _invalid_target(display, "must be an IP address or hostname")
    if "%" in display:
        raise _invalid_target(display, "must not contain an IPv6 scope ID")

    try:
        parsed = ipaddress.ip_address(display)
    except ValueError:
        parsed = None

    if parsed is not None:
        address = validate_scannable_address(parsed.compressed, target=display)
        return ValidatedPortTarget(
            display=display,
            lookup=address.compressed,
            address=address.compressed,
        )

    if ":" in display or _IPV4_LIKE.fullmatch(display):
        raise _invalid_target(display, "is not a valid IP address")

    hostname = display[:-1] if display.endswith(".") else display
    if not hostname or len(hostname) > 253:
        raise _invalid_target(display, "is not a valid hostname")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _invalid_target(display, "is not a valid hostname") from exc
    if len(ascii_hostname) > 253:
        raise _invalid_target(display, "is not a valid hostname")
    if any(not _HOST_LABEL.fullmatch(label) for label in ascii_hostname.split(".")):
        raise _invalid_target(display, "is not a valid hostname")

    return ValidatedPortTarget(
        display=display,
        lookup=ascii_hostname.lower(),
        address=None,
    )


def parse_port_spec(spec: str, *, port_limit: int) -> ValidatedPortSpec:
    """Parse a comma-separated list of ports/ranges and return sorted unique ports."""

    raw = spec.strip()
    if not raw:
        raise PortValidationError(
            "invalid_port_spec", "the TCP port expression must not be empty"
        )

    intervals: list[tuple[int, int]] = []
    for index, raw_token in enumerate(raw.split(",")):
        token = raw_token.strip()
        match = _PORT_TOKEN.fullmatch(token)
        if match is None:
            raise PortValidationError(
                "invalid_port_spec",
                f"port entry {index + 1} must be a port or inclusive range",
                entry=raw_token,
                index=index,
            )
        start = int(match.group(1))
        end = int(match.group(2) or start)
        if not 1 <= start <= 65535 or not 1 <= end <= 65535:
            raise PortValidationError(
                "invalid_port_spec",
                f"port entry {index + 1} must stay between 1 and 65535",
                entry=token,
                index=index,
            )
        if start > end:
            raise PortValidationError(
                "invalid_port_spec",
                f"port entry {index + 1} has a descending range",
                entry=token,
                index=index,
            )

        intervals.append((start, end))

    if not intervals:
        raise PortValidationError(
            "invalid_port_spec", "at least one TCP port is required"
        )

    intervals.sort()
    merged: list[tuple[int, int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1] + 1:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))

    total = sum(end - start + 1 for start, end in merged)
    if total > port_limit:
        raise PortValidationError(
            "port_limit_exceeded",
            f"NetPorts jobs may scan at most {port_limit} unique TCP ports",
            limit=port_limit,
            actual=total,
        )

    ports = tuple(
        port for start, end in merged for port in range(start, end + 1)
    )
    return ValidatedPortSpec(canonical=format_port_spec(ports), ports=ports)


def format_port_spec(ports: tuple[int, ...]) -> str:
    """Collapse sorted ports into a stable compact inclusive-range expression."""

    ranges: list[str] = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)
