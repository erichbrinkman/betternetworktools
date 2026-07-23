"""Validation and normalization for NetTrace targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_LIKE = re.compile(r"^[0-9.]+$")


class TraceValidationError(ValueError):
    """A stable validation failure suitable for an API error response."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context

    def as_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.context}


@dataclass(frozen=True, slots=True)
class ValidatedTraceTarget:
    display: str
    lookup: str
    address: str | None


def _invalid(target: str, reason: str) -> TraceValidationError:
    return TraceValidationError(
        "invalid_trace_target",
        f"target {reason}",
        target=target,
    )


def validate_traceable_address(
    value: str, *, target: str | None = None
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Return a canonical, safe native-command destination address."""

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TraceValidationError(
            "invalid_resolved_address",
            "the target resolver returned an invalid IP address",
            target=target or value,
        ) from exc

    unsafe_reason: str | None = None
    if address.is_unspecified:
        unsafe_reason = "must not be an unspecified address"
    elif address.is_multicast:
        unsafe_reason = "must not be a multicast address"
    elif address.version == 4 and int(address) == 0xFFFFFFFF:
        unsafe_reason = "must not be the IPv4 limited broadcast address"
    elif address.version == 6 and address.is_link_local:
        # A useful IPv6 link-local destination requires an interface scope ID,
        # which NetTrace deliberately rejects as platform-specific argv input.
        unsafe_reason = "must not be an unscoped IPv6 link-local address"

    if unsafe_reason is not None:
        raise TraceValidationError(
            "unsafe_trace_target",
            f"target {unsafe_reason}",
            target=target or value,
        )
    return address


def validate_trace_target(target: str) -> ValidatedTraceTarget:
    """Validate one IP address or hostname without resolving a hostname."""

    display = target.strip()
    if not display:
        raise _invalid(target, "must not be empty")
    if display.startswith("-"):
        raise _invalid(display, "must not be option-like")
    if any(character.isspace() for character in display):
        raise _invalid(display, "must not contain whitespace")
    if any(marker in display for marker in ("://", "/", "\\", "?", "#", "@")):
        raise _invalid(display, "must be an IP address or hostname")
    if "%" in display:
        raise _invalid(display, "must not contain an IPv6 scope ID")

    try:
        parsed = ipaddress.ip_address(display)
    except ValueError:
        parsed = None

    if parsed is not None:
        address = validate_traceable_address(parsed.compressed, target=display)
        return ValidatedTraceTarget(
            display=display,
            lookup=address.compressed,
            address=address.compressed,
        )

    if ":" in display or _IPV4_LIKE.fullmatch(display):
        raise _invalid(display, "is not a valid IP address")

    hostname = display[:-1] if display.endswith(".") else display
    if not hostname or len(hostname) > 253:
        raise _invalid(display, "is not a valid hostname")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _invalid(display, "is not a valid hostname") from exc
    if len(ascii_hostname) > 253:
        raise _invalid(display, "is not a valid hostname")
    if any(not _HOST_LABEL.fullmatch(label) for label in ascii_hostname.split(".")):
        raise _invalid(display, "is not a valid hostname")

    return ValidatedTraceTarget(
        display=display,
        lookup=ascii_hostname.lower(),
        address=None,
    )
