"""Validation and normalization for NetPinger targets."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_IPV4_LIKE = re.compile(r"^[0-9.]+$")


class PingValidationError(ValueError):
    """A stable validation failure suitable for an API error response."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context

    def as_detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.context}


@dataclass(frozen=True, slots=True)
class ValidatedPingTarget:
    display: str
    lookup: str
    dedupe_key: str
    address: str | None


def _invalid_target(target: str, index: int, reason: str) -> PingValidationError:
    return PingValidationError(
        "invalid_ping_target",
        f"target at index {index} {reason}",
        index=index,
        target=target,
    )


def validate_ping_target(target: str, index: int = 0) -> ValidatedPingTarget:
    """Validate one IP address or hostname without performing DNS resolution."""

    display = target.strip()
    if not display:
        raise _invalid_target(target, index, "must not be empty")
    if display.startswith("-"):
        raise _invalid_target(display, index, "must not be option-like")
    if any(character.isspace() for character in display):
        raise _invalid_target(display, index, "must not contain whitespace")
    if any(marker in display for marker in ("://", "/", "\\", "?", "#", "@")):
        raise _invalid_target(display, index, "must be an IP address or hostname")
    if "%" in display:
        # Interface-scoped literals are platform-specific and could be interpreted
        # differently by native ping implementations.
        raise _invalid_target(display, index, "must not contain an IPv6 scope ID")

    try:
        address = ipaddress.ip_address(display)
    except ValueError:
        address = None

    if address is not None:
        canonical = address.compressed
        return ValidatedPingTarget(
            display=display,
            lookup=canonical,
            dedupe_key=f"ip:{canonical}",
            address=canonical,
        )

    if ":" in display or _IPV4_LIKE.fullmatch(display):
        raise _invalid_target(display, index, "is not a valid IP address")

    hostname = display[:-1] if display.endswith(".") else display
    if not hostname or len(hostname) > 253:
        raise _invalid_target(display, index, "is not a valid hostname")

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise _invalid_target(display, index, "is not a valid hostname") from exc

    if len(ascii_hostname) > 253:
        raise _invalid_target(display, index, "is not a valid hostname")
    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise _invalid_target(display, index, "is not a valid hostname")

    normalized_hostname = ascii_hostname.lower()
    return ValidatedPingTarget(
        display=display,
        lookup=normalized_hostname,
        dedupe_key=f"host:{normalized_hostname}",
        address=None,
    )


def validate_ping_targets(
    targets: list[str], *, target_limit: int
) -> list[ValidatedPingTarget]:
    """Validate targets and deduplicate them while preserving their first order."""

    unique: list[ValidatedPingTarget] = []
    seen: set[str] = set()
    for index, target in enumerate(targets):
        validated = validate_ping_target(target, index)
        if validated.dedupe_key in seen:
            continue
        seen.add(validated.dedupe_key)
        unique.append(validated)

    if not unique:
        raise PingValidationError(
            "empty_ping_targets", "at least one unique ping target is required"
        )
    if len(unique) > target_limit:
        raise PingValidationError(
            "ping_target_limit_exceeded",
            f"ping jobs may contain at most {target_limit} unique targets",
            limit=target_limit,
            actual=len(unique),
        )
    return unique
