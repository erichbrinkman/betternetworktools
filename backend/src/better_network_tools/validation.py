"""CIDR validation that avoids materializing unsafe address ranges."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanTarget:
    network: ipaddress.IPv4Network
    host_count: int


class ScanValidationError(ValueError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        limit: int | None = None,
        actual: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.limit = limit
        self.actual = actual

    def as_detail(self) -> dict[str, str | int]:
        detail: dict[str, str | int] = {"code": self.code, "message": self.message}
        if self.limit is not None:
            detail["limit"] = self.limit
        if self.actual is not None:
            detail["actual"] = self.actual
        return detail


def _usable_host_count(network: ipaddress.IPv4Network) -> int:
    # ipaddress.hosts() includes both addresses for /31 and the address for /32.
    return network.num_addresses if network.prefixlen >= 31 else network.num_addresses - 2


def parse_scan_target(subnet: str, host_limit: int) -> ScanTarget:
    """Normalize an IPv4 CIDR and enforce a host count before enumeration."""

    try:
        parsed = ipaddress.ip_network(subnet.strip(), strict=False)
    except ValueError as exc:
        raise ScanValidationError(
            "invalid_subnet", "subnet must be a valid IPv4 CIDR"
        ) from exc

    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ScanValidationError(
            "unsupported_address_family", "NetScanner currently supports IPv4 subnets only"
        )

    if parsed.network_address.is_multicast or parsed.broadcast_address.is_multicast:
        raise ScanValidationError(
            "unsafe_subnet", "multicast address ranges cannot be scanned"
        )

    if parsed.prefixlen == 32 and (
        parsed.network_address.is_unspecified
        or parsed.network_address == ipaddress.IPv4Address("255.255.255.255")
    ):
        raise ScanValidationError(
            "unsafe_subnet", "unspecified and limited-broadcast addresses cannot be scanned"
        )

    host_count = _usable_host_count(parsed)
    if host_count > host_limit:
        raise ScanValidationError(
            "host_limit_exceeded",
            f"subnet contains {host_count} usable hosts; the configured limit is {host_limit}",
            limit=host_limit,
            actual=host_count,
        )

    return ScanTarget(network=parsed, host_count=host_count)
