"""Shared parsing helpers for native ping command output."""

from __future__ import annotations

import re


_PING_TIME_PATTERN = re.compile(
    r"\btime\s*(?P<operator>[=<])\s*(?P<value>\d+(?:[.,]\d+)?)\s*ms\b",
    re.IGNORECASE,
)
_WINDOWS_REPLY_TIME_PATTERN = re.compile(
    r"(?P<operator>[=<])\s*(?P<value>\d+(?:[.,]\d+)?)\s*ms\b",
    re.IGNORECASE,
)


def parse_ping_latency(output: str) -> float | None:
    """Extract an RTT in milliseconds, including native ``time<1ms`` output."""

    match = _PING_TIME_PATTERN.search(output)
    if match is None:
        return None
    value = float(match.group("value").replace(",", "."))
    if match.group("operator") == "<":
        return value / 2
    return value


def parse_windows_ping_latency(output: str) -> float | None:
    """Parse a Windows echo reply without depending on the localized word `time`."""

    parsed = parse_ping_latency(output)
    if parsed is not None:
        return parsed
    for line in output.splitlines():
        # Reply lines contain one RTT token; the Windows summary normally contains
        # three and must not turn a destination-unreachable into a false success.
        if len(re.findall(r"ms\b", line, flags=re.IGNORECASE)) != 1:
            continue
        match = _WINDOWS_REPLY_TIME_PATTERN.search(line)
        if match is None:
            continue
        value = float(match.group("value").replace(",", "."))
        return value / 2 if match.group("operator") == "<" else value
    return None


def native_ping_received(*, returncode: int, output: str, platform_name: str) -> bool:
    """Return whether native ping produced an echo reply rather than an ICMP error."""

    if returncode != 0:
        return False
    if platform_name.lower() == "windows":
        # Windows can exit zero after receiving an ICMP destination-unreachable
        # message. A reply-time token is the stable signal that the target itself
        # returned an echo response.
        return parse_windows_ping_latency(output) is not None
    return True
