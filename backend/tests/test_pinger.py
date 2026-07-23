from __future__ import annotations

import socket

import pytest

from better_network_tools.network import CommandResult
from better_network_tools.ping_validation import (
    PingValidationError,
    validate_ping_target,
    validate_ping_targets,
)
from better_network_tools.pinger import (
    NativePingProbe,
    SystemReverseDNSResolver,
    parse_ping_latency,
    parse_windows_ping_latency,
    ping_job_arguments,
)


@pytest.mark.asyncio
async def test_system_reverse_resolver_requires_a_name_for_ipv4_and_ipv6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, int]] = []

    def fake_getnameinfo(socket_address: object, flags: int):
        calls.append((socket_address, flags))
        return ("router.example", "0")

    monkeypatch.setattr(socket, "getnameinfo", fake_getnameinfo)
    resolver = SystemReverseDNSResolver()

    assert await resolver.resolve("192.0.2.1", "IPv4") == "router.example"
    assert await resolver.resolve("2001:db8::1", "IPv6") == "router.example"
    assert calls == [
        (("192.0.2.1", 0), socket.NI_NAMEREQD | socket.NI_NUMERICSERV),
        (
            ("2001:db8::1", 0, 0, 0),
            socket.NI_NAMEREQD | socket.NI_NUMERICSERV,
        ),
    ]


def test_ping_target_validation_normalizes_and_deduplicates() -> None:
    targets = validate_ping_targets(
        [
            " Router.Example ",
            "router.example.",
            "2001:0db8::1",
            "2001:db8:0:0:0:0:0:1",
            "192.0.2.1",
        ],
        target_limit=32,
    )

    assert [target.display for target in targets] == [
        "Router.Example",
        "2001:0db8::1",
        "192.0.2.1",
    ]
    assert targets[1].address == "2001:db8::1"
    assert targets[2].address == "192.0.2.1"


@pytest.mark.parametrize(
    "target",
    [
        "https://router.example",
        "router.example/path",
        r"router.example\path",
        "-c",
        "bad host",
        "192.0.2.999",
        "fe80::1%en0",
        "bad_name.example",
    ],
)
def test_ping_target_validation_rejects_unsafe_or_invalid_values(target: str) -> None:
    with pytest.raises(PingValidationError):
        validate_ping_target(target)


def test_ping_target_limit_is_applied_after_deduplication() -> None:
    duplicates = ["ROUTER.example", "router.example."] * 64
    assert len(validate_ping_targets(duplicates, target_limit=1)) == 1


def test_ping_argument_vectors_are_platform_and_family_specific() -> None:
    assert ping_job_arguments("192.0.2.1", "IPv4", 0.75, "windows") == (
        "ping",
        "-4",
        "-n",
        "1",
        "-w",
        "750",
        "192.0.2.1",
    )
    assert ping_job_arguments("2001:db8::1", "IPv6", 0.75, "windows")[1] == "-6"
    assert ping_job_arguments("192.0.2.1", "IPv4", 0.75, "darwin") == (
        "ping",
        "-n",
        "-c",
        "1",
        "-W",
        "750",
        "192.0.2.1",
    )
    assert ping_job_arguments("2001:db8::1", "IPv6", 0.75, "darwin") == (
        "ping6",
        "-n",
        "-c",
        "1",
        "2001:db8::1",
    )
    assert ping_job_arguments("192.0.2.1", "IPv4", 0.75, "linux") == (
        "ping",
        "-4",
        "-n",
        "-c",
        "1",
        "-W",
        "0.75",
        "192.0.2.1",
    )


def test_ping_latency_parses_exact_censored_and_localized_windows_output() -> None:
    assert parse_ping_latency("64 bytes time=12.375 ms") == 12.375
    assert parse_ping_latency("Reply time<1ms TTL=128") == 0.5
    assert parse_windows_ping_latency("Réponse: temps<1ms TTL=128") == 0.5
    assert (
        parse_windows_ping_latency(
            "Minimum = 0ms, Maximum = 0ms, Average = 0ms"
        )
        is None
    )


@pytest.mark.asyncio
async def test_native_probe_handles_null_latency_and_platform_return_codes() -> None:
    async def success_without_rtt(arguments: tuple[str, ...], timeout: float):
        return CommandResult(returncode=0, stdout="one echo response")

    linux = await NativePingProbe(
        platform_name="linux", command_runner=success_without_rtt
    ).probe("192.0.2.1", "IPv4", 0.1)
    windows = await NativePingProbe(
        platform_name="windows", command_runner=success_without_rtt
    ).probe("192.0.2.1", "IPv4", 0.1)

    assert linux.received is True
    assert linux.latency_ms is None
    assert windows.received is False

    async def no_reply(arguments: tuple[str, ...], timeout: float):
        return CommandResult(returncode=2)

    darwin = await NativePingProbe(
        platform_name="darwin", command_runner=no_reply
    ).probe("192.0.2.1", "IPv4", 0.1)
    linux_error = await NativePingProbe(
        platform_name="linux", command_runner=no_reply
    ).probe("192.0.2.1", "IPv4", 0.1)

    assert darwin.received is False and darwin.error is None
    assert linux_error.received is False
    assert linux_error.error == "native ping exited with status 2"


@pytest.mark.asyncio
async def test_native_probe_bounds_and_sanitizes_command_errors() -> None:
    async def failed(arguments: tuple[str, ...], timeout: float):
        return CommandResult(returncode=127, stderr="missing\ncommand\x00" + ("x" * 500))

    result = await NativePingProbe(
        platform_name="linux", command_runner=failed
    ).probe("192.0.2.1", "IPv4", 0.1)

    assert result.received is False
    assert result.error is not None
    assert "\n" not in result.error and "\x00" not in result.error
    assert len(result.error) < 260
