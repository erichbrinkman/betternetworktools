from __future__ import annotations

import asyncio

import pytest

from better_network_tools.models import OpenPort
from better_network_tools.network import (
    CommandResult,
    NetworkProber,
    ProbeOptions,
    calculate_confidence,
    parse_mac_address,
    ping_arguments,
)
from better_network_tools.validation import ScanValidationError, parse_scan_target


def test_scan_target_normalizes_cidr_without_enumerating_it() -> None:
    target = parse_scan_target("192.168.10.55/30", host_limit=16)

    assert str(target.network) == "192.168.10.52/30"
    assert target.host_count == 2


def test_scan_target_counts_point_to_point_and_single_host_ranges() -> None:
    assert parse_scan_target("10.0.0.0/31", 2).host_count == 2
    assert parse_scan_target("10.0.0.9/32", 1).host_count == 1


@pytest.mark.parametrize(
    ("subnet", "code"),
    [
        ("not-a-cidr", "invalid_subnet"),
        ("2001:db8::/126", "unsupported_address_family"),
        ("224.0.0.0/30", "unsafe_subnet"),
        ("0.0.0.0/32", "unsafe_subnet"),
        ("255.255.255.255/32", "unsafe_subnet"),
    ],
)
def test_scan_target_rejects_invalid_or_unsafe_ranges(subnet: str, code: str) -> None:
    with pytest.raises(ScanValidationError) as raised:
        parse_scan_target(subnet, host_limit=16)

    assert raised.value.code == code


def test_scan_target_enforces_limit_before_host_iteration() -> None:
    with pytest.raises(ScanValidationError) as raised:
        parse_scan_target("10.0.0.0/24", host_limit=32)

    assert raised.value.code == "host_limit_exceeded"
    assert raised.value.actual == 254
    assert raised.value.limit == 32


def test_ping_arguments_are_platform_specific_and_shell_free() -> None:
    assert ping_arguments("192.0.2.10", 0.75, "Windows") == (
        "ping",
        "-n",
        "1",
        "-w",
        "750",
        "192.0.2.10",
    )
    assert ping_arguments("192.0.2.10", 0.75, "Darwin") == (
        "ping",
        "-n",
        "-c",
        "1",
        "-W",
        "750",
        "192.0.2.10",
    )
    assert ping_arguments("192.0.2.10", 0.75, "Linux") == (
        "ping",
        "-n",
        "-c",
        "1",
        "-W",
        "1",
        "192.0.2.10",
    )


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("192.0.2.2 dev en0 lladdr aa:bb:cc:dd:ee:ff REACHABLE", "AA:BB:CC:DD:EE:FF"),
        ("192.0.2.2  00-11-22-33-44-55 dynamic", "00:11:22:33:44:55"),
        ("? (192.0.2.2) at 9e:e:87:57:9e:3d on en0", "9E:0E:87:57:9E:3D"),
        ("? (192.0.2.2) at (incomplete) on en0", None),
        ("192.0.2.255 at ff:ff:ff:ff:ff:ff", None),
    ],
)
def test_parse_mac_address(output: str, expected: str | None) -> None:
    assert parse_mac_address(output) == expected


def test_parse_mac_address_is_bound_to_the_requested_ip() -> None:
    output = "\n".join(
        [
            "? (192.0.2.2) at (incomplete) on en0",
            "? (192.0.2.20) at aa:bb:cc:dd:ee:ff on en0",
        ]
    )

    assert parse_mac_address(output, "192.0.2.2") is None
    assert parse_mac_address(output, "192.0.2.20") == "AA:BB:CC:DD:EE:FF"


def test_confidence_scoring_is_deterministic() -> None:
    assert calculate_confidence(icmp=True, tcp=True, arp=False, reverse_dns=False) == (
        80,
        "high",
    )
    assert calculate_confidence(icmp=False, tcp=False, arp=True, reverse_dns=True) == (
        40,
        "medium",
    )
    assert calculate_confidence(icmp=False, tcp=False, arp=True, reverse_dns=False) == (
        30,
        "low",
    )


@pytest.mark.asyncio
async def test_windows_icmp_requires_an_echo_reply_not_only_a_zero_exit() -> None:
    async def unreachable_runner(
        arguments: tuple[str, ...], timeout: float
    ) -> CommandResult:
        return CommandResult(
            returncode=0,
            stdout="Reply from 192.168.1.1: Destination host unreachable.",
        )

    unreachable = NetworkProber(
        platform_name="windows", command_runner=unreachable_runner
    )
    assert await unreachable.icmp_reachable("192.168.1.99", 0.1) is False

    async def echo_runner(
        arguments: tuple[str, ...], timeout: float
    ) -> CommandResult:
        return CommandResult(
            returncode=0,
            stdout="Réponse de 192.168.1.99 : octets=32 temps<1ms TTL=128",
        )

    reachable = NetworkProber(platform_name="windows", command_runner=echo_runner)
    assert await reachable.icmp_reachable("192.168.1.99", 0.1) is True


@pytest.mark.asyncio
async def test_tcp_dns_interception_cannot_discover_a_host_by_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prober = NetworkProber()

    async def no_ping(ip_address: str, timeout: float) -> bool:
        return False

    async def no_arp(ip_address: str, timeout: float) -> None:
        return None

    async def open_tcp_port(
        ip_address: str,
        port: int,
        *,
        timeout: float,
        banner_timeout: float,
        collect_banner: bool,
    ) -> OpenPort:
        return OpenPort(port=port)

    monkeypatch.setattr(prober, "icmp_reachable", no_ping)
    monkeypatch.setattr(prober, "arp_mac", no_arp)
    monkeypatch.setattr(prober, "tcp_port", open_tcp_port)
    dns_only = await prober.inspect_host(
        "192.0.2.9",
        ProbeOptions(
            ports=(53,),
            timeout=0.1,
            ping_timeout=0.1,
            banner_timeout=0.1,
            resolve_dns=False,
            collect_banners=False,
        ),
    )

    assert dns_only is None

    ssh_and_dns = await prober.inspect_host(
        "192.0.2.9",
        ProbeOptions(
            ports=(22, 53),
            timeout=0.1,
            ping_timeout=0.1,
            banner_timeout=0.1,
            resolve_dns=False,
            collect_banners=False,
        ),
    )

    assert ssh_and_dns is not None
    assert [entry.port for entry in ssh_and_dns.open_ports] == [22, 53]
    assert ssh_and_dns.discovery_methods == ["tcp"]
    assert ssh_and_dns.confidence_score == 35


@pytest.mark.asyncio
async def test_network_prober_combines_only_mocked_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[tuple[str, ...]] = []

    async def fake_command(arguments: tuple[str, ...], timeout: float) -> CommandResult:
        commands.append(tuple(arguments))
        if arguments[0] == "ping":
            return CommandResult(returncode=0)
        return CommandResult(
            returncode=0,
            stdout="? (192.0.2.7) at aa:bb:cc:dd:ee:ff on en0",
        )

    def fake_resolver(ip_address: str) -> tuple[str, list[str], list[str]]:
        return ("switch-7.example.test.", [], [ip_address])

    async def fake_tcp_port(*args: object, **kwargs: object) -> OpenPort:
        return OpenPort(port=22, service="ssh", banner="SSH-2.0-Test")

    prober = NetworkProber(
        platform_name="darwin", command_runner=fake_command, resolver=fake_resolver
    )
    monkeypatch.setattr(prober, "tcp_port", fake_tcp_port)
    device = await prober.inspect_host(
        "192.0.2.7",
        ProbeOptions(
            ports=(22,),
            timeout=0.1,
            ping_timeout=0.1,
            banner_timeout=0.1,
            resolve_dns=True,
            collect_banners=True,
        ),
    )

    assert device is not None
    assert device.hostname == "switch-7.example.test"
    assert device.mac_address == "AA:BB:CC:DD:EE:FF"
    assert device.discovery_methods == ["icmp", "tcp", "arp", "reverse_dns"]
    assert device.confidence_score == 100
    assert any(command[0] == "ping" for command in commands)
    assert any(command[0] == "arp" for command in commands)


@pytest.mark.asyncio
async def test_tcp_http_hint_uses_mocked_streams(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeReader:
        async def read(self, _size: int) -> bytes:
            return b"HTTP/1.1 204 No Content\r\nServer: test-appliance/1.0\r\n\r\n"

    class FakeWriter:
        def __init__(self) -> None:
            self.written = b""
            self.closed = False

        def write(self, data: bytes) -> None:
            self.written += data

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    writer = FakeWriter()

    async def fake_open_connection(ip_address: str, port: int):
        assert (ip_address, port) == ("192.0.2.9", 80)
        return FakeReader(), writer

    monkeypatch.setattr(asyncio, "open_connection", fake_open_connection)
    result = await NetworkProber().tcp_port(
        "192.0.2.9",
        80,
        timeout=0.1,
        banner_timeout=0.1,
        collect_banner=True,
    )

    assert result is not None
    assert result.http_status == 204
    assert result.http_server == "test-appliance/1.0"
    assert result.banner == "HTTP/1.1 204 No Content"
    assert writer.written.startswith(b"HEAD / HTTP/1.0")
    assert writer.closed is True
