from __future__ import annotations

import asyncio
import sys

import pytest

from better_network_tools.tracer import (
    NativeTracer,
    NativeTraceCancelled,
    TraceCommandCancelled,
    TraceCommandResult,
    native_trace_arguments,
    parse_trace_line,
    parse_trace_output,
    run_trace_command,
)


def test_native_trace_argument_vectors_are_fixed_and_platform_specific() -> None:
    assert native_trace_arguments(
        "192.0.2.1",
        "IPv4",
        max_hops=30,
        timeout=1.25,
        platform_name="windows",
    ) == (
        "tracert",
        "-d",
        "-4",
        "-h",
        "30",
        "-w",
        "1250",
        "192.0.2.1",
    )
    assert native_trace_arguments(
        "2001:db8::1",
        "IPv6",
        max_hops=20,
        timeout=0.5,
        platform_name="darwin",
    ) == (
        "traceroute6",
        "-n",
        "-m",
        "20",
        "-q",
        "3",
        "-w",
        "1",
        "2001:db8::1",
    )
    darwin_ipv4 = native_trace_arguments(
        "192.0.2.1",
        "IPv4",
        max_hops=20,
        timeout=1.25,
        platform_name="darwin",
    )
    assert darwin_ipv4[-2:] == ("2", "192.0.2.1")
    linux = native_trace_arguments(
        "192.0.2.1",
        "IPv4",
        max_hops=10,
        timeout=1.0,
        platform_name="linux",
    )
    assert linux[:3] == ("traceroute", "-4", "-n")
    assert linux[-1] == "192.0.2.1"


def test_macos_parser_preserves_per_probe_ecmp_addresses_and_annotations() -> None:
    hop = parse_trace_line(
        " 4  192.0.2.1  1.125 ms  1.250 ms  198.51.100.9  3.5 ms !H"
    )

    assert hop is not None
    assert [probe.address for probe in hop.probes] == [
        "192.0.2.1",
        "192.0.2.1",
        "198.51.100.9",
    ]
    assert [probe.latency_ms for probe in hop.probes] == [1.125, 1.25, 3.5]
    assert hop.probes[2].status == "unreachable"
    assert hop.probes[2].annotation == "!H"


def test_windows_parser_backfills_trailing_address_and_handles_censored_rtt() -> None:
    hop = parse_trace_line("  1    <1 ms     2 ms     3 ms  192.168.1.1")

    assert hop is not None
    assert [probe.address for probe in hop.probes] == ["192.168.1.1"] * 3
    assert [probe.latency_ms for probe in hop.probes] == [0.5, 2.0, 3.0]
    assert all(probe.status == "reply" for probe in hop.probes)


def test_parser_keeps_timeouts_and_ignores_headers_or_hostile_long_lines() -> None:
    output = "\n".join(
        [
            "Tracing route to 8.8.8.8 over a maximum of 30 hops:",
            " 1  *  *  *  Request timed out.",
            " 2  2001:db8::1  12,5 ms  *  13 ms",
            "999 " + ("x" * 5000),
        ]
    )
    hops = parse_trace_output(output)

    assert [hop.number for hop in hops] == [1, 2]
    assert [probe.status for probe in hops[0].probes] == ["timeout"] * 3
    assert hops[1].probes[0].address == "2001:db8::1"
    assert hops[1].probes[0].latency_ms == 12.5
    assert hops[1].probes[1].status == "timeout"


@pytest.mark.parametrize(
    "annotation",
    ["!I", "!Z", "!Q", "!T", "!V", "!F", "!F-1500", "!13", "!<13>"],
)
def test_parser_recognizes_bsd_and_numeric_unreachable_annotations(
    annotation: str,
) -> None:
    hop = parse_trace_line(f" 2  192.0.2.1  1 ms {annotation}  2 ms  3 ms")

    assert hop is not None
    assert hop.probes[0].status == "unreachable"
    assert hop.probes[0].annotation == annotation


@pytest.mark.asyncio
async def test_trace_command_incrementally_drains_and_caps_both_streams() -> None:
    script = (
        "import sys; "
        "sys.stdout.write('o' * 100000); sys.stdout.flush(); "
        "sys.stderr.write('e' * 100000); sys.stderr.flush()"
    )

    result = await run_trace_command((sys.executable, "-c", script), timeout=5.0)

    assert result.returncode == 0
    assert len(result.stdout) == 65_536
    assert len(result.stderr) == 65_536
    assert result.output_truncated is True


@pytest.mark.asyncio
async def test_trace_command_timeout_keeps_partial_output_and_kills_process() -> None:
    script = (
        "import sys,time; "
        "sys.stdout.write('1  192.0.2.1  1 ms  2 ms  3 ms\\n'); "
        "sys.stdout.flush(); time.sleep(30)"
    )

    result = await run_trace_command((sys.executable, "-c", script), timeout=0.1)

    assert result.returncode == 124
    assert "192.0.2.1" in result.stdout


@pytest.mark.asyncio
async def test_trace_command_cancellation_kills_and_drains_child() -> None:
    script = (
        "import sys,time; "
        "sys.stdout.write('partial\\n'); sys.stdout.flush(); time.sleep(30)"
    )
    task = asyncio.create_task(
        run_trace_command((sys.executable, "-c", script), timeout=20.0)
    )
    await asyncio.sleep(0.1)
    task.cancel()

    with pytest.raises(TraceCommandCancelled) as raised:
        await asyncio.wait_for(task, timeout=2.0)
    assert raised.value.result.returncode == 130
    assert raised.value.result.stdout.splitlines() == ["partial"]


@pytest.mark.asyncio
async def test_native_tracer_parses_partial_hops_carried_by_cancellation() -> None:
    async def cancelled_runner(arguments, timeout):
        raise TraceCommandCancelled(
            TraceCommandResult(
                returncode=130,
                stdout="1  192.0.2.1  1 ms  2 ms  3 ms\n",
            )
        )

    with pytest.raises(NativeTraceCancelled) as raised:
        await NativeTracer(
            platform_name="darwin", command_runner=cancelled_runner
        ).trace(
            "192.0.2.9",
            "IPv4",
            max_hops=5,
            timeout=1.0,
            probes_per_hop=3,
            total_timeout=10.0,
        )

    assert raised.value.result.hops[0].number == 1
    assert raised.value.result.hops[0].probes[0].address == "192.0.2.1"


@pytest.mark.asyncio
async def test_native_tracer_uses_injected_runner_and_sanitizes_error_detail() -> None:
    calls: list[tuple[tuple[str, ...], float]] = []

    async def runner(arguments, timeout):
        calls.append((tuple(arguments), timeout))
        return TraceCommandResult(
            returncode=1,
            stdout="1  192.0.2.1  1 ms  2 ms  3 ms",
            stderr="permission\nerror\x00detail",
            output_truncated=True,
        )

    result = await NativeTracer(
        platform_name="darwin", command_runner=runner
    ).trace(
        "192.0.2.1",
        "IPv4",
        max_hops=12,
        timeout=0.5,
        probes_per_hop=3,
        total_timeout=20.0,
    )

    assert calls[0][0][-1] == "192.0.2.1"
    assert calls[0][1] == 20.0
    assert result.hops[0].number == 1
    assert result.output_truncated is True
    assert result.error_detail == "permission error detail"
