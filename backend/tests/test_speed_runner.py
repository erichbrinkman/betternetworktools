from __future__ import annotations

import asyncio

import httpx
import pytest

import better_network_tools.speedtest as speedtest_module
from better_network_tools.config import Settings
from better_network_tools.models import SpeedServerResponse
from better_network_tools.speedtest import (
    CLOUDFLARE_SERVER_ID,
    HttpxSpeedClient,
    SpeedRunError,
    SpeedServerCatalog,
    SpeedServerNotFoundError,
    SpeedServerTarget,
    SpeedTestOptions,
    SpeedTestRunner,
    SpeedTransportError,
    TransferObservation,
)


TARGET = SpeedServerTarget(
    public=SpeedServerResponse(
        id="7",
        name="Mock server",
        provider="librespeed",
        location="Test Lab",
        country="US",
        sponsor=None,
        automatic=False,
    ),
    ping_url="https://speed.example.test/ping",
    download_url="https://speed.example.test/download",
    upload_url="https://speed.example.test/upload",
)


@pytest.mark.asyncio
async def test_runner_orchestrates_phases_metrics_and_configured_byte_caps() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([10.0, 12.0, 11.0])
            self.download_limits: list[int] = []
            self.upload_limits: list[int] = []

        async def ping(self, server, *, timeout: float) -> float:
            assert server is TARGET
            assert timeout == 2.0
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.5, 10.0, 10.5)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.upload_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.25, 20.0, 20.25)

    phases: list[tuple[str, float, int, int]] = []

    async def progress(phase, percent, download_bytes, upload_bytes):
        phases.append((phase, percent, download_bytes, upload_bytes))

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=3,
            speed_request_timeout_seconds=2.0,
            speed_total_timeout_seconds=10.0,
            speed_download_byte_limit=2_500_000,
            speed_upload_byte_limit=1_500_000,
        ),
        client=client,
        transfer_concurrency=2,
    )
    result = await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=2_500_000, upload_bytes=1_500_000),
    )

    assert result.ping_ms == 11.0
    assert result.jitter_ms == 1.5
    assert result.download_mbps == 40.0
    assert result.upload_mbps == 48.0
    assert result.download_bytes == 2_500_000
    assert result.upload_bytes == 1_500_000
    assert client.download_limits == [1_250_000, 1_250_000]
    assert client.upload_limits == [750_000, 750_000]
    assert [phase for phase, *_ in phases] == [
        "ping",
        "ping",
        "ping",
        "ping",
        "download",
        "download",
        "upload",
        "upload",
    ]
    assert phases[-1] == ("upload", 95.0, 2_500_000, 1_500_000)


@pytest.mark.asyncio
async def test_runner_rejects_transport_results_over_the_byte_cap() -> None:
    class Client:
        async def ping(self, server, *, timeout: float) -> float:
            return 1.0

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            return TransferObservation(byte_limit + 1, 0.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            raise AssertionError("upload must not start")

    async def progress(*args):
        return None

    runner = SpeedTestRunner(
        Settings(speed_ping_samples=2, speed_download_byte_limit=100),
        client=Client(),
    )
    with pytest.raises(SpeedRunError) as error:
        await runner.run(
            TARGET,
            progress,
            SpeedTestOptions(download_bytes=100, upload_bytes=100),
        )
    assert str(error.value) == (
        "The selected speed-test server did not complete the download test."
    )


@pytest.mark.asyncio
async def test_runner_total_deadline_is_bounded_and_user_safe() -> None:
    class BlockingClient:
        async def ping(self, server, *, timeout: float) -> float:
            await asyncio.Event().wait()
            raise AssertionError("deadline must cancel the request")

    async def progress(*args):
        return None

    runner = SpeedTestRunner(
        Settings(speed_total_timeout_seconds=0.01), client=BlockingClient()
    )
    with pytest.raises(SpeedRunError) as error:
        await runner.run(
            TARGET,
            progress,
            SpeedTestOptions(download_bytes=1, upload_bytes=1),
        )
    assert str(error.value) == "The speed test exceeded the configured time limit."


@pytest.mark.asyncio
async def test_runner_uses_bounded_parallel_streams_and_exact_byte_allocation() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.active = 0
            self.peak = 0
            self.download_limits: list[int] = []
            self.upload_limits: list[int] = []
            self.gate = asyncio.Event()

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def _transfer(self, byte_limit, on_progress, limits):
            limits.append(byte_limit)
            self.active += 1
            self.peak = max(self.peak, self.active)
            if self.active == 4:
                self.gate.set()
            await self.gate.wait()
            if on_progress is not None:
                on_progress(byte_limit)
            self.active -= 1
            return TransferObservation(byte_limit, 0.5, 100.0, 100.5)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            return await self._transfer(
                byte_limit, on_progress, self.download_limits
            )

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            # Reset the barrier after the completed download phase.
            if not self.active and self.gate.is_set():
                self.gate = asyncio.Event()
            return await self._transfer(byte_limit, on_progress, self.upload_limits)

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=2_500_001,
            speed_upload_byte_limit=1_500_003,
        ),
        client=client,
        transfer_concurrency=4,
    )
    result = await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=2_500_001, upload_bytes=1_500_003),
    )

    assert client.peak == 4
    assert sorted(client.download_limits) == [625_000, 625_000, 625_000, 625_001]
    assert sorted(client.upload_limits) == [375_000, 375_001, 375_001, 375_001]
    assert result.download_bytes == 2_500_001
    assert result.upload_bytes == 1_500_003


@pytest.mark.asyncio
async def test_runner_splits_large_lane_budgets_into_bounded_requests() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.download_limits: list[int] = []
            self.upload_limits: list[int] = []

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 1.0, 10.0, 11.0)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.upload_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 1.0, 20.0, 21.0)

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=2_000_000_000,
            speed_upload_byte_limit=1_000_000_000,
        ),
        client=client,
        transfer_concurrency=4,
    )
    result = await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(
            download_bytes=2_000_000_000,
            upload_bytes=1_000_000_000,
        ),
    )

    assert len(client.download_limits) == 20
    assert max(client.download_limits) == 100 * 1_048_576
    assert sum(client.download_limits) == 2_000_000_000
    assert len(client.upload_limits) == 48
    assert max(client.upload_limits) == 20 * 1_048_576
    assert sum(client.upload_limits) == 1_000_000_000
    assert result.download_bytes == 2_000_000_000
    assert result.upload_bytes == 1_000_000_000
    assert result.download_mbps == 16_000.0
    assert result.upload_mbps == 8_000.0


@pytest.mark.asyncio
async def test_runner_reports_throttled_live_transfer_progress() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            assert on_progress is not None
            on_progress(byte_limit // 2)
            await asyncio.sleep(0.25)
            on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.25, 10.0, 10.25)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            assert on_progress is not None
            on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 20.0, 20.1)

    phases: list[tuple[str, float, int, int]] = []

    async def progress(phase, percent, download_bytes, upload_bytes):
        phases.append((phase, percent, download_bytes, upload_bytes))

    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_request_timeout_seconds=1.0,
            speed_download_byte_limit=4_000,
            speed_upload_byte_limit=2_000,
        ),
        client=Client(),
        transfer_concurrency=2,
    )
    await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=4_000, upload_bytes=2_000),
    )

    live_download = [
        item for item in phases if item[0] == "download" and 30.0 < item[1] < 65.0
    ]
    assert live_download
    assert live_download[0][2:] == (2_000, 0)
    assert len(live_download) == 1


@pytest.mark.asyncio
async def test_runner_returns_bounded_partial_phase_at_phase_deadline() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            assert on_progress is not None
            on_progress(5)
            on_progress(10)
            await asyncio.Event().wait()
            raise AssertionError("phase deadline must cancel the request")

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.01, 20.0, 20.01)

    async def progress(*args):
        return None

    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_request_timeout_seconds=0.03,
            speed_total_timeout_seconds=1.0,
            speed_download_byte_limit=100,
            speed_upload_byte_limit=20,
        ),
        client=Client(),
        transfer_concurrency=2,
    )
    result = await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=100, upload_bytes=20),
    )

    assert result.download_bytes == 20
    assert result.upload_bytes == 20
    # A lone early chunk must not be divided by a synthetic microsecond window.
    assert result.download_mbps == 0.0


@pytest.mark.asyncio
async def test_http_transport_rejects_private_dns_before_sending_a_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b"")

    class PrivateResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("127.0.0.1",)

    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PrivateResolver())

    with pytest.raises(SpeedTransportError):
        await client.ping(TARGET, timeout=1.0)
    assert requests == []
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_transport_disables_redirects_on_an_injected_client() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) > 1:
            raise AssertionError("redirect destination must never be requested")
        return httpx.Response(
            302,
            headers={"Location": "https://127.0.0.1/private"},
        )

    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("8.8.8.8",)

    injected = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    )
    client = HttpxSpeedClient(injected, resolver=PublicResolver())

    with pytest.raises(SpeedTransportError):
        await client.ping(TARGET, timeout=1.0)
    assert len(requests) == 1
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_download_times_payload_and_reports_exact_progress() -> None:
    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            await asyncio.sleep(0.02)
            return ("8.8.8.8",)

    class DelayedBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(0.02)
            yield b"x" * 100

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=DelayedBody())

    progress: list[int] = []
    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PublicResolver())
    overall_started = asyncio.get_running_loop().time()
    observation = await client.download(
        TARGET, byte_limit=100, timeout=1.0, on_progress=progress.append
    )
    overall_duration = asyncio.get_running_loop().time() - overall_started

    assert observation.bytes_transferred == 100
    assert progress == [100]
    assert observation.duration_seconds >= 0.015
    assert overall_duration - observation.duration_seconds >= 0.015
    assert observation.payload_started_at is not None
    assert observation.payload_finished_at is not None
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_cloudflare_download_retains_payload_before_read_error() -> None:
    requests: list[httpx.Request] = []

    class InterruptedBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * 40
            raise httpx.ReadError("edge closed the response")

    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("8.8.8.8",)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, stream=InterruptedBody())

    progress: list[int] = []
    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PublicResolver())
    observation = await client.download(
        speedtest_module._cloudflare_target(),
        byte_limit=100,
        timeout=1.0,
        on_progress=progress.append,
    )

    assert observation.bytes_transferred == 40
    assert progress == [40]
    assert requests[0].url.path == "/__down"
    assert requests[0].url.params["bytes"] == "100"
    assert requests[0].url.params["r"]
    assert "ckSize" not in requests[0].url.params
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_cloudflare_download_still_rejects_zero_byte_read_error() -> None:
    class FailedBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise httpx.ReadError("edge closed before payload")
            yield b""  # pragma: no cover - keeps this an async generator

    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("8.8.8.8",)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=FailedBody())

    progress: list[int] = []
    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PublicResolver())

    with pytest.raises(SpeedTransportError):
        await client.download(
            speedtest_module._cloudflare_target(),
            byte_limit=100,
            timeout=1.0,
            on_progress=progress.append,
        )

    assert progress == []
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_upload_counts_only_the_exact_body_sent() -> None:
    requests: list[httpx.Request] = []
    bodies: list[bytes] = []

    class EmptyBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            if False:
                yield b""

    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("8.8.8.8",)

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        bodies.append(await request.aread())
        await asyncio.sleep(0.01)
        return httpx.Response(200, stream=EmptyBody())

    progress: list[int] = []
    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PublicResolver())
    observation = await client.upload(
        speedtest_module._cloudflare_target(),
        byte_limit=700_000,
        timeout=1.0,
        on_progress=progress.append,
    )

    assert len(bodies) == 1
    assert len(bodies[0]) == 700_000
    assert requests[0].url.path == "/__up"
    assert requests[0].url.params["bytes"] == "700000"
    assert requests[0].url.params["r"]
    assert observation.bytes_transferred == 700_000
    assert progress[-1] == 700_000
    assert all(earlier < later for earlier, later in zip(progress, progress[1:]))
    assert observation.payload_started_at is not None
    assert observation.payload_finished_at is not None
    await injected.aclose()


@pytest.mark.asyncio
async def test_http_librespeed_download_uses_binary_mebibyte_cksize() -> None:
    requests: list[httpx.Request] = []

    class OneByteBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x"

    class PublicResolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            return ("8.8.8.8",)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, stream=OneByteBody())

    injected = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = HttpxSpeedClient(injected, resolver=PublicResolver())
    await client.download(TARGET, byte_limit=1_048_577, timeout=1.0)

    assert requests[0].url.params["ckSize"] == "2"
    await injected.aclose()


@pytest.mark.asyncio
async def test_runner_retries_bounded_ping_failures_with_five_second_cap() -> None:
    class Client:
        def __init__(self) -> None:
            self.pings: list[float] = []
            self.responses: list[float | Exception] = [
                SpeedTransportError("temporary"),
                10.0,
                12.0,
            ]

        async def ping(self, server, *, timeout: float) -> float:
            self.pings.append(timeout)
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 10.0, 10.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 20.0, 20.1)

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_request_timeout_seconds=30.0,
            speed_download_byte_limit=10,
            speed_upload_byte_limit=10,
        ),
        client=client,
        transfer_concurrency=1,
    )
    result = await runner.run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=10, upload_bytes=10),
    )

    assert client.pings == [5.0, 5.0, 5.0]
    assert result.ping_ms == 11.0


@pytest.mark.asyncio
async def test_runner_reports_latency_specific_error_after_bounded_retries() -> None:
    class Client:
        def __init__(self) -> None:
            self.calls = 0

        async def ping(self, server, *, timeout: float) -> float:
            self.calls += 1
            raise SpeedTransportError("remote detail")

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(speed_ping_samples=2, speed_total_timeout_seconds=30.0),
        client=client,
    )
    with pytest.raises(SpeedRunError) as error:
        await runner.run(
            TARGET,
            progress,
            SpeedTestOptions(download_bytes=1, upload_bytes=1),
        )

    assert client.calls == 4
    assert str(error.value) == (
        "The selected speed-test server did not complete latency checks."
    )
    assert "remote detail" not in str(error.value)


@pytest.mark.asyncio
async def test_runner_retries_only_zero_progress_download_once() -> None:
    class Client:
        def __init__(self) -> None:
            self.download_calls = 0
            self.samples = iter([1.0, 1.0])

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_calls += 1
            if self.download_calls == 1:
                raise SpeedTransportError("failed before payload")
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 10.0, 10.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 20.0, 20.1)

    async def progress(*args):
        return None

    client = Client()
    result = await SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=10,
            speed_upload_byte_limit=10,
        ),
        client=client,
        transfer_concurrency=1,
    ).run(
        TARGET,
        progress,
        SpeedTestOptions(download_bytes=10, upload_bytes=10),
    )

    assert client.download_calls == 2
    assert result.download_bytes == 10


@pytest.mark.asyncio
async def test_runner_does_not_retry_download_after_observed_progress() -> None:
    class Client:
        def __init__(self) -> None:
            self.download_calls = 0
            self.samples = iter([1.0, 1.0])

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_calls += 1
            assert on_progress is not None
            on_progress(1)
            raise SpeedTransportError("failed after payload")

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            raise AssertionError("upload must not start")

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=10,
            speed_upload_byte_limit=10,
        ),
        client=client,
        transfer_concurrency=1,
    )
    with pytest.raises(SpeedRunError) as error:
        await runner.run(
            TARGET,
            progress,
            SpeedTestOptions(download_bytes=10, upload_bytes=10),
        )

    assert client.download_calls == 1
    assert str(error.value) == (
        "The selected speed-test server did not complete the download test."
    )


@pytest.mark.asyncio
async def test_runner_reports_upload_specific_error_without_replaying_body() -> None:
    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.upload_calls = 0

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 10.0, 10.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.upload_calls += 1
            raise SpeedTransportError("remote upload detail")

    async def progress(*args):
        return None

    client = Client()
    runner = SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=10,
            speed_upload_byte_limit=10,
        ),
        client=client,
        transfer_concurrency=1,
    )
    with pytest.raises(SpeedRunError) as error:
        await runner.run(
            TARGET,
            progress,
            SpeedTestOptions(download_bytes=10, upload_bytes=10),
        )

    assert client.upload_calls == 1
    assert str(error.value) == (
        "The selected speed-test server did not complete the upload test."
    )
    assert "remote upload detail" not in str(error.value)


@pytest.mark.asyncio
async def test_cloudflare_retains_larger_per_request_transfer_caps() -> None:
    cloudflare = speedtest_module._cloudflare_target()

    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.download_limits: list[int] = []
            self.upload_limits: list[int] = []

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 10.0, 10.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.upload_limits.append(byte_limit)
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 20.0, 20.1)

    async def progress(*args):
        return None

    client = Client()
    await SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=500_000_000,
            speed_upload_byte_limit=200_000_000,
        ),
        client=client,
        transfer_concurrency=1,
    ).run(
        cloudflare,
        progress,
        SpeedTestOptions(
            download_bytes=500_000_000,
            upload_bytes=200_000_000,
        ),
    )

    assert client.download_limits == [250_000_000, 250_000_000]
    assert client.upload_limits == [
        50_000_000,
        50_000_000,
        50_000_000,
        50_000_000,
    ]


@pytest.mark.asyncio
async def test_cloudflare_download_keeps_successful_parallel_lanes() -> None:
    cloudflare = speedtest_module._cloudflare_target()

    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.failed_lane: asyncio.Task | None = None
            self.failed_attempts = 0

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            lane = asyncio.current_task()
            assert lane is not None
            if self.failed_lane is None:
                self.failed_lane = lane
            if lane is self.failed_lane:
                self.failed_attempts += 1
                raise SpeedTransportError("transient edge failure")
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 10.0, 10.1)

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            if on_progress is not None:
                on_progress(byte_limit)
            return TransferObservation(byte_limit, 0.1, 20.0, 20.1)

    async def progress(*args):
        return None

    client = Client()
    result = await SpeedTestRunner(
        Settings(
            speed_ping_samples=2,
            speed_download_byte_limit=40,
            speed_upload_byte_limit=40,
        ),
        client=client,
        transfer_concurrency=4,
    ).run(
        cloudflare,
        progress,
        SpeedTestOptions(download_bytes=40, upload_bytes=40),
    )

    assert client.failed_attempts == 4
    assert result.download_bytes == 30
    assert result.upload_bytes == 40


@pytest.mark.asyncio
async def test_cloudflare_download_fails_when_every_lane_exhausts_retries() -> None:
    cloudflare = speedtest_module._cloudflare_target()

    class Client:
        def __init__(self) -> None:
            self.samples = iter([1.0, 1.0])
            self.download_calls = 0

        async def ping(self, server, *, timeout: float) -> float:
            return next(self.samples)

        async def download(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            self.download_calls += 1
            raise SpeedTransportError("edge unavailable")

        async def upload(
            self, server, *, byte_limit: int, timeout: float, on_progress=None
        ):
            raise AssertionError("upload must not start")

    async def progress(*args):
        return None

    client = Client()
    with pytest.raises(SpeedRunError) as error:
        await SpeedTestRunner(
            Settings(
                speed_ping_samples=2,
                speed_download_byte_limit=20,
                speed_upload_byte_limit=20,
            ),
            client=client,
            transfer_concurrency=2,
        ).run(
            cloudflare,
            progress,
            SpeedTestOptions(download_bytes=20, upload_bytes=20),
        )

    assert client.download_calls == 8
    assert str(error.value) == (
        "The selected speed-test server did not complete the download test."
    )


@pytest.mark.asyncio
async def test_catalog_validates_each_unique_measurement_origin() -> None:
    class NeverFetch:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            raise AssertionError("direct target validation must not fetch")

    class Resolver:
        def __init__(self) -> None:
            self.calls: list[tuple[str, int]] = []

        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            self.calls.append((hostname, port))
            return ("8.8.8.8",)

    target = SpeedServerTarget(
        public=TARGET.public,
        ping_url="https://one.example.test/ping",
        download_url="https://one.example.test/download",
        upload_url="https://two.example.test:8443/upload",
    )
    resolver = Resolver()
    catalog = SpeedServerCatalog(
        Settings(), fetcher=NeverFetch(), resolver=resolver
    )
    checked = await catalog._public_directory_targets((target,))

    assert checked == (target,)
    assert sorted(resolver.calls) == [
        ("one.example.test", 443),
        ("two.example.test", 8443),
    ]


@pytest.mark.asyncio
async def test_catalog_quarantines_failed_public_server_for_five_minutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NeverFetch:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            raise AssertionError("warm catalog must not fetch")

    clock = [100.0]
    monkeypatch.setattr(speedtest_module.time, "monotonic", lambda: clock[0])
    catalog = SpeedServerCatalog(Settings(), fetcher=NeverFetch())
    catalog._targets[TARGET.public.id] = TARGET
    catalog._expires_at = float("inf")

    await catalog.report_failure(TARGET.public.id)
    quarantined = await catalog.list_servers()
    assert [server.id for server in quarantined.servers] == [CLOUDFLARE_SERVER_ID]
    with pytest.raises(SpeedServerNotFoundError):
        await catalog.resolve(TARGET.public.id)

    await catalog.report_failure(CLOUDFLARE_SERVER_ID)
    assert await catalog.resolve(CLOUDFLARE_SERVER_ID)

    clock[0] += 299.9
    with pytest.raises(SpeedServerNotFoundError):
        await catalog.resolve(TARGET.public.id)
    clock[0] += 0.2
    assert await catalog.resolve(TARGET.public.id) is TARGET
