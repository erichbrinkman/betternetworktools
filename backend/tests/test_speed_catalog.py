from __future__ import annotations

import asyncio

import pytest

from better_network_tools import speedtest as speedtest_module
from better_network_tools.config import Settings
from better_network_tools.speedtest import (
    CLOUDFLARE_SERVER_ID,
    SpeedCatalogError,
    SpeedServerCatalog,
    SpeedServerNotFoundError,
    parse_librespeed_directory,
)


class PublicResolver:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, float]] = []

    async def resolve(
        self, hostname: str, port: int, *, timeout: float
    ) -> tuple[str, ...]:
        self.calls.append((hostname, port, timeout))
        return ("8.8.8.8", "2001:4860:4860::8888")


def valid_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": 7,
        "name": "Example Public Server",
        "server": "https://speed.example.com/speedtest/",
        "dlURL": "garbage.php",
        "ulURL": "empty.php",
        "pingURL": "empty.php",
        "location": "New York",
        "country": "US",
        "sponsor": "Example ISP",
    }
    row.update(overrides)
    return row


def test_directory_parser_keeps_only_https_same_origin_public_servers() -> None:
    targets = parse_librespeed_directory(
        [
            valid_row(),
            valid_row(
                id=14,
                server="//secure-upgrade.example/backend",
                sponsor=None,
                sponsorName="Directory Sponsor",
            ),
            valid_row(id=8, server="http://speed.example.com/"),
            valid_row(id=9, server="https://127.0.0.1/"),
            valid_row(id=10, server="https://speed.local/"),
            valid_row(id=11, dlURL="https://attacker.example/payload"),
            valid_row(id=12, pingURL="../private"),
            valid_row(id=13, server="https://user:secret@speed.example.com/"),
            valid_row(id="bad/id"),
        ]
    )

    assert len(targets) == 2
    target = targets[0]
    assert target.public.model_dump() == {
        "id": "7",
        "name": "Example Public Server",
        "provider": "librespeed",
        "location": "New York",
        "country": "US",
        "sponsor": "Example ISP",
        "automatic": False,
        "latency_ms": None,
    }
    assert target.download_url == "https://speed.example.com/speedtest/garbage.php"
    assert target.upload_url == "https://speed.example.com/speedtest/empty.php"
    assert target.ping_url == "https://speed.example.com/speedtest/empty.php"
    assert "url" not in target.public.model_dump()
    upgraded = targets[1]
    assert upgraded.download_url == (
        "https://secure-upgrade.example/backend/garbage.php"
    )
    assert upgraded.public.sponsor == "Directory Sponsor"

    inferred = parse_librespeed_directory(
        [
            valid_row(
                id=15,
                name="Amsterdam, Netherlands (Clouvider)",
                location=None,
            )
        ]
    )[0]
    assert inferred.public.location == "Amsterdam, Netherlands"

    sanitized = parse_librespeed_directory(
        [valid_row(id=16, name="Trusted\u202eexe Server")]
    )[0]
    assert sanitized.public.name == "Trusted exe Server"


@pytest.mark.parametrize("payload", [None, {}, {"servers": "not-a-list"}, []])
def test_directory_parser_rejects_responses_without_usable_rows(payload: object) -> None:
    with pytest.raises(SpeedCatalogError):
        parse_librespeed_directory(payload)


@pytest.mark.asyncio
async def test_catalog_includes_cloudflare_and_caches_valid_directory() -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            self.calls += 1
            assert url.startswith("https://")
            assert timeout == 3.0
            assert max_bytes == 20_000
            return {"servers": [valid_row()]}

    fetcher = Fetcher()
    catalog = SpeedServerCatalog(
        Settings(
            speed_catalog_timeout_seconds=3.0,
            speed_catalog_max_bytes=20_000,
            speed_catalog_ttl_seconds=900,
        ),
        fetcher=fetcher,
        resolver=PublicResolver(),
    )

    first = await catalog.list_servers()
    second = await catalog.list_servers()

    assert fetcher.calls == 1
    assert first == second
    assert first.directory_status == "fresh"
    assert [server.id for server in first.servers] == [CLOUDFLARE_SERVER_ID, "7"]
    automatic = first.servers[0]
    assert automatic.provider == "cloudflare"
    assert automatic.automatic is True
    assert await catalog.resolve("7")

    with pytest.raises(SpeedServerNotFoundError):
        await catalog.resolve("not-in-the-catalog")


@pytest.mark.asyncio
async def test_catalog_ranks_servers_by_bounded_latency_and_caches_samples() -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.calls = 0

        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            self.calls += 1
            return [
                valid_row(
                    id=31,
                    name="Zulu Slow",
                    server="https://slow.example/speedtest/",
                ),
                valid_row(
                    id=32,
                    name="Bravo Fast",
                    server="https://bravo.example/speedtest/",
                ),
                valid_row(
                    id=33,
                    name="Alpha Fast",
                    server="https://alpha.example/speedtest/",
                ),
                valid_row(
                    id=34,
                    name="Failed Probe",
                    server="https://failed.example/speedtest/",
                ),
            ]

    class Prober:
        def __init__(self) -> None:
            self.calls: list[tuple[str, float]] = []

        async def ping(self, server, *, timeout: float) -> float:
            self.calls.append((server.public.id, timeout))
            if server.public.id == "34":
                raise OSError("server did not respond")
            return {"31": 42.229, "32": 5.445, "33": 5.445}[
                server.public.id
            ]

    fetcher = Fetcher()
    prober = Prober()
    catalog = SpeedServerCatalog(
        Settings(speed_catalog_ttl_seconds=900),
        fetcher=fetcher,
        prober=prober,
        resolver=PublicResolver(),
    )

    first = await catalog.list_servers()
    second = await catalog.list_servers()

    assert first == second
    assert [server.id for server in first.servers] == [
        CLOUDFLARE_SERVER_ID,
        "33",
        "32",
        "31",
        "34",
    ]
    assert [server.latency_ms for server in first.servers] == [
        None,
        5.45,
        5.45,
        42.23,
        None,
    ]
    assert fetcher.calls == 1
    assert sorted(prober.calls) == [
        ("31", 1.5),
        ("32", 1.5),
        ("33", 1.5),
        ("34", 1.5),
    ]


@pytest.mark.asyncio
async def test_injected_fetcher_is_not_used_as_a_prober_implicitly() -> None:
    class Fetcher:
        def __init__(self) -> None:
            self.ping_calls = 0

        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            return [
                valid_row(id=2, name="Zulu", country="ZZ"),
                valid_row(id=1, name="Alpha", country="AA"),
            ]

        async def ping(self, server, *, timeout: float) -> float:
            self.ping_calls += 1
            raise AssertionError("custom fetchers must not be probed implicitly")

    fetcher = Fetcher()
    response = await SpeedServerCatalog(
        Settings(), fetcher=fetcher, resolver=PublicResolver()
    ).list_servers()

    assert [server.id for server in response.servers] == [
        CLOUDFLARE_SERVER_ID,
        "1",
        "2",
    ]
    assert fetcher.ping_calls == 0


@pytest.mark.asyncio
async def test_catalog_latency_ranking_has_a_wall_clock_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Fetcher:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            return [
                valid_row(id=2, name="Zulu"),
                valid_row(id=1, name="Alpha"),
            ]

    class HangingProber:
        async def ping(self, server, *, timeout: float) -> float:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    monkeypatch.setattr(speedtest_module, "_SERVER_RANK_WALL_TIMEOUT_SECONDS", 0.01)
    response = await asyncio.wait_for(
        SpeedServerCatalog(
            Settings(),
            fetcher=Fetcher(),
            prober=HangingProber(),
            resolver=PublicResolver(),
        ).list_servers(),
        timeout=0.5,
    )

    assert response.directory_status == "fresh"
    assert [server.id for server in response.servers] == [
        CLOUDFLARE_SERVER_ID,
        "1",
        "2",
    ]
    assert all(server.latency_ms is None for server in response.servers)


@pytest.mark.asyncio
async def test_catalog_fails_closed_to_cloudflare_and_retains_stale_cache() -> None:
    class SequencedFetcher:
        def __init__(self) -> None:
            self.responses: list[object] = [[valid_row()], OSError("secret URL")]

        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

    fetcher = SequencedFetcher()
    catalog = SpeedServerCatalog(
        Settings(), fetcher=fetcher, resolver=PublicResolver()
    )
    live = await catalog.list_servers()
    assert live.directory_status == "fresh"

    catalog._expires_at = 0.0
    stale = await catalog.list_servers()

    assert stale.directory_status == "stale"
    assert [server.id for server in stale.servers] == [CLOUDFLARE_SERVER_ID, "7"]

    class FailedFetcher:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            raise OSError("do not expose this")

    unavailable = await SpeedServerCatalog(
        Settings(), fetcher=FailedFetcher()
    ).list_servers()
    assert unavailable.directory_status == "unavailable"
    assert [server.id for server in unavailable.servers] == [CLOUDFLARE_SERVER_ID]


@pytest.mark.asyncio
async def test_cloudflare_resolution_never_fetches_the_remote_directory() -> None:
    class NeverFetch:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            raise AssertionError("automatic edge resolution should be local")

    catalog = SpeedServerCatalog(Settings(), fetcher=NeverFetch())
    target = await catalog.resolve(CLOUDFLARE_SERVER_ID)
    assert target.public.provider == "cloudflare"
    assert target.download_url == "https://speed.cloudflare.com/__down"


@pytest.mark.asyncio
async def test_catalog_rejects_hostnames_with_any_non_global_dns_answer() -> None:
    class Fetcher:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            return [
                valid_row(id=7, server="https://public-answer.example/"),
                valid_row(id=8, server="https://mixed-answer.example/"),
            ]

    class Resolver:
        async def resolve(
            self, hostname: str, port: int, *, timeout: float
        ) -> tuple[str, ...]:
            assert port == 443
            assert timeout == 1.5
            if hostname == "public-answer.example":
                return ("8.8.8.8",)
            return ("8.8.8.8", "127.0.0.1")

    catalog = SpeedServerCatalog(
        Settings(speed_dns_timeout_seconds=1.5),
        fetcher=Fetcher(),
        resolver=Resolver(),
    )
    response = await catalog.list_servers()

    assert response.directory_status == "fresh"
    assert [server.id for server in response.servers] == [
        CLOUDFLARE_SERVER_ID,
        "7",
    ]


@pytest.mark.asyncio
async def test_catalog_refresh_has_a_wall_clock_deadline() -> None:
    class SlowTrickleFetcher:
        async def fetch_json(self, url: str, *, timeout: float, max_bytes: int):
            # Simulate a response that keeps making progress within an HTTP
            # inactivity timeout but never finishes its JSON document.
            while True:
                await asyncio.sleep(0.001)

    catalog = SpeedServerCatalog(
        Settings(speed_catalog_timeout_seconds=0.01),
        fetcher=SlowTrickleFetcher(),
        resolver=PublicResolver(),
    )
    response = await asyncio.wait_for(catalog.list_servers(), timeout=0.5)

    assert response.directory_status == "unavailable"
    assert [server.id for server in response.servers] == [CLOUDFLARE_SERVER_ID]
