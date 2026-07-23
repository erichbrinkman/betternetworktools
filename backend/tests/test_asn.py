from __future__ import annotations

import asyncio

import pytest

from better_network_tools.asn import TeamCymruAsnProvider, parse_cymru_response


def test_cymru_parser_accepts_plain_and_info_rows_using_final_as_name_field() -> None:
    response = "\n".join(
        [
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name",
            "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC, US",
            "13335 | 1.1.1.1 | 1.1.1.0/24 | AU | apnic | 2011-08-11 | token | CLOUDFLARENET - Cloudflare, Inc., US",
        ]
    )

    records = parse_cymru_response(response)

    assert records["8.8.8.8"].number == 15169
    assert records["8.8.8.8"].name == "GOOGLE"
    assert records["8.8.8.8"].organization == "Google LLC, US"
    assert records["1.1.1.1"].name == "CLOUDFLARENET"
    assert records["1.1.1.1"].source == "team_cymru_whois"


def test_cymru_parser_ignores_invalid_asns_addresses_prefixes_and_controls() -> None:
    response = "\n".join(
        [
            "0 | 8.8.8.8 | 8.8.8.0/24 | US | arin | date | invalid",
            "15169 | not-an-ip | 8.8.8.0/24 | US | arin | date | invalid",
            "15169 | 8.8.8.8 | 1.1.1.0/24 | US | arin | date | invalid",
            "15169 36040 | 8.8.4.4 | 8.8.4.0/24 | US | arin | date | MULTI",
            "15169 | 8.8.8.8 | 8.8.8.0/24 | U$ | bad registry | date | GOOG\x00LE",
        ]
    )

    records = parse_cymru_response(response)

    assert records["8.8.8.8"].name == "GOOG LE"
    assert records["8.8.8.8"].country_code is None
    assert records["8.8.8.8"].registry is None
    assert "8.8.4.4" not in records


class FakeWriter:
    def __init__(self) -> None:
        self.written = b""
        self.closed = False

    def write(self, value: bytes) -> None:
        self.written += value

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.mark.asyncio
async def test_cymru_provider_deduplicates_and_never_queries_non_public_addresses() -> None:
    writer = FakeWriter()
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | date | GOOGLE\n"
    )
    reader.feed_eof()
    calls: list[tuple[str, int]] = []

    async def connector(host: str, port: int):
        calls.append((host, port))
        return reader, writer

    provider = TeamCymruAsnProvider(timeout=0.5, connector=connector)
    records = await provider.lookup_many(
        ["192.168.1.1", "8.8.8.8", "8.8.8.8", "127.0.0.1", "not-an-ip"]
    )

    assert calls == [("whois.cymru.com", 43)]
    assert writer.written == b"begin\nverbose\n8.8.8.8\nend\n"
    assert writer.closed is True
    assert list(records) == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_cymru_provider_makes_no_connection_for_only_private_hops() -> None:
    async def connector(host: str, port: int):
        raise AssertionError("private addresses must not leave the machine")

    provider = TeamCymruAsnProvider(connector=connector)
    assert await provider.lookup_many(["10.0.0.1", "fd00::1"]) == {}
