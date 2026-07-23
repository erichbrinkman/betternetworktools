"""Opt-in, bounded IP-to-ASN enrichment for NetTrace."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from collections.abc import Awaitable, Callable, Sequence
from typing import Protocol

from .models import TraceAsnRecord


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_REGISTRY = re.compile(r"^[a-z0-9-]{1,24}$")
_MAX_RESPONSE_BYTES = 131_072


class AsnLookupProvider(Protocol):
    async def lookup_many(self, addresses: Sequence[str]) -> dict[str, TraceAsnRecord]: ...


Connector = Callable[
    [str, int],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


def _clean(value: str, limit: int) -> str:
    return _CONTROL_CHARACTERS.sub(" ", value).strip()[:limit]


def _split_as_name(description: str, asn: int) -> tuple[str, str | None]:
    cleaned = _clean(description, 200)
    if not cleaned:
        return f"AS{asn}", None
    if " - " in cleaned:
        short_name, organization = cleaned.split(" - ", 1)
        short_name = _clean(short_name, 200)
        organization = _clean(organization, 200)
        return short_name or f"AS{asn}", organization or None
    return cleaned, None


def parse_cymru_response(response: str) -> dict[str, TraceAsnRecord]:
    """Parse Team Cymru bulk WHOIS rows, ignoring malformed or unsafe fields."""

    records: dict[str, TraceAsnRecord] = {}
    for raw_line in response.splitlines():
        fields = [field.strip() for field in raw_line.split("|")]
        if len(fields) < 7 or fields[0].upper() == "AS":
            continue
        # A multi-origin row has no single authoritative ASN for this response
        # model. Leave it unmapped instead of inventing a primary carrier.
        raw_asns = fields[0].split()
        if len(raw_asns) != 1:
            continue
        raw_asn = raw_asns[0]
        try:
            asn = int(raw_asn)
            address = ipaddress.ip_address(fields[1])
            prefix = ipaddress.ip_network(fields[2], strict=False)
        except (ValueError, IndexError):
            continue
        if not 1 <= asn <= 4_294_967_295:
            continue
        if address.version != prefix.version or address not in prefix:
            continue

        country = fields[3].upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            country = ""
        registry = fields[4].lower()
        if not _REGISTRY.fullmatch(registry):
            registry = ""
        # Cymru may echo an optional Info token as an additional column before
        # the AS description. The description is therefore always read from
        # the final field rather than a fixed seven-column offset.
        name, organization = _split_as_name(fields[-1], asn)
        canonical = address.compressed
        records.setdefault(
            canonical,
            TraceAsnRecord(
                number=asn,
                name=name,
                organization=organization,
                prefix=str(prefix),
                country_code=country or None,
                registry=registry or None,
                source="team_cymru_whois",
            ),
        )
    return records


class TeamCymruAsnProvider:
    """Use Team Cymru's bulk WHOIS endpoint over TCP 43 after explicit opt-in."""

    def __init__(
        self,
        *,
        timeout: float = 8.0,
        connector: Connector | None = None,
    ) -> None:
        self.timeout = timeout
        self.connector = connector or asyncio.open_connection

    async def lookup_many(
        self, addresses: Sequence[str]
    ) -> dict[str, TraceAsnRecord]:
        public_addresses: list[str] = []
        seen: set[str] = set()
        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError:
                continue
            canonical = address.compressed
            if not address.is_global or canonical in seen:
                continue
            seen.add(canonical)
            public_addresses.append(canonical)
        if not public_addresses:
            return {}

        query = "begin\nverbose\n" + "\n".join(public_addresses) + "\nend\n"
        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await self.connector("whois.cymru.com", 43)
                writer.write(query.encode("ascii"))
                await writer.drain()

                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = await reader.read(16_384)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_RESPONSE_BYTES:
                        raise OSError("ASN lookup response exceeded the size limit")
                    chunks.append(chunk)
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        parsed = parse_cymru_response(b"".join(chunks).decode(errors="replace"))
        return {
            address: record
            for address, record in parsed.items()
            if address in seen
        }
