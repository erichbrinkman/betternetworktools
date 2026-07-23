"""HTTPS-only server catalog and measurement adapters for NetSpeed."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import json
import math
import re
import socket
import statistics
import time
import unicodedata
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import unquote, urljoin, urlsplit

import httpx

from .config import Settings
from .models import (
    SpeedDirectoryStatus,
    SpeedPhase,
    SpeedServerListResponse,
    SpeedServerResponse,
)


LIBRESPEED_DIRECTORY_URL = "https://librespeed.org/backend-servers/servers.php"
CLOUDFLARE_SERVER_ID = "cloudflare-auto"
_MAX_DIRECTORY_SERVERS = 256
_MAX_TRANSFER_CONCURRENCY = 8
_DEFAULT_TRANSFER_CONCURRENCY = 4
_PROGRESS_INTERVAL_SECONDS = 0.2
_MEBIBYTE = 1_048_576
_LIBRESPEED_MAX_DOWNLOAD_REQUEST_BYTES = 100 * _MEBIBYTE
_LIBRESPEED_MAX_UPLOAD_REQUEST_BYTES = 20 * _MEBIBYTE
_CLOUDFLARE_MAX_DOWNLOAD_REQUEST_BYTES = 250_000_000
_CLOUDFLARE_MAX_UPLOAD_REQUEST_BYTES = 50_000_000
_MAX_EXTRA_PARTIAL_REQUESTS = 4
_MAX_ZERO_PROGRESS_DOWNLOAD_RETRIES = 1
_CLOUDFLARE_MAX_ZERO_PROGRESS_DOWNLOAD_RETRIES = 3
_MAX_EXTRA_PING_ATTEMPTS = 2
_MAX_PING_REQUEST_TIMEOUT_SECONDS = 5.0
_SERVER_FAILURE_QUARANTINE_SECONDS = 300.0
_SERVER_RANK_CONCURRENCY = 8
_SERVER_RANK_PROBE_TIMEOUT_SECONDS = 1.5
_SERVER_RANK_WALL_TIMEOUT_SECONDS = 8.0
_MIN_PARTIAL_DURATION_SECONDS = 0.25
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_SERVER_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class SpeedCatalogError(ValueError):
    """The remote directory did not contain a safe, usable server list."""


class SpeedTransportError(OSError):
    """A bounded HTTPS measurement request failed."""


class SpeedResolutionError(OSError):
    """A hostname did not resolve exclusively to globally routable addresses."""


class SpeedRunError(RuntimeError):
    """A user-safe speed-test failure."""


class SpeedServerNotFoundError(KeyError):
    def __init__(self, server_id: str) -> None:
        self.server_id = server_id
        super().__init__(server_id)

    def as_detail(self) -> dict[str, str]:
        return {
            "code": "speed_server_not_found",
            "message": "the selected speed-test server is not available",
        }


@dataclass(frozen=True, slots=True)
class SpeedServerTarget:
    """A catalog-owned server identity and its private measurement endpoints."""

    public: SpeedServerResponse
    ping_url: str
    download_url: str
    upload_url: str


@dataclass(frozen=True, slots=True)
class TransferObservation:
    bytes_transferred: int
    duration_seconds: float
    payload_started_at: float | None = None
    payload_finished_at: float | None = None


@dataclass(frozen=True, slots=True)
class SpeedTestOptions:
    """Immutable, service-approved transfer budgets for one speed test."""

    download_bytes: int
    upload_bytes: int

    def __post_init__(self) -> None:
        for name, value in (
            ("download_bytes", self.download_bytes),
            ("upload_bytes", self.upload_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class SpeedRunnerResult:
    ping_ms: float
    jitter_ms: float
    download_mbps: float
    upload_mbps: float
    download_bytes: int
    upload_bytes: int
    duration_seconds: float


ProgressCallback = Callable[[SpeedPhase, float, int, int], Awaitable[None]]
TransferProgressCallback = Callable[[int], None]


class SpeedCatalogFetcher(Protocol):
    async def fetch_json(
        self, url: str, *, timeout: float, max_bytes: int
    ) -> object: ...


class SpeedLatencyProber(Protocol):
    async def ping(self, server: SpeedServerTarget, *, timeout: float) -> float: ...


class SpeedHostResolver(Protocol):
    async def resolve(
        self, hostname: str, port: int, *, timeout: float
    ) -> tuple[str, ...]: ...


class SpeedMeasurementClient(Protocol):
    async def ping(self, server: SpeedServerTarget, *, timeout: float) -> float: ...

    async def download(
        self,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        timeout: float,
        on_progress: TransferProgressCallback | None = None,
    ) -> TransferObservation: ...

    async def upload(
        self,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        timeout: float,
        on_progress: TransferProgressCallback | None = None,
    ) -> TransferObservation: ...


class SpeedJobRunner(Protocol):
    async def run(
        self,
        server: SpeedServerTarget,
        on_progress: ProgressCallback,
        options: SpeedTestOptions,
    ) -> SpeedRunnerResult: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SystemSpeedHostResolver:
    """Resolve HTTPS hosts through the event loop under a hard deadline."""

    async def resolve(
        self, hostname: str, port: int, *, timeout: float
    ) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(timeout):
            records = await loop.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        addresses: list[str] = []
        seen: set[str] = set()
        for family, _type, _protocol, _canonical, sockaddr in records:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            address = str(sockaddr[0])
            if address not in seen:
                seen.add(address)
                addresses.append(address)
        return tuple(addresses)


def _safe_optional_text(value: object, *, maximum: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in value
    ).strip()
    if not cleaned:
        return None
    return cleaned[:maximum]


def _directory_location(row: dict[object, object], name: str) -> str | None:
    explicit = _safe_optional_text(
        row.get("location") or row.get("city"), maximum=120
    )
    if explicit is not None:
        return explicit
    # The official directory currently carries display metadata in names such
    # as "Amsterdam, Netherlands (Operator)" rather than separate fields.
    inferred = name.split(" (", 1)[0].strip()
    if inferred != name or "," in inferred:
        return inferred[:120]
    return None


def _validated_external_host(hostname: str) -> None:
    """Reject obviously local destinations before an untrusted entry is cached."""

    if not hostname or _CONTROL_CHARACTERS.search(hostname):
        raise SpeedCatalogError("server endpoint has an invalid host")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise SpeedCatalogError("server endpoint has an invalid host") from exc
        lowered = ascii_host.casefold()
        if (
            "." not in lowered
            or lowered == "localhost"
            or lowered.endswith((".localhost", ".local", ".internal"))
            or len(lowered) > 253
            or any(not _DNS_LABEL.fullmatch(label) for label in lowered.split("."))
        ):
            raise SpeedCatalogError("server endpoint must use a public host")
        return
    if not address.is_global:
        raise SpeedCatalogError("server endpoint must use a public address")


async def _ensure_public_resolution(
    url: str, resolver: SpeedHostResolver, *, timeout: float
) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.casefold() != "https" or parsed.hostname is None:
        raise SpeedResolutionError("outbound endpoint is not HTTPS")
    hostname = parsed.hostname
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addresses = await resolver.resolve(
                hostname, parsed.port or 443, timeout=timeout
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise SpeedResolutionError("server hostname could not be resolved") from exc
        if not addresses:
            raise SpeedResolutionError("server hostname returned no addresses")
        try:
            resolved = tuple(ipaddress.ip_address(address) for address in addresses)
        except ValueError as exc:
            raise SpeedResolutionError("server hostname returned an invalid address") from exc
        if any(not address.is_global for address in resolved):
            raise SpeedResolutionError(
                "server hostname returned a non-public address"
            )
        return
    if not literal.is_global:
        raise SpeedResolutionError("server endpoint is not globally routable")


def _validated_https_base(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise SpeedCatalogError("server endpoint is missing")
    candidate = value.strip()
    # LibreSpeed's official directory historically used protocol-relative URLs
    # for some entries. Upgrade those to HTTPS; explicit HTTP is never upgraded.
    if candidate.startswith("//"):
        candidate = "https:" + candidate
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SpeedCatalogError("server endpoint must be an HTTPS origin")
    try:
        parsed.port
    except ValueError as exc:
        raise SpeedCatalogError("server endpoint has an invalid port") from exc
    _validated_external_host(parsed.hostname)
    normalized = candidate
    return normalized if normalized.endswith("/") else normalized + "/"


def _validated_relative_endpoint(base: str, value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise SpeedCatalogError("measurement endpoint is missing")
    if "\\" in value or _CONTROL_CHARACTERS.search(value):
        raise SpeedCatalogError("measurement endpoint is invalid")
    relative = urlsplit(value.strip())
    if relative.scheme or relative.netloc or relative.fragment:
        raise SpeedCatalogError("measurement endpoint must be relative")
    decoded_path = unquote(relative.path)
    if any(part == ".." for part in decoded_path.split("/")):
        raise SpeedCatalogError("measurement endpoint contains path traversal")

    joined = urljoin(base, value.strip())
    base_parts = urlsplit(base)
    joined_parts = urlsplit(joined)
    if (
        joined_parts.scheme.casefold() != "https"
        or joined_parts.netloc.casefold() != base_parts.netloc.casefold()
        or not joined_parts.path
    ):
        raise SpeedCatalogError("measurement endpoint changed server origin")
    return joined


def _cloudflare_target() -> SpeedServerTarget:
    public = SpeedServerResponse(
        id=CLOUDFLARE_SERVER_ID,
        name="Cloudflare Automatic Edge",
        provider="cloudflare",
        location="Automatic edge selection",
        country=None,
        sponsor="Cloudflare",
        automatic=True,
    )
    return SpeedServerTarget(
        public=public,
        ping_url="https://speed.cloudflare.com/__down",
        download_url="https://speed.cloudflare.com/__down",
        upload_url="https://speed.cloudflare.com/__up",
    )


def parse_librespeed_directory(payload: object) -> tuple[SpeedServerTarget, ...]:
    """Parse the official directory while dropping unsafe or malformed rows.

    Directory contents are remote input. One bad row must not suppress the
    remaining public servers, but a response with no usable rows is rejected.
    """

    rows: object = payload.get("servers") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise SpeedCatalogError("LibreSpeed directory must contain a server list")

    parsed: list[SpeedServerTarget] = []
    seen: set[str] = {CLOUDFLARE_SERVER_ID}
    for row in rows[: _MAX_DIRECTORY_SERVERS * 4]:
        if not isinstance(row, dict):
            continue
        try:
            raw_id = row.get("id")
            if isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
                raise SpeedCatalogError("server ID is invalid")
            server_id = str(raw_id).strip()
            if not _SERVER_ID.fullmatch(server_id) or server_id in seen:
                raise SpeedCatalogError("server ID is invalid or duplicated")

            name = _safe_optional_text(row.get("name"), maximum=120)
            if name is None:
                raise SpeedCatalogError("server name is missing")
            base = _validated_https_base(row.get("server"))
            target = SpeedServerTarget(
                public=SpeedServerResponse(
                    id=server_id,
                    name=name,
                    provider="librespeed",
                    location=_directory_location(row, name),
                    country=_safe_optional_text(
                        row.get("country", row.get("countryCode")), maximum=80
                    ),
                    sponsor=_safe_optional_text(
                        row.get("sponsor") or row.get("sponsorName"), maximum=120
                    ),
                    automatic=False,
                ),
                ping_url=_validated_relative_endpoint(base, row.get("pingURL")),
                download_url=_validated_relative_endpoint(base, row.get("dlURL")),
                upload_url=_validated_relative_endpoint(base, row.get("ulURL")),
            )
        except (SpeedCatalogError, ValueError):
            continue
        seen.add(server_id)
        parsed.append(target)
        if len(parsed) >= _MAX_DIRECTORY_SERVERS:
            break

    if not parsed:
        raise SpeedCatalogError("LibreSpeed directory had no usable HTTPS servers")
    return tuple(parsed)


class HttpxSpeedClient:
    """Bounded, redirect-free HTTP transport for directory and test traffic."""

    # Reuse one moderately large, allocation-free payload. A 256 KiB chunk keeps
    # Python generator overhead low without buffering an entire selected upload.
    _UPLOAD_CHUNK = bytes(range(256)) * 1024

    def __init__(
        self,
        client: httpx.AsyncClient | None = None,
        *,
        resolver: SpeedHostResolver | None = None,
        dns_timeout: float = 3.0,
    ) -> None:
        self._client = client or httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            headers={
                "User-Agent": "Better-Network-Tools-NetSpeed/0.1",
                "Accept-Encoding": "identity",
            },
            limits=httpx.Limits(
                max_connections=_MAX_TRANSFER_CONCURRENCY,
                max_keepalive_connections=_MAX_TRANSFER_CONCURRENCY,
            ),
        )
        self._owns_client = client is None
        self._resolver = resolver or SystemSpeedHostResolver()
        self._dns_timeout = dns_timeout

    async def fetch_json(
        self, url: str, *, timeout: float, max_bytes: int
    ) -> object:
        try:
            await _ensure_public_resolution(
                url, self._resolver, timeout=min(timeout, self._dns_timeout)
            )
            async with self._client.stream(
                "GET",
                url,
                timeout=httpx.Timeout(timeout),
                headers={"Accept": "application/json"},
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(body) + len(chunk) > max_bytes:
                        raise SpeedCatalogError("LibreSpeed directory response is too large")
                    body.extend(chunk)
        except asyncio.CancelledError:
            raise
        except SpeedCatalogError:
            raise
        except (httpx.HTTPError, SpeedResolutionError, TimeoutError) as exc:
            raise SpeedCatalogError("LibreSpeed directory is unavailable") from exc
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpeedCatalogError("LibreSpeed directory returned invalid JSON") from exc

    async def ping(self, server: SpeedServerTarget, *, timeout: float) -> float:
        params = {"r": str(time.monotonic_ns())}
        if server.public.provider == "cloudflare":
            params["bytes"] = "0"
        url = str(httpx.URL(server.ping_url).copy_merge_params(params))
        try:
            await _ensure_public_resolution(
                url, self._resolver, timeout=min(timeout, self._dns_timeout)
            )
            # DNS safety validation is deliberately outside latency timing. The
            # request still performs normal TLS verification and refuses redirects.
            started = time.perf_counter()
            async with self._client.stream(
                "GET",
                url,
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                received = 0
                async for chunk in response.aiter_raw():
                    received += len(chunk)
                    if received > 65_536:
                        raise SpeedTransportError("ping response exceeded its byte limit")
        except asyncio.CancelledError:
            raise
        except SpeedTransportError:
            raise
        except (httpx.HTTPError, SpeedResolutionError, TimeoutError) as exc:
            raise SpeedTransportError("ping request failed") from exc
        return max(0.0, (time.perf_counter() - started) * 1000.0)

    async def download(
        self,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        timeout: float,
        on_progress: TransferProgressCallback | None = None,
    ) -> TransferObservation:
        params = {"r": str(time.monotonic_ns())}
        if server.public.provider == "cloudflare":
            params["bytes"] = str(byte_limit)
        else:
            params["ckSize"] = str(max(1, math.ceil(byte_limit / _MEBIBYTE)))
        url = str(httpx.URL(server.download_url).copy_merge_params(params))
        received = 0
        payload_started_at: float | None = None
        payload_finished_at: float | None = None
        try:
            await _ensure_public_resolution(
                url, self._resolver, timeout=min(timeout, self._dns_timeout)
            )
            async with self._client.stream(
                "GET",
                url,
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                # httpx enters the streaming response after headers arrive. Start
                # here so DNS, TCP/TLS setup, and time-to-first-byte do not dominate
                # a high-bandwidth payload measurement.
                payload_started_at = time.perf_counter()
                async for chunk in response.aiter_raw():
                    accepted = min(len(chunk), byte_limit - received)
                    if accepted <= 0:
                        break
                    received += accepted
                    payload_finished_at = time.perf_counter()
                    if on_progress is not None:
                        on_progress(received)
                    if received >= byte_limit:
                        break
        except asyncio.CancelledError:
            raise
        except (httpx.HTTPError, SpeedResolutionError, TimeoutError) as exc:
            # A peer can terminate a large response after useful payload has
            # already arrived. Preserve those measured bytes so the bounded lane
            # logic can request only the exact remainder instead of discarding
            # progress or replaying an already received payload.
            if (
                received <= 0
                or payload_started_at is None
                or payload_finished_at is None
            ):
                raise SpeedTransportError("download request failed") from exc
        if received <= 0:
            raise SpeedTransportError("download response was empty")
        if payload_started_at is None or payload_finished_at is None:
            raise SpeedTransportError("download payload timing was unavailable")
        return TransferObservation(
            bytes_transferred=received,
            duration_seconds=max(
                payload_finished_at - payload_started_at, 0.000_001
            ),
            payload_started_at=payload_started_at,
            payload_finished_at=payload_finished_at,
        )

    async def upload(
        self,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        timeout: float,
        on_progress: TransferProgressCallback | None = None,
    ) -> TransferObservation:
        sent = 0
        payload_started_at: float | None = None
        payload_finished_at: float | None = None
        url = server.upload_url
        if server.public.provider == "cloudflare":
            url = str(
                httpx.URL(url).copy_merge_params(
                    {
                        "bytes": str(byte_limit),
                        "r": str(time.monotonic_ns()),
                    }
                )
            )

        async def content():
            nonlocal sent, payload_started_at, payload_finished_at
            remaining = byte_limit
            while remaining:
                chunk = self._UPLOAD_CHUNK[: min(remaining, len(self._UPLOAD_CHUNK))]
                remaining -= len(chunk)
                if payload_started_at is None:
                    payload_started_at = time.perf_counter()
                yield chunk
                # The generator resumes only after httpx has consumed the prior
                # chunk, so this tracks request-body progress rather than response
                # processing time.
                sent += len(chunk)
                payload_finished_at = time.perf_counter()
                if on_progress is not None:
                    on_progress(sent)

        try:
            await _ensure_public_resolution(
                url,
                self._resolver,
                timeout=min(timeout, self._dns_timeout),
            )
            async with self._client.stream(
                "POST",
                url,
                content=content(),
                headers={
                    "Content-Length": str(byte_limit),
                    "Content-Type": "application/octet-stream",
                    "Content-Encoding": "identity",
                },
                timeout=httpx.Timeout(timeout),
                follow_redirects=False,
            ) as response:
                response.raise_for_status()
                received = 0
                async for chunk in response.aiter_raw():
                    received += len(chunk)
                    if received > 65_536:
                        raise SpeedTransportError(
                            "upload response exceeded its byte limit"
                        )
        except asyncio.CancelledError:
            raise
        except SpeedTransportError:
            raise
        except (httpx.HTTPError, SpeedResolutionError, TimeoutError) as exc:
            raise SpeedTransportError("upload request failed") from exc
        if (
            sent != byte_limit
            or payload_started_at is None
            or payload_finished_at is None
        ):
            raise SpeedTransportError("upload payload was not sent completely")
        return TransferObservation(
            bytes_transferred=sent,
            duration_seconds=max(
                payload_finished_at - payload_started_at, 0.000_001
            ),
            payload_started_at=payload_started_at,
            payload_finished_at=payload_finished_at,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()


class SpeedServerCatalog:
    """Fetch, validate, and cache the public LibreSpeed directory."""

    def __init__(
        self,
        settings: Settings,
        *,
        fetcher: SpeedCatalogFetcher | None = None,
        prober: SpeedLatencyProber | None = None,
        resolver: SpeedHostResolver | None = None,
        directory_url: str = LIBRESPEED_DIRECTORY_URL,
    ) -> None:
        if urlsplit(directory_url).scheme.casefold() != "https":
            raise ValueError("the LibreSpeed directory URL must use HTTPS")
        self.settings = settings
        self.directory_url = directory_url
        self.resolver = resolver or SystemSpeedHostResolver()
        if fetcher is None:
            default_client = HttpxSpeedClient(
                resolver=self.resolver,
                dns_timeout=settings.speed_dns_timeout_seconds,
            )
            self.fetcher = default_client
            self.prober = prober or default_client
        else:
            self.fetcher = fetcher
            # Injected catalog fetchers are commonly network-free test doubles.
            # Only probe them when a caller supplies that capability explicitly.
            self.prober = prober
        self._owns_fetcher = fetcher is None
        self._cloudflare = _cloudflare_target()
        self._targets: dict[str, SpeedServerTarget] = {
            self._cloudflare.public.id: self._cloudflare
        }
        self._refreshed_at = _utc_now()
        self._directory_status: SpeedDirectoryStatus = "unavailable"
        self._expires_at = 0.0
        self._quarantined_until: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def list_servers(self) -> SpeedServerListResponse:
        if time.monotonic() >= self._expires_at:
            await self._refresh()
        return self._snapshot()

    async def resolve(self, server_id: str) -> SpeedServerTarget:
        if server_id == self._cloudflare.public.id:
            return self._cloudflare
        await self.list_servers()
        target = self._targets.get(server_id)
        if target is None or self._is_quarantined(server_id):
            raise SpeedServerNotFoundError(server_id)
        return target

    async def report_failure(self, server_id: str) -> None:
        """Temporarily hide a failed public server without trusting caller URLs."""

        if server_id == self._cloudflare.public.id:
            return
        async with self._lock:
            if server_id in self._targets:
                self._quarantined_until[server_id] = (
                    time.monotonic() + _SERVER_FAILURE_QUARANTINE_SECONDS
                )

    async def _refresh(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._expires_at:
                return
            try:
                async with asyncio.timeout(
                    self.settings.speed_catalog_timeout_seconds
                ):
                    payload = await self.fetcher.fetch_json(
                        self.directory_url,
                        timeout=self.settings.speed_catalog_timeout_seconds,
                        max_bytes=self.settings.speed_catalog_max_bytes,
                    )
                    directory_targets = parse_librespeed_directory(payload)
                    directory_targets = await self._public_directory_targets(
                        directory_targets
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                self._directory_status = (
                    "stale" if len(self._targets) > 1 else "unavailable"
                )
                # Avoid retrying a failed public request on every UI poll.
                self._expires_at = now + min(
                    60.0, float(self.settings.speed_catalog_ttl_seconds)
                )
                return

            ordered = await self._rank_directory_targets(directory_targets)
            self._targets = {
                self._cloudflare.public.id: self._cloudflare,
                **{target.public.id: target for target in ordered},
            }
            self._refreshed_at = _utc_now()
            self._directory_status = "fresh"
            self._expires_at = now + self.settings.speed_catalog_ttl_seconds

    async def _public_directory_targets(
        self, targets: tuple[SpeedServerTarget, ...]
    ) -> tuple[SpeedServerTarget, ...]:
        semaphore = asyncio.Semaphore(8)

        async def validate(
            target: SpeedServerTarget,
        ) -> SpeedServerTarget | None:
            try:
                async with semaphore:
                    await asyncio.gather(
                        *(
                            _ensure_public_resolution(
                                endpoint,
                                self.resolver,
                                timeout=self.settings.speed_dns_timeout_seconds,
                            )
                            for endpoint in self._unique_endpoint_origins(target)
                        )
                    )
            except asyncio.CancelledError:
                raise
            except Exception:
                return None
            return target

        async with asyncio.timeout(self.settings.speed_catalog_timeout_seconds):
            checked = await asyncio.gather(*(validate(target) for target in targets))
        public = tuple(target for target in checked if target is not None)
        if not public:
            raise SpeedCatalogError(
                "LibreSpeed directory had no publicly resolving HTTPS servers"
            )
        return public

    async def _rank_directory_targets(
        self, targets: tuple[SpeedServerTarget, ...]
    ) -> tuple[SpeedServerTarget, ...]:
        """Rank public servers by a small, bounded HTTPS latency sample.

        Latency is a practical network-distance estimate and avoids relying on
        third-party IP geolocation. Servers that fail or outlive the wall-clock
        budget remain available after measured servers in deterministic order.
        """

        prober = self.prober
        if prober is None:
            return tuple(sorted(targets, key=self._directory_sort_key))

        semaphore = asyncio.Semaphore(_SERVER_RANK_CONCURRENCY)
        probe_timeout = min(
            _SERVER_RANK_PROBE_TIMEOUT_SECONDS,
            self.settings.speed_request_timeout_seconds,
        )

        async def probe(target: SpeedServerTarget) -> SpeedServerTarget:
            try:
                async with semaphore:
                    async with asyncio.timeout(probe_timeout):
                        sample = await prober.ping(target, timeout=probe_timeout)
                if (
                    isinstance(sample, bool)
                    or not isinstance(sample, (int, float))
                    or not math.isfinite(sample)
                    or sample < 0
                ):
                    return target
                return SpeedServerTarget(
                    public=target.public.model_copy(
                        update={"latency_ms": round(float(sample), 2)}
                    ),
                    ping_url=target.ping_url,
                    download_url=target.download_url,
                    upload_url=target.upload_url,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                return target

        tasks = [asyncio.create_task(probe(target)) for target in targets]
        try:
            done, pending = await asyncio.wait(
                tasks,
                timeout=_SERVER_RANK_WALL_TIMEOUT_SECONDS,
            )
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

        measured = tuple(
            task.result() if task in done and not task.cancelled() else target
            for target, task in zip(targets, tasks, strict=True)
        )
        return tuple(sorted(measured, key=self._latency_sort_key))

    @staticmethod
    def _directory_sort_key(
        target: SpeedServerTarget,
    ) -> tuple[str, str, str, str]:
        return (
            target.public.country or "",
            target.public.location or "",
            target.public.name,
            target.public.id,
        )

    @classmethod
    def _latency_sort_key(
        cls, target: SpeedServerTarget
    ) -> tuple[bool, float, str, str, str, str]:
        latency = target.public.latency_ms
        return (
            latency is None,
            latency if latency is not None else math.inf,
            *cls._directory_sort_key(target),
        )

    @staticmethod
    def _unique_endpoint_origins(target: SpeedServerTarget) -> tuple[str, ...]:
        origins: dict[tuple[str, str, int], str] = {}
        for endpoint in (target.ping_url, target.download_url, target.upload_url):
            parsed = urlsplit(endpoint)
            if parsed.hostname is None:
                raise SpeedCatalogError("measurement endpoint has an invalid origin")
            key = (
                parsed.scheme.casefold(),
                parsed.hostname.casefold(),
                parsed.port or 443,
            )
            origins.setdefault(key, endpoint)
        return tuple(origins.values())

    def _is_quarantined(self, server_id: str) -> bool:
        return self._quarantined_until.get(server_id, 0.0) > time.monotonic()

    def _snapshot(self) -> SpeedServerListResponse:
        return SpeedServerListResponse(
            servers=[
                target.public
                for server_id, target in self._targets.items()
                if not self._is_quarantined(server_id)
            ],
            refreshed_at=self._refreshed_at,
            directory_status=self._directory_status,
        )

    async def shutdown(self) -> None:
        if self._owns_fetcher:
            close = getattr(self.fetcher, "aclose", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result


class SpeedTestRunner:
    """Run ping plus bounded, parallel transfer measurements within hard caps."""

    def __init__(
        self,
        settings: Settings,
        *,
        client: SpeedMeasurementClient | None = None,
        transfer_concurrency: int = _DEFAULT_TRANSFER_CONCURRENCY,
    ) -> None:
        if (
            isinstance(transfer_concurrency, bool)
            or not isinstance(transfer_concurrency, int)
            or not 1 <= transfer_concurrency <= _MAX_TRANSFER_CONCURRENCY
        ):
            raise ValueError(
                "transfer_concurrency must be between 1 and "
                f"{_MAX_TRANSFER_CONCURRENCY}"
            )
        self.settings = settings
        self.client = client or HttpxSpeedClient(
            dns_timeout=settings.speed_dns_timeout_seconds
        )
        self.transfer_concurrency = transfer_concurrency
        self._owns_client = client is None

    async def run(
        self,
        server: SpeedServerTarget,
        on_progress: ProgressCallback,
        options: SpeedTestOptions,
    ) -> SpeedRunnerResult:
        self._validate_options(options)
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self.settings.speed_total_timeout_seconds):
                await on_progress("ping", 5.0, 0, 0)
                try:
                    samples = await self._ping_samples(server, on_progress)
                except (SpeedTransportError, httpx.HTTPError, OSError) as exc:
                    raise SpeedRunError(
                        "The selected speed-test server did not complete "
                        "latency checks."
                    ) from exc

                await on_progress("download", 30.0, 0, 0)
                try:
                    download = await self._parallel_transfer(
                        "download",
                        server,
                        byte_limit=options.download_bytes,
                        on_progress=on_progress,
                        completed_download_bytes=0,
                    )
                except (
                    SpeedTransportError,
                    httpx.HTTPError,
                    OSError,
                    TimeoutError,
                ) as exc:
                    raise SpeedRunError(
                        "The selected speed-test server did not complete "
                        "the download test."
                    ) from exc
                await on_progress(
                    "download", 65.0, download.bytes_transferred, 0
                )

                await on_progress(
                    "upload", 70.0, download.bytes_transferred, 0
                )
                try:
                    upload = await self._parallel_transfer(
                        "upload",
                        server,
                        byte_limit=options.upload_bytes,
                        on_progress=on_progress,
                        completed_download_bytes=download.bytes_transferred,
                    )
                except (
                    SpeedTransportError,
                    httpx.HTTPError,
                    OSError,
                    TimeoutError,
                ) as exc:
                    raise SpeedRunError(
                        "The selected speed-test server did not complete "
                        "the upload test."
                    ) from exc
                await on_progress(
                    "upload",
                    95.0,
                    download.bytes_transferred,
                    upload.bytes_transferred,
                )
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            raise SpeedRunError(
                "The speed test exceeded the configured time limit."
            ) from exc
        except SpeedRunError:
            raise

        if not samples:
            raise SpeedRunError("The speed test returned no latency measurements.")
        ping_ms = statistics.median(samples)
        jitter_ms = (
            statistics.fmean(
                abs(current - previous)
                for previous, current in zip(samples, samples[1:], strict=False)
            )
            if len(samples) > 1
            else 0.0
        )
        return SpeedRunnerResult(
            ping_ms=round(ping_ms, 2),
            jitter_ms=round(jitter_ms, 2),
            download_mbps=round(
                download.bytes_transferred * 8
                / download.duration_seconds
                / 1_000_000,
                2,
            ),
            upload_mbps=round(
                upload.bytes_transferred * 8
                / upload.duration_seconds
                / 1_000_000,
                2,
            ),
            download_bytes=download.bytes_transferred,
            upload_bytes=upload.bytes_transferred,
            duration_seconds=round(max(time.perf_counter() - started, 0.001), 3),
        )

    async def _ping_samples(
        self, server: SpeedServerTarget, on_progress: ProgressCallback
    ) -> list[float]:
        samples: list[float] = []
        attempts = 0
        maximum_attempts = self.settings.speed_ping_samples + _MAX_EXTRA_PING_ATTEMPTS
        timeout = min(
            self.settings.speed_request_timeout_seconds,
            _MAX_PING_REQUEST_TIMEOUT_SECONDS,
        )
        last_error: BaseException | None = None
        while len(samples) < self.settings.speed_ping_samples:
            attempts += 1
            try:
                sample = await self.client.ping(server, timeout=timeout)
                if not math.isfinite(sample) or sample < 0:
                    raise SpeedTransportError("ping measurement was invalid")
            except asyncio.CancelledError:
                raise
            except (SpeedTransportError, httpx.HTTPError, OSError, TimeoutError) as exc:
                last_error = exc
                if attempts >= maximum_attempts:
                    raise SpeedTransportError("latency checks failed") from exc
                continue
            samples.append(sample)
            await on_progress(
                "ping",
                5.0
                + 20.0 * len(samples) / self.settings.speed_ping_samples,
                0,
                0,
            )
        if len(samples) != self.settings.speed_ping_samples:
            raise SpeedTransportError("latency checks were incomplete") from last_error
        return samples

    def _validate_options(self, options: SpeedTestOptions) -> None:
        if (
            options.download_bytes > self.settings.speed_download_byte_limit
            or options.upload_bytes > self.settings.speed_upload_byte_limit
        ):
            raise SpeedRunError(
                "The selected transfer size exceeds the configured safety limit."
            )

    async def _parallel_transfer(
        self,
        phase: str,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        on_progress: ProgressCallback,
        completed_download_bytes: int,
    ) -> TransferObservation:
        stream_limits = self._split_byte_limit(byte_limit)
        stream_progress = [0 for _ in stream_limits]
        stream_started_at: list[float | None] = [None for _ in stream_limits]
        stream_finished_at: list[float | None] = [None for _ in stream_limits]
        reporter_stopped = asyncio.Event()

        def progress_callback(index: int) -> TransferProgressCallback:
            def update(value: int) -> None:
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise SpeedTransportError("transfer progress was invalid")
                previous = stream_progress[index]
                current = min(
                    stream_limits[index], max(stream_progress[index], value)
                )
                stream_progress[index] = current
                if current > previous:
                    now = time.perf_counter()
                    if stream_started_at[index] is None:
                        stream_started_at[index] = now
                    stream_finished_at[index] = now

            return update

        async def report_progress() -> None:
            while True:
                await asyncio.sleep(_PROGRESS_INTERVAL_SECONDS)
                if reporter_stopped.is_set():
                    return
                transferred = min(sum(stream_progress), byte_limit)
                ratio = transferred / byte_limit
                if phase == "download":
                    await on_progress(
                        "download", 30.0 + 35.0 * ratio, transferred, 0
                    )
                else:
                    await on_progress(
                        "upload",
                        70.0 + 25.0 * ratio,
                        completed_download_bytes,
                        transferred,
                    )

        tasks = [
            asyncio.create_task(
                self._transfer_lane(
                    phase,
                    server,
                    byte_limit=stream_limit,
                    on_progress=progress_callback(index),
                ),
                name=f"netspeed-{phase}-{index + 1}",
            )
            for index, stream_limit in enumerate(stream_limits)
        ]
        reporter = asyncio.create_task(
            report_progress(), name=f"netspeed-{phase}-progress"
        )
        lane_results: list[TransferObservation | BaseException] | None = None
        phase_timed_out_at: float | None = None
        try:
            # The per-phase wall deadline keeps a deliberately large selected
            # budget usable on slower links. A phase that made measurable
            # progress returns a bounded partial observation rather than failing
            # the entire job solely because it did not consume the full budget.
            async with asyncio.timeout(
                self.settings.speed_request_timeout_seconds
            ):
                lane_results = await asyncio.gather(
                    *tasks, return_exceptions=True
                )
        except TimeoutError:
            phase_timed_out_at = time.perf_counter()
            lane_results = None
        finally:
            # Ensure a deadline or external cancellation cannot leave bulk traffic
            # running after this phase has returned.
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            reporter_stopped.set()
            if not reporter.done():
                reporter.cancel()
            await asyncio.gather(reporter, return_exceptions=True)

        if lane_results is None:
            partial_bytes = min(sum(stream_progress), byte_limit)
            valid_starts = [item for item in stream_started_at if item is not None]
            valid_finishes = [item for item in stream_finished_at if item is not None]
            if partial_bytes <= 0 or not valid_starts or not valid_finishes:
                raise TimeoutError
            partial_started_at = min(valid_starts)
            partial_finished_at = max(
                valid_finishes,
                default=phase_timed_out_at or time.perf_counter(),
            )
            if phase_timed_out_at is not None:
                partial_finished_at = max(partial_finished_at, phase_timed_out_at)
            partial_duration = max(
                partial_finished_at - partial_started_at,
                _MIN_PARTIAL_DURATION_SECONDS,
            )
            partial = TransferObservation(
                bytes_transferred=partial_bytes,
                duration_seconds=partial_duration,
                payload_started_at=partial_started_at,
                payload_finished_at=partial_finished_at,
            )
            self._validate_transfer(partial, byte_limit)
            return partial

        observations: list[TransferObservation] = []
        failures: list[BaseException] = []
        for result, stream_limit in zip(lane_results, stream_limits, strict=True):
            if isinstance(result, BaseException):
                failures.append(result)
                continue
            observation = result
            self._validate_transfer(observation, stream_limit)
            observations.append(observation)

        if failures:
            # Never convert cancellation or unexpected programming failures into
            # a partial measurement. Cloudflare downloads alone may retain the
            # successful lanes after an expected transport failure; uploads and
            # third-party servers remain strict.
            for failure in failures:
                if not isinstance(failure, SpeedTransportError):
                    raise failure
            if (
                phase != "download"
                or server.public.provider != "cloudflare"
                or not observations
            ):
                raise failures[0]

        aggregate = self._aggregate_observations(observations)
        self._validate_transfer(aggregate, byte_limit)
        return aggregate

    async def _transfer_lane(
        self,
        phase: str,
        server: SpeedServerTarget,
        *,
        byte_limit: int,
        on_progress: TransferProgressCallback,
    ) -> TransferObservation:
        transfer = (
            self.client.download if phase == "download" else self.client.upload
        )
        if server.public.provider == "cloudflare":
            request_limit = (
                _CLOUDFLARE_MAX_DOWNLOAD_REQUEST_BYTES
                if phase == "download"
                else _CLOUDFLARE_MAX_UPLOAD_REQUEST_BYTES
            )
        else:
            request_limit = (
                _LIBRESPEED_MAX_DOWNLOAD_REQUEST_BYTES
                if phase == "download"
                else _LIBRESPEED_MAX_UPLOAD_REQUEST_BYTES
            )
        zero_progress_retry_limit = (
            _CLOUDFLARE_MAX_ZERO_PROGRESS_DOWNLOAD_RETRIES
            if phase == "download" and server.public.provider == "cloudflare"
            else _MAX_ZERO_PROGRESS_DOWNLOAD_RETRIES
            if phase == "download"
            else 0
        )
        planned_requests = math.ceil(byte_limit / request_limit)
        max_requests = (
            planned_requests
            + _MAX_EXTRA_PARTIAL_REQUESTS
            + zero_progress_retry_limit
        )
        completed = 0
        observations: list[TransferObservation] = []
        zero_progress_retries = 0

        for _attempt in range(max_requests):
            if completed >= byte_limit:
                break
            current_limit = min(request_limit, byte_limit - completed)

            def request_progress(value: int, *, base: int = completed) -> None:
                on_progress(min(byte_limit, base + value))

            request_progress_bytes = 0

            def tracked_request_progress(value: int) -> None:
                nonlocal request_progress_bytes
                request_progress_bytes = max(request_progress_bytes, value)
                request_progress(value)

            try:
                observation = await transfer(
                    server,
                    byte_limit=current_limit,
                    # The enclosing phase deadline must win over a per-request
                    # inactivity timeout so valid partial payload progress can be
                    # retained instead of being wrapped as a transport failure.
                    timeout=self.settings.speed_request_timeout_seconds + 1.0,
                    on_progress=tracked_request_progress,
                )
            except asyncio.CancelledError:
                raise
            except SpeedTransportError:
                # A download that failed before yielding any response payload can
                # be retried within its provider-specific cap without
                # double-counting the selected byte budget.
                # Upload writes are never retried because a remote peer may have
                # received bytes before local write progress becomes observable.
                if (
                    phase == "download"
                    and request_progress_bytes == 0
                    and zero_progress_retries < zero_progress_retry_limit
                ):
                    zero_progress_retries += 1
                    continue
                raise
            self._validate_transfer(observation, current_limit)
            observations.append(observation)
            completed += observation.bytes_transferred
            on_progress(completed)

        if not observations:
            raise SpeedTransportError("transfer lane returned no observations")
        return self._aggregate_observations(observations, concurrent=False)

    def _split_byte_limit(self, byte_limit: int) -> tuple[int, ...]:
        stream_count = min(self.transfer_concurrency, byte_limit)
        quotient, remainder = divmod(byte_limit, stream_count)
        limits = tuple(
            quotient + (1 if index < remainder else 0)
            for index in range(stream_count)
        )
        if sum(limits) != byte_limit or any(limit <= 0 for limit in limits):
            raise SpeedTransportError("transfer byte allocation was invalid")
        return limits

    @staticmethod
    def _aggregate_observations(
        observations: list[TransferObservation], *, concurrent: bool = True
    ) -> TransferObservation:
        if not observations:
            raise SpeedTransportError("transfer returned no observations")
        total_bytes = sum(item.bytes_transferred for item in observations)
        has_payload_window = all(
            item.payload_started_at is not None
            and item.payload_finished_at is not None
            and math.isfinite(item.payload_started_at)
            and math.isfinite(item.payload_finished_at)
            and item.payload_finished_at >= item.payload_started_at
            for item in observations
        )
        if has_payload_window:
            payload_started_at = min(
                item.payload_started_at
                for item in observations
                if item.payload_started_at is not None
            )
            payload_finished_at = max(
                item.payload_finished_at
                for item in observations
                if item.payload_finished_at is not None
            )
            duration = max(payload_finished_at - payload_started_at, 0.000_001)
        else:
            payload_started_at = None
            payload_finished_at = None
            # Protocol fakes and alternate clients may only expose a payload
            # duration. Parallel lanes share one wall-clock interval; repeated
            # requests inside a lane are sequential.
            durations = [item.duration_seconds for item in observations]
            duration = max(durations) if concurrent else sum(durations)
        return TransferObservation(
            bytes_transferred=total_bytes,
            duration_seconds=duration,
            payload_started_at=payload_started_at,
            payload_finished_at=payload_finished_at,
        )

    @staticmethod
    def _validate_transfer(observation: TransferObservation, limit: int) -> None:
        if (
            observation.bytes_transferred <= 0
            or observation.bytes_transferred > limit
            or not math.isfinite(observation.duration_seconds)
            or observation.duration_seconds <= 0
        ):
            raise SpeedTransportError("transfer measurement was invalid")

    async def shutdown(self) -> None:
        if self._owns_client:
            close = getattr(self.client, "aclose", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result
