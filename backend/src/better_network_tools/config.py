"""Environment-backed application configuration.

The API is intentionally restricted to loopback because it can initiate
network probes, open interactive sessions, and manage file-transfer services.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


_DEFAULT_CORS_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)


def normalize_loopback_host(host: str) -> str:
    """Return a canonical loopback bind host or reject an unsafe value."""

    candidate = host.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if candidate.lower() == "localhost":
        return "localhost"
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(
            "BNT_HOST must be localhost or a loopback IP address"
        ) from exc
    if not address.is_loopback:
        raise ValueError("BNT_HOST must be localhost or a loopback IP address")
    return address.compressed


def normalize_cors_origins(origins: tuple[str, ...]) -> tuple[str, ...]:
    """Validate, canonicalize, and de-duplicate explicit HTTP(S) origins."""

    normalized: list[str] = []
    for origin in origins:
        candidate = origin.strip()
        try:
            parsed = urlsplit(candidate)
            port = parsed.port
        except ValueError as exc:
            raise ValueError(
                "BNT_CORS_ORIGINS entries must be valid HTTP(S) origins"
            ) from exc
        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.netloc
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "BNT_CORS_ORIGINS entries must be HTTP(S) origins without "
                "credentials, paths, queries, or fragments"
            )

        scheme = parsed.scheme.lower()
        try:
            hostname = normalize_loopback_host(parsed.hostname)
        except ValueError as exc:
            raise ValueError(
                "BNT_CORS_ORIGINS entries must use localhost or a loopback IP"
            ) from exc
        if ":" in hostname:
            hostname = f"[{hostname}]"
        if port is not None and not (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        ):
            hostname = f"{hostname}:{port}"
        canonical = f"{scheme}://{hostname}"
        if canonical not in normalized:
            normalized.append(canonical)

    if not normalized:
        raise ValueError("BNT_CORS_ORIGINS must include at least one origin")
    return tuple(normalized)


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_int_with_legacy(
    name: str,
    legacy_name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Read a renamed integer setting while honoring its previous name."""

    raw = os.getenv(name)
    if raw is None:
        raw = os.getenv(legacy_name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_origins() -> tuple[str, ...]:
    raw = os.getenv("BNT_CORS_ORIGINS")
    if raw is None:
        return _DEFAULT_CORS_ORIGINS
    origins = tuple(origin for origin in raw.split(",") if origin.strip())
    return normalize_cors_origins(origins or _DEFAULT_CORS_ORIGINS)


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings with conservative defaults and hard safety ceilings."""

    host: str = "127.0.0.1"
    port: int = 8766
    scan_host_limit: int = 1024
    scan_concurrency: int = 64
    max_ports: int = 32
    port_scan_port_limit: int = 65535
    port_scan_concurrency: int = 128
    port_scan_active_job_limit: int = 2
    port_scan_result_limit: int = 2048
    port_scan_retained_job_limit: int = 64
    port_scan_timeout_limit_seconds: float = 5.0
    port_scan_resolve_timeout_seconds: float = 5.0
    port_scan_total_timeout_seconds: float = 900.0
    ping_target_limit: int = 32
    ping_sample_limit: int = 100
    ping_active_job_limit: int = 4
    ping_probe_concurrency: int = 32
    ping_resolver_concurrency: int = 8
    ping_resolve_timeout_seconds: float = 5.0
    ping_timeout_seconds: float = 1.0
    trace_hop_limit: int = 64
    trace_active_job_limit: int = 2
    trace_probe_timeout_limit_seconds: float = 5.0
    trace_total_timeout_seconds: float = 180.0
    trace_resolver_concurrency: int = 8
    trace_resolve_timeout_seconds: float = 5.0
    trace_asn_timeout_seconds: float = 8.0
    speed_active_job_limit: int = 1
    speed_ping_samples: int = 6
    speed_request_timeout_seconds: float = 30.0
    speed_total_timeout_seconds: float = 90.0
    speed_download_byte_minimum: int = 25_000_000
    speed_download_byte_default: int = 250_000_000
    speed_download_byte_limit: int = 2_000_000_000
    speed_upload_byte_minimum: int = 10_000_000
    speed_upload_byte_default: int = 100_000_000
    speed_upload_byte_limit: int = 1_000_000_000
    speed_catalog_timeout_seconds: float = 8.0
    speed_dns_timeout_seconds: float = 3.0
    speed_catalog_ttl_seconds: int = 900
    speed_catalog_max_bytes: int = 1_000_000
    ssh_active_session_limit: int = 4
    ssh_connect_timeout_seconds: float = 15.0
    ssh_handshake_timeout_seconds: float = 60.0
    telnet_active_session_limit: int = 4
    telnet_connect_timeout_seconds: float = 15.0
    telnet_handshake_timeout_seconds: float = 60.0
    transfer_root_directory: str = str(Path.home() / "Downloads" / "NetTransfer")
    transfer_default_bind_address: str = "127.0.0.1"
    transfer_tftp_default_port: int = 6969
    transfer_sftp_default_port: int = 2222
    transfer_ftp_default_port: int = 2121
    transfer_max_file_bytes: int = 1_073_741_824
    transfer_active_transfer_limit: int = 16
    transfer_per_client_transfer_limit: int = 4
    transfer_allowed_network_host_limit: int = 65_536
    transfer_sftp_host_key_path: str = str(
        Path.home() / ".better-network-tools" / "nettransfer-ed25519"
    )
    transfer_ftp_passive_port_start: int = 50_000
    transfer_ftp_passive_port_end: int = 50_019
    # Legacy TFTP names remain available to the RFC 1350 engine for one
    # compatibility window. load_settings() maps them to NetTransfer values.
    tftp_root_directory: str = str(Path.home() / "Downloads" / "NetTransfer")
    tftp_default_bind_address: str = "127.0.0.1"
    tftp_default_port: int = 6969
    tftp_max_file_bytes: int = 1_073_741_824
    tftp_active_transfer_limit: int = 16
    tftp_per_client_transfer_limit: int = 4
    tftp_retry_timeout_seconds: float = 2.0
    tftp_max_retries: int = 5
    tftp_transfer_timeout_seconds: float = 300.0
    tftp_max_block_size: int = 1468
    tftp_allowed_network_host_limit: int = 65_536
    update_repository: str = "erichbrinkman/betternetworktools"
    update_branch: str = "main"
    update_check_timeout_seconds: float = 10.0
    update_total_check_timeout_seconds: float = 300.0
    update_git_timeout_seconds: float = 120.0
    tcp_timeout_seconds: float = 0.75
    banner_timeout_seconds: float = 0.5
    job_retention_seconds: int = 3600
    cors_origins: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_CORS_ORIGINS)
    default_ports: tuple[int, ...] = (22, 23, 53, 80, 443, 445, 3389, 8080, 8443)


def load_settings() -> Settings:
    """Load and validate settings from ``BNT_*`` environment variables."""

    transfer_root = os.getenv(
        "BNT_TRANSFER_ROOT",
        os.getenv(
            "BNT_TFTP_ROOT", str(Path.home() / "Downloads" / "NetTransfer")
        ),
    )
    transfer_bind = os.getenv(
        "BNT_TRANSFER_BIND", os.getenv("BNT_TFTP_BIND", "127.0.0.1")
    )
    transfer_tftp_port = _env_int_with_legacy(
        "BNT_TRANSFER_TFTP_PORT",
        "BNT_TFTP_PORT",
        6969,
        minimum=1,
        maximum=65535,
    )
    transfer_max_file_bytes = _env_int_with_legacy(
        "BNT_TRANSFER_MAX_FILE_BYTES",
        "BNT_TFTP_MAX_FILE_BYTES",
        1_073_741_824,
        minimum=1_024,
        maximum=17_179_869_184,
    )
    transfer_active_limit = _env_int_with_legacy(
        "BNT_TRANSFER_ACTIVE_TRANSFER_LIMIT",
        "BNT_TFTP_ACTIVE_TRANSFER_LIMIT",
        16,
        minimum=1,
        maximum=128,
    )
    transfer_per_client_limit = _env_int_with_legacy(
        "BNT_TRANSFER_PER_CLIENT_TRANSFER_LIMIT",
        "BNT_TFTP_PER_CLIENT_TRANSFER_LIMIT",
        4,
        minimum=1,
        maximum=32,
    )
    transfer_allowed_host_limit = _env_int_with_legacy(
        "BNT_TRANSFER_ALLOWED_NETWORK_HOST_LIMIT",
        "BNT_TFTP_ALLOWED_NETWORK_HOST_LIMIT",
        65_536,
        minimum=1,
        maximum=16_777_216,
    )

    settings = Settings(
        host=normalize_loopback_host(os.getenv("BNT_HOST", "127.0.0.1")),
        port=_env_int("BNT_PORT", 8766, minimum=1, maximum=65535),
        scan_host_limit=_env_int(
            "BNT_SCAN_HOST_LIMIT", 1024, minimum=1, maximum=65536
        ),
        scan_concurrency=_env_int(
            "BNT_SCAN_CONCURRENCY", 64, minimum=1, maximum=512
        ),
        max_ports=_env_int("BNT_MAX_PORTS", 32, minimum=1, maximum=256),
        port_scan_port_limit=_env_int(
            "BNT_PORT_SCAN_PORT_LIMIT", 65535, minimum=1, maximum=65535
        ),
        port_scan_concurrency=_env_int(
            "BNT_PORT_SCAN_CONCURRENCY", 128, minimum=1, maximum=512
        ),
        port_scan_active_job_limit=_env_int(
            "BNT_PORT_SCAN_ACTIVE_JOB_LIMIT", 2, minimum=1, maximum=16
        ),
        port_scan_result_limit=_env_int(
            "BNT_PORT_SCAN_RESULT_LIMIT", 2048, minimum=1, maximum=65535
        ),
        port_scan_retained_job_limit=_env_int(
            "BNT_PORT_SCAN_RETAINED_JOB_LIMIT", 64, minimum=16, maximum=1024
        ),
        port_scan_timeout_limit_seconds=_env_float(
            "BNT_PORT_SCAN_TIMEOUT_LIMIT_SECONDS",
            5.0,
            minimum=0.05,
            maximum=10.0,
        ),
        port_scan_resolve_timeout_seconds=_env_float(
            "BNT_PORT_SCAN_RESOLVE_TIMEOUT_SECONDS",
            5.0,
            minimum=0.1,
            maximum=10.0,
        ),
        port_scan_total_timeout_seconds=_env_float(
            "BNT_PORT_SCAN_TOTAL_TIMEOUT_SECONDS",
            900.0,
            minimum=10.0,
            maximum=3600.0,
        ),
        ping_target_limit=_env_int(
            "BNT_PING_TARGET_LIMIT", 32, minimum=1, maximum=32
        ),
        ping_sample_limit=_env_int(
            "BNT_PING_SAMPLE_LIMIT", 100, minimum=1, maximum=100
        ),
        ping_active_job_limit=_env_int(
            "BNT_PING_ACTIVE_JOB_LIMIT", 4, minimum=1, maximum=32
        ),
        ping_probe_concurrency=_env_int(
            "BNT_PING_PROBE_CONCURRENCY", 32, minimum=1, maximum=32
        ),
        ping_resolver_concurrency=_env_int(
            "BNT_PING_RESOLVER_CONCURRENCY", 8, minimum=1, maximum=32
        ),
        ping_resolve_timeout_seconds=_env_float(
            "BNT_PING_RESOLVE_TIMEOUT_SECONDS", 5.0, minimum=0.1, maximum=10.0
        ),
        ping_timeout_seconds=_env_float(
            "BNT_PING_TIMEOUT_SECONDS", 1.0, minimum=0.05, maximum=10.0
        ),
        trace_hop_limit=_env_int(
            "BNT_TRACE_HOP_LIMIT", 64, minimum=1, maximum=64
        ),
        trace_active_job_limit=_env_int(
            "BNT_TRACE_ACTIVE_JOB_LIMIT", 2, minimum=1, maximum=16
        ),
        trace_probe_timeout_limit_seconds=_env_float(
            "BNT_TRACE_PROBE_TIMEOUT_LIMIT_SECONDS",
            5.0,
            minimum=0.2,
            maximum=5.0,
        ),
        trace_total_timeout_seconds=_env_float(
            "BNT_TRACE_TOTAL_TIMEOUT_SECONDS",
            180.0,
            minimum=5.0,
            maximum=900.0,
        ),
        trace_resolver_concurrency=_env_int(
            "BNT_TRACE_RESOLVER_CONCURRENCY", 8, minimum=1, maximum=32
        ),
        trace_resolve_timeout_seconds=_env_float(
            "BNT_TRACE_RESOLVE_TIMEOUT_SECONDS",
            5.0,
            minimum=0.1,
            maximum=10.0,
        ),
        trace_asn_timeout_seconds=_env_float(
            "BNT_TRACE_ASN_TIMEOUT_SECONDS", 8.0, minimum=0.5, maximum=30.0
        ),
        speed_active_job_limit=_env_int(
            "BNT_SPEED_ACTIVE_JOB_LIMIT", 1, minimum=1, maximum=8
        ),
        speed_ping_samples=_env_int(
            "BNT_SPEED_PING_SAMPLES", 6, minimum=2, maximum=20
        ),
        speed_request_timeout_seconds=_env_float(
            "BNT_SPEED_REQUEST_TIMEOUT_SECONDS",
            30.0,
            minimum=1.0,
            maximum=60.0,
        ),
        speed_total_timeout_seconds=_env_float(
            "BNT_SPEED_TOTAL_TIMEOUT_SECONDS",
            90.0,
            minimum=5.0,
            maximum=300.0,
        ),
        speed_download_byte_minimum=_env_int(
            "BNT_SPEED_DOWNLOAD_BYTE_MINIMUM",
            25_000_000,
            minimum=1_000_000,
            maximum=250_000_000,
        ),
        speed_download_byte_default=_env_int(
            "BNT_SPEED_DOWNLOAD_BYTE_DEFAULT",
            250_000_000,
            minimum=1_000_000,
            maximum=2_000_000_000,
        ),
        speed_download_byte_limit=_env_int(
            "BNT_SPEED_DOWNLOAD_BYTE_LIMIT",
            2_000_000_000,
            minimum=1_000_000,
            maximum=2_000_000_000,
        ),
        speed_upload_byte_minimum=_env_int(
            "BNT_SPEED_UPLOAD_BYTE_MINIMUM",
            10_000_000,
            minimum=1_000_000,
            maximum=100_000_000,
        ),
        speed_upload_byte_default=_env_int(
            "BNT_SPEED_UPLOAD_BYTE_DEFAULT",
            100_000_000,
            minimum=1_000_000,
            maximum=1_000_000_000,
        ),
        speed_upload_byte_limit=_env_int(
            "BNT_SPEED_UPLOAD_BYTE_LIMIT",
            1_000_000_000,
            minimum=1_000_000,
            maximum=1_000_000_000,
        ),
        speed_catalog_timeout_seconds=_env_float(
            "BNT_SPEED_CATALOG_TIMEOUT_SECONDS",
            8.0,
            minimum=1.0,
            maximum=30.0,
        ),
        speed_dns_timeout_seconds=_env_float(
            "BNT_SPEED_DNS_TIMEOUT_SECONDS",
            3.0,
            minimum=0.5,
            maximum=10.0,
        ),
        speed_catalog_ttl_seconds=_env_int(
            "BNT_SPEED_CATALOG_TTL_SECONDS", 900, minimum=60, maximum=86_400
        ),
        speed_catalog_max_bytes=_env_int(
            "BNT_SPEED_CATALOG_MAX_BYTES",
            1_000_000,
            minimum=10_000,
            maximum=5_000_000,
        ),
        ssh_active_session_limit=_env_int(
            "BNT_SSH_ACTIVE_SESSION_LIMIT", 4, minimum=1, maximum=16
        ),
        ssh_connect_timeout_seconds=_env_float(
            "BNT_SSH_CONNECT_TIMEOUT_SECONDS", 15.0, minimum=1.0, maximum=60.0
        ),
        ssh_handshake_timeout_seconds=_env_float(
            "BNT_SSH_HANDSHAKE_TIMEOUT_SECONDS",
            60.0,
            minimum=5.0,
            maximum=300.0,
        ),
        telnet_active_session_limit=_env_int(
            "BNT_TELNET_ACTIVE_SESSION_LIMIT", 4, minimum=1, maximum=16
        ),
        telnet_connect_timeout_seconds=_env_float(
            "BNT_TELNET_CONNECT_TIMEOUT_SECONDS",
            15.0,
            minimum=1.0,
            maximum=60.0,
        ),
        telnet_handshake_timeout_seconds=_env_float(
            "BNT_TELNET_HANDSHAKE_TIMEOUT_SECONDS",
            60.0,
            minimum=5.0,
            maximum=300.0,
        ),
        transfer_root_directory=transfer_root,
        transfer_default_bind_address=transfer_bind,
        transfer_tftp_default_port=transfer_tftp_port,
        transfer_sftp_default_port=_env_int(
            "BNT_TRANSFER_SFTP_PORT", 2222, minimum=1, maximum=65535
        ),
        transfer_ftp_default_port=_env_int(
            "BNT_TRANSFER_FTP_PORT", 2121, minimum=1, maximum=65535
        ),
        transfer_max_file_bytes=transfer_max_file_bytes,
        transfer_active_transfer_limit=transfer_active_limit,
        transfer_per_client_transfer_limit=transfer_per_client_limit,
        transfer_allowed_network_host_limit=transfer_allowed_host_limit,
        transfer_sftp_host_key_path=os.getenv(
            "BNT_TRANSFER_SFTP_HOST_KEY",
            str(Path.home() / ".better-network-tools" / "nettransfer-ed25519"),
        ),
        transfer_ftp_passive_port_start=_env_int(
            "BNT_TRANSFER_FTP_PASSIVE_PORT_START",
            50_000,
            minimum=1024,
            maximum=65535,
        ),
        transfer_ftp_passive_port_end=_env_int(
            "BNT_TRANSFER_FTP_PASSIVE_PORT_END",
            50_019,
            minimum=1024,
            maximum=65535,
        ),
        tftp_root_directory=transfer_root,
        tftp_default_bind_address=transfer_bind,
        tftp_default_port=transfer_tftp_port,
        tftp_max_file_bytes=transfer_max_file_bytes,
        tftp_active_transfer_limit=transfer_active_limit,
        tftp_per_client_transfer_limit=transfer_per_client_limit,
        tftp_retry_timeout_seconds=_env_float(
            "BNT_TFTP_RETRY_TIMEOUT_SECONDS", 2.0, minimum=0.2, maximum=10.0
        ),
        tftp_max_retries=_env_int(
            "BNT_TFTP_MAX_RETRIES", 5, minimum=1, maximum=12
        ),
        tftp_transfer_timeout_seconds=_env_float(
            "BNT_TFTP_TRANSFER_TIMEOUT_SECONDS",
            300.0,
            minimum=5.0,
            maximum=3600.0,
        ),
        tftp_max_block_size=_env_int(
            "BNT_TFTP_MAX_BLOCK_SIZE", 1468, minimum=512, maximum=8192
        ),
        tftp_allowed_network_host_limit=transfer_allowed_host_limit,
        update_repository=os.getenv(
            "BNT_UPDATE_REPOSITORY", "erichbrinkman/betternetworktools"
        ),
        update_branch=os.getenv("BNT_UPDATE_BRANCH", "main"),
        update_check_timeout_seconds=_env_float(
            "BNT_UPDATE_CHECK_TIMEOUT_SECONDS",
            10.0,
            minimum=1.0,
            maximum=30.0,
        ),
        update_total_check_timeout_seconds=_env_float(
            "BNT_UPDATE_TOTAL_CHECK_TIMEOUT_SECONDS",
            300.0,
            minimum=30.0,
            maximum=1800.0,
        ),
        update_git_timeout_seconds=_env_float(
            "BNT_UPDATE_GIT_TIMEOUT_SECONDS",
            120.0,
            minimum=10.0,
            maximum=600.0,
        ),
        tcp_timeout_seconds=_env_float(
            "BNT_TCP_TIMEOUT_SECONDS", 0.75, minimum=0.05, maximum=10.0
        ),
        banner_timeout_seconds=_env_float(
            "BNT_BANNER_TIMEOUT_SECONDS", 0.5, minimum=0.05, maximum=5.0
        ),
        job_retention_seconds=_env_int(
            "BNT_JOB_RETENTION_SECONDS", 3600, minimum=60, maximum=86400
        ),
        cors_origins=_env_origins(),
    )
    for direction in ("download", "upload"):
        minimum = getattr(settings, f"speed_{direction}_byte_minimum")
        default = getattr(settings, f"speed_{direction}_byte_default")
        limit = getattr(settings, f"speed_{direction}_byte_limit")
        if not minimum <= default <= limit:
            raise ValueError(
                f"BNT_SPEED_{direction.upper()} sizes must satisfy "
                "minimum <= default <= limit"
            )
    if settings.transfer_ftp_passive_port_start > settings.transfer_ftp_passive_port_end:
        raise ValueError(
            "BNT_TRANSFER_FTP_PASSIVE_PORT_START must not exceed "
            "BNT_TRANSFER_FTP_PASSIVE_PORT_END"
        )
    passive_width = (
        settings.transfer_ftp_passive_port_end
        - settings.transfer_ftp_passive_port_start
        + 1
    )
    if passive_width > 128:
        raise ValueError(
            "the NetTransfer FTP passive range may contain at most 128 ports"
        )
    if passive_width < settings.transfer_active_transfer_limit:
        raise ValueError(
            "the NetTransfer FTP passive range must provide at least one port "
            "per configured active transfer"
        )
    return settings
