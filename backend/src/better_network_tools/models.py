"""Public API and scanner data models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


StrictPort = Annotated[int, Field(strict=True, ge=1, le=65535)]
StrictTarget = Annotated[str, Field(strict=True, min_length=1, max_length=253)]


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_SCAN_STATUSES = {
    ScanStatus.COMPLETED,
    ScanStatus.CANCELLED,
    ScanStatus.FAILED,
}


class ScanRequest(BaseModel):
    """Parameters accepted when creating a NetScanner job."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    subnet: str = Field(min_length=1, max_length=64)
    ports: list[StrictPort] | None = None
    timeout: float | None = Field(default=None, ge=0.05, le=10.0)
    concurrency: int | None = Field(default=None, strict=True, ge=1, le=512)
    resolve_dns: bool = True
    collect_banners: bool = True

    @field_validator("ports")
    @classmethod
    def ports_must_not_be_empty(cls, value: list[int] | None) -> list[int] | None:
        if value == []:
            raise ValueError("ports must contain at least one port when provided")
        return value


class ScanOptions(BaseModel):
    model_config = ConfigDict(frozen=True)

    ports: list[int]
    timeout: float
    concurrency: int
    resolve_dns: bool
    collect_banners: bool


class OpenPort(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int
    service: str | None = None
    banner: str | None = None
    http_status: int | None = None
    http_server: str | None = None


DiscoveryMethod = Literal["icmp", "tcp", "arp", "reverse_dns"]
ConfidenceLevel = Literal["low", "medium", "high"]


class DeviceResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    icmp_reachable: bool
    reachable: bool
    open_ports: list[OpenPort]
    discovery_methods: list[DiscoveryMethod]
    confidence_score: int = Field(ge=0, le=100)
    confidence: ConfidenceLevel


class ScanProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_hosts: int
    scanned_hosts: int
    discovered_hosts: int
    percent: float = Field(ge=0, le=100)


class ScanJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: ScanStatus
    subnet: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress: ScanProgress
    options: ScanOptions
    results: list[DeviceResult]
    error: str | None
    cancel_requested: bool


class ScanSummaryResponse(BaseModel):
    """Lightweight scan metadata for recent-job listings."""

    model_config = ConfigDict(frozen=True)

    id: str
    status: ScanStatus
    subnet: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    progress: ScanProgress
    error: str | None
    cancel_requested: bool


class ScanResultsResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    count: int
    results: list[DeviceResult]


class PingJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_PING_JOB_STATUSES = {
    PingJobStatus.COMPLETED,
    PingJobStatus.CANCELLED,
    PingJobStatus.FAILED,
}


class PingJobRequest(BaseModel):
    """Parameters accepted when starting a multi-target NetPinger job."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    # A larger raw cap permits duplicate entries to collapse before the configured
    # 32-unique-target safety limit is applied by the service.
    targets: list[StrictTarget] = Field(min_length=1, max_length=256)
    count: int = Field(default=10, strict=True, ge=1, le=100)
    interval: float = Field(default=1.0, ge=0.2, le=60.0)
    timeout: float = Field(default=1.0, ge=0.1, le=10.0)
    continuous: bool = False


class PingJobOptions(BaseModel):
    model_config = ConfigDict(frozen=True)

    count: int
    interval: float
    timeout: float
    continuous: bool


class PingJobProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Continuous jobs have no meaningful total or completion percentage. Their
    # completed probe counter still provides a monotonically increasing measure
    # of live progress until the job is cancelled.
    total_probes: int | None = Field(default=None, ge=0)
    completed_probes: int = Field(ge=0)
    percent: float | None = Field(default=None, ge=0, le=100)


PingAddressFamily = Literal["IPv4", "IPv6"]
PingTargetStatus = Literal["pending", "up", "down", "error"]
PingReverseDnsStatus = Literal[
    "not_requested", "pending", "resolved", "not_found", "unavailable"
]


class PingTargetResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    resolved_address: str | None
    address_family: PingAddressFamily | None
    reverse_hostname: str | None = Field(min_length=1, max_length=253)
    reverse_dns_status: PingReverseDnsStatus
    status: PingTargetStatus
    sent: int
    received: int
    failed: int
    consecutive_successes: int = Field(ge=0)
    max_consecutive_successes: int = Field(ge=0)
    consecutive_failures: int = Field(ge=0)
    max_consecutive_failures: int = Field(ge=0)
    reply_time_history_ms: list[float | None] = Field(max_length=60)
    # Replies whose native command output contained a parseable RTT. This can
    # be lower than `received`, so clients can correctly weight `avg_ms`.
    latency_samples: int = Field(ge=0)
    success_rate: float = Field(ge=0, le=100)
    loss_percent: float = Field(ge=0, le=100)
    last_ms: float | None
    avg_ms: float | None
    min_ms: float | None
    max_ms: float | None
    last_checked: datetime | None
    error: str | None


class PingJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: PingJobStatus
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    options: PingJobOptions
    progress: PingJobProgress
    targets: list[PingTargetResponse]
    error: str | None
    cancel_requested: bool


class TraceJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_TRACE_JOB_STATUSES = {
    TraceJobStatus.COMPLETED,
    TraceJobStatus.CANCELLED,
    TraceJobStatus.FAILED,
}


TracePhase = Literal["resolving", "tracing", "enriching", "complete"]
TraceAddressFamily = Literal["IPv4", "IPv6"]
TraceProbeStatus = Literal["reply", "timeout", "unreachable"]
TraceAddressScope = Literal[
    "public", "private", "loopback", "link_local", "reserved"
]
TraceBoundaryConfidence = Literal["exact", "gap", "ecmp"]


class TraceJobRequest(BaseModel):
    """Parameters accepted when starting a NetTrace job."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: StrictTarget
    max_hops: int = Field(default=30, strict=True, ge=1, le=64)
    timeout: float = Field(default=1.0, ge=0.2, le=5.0)
    resolve_dns: bool = True
    # Remote IP-to-ASN lookup is deliberately opt-in because it discloses the
    # public hop addresses to the configured lookup provider.
    lookup_asn: StrictBool = False


class TraceJobOptions(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_hops: int
    timeout: float
    probes_per_hop: int = Field(default=3, ge=1, le=3)
    resolve_dns: bool
    lookup_asn: bool


class TraceProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    last_hop: int = Field(ge=0)
    max_hops: int = Field(ge=1, le=64)


class TraceWarning(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=240)


class TraceAsnRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1, le=4_294_967_295)
    name: str = Field(min_length=1, max_length=200)
    organization: str | None = Field(default=None, min_length=1, max_length=200)
    prefix: str = Field(min_length=1, max_length=64)
    country_code: str | None = Field(default=None, min_length=2, max_length=2)
    registry: str | None = Field(default=None, min_length=1, max_length=24)
    source: Literal["team_cymru_whois"]


class TraceProbeResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=1, le=3)
    address: str | None = Field(default=None, max_length=45)
    latency_ms: float | None = Field(default=None, ge=0)
    status: TraceProbeStatus
    annotation: str | None = Field(default=None, max_length=32)


class TraceResponderResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: str = Field(min_length=1, max_length=45)
    hostname: str | None = Field(default=None, min_length=1, max_length=253)
    scope: TraceAddressScope
    asn: TraceAsnRecord | None = None


class TraceHopResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1, le=64)
    probes: list[TraceProbeResponse] = Field(min_length=1, max_length=3)
    responders: list[TraceResponderResponse] = Field(max_length=3)
    reached_destination: bool


class TraceAsPathSegment(BaseModel):
    model_config = ConfigDict(frozen=True)

    asn: int | None = Field(default=None, ge=1, le=4_294_967_295)
    network_name: str = Field(min_length=1, max_length=200)
    first_hop: int = Field(ge=1, le=64)
    last_hop: int = Field(ge=1, le=64)
    prefixes: list[str] = Field(max_length=16)
    ambiguous: bool
    boundary_confidence: TraceBoundaryConfidence


class TraceJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: TraceJobStatus
    phase: TracePhase
    target: str
    resolved_address: str | None
    address_family: TraceAddressFamily | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    options: TraceJobOptions
    progress: TraceProgress
    hops: list[TraceHopResponse] = Field(max_length=64)
    as_path: list[TraceAsPathSegment] = Field(max_length=192)
    reached_destination: bool
    error: str | None
    warnings: list[TraceWarning] = Field(max_length=32)
    cancel_requested: bool


class SpeedJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_SPEED_JOB_STATUSES = {
    SpeedJobStatus.COMPLETED,
    SpeedJobStatus.CANCELLED,
    SpeedJobStatus.FAILED,
}


SpeedServerProvider = Literal["cloudflare", "librespeed"]
SpeedDirectoryStatus = Literal["fresh", "stale", "unavailable"]
SpeedPhase = Literal["queued", "ping", "download", "upload", "complete"]


class SpeedServerResponse(BaseModel):
    """Public identity for an allowlisted speed-test server.

    Measurement endpoint URLs intentionally remain internal to the service. A
    caller can select only this opaque catalog identifier.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=120)
    provider: SpeedServerProvider
    location: str | None = Field(default=None, min_length=1, max_length=120)
    country: str | None = Field(default=None, min_length=1, max_length=80)
    sponsor: str | None = Field(default=None, min_length=1, max_length=120)
    latency_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    automatic: bool


class SpeedServerListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    servers: list[SpeedServerResponse] = Field(min_length=1, max_length=257)
    refreshed_at: datetime
    directory_status: SpeedDirectoryStatus


class SpeedJobRequest(BaseModel):
    """Select an opaque catalog server and optional aggregate transfer sizes."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    server_id: str = Field(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._:-]+$",
    )
    # Runtime-configured minima and maxima are enforced by the service so API
    # errors can report the active limits. Strict integers reject booleans,
    # floats, and numeric strings instead of silently coercing them.
    download_bytes: int | None = Field(default=None, strict=True)
    upload_bytes: int | None = Field(default=None, strict=True)


class SpeedJobOptions(BaseModel):
    model_config = ConfigDict(frozen=True)

    download_bytes: int = Field(ge=1)
    upload_bytes: int = Field(ge=1)


class SpeedThroughputSample(BaseModel):
    """One bounded transfer-rate sample on the job's elapsed timeline."""

    model_config = ConfigDict(frozen=True)

    phase: Literal["download", "upload"]
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    mbps: float = Field(ge=0, allow_inf_nan=False)


class SpeedJobProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    percent: float = Field(ge=0, le=100)
    download_bytes: int = Field(ge=0)
    upload_bytes: int = Field(ge=0)
    current_mbps: float | None = Field(ge=0, allow_inf_nan=False)
    samples: list[SpeedThroughputSample] = Field(max_length=160)


class SpeedTestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    server: SpeedServerResponse
    ping_ms: float = Field(ge=0)
    jitter_ms: float = Field(ge=0)
    download_mbps: float = Field(ge=0)
    upload_mbps: float = Field(ge=0)
    download_bytes: int = Field(ge=0)
    upload_bytes: int = Field(ge=0)
    transferred_bytes: int = Field(ge=0)
    duration_seconds: float = Field(ge=0)


class SpeedJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: SpeedJobStatus
    phase: SpeedPhase
    server: SpeedServerResponse
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    options: SpeedJobOptions
    progress: SpeedJobProgress
    result: SpeedTestResult | None
    error: str | None = Field(default=None, max_length=240)
    cancel_requested: bool


class PortJobStatus(str, Enum):
    QUEUED = "queued"
    RESOLVING = "resolving"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_PORT_JOB_STATUSES = {
    PortJobStatus.COMPLETED,
    PortJobStatus.CANCELLED,
    PortJobStatus.FAILED,
}


class PortJobRequest(BaseModel):
    """Parameters accepted when starting a single-target NetPorts TCP scan."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    target: StrictTarget
    ports: Annotated[str, Field(strict=True, min_length=1, max_length=4096)] = (
        "21-23,25,53,80,110,135,139,143,389,443,445,636,993,995,1433,"
        "1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017"
    )
    timeout: float = Field(default=0.75, strict=True, ge=0.05, le=10.0)
    concurrency: int = Field(default=128, strict=True, ge=1, le=512)
    collect_banners: StrictBool = False


class PortJobOptions(BaseModel):
    model_config = ConfigDict(frozen=True)

    port_spec: str
    total_ports: int = Field(ge=1, le=65535)
    timeout: float = Field(ge=0.05, le=10.0)
    concurrency: int = Field(ge=1, le=512)
    collect_banners: bool


class PortJobProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_ports: int = Field(ge=1, le=65535)
    scanned_ports: int = Field(ge=0, le=65535)
    open_ports: int = Field(ge=0, le=65535)
    closed_ports: int = Field(ge=0, le=65535)
    timed_out_ports: int = Field(ge=0, le=65535)
    error_ports: int = Field(ge=0, le=65535)
    percent: float = Field(ge=0, le=100)


class PortResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int = Field(ge=1, le=65535)
    service: str | None = Field(default=None, max_length=64)
    banner: str | None = Field(default=None, max_length=240)
    http_status: int | None = Field(default=None, ge=100, le=599)
    http_server: str | None = Field(default=None, max_length=240)
    latency_ms: float = Field(ge=0, allow_inf_nan=False)


class PortJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: PortJobStatus
    target: str
    resolved_address: str | None
    address_family: Literal["IPv4", "IPv6"] | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    options: PortJobOptions
    progress: PortJobProgress
    results: list[PortResult]
    results_truncated: bool
    error: str | None = Field(default=None, max_length=240)
    cancel_requested: bool


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: str
    version: str


class SystemCapabilities(BaseModel):
    icmp: bool = True
    reverse_dns: bool = True
    tcp_connect: bool = True
    banners: bool = True
    arp_cache: bool = True
    multi_target_ping: bool = True
    ssh_client: bool = True
    telnet_client: bool = True
    traceroute: bool = True
    asn_lookup: bool = True
    speed_test: bool = True
    internet_speed_test: bool = True
    public_speed_servers: bool = True
    port_scan: bool = True
    transfer_server: bool = True
    tftp_server: bool = True
    sftp_server: bool = True
    ftp_server: bool = True


class SystemLimits(BaseModel):
    max_hosts: int
    max_ports: int
    max_concurrency: int
    max_ssh_sessions: int
    max_telnet_sessions: int
    max_trace_hops: int
    max_trace_jobs: int
    max_speed_jobs: int
    max_speed_test_seconds: float
    min_speed_download_bytes: int
    default_speed_download_bytes: int
    max_speed_download_bytes: int
    min_speed_upload_bytes: int
    default_speed_upload_bytes: int
    max_speed_upload_bytes: int
    max_port_scan_ports: int
    max_port_scan_concurrency: int
    max_port_scan_jobs: int
    max_port_scan_connect_seconds: float
    max_port_scan_seconds: float
    max_port_scan_results: int
    max_retained_port_scan_jobs: int


class SystemResponse(BaseModel):
    name: str
    version: str
    platform: str
    platform_release: str
    python_version: str
    capabilities: SystemCapabilities
    limits: SystemLimits
