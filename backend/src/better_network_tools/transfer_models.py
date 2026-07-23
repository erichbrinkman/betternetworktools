"""Typed API models for the local NetTransfer server."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    StrictBool,
    field_validator,
    model_validator,
)


TransferProtocol = Literal["tftp", "sftp", "ftp"]
TransferTransport = Literal["udp", "tcp"]
TransferServerState = Literal["stopped", "starting", "running", "stopping"]
TransferDirection = Literal["download", "upload"]
TransferStatus = Literal["active", "completed", "failed", "cancelled"]
TransferAuthentication = Literal["none", "password"]


class TransferServerStartRequest(BaseModel):
    """Configuration accepted when starting the singleton transfer listener."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    protocol: TransferProtocol = "tftp"
    bind_address: str = Field(default="127.0.0.1", min_length=1, max_length=45)
    port: int | None = Field(default=None, strict=True, ge=1, le=65535)
    allow_read: StrictBool = True
    allow_write: StrictBool = False
    allow_overwrite: StrictBool = False
    allowed_client_cidrs: list[str] = Field(default_factory=list, max_length=8)
    username: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    password: SecretStr | None = Field(default=None, min_length=12, max_length=128)
    acknowledge_plaintext_ftp: StrictBool = False

    @field_validator("allowed_client_cidrs")
    @classmethod
    def cidrs_must_be_unique_and_nonempty(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for cidr in value:
            candidate = cidr.strip()
            if not candidate:
                raise ValueError("allowed client CIDRs must not be empty")
            key = candidate.casefold()
            if key not in seen:
                seen.add(key)
                normalized.append(candidate)
        return normalized

    @model_validator(mode="after")
    def validate_protocol_fields(self) -> "TransferServerStartRequest":
        if not self.allow_read and not self.allow_write:
            raise ValueError("enable downloads, uploads, or both")
        if self.allow_overwrite and not self.allow_write:
            raise ValueError("overwrite requires uploads to be enabled")
        if self.protocol == "tftp":
            if self.username is not None or self.password is not None:
                raise ValueError("TFTP does not accept credentials")
        elif self.username is None or self.password is None:
            raise ValueError(f"{self.protocol.upper()} requires a username and password")
        return self


class TransferResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    protocol: TransferProtocol
    direction: TransferDirection
    status: TransferStatus
    filename: str
    client: str
    username: str | None
    bytes_transferred: int = Field(ge=0)
    started_at: datetime
    finished_at: datetime | None
    error: str | None = Field(default=None, max_length=240)


class TransferServerStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    state: TransferServerState
    running: bool
    protocol: TransferProtocol | None
    transport: TransferTransport | None
    bind_address: str
    port: int | None = Field(default=None, ge=1, le=65535)
    root_directory: str
    allow_read: bool
    allow_write: bool
    allow_overwrite: bool
    allowed_client_cidrs: list[str]
    authentication: TransferAuthentication
    username: str | None
    sftp_host_key_fingerprint: str | None
    ftp_passive_port_start: int | None = Field(default=None, ge=1, le=65535)
    ftp_passive_port_end: int | None = Field(default=None, ge=1, le=65535)
    default_ports: dict[TransferProtocol, int]
    started_at: datetime | None
    active_transfer_count: int = Field(ge=0)
    completed_transfer_count: int = Field(ge=0)
    failed_transfer_count: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    recent_transfers: list[TransferResponse]


class TransferFileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    size: int = Field(ge=0)
    modified_at: datetime


class TransferFileListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_directory: str
    files: list[TransferFileResponse]
    truncated: bool
