"""Typed compatibility models for the NetTransfer TFTP adapter."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator


class TftpServerStartRequest(BaseModel):
    """Configuration accepted when starting the singleton TFTP listener."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    bind_address: str = Field(default="127.0.0.1", min_length=1, max_length=45)
    port: int = Field(default=6969, strict=True, ge=1, le=65535)
    allow_read: StrictBool = True
    allow_write: StrictBool = False
    allow_overwrite: StrictBool = False
    allowed_client_cidrs: list[str] = Field(default_factory=list, max_length=8)

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


TftpServerState = Literal["stopped", "running"]
TftpTransferDirection = Literal["download", "upload"]
TftpTransferStatus = Literal["active", "completed", "failed", "cancelled"]


class TftpTransferResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    direction: TftpTransferDirection
    status: TftpTransferStatus
    filename: str
    client: str
    bytes_transferred: int = Field(ge=0)
    started_at: datetime
    finished_at: datetime | None
    error: str | None = Field(default=None, max_length=240)


class TftpServerStatusResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    state: TftpServerState
    running: bool
    bind_address: str
    port: int = Field(ge=1, le=65535)
    root_directory: str
    allow_read: bool
    allow_write: bool
    allow_overwrite: bool
    allowed_client_cidrs: list[str]
    started_at: datetime | None
    active_transfer_count: int = Field(ge=0)
    completed_transfer_count: int = Field(ge=0)
    failed_transfer_count: int = Field(ge=0)
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    recent_transfers: list[TftpTransferResponse]


class TftpFileResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    size: int = Field(ge=0)
    modified_at: datetime


class TftpFileListResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    root_directory: str
    files: list[TftpFileResponse]
    truncated: bool
