"""Shared protocol-runtime events used by NetTransfer adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Literal


TransferProtocolName = Literal["tftp", "sftp", "ftp"]
TransferDirectionName = Literal["download", "upload"]
TransferStatusName = Literal["active", "completed", "failed", "cancelled"]


@dataclass(frozen=True, slots=True)
class RuntimeTransferEvent:
    """A sanitized transfer lifecycle event emitted by a protocol runtime."""

    id: str
    protocol: TransferProtocolName
    direction: TransferDirectionName
    status: TransferStatusName
    filename: str
    client: str
    username: str | None
    bytes_transferred: int
    started_at: datetime
    finished_at: datetime | None = None
    error: str | None = None


RuntimeEventCallback = Callable[[RuntimeTransferEvent], None]
