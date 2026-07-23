"""Strict wire models for the QuickSSH Telnet WebSocket protocol.

Telnet credentials are deliberately absent from the connect model. Login and
password prompts are handled as ordinary interactive terminal bytes and are
never collected or retained by the local API.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator


TELNET_INPUT_LIMIT_BYTES = 32 * 1024
TELNET_MESSAGE_LIMIT_CHARS = 64 * 1024
_HOSTNAME_LABEL = re.compile(
    r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$"
)


class _StrictMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _validate_host(value: str) -> str:
    host = value.rstrip(".")
    if not host or len(host) > 253 or host.startswith("-"):
        raise ValueError("host is invalid")
    if any(character in host for character in "/\\?#@[]") or "://" in host:
        raise ValueError("host must be a hostname or IP address")

    address_part, separator, scope = host.partition("%")
    if ":" in address_part:
        try:
            parsed = ipaddress.ip_address(address_part)
        except ValueError as exc:
            raise ValueError("host contains an invalid IPv6 address") from exc
        if parsed.version != 6 or (
            separator and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", scope)
        ):
            raise ValueError("host contains an invalid IPv6 scope")
        return host

    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", host):
            raise ValueError("host contains an invalid IPv4 address")
        labels = host.split(".")
        if any(not _HOSTNAME_LABEL.fullmatch(label) for label in labels):
            raise ValueError("host contains an invalid hostname")
    else:
        if parsed.version != 4:
            raise ValueError("host is invalid")
    return host


class TelnetConnectMessage(_StrictMessage):
    type: Literal["connect"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=23, ge=1, le=65535)
    cols: int = Field(default=80, ge=2, le=512)
    rows: int = Field(default=24, ge=1, le=256)

    @field_validator("host")
    @classmethod
    def host_must_be_safe(cls, value: str) -> str:
        return _validate_host(value)


class TelnetInputMessage(_StrictMessage):
    type: Literal["input"]
    data: str = Field(min_length=4, max_length=44 * 1024)

    def decode(self) -> bytes:
        return base64.b64decode(self.data, validate=True)

    @field_validator("data")
    @classmethod
    def data_must_be_bounded_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("input data is not valid base64") from exc
        if not decoded or len(decoded) > TELNET_INPUT_LIMIT_BYTES:
            raise ValueError("input data exceeds the allowed size")
        return value


class TelnetResizeMessage(_StrictMessage):
    type: Literal["resize"]
    cols: int = Field(ge=2, le=512)
    rows: int = Field(ge=1, le=256)
    pixel_width: int = Field(default=0, ge=0, le=32768)
    pixel_height: int = Field(default=0, ge=0, le=32768)


class TelnetDisconnectMessage(_StrictMessage):
    type: Literal["disconnect"]


TelnetConnectedMessage = Annotated[
    TelnetInputMessage | TelnetResizeMessage | TelnetDisconnectMessage,
    Field(discriminator="type"),
]

CONNECT_ADAPTER = TypeAdapter(TelnetConnectMessage)
CONNECTED_ADAPTER = TypeAdapter(TelnetConnectedMessage)
