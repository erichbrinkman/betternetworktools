"""Strict wire models for the QuickSSH WebSocket protocol.

Secrets are accepted only in the initial in-memory connect message. They are
represented with ``SecretStr`` so an accidental model representation cannot
expose a password.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    field_validator,
)


SSH_INPUT_LIMIT_BYTES = 32 * 1024
SSH_MESSAGE_LIMIT_CHARS = 64 * 1024
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
_USERNAME = re.compile(r"^[^\s\x00-\x1f\x7f]{1,128}$")
_KEY_ALGORITHM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._+-]{0,127}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{16,96}={0,2}$")


class _StrictMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SshAgentAuth(_StrictMessage):
    type: Literal["agent"]


class SshPasswordAuth(_StrictMessage):
    type: Literal["password"]
    password: SecretStr = Field(min_length=1, max_length=4096)


SshAuth = Annotated[SshAgentAuth | SshPasswordAuth, Field(discriminator="type")]


def _validate_host(value: str) -> str:
    host = value.rstrip(".")
    if not host or len(host) > 253 or host.startswith("-"):
        raise ValueError("host is invalid")
    if any(character in host for character in "/\\?#@[]") or "://" in host:
        raise ValueError("host must be a hostname or IP address")

    # IPv6 literals may include an interface scope (for example, fe80::1%en0).
    address_part, separator, scope = host.partition("%")
    if ":" in address_part:
        try:
            parsed = ipaddress.ip_address(address_part)
        except ValueError as exc:
            raise ValueError("host contains an invalid IPv6 address") from exc
        if parsed.version != 6 or (separator and not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", scope)):
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


def _validate_public_key(value: str) -> str:
    fields = value.split()
    if len(fields) != 2 or not _KEY_ALGORITHM.fullmatch(fields[0]):
        raise ValueError("known_host_key must be an OpenSSH public key without a comment")
    try:
        decoded = base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("known_host_key contains invalid base64") from exc
    if not decoded or len(decoded) > 12 * 1024:
        raise ValueError("known_host_key is invalid")
    return f"{fields[0]} {fields[1]}"


class SshConnectMessage(_StrictMessage):
    type: Literal["connect"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    auth: SshAuth = Field(default_factory=lambda: SshAgentAuth(type="agent"))
    known_host_key: str | None = Field(default=None, max_length=16 * 1024)
    cols: int = Field(default=80, ge=2, le=512)
    rows: int = Field(default=24, ge=1, le=256)

    @field_validator("host")
    @classmethod
    def host_must_be_safe(cls, value: str) -> str:
        return _validate_host(value)

    @field_validator("username")
    @classmethod
    def username_must_be_safe(cls, value: str) -> str:
        if not _USERNAME.fullmatch(value):
            raise ValueError("username contains unsupported characters")
        return value

    @field_validator("known_host_key")
    @classmethod
    def known_host_key_must_be_canonical(cls, value: str | None) -> str | None:
        return _validate_public_key(value) if value is not None else None


class SshTrustHostKeyMessage(_StrictMessage):
    type: Literal["trust_host_key"]
    fingerprint: str = Field(min_length=24, max_length=128)

    @field_validator("fingerprint")
    @classmethod
    def fingerprint_must_be_sha256(cls, value: str) -> str:
        if not _FINGERPRINT.fullmatch(value):
            raise ValueError("fingerprint must be an SSH SHA256 fingerprint")
        return value


class SshInputMessage(_StrictMessage):
    type: Literal["input"]
    data: str = Field(min_length=4, max_length=44 * 1024)

    def decode(self) -> bytes:
        try:
            decoded = base64.b64decode(self.data, validate=True)
        except (binascii.Error, ValueError) as exc:  # validated below as well
            raise ValueError("input data is not valid base64") from exc
        if not decoded or len(decoded) > SSH_INPUT_LIMIT_BYTES:
            raise ValueError("input data exceeds the allowed size")
        return decoded

    @field_validator("data")
    @classmethod
    def data_must_be_bounded_base64(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("input data is not valid base64") from exc
        if not decoded or len(decoded) > SSH_INPUT_LIMIT_BYTES:
            raise ValueError("input data exceeds the allowed size")
        return value


class SshResizeMessage(_StrictMessage):
    type: Literal["resize"]
    cols: int = Field(ge=2, le=512)
    rows: int = Field(ge=1, le=256)
    pixel_width: int = Field(default=0, ge=0, le=32768)
    pixel_height: int = Field(default=0, ge=0, le=32768)


class SshDisconnectMessage(_StrictMessage):
    type: Literal["disconnect"]


SshTrustPhaseMessage = Annotated[
    SshTrustHostKeyMessage | SshDisconnectMessage, Field(discriminator="type")
]
SshConnectedMessage = Annotated[
    SshInputMessage | SshResizeMessage | SshDisconnectMessage,
    Field(discriminator="type"),
]

CONNECT_ADAPTER = TypeAdapter(SshConnectMessage)
TRUST_PHASE_ADAPTER = TypeAdapter(SshTrustPhaseMessage)
CONNECTED_ADAPTER = TypeAdapter(SshConnectedMessage)
