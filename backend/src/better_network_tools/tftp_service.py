"""Bounded, root-confined TFTP adapter used by the NetTransfer local app.

The implementation intentionally supports the interoperable binary subset used by
network appliances: RFC 1350 RRQ/WRQ in ``octet`` mode plus the RFC 2347-2349
``blksize``, ``timeout``, and ``tsize`` options.  Every transfer uses a fresh UDP
transfer identifier, is locked to its originating client, and is owned by the
service lifecycle so shutdown cannot leave a listener behind.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import struct
import time
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from .config import Settings
from .tftp_models import (
    TftpFileListResponse,
    TftpFileResponse,
    TftpServerStartRequest,
    TftpServerStatusResponse,
    TftpTransferResponse,
)


OP_RRQ = 1
OP_WRQ = 2
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
OP_OACK = 6

ERR_UNDEFINED = 0
ERR_FILE_NOT_FOUND = 1
ERR_ACCESS_VIOLATION = 2
ERR_DISK_FULL = 3
ERR_ILLEGAL_OPERATION = 4
ERR_UNKNOWN_TID = 5
ERR_FILE_EXISTS = 6
ERR_OPTION_NEGOTIATION = 8

DEFAULT_BLOCK_SIZE = 512
MAX_REQUEST_BYTES = 512
MAX_DATAGRAM_BYTES = 65_535
MAX_FILENAME_BYTES = 255
RECENT_TRANSFER_LIMIT = 100
FILE_LIST_LIMIT = 500
UPLOAD_PREFIX = ".nettransfer-upload-"
LEGACY_UPLOAD_PREFIX = ".nettftp-upload-"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class TftpServiceError(RuntimeError):
    code = "tftp_service_error"

    def as_detail(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


class TftpConfigurationError(TftpServiceError):
    code = "invalid_tftp_configuration"


class TftpServerAlreadyRunningError(TftpServiceError):
    code = "tftp_server_already_running"


class TftpServerBindError(TftpServiceError):
    code = "tftp_server_bind_failed"


class TftpPacketError(ValueError):
    """Raised when an initial request packet is malformed."""


class _TransferRejected(Exception):
    def __init__(self, error_code: int, message: str, *, send_error: bool = True):
        super().__init__(message)
        self.error_code = error_code
        self.message = message
        self.send_error = send_error


@dataclass(frozen=True, slots=True)
class TftpRequest:
    opcode: int
    filename: str
    mode: str
    options: dict[str, str]


@dataclass(frozen=True, slots=True)
class _RuntimeConfig:
    bind_address: str
    port: int
    allow_read: bool
    allow_write: bool
    allow_overwrite: bool
    allowed_networks: tuple[ipaddress.IPv4Network, ...]


@dataclass(slots=True)
class _TransferRecord:
    id: str
    direction: str
    status: str
    filename: str
    client: str
    bytes_transferred: int
    started_at: datetime
    finished_at: datetime | None = None
    error: str | None = None


@dataclass(slots=True)
class _SessionHandle:
    sock: socket.socket
    initial_response: bytes | None = None


@dataclass(frozen=True, slots=True)
class _NegotiatedOptions:
    block_size: int
    retry_timeout: float
    accepted: dict[str, str]
    advertised_size: int | None


def parse_tftp_request(data: bytes) -> TftpRequest:
    """Parse and strictly bound an RFC 1350 RRQ or WRQ packet."""

    if len(data) > MAX_REQUEST_BYTES:
        raise TftpPacketError("request packet exceeds 512 bytes")
    if len(data) < 4:
        raise TftpPacketError("request packet is truncated")

    (opcode,) = struct.unpack("!H", data[:2])
    if opcode not in {OP_RRQ, OP_WRQ}:
        raise TftpPacketError("only read and write requests are accepted here")

    parts = data[2:].split(b"\0")
    if not parts or parts[-1] != b"":
        raise TftpPacketError("request fields must be NUL terminated")
    fields = parts[:-1]
    if len(fields) < 2 or (len(fields) - 2) % 2:
        raise TftpPacketError("request contains incomplete option fields")
    if not fields[0] or not fields[1]:
        raise TftpPacketError("filename and transfer mode are required")
    if len(fields[0]) > MAX_FILENAME_BYTES:
        raise TftpPacketError("filename exceeds 255 bytes")

    try:
        filename = fields[0].decode("utf-8", "strict")
        mode = fields[1].decode("ascii", "strict").casefold()
    except UnicodeDecodeError as exc:
        raise TftpPacketError("request text is not valid UTF-8/ASCII") from exc

    options: dict[str, str] = {}
    for index in range(2, len(fields), 2):
        try:
            name = fields[index].decode("ascii", "strict").casefold()
            value = fields[index + 1].decode("ascii", "strict")
        except UnicodeDecodeError as exc:
            raise TftpPacketError("option fields must be ASCII") from exc
        if not name or not value:
            raise TftpPacketError("option names and values must not be empty")
        if name in options:
            raise TftpPacketError(f"duplicate option: {name}")
        options[name] = value

    return TftpRequest(opcode=opcode, filename=filename, mode=mode, options=options)


def _error_packet(code: int, message: str) -> bytes:
    safe = message.replace("\0", " ").encode("utf-8", "replace")[:240]
    return struct.pack("!HH", OP_ERROR, code) + safe + b"\0"


def _ack_packet(block: int) -> bytes:
    return struct.pack("!HH", OP_ACK, block & 0xFFFF)


def _data_packet(block: int, payload: bytes) -> bytes:
    return struct.pack("!HH", OP_DATA, block & 0xFFFF) + payload


def _oack_packet(options: dict[str, str]) -> bytes:
    payload = bytearray(struct.pack("!H", OP_OACK))
    for name, value in options.items():
        payload.extend(name.encode("ascii"))
        payload.append(0)
        payload.extend(value.encode("ascii"))
        payload.append(0)
    return bytes(payload)


def _packet_opcode(data: bytes) -> int | None:
    if len(data) < 2:
        return None
    return struct.unpack("!H", data[:2])[0]


def _client_error_message(data: bytes) -> str:
    if len(data) < 5:
        return "Client ended the transfer"
    raw = data[4:].split(b"\0", 1)[0]
    message = raw.decode("utf-8", "replace").strip()
    return message[:200] or "Client ended the transfer"


def _display_filename(value: str) -> str:
    return "".join(
        character if ord(character) >= 32 and ord(character) != 127 else "�"
        for character in value
    )[:MAX_FILENAME_BYTES]


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _validate_filename(filename: str) -> tuple[str, ...]:
    if not filename or len(filename.encode("utf-8")) > MAX_FILENAME_BYTES:
        raise _TransferRejected(ERR_ACCESS_VIOLATION, "Invalid filename")
    if any(ord(character) < 32 or ord(character) == 127 for character in filename):
        raise _TransferRejected(ERR_ACCESS_VIOLATION, "Invalid filename")
    if "\\" in filename or ":" in filename:
        raise _TransferRejected(ERR_ACCESS_VIOLATION, "Invalid filename")

    path = PurePosixPath(filename)
    if path.is_absolute() or filename.startswith("//"):
        raise _TransferRejected(ERR_ACCESS_VIOLATION, "Absolute paths are not allowed")
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _TransferRejected(ERR_ACCESS_VIOLATION, "Path traversal is not allowed")
    for part in parts:
        if part.rstrip(" .") != part:
            raise _TransferRejected(ERR_ACCESS_VIOLATION, "Invalid filename")
        stem = part.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise _TransferRejected(ERR_ACCESS_VIOLATION, "Invalid filename")
    return parts


class TftpServerService:
    """Own the singleton listener, active transfers, and bounded event history."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lifecycle_lock = asyncio.Lock()
        self._listener_socket: socket.socket | None = None
        self._listener_task: asyncio.Task[None] | None = None
        self._transfer_tasks: set[asyncio.Task[None]] = set()
        self._sessions: dict[
            tuple[str, int, int, str], _SessionHandle | None
        ] = {}
        self._active_records: dict[str, _TransferRecord] = {}
        self._recent_records: deque[_TransferRecord] = deque(
            maxlen=RECENT_TRANSFER_LIMIT
        )
        self._config: _RuntimeConfig | None = None
        self._root: Path | None = None
        self._started_at: datetime | None = None
        self._completed_transfer_count = 0
        self._failed_transfer_count = 0
        self._bytes_sent = 0
        self._bytes_received = 0

    async def start(
        self, request: TftpServerStartRequest
    ) -> TftpServerStatusResponse:
        async with self._lifecycle_lock:
            if self._listener_socket is not None:
                raise TftpServerAlreadyRunningError(
                    "The NetTransfer TFTP server is already running."
                )
            if not _is_loopback_host(self.settings.host):
                raise TftpConfigurationError(
                    "NetTransfer can only be managed by a loopback-bound local API."
                )

            config = self._validate_configuration(request)
            root = self._prepare_root()
            listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listener.setblocking(False)
            try:
                listener.bind((config.bind_address, config.port))
            except PermissionError as exc:
                listener.close()
                raise TftpServerBindError(
                    f"Permission was denied while binding UDP port {config.port}. "
                    "Choose an unprivileged port such as 6969 or adjust the "
                    "operating-system service permissions."
                ) from exc
            except OSError as exc:
                listener.close()
                raise TftpServerBindError(
                    f"Could not bind {config.bind_address}:{config.port}: {exc.strerror or exc}"
                ) from exc

            self._listener_socket = listener
            self._config = config
            self._root = root
            self._started_at = _utc_now()
            self._completed_transfer_count = 0
            self._failed_transfer_count = 0
            self._bytes_sent = 0
            self._bytes_received = 0
            self._recent_records.clear()
            self._listener_task = asyncio.create_task(
                self._serve_requests(listener), name="nettransfer-tftp-listener"
            )

        return await self.status()

    async def stop(self) -> TftpServerStatusResponse:
        async with self._lifecycle_lock:
            listener = self._listener_socket
            listener_task = self._listener_task
            transfer_tasks = list(self._transfer_tasks)
            self._listener_socket = None
            self._listener_task = None
            self._started_at = None

            if listener_task is not None:
                listener_task.cancel()
            if listener is not None:
                listener.close()
            for task in transfer_tasks:
                task.cancel()

        if listener_task is not None:
            await asyncio.gather(listener_task, return_exceptions=True)
        if transfer_tasks:
            await asyncio.gather(*transfer_tasks, return_exceptions=True)
        self._sessions.clear()
        return await self.status()

    async def shutdown(self) -> None:
        await self.stop()

    async def status(self) -> TftpServerStatusResponse:
        config = self._config or self._default_runtime_config()
        root = self._root or self._configured_root()
        running = self._listener_socket is not None
        active = sorted(
            self._active_records.values(), key=lambda record: record.started_at
        )
        recent = list(reversed(self._recent_records))
        transfers = [self._record_response(record) for record in active + recent]
        return TftpServerStatusResponse(
            state="running" if running else "stopped",
            running=running,
            bind_address=config.bind_address,
            port=config.port,
            root_directory=str(root),
            allow_read=config.allow_read,
            allow_write=config.allow_write,
            allow_overwrite=config.allow_overwrite,
            allowed_client_cidrs=[str(network) for network in config.allowed_networks],
            started_at=self._started_at,
            active_transfer_count=len(active),
            completed_transfer_count=self._completed_transfer_count,
            failed_transfer_count=self._failed_transfer_count,
            bytes_sent=self._bytes_sent,
            bytes_received=self._bytes_received,
            recent_transfers=transfers[:RECENT_TRANSFER_LIMIT],
        )

    async def list_files(self) -> TftpFileListResponse:
        root = self._root or self._configured_root()
        files, truncated = await asyncio.to_thread(self._scan_files, root)
        return TftpFileListResponse(
            root_directory=str(root), files=files, truncated=truncated
        )

    def _default_runtime_config(self) -> _RuntimeConfig:
        bind = self.settings.tftp_default_bind_address
        networks: tuple[ipaddress.IPv4Network, ...] = ()
        try:
            address = ipaddress.IPv4Address(bind)
            if address.is_loopback:
                networks = (ipaddress.IPv4Network("127.0.0.0/8"),)
        except ipaddress.AddressValueError:
            pass
        return _RuntimeConfig(
            bind_address=bind,
            port=self.settings.tftp_default_port,
            allow_read=True,
            allow_write=False,
            allow_overwrite=False,
            allowed_networks=networks,
        )

    def _validate_configuration(
        self, request: TftpServerStartRequest
    ) -> _RuntimeConfig:
        bind_value = (
            request.bind_address
            if "bind_address" in request.model_fields_set
            else self.settings.tftp_default_bind_address
        )
        port_value = (
            request.port
            if "port" in request.model_fields_set
            else self.settings.tftp_default_port
        )
        try:
            bind_address = ipaddress.IPv4Address(bind_value)
        except ipaddress.AddressValueError as exc:
            raise TftpConfigurationError(
                "Bind address must be a numeric IPv4 address."
            ) from exc
        if bind_address.is_multicast or str(bind_address) == "255.255.255.255":
            raise TftpConfigurationError(
                "Bind address must be a local unicast address or 0.0.0.0."
            )
        if not request.allow_read and not request.allow_write:
            raise TftpConfigurationError(
                "Enable downloads, uploads, or both before starting the server."
            )
        if request.allow_overwrite and not request.allow_write:
            raise TftpConfigurationError(
                "Overwrite can only be enabled when uploads are enabled."
            )

        networks: list[ipaddress.IPv4Network] = []
        for raw_cidr in request.allowed_client_cidrs:
            try:
                network = ipaddress.ip_network(raw_cidr, strict=False)
            except ValueError as exc:
                raise TftpConfigurationError(
                    f"Invalid allowed client CIDR: {raw_cidr}"
                ) from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise TftpConfigurationError(
                    "Allowed client networks must be IPv4 CIDRs."
                )
            if network.num_addresses > self.settings.tftp_allowed_network_host_limit:
                raise TftpConfigurationError(
                    f"Allowed network {network} contains {network.num_addresses} "
                    "addresses, exceeding the configured limit of "
                    f"{self.settings.tftp_allowed_network_host_limit}."
                )
            if network.is_multicast or network.prefixlen == 0:
                raise TftpConfigurationError(
                    f"Allowed client network {network} is too broad or multicast."
                )
            if network not in networks:
                networks.append(network)

        if bind_address.is_loopback:
            if not networks:
                networks.append(ipaddress.IPv4Network("127.0.0.0/8"))
        elif not networks:
            raise TftpConfigurationError(
                "A non-loopback or all-interface bind requires at least one "
                "allowed IPv4 client CIDR."
            )

        return _RuntimeConfig(
            bind_address=str(bind_address),
            port=port_value,
            allow_read=request.allow_read,
            allow_write=request.allow_write,
            allow_overwrite=request.allow_overwrite,
            allowed_networks=tuple(networks),
        )

    def _configured_root(self) -> Path:
        raw = self.settings.tftp_root_directory.strip()
        if not raw or "\0" in raw:
            raise TftpConfigurationError("BNT_TFTP_ROOT must be a valid directory path.")
        return Path(raw).expanduser().resolve(strict=False)

    def _prepare_root(self) -> Path:
        root = self._configured_root()
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TftpConfigurationError(
                f"Could not create the configured TFTP root: {exc.strerror or exc}"
            ) from exc
        if not root.is_dir():
            raise TftpConfigurationError("The configured TFTP root is not a directory.")
        return root.resolve(strict=True)

    async def _serve_requests(self, listener: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        try:
            while self._listener_socket is listener:
                data, client = await loop.sock_recvfrom(listener, MAX_DATAGRAM_BYTES)
                client_address = (str(client[0]), int(client[1]))
                if not self._client_is_allowed(client_address[0]):
                    await self._sendto(
                        listener,
                        _error_packet(ERR_ACCESS_VIOLATION, "Client is not allowed"),
                        client_address,
                    )
                    continue
                try:
                    request = parse_tftp_request(data)
                except TftpPacketError as exc:
                    await self._sendto(
                        listener,
                        _error_packet(ERR_ILLEGAL_OPERATION, str(exc)),
                        client_address,
                    )
                    continue

                key = (
                    client_address[0],
                    client_address[1],
                    request.opcode,
                    request.filename,
                )
                existing = self._sessions.get(key)
                if key in self._sessions:
                    if existing is not None and existing.initial_response is not None:
                        await self._sendto(
                            existing.sock, existing.initial_response, client_address
                        )
                    continue

                if len(self._transfer_tasks) >= self.settings.tftp_active_transfer_limit:
                    await self._sendto(
                        listener,
                        _error_packet(ERR_UNDEFINED, "Server is busy"),
                        client_address,
                    )
                    continue
                active_for_client = sum(
                    1
                    for record in self._active_records.values()
                    if record.client.startswith(f"{client_address[0]}:")
                )
                if active_for_client >= self.settings.tftp_per_client_transfer_limit:
                    await self._sendto(
                        listener,
                        _error_packet(ERR_UNDEFINED, "Client transfer limit reached"),
                        client_address,
                    )
                    continue

                self._sessions[key] = None
                task = asyncio.create_task(
                    self._run_transfer(request, client_address, key),
                    name=f"nettransfer-tftp-{request.filename}-{uuid.uuid4()}",
                )
                self._transfer_tasks.add(task)
                task.add_done_callback(self._transfer_tasks.discard)
        except asyncio.CancelledError:
            raise
        except (OSError, RuntimeError):
            if self._listener_socket is listener:
                self._listener_socket = None

    def _client_is_allowed(self, client: str) -> bool:
        config = self._config
        if config is None:
            return False
        try:
            address = ipaddress.IPv4Address(client)
        except ipaddress.AddressValueError:
            return False
        if address.is_multicast or address.is_unspecified:
            return False
        return any(address in network for network in config.allowed_networks)

    async def _run_transfer(
        self,
        request: TftpRequest,
        client: tuple[str, int],
        key: tuple[str, int, int, str],
    ) -> None:
        config = self._config
        root = self._root
        if config is None or root is None:
            self._sessions.pop(key, None)
            return

        direction = "download" if request.opcode == OP_RRQ else "upload"
        record = _TransferRecord(
            id=str(uuid.uuid4()),
            direction=direction,
            status="active",
            filename=_display_filename(request.filename),
            client=f"{client[0]}:{client[1]}",
            bytes_transferred=0,
            started_at=_utc_now(),
        )
        self._active_records[record.id] = record
        transfer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        transfer_socket.setblocking(False)
        try:
            transfer_socket.bind((config.bind_address, 0))
            handle = _SessionHandle(sock=transfer_socket)
            self._sessions[key] = handle
            deadline = time.monotonic() + self.settings.tftp_transfer_timeout_seconds
            if request.mode != "octet":
                raise _TransferRejected(
                    ERR_ILLEGAL_OPERATION,
                    "Only octet (binary) transfer mode is supported",
                )
            if request.opcode == OP_RRQ:
                if not config.allow_read:
                    raise _TransferRejected(
                        ERR_ACCESS_VIOLATION, "Downloads are disabled"
                    )
                await self._serve_read_request(
                    transfer_socket, handle, request, client, record, deadline
                )
            else:
                if not config.allow_write:
                    raise _TransferRejected(
                        ERR_ACCESS_VIOLATION, "Uploads are disabled"
                    )
                await self._serve_write_request(
                    transfer_socket, handle, request, client, record, deadline
                )
        except asyncio.CancelledError:
            self._finish_record(record, "cancelled", "Server stopped")
            raise
        except _TransferRejected as exc:
            if exc.send_error:
                await self._sendto(
                    transfer_socket,
                    _error_packet(exc.error_code, exc.message),
                    client,
                )
            self._finish_record(record, "failed", exc.message)
        except OSError as exc:
            message = f"Transfer failed: {exc.strerror or type(exc).__name__}"
            await self._sendto(
                transfer_socket, _error_packet(ERR_UNDEFINED, message), client
            )
            self._finish_record(record, "failed", message)
        except Exception:
            message = "Transfer failed because of an internal server error"
            await self._sendto(
                transfer_socket, _error_packet(ERR_UNDEFINED, message), client
            )
            self._finish_record(record, "failed", message)
        else:
            self._finish_record(record, "completed", None)
        finally:
            transfer_socket.close()
            self._sessions.pop(key, None)

    async def _serve_read_request(
        self,
        sock: socket.socket,
        handle: _SessionHandle,
        request: TftpRequest,
        client: tuple[str, int],
        record: _TransferRecord,
        deadline: float,
    ) -> None:
        path = self._resolve_request_path(request.filename, for_write=False)
        try:
            stat = path.stat()
        except FileNotFoundError as exc:
            raise _TransferRejected(ERR_FILE_NOT_FOUND, "File not found") from exc
        if not path.is_file() or path.is_symlink():
            raise _TransferRejected(ERR_ACCESS_VIOLATION, "File is not available")
        if stat.st_size > self.settings.tftp_max_file_bytes:
            raise _TransferRejected(ERR_DISK_FULL, "File exceeds the server size limit")

        negotiated = self._negotiate_options(
            request, direction="download", file_size=stat.st_size
        )
        try:
            file_handle = path.open("rb")
        except FileNotFoundError as exc:
            raise _TransferRejected(ERR_FILE_NOT_FOUND, "File not found") from exc
        except PermissionError as exc:
            raise _TransferRejected(ERR_ACCESS_VIOLATION, "File is not readable") from exc

        with file_handle:
            if negotiated.accepted:
                oack = _oack_packet(negotiated.accepted)
                handle.initial_response = oack
                await self._send_and_wait_for_ack(
                    sock,
                    client,
                    oack,
                    expected_block=0,
                    retry_timeout=negotiated.retry_timeout,
                    deadline=deadline,
                )
                handle.initial_response = None

            block = 1
            first_data = True
            while True:
                payload = file_handle.read(negotiated.block_size)
                packet = _data_packet(block, payload)
                if first_data and not negotiated.accepted:
                    handle.initial_response = packet
                await self._send_and_wait_for_ack(
                    sock,
                    client,
                    packet,
                    expected_block=block,
                    retry_timeout=negotiated.retry_timeout,
                    deadline=deadline,
                )
                handle.initial_response = None
                record.bytes_transferred += len(payload)
                if len(payload) < negotiated.block_size:
                    return
                first_data = False
                block = (block + 1) & 0xFFFF

    async def _serve_write_request(
        self,
        sock: socket.socket,
        handle: _SessionHandle,
        request: TftpRequest,
        client: tuple[str, int],
        record: _TransferRecord,
        deadline: float,
    ) -> None:
        config = self._config
        assert config is not None
        destination = self._resolve_request_path(request.filename, for_write=True)
        if destination.exists() and not config.allow_overwrite:
            raise _TransferRejected(ERR_FILE_EXISTS, "File already exists")

        negotiated = self._negotiate_options(
            request, direction="upload", file_size=None
        )
        if (
            negotiated.advertised_size is not None
            and negotiated.advertised_size > self.settings.tftp_max_file_bytes
        ):
            raise _TransferRejected(ERR_DISK_FULL, "Upload exceeds the server size limit")

        temporary = destination.parent / f"{UPLOAD_PREFIX}{uuid.uuid4().hex}.part"
        try:
            file_handle = temporary.open("xb")
        except OSError as exc:
            raise _TransferRejected(
                ERR_ACCESS_VIOLATION, "Upload destination is not writable"
            ) from exc

        published = False
        try:
            initial = (
                _oack_packet(negotiated.accepted)
                if negotiated.accepted
                else _ack_packet(0)
            )
            handle.initial_response = initial
            response = initial
            expected_block = 1
            retries = 0

            while True:
                await self._sendto(sock, response, client)
                packet = await self._receive_with_timeout(
                    sock, client, negotiated.retry_timeout, deadline
                )
                if packet is None:
                    retries += 1
                    if retries > self.settings.tftp_max_retries:
                        raise _TransferRejected(
                            ERR_UNDEFINED, "Transfer timed out after repeated retries"
                        )
                    continue

                opcode = _packet_opcode(packet)
                if opcode == OP_ERROR:
                    raise _TransferRejected(
                        ERR_UNDEFINED,
                        _client_error_message(packet),
                        send_error=False,
                    )
                if opcode != OP_DATA or len(packet) < 4:
                    raise _TransferRejected(
                        ERR_ILLEGAL_OPERATION, "Expected a TFTP DATA packet"
                    )
                if len(packet) > negotiated.block_size + 4:
                    raise _TransferRejected(
                        ERR_ILLEGAL_OPERATION, "DATA packet exceeds negotiated block size"
                    )

                block = struct.unpack("!H", packet[2:4])[0]
                previous_block = (expected_block - 1) & 0xFFFF
                if block == previous_block:
                    await self._sendto(sock, _ack_packet(previous_block), client)
                    continue
                if block != expected_block:
                    continue

                handle.initial_response = None
                payload = packet[4:]
                new_total = record.bytes_transferred + len(payload)
                if new_total > self.settings.tftp_max_file_bytes:
                    raise _TransferRejected(
                        ERR_DISK_FULL, "Upload exceeds the server size limit"
                    )
                try:
                    file_handle.write(payload)
                except OSError as exc:
                    raise _TransferRejected(
                        ERR_DISK_FULL, "Could not write the uploaded file"
                    ) from exc
                record.bytes_transferred = new_total
                retries = 0

                if len(payload) < negotiated.block_size:
                    if (
                        negotiated.advertised_size is not None
                        and negotiated.advertised_size != record.bytes_transferred
                    ):
                        raise _TransferRejected(
                            ERR_UNDEFINED,
                            "Upload size did not match the negotiated transfer size",
                        )
                    try:
                        file_handle.flush()
                        os.fsync(file_handle.fileno())
                        file_handle.close()
                        self._publish_upload(
                            temporary,
                            destination,
                            allow_overwrite=config.allow_overwrite,
                        )
                    except FileExistsError as exc:
                        raise _TransferRejected(
                            ERR_FILE_EXISTS, "File already exists"
                        ) from exc
                    except OSError as exc:
                        raise _TransferRejected(
                            ERR_DISK_FULL, "Could not publish the uploaded file"
                        ) from exc
                    published = True
                    final_ack = _ack_packet(block)
                    await self._sendto(sock, final_ack, client)
                    await self._dally_for_final_data(
                        sock,
                        client,
                        final_block=block,
                        final_ack=final_ack,
                        retry_timeout=negotiated.retry_timeout,
                        deadline=deadline,
                    )
                    return

                response = _ack_packet(block)
                expected_block = (expected_block + 1) & 0xFFFF
        finally:
            if not file_handle.closed:
                file_handle.close()
            if not published:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def _negotiate_options(
        self,
        request: TftpRequest,
        *,
        direction: str,
        file_size: int | None,
    ) -> _NegotiatedOptions:
        block_size = DEFAULT_BLOCK_SIZE
        retry_timeout = self.settings.tftp_retry_timeout_seconds
        accepted: dict[str, str] = {}
        advertised_size: int | None = None

        for name, raw_value in request.options.items():
            if name == "blksize":
                try:
                    requested = int(raw_value, 10)
                except ValueError as exc:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid blksize option"
                    ) from exc
                if not 8 <= requested <= 65_464:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid blksize option"
                    )
                block_size = min(requested, self.settings.tftp_max_block_size)
                accepted[name] = str(block_size)
            elif name == "timeout":
                try:
                    requested_timeout = int(raw_value, 10)
                except ValueError as exc:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid timeout option"
                    ) from exc
                if not 1 <= requested_timeout <= 255:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid timeout option"
                    )
                if requested_timeout <= 10:
                    retry_timeout = float(requested_timeout)
                    accepted[name] = str(requested_timeout)
            elif name == "tsize":
                try:
                    requested_size = int(raw_value, 10)
                except ValueError as exc:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid tsize option"
                    ) from exc
                if requested_size < 0:
                    raise _TransferRejected(
                        ERR_OPTION_NEGOTIATION, "Invalid tsize option"
                    )
                if direction == "download":
                    if requested_size != 0 or file_size is None:
                        raise _TransferRejected(
                            ERR_OPTION_NEGOTIATION,
                            "Read requests must use tsize 0",
                        )
                    accepted[name] = str(file_size)
                else:
                    advertised_size = requested_size
                    accepted[name] = str(requested_size)
            # Unknown options are deliberately ignored as required by RFC 2347.

        return _NegotiatedOptions(
            block_size=block_size,
            retry_timeout=retry_timeout,
            accepted=accepted,
            advertised_size=advertised_size,
        )

    async def _send_and_wait_for_ack(
        self,
        sock: socket.socket,
        client: tuple[str, int],
        outbound: bytes,
        *,
        expected_block: int,
        retry_timeout: float,
        deadline: float,
    ) -> None:
        for _attempt in range(self.settings.tftp_max_retries + 1):
            await self._sendto(sock, outbound, client)
            wait_until = min(deadline, time.monotonic() + retry_timeout)
            while time.monotonic() < wait_until:
                packet = await self._receive_until(sock, client, wait_until)
                if packet is None:
                    break
                opcode = _packet_opcode(packet)
                if opcode == OP_ERROR:
                    raise _TransferRejected(
                        ERR_UNDEFINED,
                        _client_error_message(packet),
                        send_error=False,
                    )
                if opcode != OP_ACK or len(packet) != 4:
                    raise _TransferRejected(
                        ERR_ILLEGAL_OPERATION, "Expected a TFTP ACK packet"
                    )
                block = struct.unpack("!H", packet[2:4])[0]
                if block == (expected_block & 0xFFFF):
                    return
                # Duplicate/old ACKs are ignored. Retransmission occurs only on
                # timeout, avoiding the Sorcerer's Apprentice retransmit loop.
            if time.monotonic() >= deadline:
                break
        raise _TransferRejected(
            ERR_UNDEFINED, "Transfer timed out after repeated retries"
        )

    async def _receive_with_timeout(
        self,
        sock: socket.socket,
        client: tuple[str, int],
        retry_timeout: float,
        deadline: float,
    ) -> bytes | None:
        wait_until = min(deadline, time.monotonic() + retry_timeout)
        return await self._receive_until(sock, client, wait_until)

    async def _receive_until(
        self,
        sock: socket.socket,
        client: tuple[str, int],
        wait_until: float,
    ) -> bytes | None:
        loop = asyncio.get_running_loop()
        while True:
            remaining = wait_until - time.monotonic()
            if remaining <= 0:
                return None
            try:
                packet, peer = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, MAX_DATAGRAM_BYTES), timeout=remaining
                )
            except TimeoutError:
                return None
            peer_address = (str(peer[0]), int(peer[1]))
            if peer_address != client:
                await self._sendto(
                    sock,
                    _error_packet(ERR_UNKNOWN_TID, "Unknown transfer ID"),
                    peer_address,
                )
                continue
            return packet

    async def _dally_for_final_data(
        self,
        sock: socket.socket,
        client: tuple[str, int],
        *,
        final_block: int,
        final_ack: bytes,
        retry_timeout: float,
        deadline: float,
    ) -> None:
        wait_until = min(deadline, time.monotonic() + retry_timeout * 1.1)
        while time.monotonic() < wait_until:
            packet = await self._receive_until(sock, client, wait_until)
            if packet is None:
                return
            if (
                _packet_opcode(packet) == OP_DATA
                and len(packet) >= 4
                and struct.unpack("!H", packet[2:4])[0] == final_block
            ):
                await self._sendto(sock, final_ack, client)

    async def _sendto(
        self,
        sock: socket.socket,
        packet: bytes,
        address: tuple[str, int],
    ) -> None:
        try:
            await asyncio.get_running_loop().sock_sendto(sock, packet, address)
        except (OSError, RuntimeError):
            # A closing listener/transfer owns no useful recovery path. The
            # surrounding transfer timeout or cancellation finalizes its record.
            pass

    def _resolve_request_path(self, filename: str, *, for_write: bool) -> Path:
        root = self._root
        assert root is not None
        parts = _validate_filename(filename)
        candidate = root.joinpath(*parts)
        current = root
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink() or not current.is_dir():
                raise _TransferRejected(
                    ERR_ACCESS_VIOLATION, "Path is outside the TFTP root"
                )
        if candidate.is_symlink():
            raise _TransferRejected(
                ERR_ACCESS_VIOLATION, "Symbolic links are not served"
            )
        if for_write and not candidate.parent.is_dir():
            raise _TransferRejected(
                ERR_ACCESS_VIOLATION, "Upload directory does not exist"
            )
        try:
            resolved = candidate.resolve(strict=not for_write)
            resolved.relative_to(root)
        except (FileNotFoundError, ValueError) as exc:
            if not for_write and isinstance(exc, FileNotFoundError):
                raise _TransferRejected(ERR_FILE_NOT_FOUND, "File not found") from exc
            raise _TransferRejected(
                ERR_ACCESS_VIOLATION, "Path is outside the TFTP root"
            ) from exc
        return resolved

    @staticmethod
    def _publish_upload(
        temporary: Path, destination: Path, *, allow_overwrite: bool
    ) -> None:
        if allow_overwrite:
            os.replace(temporary, destination)
            return
        os.link(temporary, destination)
        temporary.unlink()

    def _finish_record(
        self, record: _TransferRecord, status: str, error: str | None
    ) -> None:
        if record.id not in self._active_records:
            return
        self._active_records.pop(record.id, None)
        record.status = status
        record.finished_at = _utc_now()
        record.error = error[:240] if error else None
        self._recent_records.append(record)
        if status == "completed":
            self._completed_transfer_count += 1
            if record.direction == "download":
                self._bytes_sent += record.bytes_transferred
            else:
                self._bytes_received += record.bytes_transferred
        elif status == "failed":
            self._failed_transfer_count += 1

    @staticmethod
    def _record_response(record: _TransferRecord) -> TftpTransferResponse:
        return TftpTransferResponse(
            id=record.id,
            direction=record.direction,  # type: ignore[arg-type]
            status=record.status,  # type: ignore[arg-type]
            filename=record.filename,
            client=record.client,
            bytes_transferred=record.bytes_transferred,
            started_at=record.started_at,
            finished_at=record.finished_at,
            error=record.error,
        )

    @staticmethod
    def _scan_files(root: Path) -> tuple[list[TftpFileResponse], bool]:
        if not root.is_dir():
            return [], False
        found: list[TftpFileResponse] = []
        truncated = False
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            dirnames[:] = sorted(
                name
                for name in dirnames
                if not (directory_path / name).is_symlink()
            )
            for name in sorted(filenames):
                path = directory_path / name
                if name.startswith(
                    (UPLOAD_PREFIX, LEGACY_UPLOAD_PREFIX)
                ) or path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                    relative = path.relative_to(root).as_posix()
                except (OSError, ValueError):
                    continue
                try:
                    _validate_filename(relative)
                except _TransferRejected:
                    continue
                found.append(
                    TftpFileResponse(
                        filename=relative,
                        size=stat.st_size,
                        modified_at=datetime.fromtimestamp(stat.st_mtime, UTC),
                    )
                )
                if len(found) > FILE_LIST_LIMIT:
                    truncated = True
                    return found[:FILE_LIST_LIMIT], truncated
        found.sort(key=lambda item: item.filename.casefold())
        return found, truncated
