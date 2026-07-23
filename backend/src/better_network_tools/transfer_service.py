"""Singleton lifecycle and shared API surface for NetTransfer protocols."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import threading
import uuid
from collections import deque
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import Settings
from .tftp_models import TftpServerStartRequest
from .tftp_service import (
    TftpConfigurationError,
    TftpServerAlreadyRunningError,
    TftpServerBindError,
    TftpServerService,
)
from .transfer_models import (
    TransferFileListResponse,
    TransferFileResponse,
    TransferResponse,
    TransferServerStartRequest,
    TransferServerStatusResponse,
)
from .transfer_runtime import RuntimeTransferEvent


RECENT_TRANSFER_LIMIT = 100
FILE_LIST_LIMIT = 500


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class TransferServiceError(RuntimeError):
    code = "transfer_service_error"
    status_code = 422

    def as_detail(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self)}


class TransferConfigurationError(TransferServiceError):
    code = "invalid_transfer_configuration"


class TransferServerAlreadyRunningError(TransferServiceError):
    code = "transfer_server_already_running"
    status_code = 409


class TransferServerBindError(TransferServiceError):
    code = "transfer_server_bind_failed"
    status_code = 409


@dataclass(frozen=True, slots=True)
class _RuntimeConfig:
    protocol: str
    bind_address: str
    port: int
    allow_read: bool
    allow_write: bool
    allow_overwrite: bool
    allowed_networks: tuple[ipaddress.IPv4Network, ...]
    username: str | None


class TransferServerService:
    """Own exactly one TFTP, SFTP, or FTP listener at a time."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lifecycle_lock = asyncio.Lock()
        self._state = "stopped"
        self._config: _RuntimeConfig | None = None
        self._runtime: Any | None = None
        self._runtime_token: str | None = None
        self._event_loop: asyncio.AbstractEventLoop | None = None
        self._started_at: datetime | None = None
        self._details: dict[str, object] = {}
        self._active_records: dict[str, RuntimeTransferEvent] = {}
        self._recent_records: deque[RuntimeTransferEvent] = deque(
            maxlen=RECENT_TRANSFER_LIMIT
        )
        self._completed_transfer_count = 0
        self._failed_transfer_count = 0
        self._bytes_sent = 0
        self._bytes_received = 0
        self._event_thread_lock = threading.Lock()

    async def start(
        self, request: TransferServerStartRequest
    ) -> TransferServerStatusResponse:
        async with self._lifecycle_lock:
            if self._state != "stopped":
                active = self._config.protocol.upper() if self._config else "another"
                raise TransferServerAlreadyRunningError(
                    f"A {active} NetTransfer server is already starting or running."
                )
            if not _is_loopback_host(self.settings.host):
                raise TransferConfigurationError(
                    "NetTransfer can only be managed by a loopback-bound local API."
                )

            config = self._validate_configuration(request)
            root = self._prepare_root()
            token = str(uuid.uuid4())
            self._state = "starting"
            self._config = config
            self._runtime_token = token
            self._event_loop = asyncio.get_running_loop()
            self._started_at = None
            self._details = {}
            self._active_records.clear()
            self._recent_records.clear()
            self._completed_transfer_count = 0
            self._failed_transfer_count = 0
            self._bytes_sent = 0
            self._bytes_received = 0

            runtime: Any | None = None
            try:
                if config.protocol == "tftp":
                    runtime = TftpServerService(
                        replace(
                            self.settings,
                            tftp_root_directory=self.settings.transfer_root_directory,
                            tftp_default_bind_address=(
                                self.settings.transfer_default_bind_address
                            ),
                            tftp_default_port=(
                                self.settings.transfer_tftp_default_port
                            ),
                            tftp_max_file_bytes=(
                                self.settings.transfer_max_file_bytes
                            ),
                            tftp_active_transfer_limit=(
                                self.settings.transfer_active_transfer_limit
                            ),
                            tftp_per_client_transfer_limit=(
                                self.settings.transfer_per_client_transfer_limit
                            ),
                            tftp_allowed_network_host_limit=(
                                self.settings.transfer_allowed_network_host_limit
                            ),
                        )
                    )
                    await runtime.start(
                        TftpServerStartRequest(
                            bind_address=config.bind_address,
                            port=config.port,
                            allow_read=config.allow_read,
                            allow_write=config.allow_write,
                            allow_overwrite=config.allow_overwrite,
                            allowed_client_cidrs=[
                                str(network) for network in config.allowed_networks
                            ],
                        )
                    )
                elif config.protocol == "sftp":
                    from .sftp_service import SftpServerRuntime

                    host_key_path = Path(
                        self.settings.transfer_sftp_host_key_path
                    ).expanduser().resolve(strict=False)
                    try:
                        host_key_path.relative_to(root)
                    except ValueError:
                        pass
                    else:
                        raise TransferConfigurationError(
                            "The SFTP host key must be stored outside the shared "
                            "NetTransfer root."
                        )
                    runtime = SftpServerRuntime(
                        root=root,
                        max_file_bytes=self.settings.transfer_max_file_bytes,
                        active_transfer_limit=(
                            self.settings.transfer_active_transfer_limit
                        ),
                        per_client_transfer_limit=(
                            self.settings.transfer_per_client_transfer_limit
                        ),
                        host_key_path=host_key_path,
                        event_callback=lambda event: self._accept_event(token, event),
                    )
                    self._details = await runtime.start(
                        bind_address=config.bind_address,
                        port=config.port,
                        username=config.username or "",
                        password=request.password.get_secret_value()
                        if request.password
                        else "",
                        allow_read=config.allow_read,
                        allow_write=config.allow_write,
                        allow_overwrite=config.allow_overwrite,
                        allowed_networks=config.allowed_networks,
                    )
                else:
                    from .ftp_service import FtpServerRuntime

                    runtime = FtpServerRuntime(
                        root=root,
                        max_file_bytes=self.settings.transfer_max_file_bytes,
                        active_transfer_limit=(
                            self.settings.transfer_active_transfer_limit
                        ),
                        per_client_transfer_limit=(
                            self.settings.transfer_per_client_transfer_limit
                        ),
                        passive_port_start=(
                            self.settings.transfer_ftp_passive_port_start
                        ),
                        passive_port_end=self.settings.transfer_ftp_passive_port_end,
                        event_callback=lambda event: self._accept_event(token, event),
                    )
                    self._details = await runtime.start(
                        bind_address=config.bind_address,
                        port=config.port,
                        username=config.username or "",
                        password=request.password.get_secret_value()
                        if request.password
                        else "",
                        allow_read=config.allow_read,
                        allow_write=config.allow_write,
                        allow_overwrite=config.allow_overwrite,
                        allowed_networks=config.allowed_networks,
                    )
            except TftpConfigurationError as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferConfigurationError(str(exc)) from exc
            except TftpServerAlreadyRunningError as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferServerAlreadyRunningError(str(exc)) from exc
            except TftpServerBindError as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferServerBindError(str(exc)) from exc
            except PermissionError as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferServerBindError(
                    f"Permission was denied while binding port {config.port}. "
                    "Choose an unprivileged port or adjust the operating-system permissions."
                ) from exc
            except OSError as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferServerBindError(
                    f"Could not bind {config.bind_address}:{config.port}: "
                    f"{exc.strerror or exc}"
                ) from exc
            except (RuntimeError, ValueError) as exc:
                await self._rollback_runtime(runtime)
                self._clear_after_failed_start()
                raise TransferConfigurationError(str(exc)) from exc

            self._runtime = runtime
            self._state = "running"
            self._started_at = _utc_now()
        return await self.status()

    async def stop(self) -> TransferServerStatusResponse:
        async with self._lifecycle_lock:
            if self._state == "stopped":
                return await self.status()
            self._state = "stopping"
            runtime = self._runtime
            try:
                if runtime is not None:
                    await runtime.stop()
            finally:
                self._active_records.clear()
                self._runtime = None
                self._runtime_token = None
                self._started_at = None
                self._state = "stopped"
        return await self.status()

    async def shutdown(self) -> None:
        await self.stop()

    async def status(self) -> TransferServerStatusResponse:
        config = self._config
        protocol = config.protocol if config and self._state != "stopped" else None
        if protocol == "tftp" and self._runtime is not None:
            tftp_status = await self._runtime.status()
            transfers = [
                TransferResponse(
                    id=item.id,
                    protocol="tftp",
                    direction=item.direction,
                    status=item.status,
                    filename=item.filename,
                    client=item.client,
                    username=None,
                    bytes_transferred=item.bytes_transferred,
                    started_at=item.started_at,
                    finished_at=item.finished_at,
                    error=item.error,
                )
                for item in tftp_status.recent_transfers
            ]
            active_count = tftp_status.active_transfer_count
            completed_count = tftp_status.completed_transfer_count
            failed_count = tftp_status.failed_transfer_count
            bytes_sent = tftp_status.bytes_sent
            bytes_received = tftp_status.bytes_received
        else:
            records = sorted(
                self._active_records.values(), key=lambda item: item.started_at
            ) + list(reversed(self._recent_records))
            transfers = [self._event_response(item) for item in records]
            active_count = len(self._active_records)
            completed_count = self._completed_transfer_count
            failed_count = self._failed_transfer_count
            bytes_sent = self._bytes_sent
            bytes_received = self._bytes_received

        bind = config.bind_address if config else self.settings.transfer_default_bind_address
        port = config.port if config and self._state != "stopped" else None
        networks = (
            [str(network) for network in config.allowed_networks]
            if config
            else ["127.0.0.0/8"]
        )
        return TransferServerStatusResponse(
            state=self._state,  # type: ignore[arg-type]
            running=self._state == "running",
            protocol=protocol,  # type: ignore[arg-type]
            transport=("udp" if protocol == "tftp" else "tcp") if protocol else None,
            bind_address=bind,
            port=port,
            root_directory=str(self._configured_root()),
            allow_read=config.allow_read if config else True,
            allow_write=config.allow_write if config else False,
            allow_overwrite=config.allow_overwrite if config else False,
            allowed_client_cidrs=networks,
            authentication="none" if protocol in {None, "tftp"} else "password",
            username=config.username if protocol in {"sftp", "ftp"} else None,
            sftp_host_key_fingerprint=(
                str(self._details.get("fingerprint"))
                if protocol == "sftp" and self._details.get("fingerprint")
                else None
            ),
            ftp_passive_port_start=(
                self.settings.transfer_ftp_passive_port_start
                if protocol == "ftp"
                else None
            ),
            ftp_passive_port_end=(
                self.settings.transfer_ftp_passive_port_end
                if protocol == "ftp"
                else None
            ),
            default_ports={
                "tftp": self.settings.transfer_tftp_default_port,
                "sftp": self.settings.transfer_sftp_default_port,
                "ftp": self.settings.transfer_ftp_default_port,
            },
            started_at=self._started_at,
            active_transfer_count=active_count,
            completed_transfer_count=completed_count,
            failed_transfer_count=failed_count,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            recent_transfers=transfers[:RECENT_TRANSFER_LIMIT],
        )

    async def list_files(self) -> TransferFileListResponse:
        root = self._configured_root()
        files, truncated = await asyncio.to_thread(self._scan_files, root)
        return TransferFileListResponse(
            root_directory=str(root), files=files, truncated=truncated
        )

    def _validate_configuration(
        self, request: TransferServerStartRequest
    ) -> _RuntimeConfig:
        try:
            bind_address = ipaddress.IPv4Address(request.bind_address)
        except ipaddress.AddressValueError as exc:
            raise TransferConfigurationError(
                "Bind address must be a numeric IPv4 address."
            ) from exc
        if bind_address.is_multicast or str(bind_address) == "255.255.255.255":
            raise TransferConfigurationError(
                "Bind address must be a local unicast address or 0.0.0.0."
            )

        defaults = {
            "tftp": self.settings.transfer_tftp_default_port,
            "sftp": self.settings.transfer_sftp_default_port,
            "ftp": self.settings.transfer_ftp_default_port,
        }
        networks: list[ipaddress.IPv4Network] = []
        for raw_cidr in request.allowed_client_cidrs:
            try:
                network = ipaddress.ip_network(raw_cidr, strict=False)
            except ValueError as exc:
                raise TransferConfigurationError(
                    f"Invalid allowed client CIDR: {raw_cidr}"
                ) from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise TransferConfigurationError(
                    "Allowed client networks must be IPv4 CIDRs."
                )
            if network.num_addresses > self.settings.transfer_allowed_network_host_limit:
                raise TransferConfigurationError(
                    f"Allowed network {network} exceeds the configured host limit."
                )
            if network.is_multicast or network.prefixlen == 0:
                raise TransferConfigurationError(
                    f"Allowed client network {network} is too broad or multicast."
                )
            if network not in networks:
                networks.append(network)
        if bind_address.is_loopback:
            if not networks:
                networks.append(ipaddress.IPv4Network("127.0.0.0/8"))
        elif not networks:
            raise TransferConfigurationError(
                "A non-loopback bind requires at least one allowed IPv4 client CIDR."
            )
        if (
            request.protocol == "ftp"
            and not bind_address.is_loopback
            and not request.acknowledge_plaintext_ftp
        ):
            raise TransferConfigurationError(
                "Acknowledge that FTP credentials and files are plaintext before "
                "binding FTP to a non-loopback address."
            )
        selected_port = request.port or defaults[request.protocol]
        if (
            request.protocol == "ftp"
            and self.settings.transfer_ftp_passive_port_start
            <= selected_port
            <= self.settings.transfer_ftp_passive_port_end
        ):
            raise TransferConfigurationError(
                "The FTP control port must be outside the configured passive range."
            )
        return _RuntimeConfig(
            protocol=request.protocol,
            bind_address=str(bind_address),
            port=selected_port,
            allow_read=request.allow_read,
            allow_write=request.allow_write,
            allow_overwrite=request.allow_overwrite,
            allowed_networks=tuple(networks),
            username=request.username,
        )

    def _configured_root(self) -> Path:
        raw = self.settings.transfer_root_directory.strip()
        if not raw or "\0" in raw:
            raise TransferConfigurationError(
                "BNT_TRANSFER_ROOT must be a valid directory path."
            )
        return Path(raw).expanduser().resolve(strict=False)

    def _prepare_root(self) -> Path:
        root = self._configured_root()
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise TransferConfigurationError(
                f"Could not create the configured transfer root: {exc.strerror or exc}"
            ) from exc
        if not root.is_dir() or root.is_symlink():
            raise TransferConfigurationError(
                "The configured transfer root must be a real directory."
            )
        return root.resolve(strict=True)

    @staticmethod
    def _scan_files(root: Path) -> tuple[list[TransferFileResponse], bool]:
        files: list[TransferFileResponse] = []
        truncated = False
        for current, directories, filenames in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                name
                for name in directories
                if not (current_path / name).is_symlink()
            )
            for filename in sorted(filenames):
                if filename.startswith(
                    (".nettransfer-upload-", ".nettftp-upload-")
                ) and filename.endswith(".part"):
                    continue
                path = current_path / filename
                if path.is_symlink():
                    continue
                try:
                    stat = path.stat()
                except (FileNotFoundError, PermissionError, OSError):
                    continue
                if not path.is_file():
                    continue
                if len(files) >= FILE_LIST_LIMIT:
                    truncated = True
                    return files, truncated
                files.append(
                    TransferFileResponse(
                        filename=path.relative_to(root).as_posix(),
                        size=stat.st_size,
                        modified_at=datetime.fromtimestamp(stat.st_mtime, UTC),
                    )
                )
        files.sort(key=lambda item: item.filename.casefold())
        return files, truncated

    def _accept_event(self, token: str, event: RuntimeTransferEvent) -> None:
        loop = self._event_loop
        if loop is None or loop.is_closed():
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is loop:
            self._apply_event(token, event)
        else:
            loop.call_soon_threadsafe(self._apply_event, token, event)

    def _apply_event(self, token: str, event: RuntimeTransferEvent) -> None:
        if token != self._runtime_token:
            return
        with self._event_thread_lock:
            if event.status == "active":
                self._active_records[event.id] = event
                return
            self._active_records.pop(event.id, None)
            self._recent_records.append(event)
            if event.status == "completed":
                self._completed_transfer_count += 1
                if event.direction == "download":
                    self._bytes_sent += event.bytes_transferred
                else:
                    self._bytes_received += event.bytes_transferred
            else:
                self._failed_transfer_count += 1

    @staticmethod
    def _event_response(event: RuntimeTransferEvent) -> TransferResponse:
        return TransferResponse(
            id=event.id,
            protocol=event.protocol,
            direction=event.direction,
            status=event.status,
            filename=event.filename,
            client=event.client,
            username=event.username,
            bytes_transferred=max(0, event.bytes_transferred),
            started_at=event.started_at,
            finished_at=event.finished_at,
            error=event.error[:240] if event.error else None,
        )

    async def _rollback_runtime(self, runtime: Any | None) -> None:
        if runtime is None:
            return
        try:
            await runtime.stop()
        except Exception:
            pass

    def _clear_after_failed_start(self) -> None:
        self._runtime = None
        self._runtime_token = None
        self._started_at = None
        self._details = {}
        self._state = "stopped"
