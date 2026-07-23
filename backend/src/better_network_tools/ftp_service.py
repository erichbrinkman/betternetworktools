"""Restricted FTP runtime for the local NetTransfer application.

``pyftpdlib`` owns a select/epoll style event loop which is intentionally kept
off FastAPI's asyncio loop.  A runtime instance creates one dedicated thread,
constructs every pyftpdlib object in that thread, and asks that same thread to
close all sockets during shutdown.

FTP is an unencrypted protocol.  This adapter therefore has deliberately
conservative behavior: password authentication is mandatory, clients are
filtered before a protocol handler is created, active mode and filesystem
mutation commands are disabled, and uploads are committed from same-directory
temporary files only after the complete payload has passed its size checks.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import hmac
import ipaddress
import os
import random
import secrets
import socket
import tempfile
import threading
import uuid
from collections.abc import Sequence
from concurrent.futures import Future
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .transfer_runtime import RuntimeEventCallback, RuntimeTransferEvent


_UPLOAD_PREFIX = ".nettransfer-upload-"
_UPLOAD_SUFFIX = ".part"
_PASSWORD_HASH_ROUNDS = 200_000
_THREAD_START_TIMEOUT_SECONDS = 10.0
_THREAD_STOP_TIMEOUT_SECONDS = 10.0


class FtpRuntimeError(RuntimeError):
    """Base error raised by the FTP runtime."""


class FtpRuntimeAlreadyRunningError(FtpRuntimeError):
    """Raised when a second listener is requested on one runtime."""


class FtpRuntimeBindError(OSError):
    """Raised when the FTP control listener cannot be created."""


@dataclass(frozen=True, slots=True)
class _ThreadConfig:
    root: Path
    bind_address: str
    port: int
    username: str
    password_salt: bytes
    password_digest: bytes
    allow_read: bool
    allow_write: bool
    allow_overwrite: bool
    allowed_networks: tuple[ipaddress.IPv4Network, ...]
    max_file_bytes: int
    active_transfer_limit: int
    per_client_transfer_limit: int
    passive_port_start: int
    passive_port_end: int


@dataclass(frozen=True, slots=True)
class _ActiveTransfer:
    id: str
    direction: str
    filename: str
    client: str
    client_ip: str
    username: str
    started_at: datetime


class _TransferTracker:
    """Bounded event tracker shared by handlers in the FTP thread."""

    def __init__(
        self,
        *,
        active_limit: int,
        per_client_limit: int,
        callback: RuntimeEventCallback,
    ) -> None:
        self._active_limit = active_limit
        self._per_client_limit = per_client_limit
        self._callback = callback
        self._active: dict[str, _ActiveTransfer] = {}
        self._lock = threading.Lock()
        self._stopping = False

    @property
    def stopping(self) -> bool:
        with self._lock:
            return self._stopping

    def begin(
        self,
        *,
        direction: str,
        filename: str,
        client: str,
        client_ip: str,
        username: str,
    ) -> tuple[str | None, str | None]:
        with self._lock:
            if self._stopping:
                return None, "The FTP server is stopping."
            if len(self._active) >= self._active_limit:
                return None, "The active transfer limit has been reached."
            active_for_client = sum(
                record.client_ip == client_ip for record in self._active.values()
            )
            if active_for_client >= self._per_client_limit:
                return None, "The per-client transfer limit has been reached."

            transfer_id = str(uuid.uuid4())
            record = _ActiveTransfer(
                id=transfer_id,
                direction=direction,
                filename=_display_filename(filename),
                client=client,
                client_ip=client_ip,
                username=username,
                started_at=datetime.now(UTC),
            )
            self._active[transfer_id] = record

        self._emit(
            RuntimeTransferEvent(
                id=record.id,
                protocol="ftp",
                direction=record.direction,  # type: ignore[arg-type]
                status="active",
                filename=record.filename,
                client=record.client,
                username=record.username,
                bytes_transferred=0,
                started_at=record.started_at,
            )
        )
        return transfer_id, None

    def finish(
        self,
        transfer_id: str | None,
        *,
        status: str,
        bytes_transferred: int,
        error: str | None = None,
    ) -> None:
        if transfer_id is None:
            return
        with self._lock:
            record = self._active.pop(transfer_id, None)
        if record is None:
            return

        self._emit(
            RuntimeTransferEvent(
                id=record.id,
                protocol="ftp",
                direction=record.direction,  # type: ignore[arg-type]
                status=status,  # type: ignore[arg-type]
                filename=record.filename,
                client=record.client,
                username=record.username,
                bytes_transferred=max(0, int(bytes_transferred)),
                started_at=record.started_at,
                finished_at=datetime.now(UTC),
                error=_safe_error(error),
            )
        )

    def mark_stopping(self) -> None:
        with self._lock:
            self._stopping = True

    def cancel_all(self, message: str) -> None:
        with self._lock:
            records = list(self._active.values())
            self._active.clear()
            self._stopping = True
        finished_at = datetime.now(UTC)
        for record in records:
            self._emit(
                RuntimeTransferEvent(
                    id=record.id,
                    protocol="ftp",
                    direction=record.direction,  # type: ignore[arg-type]
                    status="cancelled",
                    filename=record.filename,
                    client=record.client,
                    username=record.username,
                    bytes_transferred=0,
                    started_at=record.started_at,
                    finished_at=finished_at,
                    error=_safe_error(message),
                )
            )

    def _emit(self, event: RuntimeTransferEvent) -> None:
        try:
            self._callback(event)
        except Exception:
            # Protocol I/O must not be torn down by an observability callback.
            pass


def _display_filename(value: str) -> str:
    cleaned = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else "�"
        for character in value
    )
    cleaned = cleaned.replace("\\", "/").lstrip("/")
    return (cleaned or "unnamed")[:255]


def _safe_error(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.replace("\x00", " ").split())
    return (cleaned or "Transfer failed")[:240]


def _password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8", "strict"),
        salt,
        _PASSWORD_HASH_ROUNDS,
    )


def _normalize_networks(
    networks: Sequence[ipaddress.IPv4Network | str],
    bind_address: ipaddress.IPv4Address,
) -> tuple[ipaddress.IPv4Network, ...]:
    normalized: list[ipaddress.IPv4Network] = []
    for value in networks:
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid allowed client CIDR: {value}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("FTP currently accepts IPv4 client networks only.")
        if network not in normalized:
            normalized.append(network)

    if not normalized and bind_address.is_loopback:
        normalized.append(ipaddress.IPv4Network("127.0.0.0/8"))
    if not normalized:
        raise ValueError(
            "At least one allowed IPv4 client CIDR is required for a non-loopback bind."
        )
    return tuple(normalized)


def _cleanup_stale_uploads(root: Path) -> None:
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not (directory_path / name).is_symlink()
        ]
        for name in filenames:
            if not (name.startswith(_UPLOAD_PREFIX) and name.endswith(_UPLOAD_SUFFIX)):
                continue
            candidate = directory_path / name
            try:
                if candidate.is_file() and not candidate.is_symlink():
                    candidate.unlink()
            except OSError:
                pass


def _load_pyftpdlib() -> dict[str, Any]:
    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.exceptions import AuthenticationFailed, FilesystemError
        from pyftpdlib.filesystems import AbstractedFS
        from pyftpdlib.handlers import DTPHandler, FTPHandler
        from pyftpdlib.ioloop import Acceptor, IOLoop
        from pyftpdlib.log import logger
        from pyftpdlib.servers import FTPServer
    except ImportError as exc:  # pragma: no cover - packaging failure path
        raise FtpRuntimeError(
            "pyftpdlib 2.2 or newer is required to start the FTP server."
        ) from exc

    return {
        "DummyAuthorizer": DummyAuthorizer,
        "AuthenticationFailed": AuthenticationFailed,
        "FilesystemError": FilesystemError,
        "AbstractedFS": AbstractedFS,
        "DTPHandler": DTPHandler,
        # The data handler's retry and I/O wrapper exceptions are private in
        # pyftpdlib 2.2. Resolve them from the method we override instead of
        # depending on their package location, which has changed before.
        "RetryError": DTPHandler.handle_read.__globals__["_RetryError"],
        "FileReadWriteError": DTPHandler.handle_read.__globals__[
            "_FileReadWriteError"
        ],
        "FTPHandler": FTPHandler,
        # PassiveDTP moved into ``pyftpdlib.handlers.ftp.dispatchers`` in
        # pyftpdlib 2.2 and is no longer re-exported from ``handlers``.  The
        # supported customization point is the handler class attribute, which
        # also keeps this adapter compatible with the earlier module layout.
        "PassiveDTP": FTPHandler.passive_dtp,
        "Acceptor": Acceptor,
        "IOLoop": IOLoop,
        "logger": logger,
        "FTPServer": FTPServer,
    }


def _build_server(
    config: _ThreadConfig,
    tracker: _TransferTracker,
    dependencies: dict[str, Any],
    ioloop: Any,
) -> Any:
    DummyAuthorizer = dependencies["DummyAuthorizer"]
    AuthenticationFailed = dependencies["AuthenticationFailed"]
    FilesystemError = dependencies["FilesystemError"]
    AbstractedFS = dependencies["AbstractedFS"]
    DTPHandler = dependencies["DTPHandler"]
    RetryError = dependencies["RetryError"]
    FileReadWriteError = dependencies["FileReadWriteError"]
    FTPHandler = dependencies["FTPHandler"]
    PassiveDTP = dependencies["PassiveDTP"]
    Acceptor = dependencies["Acceptor"]
    logger = dependencies["logger"]
    FTPServer = dependencies["FTPServer"]

    class RuntimeAuthorizer(DummyAuthorizer):  # type: ignore[misc, valid-type]
        def validate_authentication(
            self, username: str, password: str, handler: Any
        ) -> None:
            del handler
            supplied = _password_digest(password, config.password_salt)
            username_matches = hmac.compare_digest(
                username.encode("utf-8", "replace"),
                config.username.encode("utf-8", "strict"),
            )
            password_matches = hmac.compare_digest(
                supplied, config.password_digest
            )
            if not (username_matches and password_matches):
                raise AuthenticationFailed("Authentication failed.")

    class _NamedUploadFile:
        """Keep the secure mkstemp path visible to pyftpdlib.

        ``os.fdopen()`` exposes the numeric descriptor as ``name`` on Python
        3.14, while pyftpdlib passes ``file_obj.name`` to transfer callbacks.
        This narrow proxy retains the same already-open descriptor and gives
        the data handler the pathname needed for an atomic commit or cleanup.
        """

        def __init__(self, descriptor: int, name: str) -> None:
            self.name = name
            self._file = os.fdopen(descriptor, "wb")

        def __getattr__(self, name: str) -> Any:
            return getattr(self._file, name)

    class RestrictedFilesystem(AbstractedFS):  # type: ignore[misc, valid-type]
        def __init__(self, root: str, cmd_channel: Any) -> None:
            super().__init__(root, cmd_channel)
            self._root_path = Path(root).resolve(strict=True)
            self._uploads: dict[str, Path] = {}

        @staticmethod
        def _reserved_name(name: str) -> bool:
            return name.startswith(_UPLOAD_PREFIX) and name.endswith(_UPLOAD_SUFFIX)

        def validpath(self, path: str) -> bool:
            try:
                candidate = Path(os.path.abspath(path))
                root_value = os.path.normcase(str(self._root_path))
                candidate_value = os.path.normcase(str(candidate))
                if os.path.commonpath((root_value, candidate_value)) != root_value:
                    return False
                relative = candidate.relative_to(self._root_path)
            except (OSError, ValueError):
                return False

            current = self._root_path
            for part in relative.parts:
                if part in {"", ".", ".."} or self._reserved_name(part):
                    return False
                current /= part
                if os.path.islink(current):
                    return False

            try:
                resolved = candidate.resolve(strict=False)
                resolved_value = os.path.normcase(str(resolved))
                return os.path.commonpath((root_value, resolved_value)) == root_value
            except (OSError, ValueError):
                return False

        def chdir(self, path: str) -> None:
            if not self.validpath(path) or not os.path.isdir(path):
                raise FilesystemError("Directory is not available")
            # Avoid AbstractedFS.chdir(), which briefly changes process-wide cwd.
            self.cwd = self.fs2ftp(path)

        def listdir(self, path: str) -> list[str]:
            if not self.validpath(path):
                raise FilesystemError("Directory is not available")
            return [
                name
                for name in os.listdir(path)
                if not self._reserved_name(name)
                and not os.path.islink(os.path.join(path, name))
            ]

        def listdirinfo(self, path: str) -> list[str]:
            return self.listdir(path)

        def safe_regular_file(self, path: str) -> bool:
            return (
                self.validpath(path)
                and os.path.isfile(path)
                and not os.path.islink(path)
            )

        def open(self, filename: str, mode: str) -> Any:
            if mode in {"r", "rb"}:
                if not self.safe_regular_file(filename):
                    raise FilesystemError("File is not available")
                return open(filename, mode)

            if mode != "wb":
                raise FilesystemError("Append and resumed uploads are disabled")
            if not self.validpath(filename):
                raise FilesystemError("Upload path is not available")

            destination = Path(filename)
            parent = destination.parent
            if not self.validpath(str(parent)) or not parent.is_dir():
                raise FilesystemError("Upload directory is not available")
            if destination.exists():
                if destination.is_symlink() or not destination.is_file():
                    raise FilesystemError("Upload destination is not a regular file")
                if not config.allow_overwrite:
                    raise FileExistsError(errno.EEXIST, "File already exists", filename)

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=_UPLOAD_PREFIX,
                suffix=_UPLOAD_SUFFIX,
                dir=parent,
            )
            self._uploads[temporary_name] = destination
            try:
                return _NamedUploadFile(descriptor, temporary_name)
            except Exception:
                self._uploads.pop(temporary_name, None)
                os.close(descriptor)
                try:
                    os.unlink(temporary_name)
                except OSError:
                    pass
                raise

        def commit_upload(self, temporary_name: str) -> None:
            destination = self._uploads.pop(temporary_name, None)
            if destination is None:
                raise FilesystemError("Upload state is no longer available")
            temporary = Path(temporary_name)
            try:
                if (
                    not temporary.is_file()
                    or temporary.is_symlink()
                    or temporary.stat().st_size > config.max_file_bytes
                ):
                    raise FilesystemError("Upload exceeds the configured size limit")
                if not self.validpath(str(destination)):
                    raise FilesystemError("Upload destination is not available")
                if destination.exists() and (
                    destination.is_symlink() or not destination.is_file()
                ):
                    raise FilesystemError("Upload destination is not a regular file")

                if config.allow_overwrite:
                    os.replace(temporary, destination)
                else:
                    # Same-directory hard-linking provides an atomic no-overwrite
                    # commit. It fails rather than replacing a racing destination.
                    os.link(temporary, destination)
                    temporary.unlink()
            except Exception:
                try:
                    temporary.unlink()
                except OSError:
                    pass
                raise

        def discard_upload(self, temporary_name: str) -> None:
            self._uploads.pop(temporary_name, None)
            try:
                path = Path(temporary_name)
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            except OSError:
                pass

        def discard_all_uploads(self) -> None:
            for temporary_name in list(self._uploads):
                self.discard_upload(temporary_name)

        def mkstemp(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            raise FilesystemError("Unique-name uploads are disabled")

        def mkdir(self, path: str) -> None:
            del path
            raise FilesystemError("Directory creation is disabled")

        def rmdir(self, path: str) -> None:
            del path
            raise FilesystemError("Directory removal is disabled")

        def remove(self, path: str) -> None:
            del path
            raise FilesystemError("File deletion is disabled")

        def rename(self, src: str, dst: str) -> None:
            del src, dst
            raise FilesystemError("Renaming is disabled")

        def chmod(self, path: str, mode: int) -> None:
            del path, mode
            raise FilesystemError("Permission changes are disabled")

        def utime(self, path: str, timeval: float) -> None:
            del path, timeval
            raise FilesystemError("Timestamp changes are disabled")

    class StrictPassiveDTP(PassiveDTP):  # type: ignore[misc, valid-type]
        def __init__(self, cmd_channel: Any, extmode: bool = False) -> None:
            self.cmd_channel = cmd_channel
            self.log = cmd_channel.log
            self.log_exception = cmd_channel.log_exception
            Acceptor.__init__(self, ioloop=cmd_channel.ioloop)

            local_ip = cmd_channel.socket.getsockname()[0]
            masqueraded_ip = cmd_channel.masquerade_address_map.get(
                local_ip, cmd_channel.masquerade_address
            )
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)

            ports = list(cmd_channel.passive_ports or ())
            random.shuffle(ports)
            bound = False
            for passive_port in ports:
                self.set_reuse_addr()
                try:
                    self.bind((local_ip, passive_port))
                except PermissionError:
                    continue
                except OSError as exc:
                    if exc.errno in {errno.EADDRINUSE, errno.EACCES}:
                        continue
                    self.close()
                    raise
                else:
                    bound = True
                    break

            if not bound:
                self.close()
                cmd_channel.respond("425 No configured passive port is available.")
                return

            self.listen(self.backlog or cmd_channel.server.backlog)
            passive_port = int(self.socket.getsockname()[1])
            if extmode:
                cmd_channel.respond(
                    f"229 Entering extended passive mode (|||{passive_port}|)."
                )
            else:
                advertised_ip = masqueraded_ip or local_ip
                cmd_channel.respond(
                    "227 Entering passive mode (%s,%d,%d)."
                    % (
                        advertised_ip.replace(".", ","),
                        passive_port // 256,
                        passive_port % 256,
                    )
                )
            if self.timeout:
                self.call_later(self.timeout, self.handle_timeout)

        def handle_timeout(self) -> None:
            if self.cmd_channel.connected:
                self.cmd_channel._cancel_pending_transfer(  # noqa: SLF001
                    "Passive data channel timed out"
                )
            super().handle_timeout()

    class BoundedDTPHandler(DTPHandler):  # type: ignore[misc, valid-type]
        def __init__(self, sock: socket.socket, cmd_channel: Any) -> None:
            self._upload_finalized = False
            self._limit_exceeded = False
            super().__init__(sock, cmd_channel)

        def handle_read(self) -> None:
            try:
                chunk = self.recv(self.ac_in_buffer_size)
            except RetryError:
                return
            except OSError:
                self.handle_error()
                return

            if chunk and self.tot_bytes_received + len(chunk) > config.max_file_bytes:
                self._limit_exceeded = True
                self.transfer_finished = False
                self.cmd_channel._runtime_failure_reason = (  # noqa: SLF001
                    "Upload exceeds the configured size limit"
                )
                self._resp = (
                    "552 Upload exceeds the configured size limit.",
                    logger.warning,
                )
                self.close()
                return

            self.tot_bytes_received += len(chunk)
            if not chunk:
                self.transfer_finished = True
                return
            if self._data_wrapper is not None:
                chunk = self._data_wrapper(chunk)
            try:
                self.file_obj.write(chunk)
            except OSError as exc:
                raise FileReadWriteError(exc) from exc

        handle_read_event = handle_read

        def close(self) -> None:
            if (
                not getattr(self, "_closed", True)
                and getattr(self, "receive", False)
                and getattr(self, "file_obj", None) is not None
                and not self._upload_finalized
            ):
                self._upload_finalized = True
                temporary_name = str(self.file_obj.name)
                try:
                    if not self.file_obj.closed:
                        self.file_obj.flush()
                        os.fsync(self.file_obj.fileno())
                        self.file_obj.close()
                    if self.transfer_finished and not self._limit_exceeded:
                        self.cmd_channel.fs.commit_upload(temporary_name)
                    else:
                        self.cmd_channel.fs.discard_upload(temporary_name)
                except Exception:
                    self.cmd_channel.fs.discard_upload(temporary_name)
                    self.transfer_finished = False
                    self.cmd_channel._runtime_failure_reason = (  # noqa: SLF001
                        "Upload could not be committed"
                    )
                    self._resp = (
                        "426 Upload could not be committed.",
                        logger.warning,
                    )
            super().close()

    unsupported_commands = {
        "APPE",
        "DELE",
        "EPRT",
        "MFMT",
        "MKD",
        "PORT",
        "REIN",
        "REST",
        "RMD",
        "RNFR",
        "RNTO",
        "SITE CHMOD",
        "STOU",
        "XMKD",
        "XRMD",
    }

    class RestrictedFTPHandler(FTPHandler):  # type: ignore[misc, valid-type]
        authorizer: Any
        abstracted_fs = RestrictedFilesystem
        passive_dtp = StrictPassiveDTP
        dtp_handler = BoundedDTPHandler
        passive_ports = range(config.passive_port_start, config.passive_port_end + 1)
        permit_foreign_addresses = False
        permit_privileged_ports = False
        use_sendfile = False
        banner = "NetTransfer FTP server ready."
        max_login_attempts = 3
        auth_failed_timeout = 1
        proto_cmds = {
            name: value
            for name, value in FTPHandler.proto_cmds.items()
            if name not in unsupported_commands
        }

        def __init__(self, conn: socket.socket, server: Any, ioloop: Any = None):
            self._runtime_transfer_id: str | None = None
            self._runtime_failure_reason: str | None = None
            super().__init__(conn, server, ioloop=ioloop)

        def handle_auth_success(
            self, home: str, password: str, msg_login: str
        ) -> None:
            super().handle_auth_success(home, password, msg_login)
            # RuntimeAuthorizer never impersonates OS users, so retaining the
            # wire password after validation serves no purpose.
            self.password = ""

        def on_login_failed(self, username: str, password: str) -> None:
            del username, password

        def _virtual_name(self, path: str) -> str:
            return _display_filename(self.fs.fs2ftp(path))

        def _begin_transfer(self, direction: str, path: str) -> bool:
            if self._runtime_transfer_id is not None:
                self.respond("450 Another transfer is already active.")
                return False
            transfer_id, reason = tracker.begin(
                direction=direction,
                filename=self._virtual_name(path),
                client=f"{self.remote_ip}:{self.remote_port}",
                client_ip=self.remote_ip,
                username=self.username,
            )
            if transfer_id is None:
                self.respond(f"450 {reason or 'Transfer limit reached'}")
                return False
            self._runtime_transfer_id = transfer_id
            self._runtime_failure_reason = None
            return True

        def _transferred_bytes(self) -> int:
            channel = getattr(self, "data_channel", None)
            if channel is None:
                return 0
            try:
                return int(channel.get_transmitted_bytes())
            except (AttributeError, TypeError, ValueError):
                return 0

        def _finish_transfer(
            self, status: str, error: str | None = None
        ) -> None:
            transfer_id = self._runtime_transfer_id
            self._runtime_transfer_id = None
            tracker.finish(
                transfer_id,
                status=status,
                bytes_transferred=self._transferred_bytes(),
                error=error,
            )
            self._runtime_failure_reason = None

        def _cancel_pending_transfer(self, reason: str) -> None:
            incoming = getattr(self, "_in_dtp_queue", None)
            self._in_dtp_queue = None
            if incoming is not None:
                file_obj = incoming[0]
                try:
                    temporary_name = str(file_obj.name)
                    file_obj.close()
                    if self.fs is not None:
                        self.fs.discard_upload(temporary_name)
                except (AttributeError, OSError):
                    pass

            outgoing = getattr(self, "_out_dtp_queue", None)
            self._out_dtp_queue = None
            if outgoing is not None:
                try:
                    outgoing[2].close()
                except (AttributeError, OSError, TypeError):
                    pass

            if self._runtime_transfer_id is not None:
                status = "cancelled" if tracker.stopping else "failed"
                self._finish_transfer(status, reason)

        def ftp_RETR(self, file: str) -> str | None:
            if not config.allow_read:
                self.respond("550 Downloads are disabled.")
                return None
            if not self._begin_transfer("download", file):
                return None
            try:
                if not self.fs.safe_regular_file(file):
                    self.respond("550 File is not available.")
                    self._finish_transfer("failed", "File is not available")
                    return None
                if os.path.getsize(file) > config.max_file_bytes:
                    self.respond("550 File exceeds the configured size limit.")
                    self._finish_transfer(
                        "failed", "File exceeds the configured size limit"
                    )
                    return None
                result = super().ftp_RETR(file)
            except Exception:
                self._finish_transfer("failed", "Download could not be started")
                raise
            if result is None:
                self._finish_transfer("failed", "Download could not be started")
            return result

        def ftp_STOR(self, file: str, mode: str = "w") -> str | None:
            if not config.allow_write:
                self.respond("550 Uploads are disabled.")
                return None
            if mode != "w":
                self.respond("550 Append and resumed uploads are disabled.")
                return None
            if not self._begin_transfer("upload", file):
                return None
            try:
                result = super().ftp_STOR(file, mode=mode)
            except Exception:
                self._cancel_pending_transfer("Upload could not be started")
                raise
            if result is None:
                self._cancel_pending_transfer("Upload could not be started")
            return result

        def ftp_PORT(self, line: str) -> None:
            del line
            self.respond("502 Active FTP mode is disabled; use PASV or EPSV.")

        ftp_EPRT = ftp_PORT

        def ftp_USER(self, line: str) -> None:
            if self.authenticated:
                self.respond("503 Re-authentication is disabled for this session.")
                return
            super().ftp_USER(line)

        def ftp_REST(self, line: str) -> None:
            del line
            self.respond("502 Resumed transfers are disabled.")

        def ftp_APPE(self, file: str) -> None:
            del file
            self.respond("502 Append uploads are disabled.")

        def ftp_STOU(self, line: str) -> None:
            del line
            self.respond("502 Unique-name uploads are disabled.")

        def ftp_ABOR(self, line: str) -> None:
            super().ftp_ABOR(line)
            self._cancel_pending_transfer("Transfer aborted by client")

        def on_file_sent(self, file: str) -> None:
            del file
            self._finish_transfer("completed")

        def on_incomplete_file_sent(self, file: str) -> None:
            del file
            status = "cancelled" if tracker.stopping else "failed"
            self._finish_transfer(
                status, self._runtime_failure_reason or "Download was interrupted"
            )

        def on_file_received(self, file: str) -> None:
            del file
            self._finish_transfer("completed")

        def on_incomplete_file_received(self, file: str) -> None:
            if self.fs is not None:
                self.fs.discard_upload(file)
            status = "cancelled" if tracker.stopping else "failed"
            self._finish_transfer(
                status, self._runtime_failure_reason or "Upload was interrupted"
            )

        def on_disconnect(self) -> None:
            if self.fs is not None:
                self.fs.discard_all_uploads()
            self._cancel_pending_transfer(
                "Server stopped" if tracker.stopping else "Client disconnected"
            )

        def close(self) -> None:
            filesystem = getattr(self, "fs", None)
            if not getattr(self, "_closed", True):
                self._cancel_pending_transfer(
                    "Server stopped" if tracker.stopping else "Client disconnected"
                )
            super().close()
            if filesystem is not None:
                filesystem.discard_all_uploads()

    permission_string = "el"
    if config.allow_read:
        permission_string += "r"
    if config.allow_write:
        permission_string += "w"

    authorizer = RuntimeAuthorizer()
    # The placeholder is never used by validate_authentication(). Keeping the
    # real password out of DummyAuthorizer avoids retaining it for the runtime.
    authorizer.add_user(
        config.username,
        "<validated-by-runtime-authorizer>",
        str(config.root),
        perm=permission_string,
        msg_login="Login successful.",
    )
    RestrictedFTPHandler.authorizer = authorizer

    class RestrictedFTPServer(FTPServer):  # type: ignore[misc, valid-type]
        def handle_accepted(self, sock: socket.socket, addr: Any) -> Any:
            try:
                client_address = ipaddress.IPv4Address(str(addr[0]))
            except (ipaddress.AddressValueError, IndexError, TypeError):
                sock.close()
                return None
            if not any(
                client_address in network for network in config.allowed_networks
            ):
                sock.close()
                return None
            return super().handle_accepted(sock, addr)

    try:
        server = RestrictedFTPServer(
            (config.bind_address, config.port),
            RestrictedFTPHandler,
            ioloop=ioloop,
        )
    except OSError as exc:
        raise FtpRuntimeBindError(
            f"Could not bind FTP control listener at "
            f"{config.bind_address}:{config.port}: {exc.strerror or exc}"
        ) from exc

    # pyftpdlib counts control, passive-listener, and data sockets here.
    server.max_cons = max(8, config.active_transfer_limit * 3 + 4)
    server.max_cons_per_ip = max(2, config.per_client_transfer_limit * 2)
    return server


class FtpServerRuntime:
    """Own one restricted pyftpdlib listener and its worker thread."""

    def __init__(
        self,
        *,
        root: Path,
        max_file_bytes: int,
        active_transfer_limit: int,
        per_client_transfer_limit: int,
        passive_port_start: int,
        passive_port_end: int,
        event_callback: RuntimeEventCallback,
    ) -> None:
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be positive")
        if active_transfer_limit <= 0:
            raise ValueError("active_transfer_limit must be positive")
        if per_client_transfer_limit <= 0:
            raise ValueError("per_client_transfer_limit must be positive")
        if not 1024 <= passive_port_start <= 65535:
            raise ValueError("passive_port_start must be an unprivileged TCP port")
        if not passive_port_start <= passive_port_end <= 65535:
            raise ValueError("passive_port_end must not precede passive_port_start")
        if not callable(event_callback):
            raise TypeError("event_callback must be callable")

        self._root_input = Path(root)
        self._max_file_bytes = max_file_bytes
        self._active_transfer_limit = active_transfer_limit
        self._per_client_transfer_limit = per_client_transfer_limit
        self._passive_port_start = passive_port_start
        self._passive_port_end = passive_port_end
        self._event_callback = event_callback

        self._lifecycle_lock = asyncio.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event: threading.Event | None = None
        self._thread_error: BaseException | None = None

    async def start(
        self,
        *,
        bind_address: str,
        port: int,
        username: str,
        password: str,
        allow_read: bool,
        allow_write: bool,
        allow_overwrite: bool,
        allowed_networks: Sequence[ipaddress.IPv4Network | str],
    ) -> dict[str, int]:
        async with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                raise FtpRuntimeAlreadyRunningError(
                    "The FTP server is already running."
                )
            if not allow_read and not allow_write:
                raise ValueError("Enable downloads, uploads, or both.")
            if allow_overwrite and not allow_write:
                raise ValueError("Overwrite requires uploads to be enabled.")
            if not 0 <= port <= 65535:
                raise ValueError("port must be between 0 and 65535")
            if not username or len(username) > 128 or any(
                ord(character) < 32 or ord(character) == 127
                for character in username
            ):
                raise ValueError("username must contain 1-128 printable characters")
            if username.casefold() == "anonymous":
                raise ValueError("Anonymous FTP access is disabled.")
            if not password or len(password) > 1024:
                raise ValueError("password must contain 1-1024 characters")

            try:
                address = ipaddress.IPv4Address(bind_address)
            except ipaddress.AddressValueError as exc:
                raise ValueError("bind_address must be a numeric IPv4 address") from exc
            if address.is_multicast or str(address) == "255.255.255.255":
                raise ValueError("bind_address must be a local unicast address")

            root = self._root_input.expanduser()
            try:
                if root.is_symlink():
                    raise FtpRuntimeError(
                        "The configured FTP root must not be a symbolic link."
                    )
                root.mkdir(parents=True, exist_ok=True)
                root = root.resolve(strict=True)
            except FtpRuntimeError:
                raise
            except OSError as exc:
                raise FtpRuntimeError(
                    f"Could not prepare FTP root directory: {exc.strerror or exc}"
                ) from exc
            if not root.is_dir():
                raise FtpRuntimeError("The configured FTP root is not a directory.")
            _cleanup_stale_uploads(root)

            salt = secrets.token_bytes(32)
            config = _ThreadConfig(
                root=root,
                bind_address=str(address),
                port=port,
                username=username,
                password_salt=salt,
                password_digest=_password_digest(password, salt),
                allow_read=allow_read,
                allow_write=allow_write,
                allow_overwrite=allow_overwrite,
                allowed_networks=_normalize_networks(allowed_networks, address),
                max_file_bytes=self._max_file_bytes,
                active_transfer_limit=self._active_transfer_limit,
                per_client_transfer_limit=self._per_client_transfer_limit,
                passive_port_start=self._passive_port_start,
                passive_port_end=self._passive_port_end,
            )

            stop_event = threading.Event()
            ready: Future[dict[str, int]] = Future()
            self._thread_error = None
            thread = threading.Thread(
                target=self._thread_main,
                args=(config, stop_event, ready),
                name="nettransfer-ftp",
                daemon=True,
            )
            self._stop_event = stop_event
            self._thread = thread
            thread.start()

            try:
                result = await asyncio.wait_for(
                    asyncio.wrap_future(ready),
                    timeout=_THREAD_START_TIMEOUT_SECONDS,
                )
            except Exception:
                stop_event.set()
                await asyncio.to_thread(
                    thread.join, _THREAD_STOP_TIMEOUT_SECONDS
                )
                self._thread = None
                self._stop_event = None
                raise
            return result

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            thread = self._thread
            stop_event = self._stop_event
            if thread is None:
                return
            if stop_event is not None:
                stop_event.set()
            await asyncio.to_thread(thread.join, _THREAD_STOP_TIMEOUT_SECONDS)
            if thread.is_alive():
                raise FtpRuntimeError("The FTP server thread did not stop cleanly.")
            self._thread = None
            self._stop_event = None

    async def shutdown(self) -> None:
        await self.stop()

    def _thread_main(
        self,
        config: _ThreadConfig,
        stop_event: threading.Event,
        ready: Future[dict[str, int]],
    ) -> None:
        tracker = _TransferTracker(
            active_limit=config.active_transfer_limit,
            per_client_limit=config.per_client_transfer_limit,
            callback=self._event_callback,
        )
        server: Any = None
        ioloop: Any = None
        try:
            dependencies = _load_pyftpdlib()
            ioloop = dependencies["IOLoop"].factory()
            server = _build_server(config, tracker, dependencies, ioloop)
            bound_port = int(server.address[1])
            ready.set_result(
                {
                    "bound_port": bound_port,
                    "passive_port_start": config.passive_port_start,
                    "passive_port_end": config.passive_port_end,
                }
            )

            while not stop_event.is_set():
                server.serve_forever(
                    timeout=0.1,
                    blocking=False,
                    handle_exit=False,
                )
        except BaseException as exc:
            self._thread_error = exc
            if not ready.done():
                ready.set_exception(exc)
        finally:
            tracker.mark_stopping()
            if server is not None:
                try:
                    server.close_all()
                except Exception:
                    pass
            elif ioloop is not None:
                try:
                    ioloop.close()
                except Exception:
                    pass
            tracker.cancel_all("Server stopped")


__all__ = [
    "FtpRuntimeAlreadyRunningError",
    "FtpRuntimeBindError",
    "FtpRuntimeError",
    "FtpServerRuntime",
]
