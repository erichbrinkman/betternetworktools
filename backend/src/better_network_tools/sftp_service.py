"""Root-confined, password-only SFTP runtime for NetTransfer.

The runtime deliberately exposes only the small file-transfer surface shared by
the other NetTransfer protocols: directory listing, stat, downloads, and atomic
uploads.  It does not provide a shell, command execution, forwarding, links,
directory mutation, deletion, rename, append, or in-place file editing.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import secrets
import stat
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, AsyncIterator, BinaryIO

import asyncssh

from .transfer_runtime import RuntimeEventCallback, RuntimeTransferEvent


_MAX_PATH_BYTES = 1_024
_MAX_COMPONENT_BYTES = 255
_MAX_AUTH_ATTEMPTS = 5
_CONNECTION_CLOSE_TIMEOUT_SECONDS = 3.0
_TEMP_PREFIX = ".nettransfer-upload-"
_LEGACY_TEMP_PREFIX = ".nettftp-upload-"

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _safe_text(value: str, *, limit: int) -> str:
    return "".join(
        character if ord(character) >= 32 and ord(character) != 127 else "�"
        for character in value
    )[:limit]


def _client_identity(peername: object) -> tuple[str, str]:
    if isinstance(peername, tuple) and len(peername) >= 2:
        host = _safe_text(str(peername[0]), limit=45)
        try:
            port = int(peername[1])
        except (TypeError, ValueError):
            port = 0
        return host, f"{host}:{port}"
    return "", "unknown"


def _permission_denied(message: str = "Operation is not permitted") -> Exception:
    return asyncssh.SFTPPermissionDenied(message)


@dataclass(slots=True)
class _OpenTransfer:
    id: str
    owner: "_RootedSFTPServer"
    file: BinaryIO
    direction: str
    filename: str
    client_ip: str
    client: str
    username: str
    started_at: datetime
    temporary: Path | None = None
    destination: Path | None = None
    bytes_transferred: int = 0
    maximum_extent: int = 0
    failed_error: str | None = None
    finished: bool = False


class _PasswordOnlySSHServer(asyncssh.SSHServer):
    """Authenticate one in-memory user and reject every non-SFTP capability."""

    def __init__(self, runtime: "SftpServerRuntime") -> None:
        self._runtime = runtime
        self._connection: Any | None = None
        self._accepted = False
        self._auth_attempts = 0

    def connection_made(self, conn: Any) -> None:
        self._connection = conn
        self._accepted = self._runtime._register_connection(conn)
        if not self._accepted:
            conn.abort()

    def connection_lost(self, exc: Exception | None) -> None:
        if self._accepted and self._connection is not None:
            self._runtime._unregister_connection(self._connection)
        self._connection = None
        self._accepted = False

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return self._accepted and self._auth_attempts < _MAX_AUTH_ATTEMPTS

    def validate_password(self, username: str, password: str) -> bool:
        self._auth_attempts += 1
        valid = self._runtime._password_matches(username, password)
        if not valid and self._auth_attempts >= _MAX_AUTH_ATTEMPTS:
            if self._connection is not None:
                self._connection.abort()
        return self._accepted and valid

    def session_requested(self) -> bool:
        return False

    def connection_requested(
        self, dest_host: str, dest_port: int, orig_host: str, orig_port: int
    ) -> bool:
        return False

    def server_requested(self, listen_host: str, listen_port: int) -> bool:
        return False

    def unix_connection_requested(self, dest_path: str) -> bool:
        return False

    def unix_server_requested(self, listen_path: str) -> bool:
        return False

    def tun_requested(self, unit: int | None) -> bool:
        return False

    def tap_requested(self, unit: int | None) -> bool:
        return False


class _RootedSFTPServer(asyncssh.SFTPServer):
    """SFTP v3 operations backed by a symlink-free fixed server root."""

    def __init__(self, chan: Any, runtime: "SftpServerRuntime") -> None:
        super().__init__(chan)
        self._runtime = runtime
        connection = chan.get_connection()
        self._client_ip, self._client = _client_identity(
            connection.get_extra_info("peername")
        )
        username = connection.get_extra_info("username", "")
        self._username = _safe_text(str(username), limit=64)

    async def open(
        self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs
    ) -> object:
        writing = bool(pflags & asyncssh.FXF_WRITE)
        reading = bool(pflags & asyncssh.FXF_READ) or not writing

        if writing and reading:
            raise _permission_denied("Combined read/write handles are disabled")
        if writing:
            return await self._open_upload(path, pflags)
        return await self._open_download(path)

    async def open56(
        self,
        path: bytes,
        desired_access: int,
        flags: int,
        attrs: asyncssh.SFTPAttrs,
    ) -> object:
        # The listener negotiates SFTP v3, but explicitly reject this entry
        # point as well so a future version change cannot bypass the v3 policy.
        raise asyncssh.SFTPOpUnsupported("Only SFTP version 3 is supported")

    async def _open_download(self, path: bytes) -> _OpenTransfer:
        if not self._runtime._allow_read:
            raise _permission_denied("Downloads are disabled")
        target, display = self._runtime._resolve_path(
            path, allow_root=False, for_write=False
        )
        try:
            info = target.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise asyncssh.SFTPFileIsADirectory("File is not available")
            if info.st_size > self._runtime.max_file_bytes:
                raise asyncssh.SFTPFailure("File exceeds the server size limit")
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(target, flags)
            file_obj = os.fdopen(fd, "rb", buffering=0)
        except FileNotFoundError as exc:
            raise asyncssh.SFTPNoSuchFile("File not found") from exc
        except PermissionError as exc:
            raise _permission_denied("File is not readable") from exc
        except OSError as exc:
            raise asyncssh.SFTPFailure("Could not open file") from exc

        handle = _OpenTransfer(
            id=str(uuid.uuid4()),
            owner=self,
            file=file_obj,
            direction="download",
            filename=display,
            client_ip=self._client_ip,
            client=self._client,
            username=self._username,
            started_at=_utc_now(),
        )
        try:
            await self._runtime._activate_handle(handle)
        except Exception:
            file_obj.close()
            raise
        return handle

    async def _open_upload(self, path: bytes, pflags: int) -> _OpenTransfer:
        if not self._runtime._allow_write:
            raise _permission_denied("Uploads are disabled")
        if pflags & asyncssh.FXF_APPEND:
            raise _permission_denied("Append and resume are disabled")

        destination, display = self._runtime._resolve_path(
            path, allow_root=False, for_write=True
        )
        exists = destination.exists()
        if not exists and not pflags & asyncssh.FXF_CREAT:
            raise asyncssh.SFTPNoSuchFile("File not found")
        if exists and pflags & asyncssh.FXF_EXCL:
            raise asyncssh.SFTPFileAlreadyExists("File already exists")
        if exists and not self._runtime._allow_overwrite:
            raise asyncssh.SFTPFileAlreadyExists("File already exists")
        if exists and not pflags & asyncssh.FXF_TRUNC:
            raise _permission_denied("In-place writes and resume are disabled")

        temporary = destination.parent / f"{_TEMP_PREFIX}{uuid.uuid4().hex}.part"
        try:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temporary, flags, 0o600)
            file_obj = os.fdopen(fd, "w+b", buffering=0)
        except FileExistsError as exc:  # pragma: no cover - UUID collision
            raise asyncssh.SFTPFailure("Could not allocate upload") from exc
        except PermissionError as exc:
            raise _permission_denied("Upload directory is not writable") from exc
        except OSError as exc:
            raise asyncssh.SFTPFailure("Could not allocate upload") from exc

        handle = _OpenTransfer(
            id=str(uuid.uuid4()),
            owner=self,
            file=file_obj,
            direction="upload",
            filename=display,
            client_ip=self._client_ip,
            client=self._client,
            username=self._username,
            started_at=_utc_now(),
            temporary=temporary,
            destination=destination,
        )
        try:
            await self._runtime._activate_handle(handle)
        except Exception:
            file_obj.close()
            temporary.unlink(missing_ok=True)
            raise
        return handle

    async def close(self, file_obj: object) -> None:
        if isinstance(file_obj, _OpenTransfer) and file_obj.finished:
            return
        handle = self._require_handle(file_obj)
        if self.channel.is_closing():
            await self._runtime._finish_handle(
                handle, "cancelled", "SFTP session closed"
            )
        elif handle.failed_error:
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
        else:
            await self._runtime._finish_handle(handle, "completed", None)

    async def read(self, file_obj: object, offset: int, size: int) -> bytes:
        handle = self._require_handle(file_obj, direction="download")
        if offset < 0 or size < 0:
            raise asyncssh.SFTPInvalidParameter("Invalid read range")
        try:
            handle.file.seek(offset)
            data = handle.file.read(size)
            if handle.bytes_transferred + len(data) > self._runtime.max_file_bytes:
                raise asyncssh.SFTPFailure("Transfer exceeds the server size limit")
            handle.bytes_transferred += len(data)
            return data
        except asyncssh.SFTPError:
            handle.failed_error = "Transfer exceeds the server size limit"
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
            raise
        except OSError as exc:
            handle.failed_error = "File read failed"
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
            raise asyncssh.SFTPFailure("File read failed") from exc

    async def write(self, file_obj: object, offset: int, data: bytes) -> int:
        handle = self._require_handle(file_obj, direction="upload")
        if offset < 0:
            raise asyncssh.SFTPInvalidParameter("Invalid write offset")
        new_extent = offset + len(data)
        new_total = handle.bytes_transferred + len(data)
        if (
            new_extent > self._runtime.max_file_bytes
            or new_total > self._runtime.max_file_bytes
        ):
            handle.failed_error = "File exceeds the server size limit"
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
            raise asyncssh.SFTPNoSpaceOnFilesystem(
                "File exceeds the server size limit"
            )
        try:
            handle.file.seek(offset)
            written = handle.file.write(data)
        except OSError as exc:
            handle.failed_error = "File write failed"
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
            raise asyncssh.SFTPFailure("File write failed") from exc
        if written != len(data):
            handle.failed_error = "File write was incomplete"
            await self._runtime._finish_handle(
                handle, "failed", handle.failed_error
            )
            raise asyncssh.SFTPFailure("File write was incomplete")
        handle.bytes_transferred = new_total
        handle.maximum_extent = max(handle.maximum_extent, new_extent)
        return written

    def lstat(self, path: bytes) -> os.stat_result:
        return self._stat_path(path)

    def stat(self, path: bytes) -> os.stat_result:
        return self._stat_path(path)

    def _stat_path(self, path: bytes) -> os.stat_result:
        target, _display = self._runtime._resolve_path(
            path, allow_root=True, for_write=False
        )
        try:
            return target.stat(follow_symlinks=False)
        except FileNotFoundError as exc:
            raise asyncssh.SFTPNoSuchFile("File not found") from exc
        except PermissionError as exc:
            raise _permission_denied() from exc
        except OSError as exc:
            raise asyncssh.SFTPFailure("Could not read file attributes") from exc

    def fstat(self, file_obj: object) -> os.stat_result:
        handle = self._require_handle(file_obj)
        try:
            handle.file.flush()
            return os.fstat(handle.file.fileno())
        except OSError as exc:
            raise asyncssh.SFTPFailure("Could not read file attributes") from exc

    async def scandir(self, path: bytes) -> AsyncIterator[asyncssh.SFTPName]:
        directory, _display = self._runtime._resolve_path(
            path, allow_root=True, for_write=False
        )
        try:
            if not directory.is_dir():
                raise asyncssh.SFTPNotADirectory("Not a directory")
            with os.scandir(directory) as entries:
                visible: list[tuple[bytes, os.stat_result]] = []
                for entry in entries:
                    if entry.is_symlink():
                        continue
                    if entry.name.startswith((_TEMP_PREFIX, _LEGACY_TEMP_PREFIX)):
                        continue
                    try:
                        self._runtime._validate_component(entry.name)
                        entry_stat = entry.stat(follow_symlinks=False)
                    except (OSError, ValueError):
                        continue
                    visible.append((os.fsencode(entry.name), entry_stat))
        except asyncssh.SFTPError:
            raise
        except FileNotFoundError as exc:
            raise asyncssh.SFTPNoSuchFile("Directory not found") from exc
        except PermissionError as exc:
            raise _permission_denied("Directory is not readable") from exc
        except OSError as exc:
            raise asyncssh.SFTPFailure("Could not list directory") from exc

        for filename, entry_stat in sorted(
            visible, key=lambda item: os.fsdecode(item[0]).casefold()
        ):
            yield asyncssh.SFTPName(
                filename, attrs=asyncssh.SFTPAttrs.from_local(entry_stat)
            )

    def realpath(self, path: bytes) -> bytes:
        _target, display = self._runtime._resolve_path(
            path, allow_root=True, for_write=False
        )
        return b"/" if display == "." else b"/" + display.encode("utf-8")

    def setstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        raise _permission_denied("Changing attributes is disabled")

    def lsetstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        raise _permission_denied("Changing attributes is disabled")

    def fsetstat(self, file_obj: object, attrs: asyncssh.SFTPAttrs) -> None:
        raise _permission_denied("Changing attributes is disabled")

    def remove(self, path: bytes) -> None:
        raise _permission_denied("Deleting files is disabled")

    def mkdir(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        raise _permission_denied("Creating directories is disabled")

    def rmdir(self, path: bytes) -> None:
        raise _permission_denied("Deleting directories is disabled")

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        raise _permission_denied("Renaming files is disabled")

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        raise _permission_denied("Renaming files is disabled")

    def readlink(self, path: bytes) -> bytes:
        raise _permission_denied("Links are disabled")

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        raise _permission_denied("Links are disabled")

    def link(self, oldpath: bytes, newpath: bytes) -> None:
        raise _permission_denied("Links are disabled")

    def lock(self, file_obj: object, offset: int, length: int, flags: int) -> None:
        raise _permission_denied("File locking is disabled")

    def unlock(self, file_obj: object, offset: int, length: int) -> None:
        raise _permission_denied("File locking is disabled")

    def statvfs(self, path: bytes) -> object:
        raise _permission_denied("Filesystem statistics are disabled")

    def fstatvfs(self, file_obj: object) -> object:
        raise _permission_denied("Filesystem statistics are disabled")

    def fsync(self, file_obj: object) -> None:
        raise _permission_denied("Explicit filesystem synchronization is disabled")

    @staticmethod
    def _require_handle(
        file_obj: object, *, direction: str | None = None
    ) -> _OpenTransfer:
        if not isinstance(file_obj, _OpenTransfer) or file_obj.finished:
            raise asyncssh.SFTPInvalidHandle("Invalid file handle")
        if direction is not None and file_obj.direction != direction:
            raise _permission_denied()
        return file_obj


class SftpServerRuntime:
    """Own one AsyncSSH listener and all SFTP connections and transfers."""

    def __init__(
        self,
        *,
        root: Path,
        max_file_bytes: int,
        active_transfer_limit: int,
        per_client_transfer_limit: int,
        host_key_path: Path,
        event_callback: RuntimeEventCallback,
    ) -> None:
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        if active_transfer_limit < 1 or per_client_transfer_limit < 1:
            raise ValueError("transfer limits must be positive")

        self._configured_root = Path(root).expanduser()
        self.root = self._configured_root
        self.max_file_bytes = max_file_bytes
        self.active_transfer_limit = active_transfer_limit
        self.per_client_transfer_limit = per_client_transfer_limit
        self.host_key_path = Path(host_key_path).expanduser()
        self._event_callback = event_callback

        self._lifecycle_lock = asyncio.Lock()
        self._handle_lock = asyncio.Lock()
        self._acceptor: Any | None = None
        self._connections: set[Any] = set()
        self._connection_clients: dict[Any, str] = {}
        self._connection_counts: Counter[str] = Counter()
        self._handles: dict[str, _OpenTransfer] = {}
        self._transfer_counts: Counter[str] = Counter()

        self._allowed_networks: tuple[ipaddress.IPv4Network, ...] = ()
        self._allow_read = True
        self._allow_write = False
        self._allow_overwrite = False
        self._username_digest = b""
        self._password_digest = b""

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
        allowed_networks: tuple[ipaddress.IPv4Network, ...],
    ) -> dict[str, object]:
        async with self._lifecycle_lock:
            if self._acceptor is not None:
                raise RuntimeError("The SFTP server is already running")
            self._validate_start(
                bind_address=bind_address,
                port=port,
                username=username,
                password=password,
                allow_read=allow_read,
                allow_write=allow_write,
                allow_overwrite=allow_overwrite,
                allowed_networks=allowed_networks,
            )
            self.root = self._prepare_root()
            host_key = self._load_or_create_host_key()
            fingerprint = host_key.get_fingerprint("sha256")

            self._allowed_networks = tuple(allowed_networks)
            self._allow_read = allow_read
            self._allow_write = allow_write
            self._allow_overwrite = allow_overwrite
            self._username_digest = hashlib.sha256(username.encode("utf-8")).digest()
            self._password_digest = hashlib.sha256(password.encode("utf-8")).digest()

            try:
                acceptor = await asyncssh.create_server(
                    lambda: _PasswordOnlySSHServer(self),
                    bind_address,
                    port,
                    server_host_keys=[host_key],
                    sftp_factory=lambda chan: _RootedSFTPServer(chan, self),
                    sftp_version=3,
                    allow_scp=False,
                    process_factory=None,
                    session_factory=None,
                    password_auth=True,
                    public_key_auth=False,
                    kbdint_auth=False,
                    host_based_auth=False,
                    gss_auth=False,
                    gss_kex=False,
                    gss_host=None,
                    x11_forwarding=False,
                    agent_forwarding=False,
                    rdns_lookup=False,
                    login_timeout=15,
                    server_version="BetterNetworkTools-NetTransfer",
                )
            except Exception:
                self._clear_credentials()
                self._allowed_networks = ()
                raise

            self._acceptor = acceptor
            return {
                "fingerprint": fingerprint,
                "bound_port": int(acceptor.get_port()),
                "host_key_algorithm": "ssh-ed25519",
            }

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            acceptor = self._acceptor
            self._acceptor = None
            if acceptor is not None:
                acceptor.close()

            for handle in list(self._handles.values()):
                await self._finish_handle(handle, "cancelled", "Server stopped")

            connections = list(self._connections)
            for connection in connections:
                connection.close()
            for connection in connections:
                try:
                    await asyncio.wait_for(
                        connection.wait_closed(),
                        timeout=_CONNECTION_CLOSE_TIMEOUT_SECONDS,
                    )
                except (TimeoutError, OSError, RuntimeError):
                    connection.abort()

            if acceptor is not None:
                await acceptor.wait_closed()

            self._connections.clear()
            self._connection_clients.clear()
            self._connection_counts.clear()
            self._transfer_counts.clear()
            self._handles.clear()
            self._allowed_networks = ()
            self._clear_credentials()

    async def shutdown(self) -> None:
        await self.stop()

    def _validate_start(
        self,
        *,
        bind_address: str,
        port: int,
        username: str,
        password: str,
        allow_read: bool,
        allow_write: bool,
        allow_overwrite: bool,
        allowed_networks: tuple[ipaddress.IPv4Network, ...],
    ) -> None:
        try:
            address = ipaddress.IPv4Address(bind_address)
        except ipaddress.AddressValueError as exc:
            raise ValueError("Bind address must be a numeric IPv4 address") from exc
        if address.is_multicast or str(address) == "255.255.255.255":
            raise ValueError("Bind address must be local unicast or 0.0.0.0")
        if not 0 <= port <= 65_535:
            raise ValueError("Port must be between 0 and 65535")
        if not username or len(username) > 64 or any(
            ord(character) < 32 or ord(character) == 127 for character in username
        ):
            raise ValueError("A valid SFTP username is required")
        if not password or len(password) > 128 or "\0" in password:
            raise ValueError("A valid SFTP password is required")
        if not allow_read and not allow_write:
            raise ValueError("Enable downloads, uploads, or both")
        if allow_overwrite and not allow_write:
            raise ValueError("Overwrite requires uploads to be enabled")
        if not all(isinstance(network, ipaddress.IPv4Network) for network in allowed_networks):
            raise ValueError("Allowed client networks must be IPv4 CIDRs")

    def _prepare_root(self) -> Path:
        if self._configured_root.is_symlink():
            raise ValueError("The configured transfer root cannot be a symbolic link")
        try:
            self._configured_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ValueError("Could not create the configured transfer root") from exc
        if not self._configured_root.is_dir() or self._configured_root.is_symlink():
            raise ValueError("The configured transfer root must be a real directory")
        return self._configured_root.resolve(strict=True)

    def _load_or_create_host_key(self) -> Any:
        path = self.host_key_path
        if path.is_symlink():
            raise ValueError("The SFTP host key cannot be a symbolic link")
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        except OSError as exc:
            raise ValueError("Could not create the SFTP host key directory") from exc

        if not path.exists():
            key = asyncssh.generate_private_key("ssh-ed25519")
            payload = key.export_private_key("openssh")
            temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
            try:
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb", buffering=0) as key_file:
                    key_file.write(payload)
                    os.fsync(key_file.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    pass
                except OSError:
                    if not path.exists():
                        os.replace(temporary, path)
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                raise ValueError("Could not persist the SFTP host key") from exc

        if path.is_symlink() or not path.is_file():
            raise ValueError("The SFTP host key must be a regular file")
        try:
            os.chmod(path, 0o600)
            key = asyncssh.read_private_key(path)
        except (OSError, asyncssh.KeyImportError) as exc:
            raise ValueError("Could not read the SFTP host key") from exc
        if key.get_algorithm() != "ssh-ed25519":
            raise ValueError("The SFTP host key must be an Ed25519 private key")
        return key

    def _register_connection(self, connection: Any) -> bool:
        client_ip, _client = _client_identity(connection.get_extra_info("peername"))
        try:
            address = ipaddress.IPv4Address(client_ip)
        except ipaddress.AddressValueError:
            return False
        if address.is_multicast or address.is_unspecified:
            return False
        if not any(address in network for network in self._allowed_networks):
            return False
        if len(self._connections) >= self.active_transfer_limit:
            return False
        if self._connection_counts[client_ip] >= self.per_client_transfer_limit:
            return False
        self._connections.add(connection)
        self._connection_clients[connection] = client_ip
        self._connection_counts[client_ip] += 1
        return True

    def _unregister_connection(self, connection: Any) -> None:
        self._connections.discard(connection)
        client_ip = self._connection_clients.pop(connection, None)
        if client_ip is not None:
            self._connection_counts[client_ip] -= 1
            if self._connection_counts[client_ip] <= 0:
                self._connection_counts.pop(client_ip, None)

    def _password_matches(self, username: str, password: str) -> bool:
        username_digest = hashlib.sha256(username.encode("utf-8")).digest()
        password_digest = hashlib.sha256(password.encode("utf-8")).digest()
        username_valid = secrets.compare_digest(
            username_digest, self._username_digest
        )
        password_valid = secrets.compare_digest(
            password_digest, self._password_digest
        )
        return username_valid and password_valid

    async def _activate_handle(self, handle: _OpenTransfer) -> None:
        async with self._handle_lock:
            if len(self._handles) >= self.active_transfer_limit:
                raise asyncssh.SFTPFailure("Server transfer limit reached")
            if (
                self._transfer_counts[handle.client_ip]
                >= self.per_client_transfer_limit
            ):
                raise asyncssh.SFTPFailure("Client transfer limit reached")
            self._handles[handle.id] = handle
            self._transfer_counts[handle.client_ip] += 1
        self._emit(handle, "active", None)

    async def _finish_handle(
        self, handle: _OpenTransfer, status_name: str, error: str | None
    ) -> None:
        async with self._handle_lock:
            if handle.finished:
                return
            handle.finished = True
            self._handles.pop(handle.id, None)
            self._transfer_counts[handle.client_ip] -= 1
            if self._transfer_counts[handle.client_ip] <= 0:
                self._transfer_counts.pop(handle.client_ip, None)

        terminal_status = status_name
        terminal_error = error
        try:
            handle.file.flush()
            if handle.direction == "upload" and status_name == "completed":
                os.fsync(handle.file.fileno())
            handle.file.close()
            if handle.direction == "upload":
                assert handle.temporary is not None
                assert handle.destination is not None
                if status_name == "completed":
                    info = handle.temporary.stat(follow_symlinks=False)
                    if info.st_size > self.max_file_bytes:
                        raise OSError("upload exceeds size limit")
                    destination, _display = self._resolve_path(
                        handle.filename.encode("utf-8"),
                        allow_root=False,
                        for_write=True,
                    )
                    if destination != handle.destination:
                        raise OSError("upload destination changed")
                    if self._allow_overwrite:
                        os.replace(handle.temporary, handle.destination)
                    else:
                        os.link(handle.temporary, handle.destination)
                        handle.temporary.unlink()
                else:
                    handle.temporary.unlink(missing_ok=True)
        except (OSError, asyncssh.SFTPError):
            if handle.temporary is not None:
                handle.temporary.unlink(missing_ok=True)
            terminal_status = "failed" if status_name != "cancelled" else "cancelled"
            terminal_error = error or "Upload could not be published"

        self._emit(handle, terminal_status, terminal_error)

    def _emit(
        self, handle: _OpenTransfer, status_name: str, error: str | None
    ) -> None:
        event = RuntimeTransferEvent(
            id=handle.id,
            protocol="sftp",
            direction=handle.direction,  # type: ignore[arg-type]
            status=status_name,  # type: ignore[arg-type]
            filename=_safe_text(handle.filename, limit=512),
            client=_safe_text(handle.client, limit=80),
            username=_safe_text(handle.username, limit=64) or None,
            bytes_transferred=max(0, handle.bytes_transferred),
            started_at=handle.started_at,
            finished_at=None if status_name == "active" else _utc_now(),
            error=_safe_text(error, limit=240) if error else None,
        )
        try:
            self._event_callback(event)
        except Exception:
            # Runtime accounting must not be controlled by an observer.
            pass

    def _resolve_path(
        self, path: bytes, *, allow_root: bool, for_write: bool
    ) -> tuple[Path, str]:
        try:
            text = path.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise asyncssh.SFTPInvalidFilename("Filename is not valid UTF-8") from exc
        if len(path) > _MAX_PATH_BYTES or "\0" in text:
            raise asyncssh.SFTPInvalidFilename("Invalid filename")
        if text.startswith("/") and text != "/":
            raise _permission_denied("Absolute paths are disabled")
        if "\\" in text or ":" in text:
            raise asyncssh.SFTPInvalidFilename("Invalid filename")
        if any(ord(character) < 32 or ord(character) == 127 for character in text):
            raise asyncssh.SFTPInvalidFilename("Invalid filename")

        raw_parts = text.split("/")
        if any(part == ".." for part in raw_parts):
            raise _permission_denied("Path traversal is disabled")
        parts = [part for part in raw_parts if part not in {"", "."}]
        if not parts:
            if not allow_root:
                raise _permission_denied("A filename is required")
            return self.root, "."
        for part in parts:
            try:
                self._validate_component(part)
            except ValueError as exc:
                raise asyncssh.SFTPInvalidFilename("Invalid filename") from exc

        current = self.root
        for index, part in enumerate(parts):
            current = current / part
            if current.is_symlink():
                raise _permission_denied("Symbolic links are disabled")
            if index < len(parts) - 1:
                if not current.exists():
                    raise asyncssh.SFTPNoSuchPath("Directory not found")
                if not current.is_dir():
                    raise asyncssh.SFTPNotADirectory("Not a directory")

        if for_write:
            if not current.parent.is_dir() or current.parent.is_symlink():
                raise asyncssh.SFTPNoSuchPath("Upload directory does not exist")
        elif not current.exists():
            raise asyncssh.SFTPNoSuchFile("File not found")

        try:
            current.resolve(strict=not for_write).relative_to(self.root)
        except (FileNotFoundError, ValueError) as exc:
            raise _permission_denied("Path is outside the transfer root") from exc
        return current, "/".join(parts)

    @staticmethod
    def _validate_component(component: str) -> None:
        encoded = component.encode("utf-8")
        if not encoded or len(encoded) > _MAX_COMPONENT_BYTES:
            raise ValueError("Invalid filename component")
        if component.rstrip(" .") != component:
            raise ValueError("Invalid filename component")
        stem = component.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("Invalid filename component")
        if component.startswith((_TEMP_PREFIX, _LEGACY_TEMP_PREFIX)):
            raise ValueError("Reserved filename component")

    def _clear_credentials(self) -> None:
        self._username_digest = b""
        self._password_digest = b""


__all__ = ["SftpServerRuntime"]
