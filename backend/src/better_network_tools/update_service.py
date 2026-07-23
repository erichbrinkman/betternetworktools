"""Safe, release-pinned updater service.

Production trust is rooted in the fixed GitHub repository below.  Browser
requests never provide a URL, ref, command, or filesystem path.  Checking may
fetch Git objects into private refs, but only ``apply`` changes the worktree.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import quote, urlsplit

import httpx

from .update_models import (
    STABLE_RELEASE_TAG_PATTERN,
    UpdateApplyRequest,
    UpdateApplyResponse,
    UpdateCheckResponse,
    UpdateCheckState,
    UpdateInstallKind,
    UpdateOperationResponse,
    UpdateOperationState,
)


DEFAULT_REPOSITORY = "erichbrinkman/betternetworktools"
DEFAULT_BRANCH = "main"
GITHUB_API_VERSION = "2026-03-10"
GITHUB_ACCEPT = "application/vnd.github+json"
MAX_GITHUB_RESPONSE_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
_CANDIDATE_REF = "refs/bnt-updater/candidate"
_MAIN_REF = "refs/bnt-updater/main"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TAG_RE = re.compile(STABLE_RELEASE_TAG_PATTERN)
_REPOSITORY_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9._-]{1,100})$"
)
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_PROTECTED_ROOTS = {
    ".git",
    ".next",
    ".venv",
    ".vinext",
    ".wrangler",
    "coverage",
    "data",
    "htmlcov",
    "node_modules",
    "outputs",
    "scan-results",
    "work",
}
_DEPENDENCY_PATHS = {
    "backend/pyproject.toml",
    "package.json",
    "pnpm-lock.yaml",
}
_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_WINDOWS_INVALID_CHARACTERS = frozenset('<>:"|?*')


class UpdateServiceError(RuntimeError):
    def __init__(self, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def as_detail(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


class UpdateConflictError(UpdateServiceError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, 409)


class UpdatePermissionError(UpdateServiceError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, 403)


class UpdateUpstreamError(UpdateServiceError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, 502)


class UpdateUnavailableError(UpdateServiceError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message, 503)


class UnsafeCandidateError(UpdateConflictError):
    pass


class CommandRunnerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class CommandRunner(Protocol):
    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Run a fixed argument vector without a shell or interactive stdin."""

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process) -> None:
        terminated_tree = False
        try:
            if os.name == "posix" and process.pid is not None:
                os.killpg(process.pid, signal.SIGKILL)
                terminated_tree = True
            elif os.name == "nt" and process.pid is not None:
                system_root = os.environ.get("SystemRoot", r"C:\Windows")
                taskkill_path = Path(system_root) / "System32" / "taskkill.exe"
                taskkill = await asyncio.create_subprocess_exec(
                    str(taskkill_path),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    await asyncio.wait_for(taskkill.wait(), timeout=5.0)
                except TimeoutError:
                    taskkill.kill()
                    await taskkill.wait()
                    raise
                terminated_tree = taskkill.returncode == 0
            if not terminated_tree:
                process.kill()
        except (OSError, ProcessLookupError, PermissionError, TimeoutError):
            try:
                process.kill()
            except ProcessLookupError:
                pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except TimeoutError:
            pass

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> CommandResult:
        creation_options: dict[str, object] = {}
        if os.name == "posix":
            creation_options["start_new_session"] = True
        elif os.name == "nt":
            creation_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=str(cwd),
                env=dict(env),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **creation_options,
            )
        except OSError as exc:
            raise CommandRunnerError("command could not be started") from exc

        assert process.stdout is not None and process.stderr is not None
        total = [0]

        async def read_bounded(stream: asyncio.StreamReader) -> bytes:
            chunks: list[bytes] = []
            while True:
                chunk = await stream.read(64 * 1024)
                if not chunk:
                    return b"".join(chunks)
                total[0] += len(chunk)
                if total[0] > MAX_COMMAND_OUTPUT_BYTES:
                    raise CommandRunnerError("command output exceeded its limit")
                chunks.append(chunk)

        tasks = [
            asyncio.create_task(read_bounded(process.stdout)),
            asyncio.create_task(read_bounded(process.stderr)),
            asyncio.create_task(process.wait()),
        ]
        try:
            stdout, stderr, _returncode = await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=timeout
            )
        except TimeoutError as exc:
            await self._stop_process(process)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise CommandRunnerError("command timed out") from exc
        except CommandRunnerError:
            await self._stop_process(process)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        except asyncio.CancelledError:
            await self._stop_process(process)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

        return CommandResult(process.returncode, stdout, stderr)


@dataclass(frozen=True, slots=True)
class ReleaseInfo:
    tag: str
    version: str
    url: str
    immutable: bool
    tag_commit: str
    main_commit: str


@dataclass(frozen=True, slots=True)
class CheckoutSnapshot:
    commit: str
    branch: str | None
    dirty: bool


def _is_loopback_host(value: str) -> bool:
    candidate = value.strip().strip("[]").lower()
    if candidate == "localhost":
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        return False


def authorize_update_request(
    *,
    api_host: str,
    client_host: str | None,
    origin: str | None,
    allowed_origins: Sequence[str],
    mutation: bool,
) -> None:
    """Require an explicitly configured local origin for update operations."""

    if not _is_loopback_host(api_host) or not client_host or not _is_loopback_host(
        client_host
    ):
        raise UpdatePermissionError(
            "update_requires_loopback", "Updates require the loopback-only local API."
        )
    if not mutation:
        return
    normalized_allowed = {item.rstrip("/") for item in allowed_origins}
    normalized_origin = origin.rstrip("/") if origin else None
    if normalized_origin not in normalized_allowed:
        raise UpdatePermissionError(
            "update_origin_not_allowed",
            "The update request did not come from the configured local interface.",
        )
    parsed = urlsplit(normalized_origin)
    if parsed.scheme != "http" or not parsed.hostname or not _is_loopback_host(
        parsed.hostname
    ):
        raise UpdatePermissionError(
            "update_origin_not_local", "Updates require a local HTTP interface."
        )


def discover_project_root(start: Path | None = None) -> Path | None:
    location = (start or Path(__file__)).resolve()
    candidates = [location] if location.is_dir() else [location.parent]
    candidates.extend(candidates[0].parents)
    for candidate in candidates:
        if (candidate / "package.json").is_file() and (
            candidate / "backend" / "pyproject.toml"
        ).is_file():
            return candidate.resolve()
    return None


class UpdateService:
    def __init__(
        self,
        *,
        project_root: Path | None = None,
        current_version: str = "0.1.0",
        repository: str = DEFAULT_REPOSITORY,
        branch: str = DEFAULT_BRANCH,
        git_executable: str | None = None,
        runner: CommandRunner | None = None,
        http_client: httpx.AsyncClient | None = None,
        check_timeout_seconds: float = 10.0,
        total_check_timeout_seconds: float = 300.0,
        git_timeout_seconds: float = 120.0,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        match = _REPOSITORY_RE.fullmatch(repository)
        if not match:
            raise ValueError("repository must be a GitHub owner/repository slug")
        if (
            not _BRANCH_RE.fullmatch(branch)
            or ".." in branch
            or "//" in branch
            or "@{" in branch
            or branch.endswith("/")
            or branch.endswith(".lock")
        ):
            raise ValueError("branch is not a safe Git ref name")

        self.project_root = (
            project_root.resolve() if project_root else discover_project_root()
        )
        self.current_version = current_version
        self.repository = repository
        self.branch = branch
        self.clone_url = f"https://github.com/{repository}.git"
        self.api_root = f"https://api.github.com/repos/{repository}"
        self.api_url = f"{self.api_root}/releases/latest"
        self.releases_url = f"https://github.com/{repository}/releases"
        self.git_executable = git_executable or shutil.which("git")
        self.runner = runner or SubprocessRunner()
        self.check_timeout_seconds = check_timeout_seconds
        self.total_check_timeout_seconds = total_check_timeout_seconds
        self.git_timeout_seconds = git_timeout_seconds
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._owns_http_client = http_client is None
        self.http_client = http_client
        self._git_lock = asyncio.Lock()
        self._apply_lock = asyncio.Lock()
        self._operation = UpdateOperationResponse(
            message="No update installation is running."
        )

    async def shutdown(self) -> None:
        if self._owns_http_client and self.http_client is not None:
            await self.http_client.aclose()

    def operation_status(self) -> UpdateOperationResponse:
        """Return a snapshot clients can use after navigation or disconnection."""

        return self._operation.model_copy(deep=True)

    async def check(self) -> UpdateCheckResponse:
        if self._git_lock.locked():
            raise UpdateConflictError(
                "update_operation_in_progress",
                "Another update operation is already in progress.",
            )
        async with self._git_lock:
            try:
                async with asyncio.timeout(self.total_check_timeout_seconds):
                    return await self._check_serialized()
            except TimeoutError as exc:
                raise UpdateUnavailableError(
                    "update_check_timed_out",
                    "The update check exceeded its total safety deadline.",
                ) from exc

    async def _check_serialized(self) -> UpdateCheckResponse:
        if self._operation.state is UpdateOperationState.FAILED:
            self._operation = UpdateOperationResponse(
                message="No update installation is running."
            )
        checked_at = self._now()
        install_kind = await self._install_kind()
        release = await self._latest_release()
        if release is None:
            return UpdateCheckResponse(
                state=UpdateCheckState.UNCONFIGURED,
                install_kind=install_kind,
                current_version=self.current_version,
                release_url=self.releases_url,
                reason="no_stable_release",
                message="No stable GitHub release is published yet.",
                checked_at=checked_at,
            )

        if not release.immutable:
            return UpdateCheckResponse(
                state=UpdateCheckState.BLOCKED,
                install_kind=install_kind,
                current_version=self.current_version,
                latest_version=release.version,
                release_tag=release.tag,
                release_url=release.url,
                reason="mutable_release",
                message=(
                    "The latest GitHub release is still mutable. Enable immutable "
                    "releases before installing it."
                ),
                checked_at=checked_at,
            )

        if install_kind is not UpdateInstallKind.GIT_CHECKOUT:
            return UpdateCheckResponse(
                state=UpdateCheckState.MANUAL_UPDATE_REQUIRED,
                install_kind=install_kind,
                current_version=self.current_version,
                latest_version=release.version,
                release_tag=release.tag,
                release_url=release.url,
                reason="non_git_install",
                message=(
                    "This installation cannot be replaced safely in place; "
                    "install the latest release manually."
                ),
                checked_at=checked_at,
            )

        snapshot = await self._snapshot()
        if snapshot.branch != self.branch:
            return self._blocked_response(
                snapshot,
                release,
                checked_at,
                "wrong_branch",
                f"Switch to the clean {self.branch} branch before updating.",
            )

        candidate, official_main = await self._fetch_release(release)
        try:
            if not await self._is_ancestor(candidate, official_main):
                raise UnsafeCandidateError(
                    "release_not_on_main",
                    "The latest release is not reachable from the official main branch.",
                )
            bootstrap_required = await self._preflight_candidate(
                snapshot.commit, candidate
            )
        except UnsafeCandidateError as exc:
            return self._blocked_response(
                snapshot,
                release,
                checked_at,
                exc.code,
                exc.message,
                candidate=candidate,
            )

        if snapshot.commit == candidate:
            return UpdateCheckResponse(
                state=UpdateCheckState.UP_TO_DATE,
                install_kind=UpdateInstallKind.GIT_CHECKOUT,
                current_version=self.current_version,
                current_commit=snapshot.commit,
                latest_version=release.version,
                candidate_commit=candidate,
                release_tag=release.tag,
                release_url=release.url,
                dirty=snapshot.dirty,
                reason="local_changes" if snapshot.dirty else None,
                message=(
                    "The latest release is installed; local changes are present."
                    if snapshot.dirty
                    else "Better Network Tools is up to date."
                ),
                checked_at=checked_at,
            )

        if not await self._is_ancestor(snapshot.commit, candidate):
            reason = (
                "checkout_ahead"
                if await self._is_ancestor(candidate, snapshot.commit)
                else "history_diverged"
            )
            return self._blocked_response(
                snapshot,
                release,
                checked_at,
                reason,
                "The local checkout cannot be fast-forwarded to the latest release.",
                candidate=candidate,
            )
        if snapshot.dirty:
            return self._blocked_response(
                snapshot,
                release,
                checked_at,
                "local_changes",
                "Commit, move, or remove local changes before updating.",
                candidate=candidate,
                bootstrap_required=bootstrap_required,
            )
        return UpdateCheckResponse(
            state=UpdateCheckState.AVAILABLE,
            install_kind=UpdateInstallKind.GIT_CHECKOUT,
            current_version=self.current_version,
            current_commit=snapshot.commit,
            latest_version=release.version,
            candidate_commit=candidate,
            release_tag=release.tag,
            release_url=release.url,
            can_apply=True,
            bootstrap_required=bootstrap_required,
            message=f"Better Network Tools {release.version} is available.",
            checked_at=checked_at,
        )

    async def apply(self, request: UpdateApplyRequest) -> UpdateApplyResponse:
        if self._apply_lock.locked() or self._git_lock.locked():
            raise UpdateConflictError(
                "update_in_progress", "Another update is already in progress."
            )
        async with self._apply_lock:
            async with self._git_lock:
                return await self._apply_serialized(request)

    async def _apply_serialized(
        self, request: UpdateApplyRequest
    ) -> UpdateApplyResponse:
        started_at = self._now()
        self._operation = UpdateOperationResponse(
            state=UpdateOperationState.APPLYING,
            release_tag=request.expected_release_tag,
            release_url=(
                f"{self.releases_url}/tag/"
                f"{quote(request.expected_release_tag, safe='')}"
            ),
            message=(
                f"Installing {request.expected_release_tag} from the official "
                "GitHub release."
            ),
            started_at=started_at,
        )
        try:
            response = await self._apply_confirmed(request)
        except UpdateServiceError as exc:
            self._operation = UpdateOperationResponse(
                state=UpdateOperationState.FAILED,
                release_tag=request.expected_release_tag,
                release_url=(
                    f"{self.releases_url}/tag/"
                    f"{quote(request.expected_release_tag, safe='')}"
                ),
                message=exc.message,
                started_at=started_at,
                finished_at=self._now(),
            )
            raise
        except asyncio.CancelledError:
            self._operation = UpdateOperationResponse(
                state=UpdateOperationState.FAILED,
                release_tag=request.expected_release_tag,
                release_url=(
                    f"{self.releases_url}/tag/"
                    f"{quote(request.expected_release_tag, safe='')}"
                ),
                message=(
                    "The update request was interrupted. Check for updates "
                    "again before retrying."
                ),
                started_at=started_at,
                finished_at=self._now(),
            )
            raise
        except Exception:
            self._operation = UpdateOperationResponse(
                state=UpdateOperationState.FAILED,
                release_tag=request.expected_release_tag,
                release_url=(
                    f"{self.releases_url}/tag/"
                    f"{quote(request.expected_release_tag, safe='')}"
                ),
                message=(
                    "The update stopped unexpectedly. Check for updates "
                    "again before retrying."
                ),
                started_at=started_at,
                finished_at=self._now(),
            )
            raise

        self._operation = UpdateOperationResponse(
            state=UpdateOperationState.UPDATED,
            release_tag=response.release_tag,
            release_url=response.release_url,
            applied_commit=response.applied_commit,
            restart_required=response.restart_required,
            bootstrap_required=response.bootstrap_required,
            message=response.message,
            started_at=started_at,
            finished_at=self._now(),
        )
        return response

    async def _apply_confirmed(
        self, request: UpdateApplyRequest
    ) -> UpdateApplyResponse:
        if await self._install_kind() is not UpdateInstallKind.GIT_CHECKOUT:
            raise UpdateConflictError(
                "manual_update_required",
                "This installation must be updated manually.",
            )
        before = await self._snapshot()
        if before.branch != self.branch:
            raise UpdateConflictError(
                "wrong_branch", f"Updates require the {self.branch} branch."
            )
        if before.dirty:
            raise UpdateConflictError(
                "local_changes", "The worktree changed after the update check."
            )
        if before.commit != request.expected_current_commit:
            raise UpdateConflictError(
                "current_commit_changed",
                "The checkout changed after the update check; check again.",
            )

        release = await self._latest_release()
        if (
            release is None
            or not release.immutable
            or release.tag != request.expected_release_tag
        ):
            raise UpdateConflictError(
                "release_changed",
                "The latest release changed after the update check; check again.",
            )
        candidate, official_main = await self._fetch_release(release)
        if candidate != request.expected_candidate_commit:
            raise UpdateConflictError(
                "candidate_changed",
                "The release commit changed after the update check; check again.",
            )

        after_fetch = await self._snapshot()
        if (
            after_fetch.commit != request.expected_current_commit
            or after_fetch.branch != self.branch
            or after_fetch.dirty
        ):
            raise UpdateConflictError(
                "checkout_changed",
                "The checkout changed while the release was fetched; check again.",
            )
        if not await self._is_ancestor(candidate, official_main):
            raise UnsafeCandidateError(
                "release_not_on_main",
                "The release is not reachable from the official main branch.",
            )
        if not await self._is_ancestor(after_fetch.commit, candidate):
            raise UpdateConflictError(
                "non_fast_forward",
                "The update is not a clean fast-forward.",
            )
        bootstrap_required = await self._preflight_candidate(
            after_fetch.commit, candidate
        )

        # Recheck after the complete preflight and immediately before Git is
        # permitted to touch the working tree.
        ready = await self._snapshot()
        if (
            ready.commit != after_fetch.commit
            or ready.branch != self.branch
            or ready.dirty
        ):
            raise UpdateConflictError(
                "checkout_changed",
                "The checkout changed during update validation; check again.",
            )
        self._require_safe_repository_metadata()
        result = await self._git_result(
            "merge",
            "--ff-only",
            "--no-edit",
            "--no-overwrite-ignore",
            candidate,
            extra_config=("merge.autoStash=false",),
        )
        if result.returncode != 0:
            raise UpdateConflictError(
                "fast_forward_failed",
                "Git could not fast-forward the checkout; no reset or stash was attempted.",
            )
        applied = await self._snapshot()
        if (
            applied.commit != candidate
            or applied.branch != self.branch
            or applied.dirty
        ):
            raise UpdateUnavailableError(
                "update_verification_failed",
                "The updated checkout could not be verified.",
            )
        return UpdateApplyResponse(
            previous_commit=before.commit,
            applied_commit=applied.commit,
            applied_version=release.version,
            release_tag=release.tag,
            release_url=release.url,
            bootstrap_required=bootstrap_required,
            message=(
                "Update applied. Restart Better Network Tools and rerun "
                "scripts/bootstrap.py if dependencies changed."
                if bootstrap_required
                else "Update applied. Restart Better Network Tools."
            ),
        )

    def _blocked_response(
        self,
        snapshot: CheckoutSnapshot,
        release: ReleaseInfo,
        checked_at: datetime,
        reason: str,
        message: str,
        *,
        candidate: str | None = None,
        bootstrap_required: bool = False,
    ) -> UpdateCheckResponse:
        return UpdateCheckResponse(
            state=UpdateCheckState.BLOCKED,
            install_kind=UpdateInstallKind.GIT_CHECKOUT,
            current_version=self.current_version,
            current_commit=snapshot.commit,
            latest_version=release.version,
            candidate_commit=candidate,
            release_tag=release.tag,
            release_url=release.url,
            dirty=snapshot.dirty,
            bootstrap_required=bootstrap_required,
            reason=reason,
            message=message,
            checked_at=checked_at,
        )

    async def _install_kind(self) -> UpdateInstallKind:
        root = self.project_root
        if root is None or not (root / "package.json").is_file() or not (
            root / "backend" / "pyproject.toml"
        ).is_file():
            return UpdateInstallKind.PACKAGED
        if not self.git_executable:
            return UpdateInstallKind.SOURCE_ARCHIVE
        if not self._repository_metadata_is_safe():
            return UpdateInstallKind.SOURCE_ARCHIVE
        result = await self._git_result("rev-parse", "--show-toplevel")
        if result.returncode != 0:
            return UpdateInstallKind.SOURCE_ARCHIVE
        try:
            top = Path(result.stdout.decode("utf-8").strip()).resolve()
        except (UnicodeDecodeError, OSError):
            return UpdateInstallKind.SOURCE_ARCHIVE
        return (
            UpdateInstallKind.GIT_CHECKOUT
            if top == root
            else UpdateInstallKind.SOURCE_ARCHIVE
        )

    def _repository_metadata_is_safe(self) -> bool:
        if self.project_root is None:
            return False
        git_directory = self.project_root / ".git"
        if git_directory.is_symlink() or not git_directory.is_dir():
            return False
        for relative in (
            "info/attributes",
            "info/grafts",
            "info/sparse-checkout",
        ):
            if os.path.lexists(git_directory / relative):
                return False
        return True

    def _require_safe_repository_metadata(self) -> None:
        if not self._repository_metadata_is_safe():
            raise UpdateConflictError(
                "unsupported_git_metadata",
                "The checkout uses Git metadata that the updater cannot safely apply.",
            )

    async def _github_json(
        self, url: str, *, allow_not_found: bool = False
    ) -> dict[str, object] | None:
        if self.http_client is None:
            self.http_client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=httpx.Timeout(self.check_timeout_seconds),
                trust_env=False,
            )
        headers = {
            "Accept": GITHUB_ACCEPT,
            "User-Agent": "better-network-tools-updater",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        try:
            async with self.http_client.stream(
                "GET", url, headers=headers
            ) as response:
                if response.status_code == 404 and allow_not_found:
                    return None
                if response.status_code != 200:
                    raise UpdateUpstreamError(
                        "github_api_unavailable",
                        "GitHub could not provide the trusted release metadata.",
                    )
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_GITHUB_RESPONSE_BYTES:
                        raise UpdateUpstreamError(
                            "github_response_too_large",
                            "GitHub returned an unexpectedly large API response.",
                        )
                    chunks.append(chunk)
        except UpdateServiceError:
            raise
        except (httpx.HTTPError, TimeoutError) as exc:
            raise UpdateUpstreamError(
                "github_request_failed", "The GitHub release check failed."
            ) from exc

        try:
            payload = json.loads(b"".join(chunks).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as exc:
            raise UpdateUpstreamError(
                "invalid_github_response", "GitHub returned an invalid API response."
            ) from exc
        if not isinstance(payload, dict):
            raise UpdateUpstreamError(
                "invalid_github_response", "GitHub returned an invalid API response."
            )
        return payload

    @staticmethod
    def _github_object(payload: object) -> tuple[str, str]:
        if not isinstance(payload, dict):
            raise UpdateUpstreamError(
                "invalid_github_ref", "GitHub returned an invalid Git reference."
            )
        object_type = payload.get("type")
        sha = payload.get("sha")
        if (
            object_type not in {"commit", "tag"}
            or not isinstance(sha, str)
            or not _SHA_RE.fullmatch(sha)
        ):
            raise UpdateUpstreamError(
                "invalid_github_ref", "GitHub returned an invalid Git reference."
            )
        return object_type, sha

    async def _peel_github_ref(self, payload: dict[str, object]) -> str:
        object_type, sha = self._github_object(payload.get("object"))
        seen: set[str] = set()
        for _depth in range(5):
            if object_type == "commit":
                return sha
            if sha in seen:
                break
            seen.add(sha)
            tag_payload = await self._github_json(
                f"{self.api_root}/git/tags/{sha}"
            )
            assert tag_payload is not None
            object_type, sha = self._github_object(tag_payload.get("object"))
        raise UpdateUpstreamError(
            "invalid_github_tag", "GitHub returned an invalid annotated tag chain."
        )

    async def _latest_release(self) -> ReleaseInfo | None:
        payload = await self._github_json(self.api_url, allow_not_found=True)
        if payload is None:
            return None
        try:
            tag = payload["tag_name"]
            draft = payload.get("draft", False)
            prerelease = payload.get("prerelease", False)
            immutable = payload.get("immutable", False)
        except KeyError as exc:
            raise UpdateUpstreamError(
                "invalid_github_release", "GitHub returned an invalid release record."
            ) from exc
        if not isinstance(tag, str) or not _TAG_RE.fullmatch(tag) or draft or prerelease:
            raise UpdateUpstreamError(
                "invalid_github_release",
                "The latest release does not use a stable vMAJOR.MINOR.PATCH tag.",
            )
        tag_ref = await self._github_json(
            f"{self.api_root}/git/ref/tags/{quote(tag, safe='')}"
        )
        main_ref = await self._github_json(
            f"{self.api_root}/git/ref/heads/{quote(self.branch, safe='')}"
        )
        assert tag_ref is not None and main_ref is not None
        tag_commit = await self._peel_github_ref(tag_ref)
        main_type, main_commit = self._github_object(main_ref.get("object"))
        if main_type != "commit":
            raise UpdateUpstreamError(
                "invalid_github_ref", "GitHub returned an invalid main branch reference."
            )
        return ReleaseInfo(
            tag=tag,
            version=tag[1:],
            url=(
                f"https://github.com/{self.repository}/releases/tag/"
                f"{quote(tag, safe='')}"
            ),
            immutable=immutable is True,
            tag_commit=tag_commit,
            main_commit=main_commit,
        )

    async def _snapshot(self) -> CheckoutSnapshot:
        self._require_safe_repository_metadata()
        head = self._parse_sha(
            (await self._require_git("rev-parse", "HEAD")).stdout
        )
        branch_result = await self._git_result(
            "symbolic-ref", "--quiet", "--short", "HEAD"
        )
        if branch_result.returncode not in (0, 1):
            raise UpdateUnavailableError(
                "git_inspection_failed", "Git could not inspect the current branch."
            )
        branch = (
            branch_result.stdout.decode("utf-8", "strict").strip()
            if branch_result.returncode == 0
            else None
        )
        status = await self._require_git(
            "status", "--porcelain=v1", "-z", "--untracked-files=all"
        )
        index_flags = await self._require_git("ls-files", "-v", "-z", "--")
        for record in index_flags.stdout.split(b"\0"):
            if record and (record[:1] == b"S" or record[:1].islower()):
                raise UpdateConflictError(
                    "unsupported_index_state",
                    "Disable sparse-checkout and assume-unchanged index flags before updating.",
                )
        return CheckoutSnapshot(head, branch, bool(status.stdout))

    async def _fetch_release(self, release: ReleaseInfo) -> tuple[str, str]:
        # Network transport runs in a new bare repository so the checkout's
        # .git/config cannot rewrite GitHub URLs or invoke credential helpers.
        # GitHub's separately authenticated API pins both commits first.
        with tempfile.TemporaryDirectory(prefix="bnt-update-fetch-") as temporary:
            temporary_root = Path(temporary)
            bare_repository = temporary_root / "repository.git"
            bundle_path = temporary_root / "release.bundle"
            bare_repository.mkdir(mode=0o700)

            initialized = await self._git_result_at(
                bare_repository, "init", "--bare"
            )
            if initialized.returncode != 0:
                raise UpdateUnavailableError(
                    "git_staging_failed", "Git could not create an isolated fetch area."
                )
            fetched = await self._git_result_at(
                bare_repository,
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--no-write-fetch-head",
                self.clone_url,
                f"+{release.tag_commit}:{_CANDIDATE_REF}",
                f"+{release.main_commit}:{_MAIN_REF}",
            )
            if fetched.returncode != 0:
                raise UpdateUpstreamError(
                    "github_fetch_failed",
                    "Git could not fetch the pinned stable GitHub release.",
                )
            candidate = self._parse_sha(
                (
                    await self._require_git_at(
                        bare_repository,
                        "rev-parse",
                        f"{_CANDIDATE_REF}^{{commit}}",
                    )
                ).stdout
            )
            official_main = self._parse_sha(
                (
                    await self._require_git_at(
                        bare_repository, "rev-parse", f"{_MAIN_REF}^{{commit}}"
                    )
                ).stdout
            )
            if (
                candidate != release.tag_commit
                or official_main != release.main_commit
            ):
                raise UpdateUpstreamError(
                    "github_ref_mismatch",
                    "The fetched Git objects did not match GitHub's pinned references.",
                )
            bundled = await self._git_result_at(
                bare_repository,
                "bundle",
                "create",
                str(bundle_path),
                _CANDIDATE_REF,
                _MAIN_REF,
            )
            if bundled.returncode != 0:
                raise UpdateUnavailableError(
                    "git_staging_failed", "Git could not stage the verified update."
                )
            imported = await self._git_result("bundle", "unbundle", str(bundle_path))
            if imported.returncode != 0:
                raise UpdateUnavailableError(
                    "git_import_failed", "Git could not import the verified update."
                )
            await self._require_git("cat-file", "-e", f"{candidate}^{{commit}}")
            await self._require_git("cat-file", "-e", f"{official_main}^{{commit}}")
            return candidate, official_main

    async def _preflight_candidate(self, current: str, candidate: str) -> bool:
        tree = await self._require_git("ls-tree", "-r", "-z", candidate, "--")
        normalized_paths: set[str] = set()
        for record in tree.stdout.split(b"\0"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, _object_id = metadata.split(b" ", 2)
                path = raw_path.decode("utf-8", "strict")
            except (ValueError, UnicodeDecodeError) as exc:
                raise UnsafeCandidateError(
                    "unsafe_release_tree", "The release contains an unsafe tree entry."
                ) from exc
            if mode in {b"120000", b"160000"} or object_type != b"blob":
                raise UnsafeCandidateError(
                    "unsupported_tree_entry",
                    "The release contains a symlink, gitlink, or unsupported file type.",
                )
            if mode not in {b"100644", b"100755"}:
                raise UnsafeCandidateError(
                    "unsupported_file_mode",
                    "The release contains an unsupported file mode.",
                )
            self._validate_tree_path(path)
            normalized_path = unicodedata.normalize("NFC", path).casefold()
            if normalized_path in normalized_paths:
                raise UnsafeCandidateError(
                    "colliding_release_paths",
                    "The release contains paths that collide on macOS or Windows.",
                )
            normalized_paths.add(normalized_path)

        added = await self._require_git(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--diff-filter=A",
            "--name-only",
            "-z",
            "--no-renames",
            current,
            candidate,
            "--",
        )
        for path in self._decode_paths(added.stdout):
            self._validate_tree_path(path)
            assert self.project_root is not None
            target = self.project_root.joinpath(*PurePosixPath(path).parts)
            if os.path.lexists(target):
                raise UnsafeCandidateError(
                    "local_path_collision",
                    "The release would replace an untracked or ignored local path.",
                )

        changed = await self._require_git(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            "--no-renames",
            current,
            candidate,
            "--",
        )
        changed_paths = set(self._decode_paths(changed.stdout))
        return bool(changed_paths & _DEPENDENCY_PATHS)

    def _validate_tree_path(self, path: str) -> None:
        pure = PurePosixPath(path)
        parts = pure.parts
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or len(path.encode("utf-8")) > 240
            or any(part in {"", ".", ".."} for part in parts)
            or any(any(ord(char) < 32 or ord(char) == 127 for char in part) for part in parts)
            or any(
                len(part.encode("utf-8")) > 255
                or part.endswith((" ", "."))
                or any(char in _WINDOWS_INVALID_CHARACTERS for char in part)
                or unicodedata.normalize("NFKC", part)
                .split(".", 1)[0]
                .casefold()
                in _WINDOWS_RESERVED_NAMES
                for part in parts
            )
        ):
            raise UnsafeCandidateError(
                "unsafe_release_path", "The release contains an unsafe path."
            )
        folded = tuple(part.casefold() for part in parts)
        if (
            folded[0] in _PROTECTED_ROOTS
            or ".git" in folded
            or any(
                part
                in {".gitattributes", ".gitconfig", ".gitmodules", ".lfsconfig"}
                for part in folded
            )
            or (
                path.casefold() != ".env.example"
                and any(part.startswith(".env") for part in folded)
            )
        ):
            raise UnsafeCandidateError(
                "protected_release_path",
                "The release attempts to modify a protected local path.",
            )
        assert self.project_root is not None
        try:
            resolved = self.project_root.joinpath(*parts).resolve(strict=False)
            resolved.relative_to(self.project_root)
        except (OSError, ValueError) as exc:
            raise UnsafeCandidateError(
                "release_path_escape", "The release path escapes the project root."
            ) from exc

    @staticmethod
    def _decode_paths(payload: bytes) -> list[str]:
        try:
            return [item.decode("utf-8", "strict") for item in payload.split(b"\0") if item]
        except UnicodeDecodeError as exc:
            raise UnsafeCandidateError(
                "unsafe_release_path", "The release contains a non-UTF-8 path."
            ) from exc

    async def _is_ancestor(self, older: str, newer: str) -> bool:
        result = await self._git_result("merge-base", "--is-ancestor", older, newer)
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise UpdateUnavailableError(
            "git_history_failed", "Git could not verify the update history."
        )

    async def _require_git(self, *args: str) -> CommandResult:
        result = await self._git_result(*args)
        if result.returncode != 0:
            raise UpdateUnavailableError(
                "git_inspection_failed", "Git could not inspect the local checkout."
            )
        return result

    async def _require_git_at(self, root: Path, *args: str) -> CommandResult:
        result = await self._git_result_at(root, *args)
        if result.returncode != 0:
            raise UpdateUnavailableError(
                "git_inspection_failed", "Git could not inspect the staged update."
            )
        return result

    async def _git_result(
        self, *args: str, extra_config: Sequence[str] = ()
    ) -> CommandResult:
        if not self.git_executable or self.project_root is None:
            return CommandResult(127, b"", b"")
        return await self._git_result_at(
            self.project_root,
            *args,
            extra_config=(
                "core.bare=false",
                f"core.worktree={self.project_root}",
                *extra_config,
            ),
        )

    async def _git_result_at(
        self, root: Path, *args: str, extra_config: Sequence[str] = ()
    ) -> CommandResult:
        if not self.git_executable:
            return CommandResult(127, b"", b"")
        config = [
            "protocol.allow=never",
            "protocol.https.allow=always",
            "protocol.file.allow=never",
            "protocol.ext.allow=never",
            "submodule.recurse=false",
            "fetch.recurseSubmodules=false",
            "credential.helper=",
            "credential.interactive=false",
            "core.askPass=",
            "core.fsmonitor=false",
            f"core.attributesFile={os.devnull}",
            f"core.excludesFile={os.devnull}",
            "core.protectHFS=true",
            "core.protectNTFS=true",
            "core.sparseCheckout=false",
            "core.sparseCheckoutCone=false",
            "index.sparse=false",
            "gc.auto=0",
            "maintenance.auto=false",
            "merge.autoStash=false",
            "transfer.fsckObjects=true",
            "fetch.fsckObjects=true",
            *extra_config,
        ]
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.upper().startswith(("GIT_", "DYLD_"))
            and key.upper()
            not in {
                "ALL_PROXY",
                "BASH_ENV",
                "CURL_CA_BUNDLE",
                "ENV",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "LD_LIBRARY_PATH",
                "LD_PRELOAD",
                "NO_PROXY",
                "SSL_CERT_DIR",
                "SSL_CERT_FILE",
                "SSH_ASKPASS",
            }
        }
        env.update(
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_LFS_SKIP_SMUDGE": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_PAGER": "",
                "GIT_TERMINAL_PROMPT": "0",
                "GCM_INTERACTIVE": "Never",
                "LC_ALL": "C",
            }
        )
        with tempfile.TemporaryDirectory(prefix="bnt-empty-hooks-") as hooks:
            argv = [self.git_executable, "--no-replace-objects"]
            for item in [*config, f"core.hooksPath={hooks}"]:
                argv.extend(("-c", item))
            argv.extend(("-C", str(root), *args))
            try:
                return await self.runner.run(
                    argv,
                    cwd=root,
                    env=env,
                    timeout=self.git_timeout_seconds,
                )
            except CommandRunnerError as exc:
                raise UpdateUnavailableError(
                    "git_command_failed", "A bounded Git command failed."
                ) from exc

    @staticmethod
    def _parse_sha(payload: bytes) -> str:
        try:
            value = payload.decode("ascii", "strict").strip()
        except UnicodeDecodeError as exc:
            raise UpdateUnavailableError(
                "invalid_git_commit", "Git returned an invalid commit identifier."
            ) from exc
        if not _SHA_RE.fullmatch(value):
            raise UpdateUnavailableError(
                "invalid_git_commit", "Git returned an invalid commit identifier."
            )
        return value
