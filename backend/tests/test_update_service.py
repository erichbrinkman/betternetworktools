from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence

import httpx
import pytest

from better_network_tools.update_models import (
    UpdateApplyRequest,
    UpdateCheckState,
    UpdateOperationState,
)
from better_network_tools.update_service import (
    CommandResult,
    CommandRunnerError,
    SubprocessRunner,
    UpdateConflictError,
    UpdatePermissionError,
    UpdateService,
    UpdateUpstreamError,
    UpdateUnavailableError,
    authorize_update_request,
)


LOCAL_COMMIT = "1" * 40
CANDIDATE_COMMIT = "2" * 40
MAIN_COMMIT = "3" * 40
GIT_EXECUTABLE = shutil.which("git")


def run_git(root: Path, *args: str) -> str:
    assert GIT_EXECUTABLE is not None
    result = subprocess.run(
        [GIT_EXECUTABLE, "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class FakeGitRunner:
    def __init__(
        self,
        *,
        dirty: bool = False,
        unsafe_mode: bytes | None = None,
        tree_path: bytes = b"README.md",
        changed_path: bytes = b"README.md",
        added_path: bytes | None = None,
        dirty_status_call: int | None = None,
    ) -> None:
        self.commit = LOCAL_COMMIT
        self.dirty = dirty
        self.unsafe_mode = unsafe_mode
        self.tree_path = tree_path
        self.changed_path = changed_path
        self.added_path = added_path
        self.dirty_status_call = dirty_status_call
        self.status_calls = 0
        self.commands: list[tuple[str, ...]] = []
        self.argvs: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self.working_directories: list[Path] = []

    async def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> CommandResult:
        del timeout
        command = tuple(argv[argv.index("-C") + 2 :])
        self.commands.append(command)
        self.argvs.append(tuple(argv))
        self.environments.append(dict(env))
        self.working_directories.append(cwd)

        if command == ("init", "--bare"):
            return CommandResult(0, b"", b"")
        if command == ("rev-parse", "--show-toplevel"):
            return CommandResult(0, b"__PROJECT_ROOT__\n", b"")
        if command == ("rev-parse", "HEAD"):
            return CommandResult(0, f"{self.commit}\n".encode(), b"")
        if command == ("symbolic-ref", "--quiet", "--short", "HEAD"):
            return CommandResult(0, b"main\n", b"")
        if command == (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ):
            self.status_calls += 1
            dirty = self.dirty or self.status_calls == self.dirty_status_call
            return CommandResult(0, b" M README.md\0" if dirty else b"", b"")
        if command == ("ls-files", "-v", "-z", "--"):
            return CommandResult(0, b"H README.md\0", b"")
        if command and command[0] == "fetch":
            return CommandResult(0, b"", b"")
        if command[:2] == ("bundle", "create"):
            return CommandResult(0, b"", b"")
        if command[:2] == ("bundle", "unbundle"):
            return CommandResult(0, b"", b"")
        if command[:2] == ("cat-file", "-e"):
            return CommandResult(0, b"", b"")
        if command == (
            "rev-parse",
            "refs/bnt-updater/candidate^{commit}",
        ):
            return CommandResult(0, f"{CANDIDATE_COMMIT}\n".encode(), b"")
        if command == ("rev-parse", "refs/bnt-updater/main^{commit}"):
            return CommandResult(0, f"{MAIN_COMMIT}\n".encode(), b"")
        if command[:2] == ("merge-base", "--is-ancestor"):
            older, newer = command[2], command[3]
            is_ancestor = (older, newer) in {
                (LOCAL_COMMIT, CANDIDATE_COMMIT),
                (CANDIDATE_COMMIT, MAIN_COMMIT),
            }
            if self.commit == CANDIDATE_COMMIT and older == newer == CANDIDATE_COMMIT:
                is_ancestor = True
            return CommandResult(0 if is_ancestor else 1, b"", b"")
        if command == ("ls-tree", "-r", "-z", CANDIDATE_COMMIT, "--"):
            mode = self.unsafe_mode or b"100644"
            object_type = b"blob" if mode != b"160000" else b"commit"
            tree = (
                mode
                + b" "
                + object_type
                + b" "
                + b"a" * 40
                + b"\t"
                + self.tree_path
                + b"\0"
            )
            return CommandResult(0, tree, b"")
        if command and command[0] == "diff" and "--diff-filter=A" in command:
            added = self.added_path + b"\0" if self.added_path else b""
            return CommandResult(0, added, b"")
        if command and command[0] == "diff":
            return CommandResult(0, self.changed_path + b"\0", b"")
        if command and command[0] == "merge":
            self.commit = CANDIDATE_COMMIT
            return CommandResult(0, b"", b"")
        raise AssertionError(f"unexpected Git command: {command!r}")


def release_client(
    *,
    immutable: bool = True,
    status_code: int = 200,
    tag_commit: str = CANDIDATE_COMMIT,
    main_commit: str = MAIN_COMMIT,
    annotated_tag: bool = False,
) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-github-api-version"] == "2026-03-10"
        if request.url.path.endswith("/releases/latest") and status_code != 200:
            return httpx.Response(status_code, request=request)
        if request.url.path.endswith("/releases/latest"):
            payload: object = {
                "tag_name": "v0.2.0",
                "draft": False,
                "prerelease": False,
                "immutable": immutable,
            }
        elif request.url.path.endswith("/git/ref/tags/v0.2.0"):
            payload = {
                "object": {
                    "type": "tag" if annotated_tag else "commit",
                    "sha": "4" * 40 if annotated_tag else tag_commit,
                }
            }
        elif request.url.path.endswith(f"/git/tags/{'4' * 40}"):
            payload = {"object": {"type": "commit", "sha": tag_commit}}
        elif request.url.path.endswith("/git/ref/heads/main"):
            payload = {"object": {"type": "commit", "sha": main_commit}}
        else:
            raise AssertionError(f"unexpected GitHub API path: {request.url.path}")
        return httpx.Response(
            200,
            request=request,
            content=json.dumps(payload).encode(),
            headers={"content-type": "application/json"},
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def project_root(tmp_path: Path) -> Path:
    (tmp_path / "backend").mkdir()
    (tmp_path / ".git" / "info").mkdir(parents=True)
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "backend" / "pyproject.toml").write_text("", encoding="utf-8")
    return tmp_path


def runner_for(root: Path, **kwargs: object) -> FakeGitRunner:
    runner = FakeGitRunner(**kwargs)
    original_run = runner.run

    async def run_with_root(
        argv: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> CommandResult:
        result = await original_run(argv, cwd=cwd, env=env, timeout=timeout)
        if result.stdout == b"__PROJECT_ROOT__\n":
            return CommandResult(0, f"{root}\n".encode(), b"")
        return result

    runner.run = run_with_root  # type: ignore[method-assign]
    return runner


@pytest.mark.asyncio
async def test_subprocess_runner_bounds_time_and_combined_output(tmp_path: Path) -> None:
    runner = SubprocessRunner()
    with pytest.raises(CommandRunnerError, match="timed out"):
        await runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=tmp_path,
            env=os.environ,
            timeout=0.05,
        )
    with pytest.raises(CommandRunnerError, match="output exceeded"):
        await runner.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * (8 * 1024 * 1024 + 1))",
            ],
            cwd=tmp_path,
            env=os.environ,
            timeout=10.0,
        )


@pytest.mark.asyncio
async def test_clean_checkout_checks_and_applies_pinned_release(tmp_path: Path) -> None:
    root = project_root(tmp_path)
    runner = runner_for(root)
    client = release_client()
    service = UpdateService(
        project_root=root,
        current_version="0.1.0",
        git_executable="git",
        runner=runner,
        http_client=client,
    )

    checked = await service.check()
    assert checked.state is UpdateCheckState.AVAILABLE
    assert checked.current_commit == LOCAL_COMMIT
    assert checked.candidate_commit == CANDIDATE_COMMIT
    assert checked.release_tag == "v0.2.0"
    assert checked.can_apply is True
    assert checked.bootstrap_required is False

    applied = await service.apply(
        UpdateApplyRequest(
            confirm=True,
            expected_current_commit=LOCAL_COMMIT,
            expected_candidate_commit=CANDIDATE_COMMIT,
            expected_release_tag="v0.2.0",
        )
    )
    assert applied.applied_commit == CANDIDATE_COMMIT
    assert applied.restart_required is True
    assert applied.bootstrap_required is False
    assert service.operation_status().state is UpdateOperationState.UPDATED
    assert not any("stash" in command or "reset" in command for command in runner.commands)
    merge = next(command for command in runner.commands if command[0] == "merge")
    assert "--no-overwrite-ignore" in merge
    merge_argv = next(argv for argv in runner.argvs if "merge" in argv)
    assert "merge.autoStash=false" in merge_argv
    fetch_index = next(
        index for index, command in enumerate(runner.commands) if command[0] == "fetch"
    )
    assert runner.working_directories[fetch_index] != root
    assert f"+{CANDIDATE_COMMIT}:refs/bnt-updater/candidate" in runner.commands[
        fetch_index
    ]
    await client.aclose()


@pytest.mark.asyncio
async def test_api_pins_are_required_and_annotated_tags_are_peeled(
    tmp_path: Path,
) -> None:
    root = project_root(tmp_path)
    annotated_client = release_client(annotated_tag=True)
    annotated = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=annotated_client,
    )
    assert (await annotated.check()).state is UpdateCheckState.AVAILABLE
    await annotated_client.aclose()

    mismatch_client = release_client(tag_commit="9" * 40)
    mismatch = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=mismatch_client,
    )
    with pytest.raises(UpdateUpstreamError, match="pinned references"):
        await mismatch.check()
    await mismatch_client.aclose()


@pytest.mark.asyncio
@pytest.mark.skipif(GIT_EXECUTABLE is None, reason="Git is not installed")
async def test_real_git_bundle_import_makes_pinned_commit_available(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    run_git(source, "init", "-b", "main")
    run_git(source, "config", "user.name", "Updater Test")
    run_git(source, "config", "user.email", "updater@example.invalid")
    (source / "backend").mkdir()
    (source / "backend" / "pyproject.toml").write_text("", encoding="utf-8")
    (source / "package.json").write_text("{}", encoding="utf-8")
    (source / "README.md").write_text("first\n", encoding="utf-8")
    run_git(source, "add", ".")
    run_git(source, "commit", "-m", "first")
    subprocess.run(
        [GIT_EXECUTABLE, "clone", "--quiet", str(source), str(target)],
        check=True,
        capture_output=True,
    )
    old_commit = run_git(target, "rev-parse", "HEAD")

    (source / "README.md").write_text("second\n", encoding="utf-8")
    run_git(source, "add", "README.md")
    run_git(source, "commit", "-m", "second")
    candidate = run_git(source, "rev-parse", "HEAD")
    bundle = tmp_path / "candidate.bundle"
    run_git(source, "bundle", "create", str(bundle), "HEAD")

    service = UpdateService(project_root=target, git_executable=GIT_EXECUTABLE)
    imported = await service._git_result("bundle", "unbundle", str(bundle))
    assert imported.returncode == 0
    present = await service._git_result("cat-file", "-e", f"{candidate}^{{commit}}")
    assert present.returncode == 0
    assert run_git(target, "rev-parse", "HEAD") == old_commit
    await service.shutdown()


@pytest.mark.asyncio
async def test_git_environment_is_isolated_and_pre_merge_race_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = project_root(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'url.bad.insteadOf=https://github.com/'")
    monkeypatch.setenv("GIT_DIR", "/tmp/not-the-project")
    client = release_client()
    runner = runner_for(root, dirty_status_call=3)
    service = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner,
        http_client=client,
    )
    with pytest.raises(UpdateConflictError, match="during update validation"):
        await service.apply(
            UpdateApplyRequest(
                confirm=True,
                expected_current_commit=LOCAL_COMMIT,
                expected_candidate_commit=CANDIDATE_COMMIT,
                expected_release_tag="v0.2.0",
            )
        )
    assert not any(command[0] == "merge" for command in runner.commands)
    assert all("GIT_CONFIG_PARAMETERS" not in env for env in runner.environments)
    assert all("GIT_DIR" not in env for env in runner.environments)
    assert all("protocol.allow=never" in argv for argv in runner.argvs)
    assert all("core.protectHFS=true" in argv for argv in runner.argvs)
    assert all("core.protectNTFS=true" in argv for argv in runner.argvs)
    assert service.operation_status().state is UpdateOperationState.FAILED
    assert (await service.check()).state is UpdateCheckState.AVAILABLE
    assert service.operation_status().state is UpdateOperationState.IDLE
    await client.aclose()


@pytest.mark.asyncio
async def test_update_checks_have_one_total_deadline_and_do_not_overlap(
    tmp_path: Path,
) -> None:
    root = project_root(tmp_path)

    class BlockingUpdateService(UpdateService):
        def __init__(self, **kwargs: object) -> None:
            super().__init__(**kwargs)  # type: ignore[arg-type]
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def _check_serialized(self):  # type: ignore[no-untyped-def]
            self.started.set()
            await self.release.wait()
            return await super()._check_serialized()

    client = release_client()
    service = BlockingUpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=client,
        total_check_timeout_seconds=5.0,
    )
    first_check = asyncio.create_task(service.check())
    await service.started.wait()
    with pytest.raises(UpdateConflictError, match="already in progress"):
        await service.check()
    with pytest.raises(UpdateConflictError, match="already in progress"):
        await service.apply(
            UpdateApplyRequest(
                confirm=True,
                expected_current_commit=LOCAL_COMMIT,
                expected_candidate_commit=CANDIDATE_COMMIT,
                expected_release_tag="v0.2.0",
            )
        )
    service.release.set()
    assert (await first_check).state is UpdateCheckState.AVAILABLE
    await client.aclose()

    timeout_client = release_client()
    timeout_service = BlockingUpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=timeout_client,
        total_check_timeout_seconds=0.01,
    )
    with pytest.raises(UpdateUnavailableError, match="total safety deadline"):
        await timeout_service.check()
    await timeout_client.aclose()


@pytest.mark.asyncio
async def test_dirty_checkout_and_unsafe_tree_are_blocked(tmp_path: Path) -> None:
    root = project_root(tmp_path)
    client = release_client()

    dirty = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root, dirty=True),
        http_client=client,
    )
    dirty_check = await dirty.check()
    assert dirty_check.state is UpdateCheckState.BLOCKED
    assert dirty_check.reason == "local_changes"
    assert dirty_check.can_apply is False

    unsafe = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root, unsafe_mode=b"120000"),
        http_client=client,
    )
    unsafe_check = await unsafe.check()
    assert unsafe_check.state is UpdateCheckState.BLOCKED
    assert unsafe_check.reason == "unsupported_tree_entry"

    protected = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root, tree_path=b".env", changed_path=b".env"),
        http_client=client,
    )
    protected_check = await protected.check()
    assert protected_check.state is UpdateCheckState.BLOCKED
    assert protected_check.reason == "protected_release_path"

    reserved = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(
            root,
            tree_path="COM¹.txt".encode(),
            changed_path="COM¹.txt".encode(),
        ),
        http_client=client,
    )
    reserved_check = await reserved.check()
    assert reserved_check.state is UpdateCheckState.BLOCKED
    assert reserved_check.reason == "unsafe_release_path"
    await client.aclose()


@pytest.mark.asyncio
async def test_dependency_changes_and_untracked_collisions_are_detected(
    tmp_path: Path,
) -> None:
    root = project_root(tmp_path)
    client = release_client()

    dependency_service = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root, changed_path=b"package.json"),
        http_client=client,
    )
    dependency_check = await dependency_service.check()
    assert dependency_check.state is UpdateCheckState.AVAILABLE
    assert dependency_check.bootstrap_required is True

    (root / "ignored-local.txt").write_text("local", encoding="utf-8")
    collision_service = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(
            root,
            tree_path=b"ignored-local.txt",
            changed_path=b"ignored-local.txt",
            added_path=b"ignored-local.txt",
        ),
        http_client=client,
    )
    collision_check = await collision_service.check()
    assert collision_check.state is UpdateCheckState.BLOCKED
    assert collision_check.reason == "local_path_collision"
    await client.aclose()


@pytest.mark.asyncio
async def test_no_release_mutable_release_and_non_git_install_are_safe(
    tmp_path: Path,
) -> None:
    root = project_root(tmp_path)

    no_release_client = release_client(status_code=404)
    no_release = UpdateService(
        project_root=root,
        git_executable=None,
        http_client=no_release_client,
    )
    no_release_check = await no_release.check()
    assert no_release_check.state is UpdateCheckState.UNCONFIGURED
    await no_release_client.aclose()

    mutable_client = release_client(immutable=False)
    mutable = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=mutable_client,
    )
    mutable_check = await mutable.check()
    assert mutable_check.state is UpdateCheckState.BLOCKED
    assert mutable_check.reason == "mutable_release"
    with pytest.raises(UpdateConflictError, match="release changed"):
        await mutable.apply(
            UpdateApplyRequest(
                confirm=True,
                expected_current_commit=LOCAL_COMMIT,
                expected_candidate_commit=CANDIDATE_COMMIT,
                expected_release_tag="v0.2.0",
            )
        )
    await mutable_client.aclose()


def test_update_request_guard_requires_loopback_and_exact_mutation_origin() -> None:
    allowed = ("http://127.0.0.1:3000", "http://localhost:3000")
    authorize_update_request(
        api_host="127.0.0.1",
        client_host="127.0.0.1",
        origin="http://localhost:3000",
        allowed_origins=allowed,
        mutation=True,
    )

    with pytest.raises(UpdatePermissionError):
        authorize_update_request(
            api_host="0.0.0.0",
            client_host="127.0.0.1",
            origin="http://localhost:3000",
            allowed_origins=allowed,
            mutation=True,
        )
    with pytest.raises(UpdatePermissionError):
        authorize_update_request(
            api_host="127.0.0.1",
            client_host="127.0.0.1",
            origin="http://localhost:9999",
            allowed_origins=allowed,
            mutation=True,
        )


@pytest.mark.asyncio
async def test_apply_rejects_stale_confirmation(tmp_path: Path) -> None:
    root = project_root(tmp_path)
    client = release_client()
    service = UpdateService(
        project_root=root,
        git_executable="git",
        runner=runner_for(root),
        http_client=client,
    )
    with pytest.raises(UpdateConflictError, match="changed after the update check"):
        await service.apply(
            UpdateApplyRequest(
                confirm=True,
                expected_current_commit="9" * 40,
                expected_candidate_commit=CANDIDATE_COMMIT,
                expected_release_tag="v0.2.0",
            )
        )
    await client.aclose()
