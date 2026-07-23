"""Typed contracts for checking and applying Better Network Tools updates."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
STABLE_RELEASE_TAG_PATTERN = (
    r"^v(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)$"
)


class UpdateInstallKind(str, Enum):
    GIT_CHECKOUT = "git_checkout"
    SOURCE_ARCHIVE = "source_archive"
    PACKAGED = "packaged"


class UpdateCheckState(str, Enum):
    UP_TO_DATE = "up_to_date"
    AVAILABLE = "available"
    BLOCKED = "blocked"
    MANUAL_UPDATE_REQUIRED = "manual_update_required"
    UNCONFIGURED = "unconfigured"


class UpdateOperationState(str, Enum):
    IDLE = "idle"
    APPLYING = "applying"
    UPDATED = "updated"
    FAILED = "failed"


class UpdateCheckResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: UpdateCheckState
    install_kind: UpdateInstallKind
    current_version: str = Field(min_length=1, max_length=64)
    current_commit: str | None = Field(default=None, pattern=GIT_COMMIT_PATTERN)
    latest_version: str | None = Field(default=None, min_length=1, max_length=64)
    candidate_commit: str | None = Field(default=None, pattern=GIT_COMMIT_PATTERN)
    release_tag: str | None = Field(
        default=None,
        pattern=STABLE_RELEASE_TAG_PATTERN,
    )
    release_url: str | None = Field(default=None, max_length=500)
    can_apply: bool = False
    dirty: bool = False
    bootstrap_required: bool = False
    reason: str | None = Field(default=None, max_length=80)
    message: str = Field(min_length=1, max_length=300)
    checked_at: datetime


class UpdateApplyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: Literal[True]
    expected_current_commit: str = Field(pattern=GIT_COMMIT_PATTERN)
    expected_candidate_commit: str = Field(pattern=GIT_COMMIT_PATTERN)
    expected_release_tag: str = Field(pattern=STABLE_RELEASE_TAG_PATTERN)


class UpdateApplyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: Literal["updated"] = "updated"
    previous_commit: str = Field(pattern=GIT_COMMIT_PATTERN)
    applied_commit: str = Field(pattern=GIT_COMMIT_PATTERN)
    applied_version: str = Field(min_length=1, max_length=64)
    release_tag: str = Field(pattern=STABLE_RELEASE_TAG_PATTERN)
    release_url: str = Field(max_length=500)
    restart_required: Literal[True] = True
    bootstrap_required: bool
    message: str = Field(min_length=1, max_length=300)


class UpdateOperationResponse(BaseModel):
    """Recoverable state for an update request that outlives its browser page."""

    model_config = ConfigDict(extra="forbid")

    state: UpdateOperationState = UpdateOperationState.IDLE
    release_tag: str | None = Field(
        default=None,
        pattern=STABLE_RELEASE_TAG_PATTERN,
    )
    release_url: str | None = Field(default=None, max_length=500)
    applied_commit: str | None = Field(default=None, pattern=GIT_COMMIT_PATTERN)
    restart_required: bool = False
    bootstrap_required: bool = False
    message: str = Field(min_length=1, max_length=300)
    started_at: datetime | None = None
    finished_at: datetime | None = None
