"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { operationMatchesPending } from "./updateRecovery";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const CHECK_ENDPOINT = `${API_BASE_URL}/api/updates/check`;
const APPLY_ENDPOINT = `${API_BASE_URL}/api/updates/apply`;
const STATUS_ENDPOINT = `${API_BASE_URL}/api/updates/status`;
const RELEASES_URL =
  "https://github.com/erichbrinkman/betternetworktools/releases";
const CHECK_TIMEOUT_MS = 330_000;
const INSTALL_TIMEOUT_MS = 900_000;
const STATUS_TIMEOUT_MS = 15_000;
const STATUS_POLL_MS = 2_000;
const PENDING_MAX_AGE_MS = 60 * 60 * 1_000;
const PENDING_STORAGE_KEY = "better-network-tools.pending-update.v1";
const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const RELEASE_TAG_PATTERN = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/;

type PageTarget = "unknown" | "local" | "hosted";
type UpdatePhase =
  | "idle"
  | "checking"
  | "available"
  | "installing"
  | "current"
  | "updated"
  | "error";

type UpdateCheckResponse = {
  state:
    | "up_to_date"
    | "available"
    | "blocked"
    | "manual_update_required"
    | "unconfigured";
  install_kind: "git_checkout" | "source_archive" | "packaged";
  current_version: string;
  current_commit: string | null;
  latest_version: string | null;
  candidate_commit: string | null;
  release_tag: string | null;
  release_url: string | null;
  can_apply: boolean;
  dirty: boolean;
  bootstrap_required: boolean;
  reason: string | null;
  message: string;
  checked_at: string;
};

type UpdateInstallResponse = {
  state: "updated";
  previous_commit: string;
  applied_commit: string;
  applied_version: string;
  release_tag: string;
  release_url: string;
  restart_required: true;
  bootstrap_required: boolean;
  message: string;
};

type UpdateOperationResponse = {
  state: "idle" | "applying" | "updated" | "failed";
  release_tag: string | null;
  release_url: string | null;
  applied_commit: string | null;
  restart_required: boolean;
  bootstrap_required: boolean;
  message: string;
  started_at: string | null;
  finished_at: string | null;
};

type UpdateInstallRequest = {
  confirm: true;
  expected_current_commit: string;
  expected_candidate_commit: string;
  expected_release_tag: string;
};

type PendingUpdate = {
  currentCommit: string;
  candidateCommit: string;
  releaseTag: string;
  releaseUrl: string;
  bootstrapRequired: boolean;
  startedAt: number;
};

type ButtonLabels = {
  accessible: string;
  compact: string;
  full: string;
};

class UpdateRequestError extends Error {
  constructor(
    message: string,
    readonly kind: "server" | "timeout" | "network" | "invalid" = "invalid",
  ) {
    super(message);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

function isNullableCommit(value: unknown): value is string | null {
  return value === null || (typeof value === "string" && COMMIT_PATTERN.test(value));
}

function isNullableReleaseTag(value: unknown): value is string | null {
  return (
    value === null ||
    (typeof value === "string" && RELEASE_TAG_PATTERN.test(value))
  );
}

function isNullableTimestamp(value: unknown): value is string | null {
  return (
    value === null ||
    (typeof value === "string" && Number.isFinite(Date.parse(value)))
  );
}

function trustedReleaseUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    const parts = parsed.pathname.split("/").filter(Boolean);
    const validPath =
      (parts.length === 3 && parts[2] === "releases") ||
      (parts.length === 5 && parts[2] === "releases" && parts[3] === "tag");
    if (
      parsed.protocol !== "https:" ||
      parsed.hostname !== "github.com" ||
      parsed.port ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash ||
      !validPath ||
      !/^[A-Za-z0-9-]{1,39}$/.test(parts[0] ?? "") ||
      !/^[A-Za-z0-9._-]{1,100}$/.test(parts[1] ?? "") ||
      (parts.length === 5 && !RELEASE_TAG_PATTERN.test(parts[4] ?? ""))
    ) {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

function releaseUrlForTag(tag: string | null): string {
  return tag && RELEASE_TAG_PATTERN.test(tag)
    ? `${RELEASES_URL}/tag/${encodeURIComponent(tag)}`
    : RELEASES_URL;
}

function isUpdateCheckResponse(value: unknown): value is UpdateCheckResponse {
  if (!isRecord(value)) return false;
  const state = String(value.state);
  const canApply = value.can_apply;
  const releaseUrl = value.release_url;
  const valid =
    [
      "up_to_date",
      "available",
      "blocked",
      "manual_update_required",
      "unconfigured",
    ].includes(state) &&
    ["git_checkout", "source_archive", "packaged"].includes(
      String(value.install_kind),
    ) &&
    typeof value.current_version === "string" &&
    value.current_version.length > 0 &&
    isNullableCommit(value.current_commit) &&
    isNullableString(value.latest_version) &&
    isNullableCommit(value.candidate_commit) &&
    isNullableReleaseTag(value.release_tag) &&
    (releaseUrl === null || trustedReleaseUrl(releaseUrl) !== null) &&
    typeof canApply === "boolean" &&
    typeof value.dirty === "boolean" &&
    typeof value.bootstrap_required === "boolean" &&
    isNullableString(value.reason) &&
    typeof value.message === "string" &&
    value.message.length > 0 &&
    isNullableTimestamp(value.checked_at) &&
    value.checked_at !== null;

  if (!valid) return false;
  if (canApply) {
    return (
      state === "available" &&
      value.install_kind === "git_checkout" &&
      typeof value.current_commit === "string" &&
      typeof value.candidate_commit === "string" &&
      typeof value.release_tag === "string" &&
      typeof value.release_url === "string"
    );
  }
  return state !== "available";
}

function isUpdateInstallResponse(value: unknown): value is UpdateInstallResponse {
  return (
    isRecord(value) &&
    value.state === "updated" &&
    typeof value.previous_commit === "string" &&
    COMMIT_PATTERN.test(value.previous_commit) &&
    typeof value.applied_commit === "string" &&
    COMMIT_PATTERN.test(value.applied_commit) &&
    typeof value.applied_version === "string" &&
    value.applied_version.length > 0 &&
    typeof value.release_tag === "string" &&
    RELEASE_TAG_PATTERN.test(value.release_tag) &&
    trustedReleaseUrl(value.release_url) !== null &&
    value.restart_required === true &&
    typeof value.bootstrap_required === "boolean" &&
    typeof value.message === "string" &&
    value.message.length > 0
  );
}

function isUpdateOperationResponse(
  value: unknown,
): value is UpdateOperationResponse {
  return (
    isRecord(value) &&
    ["idle", "applying", "updated", "failed"].includes(String(value.state)) &&
    isNullableReleaseTag(value.release_tag) &&
    (value.release_url === null || trustedReleaseUrl(value.release_url) !== null) &&
    isNullableCommit(value.applied_commit) &&
    typeof value.restart_required === "boolean" &&
    typeof value.bootstrap_required === "boolean" &&
    typeof value.message === "string" &&
    value.message.length > 0 &&
    isNullableTimestamp(value.started_at) &&
    isNullableTimestamp(value.finished_at) &&
    (value.state !== "updated" ||
      (value.restart_required === true &&
        typeof value.applied_commit === "string" &&
        typeof value.release_tag === "string"))
  );
}

function isPendingUpdate(value: unknown): value is PendingUpdate {
  return (
    isRecord(value) &&
    typeof value.currentCommit === "string" &&
    COMMIT_PATTERN.test(value.currentCommit) &&
    typeof value.candidateCommit === "string" &&
    COMMIT_PATTERN.test(value.candidateCommit) &&
    typeof value.releaseTag === "string" &&
    RELEASE_TAG_PATTERN.test(value.releaseTag) &&
    typeof value.releaseUrl === "string" &&
    trustedReleaseUrl(value.releaseUrl) !== null &&
    typeof value.bootstrapRequired === "boolean" &&
    typeof value.startedAt === "number" &&
    Number.isFinite(value.startedAt)
  );
}

function readPendingUpdate(): PendingUpdate | null {
  try {
    const raw = window.sessionStorage.getItem(PENDING_STORAGE_KEY);
    if (!raw) return null;
    const value: unknown = JSON.parse(raw);
    if (
      !isPendingUpdate(value) ||
      Date.now() - value.startedAt > PENDING_MAX_AGE_MS
    ) {
      window.sessionStorage.removeItem(PENDING_STORAGE_KEY);
      return null;
    }
    return value;
  } catch {
    return null;
  }
}

function writePendingUpdate(update: PendingUpdate): void {
  try {
    window.sessionStorage.setItem(PENDING_STORAGE_KEY, JSON.stringify(update));
  } catch {
    // Recovery is best-effort when browser storage is disabled.
  }
}

function clearPendingUpdate(): void {
  try {
    window.sessionStorage.removeItem(PENDING_STORAGE_KEY);
  } catch {
    // Nothing else is required when browser storage is disabled.
  }
}

function isLoopbackPage(): boolean {
  const hostname = window.location.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const ipv4Parts = hostname.split(".");
  const isIpv4Loopback =
    ipv4Parts.length === 4 &&
    ipv4Parts[0] === "127" &&
    ipv4Parts.every(
      (part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255,
    );
  return (
    hostname === "localhost" ||
    hostname === "::1" ||
    hostname === "0:0:0:0:0:0:0:1" ||
    isIpv4Loopback
  );
}

function subscribeToHydration(): () => void {
  return () => {};
}

function clientHydrationSnapshot(): true {
  return true;
}

function serverHydrationSnapshot(): false {
  return false;
}

function parseResponseBody(raw: string): unknown {
  if (!raw) return null;
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    return null;
  }
}

function responseErrorMessage(payload: unknown, status: number): string {
  if (isRecord(payload)) {
    if (typeof payload.message === "string" && payload.message.trim()) {
      return payload.message;
    }
    if (typeof payload.detail === "string" && payload.detail.trim()) {
      return payload.detail;
    }
    if (
      isRecord(payload.detail) &&
      typeof payload.detail.message === "string" &&
      payload.detail.message.trim()
    ) {
      return payload.detail.message;
    }
  }
  return `The local updater returned an unexpected response (${status}).`;
}

async function requestUpdate(
  endpoint: string,
  method: "GET" | "POST",
  timeoutMs: number,
  body?: UpdateInstallRequest,
): Promise<unknown> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method,
      cache: "no-store",
      credentials: "omit",
      headers: body
        ? { Accept: "application/json", "Content-Type": "application/json" }
        : { Accept: "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    const payload = parseResponseBody(await response.text());
    if (!response.ok) {
      throw new UpdateRequestError(
        responseErrorMessage(payload, response.status),
        "server",
      );
    }
    return payload;
  } catch (error) {
    if (controller.signal.aborted) {
      throw new UpdateRequestError(
        method === "GET"
          ? "The local updater status request timed out."
          : "The update request is taking longer than expected.",
        "timeout",
      );
    }
    if (error instanceof UpdateRequestError) throw error;
    throw new UpdateRequestError(
      "The configured local Better Network Tools service could not be reached.",
      "network",
    );
  } finally {
    window.clearTimeout(timeout);
  }
}

function candidateLabel(update: UpdateCheckResponse | null): string {
  if (!update) return "the available version";
  if (update.release_tag?.trim()) return update.release_tag.trim();
  if (update.latest_version?.trim()) return `v${update.latest_version.trim()}`;
  return update.candidate_commit?.slice(0, 12) ?? "the available version";
}

function buttonLabels(
  phase: UpdatePhase,
  update: UpdateCheckResponse | null,
  restartRequired: boolean,
): ButtonLabels {
  const version = candidateLabel(update);
  switch (phase) {
    case "checking":
      return { accessible: "Checking for updates", compact: "Checking…", full: "Checking…" };
    case "available":
      return { accessible: `Install update ${version}`, compact: "Install", full: `Install ${version}` };
    case "installing":
      return { accessible: `Installing update ${version}`, compact: "Updating…", full: "Updating…" };
    case "current":
      return { accessible: "Check for updates again", compact: "Check", full: "Check Again" };
    case "updated":
      return restartRequired
        ? { accessible: "Update installed; restart Better Network Tools", compact: "Restart", full: "Restart Required" }
        : { accessible: "Better Network Tools was updated", compact: "Updated", full: "Updated" };
    case "error":
      return { accessible: "Try the update check again", compact: "Retry", full: "Try Again" };
    default:
      return { accessible: "Check for Updates", compact: "Updates", full: "Check for Updates" };
  }
}

export function UpdateButton() {
  const hydrated = useSyncExternalStore(
    subscribeToHydration,
    clientHydrationSnapshot,
    serverHydrationSnapshot,
  );
  const pageTarget: PageTarget = hydrated
    ? isLoopbackPage()
      ? "local"
      : "hosted"
    : "unknown";
  const [phase, setPhase] = useState<UpdatePhase>("idle");
  const [checkedUpdate, setCheckedUpdate] =
    useState<UpdateCheckResponse | null>(null);
  const [message, setMessage] = useState("");
  const [messageVisible, setMessageVisible] = useState(false);
  const [releaseUrl, setReleaseUrl] = useState<string | null>(null);
  const [restartRequired, setRestartRequired] = useState(false);
  const [recoveryVersion, setRecoveryVersion] = useState(0);

  const busy = phase === "checking" || phase === "installing";
  const labels = buttonLabels(phase, checkedUpdate, restartRequired);

  function showMessage(value: string) {
    setMessage(value);
    setMessageVisible(true);
  }

  useEffect(() => {
    if (!messageVisible) return;
    function dismissOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setMessageVisible(false);
    }
    window.addEventListener("keydown", dismissOnEscape);
    return () => window.removeEventListener("keydown", dismissOnEscape);
  }, [messageVisible]);

  useEffect(() => {
    if (pageTarget !== "local") return;
    let cancelled = false;
    let pollTimer: number | undefined;

    function pollAgain() {
      if (!cancelled) pollTimer = window.setTimeout(recover, STATUS_POLL_MS);
    }

    async function reconcilePending(pending: PendingUpdate) {
      try {
        const payload = await requestUpdate(
          CHECK_ENDPOINT,
          "POST",
          CHECK_TIMEOUT_MS,
        );
        if (!isUpdateCheckResponse(payload)) {
          throw new UpdateRequestError(
            "The local updater returned an invalid recovery response.",
          );
        }
        if (cancelled) return;
        if (
          !payload.dirty &&
          payload.current_commit === pending.candidateCommit &&
          (payload.state === "up_to_date" || payload.state === "available")
        ) {
          clearPendingUpdate();
          setCheckedUpdate(payload);
          setReleaseUrl(pending.releaseUrl);
          setRestartRequired(true);
          setPhase("updated");
          showMessage(
            pending.bootstrapRequired
              ? `Updated to ${pending.releaseTag}. Run the setup script again, then restart Better Network Tools.`
              : `Updated to ${pending.releaseTag}. Restart Better Network Tools to use the new files.`,
          );
          return;
        }
        clearPendingUpdate();
        setCheckedUpdate(null);
        setRestartRequired(false);
        setPhase("error");
        showMessage(
          "The previous update did not complete. Check again before retrying.",
        );
      } catch (error) {
        if (
          error instanceof UpdateRequestError &&
          (error.kind === "network" || error.kind === "timeout")
        ) {
          pollAgain();
          return;
        }
        clearPendingUpdate();
        setCheckedUpdate(null);
        setRestartRequired(false);
        setPhase("error");
        showMessage(
          error instanceof Error
            ? error.message
            : "The previous update could not be reconciled.",
        );
      }
    }

    async function recover() {
      const pending = readPendingUpdate();
      try {
        const payload = await requestUpdate(
          STATUS_ENDPOINT,
          "GET",
          STATUS_TIMEOUT_MS,
        );
        if (!isUpdateOperationResponse(payload)) {
          throw new UpdateRequestError(
            "The local updater returned an invalid status response.",
          );
        }
        if (cancelled) return;
        if (payload.state === "applying") {
          if (pending && !operationMatchesPending(payload, pending)) {
            clearPendingUpdate();
            setCheckedUpdate(null);
            setRestartRequired(false);
            setPhase("error");
            showMessage(
              "The local service is tracking a different update. Check again after it finishes.",
            );
            return;
          }
          setPhase("installing");
          setReleaseUrl(
            trustedReleaseUrl(payload.release_url) ??
              releaseUrlForTag(payload.release_tag),
          );
          showMessage(payload.message);
          pollAgain();
          return;
        }
        if (payload.state === "updated") {
          if (pending && !operationMatchesPending(payload, pending)) {
            await reconcilePending(pending);
            return;
          }
          clearPendingUpdate();
          setPhase("updated");
          setReleaseUrl(
            trustedReleaseUrl(payload.release_url) ??
              releaseUrlForTag(payload.release_tag),
          );
          setRestartRequired(payload.restart_required);
          showMessage(
            payload.bootstrap_required
              ? `${payload.message} Run the setup script again before restarting.`
              : payload.message,
          );
          return;
        }
        if (payload.state === "failed") {
          if (pending && !operationMatchesPending(payload, pending)) {
            await reconcilePending(pending);
            return;
          }
          clearPendingUpdate();
          setCheckedUpdate(null);
          setRestartRequired(false);
          setPhase("error");
          showMessage(payload.message);
          return;
        }
        if (pending) await reconcilePending(pending);
      } catch (error) {
        if (!pending) return;
        if (
          error instanceof UpdateRequestError &&
          (error.kind === "network" || error.kind === "timeout")
        ) {
          pollAgain();
          return;
        }
        clearPendingUpdate();
        setCheckedUpdate(null);
        setRestartRequired(false);
        setPhase("error");
        showMessage(
          error instanceof Error
            ? error.message
            : "The update status could not be recovered.",
        );
      }
    }

    void recover();
    return () => {
      cancelled = true;
      if (pollTimer !== undefined) window.clearTimeout(pollTimer);
    };
  }, [pageTarget, recoveryVersion]);

  async function checkForUpdates() {
    setPhase("checking");
    setCheckedUpdate(null);
    setReleaseUrl(null);
    setRestartRequired(false);
    showMessage("Checking GitHub for a newer Better Network Tools release.");
    try {
      const payload = await requestUpdate(
        CHECK_ENDPOINT,
        "POST",
        CHECK_TIMEOUT_MS,
      );
      if (!isUpdateCheckResponse(payload)) {
        throw new UpdateRequestError(
          "The local updater returned an invalid update-check response.",
        );
      }
      setCheckedUpdate(payload);
      setReleaseUrl(trustedReleaseUrl(payload.release_url));
      if (payload.state === "available" && payload.can_apply) {
        setPhase("available");
        showMessage(
          `${candidateLabel(payload)} is available. Activate Install to pull the verified release files from GitHub.`,
        );
      } else {
        setPhase("current");
        showMessage(payload.message);
      }
    } catch (error) {
      setCheckedUpdate(null);
      setPhase("error");
      showMessage(
        error instanceof Error
          ? error.message
          : "The update check could not be completed.",
      );
    }
  }

  async function installUpdate(update: UpdateCheckResponse) {
    if (!update.current_commit || !update.candidate_commit || !update.release_tag) {
      setCheckedUpdate(null);
      setPhase("error");
      showMessage("The checked release is missing its pinned update information.");
      return;
    }
    const pending: PendingUpdate = {
      currentCommit: update.current_commit,
      candidateCommit: update.candidate_commit,
      releaseTag: update.release_tag,
      releaseUrl:
        trustedReleaseUrl(update.release_url) ??
        releaseUrlForTag(update.release_tag),
      bootstrapRequired: update.bootstrap_required,
      startedAt: Date.now(),
    };
    writePendingUpdate(pending);
    setPhase("installing");
    setReleaseUrl(releaseUrlForTag(update.release_tag));
    showMessage(
      `Installing ${candidateLabel(update)} from GitHub. Keep Better Network Tools open.`,
    );
    try {
      const payload = await requestUpdate(
        APPLY_ENDPOINT,
        "POST",
        INSTALL_TIMEOUT_MS,
        {
          confirm: true,
          expected_current_commit: update.current_commit,
          expected_candidate_commit: update.candidate_commit,
          expected_release_tag: update.release_tag,
        },
      );
      if (!isUpdateInstallResponse(payload)) {
        throw new UpdateRequestError(
          "The local updater returned an invalid install response.",
        );
      }
      clearPendingUpdate();
      setReleaseUrl(trustedReleaseUrl(payload.release_url));
      setRestartRequired(payload.restart_required);
      setPhase("updated");
      showMessage(
        payload.bootstrap_required
          ? `Updated to ${payload.release_tag}. Run the setup script again, then restart Better Network Tools.`
          : `Updated to ${payload.release_tag}. Restart Better Network Tools to use the new files.`,
      );
    } catch {
      // The request can outlive this page or trigger a development-server
      // reload. Preserve the pinned candidate and reconcile it with the API.
      setPhase("installing");
      showMessage("Confirming the update result with the local service.");
      setRecoveryVersion((value) => value + 1);
    }
  }

  function handleClick() {
    if (busy || phase === "updated") return;
    if (phase === "available" && checkedUpdate) {
      void installUpdate(checkedUpdate);
      return;
    }
    void checkForUpdates();
  }

  if (pageTarget === "hosted") {
    return (
      <div className="update-control" data-state="hosted">
        <a
          className="update-button update-release-button"
          href={RELEASES_URL}
          target="_blank"
          rel="noreferrer"
          aria-label="View Better Network Tools releases on GitHub"
        >
          <span className="update-button-label-full" aria-hidden="true">
            View Releases
          </span>
          <span className="update-button-label-compact" aria-hidden="true">
            Releases
          </span>
        </a>
      </div>
    );
  }

  return (
    <div className="update-control" data-state={phase}>
      <button
        className="update-button"
        type="button"
        onClick={handleClick}
        disabled={busy || phase === "updated"}
        aria-busy={busy}
        aria-describedby={messageVisible && message ? "update-status" : undefined}
        aria-label={labels.accessible}
      >
        <span className="update-button-label-full" aria-hidden="true">
          {labels.full}
        </span>
        <span className="update-button-label-compact" aria-hidden="true">
          {labels.compact}
        </span>
      </button>

      <div
        className="update-status-panel"
        hidden={!messageVisible || !message}
      >
        <span
          className="update-status"
          id="update-status"
          role={phase === "error" ? "alert" : "status"}
          aria-live={phase === "error" ? "assertive" : "polite"}
          aria-atomic="true"
        >
          {message}
        </span>
        {releaseUrl ? (
          <a
            className="update-release-link"
            href={releaseUrl}
            target="_blank"
            rel="noreferrer"
          >
            Open release
          </a>
        ) : null}
        <button
          className="update-status-close"
          type="button"
          onClick={() => setMessageVisible(false)}
          aria-label="Dismiss update status"
        >
          ×
        </button>
      </div>
    </div>
  );
}
