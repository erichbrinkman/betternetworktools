"use client";

import {
  type CSSProperties,
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import styles from "./netspeed.module.css";
import { sortServersByProvider } from "./serverSorting";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const ACTIVE_JOB_STORAGE_KEY = "better-network-tools.netspeed.active-job-id";
const HISTORY_STORAGE_KEY = "better-network-tools.netspeed.history.v1";
const SIZE_OPTIONS_STORAGE_KEY = "better-network-tools.netspeed.size-options.v1";
const HISTORY_LIMIT = 6;
const POLL_INTERVAL_MS = 700;

const MEGABYTE = 1_000_000;
const DEFAULT_DOWNLOAD_BYTES = 250 * MEGABYTE;
const DEFAULT_UPLOAD_BYTES = 100 * MEGABYTE;

type SizePreset = {
  value: number;
  label: string;
};

const DOWNLOAD_SIZE_PRESETS: SizePreset[] = [
  { value: 50 * MEGABYTE, label: "Quick · 50 MB" },
  { value: 100 * MEGABYTE, label: "Light · 100 MB" },
  { value: DEFAULT_DOWNLOAD_BYTES, label: "Standard · 250 MB" },
  { value: 500 * MEGABYTE, label: "Fast · 500 MB" },
  { value: 1_000 * MEGABYTE, label: "High bandwidth · 1 GB" },
  { value: 2_000 * MEGABYTE, label: "Maximum · 2 GB" },
];

const UPLOAD_SIZE_PRESETS: SizePreset[] = [
  { value: 25 * MEGABYTE, label: "Quick · 25 MB" },
  { value: 50 * MEGABYTE, label: "Light · 50 MB" },
  { value: DEFAULT_UPLOAD_BYTES, label: "Standard · 100 MB" },
  { value: 250 * MEGABYTE, label: "Fast · 250 MB" },
  { value: 500 * MEGABYTE, label: "High bandwidth · 500 MB" },
  { value: 1_000 * MEGABYTE, label: "Maximum · 1 GB" },
];

type DirectoryStatus = "fresh" | "stale" | "unavailable";
type SpeedJobStatus =
  | "queued"
  | "running"
  | "completed"
  | "cancelled"
  | "failed";
type SpeedPhase = "queued" | "ping" | "download" | "upload" | "complete";
type Region = "All" | "Americas" | "Europe" | "Asia Pacific" | "Other";
type ServerSort = "nearest" | "provider";

type SpeedServer = {
  id: string;
  name: string;
  provider: "cloudflare" | "librespeed";
  location: string | null;
  country: string | null;
  sponsor: string | null;
  automatic: boolean;
  latency_ms: number | null;
};

type ServerDirectory = {
  servers: SpeedServer[];
  refreshed_at: string;
  directory_status: DirectoryStatus;
};

type SpeedTestOptions = {
  download_bytes: number;
  upload_bytes: number;
};

type ThroughputPhase = "download" | "upload";

type ThroughputSample = {
  phase: ThroughputPhase;
  elapsed_seconds: number;
  mbps: number;
};

type SpeedLimits = {
  min_speed_download_bytes: number;
  default_speed_download_bytes: number;
  max_speed_download_bytes: number;
  min_speed_upload_bytes: number;
  default_speed_upload_bytes: number;
  max_speed_upload_bytes: number;
};

type SpeedResult = {
  server: SpeedServer;
  ping_ms: number;
  jitter_ms: number;
  download_mbps: number;
  upload_mbps: number;
  download_bytes: number;
  upload_bytes: number;
  transferred_bytes: number;
  duration_seconds: number;
};

type SpeedJob = {
  id: string;
  status: SpeedJobStatus;
  phase: SpeedPhase;
  server: SpeedServer;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  options?: SpeedTestOptions;
  progress: {
    percent: number;
    download_bytes: number;
    upload_bytes: number;
    current_mbps?: number | null;
    samples?: ThroughputSample[];
  };
  result: SpeedResult | null;
  error: string | null;
  cancel_requested: boolean;
};

type StoredResult = SpeedResult & {
  id: string;
  completed_at: string;
};

const EMPTY_SERVERS: SpeedServer[] = [];

const DEFAULT_SPEED_LIMITS: SpeedLimits = {
  min_speed_download_bytes: 25 * MEGABYTE,
  default_speed_download_bytes: DEFAULT_DOWNLOAD_BYTES,
  max_speed_download_bytes: 2_000 * MEGABYTE,
  min_speed_upload_bytes: 10 * MEGABYTE,
  default_speed_upload_bytes: DEFAULT_UPLOAD_BYTES,
  max_speed_upload_bytes: 1_000 * MEGABYTE,
};

const REGIONS: Region[] = [
  "All",
  "Americas",
  "Europe",
  "Asia Pacific",
  "Other",
];

const PHASE_LABELS: Record<SpeedPhase, string> = {
  queued: "Queued",
  ping: "Measuring latency",
  download: "Testing download",
  upload: "Testing upload",
  complete: "Complete",
};

function isActiveJob(job: SpeedJob | null) {
  return job?.status === "queued" || job?.status === "running";
}

function rememberActiveJob(job: SpeedJob) {
  if (!isActiveJob(job)) return;
  try {
    window.localStorage.setItem(ACTIVE_JOB_STORAGE_KEY, job.id);
  } catch {
    // Reattachment is optional when browser storage is unavailable.
  }
}

function forgetActiveJob(jobId: string) {
  try {
    if (window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY) === jobId) {
      window.localStorage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    }
  } catch {
    // No stored identifier is available to clear.
  }
}

function readActiveJobId() {
  try {
    return window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY);
  } catch {
    return null;
  }
}

function isStoredResult(value: unknown): value is StoredResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<StoredResult>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.completed_at === "string" &&
    typeof candidate.ping_ms === "number" &&
    typeof candidate.jitter_ms === "number" &&
    typeof candidate.download_mbps === "number" &&
    typeof candidate.upload_mbps === "number" &&
    Boolean(candidate.server && typeof candidate.server.id === "string")
  );
}

function readHistory(): StoredResult[] {
  try {
    const stored = window.localStorage.getItem(HISTORY_STORAGE_KEY);
    if (!stored) return [];
    const parsed: unknown = JSON.parse(stored);
    return Array.isArray(parsed)
      ? parsed.filter(isStoredResult).slice(0, HISTORY_LIMIT)
      : [];
  } catch {
    return [];
  }
}

function writeHistory(history: StoredResult[]) {
  try {
    window.localStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history));
  } catch {
    // Completed results can still be viewed while storage is unavailable.
  }
}

function isSpeedTestOptions(value: unknown): value is SpeedTestOptions {
  if (!value || typeof value !== "object") return false;
  const options = value as Partial<SpeedTestOptions>;
  return (
    typeof options.download_bytes === "number" &&
    Number.isInteger(options.download_bytes) &&
    options.download_bytes >= DEFAULT_SPEED_LIMITS.min_speed_download_bytes &&
    options.download_bytes <= DEFAULT_SPEED_LIMITS.max_speed_download_bytes &&
    typeof options.upload_bytes === "number" &&
    Number.isInteger(options.upload_bytes) &&
    options.upload_bytes >= DEFAULT_SPEED_LIMITS.min_speed_upload_bytes &&
    options.upload_bytes <= DEFAULT_SPEED_LIMITS.max_speed_upload_bytes
  );
}

function readSizeOptions(): SpeedTestOptions | null {
  try {
    const stored = window.localStorage.getItem(SIZE_OPTIONS_STORAGE_KEY);
    if (!stored) return null;
    const parsed: unknown = JSON.parse(stored);
    if (isSpeedTestOptions(parsed)) return parsed;
  } catch {
    // Defaults remain available when browser storage is unavailable or invalid.
  }
  return null;
}

function writeSizeOptions(options: SpeedTestOptions) {
  try {
    window.localStorage.setItem(SIZE_OPTIONS_STORAGE_KEY, JSON.stringify(options));
  } catch {
    // The selected sizes still apply to the current page.
  }
}

function normalizeSpeedLimits(value: unknown): SpeedLimits | null {
  if (!value || typeof value !== "object") return null;
  const limits = value as Partial<SpeedLimits>;
  const keys: Array<keyof SpeedLimits> = [
    "min_speed_download_bytes",
    "default_speed_download_bytes",
    "max_speed_download_bytes",
    "min_speed_upload_bytes",
    "default_speed_upload_bytes",
    "max_speed_upload_bytes",
  ];
  if (
    !keys.every(
      (key) =>
        typeof limits[key] === "number" &&
        Number.isInteger(limits[key]) &&
        limits[key]! > 0,
    )
  ) {
    return null;
  }
  const normalized = limits as SpeedLimits;
  if (
    normalized.min_speed_download_bytes > normalized.default_speed_download_bytes ||
    normalized.default_speed_download_bytes > normalized.max_speed_download_bytes ||
    normalized.min_speed_upload_bytes > normalized.default_speed_upload_bytes ||
    normalized.default_speed_upload_bytes > normalized.max_speed_upload_bytes
  ) {
    return null;
  }
  return normalized;
}

function availablePresets(
  presets: SizePreset[],
  minimum: number,
  configuredDefault: number,
  maximum: number,
) {
  const available = presets.filter(
    (preset) => preset.value >= minimum && preset.value <= maximum,
  );
  if (!available.some((preset) => preset.value === configuredDefault)) {
    available.push({
      value: configuredDefault,
      label: `Configured default · ${formatBytes(configuredDefault)}`,
    });
  }
  return available.sort((left, right) => left.value - right.value);
}

function regionForServer(server: SpeedServer): Exclude<Region, "All"> {
  if (server.automatic) return "Other";
  const value = `${server.country ?? ""} ${server.location ?? ""}`.toLowerCase();
  if (
    /(united states|canada|mexico|brazil|argentina|chile|colombia|peru|america)/.test(
      value,
    )
  ) {
    return "Americas";
  }
  if (
    /(united kingdom|england|germany|france|italy|norway|finland|sweden|poland|czech|netherlands|spain|portugal|belgium|austria|lithuania|europe)/.test(
      value,
    )
  ) {
    return "Europe";
  }
  if (
    /(japan|singapore|australia|india|indonesia|malaysia|philippines|korea|new zealand|taiwan|thailand|vietnam|asia)/.test(
      value,
    )
  ) {
    return "Asia Pacific";
  }
  return "Other";
}

function formatServerLatency(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value) || value < 0) {
    return "Latency unavailable";
  }
  return `${value.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: value < 10 ? 1 : 0,
  })} ms latency`;
}

function serverSecondary(server: SpeedServer) {
  if (server.automatic) return "Nearest available edge · Cloudflare";
  const provider = server.provider === "librespeed" ? "LibreSpeed" : "Cloudflare";
  return [formatServerLatency(server.latency_ms), server.sponsor, provider]
    .filter((detail): detail is string => Boolean(detail))
    .join(" · ");
}

function serverPrimary(server: SpeedServer) {
  return server.automatic ? server.name : server.location ?? server.name;
}

function formatMetric(value: number | null, unit: string) {
  if (value == null || !Number.isFinite(value)) return "—";
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toLocaleString(undefined, {
    minimumFractionDigits: 0,
    maximumFractionDigits: digits,
  })} ${unit}`;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 MB";
  if (value >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toLocaleString(undefined, {
      maximumFractionDigits: 2,
    })} GB`;
  }
  return `${(value / 1_000_000).toLocaleString(undefined, {
    maximumFractionDigits: 1,
  })} MB`;
}

function formatWhen(value: string) {
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(parsed);
}

function formatChartSpeed(value: number | null) {
  if (value == null || !Number.isFinite(value)) return "Waiting";
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: digits,
  })} Mbps`;
}

function normalizeThroughputSamples(value: unknown): ThroughputSample[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((sample): sample is ThroughputSample => {
      if (!sample || typeof sample !== "object") return false;
      const candidate = sample as Partial<ThroughputSample>;
      return (
        (candidate.phase === "download" || candidate.phase === "upload") &&
        typeof candidate.elapsed_seconds === "number" &&
        Number.isFinite(candidate.elapsed_seconds) &&
        candidate.elapsed_seconds >= 0 &&
        typeof candidate.mbps === "number" &&
        Number.isFinite(candidate.mbps) &&
        candidate.mbps >= 0
      );
    })
    .slice(0, 320);
}

function niceChartCeiling(maximum: number) {
  if (!Number.isFinite(maximum) || maximum <= 0) return 10;
  const padded = maximum * 1.08;
  const magnitude = 10 ** Math.floor(Math.log10(padded));
  const normalized = padded / magnitude;
  const step =
    [1, 1.2, 1.5, 2, 2.5, 5, 10].find((candidate) => normalized <= candidate) ??
    10;
  return step * magnitude;
}

async function responseError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      detail?: string | { message?: string } | Array<{ msg?: string }>;
    };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return (
        payload.detail
          .map((item) => item.msg)
          .filter(Boolean)
          .join(" ") || fallback
      );
    }
    if (
      payload.detail &&
      typeof payload.detail === "object" &&
      typeof payload.detail.message === "string"
    ) {
      return payload.detail.message;
    }
  } catch {
    // Use the status-based fallback for non-JSON failures.
  }
  return fallback;
}

export function NetSpeedClient() {
  const [directory, setDirectory] = useState<ServerDirectory | null>(null);
  const [directoryLoading, setDirectoryLoading] = useState(true);
  const [directoryError, setDirectoryError] = useState<string | null>(null);
  const [directoryRequest, setDirectoryRequest] = useState(0);
  const [selectedServerId, setSelectedServerId] = useState<string | null>(null);
  const [speedLimits, setSpeedLimits] = useState(DEFAULT_SPEED_LIMITS);
  const [downloadBytes, setDownloadBytes] = useState(DEFAULT_DOWNLOAD_BYTES);
  const [uploadBytes, setUploadBytes] = useState(DEFAULT_UPLOAD_BYTES);
  const [query, setQuery] = useState("");
  const [region, setRegion] = useState<Region>("All");
  const [serverSort, setServerSort] = useState<ServerSort>("nearest");
  const [job, setJob] = useState<SpeedJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [reattaching, setReattaching] = useState(true);
  const [history, setHistory] = useState<StoredResult[]>([]);
  const [announcement, setAnnouncement] = useState("");
  const startInFlight = useRef(false);
  const stopInFlight = useRef(false);
  const savedJobs = useRef(new Set<string>());
  const refreshedFailedJobs = useRef(new Set<string>());

  const refreshDirectoryAfterFailure = useCallback((failedJob: SpeedJob) => {
    if (
      failedJob.server.provider === "cloudflare" ||
      refreshedFailedJobs.current.has(failedJob.id)
    ) {
      return;
    }
    refreshedFailedJobs.current.add(failedJob.id);
    setQuery("");
    setRegion("All");
    setSelectedServerId(null);
    setDirectoryLoading(true);
    setDirectoryError(null);
    setDirectoryRequest((value) => value + 1);
  }, []);

  const recordCompletedJob = useCallback((completedJob: SpeedJob) => {
    if (!completedJob.result || savedJobs.current.has(completedJob.id)) return;
    savedJobs.current.add(completedJob.id);
    const stored: StoredResult = {
      ...completedJob.result,
      id: completedJob.id,
      completed_at: completedJob.finished_at ?? new Date().toISOString(),
    };
    setHistory((current) => {
      if (current.some((item) => item.id === stored.id)) return current;
      const next = [stored, ...current].slice(0, HISTORY_LIMIT);
      writeHistory(next);
      return next;
    });
  }, []);

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const storedHistory = readHistory();
      storedHistory.forEach((item) => savedJobs.current.add(item.id));
      setHistory(storedHistory);
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  useEffect(() => {
    let disposed = false;
    const controller = new AbortController();

    async function loadSpeedLimits() {
      const storedOptions = readSizeOptions();
      if (storedOptions) {
        setDownloadBytes(storedOptions.download_bytes);
        setUploadBytes(storedOptions.upload_bytes);
      }
      try {
        const response = await fetch(`${API_BASE_URL}/api/system`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) return;
        const payload = (await response.json()) as { limits?: unknown };
        const limits = normalizeSpeedLimits(payload.limits);
        if (!limits || disposed) return;
        const allowedDownloadSizes = availablePresets(
          DOWNLOAD_SIZE_PRESETS,
          limits.min_speed_download_bytes,
          limits.default_speed_download_bytes,
          limits.max_speed_download_bytes,
        );
        const allowedUploadSizes = availablePresets(
          UPLOAD_SIZE_PRESETS,
          limits.min_speed_upload_bytes,
          limits.default_speed_upload_bytes,
          limits.max_speed_upload_bytes,
        );
        setSpeedLimits(limits);
        setDownloadBytes((current) =>
          allowedDownloadSizes.some((preset) => preset.value === current)
            ? current
            : limits.default_speed_download_bytes,
        );
        setUploadBytes((current) =>
          allowedUploadSizes.some((preset) => preset.value === current)
            ? current
            : limits.default_speed_upload_bytes,
        );
      } catch {
        // Standard presets remain available if capability discovery fails.
      }
    }

    void loadSpeedLimits();
    return () => {
      disposed = true;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    const controller = new AbortController();

    async function loadDirectory() {
      try {
        const response = await fetch(`${API_BASE_URL}/api/speed-servers`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(
            await responseError(response, "The public server directory is unavailable."),
          );
        }
        const payload = (await response.json()) as ServerDirectory;
        if (disposed) return;
        setDirectory(payload);
        setDirectoryError(null);
        setSelectedServerId((current) => {
          if (current && payload.servers.some((server) => server.id === current)) {
            return current;
          }
          return (
            payload.servers.find((server) => server.automatic)?.id ??
            payload.servers[0]?.id ??
            null
          );
        });
      } catch (caught) {
        if (disposed || controller.signal.aborted) return;
        setDirectoryError(
          caught instanceof Error
            ? caught.message
            : "Start the local Python service to load public test servers.",
        );
      } finally {
        if (!disposed) setDirectoryLoading(false);
      }
    }

    void loadDirectory();
    return () => {
      disposed = true;
      controller.abort();
    };
  }, [directoryRequest]);

  useEffect(() => {
    let disposed = false;
    const controller = new AbortController();
    const readyTimer = window.setTimeout(async () => {
      const activeJobId = readActiveJobId();
      if (!activeJobId) {
        if (!disposed) setReattaching(false);
        return;
      }

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/speed-jobs/${encodeURIComponent(activeJobId)}`,
          { cache: "no-store", signal: controller.signal },
        );
        if (response.status === 404) {
          forgetActiveJob(activeJobId);
          if (!disposed) {
            setError("The previous speed test has expired. You can start another test.");
          }
          return;
        }
        if (!response.ok) {
          throw new Error(
            await responseError(response, "The previous speed test could not be restored."),
          );
        }
        const restored = (await response.json()) as SpeedJob;
        if (disposed) return;
        setJob(restored);
        setSelectedServerId(restored.server.id);
        if (isSpeedTestOptions(restored.options)) {
          setDownloadBytes(restored.options.download_bytes);
          setUploadBytes(restored.options.upload_bytes);
          writeSizeOptions(restored.options);
        }
        if (isActiveJob(restored)) rememberActiveJob(restored);
        else forgetActiveJob(restored.id);
        if (restored.status === "completed") recordCompletedJob(restored);
        if (restored.status === "failed") {
          setError(restored.error ?? "The previous speed test failed.");
          refreshDirectoryAfterFailure(restored);
        }
      } catch (caught) {
        if (!disposed && !controller.signal.aborted) {
          setError(
            caught instanceof Error
              ? caught.message
              : "The previous speed test could not be restored.",
          );
        }
      } finally {
        if (!disposed) setReattaching(false);
      }
    }, 0);

    return () => {
      disposed = true;
      controller.abort();
      window.clearTimeout(readyTimer);
    };
  }, [recordCompletedJob, refreshDirectoryAfterFailure]);

  const jobId = job?.id;
  const jobStatus = job?.status;
  useEffect(() => {
    if (!jobId || (jobStatus !== "queued" && jobStatus !== "running")) return;
    let disposed = false;
    let inFlight = false;

    async function poll() {
      if (inFlight) return;
      inFlight = true;
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/speed-jobs/${encodeURIComponent(jobId!)}`,
          { cache: "no-store" },
        );
        if (!response.ok) {
          throw new Error(
            await responseError(response, "The speed-test update could not be loaded."),
          );
        }
        const updated = (await response.json()) as SpeedJob;
        if (disposed) return;
        setJob(updated);
        setAnnouncement(PHASE_LABELS[updated.phase]);
        if (isActiveJob(updated)) {
          rememberActiveJob(updated);
        } else {
          forgetActiveJob(updated.id);
          if (updated.status === "completed") {
            recordCompletedJob(updated);
            setAnnouncement(
              updated.result
                ? `Speed test complete. Download ${formatMetric(updated.result.download_mbps, "Mbps")}; upload ${formatMetric(updated.result.upload_mbps, "Mbps")}.`
                : "Speed test complete.",
            );
          } else if (updated.status === "failed") {
            setError(updated.error ?? "The selected public server could not complete the test.");
            setAnnouncement("Speed test failed.");
            refreshDirectoryAfterFailure(updated);
          } else if (updated.status === "cancelled") {
            setAnnouncement("Speed test stopped.");
          }
        }
      } catch (caught) {
        if (!disposed) {
          setError(
            caught instanceof Error
              ? caught.message
              : "The local Python service stopped responding.",
          );
        }
      } finally {
        inFlight = false;
      }
    }

    const timer = window.setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [jobId, jobStatus, recordCompletedJob, refreshDirectoryAfterFailure]);

  const servers = directory?.servers ?? EMPTY_SERVERS;
  const selectedServer =
    servers.find((server) => server.id === selectedServerId) ?? job?.server ?? null;
  const visibleServers = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const filteredServers = servers.filter((server) => {
      if (region !== "All" && regionForServer(server) !== region) return false;
      if (!normalizedQuery) return true;
      return `${server.name} ${server.location ?? ""} ${server.country ?? ""} ${server.sponsor ?? ""} ${server.provider}`
        .toLowerCase()
        .includes(normalizedQuery);
    });
    if (serverSort === "nearest") return filteredServers;
    return sortServersByProvider(filteredServers);
  }, [query, region, serverSort, servers]);
  const downloadSizePresets = useMemo(
    () =>
      availablePresets(
        DOWNLOAD_SIZE_PRESETS,
        speedLimits.min_speed_download_bytes,
        speedLimits.default_speed_download_bytes,
        speedLimits.max_speed_download_bytes,
      ),
    [speedLimits],
  );
  const uploadSizePresets = useMemo(
    () =>
      availablePresets(
        UPLOAD_SIZE_PRESETS,
        speedLimits.min_speed_upload_bytes,
        speedLimits.default_speed_upload_bytes,
        speedLimits.max_speed_upload_bytes,
      ),
    [speedLimits],
  );

  const active = isActiveJob(job);
  const controlsDisabled = active || starting || reattaching;
  const result = job?.result ?? null;
  const phase = job?.phase ?? "queued";
  const progress = Math.max(0, Math.min(100, job?.progress.percent ?? 0));
  const throughputSamples = useMemo(
    () => normalizeThroughputSamples(job?.progress.samples),
    [job?.progress.samples],
  );
  const currentMbps =
    typeof job?.progress.current_mbps === "number" &&
    Number.isFinite(job.progress.current_mbps) &&
    job.progress.current_mbps >= 0
      ? job.progress.current_mbps
      : null;
  const liveTransferPhase =
    active && (phase === "download" || phase === "upload") && currentMbps != null
      ? phase
      : null;
  const selectedTotalBytes = downloadBytes + uploadBytes;
  const activeTotalBytes = job?.options
    ? job.options.download_bytes + job.options.upload_bytes
    : selectedTotalBytes;

  function updateDownloadBytes(value: string) {
    const nextDownloadBytes = Number(value);
    if (!downloadSizePresets.some((preset) => preset.value === nextDownloadBytes)) {
      return;
    }
    setDownloadBytes(nextDownloadBytes);
    writeSizeOptions({
      download_bytes: nextDownloadBytes,
      upload_bytes: uploadBytes,
    });
  }

  function updateUploadBytes(value: string) {
    const nextUploadBytes = Number(value);
    if (!uploadSizePresets.some((preset) => preset.value === nextUploadBytes)) {
      return;
    }
    setUploadBytes(nextUploadBytes);
    writeSizeOptions({
      download_bytes: downloadBytes,
      upload_bytes: nextUploadBytes,
    });
  }

  async function startTest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedServerId || startInFlight.current || active) return;
    startInFlight.current = true;
    setStarting(true);
    setError(null);
    setAnnouncement("Starting speed test.");
    try {
      const response = await fetch(`${API_BASE_URL}/api/speed-jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          server_id: selectedServerId,
          download_bytes: downloadBytes,
          upload_bytes: uploadBytes,
        }),
      });
      if (!response.ok) {
        throw new Error(
          await responseError(response, "The speed test could not be started."),
        );
      }
      const created = (await response.json()) as SpeedJob;
      setJob(created);
      rememberActiveJob(created);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "The speed test could not be started.",
      );
      setAnnouncement("Speed test could not start.");
    } finally {
      startInFlight.current = false;
      setStarting(false);
    }
  }

  async function stopTest() {
    if (!job || !active || stopInFlight.current) return;
    stopInFlight.current = true;
    setStopping(true);
    setError(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/speed-jobs/${encodeURIComponent(job.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        throw new Error(
          await responseError(response, "The speed test could not be stopped."),
        );
      }
      const stopped = (await response.json()) as SpeedJob;
      setJob(stopped);
      forgetActiveJob(stopped.id);
      setAnnouncement("Speed test stopped.");
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "The speed test could not be stopped.",
      );
    } finally {
      stopInFlight.current = false;
      setStopping(false);
    }
  }

  function retryDirectory() {
    setDirectoryLoading(true);
    setDirectoryError(null);
    setDirectoryRequest((value) => value + 1);
  }

  function clearHistory() {
    setHistory([]);
    savedJobs.current.clear();
    try {
      window.localStorage.removeItem(HISTORY_STORAGE_KEY);
    } catch {
      // The visible history is already cleared.
    }
  }

  function useAutomaticServer() {
    const automaticServer = servers.find((server) => server.automatic);
    setQuery("");
    setRegion("All");
    if (automaticServer) {
      setSelectedServerId(automaticServer.id);
      setError(null);
      setAnnouncement("Automatic Cloudflare server selected.");
      return;
    }
    retryDirectory();
    setAnnouncement("Refreshing the public server directory.");
  }

  function useNearestPublicServer() {
    const publicServer = servers.find((server) => !server.automatic);
    setQuery("");
    setRegion("All");
    setServerSort("nearest");
    if (publicServer) {
      setSelectedServerId(publicServer.id);
      setError(null);
      setAnnouncement(`${serverPrimary(publicServer)} selected as the nearest public server.`);
      return;
    }
    retryDirectory();
    setAnnouncement("Refreshing the public server directory.");
  }

  return (
    <>
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {announcement}
      </p>

      <section className={styles.workspace} aria-label="NetSpeed workspace">
        <aside className={styles.serverPanel} aria-labelledby="servers-title">
          <div className={styles.panelHeader}>
            <div>
              <p className={styles.kicker}>Public directory</p>
              <h2 id="servers-title">Choose a server</h2>
            </div>
            <span
              className={`${styles.directoryStatus} ${
                directory?.directory_status === "fresh"
                  ? styles.directoryFresh
                  : directory?.directory_status === "stale"
                    ? styles.directoryStale
                    : ""
              }`}
            >
              <i aria-hidden="true" />
              {directoryLoading
                ? "Loading"
                : directory?.directory_status === "fresh"
                  ? "Live list"
                  : directory?.directory_status === "stale"
                    ? "Cached list"
                    : "Unavailable"}
            </span>
          </div>

          <label className={styles.searchField}>
            <span className="sr-only">Search public speed-test servers</span>
            <span aria-hidden="true">⌕</span>
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search location or provider"
              disabled={directoryLoading || servers.length === 0}
            />
            {query ? (
              <button type="button" onClick={() => setQuery("")} aria-label="Clear search">
                ×
              </button>
            ) : null}
          </label>

          <div className={styles.regionFilters} aria-label="Filter servers by region">
            {REGIONS.map((item) => (
              <button
                type="button"
                key={item}
                className={region === item ? styles.activeFilter : ""}
                onClick={() => setRegion(item)}
                aria-pressed={region === item}
                disabled={servers.length === 0}
              >
                {item}
              </button>
            ))}
          </div>

          <label className={styles.sortField} htmlFor="netspeed-server-sort">
            <span>Sort servers</span>
            <select
              id="netspeed-server-sort"
              value={serverSort}
              onChange={(event) => {
                const nextSort = event.target.value as ServerSort;
                setServerSort(nextSort);
                setAnnouncement(
                  nextSort === "nearest"
                    ? "Servers sorted by nearest measured latency."
                    : "Servers sorted by provider, A to Z.",
                );
              }}
              disabled={directoryLoading || servers.length === 0}
            >
              <option value="nearest">Nearest measured</option>
              <option value="provider">Provider A–Z</option>
            </select>
          </label>

          {directoryError ? (
            <div className={styles.directoryError} role="alert">
              <strong>Python service unavailable</strong>
              <p>{directoryError}</p>
              <button type="button" onClick={retryDirectory}>
                Try again
              </button>
            </div>
          ) : (
            <div
              className={styles.serverList}
              role="radiogroup"
              aria-label={`Public speed-test servers, sorted by ${
                serverSort === "nearest"
                  ? "nearest measured latency"
                  : "provider, A to Z"
              }`}
            >
              {visibleServers.map((server) => {
                const selected = server.id === selectedServerId;
                return (
                  <button
                    type="button"
                    role="radio"
                    aria-checked={selected}
                    key={server.id}
                    className={`${styles.serverRow} ${selected ? styles.serverSelected : ""}`}
                    onClick={() => setSelectedServerId(server.id)}
                    disabled={controlsDisabled}
                  >
                    <span className={styles.radioMark} aria-hidden="true"><i /></span>
                    <span className={styles.serverIdentity}>
                      <strong>
                        {serverPrimary(server)}
                        {server.automatic ? <em>Recommended</em> : null}
                      </strong>
                      <small>{serverSecondary(server)}</small>
                    </span>
                    <span className={styles.serverProvider}>
                      {server.provider === "cloudflare" ? "CF" : "LS"}
                    </span>
                  </button>
                );
              })}
              {!directoryLoading && visibleServers.length === 0 ? (
                <div className={styles.noServers}>
                  <strong>No matching servers</strong>
                  <span>Try another search or region.</span>
                </div>
              ) : null}
              {directoryLoading ? (
                <div className={styles.loadingServers} role="status">
                  Loading the Python-managed server directory…
                </div>
              ) : null}
            </div>
          )}

          <div className={styles.serverPanelFooter}>
            <span>{visibleServers.length} shown</span>
            <span>
              {serverSort === "nearest" ? "Nearest measured first" : "Provider A–Z"}
              {" · HTTPS only"}
            </span>
          </div>
        </aside>

        <section className={styles.testPanel} aria-labelledby="test-title">
          <div className={styles.panelHeader}>
            <div>
              <p className={styles.kicker}>Active test</p>
              <h2 id="test-title">
                {selectedServer ? serverPrimary(selectedServer) : "Select a server"}
              </h2>
            </div>
            <span className={styles.engineBadge}>
              <i aria-hidden="true" /> Python
            </span>
          </div>

          <div className={styles.gaugeArea} data-active={active ? "true" : "false"}>
            <div className={styles.gauge} style={{ "--speed-progress": `${progress}%` } as CSSProperties}>
              <div className={styles.gaugeCore}>
                <span>{job ? PHASE_LABELS[phase] : "Ready"}</span>
                <strong>
                  {result
                    ? result.download_mbps.toLocaleString(undefined, {
                        maximumFractionDigits: result.download_mbps >= 100 ? 0 : 1,
                      })
                    : liveTransferPhase && currentMbps != null
                      ? currentMbps.toLocaleString(undefined, {
                          maximumFractionDigits: currentMbps >= 100 ? 0 : 1,
                        })
                    : active
                      ? Math.round(progress)
                      : "—"}
                </strong>
                <small>
                  {result
                    ? "Mbps download"
                    : liveTransferPhase
                      ? `Mbps ${liveTransferPhase}`
                      : active
                        ? "% complete"
                        : "Mbps"}
                </small>
              </div>
            </div>
          </div>

          <div className={styles.progressBlock}>
            <div>
              <span>{job ? PHASE_LABELS[phase] : "Waiting to start"}</span>
              <strong>{active ? `${Math.round(progress)}%` : result ? "Finished" : "Idle"}</strong>
            </div>
            <progress value={progress} max="100" aria-label="Speed-test progress" />
            <p>
              {active && job
                ? `${formatBytes(job.progress.download_bytes + job.progress.upload_bytes)} of up to ${formatBytes(activeTotalBytes)} transferred`
                : result
                  ? `${formatBytes(result.transferred_bytes)} transferred in ${result.duration_seconds.toLocaleString(undefined, { maximumFractionDigits: 1 })} seconds`
                  : "One active test maximum · selectable transfer size"}
            </p>
          </div>

          {error ? (
            <div className={styles.errorMessage} role="alert">
              <span aria-hidden="true">!</span>
              <p>{error}</p>
              <div className={styles.errorActions}>
                {job?.status === "failed" && job.server.provider !== "cloudflare" ? (
                  <button
                    className={styles.fallbackButton}
                    type="button"
                    onClick={useAutomaticServer}
                  >
                    Use automatic server
                  </button>
                ) : null}
                {job?.status === "failed" && job.server.provider === "cloudflare" ? (
                  <button
                    className={styles.fallbackButton}
                    type="button"
                    onClick={useNearestPublicServer}
                  >
                    Use nearest public server
                  </button>
                ) : null}
                <button
                  className={styles.dismissError}
                  type="button"
                  onClick={() => setError(null)}
                  aria-label="Dismiss error"
                >
                  ×
                </button>
              </div>
            </div>
          ) : null}

          <ThroughputChart
            samples={throughputSamples}
            currentMbps={currentMbps}
            phase={phase}
          />

          <div className={styles.metrics} aria-label="Speed-test measurements">
            <Metric label="Ping" value={formatMetric(result?.ping_ms ?? null, "ms")} symbol="↔" />
            <Metric label="Jitter" value={formatMetric(result?.jitter_ms ?? null, "ms")} symbol="≈" />
            <Metric label="Download" value={formatMetric(result?.download_mbps ?? null, "Mbps")} symbol="↓" />
            <Metric label="Upload" value={formatMetric(result?.upload_mbps ?? null, "Mbps")} symbol="↑" />
          </div>

          <form className={styles.testForm} onSubmit={startTest}>
            <fieldset className={styles.sizeControls} disabled={controlsDisabled}>
              <legend>Transfer size</legend>
              <div className={styles.sizeFields}>
                <label className={styles.sizeField} htmlFor="netspeed-download-size">
                  <span>Download size</span>
                  <select
                    id="netspeed-download-size"
                    value={downloadBytes}
                    onChange={(event) => updateDownloadBytes(event.target.value)}
                    aria-describedby="netspeed-size-guidance"
                  >
                    {downloadSizePresets.map((preset) => (
                      <option key={preset.value} value={preset.value}>
                        {preset.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className={styles.sizeField} htmlFor="netspeed-upload-size">
                  <span>Upload size</span>
                  <select
                    id="netspeed-upload-size"
                    value={uploadBytes}
                    onChange={(event) => updateUploadBytes(event.target.value)}
                    aria-describedby="netspeed-size-guidance"
                  >
                    {uploadSizePresets.map((preset) => (
                      <option key={preset.value} value={preset.value}>
                        {preset.label}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <p id="netspeed-size-guidance" className={styles.sizeGuidance}>
                <strong>Up to {formatBytes(selectedTotalBytes)} total.</strong>{" "}
                Larger samples give fast connections more time to reach full speed
                and use more data.
              </p>
            </fieldset>
            <div className={styles.testActions}>
              <button
                className={styles.startButton}
                type="submit"
                disabled={!selectedServerId || controlsDisabled || directoryLoading}
              >
                <span aria-hidden="true">↗</span>
                {starting ? "Starting…" : result || job?.status === "failed" ? "Test again" : "Start test"}
              </button>
              <button
                className={styles.stopButton}
                type="button"
                disabled={!active || stopping}
                onClick={stopTest}
                aria-label="Stop speed test"
              >
                {stopping ? "Stopping…" : "Stop"}
              </button>
            </div>
          </form>
        </section>
      </section>

      <section className={styles.history} aria-labelledby="history-title">
        <div className={styles.historyHeader}>
          <div>
            <p className={styles.kicker}>This browser</p>
            <h2 id="history-title">Recent results</h2>
          </div>
          {history.length > 0 ? (
            <button type="button" onClick={clearHistory}>Clear history</button>
          ) : null}
        </div>

        {history.length > 0 ? (
          <div className={styles.historyTableWrap}>
            <table className={styles.historyTable}>
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Server</th>
                  <th scope="col">Ping</th>
                  <th scope="col">Download</th>
                  <th scope="col">Upload</th>
                  <th scope="col">Data</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => (
                  <tr key={item.id}>
                    <td>{formatWhen(item.completed_at)}</td>
                    <td>
                      <strong>{serverPrimary(item.server)}</strong>
                      <small>{serverSecondary(item.server)}</small>
                    </td>
                    <td>{formatMetric(item.ping_ms, "ms")}</td>
                    <td>{formatMetric(item.download_mbps, "Mbps")}</td>
                    <td>{formatMetric(item.upload_mbps, "Mbps")}</td>
                    <td>{formatBytes(item.transferred_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className={styles.emptyHistory}>
            <span className={styles.emptyPulse} aria-hidden="true"><i /></span>
            <div>
              <strong>No speed-test results yet</strong>
              <p>Completed tests appear here and stay only in this browser.</p>
            </div>
          </div>
        )}
      </section>
    </>
  );
}

function Metric({ label, value, symbol }: { label: string; value: string; symbol: string }) {
  return (
    <div className={styles.metric}>
      <span><i aria-hidden="true">{symbol}</i>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function ThroughputChart({
  samples,
  currentMbps,
  phase,
}: {
  samples: ThroughputSample[];
  currentMbps: number | null;
  phase: SpeedPhase;
}) {
  const downloadSamples = samples
    .filter((sample) => sample.phase === "download")
    .sort((left, right) => left.elapsed_seconds - right.elapsed_seconds);
  const uploadSamples = samples
    .filter((sample) => sample.phase === "upload")
    .sort((left, right) => left.elapsed_seconds - right.elapsed_seconds);
  const maximumElapsed = Math.max(
    1,
    ...samples.map((sample) => sample.elapsed_seconds),
  );
  const maximumSpeed = Math.max(
    0,
    ...samples.map((sample) => sample.mbps),
    currentMbps ?? 0,
  );
  const xMaximum = niceTimeCeiling(maximumElapsed);
  const yMaximum = niceChartCeiling(maximumSpeed);
  const fractions = [0, 0.25, 0.5, 0.75, 1];
  const yTicks = fractions
    .map((fraction) => yMaximum * fraction)
    .reverse();
  const xTicks = fractions.map((fraction) => xMaximum * fraction);

  const latestDownload = latestSeriesSpeed(
    downloadSamples,
    phase === "download" ? currentMbps : null,
  );
  const latestUpload = latestSeriesSpeed(
    uploadSamples,
    phase === "upload" ? currentMbps : null,
  );
  const peakDownload = peakSeriesSpeed(
    downloadSamples,
    phase === "download" ? currentMbps : null,
  );
  const peakUpload = peakSeriesSpeed(
    uploadSamples,
    phase === "upload" ? currentMbps : null,
  );
  const summary = samples.length
    ? [
        seriesSummary("Download", downloadSamples, latestDownload, peakDownload),
        seriesSummary("Upload", uploadSamples, latestUpload, peakUpload),
      ].join(" ")
    : "No throughput samples yet. Samples appear during the download and upload phases.";

  return (
    <figure className={styles.throughputChart}>
      <div className={styles.chartHeader}>
        <figcaption>Live throughput</figcaption>
        <div className={styles.chartLegend} aria-label="Throughput series">
          <ChartLegendItem
            kind="download"
            label="Download"
            latest={latestDownload}
            peak={peakDownload}
          />
          <ChartLegendItem
            kind="upload"
            label="Upload"
            latest={latestUpload}
            peak={peakUpload}
          />
        </div>
      </div>

      <div className={styles.chartPlotArea}>
        <span className={styles.chartYUnit} aria-hidden="true">Mbps</span>
        <div className={styles.chartYTicks} aria-hidden="true">
          {yTicks.map((tick) => <span key={tick}>{formatAxisValue(tick)}</span>)}
        </div>
        <svg
          className={styles.chartSvg}
          viewBox="0 0 100 56"
          preserveAspectRatio="xMidYMid meet"
          role="img"
          aria-labelledby="netspeed-throughput-title"
          aria-describedby="netspeed-throughput-description"
        >
          <title id="netspeed-throughput-title">
            Download and upload throughput over the current speed test
          </title>
          <desc id="netspeed-throughput-description">{summary}</desc>

          {fractions.map((fraction) => (
            <line
              className={styles.chartGrid}
              key={`horizontal-${fraction}`}
              x1="0"
              x2="100"
              y1={56 - 56 * fraction}
              y2={56 - 56 * fraction}
              vectorEffect="non-scaling-stroke"
            />
          ))}
          {fractions.map((fraction) => (
            <line
              className={styles.chartGrid}
              key={`vertical-${fraction}`}
              x1={100 * fraction}
              x2={100 * fraction}
              y1="0"
              y2="56"
              vectorEffect="non-scaling-stroke"
            />
          ))}

          {downloadSamples.length ? (
            <>
              <path
                className={styles.downloadLine}
                d={chartPath(downloadSamples, xMaximum, yMaximum)}
                vectorEffect="non-scaling-stroke"
              />
              {downloadSamples.map((sample, index) => {
                const point = chartPoint(sample, xMaximum, yMaximum);
                return (
                  <circle
                    className={styles.downloadPoint}
                    key={`download-${sample.elapsed_seconds}-${index}`}
                    cx={point.x}
                    cy={point.y}
                    r="0.7"
                    vectorEffect="non-scaling-stroke"
                  />
                );
              })}
            </>
          ) : null}

          {uploadSamples.length ? (
            <>
              <path
                className={styles.uploadLine}
                d={chartPath(uploadSamples, xMaximum, yMaximum)}
                vectorEffect="non-scaling-stroke"
              />
              {uploadSamples.map((sample, index) => {
                const point = chartPoint(sample, xMaximum, yMaximum);
                return (
                  <rect
                    className={styles.uploadPoint}
                    key={`upload-${sample.elapsed_seconds}-${index}`}
                    x={point.x - 0.7}
                    y={point.y - 0.7}
                    width="1.4"
                    height="1.4"
                    vectorEffect="non-scaling-stroke"
                  />
                );
              })}
            </>
          ) : null}
        </svg>

        {samples.length === 0 ? (
          <p className={styles.chartEmpty}>Speed samples appear during download and upload.</p>
        ) : null}
        <div className={styles.chartXTicks} aria-hidden="true">
          {xTicks.map((tick) => <span key={tick}>{formatAxisValue(tick)}</span>)}
        </div>
        <span className={styles.chartXUnit} aria-hidden="true">Test elapsed (s)</span>
      </div>
    </figure>
  );
}

function ChartLegendItem({
  kind,
  label,
  latest,
  peak,
}: {
  kind: ThroughputPhase;
  label: string;
  latest: number | null;
  peak: number | null;
}) {
  return (
    <span className={styles.legendItem}>
      <i
        className={`${styles.legendLine} ${
          kind === "download" ? styles.legendDownload : styles.legendUpload
        }`}
        aria-hidden="true"
      />
      <span>
        <strong>{label}</strong>
        <small>
          Latest {formatChartSpeed(latest)} · Peak {formatChartSpeed(peak)}
        </small>
      </span>
    </span>
  );
}

function latestSeriesSpeed(
  samples: ThroughputSample[],
  currentMbps: number | null,
) {
  return currentMbps ?? samples.at(-1)?.mbps ?? null;
}

function peakSeriesSpeed(
  samples: ThroughputSample[],
  currentMbps: number | null,
) {
  const maximum = Math.max(
    -1,
    ...samples.map((sample) => sample.mbps),
    currentMbps ?? -1,
  );
  return maximum >= 0 ? maximum : null;
}

function seriesSummary(
  label: string,
  samples: ThroughputSample[],
  latest: number | null,
  peak: number | null,
) {
  if (!samples.length) return `${label} has no samples yet.`;
  return `${label} has ${samples.length} samples; latest ${formatChartSpeed(
    latest,
  )}, peak ${formatChartSpeed(peak)}, through ${formatAxisValue(
    samples.at(-1)?.elapsed_seconds ?? 0,
  )} seconds into the test.`;
}

function niceTimeCeiling(maximum: number) {
  if (!Number.isFinite(maximum) || maximum <= 1) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(maximum));
  const normalized = maximum / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

function formatAxisValue(value: number) {
  return value.toLocaleString(undefined, {
    maximumFractionDigits: value >= 10 ? 0 : value >= 1 ? 1 : 2,
  });
}

function chartPoint(
  sample: ThroughputSample,
  xMaximum: number,
  yMaximum: number,
) {
  return {
    x: Math.max(0, Math.min(100, (sample.elapsed_seconds / xMaximum) * 100)),
    y: Math.max(0, Math.min(56, 56 - (sample.mbps / yMaximum) * 56)),
  };
}

function chartPath(
  samples: ThroughputSample[],
  xMaximum: number,
  yMaximum: number,
) {
  return samples
    .map((sample, index) => {
      const point = chartPoint(sample, xMaximum, yMaximum);
      return `${index === 0 ? "M" : "L"}${point.x.toFixed(3)} ${point.y.toFixed(3)}`;
    })
    .join(" ");
}
