"use client";

import {
  FormEvent,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import styles from "./netports.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const ACTIVE_JOB_STORAGE_KEY = "better-network-tools.netports.active-job-id";
const LEGACY_ACTIVE_JOB_STORAGE_KEY = "better-network-tools.netport.active-job-id";
const POLL_INTERVAL_MS = 700;

type PortJobStatus =
  | "queued"
  | "resolving"
  | "running"
  | "completed"
  | "cancelled"
  | "failed";

type PortResult = {
  port: number;
  service: string | null;
  banner: string | null;
  http_status: number | null;
  http_server: string | null;
  latency_ms: number;
};

type PortJob = {
  id: string;
  status: PortJobStatus;
  target: string;
  resolved_address: string | null;
  address_family: "IPv4" | "IPv6" | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  options: {
    port_spec: string;
    total_ports: number;
    timeout: number;
    concurrency: number;
    collect_banners: boolean;
  };
  progress: {
    total_ports: number;
    scanned_ports: number;
    open_ports: number;
    closed_ports: number;
    timed_out_ports: number;
    error_ports: number;
    percent: number;
  };
  results: PortResult[];
  results_truncated: boolean;
  error: string | null;
  cancel_requested: boolean;
};

type PresetKey = "common" | "web" | "remote" | "databases" | "all";
type SortKey = "port" | "service" | "latency";
type SortDirection = "ascending" | "descending";

const presets: Record<
  PresetKey,
  { label: string; note: string; short: string; ports: string }
> = {
  common: {
    label: "Common 100",
    note: "A balanced first pass across familiar infrastructure and application ports.",
    short: "100 ports",
    ports:
      "7,9,13,21-23,25,26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6646,7070,8000,8008-8009,8080-8082,8443,8888,9100,9999-10000,32768,49152-49157",
  },
  web: {
    label: "Web",
    note: "Common HTTP, HTTPS, proxy, dashboard, and alternate application ports.",
    short: "18 ports",
    ports: "80,443,3000,3128,5000,5601,7001,7443,8000,8008,8080-8081,8088,8443,8888,9000,9090,9200",
  },
  remote: {
    label: "Remote / admin",
    note: "Interactive access, management, directory, file-sharing, and monitoring services.",
    short: "23 ports",
    ports: "22-23,111,135,139,161-162,389,443,445,514,548,623,636,873,2049,3389,5900,5985-5986,8291,9100,10000",
  },
  databases: {
    label: "Databases",
    note: "Frequently used relational, document, cache, search, and messaging endpoints.",
    short: "17 ports",
    ports: "1433,1521,2379,3306,5432,5672,5984,6379,7474,7687,8529,9042,9200,11211,15672,27017,28015",
  },
  all: {
    label: "All TCP",
    note: "Every TCP port. This is intentionally slower and creates substantial connection traffic.",
    short: "65,535 ports",
    ports: "1-65535",
  },
};

const activeStatuses = new Set<PortJobStatus>([
  "queued",
  "resolving",
  "running",
]);

function isActiveJob(job: PortJob) {
  return activeStatuses.has(job.status);
}

function statusLabel(status: PortJobStatus) {
  return {
    queued: "Queued",
    resolving: "Resolving target",
    running: "Scanning",
    completed: "Completed",
    cancelled: "Stopped",
    failed: "Failed",
  }[status];
}

function readActiveJobId() {
  try {
    const activeJobId = window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY);
    if (activeJobId) return activeJobId;

    const legacyJobId = window.localStorage.getItem(LEGACY_ACTIVE_JOB_STORAGE_KEY);
    if (legacyJobId) {
      window.localStorage.setItem(ACTIVE_JOB_STORAGE_KEY, legacyJobId);
      window.localStorage.removeItem(LEGACY_ACTIVE_JOB_STORAGE_KEY);
    }
    return legacyJobId;
  } catch {
    return null;
  }
}

function rememberActiveJob(job: PortJob) {
  if (!isActiveJob(job)) return;
  try {
    window.localStorage.setItem(ACTIVE_JOB_STORAGE_KEY, job.id);
    window.localStorage.removeItem(LEGACY_ACTIVE_JOB_STORAGE_KEY);
  } catch {
    // Reattachment is optional when browser storage is unavailable.
  }
}

function forgetActiveJob(jobId: string) {
  try {
    if (window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY) === jobId) {
      window.localStorage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    }
    if (window.localStorage.getItem(LEGACY_ACTIVE_JOB_STORAGE_KEY) === jobId) {
      window.localStorage.removeItem(LEGACY_ACTIVE_JOB_STORAGE_KEY);
    }
  } catch {
    // A completed scan needs no browser storage cleanup when storage is unavailable.
  }
}

async function responseError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      detail?: string | { message?: string } | Array<{ msg?: string }>;
    };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return (
        payload.detail.map((item) => item.msg).filter(Boolean).join(" ") ||
        fallback
      );
    }
    if (payload.detail?.message) return payload.detail.message;
  } catch {
    // Use the status-aware fallback when the API response is not JSON.
  }
  return fallback;
}

function validTarget(value: string) {
  if (!value || value.length > 253) return false;
  if (/\s|[\u0000-\u001f\u007f]/.test(value)) return false;
  if (/[\\/@?#]/.test(value) || value.includes("://")) return false;
  if (value.startsWith("-") || value.startsWith("[") || value.endsWith("]")) {
    return false;
  }
  return true;
}

function analyzePortSpec(value: string): {
  valid: boolean;
  total: number;
  message: string;
} {
  const trimmed = value.trim();
  if (!trimmed) {
    return { valid: false, total: 0, message: "Enter at least one TCP port." };
  }

  const intervals: Array<[number, number]> = [];
  for (const rawToken of trimmed.split(",")) {
    const token = rawToken.trim();
    if (!token) {
      return {
        valid: false,
        total: 0,
        message: "Remove empty entries between commas.",
      };
    }
    const match = /^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/.exec(token);
    if (!match) {
      return {
        valid: false,
        total: 0,
        message: `“${token.slice(0, 24)}” is not a port or port range.`,
      };
    }
    const first = Number(match[1]);
    const last = match[2] ? Number(match[2]) : first;
    if (first < 1 || first > 65535 || last < 1 || last > 65535) {
      return {
        valid: false,
        total: 0,
        message: "TCP ports must be between 1 and 65535.",
      };
    }
    if (first > last) {
      return {
        valid: false,
        total: 0,
        message: `Range ${first}-${last} must run from lower to higher.`,
      };
    }
    intervals.push([first, last]);
  }

  intervals.sort((left, right) => left[0] - right[0] || left[1] - right[1]);
  let total = 0;
  let currentStart = intervals[0][0];
  let currentEnd = intervals[0][1];
  for (let index = 1; index < intervals.length; index += 1) {
    const [start, end] = intervals[index];
    if (start <= currentEnd + 1) {
      currentEnd = Math.max(currentEnd, end);
    } else {
      total += currentEnd - currentStart + 1;
      currentStart = start;
      currentEnd = end;
    }
  }
  total += currentEnd - currentStart + 1;
  return {
    valid: true,
    total,
    message: `${total.toLocaleString()} unique TCP ${total === 1 ? "port" : "ports"}`,
  };
}

function csvCell(value: string | number | null) {
  let rendered = value == null ? "" : String(value);
  if (/^[\t\r ]*[=+\-@]/.test(rendered)) rendered = `'${rendered}`;
  return `"${rendered.replaceAll('"', '""')}"`;
}

function downloadBlob(contents: string, type: string, filename: string) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function filenameTarget(target: string) {
  return target.replace(/[^a-z0-9._-]+/gi, "-").replace(/^-+|-+$/g, "") || "target";
}

function formatDate(value: string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(parsed);
}

export function NetPortsClient() {
  const [target, setTarget] = useState("");
  const [portSpec, setPortSpec] = useState(presets.common.ports);
  const [timeoutInput, setTimeoutInput] = useState("0.75");
  const [concurrencyInput, setConcurrencyInput] = useState("128");
  const [collectBanners, setCollectBanners] = useState(false);
  const [job, setJob] = useState<PortJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [targetInvalid, setTargetInvalid] = useState(false);
  const [portsInvalid, setPortsInvalid] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("port");
  const [sortDirection, setSortDirection] =
    useState<SortDirection>("ascending");
  const startInFlight = useRef(false);
  const stopInFlight = useRef(false);

  const jobId = job?.id;
  const isActive = Boolean(job && isActiveJob(job));
  const controlsDisabled = submitting || isActive;
  const portAnalysis = useMemo(() => analyzePortSpec(portSpec), [portSpec]);
  const selectedPreset = (Object.keys(presets) as PresetKey[]).find(
    (key) => presets[key].ports === portSpec.trim(),
  );

  useEffect(() => {
    const storedJobId = readActiveJobId();
    if (!storedJobId) return;

    let disposed = false;
    const controller = new AbortController();

    async function restoreJob() {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/port-jobs/${encodeURIComponent(storedJobId!)}`,
          { cache: "no-store", signal: controller.signal },
        );
        if (response.status === 404) {
          forgetActiveJob(storedJobId!);
          return;
        }
        if (!response.ok) {
          throw new Error(
            await responseError(
              response,
              "The saved port scan could not be restored.",
            ),
          );
        }
        const restored = (await response.json()) as PortJob;
        if (isActiveJob(restored)) rememberActiveJob(restored);
        else forgetActiveJob(restored.id);
        if (!disposed) {
          setJob(restored);
          setTarget(restored.target);
          setPortSpec(restored.options.port_spec);
          setTimeoutInput(String(restored.options.timeout));
          setConcurrencyInput(String(restored.options.concurrency));
          setCollectBanners(restored.options.collect_banners);
          setError(restored.status === "failed" ? restored.error : null);
        }
      } catch (caught) {
        if (
          !disposed &&
          !(caught instanceof DOMException && caught.name === "AbortError")
        ) {
          setError(
            caught instanceof TypeError
              ? "The local port engine is offline. A saved scan can be restored when it is running again."
              : caught instanceof Error
                ? caught.message
                : "Unable to restore the saved port scan.",
          );
        }
      }
    }

    void restoreJob();
    return () => {
      disposed = true;
      controller.abort();
    };
  }, []);

  useEffect(() => {
    if (!jobId || !isActive) return;
    const activeJobId = jobId;
    let disposed = false;
    let timer: number | undefined;
    const controller = new AbortController();

    async function refresh() {
      let shouldContinue = true;
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/port-jobs/${encodeURIComponent(activeJobId)}`,
          { cache: "no-store", signal: controller.signal },
        );
        if (response.status === 404) {
          shouldContinue = false;
          forgetActiveJob(activeJobId);
          if (!disposed) {
            setJob(null);
            setError(
              "This saved port scan is no longer available. Configure a new scan to continue.",
            );
          }
          return;
        }
        if (!response.ok) {
          throw new Error(
            await responseError(
              response,
              "The port engine stopped reporting this scan.",
            ),
          );
        }
        const nextJob = (await response.json()) as PortJob;
        shouldContinue = isActiveJob(nextJob);
        if (shouldContinue) rememberActiveJob(nextJob);
        else forgetActiveJob(nextJob.id);
        if (!disposed) {
          setJob(nextJob);
          setError(
            nextJob.status === "failed"
              ? nextJob.error ?? "The port scan could not be completed."
              : null,
          );
        }
      } catch (caught) {
        if (
          !disposed &&
          !(caught instanceof DOMException && caught.name === "AbortError")
        ) {
          setError(
            caught instanceof TypeError
              ? "The local port engine is offline. Start it and NetPorts will continue polling."
              : caught instanceof Error
                ? caught.message
                : "Unable to refresh the port scan.",
          );
        }
      } finally {
        if (!disposed && shouldContinue && !controller.signal.aborted) {
          timer = window.setTimeout(refresh, POLL_INTERVAL_MS);
        }
      }
    }

    void refresh();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      controller.abort();
    };
  }, [isActive, jobId]);

  const visibleResults = useMemo(() => {
    const query = filter.trim().toLocaleLowerCase();
    const filtered = (job?.results ?? []).filter((result) => {
      if (!query) return true;
      return [
        String(result.port),
        result.service,
        result.banner,
        result.http_server,
        result.http_status == null ? null : String(result.http_status),
      ]
        .filter((value): value is string => Boolean(value))
        .join(" ")
        .toLocaleLowerCase()
        .includes(query);
    });

    const direction = sortDirection === "ascending" ? 1 : -1;
    return filtered.sort((left, right) => {
      if (sortKey === "port") return (left.port - right.port) * direction;
      if (sortKey === "latency") {
        return (left.latency_ms - right.latency_ms) * direction;
      }
      return (
        (left.service ?? "￿").localeCompare(right.service ?? "￿") *
          direction ||
        (left.port - right.port) * direction
      );
    });
  }, [filter, job?.results, sortDirection, sortKey]);

  function choosePreset(key: PresetKey) {
    setPortSpec(presets[key].ports);
    setPortsInvalid(false);
  }

  function changeSort(nextKey: SortKey) {
    if (sortKey === nextKey) {
      setSortDirection((current) =>
        current === "ascending" ? "descending" : "ascending",
      );
    } else {
      setSortKey(nextKey);
      setSortDirection("ascending");
    }
  }

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (startInFlight.current || isActive) return;

    startInFlight.current = true;
    setError(null);
    setTargetInvalid(false);
    setPortsInvalid(false);
    const normalizedTarget = target.trim();
    const timeout = Number(timeoutInput);
    const concurrency = Number(concurrencyInput);

    if (!validTarget(normalizedTarget)) {
      setTargetInvalid(true);
      setError(
        "Enter a hostname or IP address without a URL, path, spaces, credentials, or IPv6 brackets.",
      );
      startInFlight.current = false;
      return;
    }
    if (!portAnalysis.valid) {
      setPortsInvalid(true);
      setError(portAnalysis.message);
      startInFlight.current = false;
      return;
    }
    if (!Number.isFinite(timeout) || timeout < 0.05 || timeout > 10) {
      setError("Connection timeout must be between 0.05 and 10 seconds.");
      startInFlight.current = false;
      return;
    }
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 128) {
      setError("Concurrency must be a whole number from 1 to 128.");
      startInFlight.current = false;
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/port-jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: normalizedTarget,
          ports: portSpec.trim(),
          timeout,
          concurrency,
          collect_banners: collectBanners,
        }),
      });
      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `The port engine rejected the request (${response.status}).`,
          ),
        );
      }
      const nextJob = (await response.json()) as PortJob;
      if (isActiveJob(nextJob)) rememberActiveJob(nextJob);
      else forgetActiveJob(nextJob.id);
      setFilter("");
      setSortKey("port");
      setSortDirection("ascending");
      setJob(nextJob);
      setError(
        nextJob.status === "failed"
          ? nextJob.error ?? "The port scan could not be started."
          : null,
      );
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local port engine is offline. Start Better Network Tools locally, then try again."
          : caught instanceof Error
            ? caught.message
            : "Unable to start the port scan.",
      );
    } finally {
      startInFlight.current = false;
      setSubmitting(false);
    }
  }

  async function stopScan() {
    if (
      !job ||
      !isActive ||
      job.cancel_requested ||
      stopInFlight.current
    ) {
      return;
    }

    stopInFlight.current = true;
    setStopping(true);
    setError(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/port-jobs/${encodeURIComponent(job.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        throw new Error(
          await responseError(response, "The port scan could not be stopped."),
        );
      }
      const stoppedJob = (await response.json()) as PortJob;
      if (isActiveJob(stoppedJob)) rememberActiveJob(stoppedJob);
      else forgetActiveJob(stoppedJob.id);
      setJob(stoppedJob);
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local port engine is offline. The stop request could not be confirmed."
          : caught instanceof Error
            ? caught.message
            : "Unable to stop the port scan.",
      );
    } finally {
      stopInFlight.current = false;
      setStopping(false);
    }
  }

  function exportCsv() {
    if (!job?.results.length) return;
    const rows: Array<Array<string | number | null>> = [
      [
        "Target",
        "Resolved address",
        "Address family",
        "Port",
        "Service",
        "Latency (ms)",
        "Banner",
        "HTTP status",
        "HTTP server",
      ],
      ...job.results.map((result) => [
        job.target,
        job.resolved_address,
        job.address_family,
        result.port,
        result.service,
        result.latency_ms,
        result.banner,
        result.http_status,
        result.http_server,
      ]),
    ];
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    downloadBlob(
      `\ufeff${csv}`,
      "text/csv;charset=utf-8",
      `netports-${filenameTarget(job.target)}.csv`,
    );
  }

  function exportJson() {
    if (!job?.results.length) return;
    downloadBlob(
      `${JSON.stringify(
        {
          exported_at: new Date().toISOString(),
          scan: {
            id: job.id,
            status: job.status,
            target: job.target,
            resolved_address: job.resolved_address,
            address_family: job.address_family,
            created_at: job.created_at,
            started_at: job.started_at,
            finished_at: job.finished_at,
            options: job.options,
            progress: job.progress,
            results: job.results,
          },
        },
        null,
        2,
      )}\n`,
      "application/json;charset=utf-8",
      `netports-${filenameTarget(job.target)}.json`,
    );
  }

  const statusClass = job
    ? {
        queued: styles.statusQueued,
        resolving: styles.statusResolving,
        running: styles.statusRunning,
        completed: styles.statusCompleted,
        cancelled: styles.statusStopped,
        failed: styles.statusFailed,
      }[job.status]
    : styles.statusQueued;
  const progressPercent = Math.max(0, Math.min(job?.progress.percent ?? 0, 100));
  const announcement = job
    ? `${statusLabel(job.status)}. ${job.progress.scanned_ports.toLocaleString()} of ${job.progress.total_ports.toLocaleString()} ports checked; ${job.progress.open_ports.toLocaleString()} open.`
    : "NetPorts is ready for an authorized target.";

  return (
    <div className={styles.workspace}>
      <aside className={styles.controlPanel} aria-labelledby="netports-scan-title">
        <div className={styles.panelHeading}>
          <div>
            <span>01 / Target</span>
            <h2 id="netports-scan-title">Configure scan</h2>
            <p>Define one destination and an intentional TCP port scope.</p>
          </div>
          <code>TCP connect</code>
        </div>

        <form className={styles.form} onSubmit={startScan}>
          <label className={styles.field} htmlFor="netports-target">
            <span>Hostname or IP address</span>
            <input
              id="netports-target"
              name="target"
              value={target}
              onChange={(event) => {
                setTarget(event.target.value);
                setTargetInvalid(false);
              }}
              placeholder="192.168.1.10 or server.example.test"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              disabled={controlsDisabled}
              aria-invalid={targetInvalid}
              aria-describedby={
                error ? "netports-target-help netports-error" : "netports-target-help"
              }
            />
            <small id="netports-target-help">
              One hostname, IPv4 address, or IPv6 address; no URL or subnet.
            </small>
          </label>

          <fieldset className={styles.presets} disabled={controlsDisabled}>
            <legend>Port preset</legend>
            <div className={styles.presetGrid}>
              {(Object.keys(presets) as PresetKey[]).map((key) => {
                const preset = presets[key];
                return (
                  <button
                    className={selectedPreset === key ? styles.presetActive : ""}
                    type="button"
                    key={key}
                    onClick={() => choosePreset(key)}
                    aria-pressed={selectedPreset === key}
                  >
                    <span>
                      <strong>{preset.label}</strong>
                      <small>{preset.note}</small>
                    </span>
                    <em>{preset.short}</em>
                  </button>
                );
              })}
            </div>
          </fieldset>

          <label className={styles.field} htmlFor="netports-ports">
            <span>TCP ports</span>
            <textarea
              id="netports-ports"
              name="ports"
              value={portSpec}
              onChange={(event) => {
                setPortSpec(event.target.value);
                setPortsInvalid(false);
              }}
              rows={3}
              maxLength={2048}
              disabled={controlsDisabled}
              spellCheck={false}
              aria-invalid={portsInvalid || !portAnalysis.valid}
              aria-describedby={
                error ? "netports-port-help netports-error" : "netports-port-help"
              }
            />
            <small
              id="netports-port-help"
              className={portAnalysis.valid ? styles.validHint : undefined}
            >
              {portAnalysis.message}. Use commas and inclusive ranges, such as
              22,80,443,8000-8010.
            </small>
          </label>

          <div className={styles.tuningGrid}>
            <label className={styles.numberField} htmlFor="netports-timeout">
              <span>Connection timeout</span>
              <div className={styles.numberControl}>
                <input
                  id="netports-timeout"
                  type="number"
                  inputMode="decimal"
                  min="0.05"
                  max="10"
                  step="0.05"
                  value={timeoutInput}
                  onChange={(event) => setTimeoutInput(event.target.value)}
                  disabled={controlsDisabled}
                />
                <span>sec</span>
              </div>
              <small>Per connection</small>
            </label>
            <label className={styles.numberField} htmlFor="netports-concurrency">
              <span>Concurrency</span>
              <div className={styles.numberControl}>
                <input
                  id="netports-concurrency"
                  type="number"
                  inputMode="numeric"
                  min="1"
                  max="128"
                  step="1"
                  value={concurrencyInput}
                  onChange={(event) => setConcurrencyInput(event.target.value)}
                  disabled={controlsDisabled}
                />
                <span>max</span>
              </div>
              <small>Parallel attempts</small>
            </label>
          </div>

          <label className={styles.bannerOption}>
            <input
              type="checkbox"
              checked={collectBanners}
              onChange={(event) => setCollectBanners(event.target.checked)}
              disabled={controlsDisabled}
            />
            <span>
              <strong>Collect safe service banners</strong>
              <small>
                Read a short, bounded greeting from open services. This may send
                a minimal HTTP HEAD request to familiar web ports.
              </small>
            </span>
            <em>{collectBanners ? "On" : "Off"}</em>
          </label>

          <div className={styles.authorizationNote}>
            <span aria-hidden="true">!</span>
            <p>
              Starting confirms you are authorized to scan this target. All TCP
              is a high-volume profile; narrow the range whenever possible.
            </p>
          </div>

          {error ? (
            <div className={styles.errorBanner} role="alert" id="netports-error">
              <span aria-hidden="true">!</span>
              <div>
                <strong>NetPorts needs attention</strong>
                <p>{error}</p>
              </div>
            </div>
          ) : null}

          <div className={styles.actions}>
            {isActive ? (
              <button
                className={styles.stopButton}
                type="button"
                onClick={stopScan}
                disabled={stopping || job?.cancel_requested}
              >
                {stopping || job?.cancel_requested ? "Stopping…" : "Stop scan"}
              </button>
            ) : (
              <button
                className={styles.startButton}
                type="submit"
                disabled={submitting}
              >
                {submitting ? "Starting…" : "Start TCP scan"}
                <span aria-hidden="true">→</span>
              </button>
            )}
            <span>Runs from the local Python service</span>
          </div>
        </form>
      </aside>

      <section className={styles.resultsPanel} aria-labelledby="netports-results-title">
        <p className="sr-only" aria-live="polite">
          {announcement}
        </p>
        <div className={styles.resultsHeading}>
          <div>
            <span>02 / Results</span>
            <h2 id="netports-results-title">Open TCP services</h2>
            <p>
              {job
                ? `${job.target}${job.resolved_address ? ` · ${job.resolved_address}` : ""}`
                : "Open ports will appear as the local engine finds them."}
            </p>
          </div>
          {job?.results.length ? (
            <div className={styles.exportActions} aria-label="Export scan results">
              <button type="button" onClick={exportCsv}>
                Export CSV
              </button>
              <button type="button" onClick={exportJson}>
                Export JSON
              </button>
            </div>
          ) : null}
        </div>

        {job ? (
          <>
            <div className={styles.scanStatus}>
              <div className={styles.statusTopline}>
                <span className={`${styles.statusBadge} ${statusClass}`}>
                  <i aria-hidden="true" />
                  {statusLabel(job.status)}
                </span>
                <strong>{Math.round(progressPercent)}%</strong>
              </div>
              <progress
                value={progressPercent}
                max="100"
                aria-label="Port scan progress"
              >
                {progressPercent}%
              </progress>
              <div className={styles.progressMeta}>
                <span>
                  {job.progress.scanned_ports.toLocaleString()} of{" "}
                  {job.progress.total_ports.toLocaleString()} ports checked
                </span>
                <span>
                  {job.address_family ?? "Address pending"}
                  {job.finished_at ? ` · ${formatDate(job.finished_at)}` : ""}
                </span>
              </div>
            </div>

            <div className={styles.summaryGrid}>
              <article>
                <span>Open</span>
                <strong>{job.progress.open_ports.toLocaleString()}</strong>
                <small>Accepting TCP</small>
              </article>
              <article>
                <span>Closed</span>
                <strong>{job.progress.closed_ports.toLocaleString()}</strong>
                <small>Refused</small>
              </article>
              <article>
                <span>Timed out</span>
                <strong>{job.progress.timed_out_ports.toLocaleString()}</strong>
                <small>No response</small>
              </article>
              <article>
                <span>Errors</span>
                <strong>{job.progress.error_ports.toLocaleString()}</strong>
                <small>Local failures</small>
              </article>
              <article>
                <span>Remaining</span>
                <strong>
                  {Math.max(
                    0,
                    job.progress.total_ports - job.progress.scanned_ports,
                  ).toLocaleString()}
                </strong>
                <small>Still queued</small>
              </article>
            </div>

            {job.results_truncated ? (
              <div className={styles.truncationNotice} role="status">
                <span aria-hidden="true">i</span>
                <p>
                  The scan found {job.progress.open_ports.toLocaleString()} open
                  ports, but retained details for the first{" "}
                  {job.results.length.toLocaleString()}. Exports include only the
                  retained rows shown by NetPorts.
                </p>
              </div>
            ) : null}

            <div className={styles.resultToolbar}>
              <label htmlFor="netports-filter">
                <span>Filter open ports</span>
                <input
                  id="netports-filter"
                  type="search"
                  placeholder="Port, service, banner…"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                />
              </label>
              <span>
                {visibleResults.length.toLocaleString()} of{" "}
                {job.results.length.toLocaleString()} shown
              </span>
            </div>

            {visibleResults.length ? (
              <div
                className={styles.tableRegion}
                tabIndex={0}
                role="region"
                aria-label="Open TCP port results"
              >
                <table className={styles.resultsTable}>
                  <thead>
                    <tr>
                      <th scope="col" aria-sort={sortKey === "port" ? sortDirection : "none"}>
                        <button type="button" onClick={() => changeSort("port")}>
                          Port <span aria-hidden="true">↕</span>
                        </button>
                      </th>
                      <th scope="col" aria-sort={sortKey === "service" ? sortDirection : "none"}>
                        <button type="button" onClick={() => changeSort("service")}>
                          Service <span aria-hidden="true">↕</span>
                        </button>
                      </th>
                      <th scope="col">Service evidence</th>
                      <th scope="col">HTTP</th>
                      <th scope="col" aria-sort={sortKey === "latency" ? sortDirection : "none"}>
                        <button type="button" onClick={() => changeSort("latency")}>
                          Connect <span aria-hidden="true">↕</span>
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleResults.map((result) => (
                      <tr key={result.port}>
                        <th scope="row">
                          <strong>{result.port}</strong>
                          <span>/tcp</span>
                        </th>
                        <td>
                          <span className={styles.serviceName}>
                            {result.service ?? "Unknown"}
                          </span>
                        </td>
                        <td>
                          {result.banner || result.http_server ? (
                            <div className={styles.evidenceCell}>
                              {result.banner ? <code>{result.banner}</code> : null}
                              {result.http_server ? (
                                <span>Server: {result.http_server}</span>
                              ) : null}
                            </div>
                          ) : (
                            <span className={styles.emptyValue}>
                              {job.options.collect_banners
                                ? "No banner returned"
                                : "Banner collection off"}
                            </span>
                          )}
                        </td>
                        <td>
                          {result.http_status == null ? (
                            <span className={styles.emptyValue}>—</span>
                          ) : (
                            <span className={styles.httpStatus}>
                              {result.http_status}
                            </span>
                          )}
                        </td>
                        <td className={styles.latencyCell}>
                          {result.latency_ms.toFixed(1)} ms
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className={styles.compactEmpty}>
                <span aria-hidden="true">◎</span>
                <div>
                  <h3>
                    {job.results.length
                      ? "No open ports match that filter"
                      : job.status === "completed"
                        ? "No open TCP ports found"
                        : job.status === "cancelled"
                          ? "Scan stopped before an open port was found"
                          : "Listening for open ports"}
                  </h3>
                  <p>
                    {job.results.length
                      ? "Try a port number, service name, or banner fragment."
                      : job.status === "completed"
                        ? "The target did not accept a TCP connection on the selected ports."
                        : "Results appear here immediately; closed and timed-out ports stay summarized above."}
                  </p>
                </div>
              </div>
            )}

            <footer className={styles.resultFooter}>
              <span>
                Scan ID <code>{job.id}</code>
              </span>
              <span>
                Timeout {job.options.timeout}s · concurrency {job.options.concurrency}
              </span>
            </footer>
          </>
        ) : (
          <div className={styles.emptyState}>
            <div className={styles.portFieldArt} aria-hidden="true">
              <span>21</span>
              <span>22</span>
              <span>80</span>
              <span>443</span>
              <i />
            </div>
            <span className={styles.emptyKicker}>Awaiting target</span>
            <h3>Find the services that are listening</h3>
            <p>
              NetPorts resolves one target, opens bounded TCP connections, and
              reports open ports as soon as they answer. Nothing is stored until
              you deliberately export it.
            </p>
            <div className={styles.methodRow} aria-label="NetPorts scan properties">
              <span>TCP</span>
              <span>IPv4</span>
              <span>IPv6</span>
              <span>Bounded</span>
              <span>Cancellable</span>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
