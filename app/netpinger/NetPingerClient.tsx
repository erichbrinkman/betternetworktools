"use client";

import type { CSSProperties, FormEvent } from "react";
import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import styles from "./netpinger.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const ACTIVE_JOB_STORAGE_KEY = "better-network-tools.netpinger.active-job-id";
const RESULT_COLUMN_COUNT = 10;
const REPLY_HISTORY_LIMIT = 60;
const REPLY_CHART_SCALE = 100;

type PingJobStatus =
  | "queued"
  | "running"
  | "completed"
  | "cancelled"
  | "failed";

type PingTargetStatus = "pending" | "up" | "down" | "error";
type ReverseDnsStatus =
  | "not_requested"
  | "pending"
  | "resolved"
  | "not_found"
  | "unavailable";

type PingTarget = {
  target: string;
  resolved_address: string | null;
  address_family: "IPv4" | "IPv6" | null;
  reverse_hostname?: string | null;
  reverse_dns_status?: ReverseDnsStatus;
  status: PingTargetStatus;
  sent: number;
  received: number;
  failed: number;
  latency_samples: number;
  consecutive_successes: number;
  max_consecutive_successes: number;
  consecutive_failures: number;
  max_consecutive_failures: number;
  reply_time_history_ms?: Array<number | null>;
  success_rate: number;
  loss_percent: number;
  last_ms: number | null;
  avg_ms: number | null;
  min_ms: number | null;
  max_ms: number | null;
  last_checked: string | null;
  error: string | null;
};

type PingJob = {
  id: string;
  status: PingJobStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  options: {
    count: number;
    continuous: boolean;
    interval: number;
    timeout: number;
  };
  progress: {
    total_probes: number | null;
    completed_probes: number;
    percent: number | null;
  };
  targets: PingTarget[];
  error: string | null;
  cancel_requested: boolean;
};

function isActiveJob(job: PingJob) {
  return job.status === "queued" || job.status === "running";
}

function readActiveJobId() {
  try {
    return window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY);
  } catch {
    return null;
  }
}

function rememberActiveJob(job: PingJob) {
  if (!job.options.continuous || !isActiveJob(job)) return;
  try {
    window.localStorage.setItem(ACTIVE_JOB_STORAGE_KEY, job.id);
  } catch {
    // Monitoring still works when browser storage is unavailable.
  }
}

function forgetActiveJob(jobId: string) {
  try {
    if (window.localStorage.getItem(ACTIVE_JOB_STORAGE_KEY) === jobId) {
      window.localStorage.removeItem(ACTIVE_JOB_STORAGE_KEY);
    }
  } catch {
    // There is no stored identifier to clear when storage is unavailable.
  }
}

const jobLabels: Record<PingJobStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  cancelled: "Stopped",
  failed: "Failed",
};

const targetLabels: Record<PingTargetStatus, string> = {
  pending: "Pending",
  up: "Up",
  down: "Down",
  error: "Error",
};

function parseTargets(value: string) {
  const entries = value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const seen = new Set<string>();

  return entries.filter((entry) => {
    const key = entry.toLocaleLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function countEnteredTargets(value: string) {
  return value
    .split(/[\n,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean).length;
}

function formatLatency(value: number | null) {
  if (value == null) return "—";
  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: 1,
    minimumFractionDigits: value < 10 ? 1 : 0,
  })} ms`;
}

function formatPercent(value: number) {
  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: 1,
  })}%`;
}

function ReverseDnsIdentity({ target }: { target: PingTarget }) {
  if (
    target.reverse_dns_status === "resolved" &&
    target.reverse_hostname
  ) {
    return (
      <span
        className={styles.reverseDnsLine}
        data-reverse-dns-status="resolved"
      >
        <span aria-hidden="true">PTR: </span>
        <span className="sr-only">Reverse DNS hostname: </span>
        {target.reverse_hostname}
      </span>
    );
  }

  if (target.reverse_dns_status === "pending") {
    return (
      <span
        className={styles.reverseDnsLine}
        data-reverse-dns-status="pending"
      >
        PTR lookup pending
      </span>
    );
  }

  if (target.reverse_dns_status === "not_found") {
    return (
      <span
        className={styles.reverseDnsLine}
        data-reverse-dns-status="not-found"
      >
        No PTR record
      </span>
    );
  }

  if (target.reverse_dns_status === "unavailable") {
    return (
      <span
        className={styles.reverseDnsLine}
        data-reverse-dns-status="unavailable"
      >
        PTR unavailable
      </span>
    );
  }

  return null;
}

type ReplySparklineStyle = CSSProperties & {
  "--reply-sparkline": string;
};

type ReplyChartSampleStyle = CSSProperties & {
  "--sample-x": string;
  "--sample-y": string;
};

type ReplyChartPoint = {
  x: number;
  y: number;
};

function replySparklineStyle(
  history: Array<number | null> | undefined,
): ReplySparklineStyle | undefined {
  if (!Array.isArray(history) || history.length === 0) return undefined;

  const recentSamples = history.slice(-60).map((sample) =>
    typeof sample === "number" && Number.isFinite(sample) && sample >= 0
      ? sample
      : null,
  );
  const replySamples = recentSamples.filter(
    (sample): sample is number => sample !== null,
  );
  if (replySamples.length === 0) return undefined;

  const samples =
    recentSamples.length === 1
      ? [recentSamples[0], recentSamples[0]]
      : recentSamples;
  const minimum = Math.min(...replySamples);
  const maximum = Math.max(...replySamples);
  const range = maximum - minimum;
  const points = samples.map((sample, index) => {
    const x = (index / (samples.length - 1)) * 100;
    if (sample === null) return `${x.toFixed(2)}% 100%`;

    const normalized =
      range === 0 ? 0.6 : 0.3 + ((sample - minimum) / range) * 0.7;
    const y = 94 - normalized * 72;
    return `${x.toFixed(2)}% ${y.toFixed(2)}%`;
  });

  return {
    "--reply-sparkline": `polygon(0% 100%, ${points.join(", ")}, 100% 100%)`,
  };
}

function normalizeReplyHistory(history: Array<number | null> | undefined) {
  if (!Array.isArray(history)) return [];

  return history.slice(-REPLY_HISTORY_LIMIT).map((sample) =>
    typeof sample === "number" && Number.isFinite(sample) && sample >= 0
      ? sample
      : null,
  );
}

function niceLatencyScale(samples: number[]) {
  const maximum = Math.max(...samples, 0);
  if (maximum === 0) {
    return { ceiling: 1, ticks: [1, 0] };
  }

  const paddedMaximum = maximum * 1.1;
  const roughStep = paddedMaximum / 4;
  const magnitude = 10 ** Math.floor(Math.log10(roughStep));
  const normalizedStep = roughStep / magnitude;
  const niceStepMultiplier =
    normalizedStep <= 1 ? 1 : normalizedStep <= 2 ? 2 : normalizedStep <= 5 ? 5 : 10;
  const step = niceStepMultiplier * magnitude;
  const ceiling = Math.ceil(paddedMaximum / step) * step;
  const intervalCount = Math.round(ceiling / step);
  const ticks = Array.from({ length: intervalCount + 1 }, (_, index) => {
    const value = ceiling - index * step;
    return Math.abs(value) < step / 1_000 ? 0 : Number(value.toPrecision(12));
  });

  return { ceiling, ticks };
}

function formatAxisLatency(value: number) {
  return value.toLocaleString(undefined, {
    maximumFractionDigits: value < 1 ? 2 : value < 10 ? 1 : 0,
  });
}

function buildReplyLineSeries(
  samples: Array<number | null>,
  leadingSlots: number,
  ceiling: number,
) {
  const points: Array<ReplyChartPoint | null> = [];
  const lineSegments: ReplyChartPoint[][] = [];
  let activeSegment: ReplyChartPoint[] = [];

  const finishSegment = () => {
    if (activeSegment.length > 0) lineSegments.push(activeSegment);
    activeSegment = [];
  };

  samples.forEach((sample, sampleIndex) => {
    if (sample === null) {
      points.push(null);
      finishSegment();
      return;
    }

    const visualSlot = leadingSlots + sampleIndex;
    const point = {
      x: (visualSlot / (REPLY_HISTORY_LIMIT - 1)) * REPLY_CHART_SCALE,
      y: REPLY_CHART_SCALE - (sample / ceiling) * REPLY_CHART_SCALE,
    };
    points.push(point);
    activeSegment.push(point);
  });
  finishSegment();

  return { lineSegments, points };
}

function ReplyTimeDetailChart({
  target,
  titleId,
}: {
  target: PingTarget;
  titleId: string;
}) {
  const samples = normalizeReplyHistory(target.reply_time_history_ms);
  const replies = samples.filter(
    (sample): sample is number => sample !== null,
  );
  const { ceiling, ticks } = niceLatencyScale(replies);
  const firstProbeNumber = Math.max(1, target.sent - samples.length + 1);
  const leadingSlots = REPLY_HISTORY_LIMIT - samples.length;
  const gapCount = samples.length - replies.length;
  const descriptionId = `${titleId}-description`;
  const { lineSegments, points } = buildReplyLineSeries(
    samples,
    leadingSlots,
    ceiling,
  );

  return (
    <section
      className={styles.detailPanel}
      aria-describedby={descriptionId}
      aria-labelledby={titleId}
    >
      <div className={styles.detailHeader}>
        <div>
          <h3 id={titleId}>{target.target} reply-time detail</h3>
          <p>
            Most recent {samples.length || 0} of {REPLY_HISTORY_LIMIT} probe
            slots, oldest to latest
          </p>
        </div>
        <div className={styles.detailMetrics} aria-label="Latency summary">
          <span>
            <small>Last</small>
            <strong>{formatLatency(target.last_ms)}</strong>
          </span>
          <span>
            <small>Average</small>
            <strong>{formatLatency(target.avg_ms)}</strong>
          </span>
          <span>
            <small>Range</small>
            <strong>
              {formatLatency(target.min_ms)}–{formatLatency(target.max_ms)}
            </strong>
          </span>
        </div>
      </div>
      <p className="sr-only" id={descriptionId}>
        Line graph of reply time in milliseconds for the latest {samples.length}
        {" "}probes, ordered oldest to latest. {replies.length} timed replies
        and {gapCount} gaps with no timed reply. The line breaks at each gap.
      </p>

      {samples.length === 0 || replies.length === 0 ? (
        <div className={styles.chartEmpty}>
          <strong>No timed replies to graph yet</strong>
          <span>
            {samples.length
              ? `${samples.length} recent probe${samples.length === 1 ? " has" : "s have"} no timed reply.`
              : "The chart will appear after the first completed probe."}
          </span>
        </div>
      ) : (
        <>
          <div className={styles.chartLegend} aria-hidden="true">
            <span>
              <i className={styles.replyLegendMark} /> Timed reply
            </span>
            <span>
              <i className={styles.gapLegendMark} /> Gap = no timed reply
            </span>
          </div>
          <div
            className={styles.chartScroller}
            aria-label={`Scrollable reply-time chart for ${target.target}`}
            tabIndex={0}
          >
            <div className={styles.chartFrame}>
              <div className={styles.yAxisTitle}>Reply time (ms)</div>
              <div className={styles.yAxisTicks} aria-hidden="true">
                {ticks.map((tick) => (
                  <span key={tick}>{formatAxisLatency(tick)}</span>
                ))}
              </div>
              <div className={styles.chartPlot}>
                <div className={styles.chartGrid} aria-hidden="true">
                  {ticks.map((tick) => (
                    <span key={tick} />
                  ))}
                </div>
                <svg
                  aria-hidden="true"
                  className={styles.chartLineSvg}
                  data-chart-kind="line"
                  preserveAspectRatio="none"
                  viewBox={`0 0 ${REPLY_CHART_SCALE} ${REPLY_CHART_SCALE}`}
                >
                  {lineSegments.map((segment, segmentIndex) =>
                    segment.length > 1 ? (
                      <path
                        className={styles.chartLineSegment}
                        d={segment
                          .map(
                            (point, pointIndex) =>
                              `${pointIndex === 0 ? "M" : "L"} ${point.x} ${point.y}`,
                          )
                          .join(" ")}
                        key={`segment-${segmentIndex}`}
                        vectorEffect="non-scaling-stroke"
                      />
                    ) : null,
                  )}
                </svg>
                <div
                  className={styles.chartSamples}
                  aria-hidden="true"
                >
                  {samples.map((sample, index) => {
                    const probeNumber = firstProbeNumber + index;
                    const spokenValue =
                      sample === null
                        ? "no timed reply"
                        : `${formatAxisLatency(sample)} milliseconds`;
                    const sampleLabel = `Probe ${probeNumber}: ${spokenValue}`;
                    const visualSlot = leadingSlots + index;
                    const point = points[index];
                    const sampleStyle: ReplyChartSampleStyle = {
                      "--sample-x": `${
                        (visualSlot / (REPLY_HISTORY_LIMIT - 1)) * 100
                      }%`,
                      "--sample-y": point ? `${point.y}%` : "calc(100% - 3px)",
                    };
                    const edgeClass =
                      visualSlot < 3
                        ? styles.chartSampleStart
                        : visualSlot >= REPLY_HISTORY_LIMIT - 3
                          ? styles.chartSampleEnd
                          : "";

                    return (
                      <span
                        className={`${styles.chartSample} ${
                          sample === null ? styles.chartSampleGap : ""
                        } ${edgeClass}`}
                        data-sample-label={sampleLabel}
                        key={`${probeNumber}-${index}`}
                        style={sampleStyle}
                        title={sampleLabel}
                      />
                    );
                  })}
                </div>
              </div>
              <div className={styles.xAxis} aria-hidden="true">
                <span>Older</span>
                <span>Recent {REPLY_HISTORY_LIMIT} probe slots</span>
                <span>Latest</span>
              </div>
            </div>
          </div>
          <ol className="sr-only">
            {samples.map((sample, index) => {
              const probeNumber = firstProbeNumber + index;
              return (
                <li key={`accessible-${probeNumber}-${index}`}>
                  Probe {probeNumber}: {sample === null
                    ? "no timed reply"
                    : `${formatAxisLatency(sample)} milliseconds`}
                </li>
              );
            })}
          </ol>
        </>
      )}
    </section>
  );
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
    // Use the status-based message when the API response has no JSON detail.
  }
  return fallback;
}

function jobAnnouncement(status: PingJobStatus) {
  switch (status) {
    case "queued":
      return "Ping job queued.";
    case "running":
      return "Ping job started.";
    case "completed":
      return "Ping job completed.";
    case "cancelled":
      return "Continuous ping monitoring stopped.";
    case "failed":
      return "Ping job failed.";
  }
}

export function NetPingerClient() {
  const [targetInput, setTargetInput] = useState("");
  const [intervalInput, setIntervalInput] = useState("1");
  const [timeoutInput, setTimeoutInput] = useState("1");
  const [job, setJob] = useState<PingJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [targetsInvalid, setTargetsInvalid] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [reattaching, setReattaching] = useState(true);
  const [announcement, setAnnouncement] = useState("");
  const [expandedTargetKeys, setExpandedTargetKeys] = useState<Set<string>>(
    () => new Set(),
  );
  const startInFlight = useRef(false);
  const stopInFlight = useRef(false);
  const reattachInFlight = useRef(false);
  const announcedState = useRef<{ id: string; status: PingJobStatus } | null>(
    null,
  );

  const uniqueTargets = useMemo(() => parseTargets(targetInput), [targetInput]);
  const enteredTargetCount = useMemo(
    () => countEnteredTargets(targetInput),
    [targetInput],
  );
  const duplicatesRemoved = enteredTargetCount - uniqueTargets.length;
  const targetLimitExceeded = uniqueTargets.length > 32;
  const isActive = job ? isActiveJob(job) : false;
  const controlsDisabled = submitting || reattaching || isActive;
  const jobId = job?.id;

  useEffect(() => {
    const storedJobId = readActiveJobId();
    if (!storedJobId) {
      const readyTimer = window.setTimeout(() => setReattaching(false), 0);
      return () => window.clearTimeout(readyTimer);
    }

    reattachInFlight.current = true;
    let disposed = false;
    let timer: number | undefined;
    const reconnectingTimer = window.setTimeout(
      () => setReattaching(true),
      0,
    );
    let controller: AbortController | undefined;

    async function reattach() {
      controller = new AbortController();
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/ping-jobs/${encodeURIComponent(storedJobId)}`,
          {
            cache: "no-store",
            signal: controller.signal,
          },
        );

        if (response.status === 404) {
          forgetActiveJob(storedJobId);
          if (!disposed) {
            setJob(null);
            setError(
              "The previous ping job is no longer available. You can start a new continuous ping.",
            );
            window.clearTimeout(reconnectingTimer);
            reattachInFlight.current = false;
            setReattaching(false);
          }
          return;
        }

        if (!response.ok) {
          throw new Error(`Reconnection failed (${response.status}).`);
        }

        const restoredJob = (await response.json()) as PingJob;
        if (disposed) return;

        setJob(restoredJob);
        setTargetInput(
          restoredJob.targets.map((target) => target.target).join("\n"),
        );
        setIntervalInput(String(restoredJob.options.interval));
        setTimeoutInput(String(restoredJob.options.timeout));
        setError(
          restoredJob.status === "failed"
            ? restoredJob.error ?? "The ping job could not be completed."
            : null,
        );
        window.clearTimeout(reconnectingTimer);
        reattachInFlight.current = false;
        setReattaching(false);

        if (isActiveJob(restoredJob)) {
          rememberActiveJob(restoredJob);
        } else {
          forgetActiveJob(restoredJob.id);
        }
      } catch (caught) {
        if (
          disposed ||
          (caught instanceof DOMException && caught.name === "AbortError")
        ) {
          return;
        }

        setError("Reconnecting to the active ping job…");
        timer = window.setTimeout(reattach, 1200);
      }
    }

    void reattach();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      window.clearTimeout(reconnectingTimer);
      controller?.abort();
      reattachInFlight.current = false;
    };
  }, []);

  useEffect(() => {
    if (!job) return;
    const last = announcedState.current;
    if (last?.id === job.id && last.status === job.status) return;
    announcedState.current = { id: job.id, status: job.status };
    setAnnouncement(jobAnnouncement(job.status));
  }, [job]);

  useEffect(() => {
    if (!jobId || !isActive) return;

    let disposed = false;
    let timer: number | undefined;
    const controller = new AbortController();

    async function poll() {
      let continuePolling = true;
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/ping-jobs/${encodeURIComponent(jobId)}`,
          {
            cache: "no-store",
            signal: controller.signal,
          },
        );
        if (response.status === 404) {
          forgetActiveJob(jobId);
          if (!disposed) {
            setJob(null);
            setError(
              "The active ping job is no longer available. You can start a new continuous ping.",
            );
          }
          continuePolling = false;
          return;
        }
        if (!response.ok) {
          throw new Error(
            await responseError(
              response,
              `Live status is unavailable (${response.status}).`,
            ),
          );
        }

        const nextJob = (await response.json()) as PingJob;
        if (disposed) return;
        setJob(nextJob);
        if (isActiveJob(nextJob)) {
          rememberActiveJob(nextJob);
        } else {
          forgetActiveJob(nextJob.id);
        }
        if (nextJob.status === "failed") {
          setError(nextJob.error ?? "The ping job could not be completed.");
        } else {
          setError(null);
        }
        continuePolling =
          nextJob.status === "queued" || nextJob.status === "running";
      } catch (caught) {
        if (
          !disposed &&
          !(caught instanceof DOMException && caught.name === "AbortError")
        ) {
          setError(
            caught instanceof TypeError
              ? "Live updates are temporarily unavailable. Reconnecting…"
              : caught instanceof Error
                ? caught.message
                : "Unable to refresh the ping job.",
          );
        }
      } finally {
        if (!disposed && continuePolling && !controller.signal.aborted) {
          timer = window.setTimeout(poll, 900);
        }
      }
    }

    void poll();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      controller.abort();
    };
  }, [isActive, jobId]);

  const summary = useMemo(() => {
    const targets = job?.targets ?? [];
    const sent = targets.reduce((total, target) => total + target.sent, 0);
    const received = targets.reduce(
      (total, target) => total + target.received,
      0,
    );
    const reachable = targets.filter((target) => target.status === "up").length;
    const latencyTotal = targets.reduce(
      (total, target) =>
        total +
        (target.avg_ms == null
          ? 0
          : target.avg_ms * (target.latency_samples ?? 0)),
      0,
    );
    const latencySamples = targets.reduce(
      (total, target) => total + (target.latency_samples ?? 0),
      0,
    );

    return {
      sent,
      received,
      reachable,
      successRate: sent ? (received / sent) * 100 : 0,
      averageLatency: latencySamples ? latencyTotal / latencySamples : null,
    };
  }, [job?.targets]);

  async function startPing(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      startInFlight.current ||
      reattachInFlight.current ||
      reattaching ||
      isActive
    ) {
      return;
    }

    startInFlight.current = true;
    setError(null);
    setTargetsInvalid(false);

    const interval = Number(intervalInput);
    const timeout = Number(timeoutInput);

    if (!uniqueTargets.length) {
      setTargetsInvalid(true);
      setError("Enter at least one hostname or IP address.");
      startInFlight.current = false;
      return;
    }

    if (targetLimitExceeded) {
      setTargetsInvalid(true);
      setError("Enter no more than 32 unique targets per ping job.");
      startInFlight.current = false;
      return;
    }

    if (
      !Number.isFinite(interval) ||
      interval < 0.2 ||
      interval > 60 ||
      !Number.isFinite(timeout) ||
      timeout < 0.1 ||
      timeout > 10
    ) {
      setError(
        "Use a 0.2–60 second interval and a 0.1–10 second timeout.",
      );
      startInFlight.current = false;
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/ping-jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          targets: uniqueTargets,
          continuous: true,
          interval,
          timeout,
        }),
      });

      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `The ping engine rejected the request (${response.status}).`,
          ),
        );
      }

      const nextJob = (await response.json()) as PingJob;
      rememberActiveJob(nextJob);
      setExpandedTargetKeys(new Set());
      setJob(nextJob);
      setError(nextJob.status === "failed" ? nextJob.error : null);
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local ping engine is offline. Start it, then try again."
          : caught instanceof Error
            ? caught.message
            : "Unable to start the ping job.",
      );
    } finally {
      startInFlight.current = false;
      setSubmitting(false);
    }
  }

  async function stopPing() {
    if (!job || !isActive || job.cancel_requested || stopInFlight.current) {
      return;
    }

    stopInFlight.current = true;
    setStopping(true);
    setError(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/ping-jobs/${encodeURIComponent(job.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            "Continuous pinging could not be stopped.",
          ),
        );
      }
      const nextJob = (await response.json()) as PingJob;
      setJob(nextJob);
      if (isActiveJob(nextJob)) {
        rememberActiveJob(nextJob);
      } else {
        forgetActiveJob(nextJob.id);
      }
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local ping engine is offline. Continuous pinging could not be stopped."
          : caught instanceof Error
            ? caught.message
            : "Unable to stop continuous pinging.",
      );
    } finally {
      stopInFlight.current = false;
      setStopping(false);
    }
  }

  const jobStatusClass: Record<PingJobStatus, string> = {
    queued: styles.statusQueued,
    running: styles.statusRunning,
    completed: styles.statusCompleted,
    cancelled: styles.statusStopped,
    failed: styles.statusFailed,
  };
  const targetStatusClass: Record<PingTargetStatus, string> = {
    pending: styles.statusQueued,
    up: styles.statusUp,
    down: styles.statusDown,
    error: styles.statusFailed,
  };

  return (
    <div className={styles.workspace}>
      <p
        className="sr-only"
        role="status"
        aria-live="polite"
        aria-atomic="true"
      >
        {announcement}
      </p>

      <section className={styles.controlPanel} aria-labelledby="ping-input-title">
        <div className={styles.panelHeading}>
          <div>
            <h2 id="ping-input-title">Targets and timing</h2>
            <p>Enter one target per line or separate targets with commas.</p>
          </div>
          <span>ICMP</span>
        </div>

        <form onSubmit={startPing} className={styles.form}>
          <div className={styles.targetField}>
            <label htmlFor="ping-targets">Hostnames or IP addresses</label>
            <textarea
              id="ping-targets"
              name="targets"
              value={targetInput}
              onChange={(event) => {
                setTargetInput(event.target.value);
                setTargetsInvalid(false);
                setError(null);
              }}
              placeholder={"gateway.local\n192.168.1.1\n2001:db8::10"}
              rows={6}
              spellCheck={false}
              autoComplete="off"
              disabled={controlsDisabled}
              aria-invalid={targetsInvalid || targetLimitExceeded}
              aria-describedby="target-help"
            />
            <div className={styles.targetHelp} id="target-help">
              <span>
                {uniqueTargets.length} / 32 unique target
                {uniqueTargets.length === 1 ? "" : "s"}
              </span>
              <span>
                {duplicatesRemoved > 0
                  ? `${duplicatesRemoved} duplicate${duplicatesRemoved === 1 ? "" : "s"} removed`
                  : "Duplicates are removed automatically"}
              </span>
            </div>
          </div>

          <div className={styles.optionGrid}>
            <label>
              <span>Interval</span>
              <div className={styles.numberWithUnit}>
                <input
                  type="number"
                  min="0.2"
                  max="60"
                  step="0.1"
                  value={intervalInput}
                  onChange={(event) => {
                    setIntervalInput(event.target.value);
                    setError(null);
                  }}
                  disabled={controlsDisabled}
                  inputMode="decimal"
                />
                <span>sec</span>
              </div>
              <small>Delay between requests</small>
            </label>
            <label>
              <span>Timeout</span>
              <div className={styles.numberWithUnit}>
                <input
                  type="number"
                  min="0.1"
                  max="10"
                  step="0.1"
                  value={timeoutInput}
                  onChange={(event) => {
                    setTimeoutInput(event.target.value);
                    setError(null);
                  }}
                  disabled={controlsDisabled}
                  inputMode="decimal"
                />
                <span>sec</span>
              </div>
              <small>Wait for each reply</small>
            </label>
          </div>

          <p
            className={styles.continuousNote}
            role={reattaching ? "status" : undefined}
          >
            <strong>
              {reattaching ? "Reconnecting:" : "Continuous monitoring:"}
            </strong>{" "}
            {reattaching
              ? "checking for an active ping job so it can be safely stopped."
              : "probes keep running until you press Stop."}
          </p>

          <div className={styles.actions}>
            <button
              className={styles.startButton}
              type="submit"
              disabled={
                controlsDisabled || !uniqueTargets.length || targetLimitExceeded
              }
            >
              {submitting
                ? "Starting…"
                : isActive
                  ? "Pinging continuously"
                  : "Start continuous ping"}
            </button>
            <button
              className={styles.stopButton}
              type="button"
              onClick={stopPing}
              disabled={
                !isActive || stopping || Boolean(job?.cancel_requested)
              }
            >
              {stopping || job?.cancel_requested ? "Stopping…" : "Stop"}
            </button>
          </div>
        </form>
      </section>

      {error ? (
        <div className={styles.errorBanner} role="alert">
          <strong>NetPinger needs attention</strong>
          <span>{error}</span>
        </div>
      ) : null}

      {!job ? (
        <section className={styles.emptyState} aria-labelledby="empty-title">
          <span aria-hidden="true">—</span>
          <h2 id="empty-title">No ping results yet</h2>
          <p>
            Add one or more targets, choose the timing, and start continuous
            monitoring. Pings run until you press Stop.
          </p>
        </section>
      ) : (
        <section className={styles.results} aria-labelledby="results-title">
          <div className={styles.resultsHeader}>
            <div>
              <div className={styles.resultTitleRow}>
                <h2 id="results-title">Live results</h2>
                <span
                  className={`${styles.statusBadge} ${jobStatusClass[job.status]}`}
                >
                  <i aria-hidden="true" />
                  {jobLabels[job.status]}
                </span>
              </div>
              <p>
                {job.targets.length} target{job.targets.length === 1 ? "" : "s"}
                <span aria-hidden="true"> · </span>
                {job.options.continuous
                  ? "Continuous monitoring · runs until stopped"
                  : `${job.options.count} requests each`}
              </p>
            </div>
            <code title={job.id}>Job {job.id.slice(0, 8)}</code>
          </div>

          <div className={styles.progressBlock}>
            <div className={styles.progressMeta}>
              <span>Monitoring activity</span>
              <strong>
                {job.progress.total_probes == null
                  ? `${job.progress.completed_probes} probes sent`
                  : `${job.progress.completed_probes} / ${job.progress.total_probes} probes`}
              </strong>
            </div>
            {job.progress.percent == null ? (
              <div
                className={`${styles.progressTrack} ${
                  isActive ? styles.progressContinuous : styles.progressStopped
                }`}
                role={isActive ? "progressbar" : undefined}
                aria-label={
                  isActive ? "Continuous ping monitoring is running" : undefined
                }
              >
                <span />
              </div>
            ) : (
              <div
                className={styles.progressTrack}
                role="progressbar"
                aria-label="Ping job progress"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.round(job.progress.percent)}
              >
                <span
                  style={{
                    width: `${Math.min(100, Math.max(0, job.progress.percent))}%`,
                  }}
                />
              </div>
            )}
          </div>

          <div className={styles.summaryGrid}>
            <article>
              <span>Reachable now</span>
              <strong>
                {summary.reachable} / {job.targets.length}
              </strong>
              <small>targets currently up</small>
            </article>
            <article>
              <span>Probe success</span>
              <strong>{formatPercent(summary.successRate)}</strong>
              <small>
                {summary.received} of {summary.sent} replies
              </small>
            </article>
            <article>
              <span>Probe loss</span>
              <strong>
                {formatPercent(summary.sent ? 100 - summary.successRate : 0)}
              </strong>
              <small>{summary.sent - summary.received} failed requests</small>
            </article>
            <article>
              <span>Average latency</span>
              <strong>{formatLatency(summary.averageLatency)}</strong>
              <small>across timed replies</small>
            </article>
          </div>

          {job.status === "completed" ||
          job.status === "cancelled" ||
          job.status === "failed" ? (
            <div className={styles.terminalNote}>
              <strong>{jobLabels[job.status]}</strong>
              <span>
                {job.status === "completed"
                  ? "Monitoring has finished."
                  : job.status === "cancelled"
                    ? "Continuous pinging was stopped. Final statistics are shown."
                    : job.error ?? "The job ended before all probes completed."}
              </span>
            </div>
          ) : null}

          <p className={styles.tableHint}>
            Select one or more hosts to expand their reply-time graphs and
            inspect individual probes.
          </p>

          <div
            className={styles.tableRegion}
            role="region"
            aria-label="Ping results table"
            tabIndex={0}
          >
            <table className={styles.resultsTable}>
              <caption className="sr-only">
                Live reachability, success and failure streaks, loss, and
                latency statistics by target
              </caption>
              <thead>
                <tr>
                  <th scope="col">Target</th>
                  <th scope="col">Status</th>
                  <th scope="col">Sent / received</th>
                  <th scope="col">Success / loss</th>
                  <th scope="col">Success streak</th>
                  <th scope="col">Failure streak</th>
                  <th scope="col">Last</th>
                  <th scope="col">Average</th>
                  <th scope="col">Minimum</th>
                  <th scope="col">Maximum</th>
                </tr>
              </thead>
              <tbody>
                {job.targets.map((target, targetIndex) => {
                  const sparklineStyle = replySparklineStyle(
                    target.reply_time_history_ms,
                  );
                  const targetKey = `${job.id}:${target.target}`;
                  const expanded = expandedTargetKeys.has(targetKey);
                  const detailId = `reply-detail-${job.id}-${targetIndex}`;
                  const detailTitleId = `${detailId}-title`;

                  return (
                    <Fragment key={targetKey}>
                      <tr
                        className={`${styles.targetRow} ${
                          expanded ? styles.targetRowExpanded : ""
                        }`}
                        data-reply-history={sparklineStyle ? "true" : undefined}
                        style={sparklineStyle}
                      >
                    <th scope="row">
                      <button
                        aria-controls={detailId}
                        aria-expanded={expanded}
                        className={styles.targetToggle}
                        onClick={() =>
                          setExpandedTargetKeys((current) => {
                            const next = new Set(current);
                            if (next.has(targetKey)) {
                              next.delete(targetKey);
                            } else {
                              next.add(targetKey);
                            }
                            return next;
                          })
                        }
                        type="button"
                      >
                        <span className={styles.targetIdentity}>
                          <strong>{target.target}</strong>
                          <span>
                            {target.resolved_address
                              ? `${target.address_family ?? "Address"}: ${target.resolved_address}`
                              : target.status === "pending"
                                ? "Resolution pending"
                                : "Not resolved"}
                          </span>
                          <ReverseDnsIdentity target={target} />
                        </span>
                        <span className={styles.expandIndicator} aria-hidden="true">
                          {expanded ? "−" : "+"}
                        </span>
                        <span className="sr-only">
                          {expanded ? "Collapse" : "Expand"} detailed reply-time
                          graph
                        </span>
                      </button>
                      {target.error ? (
                        <small className={styles.rowError}>{target.error}</small>
                      ) : null}
                    </th>
                    <td>
                      <span
                        className={`${styles.statusBadge} ${targetStatusClass[target.status]}`}
                      >
                        <i aria-hidden="true" />
                        {targetLabels[target.status]}
                      </span>
                    </td>
                    <td className={styles.numericCell}>
                      <strong>{target.sent}</strong>
                      <span> / {target.received}</span>
                    </td>
                    <td className={styles.rateCell}>
                      {target.sent ? (
                        <>
                          <strong>{formatPercent(target.success_rate)}</strong>
                          <span>{formatPercent(target.loss_percent)} loss</span>
                        </>
                      ) : (
                        <span>—</span>
                      )}
                    </td>
                    <td className={styles.streakCell}>
                      <span className="sr-only">
                        Current consecutive successes: {target.consecutive_successes ?? 0}.
                        Maximum consecutive successes: {target.max_consecutive_successes ?? 0}.
                      </span>
                      <span className={styles.streakValues} aria-hidden="true">
                        <span>
                          <strong>{target.consecutive_successes ?? 0}</strong>{" "}
                          current
                        </span>
                        <span>{target.max_consecutive_successes ?? 0} max</span>
                      </span>
                    </td>
                    <td className={styles.streakCell}>
                      <span className="sr-only">
                        Current consecutive failures: {target.consecutive_failures ?? 0}.
                        Maximum consecutive failures: {target.max_consecutive_failures ?? 0}.
                      </span>
                      <span className={styles.streakValues} aria-hidden="true">
                        <span>
                          <strong>{target.consecutive_failures ?? 0}</strong>{" "}
                          current
                        </span>
                        <span>{target.max_consecutive_failures ?? 0} max</span>
                      </span>
                    </td>
                    <td className={styles.latencyCell}>
                      {formatLatency(target.last_ms)}
                    </td>
                    <td className={styles.latencyCell}>
                      {formatLatency(target.avg_ms)}
                    </td>
                    <td className={styles.latencyCell}>
                      {formatLatency(target.min_ms)}
                    </td>
                    <td className={styles.latencyCell}>
                      {formatLatency(target.max_ms)}
                    </td>
                      </tr>
                      {expanded ? (
                        <tr className={styles.detailRow}>
                          <td
                            className={styles.detailCell}
                            colSpan={RESULT_COLUMN_COUNT}
                            id={detailId}
                          >
                            <ReplyTimeDetailChart
                              target={target}
                              titleId={detailTitleId}
                            />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
