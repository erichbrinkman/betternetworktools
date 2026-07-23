"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import styles from "./nettrace.module.css";
import {
  clearRecentTraceStorage,
  isValidTraceTarget,
  MAX_RECENT_TRACES,
  readRecentTraces,
  removeRecentTrace,
  type RecentTrace,
  upsertRecentTrace,
  writeRecentTraces,
} from "./recentTraces";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const POLL_INTERVAL_MS = 800;
const ACTIVE_TRACE_STORAGE_KEY = "better-network-tools.nettrace.active-job-id";

type TraceJobStatus =
  | "queued"
  | "running"
  | "completed"
  | "cancelled"
  | "failed";

type TraceProbeStatus = "reply" | "timeout" | "unreachable";
type ResponderScope =
  | "public"
  | "private"
  | "loopback"
  | "link_local"
  | "reserved";

type AutonomousSystem = {
  number: number;
  name: string | null;
  organization: string | null;
  prefix: string | null;
  country_code: string | null;
  registry: string | null;
  source: string | null;
};

type TraceProbe = {
  sequence: number;
  address: string | null;
  latency_ms: number | null;
  status: TraceProbeStatus;
  annotation: string | null;
};

type TraceResponder = {
  address: string;
  hostname: string | null;
  scope: ResponderScope;
  asn: AutonomousSystem | null;
};

type TraceHop = {
  number: number;
  probes: TraceProbe[];
  responders: TraceResponder[];
  reached_destination: boolean;
};

type AsPathSegment = {
  asn: number | null;
  network_name: string;
  first_hop: number;
  last_hop: number;
  prefixes: string[];
  ambiguous: boolean;
  boundary_confidence: "exact" | "gap" | "ecmp";
};

type TraceWarning = {
  code: string;
  message: string;
};

type TraceJob = {
  id: string;
  status: TraceJobStatus;
  phase: string;
  target: string;
  resolved_address: string | null;
  address_family: "IPv4" | "IPv6" | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  options: {
    max_hops: number;
    timeout: number;
    resolve_dns: boolean;
    lookup_asn: boolean;
    probes_per_hop: number;
  };
  progress: {
    last_hop: number;
    max_hops: number;
  };
  hops: TraceHop[];
  as_path: AsPathSegment[];
  reached_destination: boolean;
  error: string | null;
  warnings: Array<TraceWarning | string>;
  cancel_requested: boolean;
};

const statusLabels: Record<TraceJobStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  cancelled: "Stopped",
  failed: "Failed",
};

function formatRecentTraceTime(value: string) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown time";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function isActiveJob(job: TraceJob) {
  return job.status === "queued" || job.status === "running";
}

function readActiveTraceJobId() {
  try {
    return window.localStorage.getItem(ACTIVE_TRACE_STORAGE_KEY);
  } catch {
    return null;
  }
}

function rememberActiveTrace(job: TraceJob) {
  if (!isActiveJob(job)) return;
  try {
    window.localStorage.setItem(ACTIVE_TRACE_STORAGE_KEY, job.id);
  } catch {
    // The trace still works when browser storage is unavailable.
  }
}

function forgetActiveTrace(jobId: string) {
  try {
    if (window.localStorage.getItem(ACTIVE_TRACE_STORAGE_KEY) === jobId) {
      window.localStorage.removeItem(ACTIVE_TRACE_STORAGE_KEY);
    }
  } catch {
    // There is no stored identifier to clear when storage is unavailable.
  }
}

function formatLatency(value: number | null) {
  if (value == null || !Number.isFinite(value)) return "—";
  return `${value.toLocaleString(undefined, {
    maximumFractionDigits: 1,
    minimumFractionDigits: value < 10 ? 1 : 0,
  })} ms`;
}

function formatScope(scope: ResponderScope) {
  if (scope === "link_local") return "Link-local";
  return scope.charAt(0).toUpperCase() + scope.slice(1);
}

function formatAttributionSource(source: string | null) {
  if (!source) return "Not reported";
  if (source === "team_cymru_whois") return "Team Cymru WHOIS";
  return source.replaceAll("_", " ");
}

function phaseLabel(job: TraceJob) {
  if (job.status !== "running" && job.status !== "queued") {
    return statusLabels[job.status];
  }

  const label = job.phase.replaceAll("_", " ").trim();
  if (!label) return statusLabels[job.status];
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function warningMessage(warning: TraceWarning | string) {
  return typeof warning === "string" ? warning : warning.message;
}

function asLabel(asn: number | null, networkName: string) {
  return asn == null ? networkName || "Private or unmapped" : `AS${asn}`;
}

function asLongLabel(asn: AutonomousSystem) {
  const operator = asn.organization || asn.name;
  return operator ? `AS${asn.number} · ${operator}` : `AS${asn.number}`;
}

function segmentLongLabel(segment: AsPathSegment) {
  const id = asLabel(segment.asn, segment.network_name);
  if (!segment.network_name || segment.network_name === id) return id;
  return `${id} ${segment.network_name}`;
}

function hopRange(first: number, last: number) {
  return first === last ? `Hop ${first}` : `Hops ${first}–${last}`;
}

type BoundaryCopy = {
  label: string;
  detail: string;
  uncertain: boolean;
};

function boundaryCopy(
  previous: AsPathSegment,
  current: AsPathSegment,
): BoundaryCopy {
  const from = segmentLongLabel(previous);
  const to = segmentLongLabel(current);
  const sameNetwork =
    previous.asn === current.asn &&
    previous.network_name === current.network_name;

  if (current.boundary_confidence === "ecmp" || current.ambiguous) {
    return {
      label: "Multiple AS paths observed",
      detail: `${from} and ${to} are both visible near hop ${current.first_hop}.`,
      uncertain: true,
    };
  }

  if (current.boundary_confidence === "gap") {
    if (sameNetwork) {
      return {
        label: `${to} continues after an unresponsive gap`,
        detail: `No different AS was observed between hops ${previous.last_hop} and ${current.first_hop}; no boundary is inferred.`,
        uncertain: true,
      };
    }
    return {
      label: `Possible exit ${from} · enter ${to}`,
      detail: `Boundary location is uncertain between hops ${previous.last_hop} and ${current.first_hop}.`,
      uncertain: true,
    };
  }

  return {
    label: `Exit ${from} · enter ${to}`,
    detail: `Observed at hop ${current.first_hop}.`,
    uncertain: false,
  };
}

async function responseError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      detail?: string | { message?: string } | Array<{ msg?: string }>;
    };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      return (
        payload.detail.map((entry) => entry.msg).filter(Boolean).join(" ") ||
        fallback
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
    // Keep the useful status-based fallback when the response is not JSON.
  }
  return fallback;
}

function probeTone(status: TraceProbeStatus) {
  if (status === "reply") return styles.probeReply;
  if (status === "unreachable") return styles.probeUnreachable;
  return styles.probeTimeout;
}

function HopDetails({ hop }: { hop: TraceHop }) {
  return (
    <div className={styles.hopDetails}>
      <section aria-labelledby={`hop-${hop.number}-probe-title`}>
        <h4 id={`hop-${hop.number}-probe-title`}>Probe observations</h4>
        <ul className={styles.probeDetailList}>
          {hop.probes.map((probe) => (
            <li key={probe.sequence}>
              <span className={styles.probeSequence}>#{probe.sequence}</span>
              <span
                className={`${styles.probeStatus} ${probeTone(probe.status)}`}
              >
                {probe.status}
              </span>
              <strong>{formatLatency(probe.latency_ms)}</strong>
              <code>{probe.address ?? "No reply address"}</code>
              {probe.annotation ? <small>{probe.annotation}</small> : null}
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby={`hop-${hop.number}-responder-title`}>
        <h4 id={`hop-${hop.number}-responder-title`}>Responders</h4>
        {hop.responders.length ? (
          <div className={styles.responderGrid}>
            {hop.responders.map((responder, index) => (
              <article key={`${responder.address}-${index}`}>
                <div className={styles.responderHeading}>
                  <div>
                    <strong>{responder.hostname ?? responder.address}</strong>
                    {responder.hostname ? <code>{responder.address}</code> : null}
                  </div>
                  <span>{formatScope(responder.scope)}</span>
                </div>

                {responder.asn ? (
                  <dl>
                    <div>
                      <dt>Autonomous system</dt>
                      <dd>{asLongLabel(responder.asn)}</dd>
                    </div>
                    <div>
                      <dt>Announced prefix</dt>
                      <dd>{responder.asn.prefix ?? "Not reported"}</dd>
                    </div>
                    <div>
                      <dt>Assigned country / registry</dt>
                      <dd>
                        {[responder.asn.country_code, responder.asn.registry]
                          .filter(Boolean)
                          .join(" · ") || "Not reported"}
                      </dd>
                    </div>
                    <div>
                      <dt>Attribution source</dt>
                      <dd>{formatAttributionSource(responder.asn.source)}</dd>
                    </div>
                  </dl>
                ) : (
                  <p className={styles.noAttribution}>
                    {responder.scope === "public"
                      ? "No autonomous-system attribution is available for this responder."
                      : "Private and special-use addresses do not have public AS attribution."}
                  </p>
                )}
              </article>
            ))}
          </div>
        ) : (
          <p className={styles.noAttribution}>
            This hop did not return responder metadata.
          </p>
        )}
      </section>
    </div>
  );
}

export function NetTraceClient() {
  const [targetInput, setTargetInput] = useState("");
  const [maxHopsInput, setMaxHopsInput] = useState("30");
  const [timeoutInput, setTimeoutInput] = useState("2");
  const [resolveDns, setResolveDns] = useState(true);
  const [lookupAsn, setLookupAsn] = useState(false);
  const [job, setJob] = useState<TraceJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [targetInvalid, setTargetInvalid] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [expandedHops, setExpandedHops] = useState<Set<number>>(new Set());
  const [recentTraces, setRecentTraces] = useState<RecentTrace[]>([]);
  const [recentAnnouncement, setRecentAnnouncement] = useState("");
  const startInFlight = useRef(false);
  const stopInFlight = useRef(false);
  const targetInputRef = useRef<HTMLInputElement>(null);
  const recentHeadingRef = useRef<HTMLHeadingElement>(null);

  const jobId = job?.id;
  const isActive = Boolean(job && isActiveJob(job));
  const controlsDisabled = submitting || isActive;

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setRecentTraces(readRecentTraces());
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    const storedJobId = readActiveTraceJobId();
    if (!storedJobId) return;

    let disposed = false;
    const controller = new AbortController();

    async function restoreActiveTrace() {
      try {
        const response = await fetch(
          `${API_BASE_URL}/api/trace-jobs/${encodeURIComponent(storedJobId)}`,
          { cache: "no-store", signal: controller.signal },
        );
        if (response.status === 404) {
          forgetActiveTrace(storedJobId);
          return;
        }
        if (!response.ok) {
          throw new Error(
            await responseError(
              response,
              "The saved route trace could not be restored.",
            ),
          );
        }

        const restoredJob = (await response.json()) as TraceJob;
        if (isActiveJob(restoredJob)) rememberActiveTrace(restoredJob);
        else forgetActiveTrace(storedJobId);
        if (!disposed) setJob(restoredJob);
      } catch (caught) {
        if (
          !disposed &&
          !(caught instanceof DOMException && caught.name === "AbortError")
        ) {
          setError(
            caught instanceof TypeError
              ? "The local trace engine is offline. A saved trace can be restored when it is running again."
              : caught instanceof Error
                ? caught.message
                : "Unable to restore the saved route trace.",
          );
        }
      }
    }

    void restoreActiveTrace();
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
          `${API_BASE_URL}/api/trace-jobs/${encodeURIComponent(activeJobId)}`,
          {
            cache: "no-store",
            signal: controller.signal,
          },
        );
        if (response.status === 404) {
          shouldContinue = false;
          forgetActiveTrace(jobId);
        }
        if (!response.ok) {
          throw new Error(
            await responseError(
              response,
              "The trace engine stopped reporting this route.",
            ),
          );
        }

        const nextJob = (await response.json()) as TraceJob;
        shouldContinue = isActiveJob(nextJob);
        if (shouldContinue) rememberActiveTrace(nextJob);
        else forgetActiveTrace(jobId);
        if (!disposed) {
          setJob(nextJob);
          setError(
            nextJob.status === "failed"
              ? nextJob.error ?? "The route trace could not be completed."
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
              ? "The local trace engine is offline. Start it, then NetTrace will continue polling."
              : caught instanceof Error
                ? caught.message
                : "Unable to refresh the route trace.",
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

  const summary = useMemo(() => {
    const hops = job?.hops ?? [];
    const respondingHops = hops.filter(
      (hop) =>
        hop.responders.length > 0 ||
        hop.probes.some((probe) => probe.status === "reply"),
    ).length;
    const publicAsns = new Set(
      (job?.as_path ?? [])
        .map((segment) => segment.asn)
        .filter((asn): asn is number => asn != null),
    );

    return {
      observedHops: hops.length,
      respondingHops,
      publicNetworks: publicAsns.size,
    };
  }, [job]);

  const collectingNativeTrace = Boolean(
    job && isActiveJob(job) && job.progress.last_hop === 0,
  );
  const announcement = job
    ? collectingNativeTrace
      ? `${phaseLabel(job)}. The native trace is collecting up to ${job.progress.max_hops} hops.`
      : `${phaseLabel(job)}. ${job.progress.last_hop} of ${job.progress.max_hops} possible hops observed.`
    : "NetTrace is ready for a target.";

  function rememberRecentTarget(target: string, tracedAt: string) {
    const entry: RecentTrace = { target, traced_at: tracedAt };
    setRecentTraces((current) => {
      const next = upsertRecentTrace(current, entry);
      writeRecentTraces(next);
      return next;
    });
  }

  function loadRecentTarget(recent: RecentTrace) {
    if (controlsDisabled) return;
    setTargetInput(recent.target);
    setTargetInvalid(false);
    setError(null);
    setRecentAnnouncement(`Loaded ${recent.target} into the trace form.`);
    window.requestAnimationFrame(() => targetInputRef.current?.focus());
  }

  function removeRecentTarget(target: string) {
    setRecentTraces((current) => {
      const next = removeRecentTrace(current, target);
      writeRecentTraces(next);
      return next;
    });
    setRecentAnnouncement(`Removed ${target} from recent traces.`);
    window.requestAnimationFrame(() => recentHeadingRef.current?.focus());
  }

  function clearRecentTargets() {
    setRecentTraces([]);
    clearRecentTraceStorage();
    setRecentAnnouncement("Recent traces cleared.");
    window.requestAnimationFrame(() => recentHeadingRef.current?.focus());
  }

  async function startTrace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (startInFlight.current || isActive) return;

    startInFlight.current = true;
    setError(null);
    setTargetInvalid(false);

    const target = targetInput.trim();
    const maxHops = Number(maxHopsInput);
    const timeout = Number(timeoutInput);

    if (!isValidTraceTarget(target)) {
      setTargetInvalid(true);
      setError(
        "Enter a hostname or IP address without a URL, path, spaces, or credentials.",
      );
      startInFlight.current = false;
      return;
    }
    if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 64) {
      setError("Max hops must be a whole number from 1 to 64.");
      startInFlight.current = false;
      return;
    }
    if (!Number.isFinite(timeout) || timeout < 0.2 || timeout > 5) {
      setError("Timeout must be between 0.2 and 5 seconds.");
      startInFlight.current = false;
      return;
    }

    setSubmitting(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/trace-jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          max_hops: maxHops,
          timeout,
          resolve_dns: resolveDns,
          lookup_asn: lookupAsn,
        }),
      });

      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `The trace engine rejected the request (${response.status}).`,
          ),
        );
      }

      const nextJob = (await response.json()) as TraceJob;
      if (nextJob.status !== "failed") {
        const createdAt = Number.isFinite(Date.parse(nextJob.created_at))
          ? nextJob.created_at
          : new Date().toISOString();
        rememberRecentTarget(nextJob.target, createdAt);
      }
      if (isActiveJob(nextJob)) rememberActiveTrace(nextJob);
      else forgetActiveTrace(nextJob.id);
      setExpandedHops(new Set());
      setJob(nextJob);
      setError(
        nextJob.status === "failed"
          ? nextJob.error ?? "The route trace could not be started."
          : null,
      );
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local trace engine is offline. Start it, then try again."
          : caught instanceof Error
            ? caught.message
            : "Unable to start the route trace.",
      );
    } finally {
      startInFlight.current = false;
      setSubmitting(false);
    }
  }

  async function stopTrace() {
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
        `${API_BASE_URL}/api/trace-jobs/${encodeURIComponent(job.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        throw new Error(
          await responseError(response, "The route trace could not be stopped."),
        );
      }
      const stoppedJob = (await response.json()) as TraceJob;
      if (isActiveJob(stoppedJob)) rememberActiveTrace(stoppedJob);
      else forgetActiveTrace(stoppedJob.id);
      setJob(stoppedJob);
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local trace engine is offline. The stop request could not be confirmed."
          : caught instanceof Error
            ? caught.message
            : "Unable to stop the route trace.",
      );
    } finally {
      stopInFlight.current = false;
      setStopping(false);
    }
  }

  function toggleHop(hopNumber: number) {
    setExpandedHops((current) => {
      const next = new Set(current);
      if (next.has(hopNumber)) next.delete(hopNumber);
      else next.add(hopNumber);
      return next;
    });
  }

  const statusClass = job
    ? {
        queued: styles.statusQueued,
        running: styles.statusRunning,
        completed: styles.statusCompleted,
        cancelled: styles.statusStopped,
        failed: styles.statusFailed,
      }[job.status]
    : styles.statusQueued;
  const progressMaximum = Math.max(job?.progress.max_hops ?? 1, 1);
  const progressValue = Math.min(
    progressMaximum,
    Math.max(job?.progress.last_hop ?? 0, 0),
  );

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

      <section className={styles.controlPanel} aria-labelledby="trace-target-title">
        <div className={styles.panelHeading}>
          <div>
            <h2 id="trace-target-title">Trace a route</h2>
            <p>Run three probes per hop through the local trace engine.</p>
          </div>
          <span>TTL</span>
        </div>

        <form className={styles.form} onSubmit={startTrace}>
          <div className={styles.targetGrid}>
            <label className={styles.targetField}>
              <span>Hostname or IP address</span>
              <input
                ref={targetInputRef}
                id="trace-target"
                name="target"
                value={targetInput}
                onChange={(event) => {
                  setTargetInput(event.target.value);
                  setTargetInvalid(false);
                  setError(null);
                }}
                placeholder="example.com or 1.1.1.1"
                spellCheck={false}
                autoComplete="off"
                disabled={controlsDisabled}
                aria-invalid={targetInvalid}
                aria-describedby="trace-target-help"
              />
              <small id="trace-target-help">
                Enter one destination. URLs and network ranges are not accepted.
              </small>
            </label>

            <label className={styles.numberField}>
              <span>Max hops</span>
              <div className={styles.numberControl}>
                <input
                  type="number"
                  min="1"
                  max="64"
                  step="1"
                  inputMode="numeric"
                  value={maxHopsInput}
                  onChange={(event) => {
                    setMaxHopsInput(event.target.value);
                    setError(null);
                  }}
                  disabled={controlsDisabled}
                />
                <span>TTL</span>
              </div>
              <small>1–64</small>
            </label>

            <label className={styles.numberField}>
              <span>Timeout</span>
              <div className={styles.numberControl}>
                <input
                  type="number"
                  min="0.2"
                  max="5"
                  step="0.1"
                  inputMode="decimal"
                  value={timeoutInput}
                  onChange={(event) => {
                    setTimeoutInput(event.target.value);
                    setError(null);
                  }}
                  disabled={controlsDisabled}
                />
                <span>sec</span>
              </div>
              <small>Per probe</small>
            </label>
          </div>

          <fieldset className={styles.enrichmentOptions} disabled={controlsDisabled}>
            <legend>Optional enrichment</legend>
            <label className={styles.optionCard}>
              <input
                type="checkbox"
                checked={resolveDns}
                onChange={(event) => setResolveDns(event.target.checked)}
              />
              <span>
                <strong>Resolve responder hostnames</strong>
                <small>
                  Ask the configured DNS resolver for a reverse-DNS name when
                  available.
                </small>
              </span>
            </label>

            <label
              className={`${styles.optionCard} ${styles.asnOption} ${
                lookupAsn ? styles.asnOptionEnabled : ""
              }`}
            >
              <input
                type="checkbox"
                name="lookup_asn"
                checked={lookupAsn}
                onChange={(event) => setLookupAsn(event.target.checked)}
              />
              <span>
                <span className={styles.optionTitleRow}>
                  <strong>Look up autonomous-system details</strong>
                  <em>{lookupAsn ? "Enabled" : "Off by default"}</em>
                </span>
                <small>
                  Sends each public hop IP address to Team Cymru&apos;s IP-to-AS
                  lookup service. Enable this to identify AS numbers, network
                  operators, prefixes, and route boundaries.
                </small>
              </span>
            </label>
          </fieldset>

          <div className={styles.actions}>
            <button
              className={styles.startButton}
              type="submit"
              disabled={controlsDisabled || !targetInput.trim()}
            >
              {submitting
                ? "Starting trace…"
                : isActive
                  ? "Tracing route…"
                  : "Trace route"}
            </button>
            <button
              className={styles.stopButton}
              type="button"
              onClick={stopTrace}
              disabled={
                !isActive || stopping || Boolean(job?.cancel_requested)
              }
            >
              {stopping || job?.cancel_requested ? "Stopping…" : "Stop"}
            </button>
            <p>
              Public AS enrichment is never performed unless you enable it for
              this trace.
            </p>
          </div>
        </form>
      </section>

      <section
        className={styles.recentPanel}
        aria-labelledby="recent-traces-title"
      >
        <div className={styles.recentHeader}>
          <div>
            <p>Device-local history</p>
            <h2 id="recent-traces-title" ref={recentHeadingRef} tabIndex={-1}>
              Recent target traces
            </h2>
            <span>
              Saved in this browser. NetTrace keeps only the target and start
              time—not hop results.
            </span>
          </div>
          {recentTraces.length ? (
            <div className={styles.recentHeaderActions}>
              <span>
                {recentTraces.length} / {MAX_RECENT_TRACES}
              </span>
              <button type="button" onClick={clearRecentTargets}>
                Clear all
              </button>
            </div>
          ) : null}
        </div>

        <p className="sr-only" role="status" aria-live="polite">
          {recentAnnouncement}
        </p>

        {recentTraces.length ? (
          <ul className={styles.recentList}>
            {recentTraces.map((recent) => (
              <li className={styles.recentItem} key={recent.target}>
                <button
                  className={styles.recentUse}
                  type="button"
                  onClick={() => loadRecentTarget(recent)}
                  disabled={controlsDisabled}
                  aria-label={`Use recent trace target ${recent.target}`}
                >
                  <span>
                    <strong>{recent.target}</strong>
                    <time dateTime={recent.traced_at}>
                      {formatRecentTraceTime(recent.traced_at)}
                    </time>
                  </span>
                  <em>Use target →</em>
                </button>
                <button
                  className={styles.recentRemove}
                  type="button"
                  onClick={() => removeRecentTarget(recent.target)}
                  aria-label={`Remove ${recent.target} from recent traces`}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className={styles.recentEmpty}>
            No recent traces yet. A target appears here after its trace starts.
          </p>
        )}
      </section>

      {error ? (
        <div className={styles.errorBanner} id="trace-error" role="alert">
          <strong>NetTrace needs attention</strong>
          <span>{error}</span>
        </div>
      ) : null}

      {!job ? (
        <section className={styles.emptyState} aria-labelledby="trace-empty-title">
          <div className={styles.emptyRoute} aria-hidden="true">
            <span>1</span>
            <i />
            <span>2</span>
            <i />
            <span>3</span>
          </div>
          <h2 id="trace-empty-title">No route traced yet</h2>
          <p>
            Enter a destination to reveal each responding hop and probe time.
            Enable the Team Cymru option when you also want autonomous-system
            ownership and enter/exit boundaries.
          </p>
        </section>
      ) : (
        <section className={styles.results} aria-labelledby="trace-results-title">
          <div className={styles.resultsHeader}>
            <div>
              <div className={styles.resultTitleRow}>
                <h2 id="trace-results-title">Route to {job.target}</h2>
                <span className={`${styles.statusBadge} ${statusClass}`}>
                  <i aria-hidden="true" />
                  {phaseLabel(job)}
                </span>
              </div>
              <p>
                {job.resolved_address ? (
                  <>
                    {job.address_family ?? "Address"}: {job.resolved_address}
                    <span aria-hidden="true"> · </span>
                  </>
                ) : null}
                Three probes per hop
              </p>
            </div>
            <code title={job.id}>Trace {job.id.slice(0, 8)}</code>
          </div>

          <div className={styles.progressBlock}>
            <div className={styles.progressMeta}>
              <span>{collectingNativeTrace ? "Native trace" : "Trace depth"}</span>
              <strong>
                {collectingNativeTrace
                  ? `Up to ${progressMaximum} hops`
                  : `Hop ${progressValue} / ${progressMaximum}`}
              </strong>
            </div>
            <div
              className={`${styles.progressTrack} ${
                collectingNativeTrace ? styles.progressIndeterminate : ""
              }`}
              role="progressbar"
              aria-label={
                collectingNativeTrace
                  ? "Native route trace in progress"
                  : "Route trace depth"
              }
              aria-valuemin={0}
              aria-valuemax={progressMaximum}
              aria-valuenow={collectingNativeTrace ? undefined : progressValue}
            >
              <span
                style={
                  collectingNativeTrace
                    ? undefined
                    : { width: `${(progressValue / progressMaximum) * 100}%` }
                }
              />
            </div>
          </div>

          <div className={styles.summaryGrid}>
            <article>
              <span>Hops observed</span>
              <strong>{summary.observedHops}</strong>
              <small>through hop {job.progress.last_hop}</small>
            </article>
            <article>
              <span>Responding hops</span>
              <strong>{summary.respondingHops}</strong>
              <small>returned at least one reply</small>
            </article>
            <article>
              <span>Public AS networks</span>
              <strong>
                {job.options.lookup_asn ? summary.publicNetworks : "Off"}
              </strong>
              <small>
                {job.options.lookup_asn
                  ? "unique AS numbers"
                  : "enrichment not requested"}
              </small>
            </article>
            <article>
              <span>Destination</span>
              <strong>
                {job.reached_destination
                  ? "Reached"
                  : isActive
                    ? "Tracing"
                    : "Not reached"}
              </strong>
              <small>
                {job.reached_destination
                  ? "destination replied"
                  : "within the selected hop limit"}
              </small>
            </article>
          </div>

          {job.warnings.length ? (
            <div className={styles.warningPanel} role="status">
              <strong>Trace notes</strong>
              <ul>
                {job.warnings.map((warning, index) => (
                  <li key={`${warningMessage(warning)}-${index}`}>
                    {warningMessage(warning)}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          <section className={styles.pathSection} aria-labelledby="as-path-title">
            <div className={styles.sectionHeading}>
              <div>
                <p>Network transitions</p>
                <h3 id="as-path-title">Autonomous-system path</h3>
              </div>
              <span>
                {job.options.lookup_asn
                  ? "Team Cymru attribution"
                  : "External lookup off"}
              </span>
            </div>

            {!job.options.lookup_asn ? (
              <div className={styles.asnDisabledNote}>
                <strong>AS enrichment was not enabled for this trace.</strong>
                <span>
                  No hop addresses were sent to Team Cymru. Reverse DNS is
                  controlled separately above and may query your configured DNS
                  resolver. Enable “Look up autonomous-system details” before
                  another trace to map public AS boundaries.
                </span>
              </div>
            ) : job.as_path.length ? (
              <>
                <p className={styles.pathDisclosure}>
                  AS enrichment was enabled. NetTrace submits only public
                  responder IP addresses, when present, to Team Cymru for
                  IP-to-AS attribution. A gap or multiple responder networks
                  makes a boundary approximate. Country codes describe registry
                  assignment, not physical location.
                </p>
                <div
                  className={styles.pathScroller}
                  role="region"
                  aria-label="Autonomous-system path from source to destination"
                  tabIndex={0}
                >
                  <ol className={styles.pathList}>
                    {job.as_path.map((segment, index) => {
                      const previous = job.as_path[index - 1];
                      const transition = previous
                        ? boundaryCopy(previous, segment)
                        : null;
                      return (
                        <li
                          className={styles.pathItem}
                          key={`${segment.asn ?? "unmapped"}-${segment.first_hop}-${index}`}
                        >
                          {transition ? (
                            <div
                              className={`${styles.pathTransition} ${
                                transition.uncertain
                                  ? styles.pathTransitionUncertain
                                  : ""
                              }`}
                            >
                              <span aria-hidden="true">→</span>
                              <small>{transition.detail}</small>
                              <span className="sr-only">{transition.label}</span>
                            </div>
                          ) : null}
                          <article className={styles.segmentCard}>
                            <div className={styles.segmentTopline}>
                              <span>
                                {segment.asn == null
                                  ? "LOCAL / UNMAPPED"
                                  : `AS${segment.asn}`}
                              </span>
                              {segment.ambiguous ? <em>Multiple paths</em> : null}
                            </div>
                            <strong>{segment.network_name}</strong>
                            <small>
                              {hopRange(segment.first_hop, segment.last_hop)}
                            </small>
                            {segment.prefixes.length ? (
                              <code>{segment.prefixes.slice(0, 2).join(" · ")}</code>
                            ) : null}
                          </article>
                        </li>
                      );
                    })}
                  </ol>
                </div>
              </>
            ) : (
              <div className={styles.asnDisabledNote}>
                <strong>
                  {isActive
                    ? "Mapping responding networks…"
                    : "No AS path was available."}
                </strong>
                <span>
                  {isActive
                    ? "Segments will appear as public responders are attributed."
                    : "Private hops, timeouts, or an unavailable lookup service can leave the AS path empty."}
                </span>
              </div>
            )}
          </section>

          <section className={styles.hopsSection} aria-labelledby="hop-list-title">
            <div className={styles.sectionHeading}>
              <div>
                <p>Per-probe evidence</p>
                <h3 id="hop-list-title">Hop timeline</h3>
              </div>
              <span>Select a hop for details</span>
            </div>

            {job.hops.length ? (
              <ol className={styles.hopList} aria-label="Traceroute hops">
                {job.hops.map((hop) => {
                  const expanded = expandedHops.has(hop.number);
                  const detailId = `trace-${job.id}-hop-${hop.number}`;
                  const responders = hop.responders;
                  const primary =
                    responders.find((responder) => responder.hostname) ??
                    responders[0];
                  const addresses = Array.from(
                    new Set(responders.map((responder) => responder.address)),
                  );
                  const hopAsns = Array.from(
                    new Map(
                      responders
                        .filter(
                          (responder): responder is TraceResponder & {
                            asn: AutonomousSystem;
                          } => responder.asn != null,
                        )
                        .map((responder) => [
                          responder.asn.number,
                          responder.asn,
                        ]),
                    ).values(),
                  );
                  const segmentIndex = job.as_path.findIndex(
                    (segment) => segment.first_hop === hop.number,
                  );
                  const segment = job.as_path[segmentIndex];
                  const previousSegment = job.as_path[segmentIndex - 1];
                  const transition =
                    segmentIndex > 0 && segment && previousSegment
                      ? boundaryCopy(previousSegment, segment)
                      : null;

                  return (
                    <li className={styles.hopItem} key={hop.number}>
                      {segmentIndex === 0 && segment ? (
                        <div
                          className={`${styles.boundaryMarker} ${
                            segment.boundary_confidence !== "exact" ||
                            segment.ambiguous
                              ? styles.boundaryMarkerUncertain
                              : ""
                          }`}
                        >
                          <span>
                            {segment.boundary_confidence === "exact" &&
                            !segment.ambiguous
                              ? `Enter ${segmentLongLabel(segment)}`
                              : `First observed network: ${segmentLongLabel(segment)}`}
                          </span>
                          <small>
                            {segment.boundary_confidence === "exact" &&
                            !segment.ambiguous
                              ? `First attributed network at hop ${hop.number}`
                              : "Earlier or alternate hops prevent an exact entry boundary."}
                          </small>
                        </div>
                      ) : transition ? (
                        <div
                          className={`${styles.boundaryMarker} ${
                            transition.uncertain
                              ? styles.boundaryMarkerUncertain
                              : ""
                          }`}
                        >
                          <span>{transition.label}</span>
                          <small>{transition.detail}</small>
                        </div>
                      ) : null}

                      <article
                        className={`${styles.hopCard} ${
                          hop.reached_destination ? styles.destinationHop : ""
                        }`}
                      >
                        <button
                          className={styles.hopToggle}
                          type="button"
                          aria-expanded={expanded}
                          aria-controls={detailId}
                          onClick={() => toggleHop(hop.number)}
                        >
                          <span className={styles.hopNumber} aria-hidden="true">
                            {String(hop.number).padStart(2, "0")}
                          </span>
                          <span className={styles.hopIdentity}>
                            <strong>
                              {primary?.hostname ??
                                primary?.address ??
                                "No response"}
                            </strong>
                            <small>
                              {addresses.length
                                ? addresses.join(" · ")
                                : "All probes timed out"}
                            </small>
                          </span>
                          <span className={styles.hopNetworks}>
                            {hopAsns.length ? (
                              hopAsns.map((asn) => (
                                <span key={asn.number}>{asLongLabel(asn)}</span>
                              ))
                            ) : primary ? (
                              <span>{formatScope(primary.scope)} network</span>
                            ) : (
                              <span>Unmapped</span>
                            )}
                            {hopAsns.length > 1 ? (
                              <em>Multiple AS responders</em>
                            ) : null}
                          </span>
                          <span className={styles.expandIndicator} aria-hidden="true">
                            {expanded ? "−" : "+"}
                          </span>
                          <span className="sr-only">
                            {expanded ? "Collapse" : "Expand"} hop {hop.number}
                            details
                          </span>
                        </button>

                        <div
                          className={styles.probeRow}
                          aria-label={`Probe results for hop ${hop.number}`}
                        >
                          {hop.probes.map((probe) => (
                            <span
                              className={`${styles.probeChip} ${probeTone(
                                probe.status,
                              )}`}
                              key={probe.sequence}
                              title={
                                probe.annotation ??
                                `Probe ${probe.sequence}: ${probe.status}`
                              }
                            >
                              <small>Probe {probe.sequence}</small>
                              <strong>
                                {probe.status === "reply"
                                  ? formatLatency(probe.latency_ms)
                                  : probe.status === "timeout"
                                    ? "Timed out"
                                    : "Unreachable"}
                              </strong>
                            </span>
                          ))}
                          {hop.reached_destination ? (
                            <span className={styles.destinationBadge}>
                              Destination reached
                            </span>
                          ) : null}
                        </div>

                        {expanded ? (
                          <div id={detailId}>
                            <HopDetails hop={hop} />
                          </div>
                        ) : null}
                      </article>
                    </li>
                  );
                })}
              </ol>
            ) : (
              <div className={styles.waitingForHops}>
                <span aria-hidden="true">···</span>
                <strong>Collecting the native route</strong>
                <p>
                  Hop and timing details appear after the native traceroute pass
                  completes.
                </p>
              </div>
            )}
          </section>
        </section>
      )}
    </div>
  );
}
