"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { webServiceUrl } from "./webServiceUrl.mjs";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";

const profiles = {
  quick: {
    label: "Quick",
    note: "Web + remote access",
    ports: [22, 80, 443, 3389],
    timeout: 0.5,
  },
  balanced: {
    label: "Balanced",
    note: "Common infrastructure",
    ports: [22, 53, 80, 161, 443, 445, 3389, 8080, 8443],
    timeout: 0.8,
  },
  extended: {
    label: "Extended",
    note: "Broader service sweep",
    ports: [21, 22, 23, 25, 53, 80, 110, 139, 161, 389, 443, 445, 636, 1433, 3306, 3389, 5432, 5900, 8080, 8443],
    timeout: 1.1,
  },
} as const;

type ProfileName = keyof typeof profiles;
type ScanStatus = "queued" | "running" | "completed" | "cancelled" | "failed";

type OpenPort = {
  port: number;
  service: string | null;
  banner: string | null;
  http_status: number | null;
  http_server: string | null;
};

type Device = {
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  icmp_reachable: boolean;
  reachable: boolean;
  open_ports: OpenPort[];
  discovery_methods: string[];
  confidence_score: number;
  confidence: "low" | "medium" | "high";
};

type ScanJob = {
  id: string;
  status: ScanStatus;
  subnet: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  progress: {
    total_hosts: number;
    scanned_hosts: number;
    discovered_hosts: number;
    percent: number;
  };
  options: {
    ports: number[];
    timeout: number;
    concurrency: number;
    resolve_dns: boolean;
    collect_banners: boolean;
  };
  results: Device[];
  error: string | null;
  cancel_requested: boolean;
};

type RecentScan = Pick<
  ScanJob,
  "id" | "status" | "subnet" | "created_at" | "finished_at" | "progress"
>;

const recentScanTimeFormatter = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

function isValidIpv4Cidr(value: string) {
  const match = value.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d|[12]\d|3[0-2])$/);
  if (!match) return false;
  return match[1].split(".").every((part) => Number(part) <= 255);
}

function statusLabel(status: ScanStatus) {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function formatScanTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : recentScanTimeFormatter.format(date);
}

function escapeCsv(value: string | number | null) {
  const text = value == null ? "" : String(value);
  const safeText = /^[\t\r ]*[=+\-@]/.test(text) ? `'${text}` : text;
  return `"${safeText.replaceAll('"', '""')}"`;
}

export function NetScannerClient() {
  const [subnet, setSubnet] = useState("192.168.1.0/24");
  const [profile, setProfile] = useState<ProfileName>("balanced");
  const [resolveDns, setResolveDns] = useState(true);
  const [collectBanners, setCollectBanners] = useState(true);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [subnetInvalid, setSubnetInvalid] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [filter, setFilter] = useState("");
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [recentScansLoading, setRecentScansLoading] = useState(true);
  const [recentScansMessage, setRecentScansMessage] = useState<string | null>(null);
  const [restoringScanId, setRestoringScanId] = useState<string | null>(null);
  const pollingAbort = useRef<AbortController | null>(null);
  const startInFlight = useRef(false);
  const restoreInFlight = useRef(false);

  const jobId = job?.id;
  const isActive = job?.status === "queued" || job?.status === "running";
  const controlsDisabled =
    submitting || Boolean(isActive) || restoringScanId !== null;

  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;

    async function refreshRecentScans() {
      let shouldContinue = false;
      try {
        const response = await fetch(`${API_BASE_URL}/api/scans?limit=8`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("Recent scans are temporarily unavailable.");
        const scans = (await response.json()) as RecentScan[];
        shouldContinue = scans.some(
          (scan) => scan.status === "queued" || scan.status === "running",
        );
        setRecentScans(
          scans
            .slice()
            .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
            .slice(0, 8),
        );
        setRecentScansMessage(null);
      } catch (caught) {
        if (!(caught instanceof DOMException && caught.name === "AbortError")) {
          setRecentScansMessage(
            caught instanceof Error ? caught.message : "Recent scans are temporarily unavailable.",
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setRecentScansLoading(false);
          if (shouldContinue) {
            timer = window.setTimeout(refreshRecentScans, 1500);
          }
        }
      }
    }

    void refreshRecentScans();
    return () => {
      if (timer !== undefined) window.clearTimeout(timer);
      controller.abort();
    };
  }, [job?.id, job?.status]);

  useEffect(() => {
    if (!jobId || !isActive) return;

    let disposed = false;
    const controller = new AbortController();
    pollingAbort.current = controller;

    let timer: number | undefined;

    async function refresh() {
      let shouldContinue = true;
      try {
        const response = await fetch(`${API_BASE_URL}/api/scans/${jobId}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("The scan engine stopped reporting this job.");
        const nextJob = (await response.json()) as ScanJob;
        if (!disposed) {
          setJob(nextJob);
          if (nextJob.status === "failed") {
            setError(nextJob.error ?? "The scan could not be completed.");
          } else {
            setError(null);
          }
          shouldContinue = nextJob.status === "queued" || nextJob.status === "running";
        }
      } catch (caught) {
        if (!disposed && !(caught instanceof DOMException && caught.name === "AbortError")) {
          setError(caught instanceof Error ? caught.message : "Unable to refresh scan status.");
        }
      } finally {
        if (!disposed && shouldContinue && !controller.signal.aborted) {
          timer = window.setTimeout(refresh, 900);
        }
      }
    }

    void refresh();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
      controller.abort();
    };
  }, [jobId, isActive]);

  const visibleDevices = useMemo(() => {
    const query = filter.trim().toLowerCase();
    if (!query) return job?.results ?? [];
    return (job?.results ?? []).filter((device) =>
      [
        device.ip_address,
        device.hostname,
        device.mac_address,
        device.discovery_methods.join(" "),
        device.open_ports.map((entry) => `${entry.port} ${entry.service ?? ""}`).join(" "),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [filter, job?.results]);

  async function startScan(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (startInFlight.current || restoreInFlight.current || isActive) return;

    startInFlight.current = true;
    setError(null);
    setSubnetInvalid(false);

    if (!isValidIpv4Cidr(subnet)) {
      setError("Enter a valid IPv4 network in CIDR notation, such as 192.168.1.0/24.");
      setSubnetInvalid(true);
      startInFlight.current = false;
      return;
    }

    setSubmitting(true);
    try {
      const selected = profiles[profile];
      const response = await fetch(`${API_BASE_URL}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subnet: subnet.trim(),
          ports: selected.ports,
          timeout: selected.timeout,
          concurrency: 64,
          resolve_dns: resolveDns,
          collect_banners: collectBanners,
        }),
      });

      if (!response.ok) {
        let message = `The scan engine rejected the request (${response.status}).`;
        try {
          const detail = (await response.json()) as {
            detail?: string | { message?: string } | Array<{ msg?: string }>;
          };
          if (typeof detail.detail === "string") message = detail.detail;
          if (
            detail.detail &&
            !Array.isArray(detail.detail) &&
            typeof detail.detail === "object" &&
            typeof detail.detail.message === "string"
          ) {
            message = detail.detail.message;
          }
          if (Array.isArray(detail.detail)) {
            message = detail.detail.map((entry) => entry.msg).filter(Boolean).join(" ") || message;
          }
        } catch {
          // Keep the status-based fallback when the response is not JSON.
        }
        if (response.status === 422) setSubnetInvalid(true);
        throw new Error(message);
      }

      const nextJob = (await response.json()) as ScanJob;
      setFilter("");
      setJob(nextJob);
    } catch (caught) {
      setError(
        caught instanceof TypeError
          ? "The local scan engine is offline. Start it, then try again."
          : caught instanceof Error
            ? caught.message
            : "Unable to start the scan.",
      );
    } finally {
      startInFlight.current = false;
      setSubmitting(false);
    }
  }

  async function cancelScan() {
    if (!job || !isActive) return;
    setError(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/scans/${job.id}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("The scan could not be cancelled.");
      pollingAbort.current?.abort();
      setJob((await response.json()) as ScanJob);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to cancel the scan.");
    }
  }

  async function restoreScan(scan: RecentScan) {
    if (restoreInFlight.current || startInFlight.current || isActive) return;

    restoreInFlight.current = true;
    setRestoringScanId(scan.id);
    setRecentScansMessage(null);
    try {
      const response = await fetch(`${API_BASE_URL}/api/scans/${scan.id}`, {
        cache: "no-store",
      });
      if (response.status === 404 || response.status === 410) {
        setRecentScans((current) => current.filter((entry) => entry.id !== scan.id));
        setRecentScansMessage("That scan has expired and was removed from recent scans.");
        return;
      }
      if (!response.ok) throw new Error("That scan could not be loaded.");

      const restoredJob = (await response.json()) as ScanJob;
      setFilter("");
      setSubnet(restoredJob.subnet);
      setSubnetInvalid(false);
      setJob(restoredJob);
      setError(
        restoredJob.status === "failed"
          ? restoredJob.error ?? "The scan could not be completed."
          : null,
      );
    } catch (caught) {
      setRecentScansMessage(
        caught instanceof TypeError
          ? "The scan engine is offline, so that scan could not be loaded."
          : caught instanceof Error
            ? caught.message
            : "That scan could not be loaded.",
      );
    } finally {
      restoreInFlight.current = false;
      setRestoringScanId(null);
    }
  }

  function exportResults() {
    if (!job?.results.length) return;
    const rows = [
      ["IP address", "Hostname", "MAC address", "Reachable", "Open ports", "Discovery evidence", "Confidence"],
      ...job.results.map((device) => [
        device.ip_address,
        device.hostname,
        device.mac_address,
        device.reachable ? "yes" : "no",
        device.open_ports.map((entry) => `${entry.port}/${entry.service ?? "unknown"}`).join("; "),
        device.discovery_methods.join("; "),
        `${device.confidence} (${device.confidence_score})`,
      ]),
    ];
    const csv = rows.map((row) => row.map(escapeCsv).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `netscanner-${job.subnet.replace("/", "-")}.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="scanner-workspace">
      <aside className="scan-sidebar" aria-label="Scan controls and history">
        <div className="scan-control-panel">
          <form onSubmit={startScan}>
            <div className="panel-heading">
              <span className="panel-step">01</span>
              <div>
                <h2 id="scan-target-title">Define target</h2>
                <p>Scan only networks you own or are authorized to assess.</p>
              </div>
            </div>

          <label className="field-label" htmlFor="subnet">
            IPv4 subnet
          </label>
          <div className="cidr-input-wrap">
            <span aria-hidden="true">CIDR</span>
            <input
              id="subnet"
              name="subnet"
              value={subnet}
              onChange={(event) => {
                setSubnet(event.target.value);
                setSubnetInvalid(false);
              }}
              placeholder="192.168.1.0/24"
              spellCheck={false}
              autoComplete="off"
              aria-invalid={subnetInvalid}
              aria-describedby={error ? "subnet-help scan-error" : "subnet-help"}
              disabled={controlsDisabled}
            />
          </div>
          <p className="field-help" id="subnet-help">
            IPv4 only · local host limit enforced by the engine
          </p>

          <fieldset className="profile-fieldset" disabled={controlsDisabled}>
            <legend>Scan profile</legend>
            <div className="profile-options">
              {(Object.keys(profiles) as ProfileName[]).map((key) => {
                const item = profiles[key];
                return (
                  <label className="profile-option" key={key}>
                    <input
                      type="radio"
                      name="profile"
                      value={key}
                      checked={profile === key}
                      onChange={() => setProfile(key)}
                    />
                    <span>
                      <strong>{item.label}</strong>
                      <small>{item.note}</small>
                    </span>
                    <em>{item.ports.length}</em>
                  </label>
                );
              })}
            </div>
          </fieldset>

          <div className="evidence-options">
            <label>
              <input
                type="checkbox"
                checked={resolveDns}
                onChange={(event) => setResolveDns(event.target.checked)}
                disabled={controlsDisabled}
              />
              <span>
                <strong>Reverse DNS</strong>
                <small>Resolve hostnames</small>
              </span>
            </label>
            <label>
              <input
                type="checkbox"
                checked={collectBanners}
                onChange={(event) => setCollectBanners(event.target.checked)}
                disabled={controlsDisabled}
              />
              <span>
                <strong>Service evidence</strong>
                <small>Collect safe banners</small>
              </span>
            </label>
          </div>

          {error ? (
            <div className="error-message" role="alert" id="scan-error">
              <span aria-hidden="true">!</span>
              <p>{error}</p>
            </div>
          ) : null}

          <div className="scan-actions">
            {isActive ? (
              <button className="button button-danger" type="button" onClick={cancelScan}>
                Cancel scan
              </button>
            ) : (
              <button className="button button-primary" type="submit" disabled={submitting}>
                {submitting ? "Starting…" : "Start discovery"} <span aria-hidden="true">↗</span>
              </button>
            )}
          </div>
          </form>
        </div>

        <section className="recent-scans-panel" aria-labelledby="recent-scans-title">
          <div className="recent-scans-heading">
            <div>
              <span className="panel-step">History</span>
              <h2 id="recent-scans-title">Recent scans</h2>
            </div>
            <span aria-hidden="true">{recentScans.length}/8</span>
          </div>

          {recentScansLoading && recentScans.length === 0 ? (
            <p className="recent-scans-empty">Loading recent scans…</p>
          ) : recentScans.length ? (
            <ul className="recent-scans-list">
              {recentScans.map((scan) => {
                const isCurrent = job?.id === scan.id;
                const isRestoring = restoringScanId === scan.id;
                const historyDisabled =
                  submitting || restoringScanId !== null || Boolean(isActive);
                return (
                  <li key={scan.id}>
                    <button
                      className={`recent-scan-item${isCurrent ? " is-current" : ""}`}
                      type="button"
                      onClick={() => void restoreScan(scan)}
                      disabled={historyDisabled}
                      aria-current={isCurrent ? "true" : undefined}
                      aria-busy={isRestoring}
                      aria-label={`Load ${scan.subnet} scan from ${formatScanTime(scan.created_at)}. ${statusLabel(scan.status)}, ${scan.progress.discovered_hosts} discovered.`}
                    >
                      <span className="recent-scan-primary">
                        <strong>{scan.subnet}</strong>
                        <time dateTime={scan.created_at}>{formatScanTime(scan.created_at)}</time>
                      </span>
                      <span className="recent-scan-meta">
                        <span className={`scan-state scan-state-${scan.status}`}>
                          <i aria-hidden="true" /> {isRestoring ? "Loading" : statusLabel(scan.status)}
                        </span>
                        <span>{scan.progress.discovered_hosts} discovered</span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="recent-scans-empty">Your latest scans will appear here.</p>
          )}

          {recentScansMessage ? (
            <p className="recent-scans-message" role="status">
              {recentScansMessage}
            </p>
          ) : null}
        </section>
      </aside>

      <section className="results-panel" aria-labelledby="results-title">
        <div className="results-topbar">
          <div>
            <span className="panel-step">02</span>
            <div>
              <h2 id="results-title">Discovery results</h2>
              <p>
                {job ? job.subnet : "Run a scan to build an evidence-backed device inventory."}
              </p>
            </div>
          </div>
          {job?.results.length ? (
            <button className="button button-quiet button-small" type="button" onClick={exportResults}>
              Export CSV
            </button>
          ) : null}
        </div>

        {job ? (
          <>
            <div className="scan-progress-block">
              <p className="sr-only" aria-live="polite">
                Scan status: {statusLabel(job.status)}.
              </p>
              <div className="progress-summary">
                <div>
                  <span className={`scan-state scan-state-${job.status}`}>
                    <i aria-hidden="true" /> {statusLabel(job.status)}
                  </span>
                  <strong>{Math.round(job.progress.percent)}%</strong>
                </div>
                <p>
                  {job.progress.scanned_hosts} of {job.progress.total_hosts} hosts examined ·{" "}
                  {job.progress.discovered_hosts} discovered
                </p>
              </div>
              <progress value={job.progress.percent} max="100" aria-label="Scan progress">
                {job.progress.percent}%
              </progress>
            </div>

            <div className="result-metrics">
              <div>
                <span>Discovered</span>
                <strong>{job.progress.discovered_hosts}</strong>
              </div>
              <div>
                <span>Open services</span>
                <strong>{job.results.reduce((total, device) => total + device.open_ports.length, 0)}</strong>
              </div>
              <div>
                <span>High confidence</span>
                <strong>{job.results.filter((device) => device.confidence === "high").length}</strong>
              </div>
            </div>

            <div className="result-toolbar">
              <label htmlFor="result-filter">Filter results</label>
              <input
                id="result-filter"
                type="search"
                placeholder="IP, hostname, MAC, service…"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              />
              <span>{visibleDevices.length} shown</span>
            </div>

            {visibleDevices.length ? (
              <div className="results-table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Address / identity</th>
                      <th scope="col">MAC address</th>
                      <th scope="col">Evidence</th>
                      <th scope="col">Open services</th>
                      <th scope="col">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visibleDevices.map((device) => (
                      <tr key={device.ip_address}>
                        <td>
                          <strong>{device.ip_address}</strong>
                          <span>{device.hostname ?? "No hostname resolved"}</span>
                        </td>
                        <td className="mono-cell">{device.mac_address ?? "—"}</td>
                        <td>
                          <div className="evidence-list">
                            {device.discovery_methods.map((method) => (
                              <span key={method}>{method.replaceAll("_", " ")}</span>
                            ))}
                          </div>
                        </td>
                        <td>
                          <div className="port-list">
                            {device.open_ports.length ? (
                              device.open_ports.map((entry) => {
                                const serviceUrl = webServiceUrl(device.ip_address, entry);
                                const serviceDetail = entry.banner ?? entry.http_server;
                                const serviceLabel = (
                                  <>
                                    <strong>{entry.port}</strong>/{entry.service ?? "tcp"}
                                  </>
                                );

                                return serviceUrl ? (
                                  <a
                                    href={serviceUrl}
                                    key={entry.port}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    referrerPolicy="no-referrer"
                                    title={`Open ${serviceUrl} in a new tab${serviceDetail ? ` · ${serviceDetail}` : ""}`}
                                  >
                                    {serviceLabel}
                                    <span className="port-service-external" aria-hidden="true">
                                      ↗
                                    </span>
                                    <span className="sr-only"> (opens in a new tab)</span>
                                  </a>
                                ) : (
                                  <span
                                    key={entry.port}
                                    title={entry.banner ?? entry.http_server ?? undefined}
                                  >
                                    {serviceLabel}
                                  </span>
                                );
                              })
                            ) : (
                              <span className="empty-value">None in profile</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <span className={`confidence confidence-${device.confidence}`}>
                            {device.confidence} · {device.confidence_score}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-results compact">
                <span className="empty-radar" aria-hidden="true">◎</span>
                <h3>{job.results.length ? "No results match that filter" : "Listening for discoveries"}</h3>
                <p>
                  {job.results.length
                    ? "Try a hostname, address, MAC, or service name."
                    : job.status === "completed"
                      ? "No responsive devices were found with this scan profile."
                      : "Responsive devices will appear here while the scan runs."}
                </p>
              </div>
            )}
          </>
        ) : (
          <div className="empty-results">
            <div className="empty-radar-art" aria-hidden="true">
              <i />
              <i />
              <i />
              <span />
            </div>
            <span className="section-kicker">Awaiting target</span>
            <h3>Build a live picture of the subnet</h3>
            <p>
              NetScanner combines reachability, open TCP services, reverse DNS,
              ARP cache evidence, and lightweight service hints.
            </p>
            <div className="method-row" aria-label="Available discovery methods">
              <span>ICMP</span>
              <span>TCP</span>
              <span>DNS</span>
              <span>ARP</span>
              <span>HTTP</span>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
