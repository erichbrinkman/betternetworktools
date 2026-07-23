"use client";

import {
  type FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import styles from "./nettransfer.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const SERVER_URL = `${API_BASE_URL}/api/transfer-server`;
const FILES_URL = `${SERVER_URL}/files`;
const POLL_INTERVAL_MS = 1_500;

type TransferProtocol = "tftp" | "sftp" | "ftp";
type Exposure = "local" | "lan";
type ConnectionState = "checking" | "online" | "offline";
type TransferDirection = "download" | "upload";
type TransferStatus = "active" | "completed" | "failed" | "cancelled";
type ServerState = "stopped" | "starting" | "running" | "stopping";

type TransferEvent = {
  id: string;
  protocol: TransferProtocol;
  direction: TransferDirection;
  status: TransferStatus;
  filename: string;
  client: string;
  username: string | null;
  bytes_transferred: number;
  started_at: string;
  finished_at: string | null;
  error: string | null;
};

type TransferServerStatus = {
  state: ServerState;
  running: boolean;
  protocol: TransferProtocol | null;
  transport: "udp" | "tcp" | null;
  bind_address: string;
  port: number | null;
  root_directory: string;
  allow_read: boolean;
  allow_write: boolean;
  allow_overwrite: boolean;
  allowed_client_cidrs: string[];
  authentication: "none" | "password";
  username: string | null;
  sftp_host_key_fingerprint: string | null;
  ftp_passive_port_start: number | null;
  ftp_passive_port_end: number | null;
  default_ports: Record<TransferProtocol, number>;
  started_at: string | null;
  active_transfer_count: number;
  completed_transfer_count: number;
  failed_transfer_count: number;
  bytes_sent: number;
  bytes_received: number;
  recent_transfers: TransferEvent[];
};

type TransferFile = {
  filename: string;
  size: number;
  modified_at: string;
};

type TransferFileList = {
  root_directory: string;
  files: TransferFile[];
  truncated: boolean;
};

type ProtocolDraft = {
  port: string;
  username: string;
  password: string;
  acknowledgePlaintextFtp: boolean;
};

const FALLBACK_PORTS: Record<TransferProtocol, number> = {
  tftp: 6969,
  sftp: 2222,
  ftp: 2121,
};

const STANDARD_PORTS: Record<TransferProtocol, number> = {
  tftp: 69,
  sftp: 22,
  ftp: 21,
};

const PROTOCOLS = [
  {
    value: "tftp",
    label: "TFTP",
    transport: "UDP",
    description: "Simple device transfers",
  },
  {
    value: "sftp",
    label: "SFTP",
    transport: "SSH · TCP",
    description: "Encrypted and authenticated",
  },
  {
    value: "ftp",
    label: "FTP",
    transport: "TCP",
    description: "Legacy client compatibility",
  },
] as const;

const INITIAL_DRAFTS: Record<TransferProtocol, ProtocolDraft> = {
  tftp: {
    port: String(FALLBACK_PORTS.tftp),
    username: "",
    password: "",
    acknowledgePlaintextFtp: false,
  },
  sftp: {
    port: String(FALLBACK_PORTS.sftp),
    username: "nettransfer",
    password: "",
    acknowledgePlaintextFtp: false,
  },
  ftp: {
    port: String(FALLBACK_PORTS.ftp),
    username: "nettransfer",
    password: "",
    acknowledgePlaintextFtp: false,
  },
};

function protocolLabel(protocol: TransferProtocol) {
  return protocol.toUpperCase();
}

function protocolTransport(protocol: TransferProtocol) {
  return protocol === "tftp" ? "UDP" : "TCP";
}

function isValidIpv4(value: string) {
  const octets = value.split(".");
  return (
    octets.length === 4 &&
    octets.every(
      (octet) =>
        /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255,
    )
  );
}

function isValidIpv4Cidr(value: string) {
  const [address, prefix, extra] = value.split("/");
  return (
    extra === undefined &&
    Boolean(prefix) &&
    isValidIpv4(address) &&
    /^\d{1,2}$/.test(prefix) &&
    Number(prefix) >= 1 &&
    Number(prefix) <= 32
  );
}

function parseCidrs(value: string) {
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeDefaultPorts(
  value: Partial<Record<TransferProtocol, number>> | null | undefined,
) {
  const next = { ...FALLBACK_PORTS };
  for (const protocol of ["tftp", "sftp", "ftp"] as const) {
    const port = value?.[protocol];
    if (Number.isInteger(port) && Number(port) >= 1 && Number(port) <= 65_535) {
      next[protocol] = Number(port);
    }
  }
  return next;
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const amount = value / 1024 ** index;
  return `${amount.toLocaleString(undefined, {
    maximumFractionDigits:
      index === 0 ? 0 : amount >= 100 ? 0 : amount >= 10 ? 1 : 2,
  })} ${units[index]}`;
}

function formatWhen(value: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function transferVerb(direction: TransferDirection) {
  return direction === "download" ? "Download" : "Upload";
}

function statusLabel(status: TransferStatus) {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

function endpointFor(
  protocol: TransferProtocol,
  address: string,
  port: number | null,
  username: string | null,
) {
  if (!port) return "—:—";
  const account = protocol === "tftp" || !username ? "" : `${username}@`;
  return `${protocol}://${account}${address}:${port}`;
}

async function responseError(response: Response, fallback: string) {
  try {
    const payload = (await response.json()) as {
      detail?: string | { message?: string } | Array<{ msg?: string }>;
    };
    if (typeof payload.detail === "string") return payload.detail;
    if (Array.isArray(payload.detail)) {
      const message = payload.detail
        .map((entry) => entry.msg)
        .filter(Boolean)
        .join(" ");
      if (message) return message;
    }
    if (
      payload.detail &&
      typeof payload.detail === "object" &&
      "message" in payload.detail &&
      typeof payload.detail.message === "string"
    ) {
      return payload.detail.message;
    }
  } catch {
    // The status-based fallback remains useful for non-JSON errors.
  }
  return fallback;
}

export function NetTransferClient() {
  const [server, setServer] = useState<TransferServerStatus | null>(null);
  const [files, setFiles] = useState<TransferFile[]>([]);
  const [filesRoot, setFilesRoot] = useState<string | null>(null);
  const [filesTruncated, setFilesTruncated] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const [connection, setConnection] =
    useState<ConnectionState>("checking");
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"start" | "stop" | null>(null);

  const [protocol, setProtocol] = useState<TransferProtocol>("tftp");
  const [drafts, setDrafts] =
    useState<Record<TransferProtocol, ProtocolDraft>>(INITIAL_DRAFTS);
  const [defaultPorts, setDefaultPorts] =
    useState<Record<TransferProtocol, number>>(FALLBACK_PORTS);
  const [exposure, setExposure] = useState<Exposure>("local");
  const [allowedCidrs, setAllowedCidrs] = useState("");
  const [allowRead, setAllowRead] = useState(true);
  const [allowWrite, setAllowWrite] = useState(false);
  const [allowOverwrite, setAllowOverwrite] = useState(false);

  const pollingRef = useRef(false);
  const actionRef = useRef(false);
  const hydratedConfigRef = useRef(false);
  const hydratedDefaultsRef = useRef(false);

  const updateDraft = useCallback(
    (draftProtocol: TransferProtocol, patch: Partial<ProtocolDraft>) => {
      setDrafts((current) => ({
        ...current,
        [draftProtocol]: { ...current[draftProtocol], ...patch },
      }));
    },
    [],
  );

  const syncDefaults = useCallback((status: TransferServerStatus) => {
    const nextDefaults = normalizeDefaultPorts(status.default_ports);
    setDefaultPorts(nextDefaults);
    if (!hydratedDefaultsRef.current) {
      setDrafts((current) => ({
        tftp: { ...current.tftp, port: String(nextDefaults.tftp) },
        sftp: { ...current.sftp, port: String(nextDefaults.sftp) },
        ftp: { ...current.ftp, port: String(nextDefaults.ftp) },
      }));
      hydratedDefaultsRef.current = true;
    }
  }, []);

  const syncRunningConfiguration = useCallback(
    (status: TransferServerStatus) => {
      if (!status.protocol) return;
      const activeProtocol = status.protocol;
      const isLocal = status.bind_address === "127.0.0.1";
      setProtocol(activeProtocol);
      setExposure(isLocal ? "local" : "lan");
      setAllowedCidrs(
        isLocal ? "" : status.allowed_client_cidrs.join("\n"),
      );
      setAllowRead(status.allow_read);
      setAllowWrite(status.allow_write);
      setAllowOverwrite(status.allow_overwrite);
      setDrafts((current) => ({
        ...current,
        [activeProtocol]: {
          ...current[activeProtocol],
          port: String(
            status.port ??
              status.default_ports?.[activeProtocol] ??
              FALLBACK_PORTS[activeProtocol],
          ),
          username:
            activeProtocol === "tftp"
              ? ""
              : status.username ?? current[activeProtocol].username,
          password: "",
        },
      }));
      hydratedConfigRef.current = true;
    },
    [],
  );

  const refreshSnapshot = useCallback(async () => {
    if (pollingRef.current || actionRef.current) return;
    pollingRef.current = true;

    try {
      const response = await fetch(SERVER_URL, {
        cache: "no-store",
        credentials: "omit",
      });
      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `Could not read transfer server status (${response.status}).`,
          ),
        );
      }

      const nextServer = (await response.json()) as TransferServerStatus;
      setServer(nextServer);
      setConnection("online");
      setRefreshError(null);
      syncDefaults(nextServer);

      if (nextServer.state !== "stopped" && nextServer.protocol) {
        syncRunningConfiguration(nextServer);
      } else if (!hydratedConfigRef.current) {
        const isLocal = nextServer.bind_address === "127.0.0.1";
        setExposure(isLocal ? "local" : "lan");
        setAllowedCidrs(
          isLocal ? "" : nextServer.allowed_client_cidrs.join("\n"),
        );
        setAllowRead(nextServer.allow_read);
        setAllowWrite(nextServer.allow_write);
        setAllowOverwrite(nextServer.allow_overwrite);
        hydratedConfigRef.current = true;
      }

      try {
        const filesResponse = await fetch(FILES_URL, {
          cache: "no-store",
          credentials: "omit",
        });
        if (!filesResponse.ok) {
          throw new Error(
            await responseError(
              filesResponse,
              `Could not list shared files (${filesResponse.status}).`,
            ),
          );
        }
        const fileList = (await filesResponse.json()) as TransferFileList;
        setFiles(fileList.files);
        setFilesRoot(fileList.root_directory);
        setFilesTruncated(fileList.truncated);
        setFileError(null);
      } catch (error) {
        setFileError(
          error instanceof Error
            ? error.message
            : "The shared file list is unavailable.",
        );
      }
    } catch (error) {
      setConnection("offline");
      setRefreshError(
        error instanceof Error
          ? error.message
          : "The local Better Network Tools service is unavailable.",
      );
    } finally {
      pollingRef.current = false;
    }
  }, [syncDefaults, syncRunningConfiguration]);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => {
      void refreshSnapshot();
    }, 0);
    const timer = window.setInterval(() => {
      void refreshSnapshot();
    }, POLL_INTERVAL_MS);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
    };
  }, [refreshSnapshot]);

  const draft = drafts[protocol];
  const parsedPort = Number(draft.port);
  const portIsValid =
    /^\d+$/.test(draft.port) &&
    Number.isInteger(parsedPort) &&
    parsedPort >= 1 &&
    parsedPort <= 65_535;
  const cidrs = useMemo(() => parseCidrs(allowedCidrs), [allowedCidrs]);
  const cidrsAreValid =
    exposure === "local" ||
    (cidrs.length > 0 && cidrs.length <= 8 && cidrs.every(isValidIpv4Cidr));
  const permissionsAreValid = allowRead || allowWrite;
  const usernameIsValid =
    protocol === "tftp" || /^[A-Za-z0-9._-]{1,64}$/.test(draft.username);
  const passwordIsValid =
    protocol === "tftp" ||
    (draft.password.length >= 12 && draft.password.length <= 128);
  const ftpAcknowledgementIsValid =
    protocol !== "ftp" ||
    exposure === "local" ||
    draft.acknowledgePlaintextFtp;
  const formIsValid =
    portIsValid &&
    cidrsAreValid &&
    permissionsAreValid &&
    usernameIsValid &&
    passwordIsValid &&
    ftpAcknowledgementIsValid;

  const serverActive =
    Boolean(server?.protocol) && server?.state !== "stopped";
  const configurationLocked = serverActive || Boolean(busy);
  const runtimeProtocol =
    serverActive && server?.protocol ? server.protocol : protocol;
  const runtimeUsername =
    serverActive && server?.protocol !== "tftp"
      ? server?.username ?? null
      : runtimeProtocol === "tftp"
        ? null
        : drafts[runtimeProtocol].username || null;
  const runtimeAddress = serverActive
    ? server?.bind_address ?? "127.0.0.1"
    : exposure === "local"
      ? "127.0.0.1"
      : "0.0.0.0";
  const runtimePort = serverActive
    ? server?.port ?? null
    : portIsValid
      ? parsedPort
      : null;
  const rootDirectory = server?.root_directory ?? filesRoot;

  function chooseProtocol(nextProtocol: TransferProtocol) {
    if (configurationLocked) return;
    setProtocol(nextProtocol);
    setActionError(null);
  }

  async function startServer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    if (
      !formIsValid ||
      busy ||
      connection !== "online" ||
      serverActive
    ) {
      return;
    }

    setBusy("start");
    setActionError(null);
    actionRef.current = true;
    try {
      const response = await fetch(SERVER_URL, {
        method: "POST",
        credentials: "omit",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          protocol,
          bind_address: exposure === "local" ? "127.0.0.1" : "0.0.0.0",
          port: parsedPort,
          allow_read: allowRead,
          allow_write: allowWrite,
          allow_overwrite: allowWrite && allowOverwrite,
          allowed_client_cidrs: exposure === "local" ? [] : cidrs,
          ...(protocol === "tftp"
            ? {}
            : {
                username: draft.username,
                password: draft.password,
              }),
          acknowledge_plaintext_ftp:
            protocol === "ftp" && exposure === "lan"
              ? draft.acknowledgePlaintextFtp
              : false,
        }),
      });
      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `Could not start the ${protocolLabel(protocol)} server (${response.status}).`,
          ),
        );
      }

      const nextServer = (await response.json()) as TransferServerStatus;
      setServer(nextServer);
      setConnection("online");
      setRefreshError(null);
      syncDefaults(nextServer);
      syncRunningConfiguration(nextServer);
      updateDraft(protocol, { password: "" });
    } catch (error) {
      setActionError(
        error instanceof Error
          ? error.message
          : `Could not start the ${protocolLabel(protocol)} server.`,
      );
    } finally {
      actionRef.current = false;
      setBusy(null);
      void refreshSnapshot();
    }
  }

  async function stopServer() {
    if (busy || connection !== "online" || !serverActive) return;

    setBusy("stop");
    setActionError(null);
    actionRef.current = true;
    try {
      const response = await fetch(SERVER_URL, {
        method: "DELETE",
        credentials: "omit",
      });
      if (!response.ok) {
        throw new Error(
          await responseError(
            response,
            `Could not stop the transfer server (${response.status}).`,
          ),
        );
      }

      const nextServer = (await response.json()) as TransferServerStatus;
      setServer(nextServer);
      setConnection("online");
      setRefreshError(null);
      syncDefaults(nextServer);
    } catch (error) {
      setActionError(
        error instanceof Error
          ? error.message
          : "Could not stop the transfer server.",
      );
    } finally {
      actionRef.current = false;
      setBusy(null);
      void refreshSnapshot();
    }
  }

  const connectionLabel =
    connection === "checking"
      ? "Checking service"
      : connection === "offline"
        ? "Service offline"
        : server?.state === "starting"
          ? `Starting ${protocolLabel(runtimeProtocol)}`
          : server?.state === "stopping"
            ? `Stopping ${protocolLabel(runtimeProtocol)}`
            : server?.running
              ? `${protocolLabel(runtimeProtocol)} server running`
              : "Server stopped";

  const protocolNotice =
    protocol === "tftp"
      ? {
          title: "No authentication or encryption",
          body: "TFTP sends file contents in plaintext and cannot verify a client identity. Use it only on a trusted, firewalled network.",
          tone: styles.noticeWarning,
        }
      : protocol === "sftp"
        ? {
            title: "Encrypted and authenticated",
            body: "SFTP protects credentials and file contents over SSH. Verify the displayed host-key fingerprint on the first connection.",
            tone: styles.noticeSecure,
          }
        : {
            title: "Plaintext credentials and file data",
            body: "FTP exposes usernames, passwords, and file contents to the network. Prefer SFTP unless a legacy client requires FTP.",
            tone: styles.noticeWarning,
          };

  const standardPortSelected =
    portIsValid && parsedPort === STANDARD_PORTS[protocol];
  const privilegedPortSelected = portIsValid && parsedPort < 1024;
  const runtimeClientGate = serverActive
    ? server?.allowed_client_cidrs.length
      ? server.allowed_client_cidrs.join(", ")
      : "Loopback only"
    : exposure === "lan" && cidrs.length
      ? cidrs.join(", ")
      : "Loopback only";

  return (
    <div className={styles.workspace}>
      <section
        className={styles.serverPanel}
        aria-labelledby="transfer-server-title"
      >
        <div className={styles.panelHeader}>
          <div>
            <p className={styles.kicker}>Runtime</p>
            <h2 id="transfer-server-title">Transfer server</h2>
          </div>
          <span
            className={`${styles.statusPill} ${
              connection === "offline"
                ? styles.statusOffline
                : server?.state === "starting" || server?.state === "stopping"
                  ? styles.statusPending
                  : server?.running
                    ? styles.statusRunning
                    : styles.statusStopped
            }`}
            role="status"
          >
            <i aria-hidden="true" />
            {connectionLabel}
          </span>
        </div>

        {connection === "offline" ? (
          <div className={styles.offlineNotice} role="status">
            <div>
              <strong>Local service unavailable</strong>
              <p>
                Start the Better Network Tools Python service, then leave this
                page open. It will reconnect automatically.
              </p>
              {refreshError ? <small>{refreshError}</small> : null}
            </div>
            <button type="button" onClick={() => void refreshSnapshot()}>
              Try again
            </button>
          </div>
        ) : null}

        {actionError ? (
          <div className={styles.errorNotice} role="alert">
            <strong>Server action failed</strong>
            <span>{actionError}</span>
          </div>
        ) : null}

        <div className={styles.panelGrid}>
          <form className={styles.controls} onSubmit={startServer}>
            <fieldset
              className={styles.fieldset}
              disabled={configurationLocked}
            >
              <legend>Protocol</legend>
              <div className={styles.protocolGrid}>
                {PROTOCOLS.map((option) => (
                  <label key={option.value}>
                    <input
                      type="radio"
                      name="transfer-protocol"
                      value={option.value}
                      checked={protocol === option.value}
                      onChange={() => chooseProtocol(option.value)}
                    />
                    <span>
                      <span className={styles.protocolCardHeading}>
                        <strong>{option.label}</strong>
                        <em>{option.transport}</em>
                      </span>
                      <small>{option.description}</small>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            <div
              className={`${styles.protocolNotice} ${protocolNotice.tone}`}
              role="note"
              aria-live="polite"
            >
              <span className={styles.safetyMark} aria-hidden="true">
                {protocol === "sftp" ? "✓" : "!"}
              </span>
              <div>
                <strong>{protocolNotice.title}</strong>
                <p>{protocolNotice.body}</p>
              </div>
            </div>

            <fieldset
              className={styles.fieldset}
              disabled={configurationLocked}
            >
              <legend>Network exposure</legend>
              <div className={styles.segmented}>
                <label>
                  <input
                    type="radio"
                    name="transfer-exposure"
                    checked={exposure === "local"}
                    onChange={() => {
                      setExposure("local");
                      if (protocol === "ftp") {
                        updateDraft("ftp", {
                          acknowledgePlaintextFtp: false,
                        });
                      }
                    }}
                  />
                  <span>
                    <strong>This machine</strong>
                    <small>127.0.0.1 only</small>
                  </span>
                </label>
                <label>
                  <input
                    type="radio"
                    name="transfer-exposure"
                    checked={exposure === "lan"}
                    onChange={() => setExposure("lan")}
                  />
                  <span>
                    <strong>Local network</strong>
                    <small>0.0.0.0 + CIDR gate</small>
                  </span>
                </label>
              </div>
            </fieldset>

            <div className={styles.inputGrid}>
              <label className={styles.rootField}>
                <span>Root directory</span>
                <div className={styles.readonlyValue}>
                  <code>{rootDirectory ?? "Waiting for local service…"}</code>
                  <span>Server managed</span>
                </div>
                <small>
                  Shared by all protocols; files never escape this directory.
                </small>
              </label>

              <label>
                <span>Port</span>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  inputMode="numeric"
                  value={draft.port}
                  disabled={configurationLocked}
                  onChange={(event) =>
                    updateDraft(protocol, { port: event.target.value })
                  }
                  aria-invalid={!portIsValid}
                  aria-describedby="transfer-port-help"
                />
                <small id="transfer-port-help">
                  {portIsValid
                    ? `${protocolTransport(protocol)} listener · default ${defaultPorts[protocol]}`
                    : "Enter a whole number from 1 to 65535"}
                </small>
              </label>

              <label>
                <span>Bind address</span>
                <div className={styles.readonlyValue}>
                  <code>
                    {exposure === "local" ? "127.0.0.1" : "0.0.0.0"}
                  </code>
                  <span>
                    {exposure === "local" ? "Loopback" : "All interfaces"}
                  </span>
                </div>
                <small>Selected by the exposure boundary above.</small>
              </label>

              {exposure === "lan" ? (
                <label className={styles.rootField}>
                  <span>Allowed client network</span>
                  <textarea
                    value={allowedCidrs}
                    disabled={configurationLocked}
                    onChange={(event) => setAllowedCidrs(event.target.value)}
                    placeholder="192.168.1.0/24"
                    rows={2}
                    spellCheck={false}
                    autoCapitalize="none"
                    aria-invalid={!cidrsAreValid}
                    aria-describedby="transfer-cidr-help"
                  />
                  <small id="transfer-cidr-help">
                    {cidrsAreValid
                      ? "Required for LAN mode. Separate up to eight IPv4 CIDRs with spaces or new lines."
                      : "Enter at least one IPv4 CIDR, such as 192.168.1.0/24."}
                  </small>
                </label>
              ) : null}
            </div>

            {standardPortSelected || privilegedPortSelected ? (
              <div className={styles.portWarning} role="note">
                <span aria-hidden="true">!</span>
                <p>
                  <strong>
                    Port {parsedPort}
                    {standardPortSelected
                      ? ` is the standard ${protocolLabel(protocol)} port.`
                      : " is a privileged port."}
                  </strong>{" "}
                  It may require elevated permissions and can conflict with an
                  existing service. Port {defaultPorts[protocol]} is the safer
                  local default.
                </p>
              </div>
            ) : null}

            {protocol !== "tftp" ? (
              <fieldset
                className={styles.fieldset}
                disabled={configurationLocked}
              >
                <legend>Authentication</legend>
                <div className={styles.inputGrid}>
                  <label>
                    <span>Username</span>
                    <input
                      value={draft.username}
                      disabled={configurationLocked}
                      onChange={(event) =>
                        updateDraft(protocol, { username: event.target.value })
                      }
                      autoComplete="off"
                      spellCheck={false}
                      aria-invalid={!usernameIsValid}
                      aria-describedby="transfer-username-help"
                    />
                    <small id="transfer-username-help">
                      {usernameIsValid
                        ? "Letters, numbers, dot, underscore, or hyphen"
                        : "Enter 1–64 supported username characters"}
                    </small>
                  </label>
                  <label>
                    <span>Password</span>
                    <input
                      type="password"
                      value={draft.password}
                      disabled={configurationLocked}
                      onChange={(event) =>
                        updateDraft(protocol, { password: event.target.value })
                      }
                      autoComplete="new-password"
                      aria-invalid={!passwordIsValid}
                      aria-describedby="transfer-password-help"
                    />
                    <small id="transfer-password-help">
                      {passwordIsValid
                        ? "Held in memory only and cleared after start"
                        : "Enter a password from 12 to 128 characters"}
                    </small>
                  </label>
                </div>
                <p className={styles.credentialsNote}>
                  One named account is active for this server run. NetTransfer
                  never returns or saves its password in the browser.
                </p>
              </fieldset>
            ) : null}

            {protocol === "ftp" && exposure === "lan" ? (
              <label className={styles.acknowledgement}>
                <input
                  type="checkbox"
                  checked={draft.acknowledgePlaintextFtp}
                  disabled={configurationLocked}
                  onChange={(event) =>
                    updateDraft("ftp", {
                      acknowledgePlaintextFtp: event.target.checked,
                    })
                  }
                />
                <span>
                  <strong>
                    I understand that FTP credentials and files will cross this
                    network in plaintext.
                  </strong>
                  <small>
                    The control port and service-managed passive port range must
                    also be allowed by the local firewall.
                  </small>
                </span>
              </label>
            ) : null}

            <fieldset
              className={styles.fieldset}
              disabled={configurationLocked}
            >
              <legend>Transfer permissions</legend>
              <div className={styles.permissionGrid}>
                <label className={styles.toggleRow}>
                  <span>
                    <strong>Allow downloads</strong>
                    <small>Clients can read shared files</small>
                  </span>
                  <input
                    type="checkbox"
                    checked={allowRead}
                    onChange={(event) => setAllowRead(event.target.checked)}
                  />
                </label>
                <label className={styles.toggleRow}>
                  <span>
                    <strong>Allow uploads</strong>
                    <small>Clients can create new files</small>
                  </span>
                  <input
                    type="checkbox"
                    checked={allowWrite}
                    onChange={(event) => {
                      setAllowWrite(event.target.checked);
                      if (!event.target.checked) setAllowOverwrite(false);
                    }}
                  />
                </label>
                <label
                  className={`${styles.toggleRow} ${
                    !allowWrite ? styles.toggleDisabled : ""
                  }`}
                >
                  <span>
                    <strong>Allow overwrite</strong>
                    <small>Uploads may replace an existing file</small>
                  </span>
                  <input
                    type="checkbox"
                    checked={allowOverwrite}
                    disabled={!allowWrite || configurationLocked}
                    onChange={(event) => setAllowOverwrite(event.target.checked)}
                  />
                </label>
              </div>
              {!permissionsAreValid ? (
                <p className={styles.validationError} role="alert">
                  Enable downloads, uploads, or both before starting the server.
                </p>
              ) : null}
            </fieldset>

            <div className={styles.actions}>
              {serverActive ? (
                <button
                  className={styles.stopButton}
                  type="button"
                  disabled={
                    busy === "stop" ||
                    connection !== "online" ||
                    server?.state === "stopping"
                  }
                  onClick={() => void stopServer()}
                >
                  <span aria-hidden="true">■</span>
                  {busy === "stop" || server?.state === "stopping"
                    ? "Stopping server…"
                    : "Stop server"}
                </button>
              ) : (
                <button
                  className={styles.startButton}
                  type="submit"
                  disabled={
                    Boolean(busy) ||
                    connection !== "online" ||
                    !formIsValid
                  }
                >
                  <span aria-hidden="true">▶</span>
                  {busy === "start"
                    ? "Starting server…"
                    : `Start ${protocolLabel(protocol)} server`}
                </button>
              )}
              <p>
                {serverActive
                  ? "Stop the listener before changing its protocol, network, credentials, or permissions."
                  : exposure === "local"
                    ? "Local mode is reachable only from this computer."
                    : "LAN mode accepts only clients inside the CIDR list; the control API stays local."}
              </p>
            </div>
          </form>

          <aside className={styles.runtime} aria-labelledby="runtime-title">
            <div className={styles.runtimeHeading}>
              <div>
                <p className={styles.kicker}>Live status</p>
                <h3 id="runtime-title">
                  {server?.state === "starting"
                    ? "Opening listener"
                    : server?.state === "stopping"
                      ? "Closing listener"
                      : server?.running
                        ? "Listening for transfers"
                        : "Listener idle"}
                </h3>
              </div>
              <span
                className={
                  server?.running ? styles.runtimeOn : styles.runtimeOff
                }
              >
                {server?.state === "starting"
                  ? "Starting"
                  : server?.state === "stopping"
                    ? "Stopping"
                    : server?.running
                      ? "On"
                      : "Off"}
              </span>
            </div>

            <div className={styles.endpointCard}>
              <span>{protocolTransport(runtimeProtocol)} endpoint</span>
              <code>
                {endpointFor(
                  runtimeProtocol,
                  runtimeAddress,
                  runtimePort,
                  runtimeUsername,
                )}
              </code>
              <small>
                {server?.running
                  ? `Started ${formatWhen(server.started_at)}`
                  : "Start the server to open the listener"}
              </small>
            </div>

            <dl className={styles.metrics}>
              <div>
                <dt>Active</dt>
                <dd>{server?.active_transfer_count ?? 0}</dd>
              </div>
              <div>
                <dt>Completed</dt>
                <dd>{server?.completed_transfer_count ?? 0}</dd>
              </div>
              <div>
                <dt>Failed</dt>
                <dd>{server?.failed_transfer_count ?? 0}</dd>
              </div>
              <div>
                <dt>Sent</dt>
                <dd>{formatBytes(server?.bytes_sent ?? 0)}</dd>
              </div>
              <div>
                <dt>Received</dt>
                <dd>{formatBytes(server?.bytes_received ?? 0)}</dd>
              </div>
            </dl>

            <div className={styles.runtimeBoundary}>
              <div>
                <span>Protocol</span>
                <strong>
                  {protocolLabel(runtimeProtocol)} · {protocolTransport(runtimeProtocol)}
                </strong>
              </div>
              <div>
                <span>Authentication</span>
                <strong>
                  {runtimeProtocol === "tftp"
                    ? "None"
                    : runtimeUsername
                      ? `Password · ${runtimeUsername}`
                      : "Password required"}
                </strong>
              </div>
              <div>
                <span>Downloads</span>
                <strong>
                  {(serverActive ? server?.allow_read : allowRead)
                    ? "Allowed"
                    : "Blocked"}
                </strong>
              </div>
              <div>
                <span>Uploads</span>
                <strong>
                  {(serverActive ? server?.allow_write : allowWrite)
                    ? "Allowed"
                    : "Blocked"}
                </strong>
              </div>
              <div>
                <span>Overwrite</span>
                <strong>
                  {(serverActive ? server?.allow_overwrite : allowOverwrite)
                    ? "Allowed"
                    : "Blocked"}
                </strong>
              </div>
              <div>
                <span>Client gate</span>
                <strong>{runtimeClientGate}</strong>
              </div>
              {runtimeProtocol === "sftp" ? (
                <div>
                  <span>Host key</span>
                  <strong>
                    {server?.sftp_host_key_fingerprint ??
                      "Available from local service"}
                  </strong>
                </div>
              ) : null}
              {runtimeProtocol === "ftp" ? (
                <div>
                  <span>Passive ports</span>
                  <strong>
                    {server?.ftp_passive_port_start &&
                    server?.ftp_passive_port_end
                      ? `${server.ftp_passive_port_start}–${server.ftp_passive_port_end}`
                      : "Service managed"}
                  </strong>
                </div>
              ) : null}
            </div>
          </aside>
        </div>
      </section>

      <section className={styles.dataPanel} aria-labelledby="shared-files-title">
        <div className={styles.dataHeader}>
          <div>
            <p className={styles.kicker}>Shared server root</p>
            <h2 id="shared-files-title">Shared files</h2>
          </div>
          <span>
            {files.length} {files.length === 1 ? "file" : "files"}
          </span>
        </div>

        <div className={styles.rootPath}>
          <span>Directory</span>
          <code>{filesRoot ?? rootDirectory ?? "Waiting for local service…"}</code>
        </div>

        {fileError ? (
          <div className={styles.inlineError} role="status">
            <strong>File list unavailable</strong>
            <span>{fileError}</span>
          </div>
        ) : files.length ? (
          <div className={styles.tableWrap}>
            <table className={styles.fileTable}>
              <thead>
                <tr>
                  <th scope="col">Filename</th>
                  <th scope="col">Size</th>
                  <th scope="col">Modified</th>
                </tr>
              </thead>
              <tbody>
                {files.map((file) => (
                  <tr key={file.filename}>
                    <td>
                      <span className={styles.fileIcon} aria-hidden="true">
                        ▤
                      </span>
                      <code>{file.filename}</code>
                    </td>
                    <td>{formatBytes(file.size)}</td>
                    <td>{formatWhen(file.modified_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className={styles.emptyState}>
            <span aria-hidden="true">□</span>
            <strong>No shared files yet</strong>
            <p>
              Add files directly to the server-managed root, or enable uploads
              and send one from an allowed client.
            </p>
          </div>
        )}

        {filesTruncated ? (
          <p className={styles.truncatedNotice}>
            This directory contains more files than the service returns in one
            listing.
          </p>
        ) : null}
      </section>

      <section
        className={styles.dataPanel}
        aria-labelledby="recent-transfers-title"
      >
        <div className={styles.dataHeader}>
          <div>
            <p className={styles.kicker}>Activity</p>
            <h2 id="recent-transfers-title">Recent transfers</h2>
          </div>
          <span>All protocols · live polling</span>
        </div>

        {server?.recent_transfers.length ? (
          <div className={styles.tableWrap}>
            <table className={styles.transferTable}>
              <thead>
                <tr>
                  <th scope="col">Transfer</th>
                  <th scope="col">Client</th>
                  <th scope="col">Status</th>
                  <th scope="col">Bytes</th>
                  <th scope="col">Started</th>
                </tr>
              </thead>
              <tbody>
                {server.recent_transfers.map((transfer) => (
                  <tr key={transfer.id}>
                    <td>
                      <span
                        className={`${styles.directionBadge} ${
                          transfer.direction === "download"
                            ? styles.directionDownload
                            : styles.directionUpload
                        }`}
                      >
                        {transfer.direction === "download" ? "↓" : "↑"}
                      </span>
                      <div>
                        <span className={styles.transferIdentity}>
                          <span className={styles.protocolBadge}>
                            {protocolLabel(transfer.protocol)}
                          </span>
                          <code>{transfer.filename}</code>
                        </span>
                        <small>{transferVerb(transfer.direction)}</small>
                      </div>
                    </td>
                    <td>
                      <code>{transfer.client}</code>
                      <small>
                        {transfer.username ??
                          (transfer.protocol === "tftp"
                            ? "No authentication"
                            : "Authenticated client")}
                      </small>
                    </td>
                    <td>
                      <span
                        className={`${styles.transferStatus} ${
                          styles[`transfer${statusLabel(transfer.status)}`]
                        }`}
                      >
                        {statusLabel(transfer.status)}
                      </span>
                      {transfer.error ? <small>{transfer.error}</small> : null}
                    </td>
                    <td>{formatBytes(transfer.bytes_transferred)}</td>
                    <td>
                      {formatWhen(transfer.started_at)}
                      {transfer.finished_at ? (
                        <small>
                          Finished {formatWhen(transfer.finished_at)}
                        </small>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className={styles.emptyState}>
            <span aria-hidden="true">↕</span>
            <strong>No transfers recorded</strong>
            <p>
              TFTP, SFTP, and FTP downloads and uploads will appear here.
            </p>
          </div>
        )}
      </section>

      <p className={styles.pollingNote} aria-live="polite">
        {connection === "checking"
          ? "Connecting to the local service…"
          : connection === "offline"
            ? "Waiting for the local service to return."
            : "Status, files, and transfers refresh automatically."}
      </p>
    </div>
  );
}
