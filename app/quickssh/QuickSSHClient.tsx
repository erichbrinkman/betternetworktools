"use client";

import "@xterm/xterm/css/xterm.css";

import type { FormEvent } from "react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { Terminal as XTermTerminal } from "@xterm/xterm";
import type { FitAddon as XTermFitAddon } from "@xterm/addon-fit";
import styles from "./quickssh.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";
const STORAGE_KEY = "better-network-tools.quickssh.recents";
const STORAGE_VERSION = 2;
const LEGACY_STORAGE_VERSION = 1;
const TRUSTED_HOST_STORAGE_KEY = "better-network-tools.quickssh.trusted-hosts";
const TRUSTED_HOST_STORAGE_VERSION = 1;
const MAX_RECENT_CONNECTIONS = 20;
const MAX_TRUSTED_HOSTS = 100;
const MAX_INPUT_FRAME_BYTES = 16 * 1024;
const MAX_OUTPUT_FRAME_LENGTH = 16 * 1024 * 1024;
const MIN_REASONABLE_TIMESTAMP = Date.UTC(2000, 0, 1);
const MAX_DATE_TIMESTAMP = 8_640_000_000_000_000;
const MAX_FUTURE_CLOCK_SKEW_MS = 24 * 60 * 60 * 1_000;
const HOSTNAME_LABEL =
  /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/;

type AuthMethod = "password" | "agent";
type Protocol = "ssh" | "telnet";

type StoredHostKey = {
  algorithm: string;
  publicKey: string;
  fingerprint: string;
};

type RecentConnectionBase = {
  host: string;
  port: number;
  pinned: boolean;
  lastUsed: number;
};

type SshRecentConnection = RecentConnectionBase & {
  protocol: "ssh";
  username: string;
  authMethod: AuthMethod;
  hostKey?: StoredHostKey;
};

type TelnetRecentConnection = RecentConnectionBase & {
  protocol: "telnet";
};

type RecentConnection = SshRecentConnection | TelnetRecentConnection;

type TrustedHost = {
  host: string;
  port: number;
  hostKey: StoredHostKey;
  lastTrusted: number;
};

type ActiveConnection =
  | Omit<SshRecentConnection, "pinned" | "lastUsed">
  | Omit<TelnetRecentConnection, "pinned" | "lastUsed">;

type HostKeyChallenge = {
  status: "unknown" | "changed";
  hostKey: StoredHostKey;
  previousFingerprint?: string;
};

type ConnectionState =
  | "idle"
  | "connecting"
  | "checking_host_key"
  | "authenticating"
  | "verifying"
  | "connected"
  | "disconnecting"
  | "disconnected"
  | "error";

type ConnectionValidation =
  | { protocol: "ssh"; host: string; port: number; username: string }
  | { protocol: "telnet"; host: string; port: number }
  | { error: string };

const stateLabels: Record<ConnectionState, string> = {
  idle: "Ready",
  connecting: "Connecting",
  checking_host_key: "Checking host key",
  authenticating: "Authenticating",
  verifying: "Verification required",
  connected: "Connected",
  disconnecting: "Disconnecting",
  disconnected: "Disconnected",
  error: "Connection error",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeText(value: unknown, maximumLength: number) {
  if (typeof value !== "string") return null;
  const trimmed = value.normalize("NFKC").trim();
  if (
    !trimmed ||
    trimmed.length > maximumLength ||
    /[\u0000-\u001f\u007f]/.test(trimmed)
  ) {
    return null;
  }
  return trimmed;
}

function cleanHost(value: string) {
  return value.normalize("NFKC").trim().replace(/\.+$/, "");
}

function isValidIpv4Literal(value: string) {
  const octets = value.split(".");
  return (
    octets.length === 4 &&
    octets.every(
      (octet) =>
        /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255,
    )
  );
}

function isValidIpv6Literal(value: string) {
  const [address, scope, extra] = value.split("%");
  if (
    extra !== undefined ||
    !address.includes(":") ||
    (scope !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(scope))
  ) {
    return false;
  }
  try {
    const parsed = new URL(`http://[${address}]/`);
    return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
  } catch {
    return false;
  }
}

function isValidSshHost(value: string) {
  const containsForbiddenCharacter = [..."/\\?#@[]"].some((character) =>
    value.includes(character),
  );
  if (
    !value ||
    value.length > 253 ||
    value.startsWith("-") ||
    containsForbiddenCharacter ||
    value.includes("://") ||
    /\s/.test(value)
  ) {
    return false;
  }
  if (value.includes(":")) return isValidIpv6Literal(value);
  if (/^[0-9.]+$/.test(value)) return isValidIpv4Literal(value);
  return value.split(".").every((label) => HOSTNAME_LABEL.test(label));
}

function isValidSshUsername(value: string) {
  return (
    value.length >= 1 &&
    value.length <= 128 &&
    !/[\s\u0000-\u001f\u007f]/.test(value)
  );
}

function isReasonableTimestamp(
  value: unknown,
  now = Date.now(),
): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= MIN_REASONABLE_TIMESTAMP &&
    value <= MAX_DATE_TIMESTAMP &&
    value <= now + MAX_FUTURE_CLOCK_SKEW_MS
  );
}

function connectionKey(
  protocol: Protocol,
  host: string,
  port: number,
  username = "",
) {
  const identityUsername =
    protocol === "ssh" ? username.normalize("NFKC").trim() : "";
  return `${protocol}\u0000${identityUsername}\u0000${cleanHost(
    host,
  ).toLocaleLowerCase()}\u0000${port}`;
}

function hostEndpointKey(host: string, port: number) {
  return `${cleanHost(host).toLocaleLowerCase()}\u0000${port}`;
}

function formatDestination(
  protocol: Protocol,
  host: string,
  port: number,
  username = "",
) {
  const displayHost = host.includes(":") ? `[${host}]` : host;
  return protocol === "ssh"
    ? `${username}@${displayHost}:${port}`
    : `telnet://${displayHost}:${port}`;
}

function formatHostEndpoint(host: string, port: number) {
  const displayHost = host.includes(":") ? `[${host}]` : host;
  return `${displayHost}:${port}`;
}

function parseStoredHostKey(value: unknown): StoredHostKey | undefined {
  if (!isRecord(value)) return undefined;
  const algorithm = safeText(value.algorithm, 128);
  const publicKey = safeText(value.publicKey, 16_384);
  const fingerprint = safeText(value.fingerprint, 256);
  if (!algorithm || !publicKey || !fingerprint?.startsWith("SHA256:")) {
    return undefined;
  }
  return { algorithm, publicKey, fingerprint };
}

function parseRecent(
  value: unknown,
  forceLegacySsh = false,
): RecentConnection | null {
  if (!isRecord(value)) return null;
  const host = safeText(value.host, 253);
  const port = value.port;
  const lastUsed = value.lastUsed;
  const protocol = forceLegacySsh
    ? "ssh"
    : value.protocol === undefined
      ? "ssh"
      : value.protocol;
  if (
    !host ||
    (protocol !== "ssh" && protocol !== "telnet") ||
    !isValidSshHost(cleanHost(host)) ||
    !Number.isInteger(port) ||
    (port as number) < 1 ||
    (port as number) > 65_535 ||
    !isReasonableTimestamp(lastUsed) ||
    typeof value.pinned !== "boolean"
  ) {
    return null;
  }

  if (protocol === "telnet") {
    return {
      protocol,
      host: cleanHost(host),
      port: port as number,
      pinned: value.pinned,
      lastUsed,
    };
  }

  const username = safeText(value.username, 128);
  const authMethod = value.authMethod;
  if (
    !username ||
    !isValidSshUsername(username) ||
    (authMethod !== "password" && authMethod !== "agent")
  ) {
    return null;
  }
  const hostKey = parseStoredHostKey(value.hostKey);
  return {
    protocol,
    host: cleanHost(host),
    port: port as number,
    username,
    authMethod,
    pinned: value.pinned,
    lastUsed,
    ...(hostKey ? { hostKey } : {}),
  };
}

function normalizeRecents(connections: RecentConnection[]) {
  const deduplicated = new Map<string, RecentConnection>();

  for (const connection of connections) {
    const key = connectionKey(
      connection.protocol,
      connection.host,
      connection.port,
      connection.protocol === "ssh" ? connection.username : undefined,
    );
    const existing = deduplicated.get(key);
    if (!existing) {
      deduplicated.set(key, connection);
      continue;
    }

    const newer =
      connection.lastUsed >= existing.lastUsed ? connection : existing;
    const older = newer === connection ? existing : connection;
    if (newer.protocol === "ssh" && older.protocol === "ssh") {
      deduplicated.set(key, {
        ...newer,
        pinned: existing.pinned || connection.pinned,
        hostKey: newer.hostKey ?? older.hostKey,
      });
    } else {
      deduplicated.set(key, {
        ...newer,
        pinned: existing.pinned || connection.pinned,
      });
    }
  }

  return [...deduplicated.values()]
    .sort(
      (left, right) =>
        Number(right.pinned) - Number(left.pinned) ||
        right.lastUsed - left.lastUsed ||
        connectionKey(
          left.protocol,
          left.host,
          left.port,
          left.protocol === "ssh" ? left.username : undefined,
        ).localeCompare(
          connectionKey(
            right.protocol,
            right.host,
            right.port,
            right.protocol === "ssh" ? right.username : undefined,
          ),
        ),
    )
    .slice(0, MAX_RECENT_CONNECTIONS);
}

function readRecents() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (
      !isRecord(parsed) ||
      (parsed.version !== STORAGE_VERSION &&
        parsed.version !== LEGACY_STORAGE_VERSION) ||
      !Array.isArray(parsed.connections)
    ) {
      return [];
    }
    const connections = normalizeRecents(
      parsed.connections
        .map((connection) =>
          parseRecent(
            connection,
            parsed.version === LEGACY_STORAGE_VERSION,
          ),
        )
        .filter((entry): entry is RecentConnection => entry !== null),
    );
    if (parsed.version === LEGACY_STORAGE_VERSION) {
      writeRecents(connections);
    }
    return connections;
  } catch {
    return [];
  }
}

function writeRecents(connections: RecentConnection[]) {
  try {
    window.localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        version: STORAGE_VERSION,
        connections: normalizeRecents(connections).map((connection) => ({
          protocol: connection.protocol,
          host: connection.host,
          port: connection.port,
          pinned: connection.pinned,
          lastUsed: connection.lastUsed,
          ...(connection.protocol === "ssh"
            ? {
                username: connection.username,
                authMethod: connection.authMethod,
              }
            : {}),
        })),
      }),
    );
  } catch {
    // A connection still works when storage is unavailable or full.
  }
}

function parseTrustedHost(value: unknown): TrustedHost | null {
  if (!isRecord(value)) return null;
  const host = safeText(value.host, 253);
  const port = value.port;
  const hostKey = parseStoredHostKey(value.hostKey);
  if (
    !host ||
    !isValidSshHost(cleanHost(host)) ||
    !Number.isInteger(port) ||
    (port as number) < 1 ||
    (port as number) > 65_535 ||
    !hostKey ||
    !isReasonableTimestamp(value.lastTrusted)
  ) {
    return null;
  }
  return {
    host: cleanHost(host),
    port: port as number,
    hostKey,
    lastTrusted: value.lastTrusted as number,
  };
}

function normalizeTrustedHosts(hosts: TrustedHost[]) {
  const deduplicated = new Map<string, TrustedHost>();
  for (const host of hosts) {
    const key = hostEndpointKey(host.host, host.port);
    const existing = deduplicated.get(key);
    if (!existing || host.lastTrusted >= existing.lastTrusted) {
      deduplicated.set(key, host);
    }
  }
  return [...deduplicated.values()]
    .sort((left, right) => right.lastTrusted - left.lastTrusted)
    .slice(0, MAX_TRUSTED_HOSTS);
}

function readTrustedHosts() {
  try {
    const raw = window.localStorage.getItem(TRUSTED_HOST_STORAGE_KEY);
    if (!raw) return [];
    const parsed: unknown = JSON.parse(raw);
    if (
      !isRecord(parsed) ||
      parsed.version !== TRUSTED_HOST_STORAGE_VERSION ||
      !Array.isArray(parsed.hosts)
    ) {
      return [];
    }
    return normalizeTrustedHosts(
      parsed.hosts
        .map(parseTrustedHost)
        .filter((entry): entry is TrustedHost => entry !== null),
    );
  } catch {
    return [];
  }
}

function writeTrustedHosts(hosts: TrustedHost[]) {
  try {
    window.localStorage.setItem(
      TRUSTED_HOST_STORAGE_KEY,
      JSON.stringify({
        version: TRUSTED_HOST_STORAGE_VERSION,
        hosts: normalizeTrustedHosts(hosts).map((host) => ({
          host: host.host,
          port: host.port,
          lastTrusted: host.lastTrusted,
          hostKey: {
            algorithm: host.hostKey.algorithm,
            publicKey: host.hostKey.publicKey,
            fingerprint: host.hostKey.fingerprint,
          },
        })),
      }),
    );
  } catch {
    // Host verification still works for this session when storage is unavailable.
  }
}

function migrateRecentHostKeys(connections: RecentConnection[]) {
  return connections.flatMap((connection): TrustedHost[] =>
    connection.protocol === "ssh" && connection.hostKey
      ? [
          {
            host: connection.host,
            port: connection.port,
            hostKey: connection.hostKey,
            lastTrusted: connection.lastUsed,
          },
        ]
      : [],
  );
}

function stripMigratedRecentHostKeys(connections: RecentConnection[]) {
  return connections.map((connection) => {
    if (connection.protocol !== "ssh" || !connection.hostKey) {
      return connection;
    }
    const recent = { ...connection };
    delete recent.hostKey;
    return recent;
  });
}

function formatLastUsed(timestamp: number) {
  const elapsed = Math.max(0, Date.now() - timestamp);
  const minute = 60_000;
  const hour = 60 * minute;
  const day = 24 * hour;
  if (elapsed < minute) return "Just now";
  if (elapsed < hour) return `${Math.floor(elapsed / minute)}m ago`;
  if (elapsed < day) return `${Math.floor(elapsed / hour)}h ago`;
  if (elapsed < 7 * day) return `${Math.floor(elapsed / day)}d ago`;
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
  }).format(timestamp);
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return window.btoa(binary);
}

function binaryStringToBytes(value: string) {
  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    bytes[index] = value.charCodeAt(index) & 0xff;
  }
  return bytes;
}

function base64ToBytes(value: string) {
  if (
    value.length > MAX_OUTPUT_FRAME_LENGTH ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(value)
  ) {
    throw new Error("Invalid terminal output encoding.");
  }
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function sendJson(socket: WebSocket, payload: Record<string, unknown>) {
  socket.send(JSON.stringify(payload));
}

function sendInputBytes(socket: WebSocket, bytes: Uint8Array) {
  let offset = 0;
  while (offset < bytes.length) {
    let end = Math.min(offset + MAX_INPUT_FRAME_BYTES, bytes.length);
    if (end < bytes.length && bytes[end - 1] === 13 && bytes[end] === 10) {
      end -= 1;
    }
    sendJson(socket, {
      type: "input",
      data: bytesToBase64(bytes.subarray(offset, end)),
    });
    offset = end;
  }
}

function webSocketUrl(protocol: Protocol) {
  const url = new URL(API_BASE_URL, window.location.origin);
  if (url.protocol === "http:") url.protocol = "ws:";
  else if (url.protocol === "https:") url.protocol = "wss:";
  else throw new Error("The local API URL must use HTTP or HTTPS.");
  url.pathname = `/api/${protocol}`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

type HostKeyDialogProps = {
  challenge: HostKeyChallenge;
  destination: string;
  onCancel: () => void;
  onTrust: () => void;
};

function HostKeyDialog({
  challenge,
  destination,
  onCancel,
  onTrust,
}: HostKeyDialogProps) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const cancelButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (!dialog.open) dialog.showModal();
    cancelButtonRef.current?.focus();
    return () => {
      if (dialog.open) dialog.close();
    };
  }, []);

  return (
    <dialog
      ref={dialogRef}
      className={styles.hostKeyDialog}
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="host-key-title"
      aria-describedby="host-key-description"
      onCancel={(event) => {
        event.preventDefault();
        onCancel();
      }}
    >
      <div className={styles.dialogContent}>
        <div className={styles.dialogBadge} aria-hidden="true">
          {challenge.status === "changed" ? "!" : "?"}
        </div>
        <div>
          <p className={styles.dialogKicker}>Host identity check</p>
          <h2 id="host-key-title">
            {challenge.status === "changed"
              ? "The host key has changed"
              : "Trust this host?"}
          </h2>
        </div>

        <p id="host-key-description" className={styles.dialogDescription}>
          {challenge.status === "changed"
            ? `The key presented by ${destination} does not match the one saved for this connection. Verify the fingerprint before continuing.`
            : `${destination} has not been verified on this device. Compare this fingerprint with a trusted source before continuing.`}
        </p>

        <dl className={styles.fingerprintDetails}>
          <div>
            <dt>Algorithm</dt>
            <dd>{challenge.hostKey.algorithm}</dd>
          </div>
          <div>
            <dt>SHA256 fingerprint</dt>
            <dd>
              <code>{challenge.hostKey.fingerprint}</code>
            </dd>
          </div>
          {challenge.status === "changed" && challenge.previousFingerprint ? (
            <div>
              <dt>Previously trusted</dt>
              <dd>
                <code>{challenge.previousFingerprint}</code>
              </dd>
            </div>
          ) : null}
        </dl>

        <p className={styles.dialogWarning}>
          An unexpected change can indicate a rebuilt server or a
          machine-in-the-middle attack.
        </p>

        <div className={styles.dialogActions}>
          <button
            ref={cancelButtonRef}
            type="button"
            className={styles.secondaryButton}
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className={styles.trustButton}
            onClick={onTrust}
          >
            {challenge.status === "changed"
              ? "Trust changed key & connect"
              : "Trust & connect"}
          </button>
        </div>
      </div>
    </dialog>
  );
}

export function QuickSSHClient() {
  const [protocol, setProtocol] = useState<Protocol>("ssh");
  const [sessionProtocol, setSessionProtocol] = useState<Protocol | null>(null);
  const [host, setHost] = useState("");
  const [portInput, setPortInput] = useState("22");
  const [username, setUsername] = useState("");
  const [authMethod, setAuthMethod] = useState<AuthMethod>("password");
  const [password, setPassword] = useState("");
  const [telnetAcknowledged, setTelnetAcknowledged] = useState(false);
  const [recents, setRecents] = useState<RecentConnection[]>([]);
  const [trustedHosts, setTrustedHosts] = useState<TrustedHost[]>([]);
  const [storageLoaded, setStorageLoaded] = useState(false);
  const [terminalReady, setTerminalReady] = useState(false);
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("idle");
  const [sessionTarget, setSessionTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const [trustStoreNotice, setTrustStoreNotice] = useState<string | null>(null);
  const [hostKeyChallenge, setHostKeyChallenge] =
    useState<HostKeyChallenge | null>(null);

  const hostInputRef = useRef<HTMLInputElement>(null);
  const terminalContainerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<XTermTerminal | null>(null);
  const fitAddonRef = useRef<XTermFitAddon | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const connectionStateRef = useRef<ConnectionState>("idle");
  const activeConnectionRef = useRef<ActiveConnection | null>(null);
  const connectionSavedRef = useRef(false);

  const updateConnectionState = useCallback((next: ConnectionState) => {
    connectionStateRef.current = next;
    setConnectionState(next);
  }, []);

  const setTerminalInputEnabled = useCallback((enabled: boolean) => {
    const terminal = terminalRef.current;
    if (terminal) terminal.options.disableStdin = !enabled;
  }, []);

  const sendTerminalSize = useCallback(() => {
    const socket = socketRef.current;
    const terminal = terminalRef.current;
    if (
      connectionStateRef.current !== "connected" ||
      !terminal ||
      !socket ||
      socket.readyState !== WebSocket.OPEN
    ) {
      return;
    }
    sendJson(socket, {
      type: "resize",
      cols: terminal.cols,
      rows: terminal.rows,
      pixel_width: 0,
      pixel_height: 0,
    });
  }, []);

  const rememberSuccessfulConnection = useCallback(
    (connection: ActiveConnection) => {
      setRecents((current) => {
        const key = connectionKey(
          connection.protocol,
          connection.host,
          connection.port,
          connection.protocol === "ssh" ? connection.username : undefined,
        );
        const existing = current.find(
          (item) =>
            connectionKey(
              item.protocol,
              item.host,
              item.port,
              item.protocol === "ssh" ? item.username : undefined,
            ) === key,
        );
        let nextConnection: RecentConnection;
        if (connection.protocol === "telnet") {
          nextConnection = {
            protocol: "telnet",
            host: connection.host,
            port: connection.port,
            pinned: existing?.pinned ?? false,
            lastUsed: Date.now(),
          };
        } else {
          const existingSsh =
            existing?.protocol === "ssh" ? existing : undefined;
          nextConnection = {
            protocol: "ssh",
            host: connection.host,
            port: connection.port,
            username: connection.username,
            authMethod: connection.authMethod,
            pinned: existingSsh?.pinned ?? false,
            lastUsed: Date.now(),
          };
        }
        return normalizeRecents([
          ...current.filter(
            (item) =>
              connectionKey(
                item.protocol,
                item.host,
                item.port,
                item.protocol === "ssh" ? item.username : undefined,
              ) !== key,
          ),
          nextConnection,
        ]);
      });
    },
    [],
  );

  const rememberTrustedHost = useCallback(
    (host: string, port: number, hostKey: StoredHostKey) => {
      const lastTrusted = Date.now();
      const endpointKey = hostEndpointKey(host, port);
      const existing = trustedHosts.find(
        (item) => hostEndpointKey(item.host, item.port) === endpointKey,
      );
      if (!existing && trustedHosts.length >= MAX_TRUSTED_HOSTS) {
        setTrustStoreNotice(
          "Trusted-host storage is full. This session can continue, but this host will not be remembered. Forget a trusted host below to save another key.",
        );
        setAnnouncement(
          "Trusted-host storage is full. The current session can continue without saving this host key.",
        );
        return false;
      }
      const nextTrustedHosts = normalizeTrustedHosts([
        ...trustedHosts.filter(
          (item) => hostEndpointKey(item.host, item.port) !== endpointKey,
        ),
        { host, port, hostKey, lastTrusted },
      ]);
      writeTrustedHosts(nextTrustedHosts);
      setTrustedHosts(nextTrustedHosts);
      setTrustStoreNotice(null);
      return true;
    },
    [trustedHosts],
  );

  useEffect(() => {
    const loadTimer = window.setTimeout(() => {
      const loadedRecents = readRecents();
      const loadedTrustedHosts = readTrustedHosts();
      const trustedEndpoints = new Set(
        loadedTrustedHosts.map((item) => hostEndpointKey(item.host, item.port)),
      );
      const remainingCapacity = Math.max(
        0,
        MAX_TRUSTED_HOSTS - loadedTrustedHosts.length,
      );
      const migratedHosts = normalizeTrustedHosts(
        migrateRecentHostKeys(loadedRecents).filter(
          (item) =>
            !trustedEndpoints.has(hostEndpointKey(item.host, item.port)),
        ),
      ).slice(0, remainingCapacity);
      setRecents(stripMigratedRecentHostKeys(loadedRecents));
      setTrustedHosts(
        normalizeTrustedHosts([...loadedTrustedHosts, ...migratedHosts]),
      );
      setStorageLoaded(true);
    }, 0);
    return () => window.clearTimeout(loadTimer);
  }, []);

  useEffect(() => {
    if (!storageLoaded) return;
    writeRecents(recents);
    writeTrustedHosts(trustedHosts);
  }, [recents, storageLoaded, trustedHosts]);

  useEffect(() => {
    const container = terminalContainerRef.current;
    if (!container) return;
    const terminalContainer = container;

    let disposed = false;
    let resizeFrame: number | undefined;
    let observer: ResizeObserver | undefined;
    let dataDisposable: { dispose(): void } | undefined;
    let binaryDisposable: { dispose(): void } | undefined;
    const textEncoder = new TextEncoder();

    async function initializeTerminal() {
      try {
        const [{ Terminal }, { FitAddon }] = await Promise.all([
          import("@xterm/xterm"),
          import("@xterm/addon-fit"),
        ]);
        if (disposed) return;

        const terminal = new Terminal({
          allowTransparency: false,
          convertEol: true,
          cursorBlink: true,
          cursorStyle: "block",
          disableStdin: true,
          drawBoldTextInBrightColors: true,
          fontFamily:
            '"SFMono-Regular", Consolas, "Liberation Mono", ui-monospace, monospace',
          fontSize: 13,
          lineHeight: 1.24,
          screenReaderMode: true,
          scrollback: 5_000,
          theme: {
            background: "#0b0d0e",
            foreground: "#d8dadd",
            cursor: "#c5c9cd",
            cursorAccent: "#0b0d0e",
            selectionBackground: "#454a50",
            black: "#151719",
            red: "#d28d8d",
            green: "#8ead98",
            yellow: "#c6b27d",
            blue: "#91a9be",
            magenta: "#ad9fb8",
            cyan: "#8eb4b3",
            white: "#d8dadd",
            brightBlack: "#747b82",
            brightRed: "#e2a0a0",
            brightGreen: "#9fc1a9",
            brightYellow: "#d6c08a",
            brightBlue: "#a7bfd3",
            brightMagenta: "#c0b0ca",
            brightCyan: "#9fc8c6",
            brightWhite: "#f4f5f6",
          },
        });
        const fitAddon = new FitAddon();
        terminal.loadAddon(fitAddon);
        terminal.open(terminalContainer);
        const terminalInput =
          terminalContainer.querySelector<HTMLTextAreaElement>(
            ".xterm-helper-textarea",
          );
        terminalInput?.setAttribute("aria-labelledby", "terminal-title");
        terminalInput?.setAttribute("aria-describedby", "terminal-help");
        terminalRef.current = terminal;
        fitAddonRef.current = fitAddon;
        fitAddon.fit();
        terminal.writeln(
          "\u001b[2mQuickSSH ready. Choose SSH or Telnet and enter a destination.\u001b[0m",
        );

        dataDisposable = terminal.onData((data) => {
          const socket = socketRef.current;
          if (
            connectionStateRef.current !== "connected" ||
            !socket ||
            socket.readyState !== WebSocket.OPEN
          ) {
            return;
          }
          sendInputBytes(socket, textEncoder.encode(data));
        });

        binaryDisposable = terminal.onBinary((data) => {
          const socket = socketRef.current;
          if (
            connectionStateRef.current !== "connected" ||
            !socket ||
            socket.readyState !== WebSocket.OPEN
          ) {
            return;
          }
          sendInputBytes(socket, binaryStringToBytes(data));
        });

        observer = new ResizeObserver(() => {
          if (resizeFrame !== undefined) window.cancelAnimationFrame(resizeFrame);
          resizeFrame = window.requestAnimationFrame(() => {
            try {
              fitAddon.fit();
              sendTerminalSize();
            } catch {
              // The next visible resize will retry fitting the terminal.
            }
          });
        });
        observer.observe(terminalContainer);
        setTerminalReady(true);
      } catch {
        if (!disposed) {
          setError("The terminal could not be prepared. Refresh and try again.");
          updateConnectionState("error");
        }
      }
    }

    void initializeTerminal();
    return () => {
      disposed = true;
      observer?.disconnect();
      if (resizeFrame !== undefined) window.cancelAnimationFrame(resizeFrame);
      dataDisposable?.dispose();
      binaryDisposable?.dispose();
      terminalRef.current?.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [sendTerminalSize, updateConnectionState]);

  useEffect(
    () => () => {
      const socket = socketRef.current;
      if (socket?.readyState === WebSocket.OPEN) {
        sendJson(socket, { type: "disconnect" });
      }
      socket?.close(1000, "QuickSSH page closed");
      socketRef.current = null;
    },
    [],
  );

  const port = Number(portInput);
  const formConnectionKey =
    host.trim() &&
    (protocol === "telnet" || username.trim()) &&
    Number.isInteger(port)
      ? connectionKey(protocol, host, port, username)
      : "";
  const sessionBusy =
    connectionState === "connecting" ||
    connectionState === "checking_host_key" ||
    connectionState === "authenticating" ||
    connectionState === "verifying" ||
    connectionState === "connected" ||
    connectionState === "disconnecting";
  const unpinnedCount = useMemo(
    () => recents.filter((connection) => !connection.pinned).length,
    [recents],
  );

  function chooseProtocol(nextProtocol: Protocol) {
    if (sessionBusy || nextProtocol === protocol) return;
    const previousDefaultPort = protocol === "ssh" ? "22" : "23";
    const nextDefaultPort = nextProtocol === "ssh" ? "22" : "23";
    setProtocol(nextProtocol);
    setPortInput((current) =>
      current === previousDefaultPort ? nextDefaultPort : current,
    );
    setPassword("");
    setTelnetAcknowledged(false);
    setError(null);
    setAnnouncement(
      nextProtocol === "ssh"
        ? "SSH selected."
        : "Telnet selected. Telnet is unencrypted; traffic can be observed or modified in transit. Prefer SSH.",
    );
  }

  function parseHostKeyMessage(message: Record<string, unknown>) {
    const status = message.status;
    const algorithm = safeText(message.algorithm, 128);
    const publicKey = safeText(message.public_key, 16_384);
    const fingerprint = safeText(message.fingerprint, 256);
    if (
      (status !== "unknown" && status !== "changed") ||
      !algorithm ||
      !publicKey ||
      !fingerprint?.startsWith("SHA256:")
    ) {
      return null;
    }
    return {
      status,
      hostKey: { algorithm, publicKey, fingerprint },
    } satisfies Omit<HostKeyChallenge, "previousFingerprint">;
  }

  function handleServerMessage(socket: WebSocket, raw: unknown) {
    if (socketRef.current !== socket || typeof raw !== "string") return;
    const activeConnection = activeConnectionRef.current;
    const activeProtocol = activeConnection?.protocol ?? protocol;
    const protocolName = activeProtocol === "ssh" ? "SSH" : "Telnet";

    let message: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!isRecord(parsed) || typeof parsed.type !== "string") return;
      message = parsed;
    } catch {
      setError(`The local ${protocolName} service sent an unreadable response.`);
      return;
    }

    if (message.type === "status") {
      const status = message.status;
      if (status === "connecting") {
        updateConnectionState("connecting");
        setAnnouncement(`Connecting to the ${protocolName} host.`);
      } else if (status === "checking_host_key" && activeProtocol === "ssh") {
        updateConnectionState("checking_host_key");
        setAnnouncement("Checking the SSH host identity.");
      } else if (status === "authenticating" && activeProtocol === "ssh") {
        updateConnectionState("authenticating");
        setAnnouncement("Authenticating with the SSH host.");
      } else if (status === "connected") {
        updateConnectionState("connected");
        setTerminalInputEnabled(true);
        setError(null);
        setAnnouncement(
          `${protocolName} connection established. Terminal input is enabled.`,
        );
        if (activeConnection && !connectionSavedRef.current) {
          rememberSuccessfulConnection(activeConnection);
          connectionSavedRef.current = true;
        }
        window.requestAnimationFrame(() => {
          sendTerminalSize();
          terminalRef.current?.focus();
        });
      } else if (status === "disconnected") {
        updateConnectionState("disconnected");
        setTerminalInputEnabled(false);
        setAnnouncement(`${protocolName} connection closed.`);
        socket.close(1000, `${protocolName} session ended`);
      }
      return;
    }

    if (message.type === "output") {
      if (typeof message.data !== "string") return;
      try {
        terminalRef.current?.write(base64ToBytes(message.data));
      } catch {
        setError(
          `The local ${protocolName} service sent invalid terminal output.`,
        );
      }
      return;
    }

    if (message.type === "host_key") {
      if (!activeConnection || activeConnection.protocol !== "ssh") {
        setError("The Telnet service sent an unexpected host-key challenge.");
        updateConnectionState("error");
        socket.close();
        return;
      }
      const challenge = parseHostKeyMessage(message);
      if (!challenge) {
        setError("The SSH host identity could not be verified safely.");
        socket.close();
        updateConnectionState("error");
        return;
      }
      const previousFingerprint = activeConnection.hostKey?.fingerprint;
      setTerminalInputEnabled(false);
      setHostKeyChallenge({
        ...challenge,
        ...(previousFingerprint ? { previousFingerprint } : {}),
      });
      updateConnectionState("verifying");
      setAnnouncement(
        challenge.status === "changed"
          ? "Warning: the SSH host key has changed."
          : "SSH host verification is required.",
      );
      return;
    }

    if (message.type === "error") {
      const messageText =
        safeText(message.message, 1_000) ??
        `The ${protocolName} connection failed.`;
      setError(messageText);
      setAnnouncement(messageText);
      if (message.fatal !== false) {
        setTerminalInputEnabled(false);
        setHostKeyChallenge(null);
        updateConnectionState("error");
        socket.close();
      }
      return;
    }

    if (message.type === "exit") {
      const exitStatus =
        typeof message.exit_status === "number" &&
        Number.isInteger(message.exit_status)
          ? message.exit_status
          : null;
      const signal = safeText(message.signal, 64);
      setTerminalInputEnabled(false);
      updateConnectionState("disconnected");
      setAnnouncement(
        signal
          ? `${protocolName} session exited after signal ${signal}.`
          : exitStatus === null
            ? `${protocolName} session ended.`
            : `${protocolName} session exited with status ${exitStatus}.`,
      );
      socket.close(1000, `${protocolName} process exited`);
    }
  }

  function validateConnection(): ConnectionValidation {
    const normalizedHost = cleanHost(host);
    if (!isValidSshHost(normalizedHost)) {
      return {
        error:
          "Enter a valid hostname or IP address without a URL, path, or brackets.",
      };
    }
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      return { error: "Use a port from 1 to 65535." };
    }
    if (protocol === "telnet") {
      if (!telnetAcknowledged) {
        return {
          error: "Acknowledge the Telnet plaintext warning before connecting.",
        };
      }
      return { protocol, host: normalizedHost, port };
    }
    const normalizedUsername = username.normalize("NFKC").trim();
    if (!isValidSshUsername(normalizedUsername)) {
      return {
        error: "Enter an SSH username without spaces or control characters.",
      };
    }
    if (authMethod === "password" && password.length === 0) {
      return { error: "Enter a password or choose SSH agent / default keys." };
    }
    return {
      protocol,
      host: normalizedHost,
      username: normalizedUsername,
      port,
    };
  }

  function startConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (sessionBusy || !terminalReady || !storageLoaded) return;

    setError(null);
    const validated = validateConnection();
    if ("error" in validated) {
      setError(validated.error);
      return;
    }

    const trustedHost =
      validated.protocol === "ssh"
        ? trustedHosts.find(
            (item) =>
              hostEndpointKey(item.host, item.port) ===
              hostEndpointKey(validated.host, validated.port),
          )
        : undefined;
    const activeConnection: ActiveConnection =
      validated.protocol === "ssh"
        ? {
            protocol: "ssh",
            host: validated.host,
            port: validated.port,
            username: validated.username,
            authMethod,
            ...(trustedHost?.hostKey ? { hostKey: trustedHost.hostKey } : {}),
          }
        : {
            protocol: "telnet",
            host: validated.host,
            port: validated.port,
          };
    const protocolName = validated.protocol === "ssh" ? "SSH" : "Telnet";
    const destination = formatDestination(
      validated.protocol,
      validated.host,
      validated.port,
      validated.protocol === "ssh" ? validated.username : undefined,
    );

    let socket: WebSocket;
    try {
      socket = new WebSocket(webSocketUrl(validated.protocol));
    } catch {
      setError(`The local ${protocolName} service address is not valid.`);
      updateConnectionState("error");
      return;
    }

    socketRef.current = socket;
    activeConnectionRef.current = activeConnection;
    setSessionProtocol(validated.protocol);
    connectionSavedRef.current = false;
    setHost(validated.host);
    setPortInput(String(validated.port));
    setUsername(validated.protocol === "ssh" ? validated.username : "");
    setSessionTarget(destination);
    setHostKeyChallenge(null);
    updateConnectionState("connecting");
    setTerminalInputEnabled(false);
    terminalRef.current?.reset();
    terminalRef.current?.writeln(
      `\u001b[2mOpening ${destination}…\u001b[0m`,
    );

    let passwordForConnect =
      validated.protocol === "ssh" && authMethod === "password"
        ? password
        : undefined;

    socket.addEventListener("open", () => {
      if (socketRef.current !== socket) return;
      try {
        const terminalSize = {
          cols: terminalRef.current?.cols ?? 80,
          rows: terminalRef.current?.rows ?? 24,
        };
        if (validated.protocol === "telnet") {
          sendJson(socket, {
            type: "connect",
            host: validated.host,
            port: validated.port,
            ...terminalSize,
          });
        } else {
          sendJson(socket, {
            type: "connect",
            host: validated.host,
            port: validated.port,
            username: validated.username,
            auth:
              authMethod === "password"
                ? { type: "password", password: passwordForConnect ?? "" }
                : { type: "agent" },
            known_host_key: trustedHost?.hostKey.publicKey ?? null,
            ...terminalSize,
          });
        }
        if (validated.protocol === "ssh" && authMethod === "password") {
          passwordForConnect = undefined;
          setPassword("");
        }
      } catch {
        passwordForConnect = undefined;
        setPassword("");
        setError("The connection request could not be sent.");
        updateConnectionState("error");
        socket.close();
      }
    });

    socket.addEventListener("message", (message) => {
      handleServerMessage(socket, message.data);
    });

    socket.addEventListener("error", () => {
      if (socketRef.current !== socket) return;
      setTerminalInputEnabled(false);
      setError(
        `QuickSSH could not reach the local ${protocolName} service. Make sure Better Network Tools is running locally.`,
      );
      setAnnouncement(`The local ${protocolName} service is unavailable.`);
      updateConnectionState("error");
    });

    socket.addEventListener("close", () => {
      if (socketRef.current !== socket) return;
      socketRef.current = null;
      activeConnectionRef.current = null;
      if (validated.protocol === "telnet") setTelnetAcknowledged(false);
      setSessionProtocol(null);
      setHostKeyChallenge(null);
      setTerminalInputEnabled(false);
      if (
        connectionStateRef.current !== "error" &&
        connectionStateRef.current !== "disconnected"
      ) {
        updateConnectionState("disconnected");
        setAnnouncement(`${protocolName} connection closed.`);
      }
    });
  }

  function disconnect() {
    const socket = socketRef.current;
    setHostKeyChallenge(null);
    setTerminalInputEnabled(false);
    if (!socket) {
      setSessionProtocol(null);
      updateConnectionState("disconnected");
      return;
    }
    updateConnectionState("disconnecting");
    if (socket.readyState === WebSocket.OPEN) {
      sendJson(socket, { type: "disconnect" });
    }
    socket.close(1000, "Disconnected by user");
  }

  function trustHostKey() {
    const challenge = hostKeyChallenge;
    const socket = socketRef.current;
    const activeConnection = activeConnectionRef.current;
    if (
      !challenge ||
      !activeConnection ||
      activeConnection.protocol !== "ssh" ||
      !socket ||
      socket.readyState !== WebSocket.OPEN
    ) {
      setHostKeyChallenge(null);
      setError("The SSH connection closed before the host could be trusted.");
      updateConnectionState("error");
      return;
    }
    rememberTrustedHost(
      activeConnection.host,
      activeConnection.port,
      challenge.hostKey,
    );
    activeConnectionRef.current = {
      ...activeConnection,
      hostKey: challenge.hostKey,
    };
    sendJson(socket, {
      type: "trust_host_key",
      fingerprint: challenge.hostKey.fingerprint,
    });
    setHostKeyChallenge(null);
    updateConnectionState("authenticating");
    setAnnouncement("Host trusted. Continuing SSH authentication.");
  }

  function cancelHostKey() {
    const socket = socketRef.current;
    setHostKeyChallenge(null);
    setTerminalInputEnabled(false);
    setAnnouncement("SSH host was not trusted. Connection cancelled.");
    updateConnectionState("disconnected");
    if (socket?.readyState === WebSocket.OPEN) {
      sendJson(socket, { type: "disconnect" });
    }
    socket?.close(1000, "Host key not trusted");
  }

  function selectRecent(connection: RecentConnection) {
    if (sessionBusy) return;
    setProtocol(connection.protocol);
    setHost(connection.host);
    setPortInput(String(connection.port));
    if (connection.protocol === "ssh") {
      setUsername(connection.username);
      setAuthMethod(connection.authMethod);
    } else {
      setUsername("");
    }
    setPassword("");
    setTelnetAcknowledged(false);
    setError(null);
    setAnnouncement(
      `${formatDestination(
        connection.protocol,
        connection.host,
        connection.port,
        connection.protocol === "ssh" ? connection.username : undefined,
      )} loaded into the connection form.`,
    );
    window.requestAnimationFrame(() => hostInputRef.current?.focus());
  }

  function togglePinned(connection: RecentConnection) {
    const key = connectionKey(
      connection.protocol,
      connection.host,
      connection.port,
      connection.protocol === "ssh" ? connection.username : undefined,
    );
    setRecents((current) =>
      normalizeRecents(
        current.map((item) =>
          connectionKey(
            item.protocol,
            item.host,
            item.port,
            item.protocol === "ssh" ? item.username : undefined,
          ) === key
            ? { ...item, pinned: !item.pinned }
            : item,
        ),
      ),
    );
    setAnnouncement(
      connection.pinned ? "Connection unstarred." : "Connection starred.",
    );
  }

  function deleteRecent(connection: RecentConnection) {
    const key = connectionKey(
      connection.protocol,
      connection.host,
      connection.port,
      connection.protocol === "ssh" ? connection.username : undefined,
    );
    setRecents((current) =>
      current.filter(
        (item) =>
          connectionKey(
            item.protocol,
            item.host,
            item.port,
            item.protocol === "ssh" ? item.username : undefined,
          ) !== key,
      ),
    );
    setAnnouncement("Recent connection removed.");
  }

  function forgetTrustedHost(trustedHost: TrustedHost) {
    const endpointKey = hostEndpointKey(trustedHost.host, trustedHost.port);
    const endpoint = formatHostEndpoint(trustedHost.host, trustedHost.port);
    const nextTrustedHosts = trustedHosts.filter(
      (item) => hostEndpointKey(item.host, item.port) !== endpointKey,
    );
    writeTrustedHosts(nextTrustedHosts);
    setTrustedHosts(nextTrustedHosts);
    const nextRecents = normalizeRecents(
      recents.map((connection) => {
        if (
          connection.protocol !== "ssh" ||
          hostEndpointKey(connection.host, connection.port) !== endpointKey
        ) {
          return connection;
        }
        const withoutHostKey = { ...connection };
        delete withoutHostKey.hostKey;
        return withoutHostKey;
      }),
    );
    writeRecents(nextRecents);
    setRecents(nextRecents);
    const activeConnection = activeConnectionRef.current;
    if (
      activeConnection &&
      activeConnection.protocol === "ssh" &&
      hostEndpointKey(activeConnection.host, activeConnection.port) === endpointKey
    ) {
    }
    setTrustStoreNotice(
      `${endpoint} forgotten. Future connections will require host verification.`,
    );
    setAnnouncement(`${endpoint} removed from trusted hosts.`);
  }

  function clearUnpinned() {
    if (!unpinnedCount) return;
    setRecents((current) => current.filter((connection) => connection.pinned));
    setAnnouncement(
      `${unpinnedCount} unpinned recent connection${
        unpinnedCount === 1 ? "" : "s"
      } cleared.`,
    );
  }

  const statusTone =
    connectionState === "connected"
      ? styles.statusConnected
      : connectionState === "error"
        ? styles.statusError
        : sessionBusy
          ? styles.statusWorking
          : styles.statusIdle;
  const selectedProtocolName = protocol === "ssh" ? "SSH" : "Telnet";
  const sessionProtocolName =
    (sessionProtocol ?? protocol) === "ssh" ? "SSH" : "Telnet";

  return (
    <>
      <section className={styles.workspace} aria-label="QuickSSH workspace">
        <aside className={styles.sidebar} aria-label="Connection setup and recents">
          <div className={styles.connectionPanel}>
            <div className={styles.panelHeading}>
              <div>
                <p className={styles.panelKicker}>New session</p>
                <h2>Connect</h2>
              </div>
              <span aria-hidden="true">{selectedProtocolName}</span>
            </div>

            <form
              onSubmit={startConnection}
              aria-describedby={
                [
                  protocol === "telnet" ? "telnet-warning-copy" : "",
                  error ? "quickssh-form-error" : "",
                ]
                  .filter(Boolean)
                  .join(" ") || undefined
              }
            >
              <fieldset
                className={`${styles.authFieldset} ${styles.protocolFieldset}`}
                disabled={sessionBusy}
              >
                <legend>Protocol</legend>
                <div className={styles.authOptions}>
                  <label
                    className={`${styles.authOption} ${
                      protocol === "ssh" ? styles.authOptionSelected : ""
                    }`}
                  >
                    <input
                      type="radio"
                      name="remote-protocol"
                      value="ssh"
                      checked={protocol === "ssh"}
                      onChange={() => chooseProtocol("ssh")}
                    />
                    <span>SSH</span>
                  </label>
                  <label
                    className={`${styles.authOption} ${
                      protocol === "telnet" ? styles.authOptionSelected : ""
                    }`}
                  >
                    <input
                      type="radio"
                      name="remote-protocol"
                      value="telnet"
                      checked={protocol === "telnet"}
                      aria-describedby={
                        protocol === "telnet"
                          ? "telnet-warning-copy"
                          : undefined
                      }
                      onChange={() => chooseProtocol("telnet")}
                    />
                    <span>Telnet</span>
                  </label>
                </div>
              </fieldset>

              <div className={styles.hostRow}>
                <label className={styles.field}>
                  <span>Host</span>
                  <input
                    ref={hostInputRef}
                    value={host}
                    onChange={(event) => setHost(event.target.value)}
                    placeholder="server.example.com"
                    autoComplete="off"
                    autoCapitalize="none"
                    spellCheck={false}
                    disabled={sessionBusy}
                    required
                  />
                </label>
                <label className={styles.field}>
                  <span>Port</span>
                  <input
                    value={portInput}
                    onChange={(event) => setPortInput(event.target.value)}
                    type="number"
                    inputMode="numeric"
                    min="1"
                    max="65535"
                    disabled={sessionBusy}
                    required
                  />
                </label>
              </div>

              {protocol === "ssh" ? (
                <>
                  <label className={styles.field}>
                    <span>Username</span>
                    <input
                      value={username}
                      onChange={(event) => setUsername(event.target.value)}
                      placeholder="admin"
                      autoComplete="username"
                      autoCapitalize="none"
                      spellCheck={false}
                      disabled={sessionBusy}
                      required
                    />
                  </label>

                  <fieldset
                    className={styles.authFieldset}
                    disabled={sessionBusy}
                  >
                    <legend>Authentication</legend>
                    <div className={styles.authOptions}>
                      <label
                        className={`${styles.authOption} ${
                          authMethod === "password"
                            ? styles.authOptionSelected
                            : ""
                        }`}
                      >
                        <input
                          type="radio"
                          name="ssh-auth-method"
                          value="password"
                          checked={authMethod === "password"}
                          onChange={() => setAuthMethod("password")}
                        />
                        <span>Password</span>
                      </label>
                      <label
                        className={`${styles.authOption} ${
                          authMethod === "agent"
                            ? styles.authOptionSelected
                            : ""
                        }`}
                      >
                        <input
                          type="radio"
                          name="ssh-auth-method"
                          value="agent"
                          checked={authMethod === "agent"}
                          onChange={() => {
                            setAuthMethod("agent");
                            setPassword("");
                          }}
                        />
                        <span>Agent / keys</span>
                      </label>
                    </div>
                  </fieldset>

                  {authMethod === "password" ? (
                    <label className={styles.field}>
                      <span>Password</span>
                      <input
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        type="password"
                        autoComplete="off"
                        disabled={sessionBusy}
                        required
                      />
                    </label>
                  ) : (
                    <p className={styles.agentNote}>
                      The local Python service uses your SSH agent or configured
                      default keys. Private key material never enters the browser.
                    </p>
                  )}
                </>
              ) : (
                <aside
                  className={styles.telnetWarning}
                  aria-labelledby="telnet-warning-title"
                >
                  <strong id="telnet-warning-title">Telnet is plaintext</strong>
                  <p id="telnet-warning-copy">
                    Telnet has no encryption or host verification. Anything you
                    type—including usernames, passwords, and commands—and all
                    output travels as plaintext and can be observed or modified
                    in transit. Use Telnet only on a trusted, isolated network;
                    prefer SSH. Sign in interactively in the terminal. QuickSSH
                    does not store credentials or anything typed there.
                  </p>
                  <label className={styles.telnetAcknowledgement}>
                    <input
                      type="checkbox"
                      checked={telnetAcknowledged}
                      aria-describedby="telnet-warning-copy"
                      onChange={(event) =>
                        setTelnetAcknowledged(event.target.checked)
                      }
                      disabled={sessionBusy}
                    />
                    <span>
                      I understand and want to use Telnet for this connection.
                    </span>
                  </label>
                </aside>
              )}

              <button
                type="submit"
                className={styles.connectButton}
                disabled={
                  sessionBusy ||
                  !terminalReady ||
                  !storageLoaded ||
                  (protocol === "telnet" && !telnetAcknowledged)
                }
              >
                {terminalReady && storageLoaded
                  ? `Connect with ${selectedProtocolName}`
                  : "Preparing terminal…"}
              </button>

              {error ? (
                <p
                  id="quickssh-form-error"
                  className={styles.formError}
                  role="alert"
                >
                  {error}
                </p>
              ) : null}
            </form>
          </div>

          <section className={styles.recentsPanel} aria-labelledby="recent-connections-title">
            <div className={styles.recentsHeading}>
              <div>
                <h2 id="recent-connections-title">Recent connections</h2>
                <span>{recents.length} of {MAX_RECENT_CONNECTIONS}</span>
              </div>
              <button
                type="button"
                className={styles.clearButton}
                onClick={clearUnpinned}
                disabled={!unpinnedCount}
              >
                Clear unpinned
              </button>
            </div>

            <div className={styles.recentList}>
              {storageLoaded && recents.length ? (
                recents.map((connection) => {
                  const key = connectionKey(
                    connection.protocol,
                    connection.host,
                    connection.port,
                    connection.protocol === "ssh"
                      ? connection.username
                      : undefined,
                  );
                  const destination = formatDestination(
                    connection.protocol,
                    connection.host,
                    connection.port,
                    connection.protocol === "ssh"
                      ? connection.username
                      : undefined,
                  );
                  const connectionHost = connection.host.includes(":")
                    ? `[${connection.host}]`
                    : connection.host;
                  return (
                    <article
                      className={`${styles.recentItem} ${
                        key === formConnectionKey ? styles.recentItemSelected : ""
                      }`}
                      key={key}
                    >
                      <button
                        type="button"
                        className={styles.recentDestination}
                        onClick={() => selectRecent(connection)}
                        disabled={sessionBusy}
                        aria-label={`Use ${destination}`}
                      >
                        <strong>
                          {connection.protocol === "ssh"
                            ? `${connection.username}@${connectionHost}`
                            : connectionHost}
                        </strong>
                        <span>
                          {connection.protocol === "ssh"
                            ? `SSH · Port ${connection.port} · ${
                                connection.authMethod === "agent"
                                  ? "Agent / keys"
                                  : "Password"
                              }`
                            : `Telnet · Port ${connection.port} · Interactive login`}
                        </span>
                        <time dateTime={new Date(connection.lastUsed).toISOString()}>
                          {formatLastUsed(connection.lastUsed)}
                        </time>
                      </button>
                      <div className={styles.recentActions}>
                        <button
                          type="button"
                          className={styles.iconButton}
                          onClick={() => togglePinned(connection)}
                          aria-label={`${connection.pinned ? "Unstar" : "Star"} ${destination}`}
                          aria-pressed={connection.pinned}
                          title={connection.pinned ? "Unstar connection" : "Star connection"}
                        >
                          <span aria-hidden="true">{connection.pinned ? "★" : "☆"}</span>
                        </button>
                        <button
                          type="button"
                          className={styles.iconButton}
                          onClick={() => deleteRecent(connection)}
                          aria-label={`Remove ${destination} from recent connections`}
                          title="Remove connection"
                        >
                          <span aria-hidden="true">×</span>
                        </button>
                      </div>
                    </article>
                  );
                })
              ) : (
                <div className={styles.recentsEmpty}>
                  <span aria-hidden="true">↗</span>
                  <p>No recent connections</p>
                  <small>A destination appears here after it connects successfully.</small>
                </div>
              )}
            </div>

            {protocol === "ssh" ? (
              <>
                {trustStoreNotice ? (
                  <p className={styles.trustStoreNotice} role="status">
                    {trustStoreNotice}
                  </p>
                ) : null}

                <details
                  className={styles.trustedHostsPanel}
                  open={
                    trustStoreNotice?.startsWith(
                      "Trusted-host storage is full",
                    ) || undefined
                  }
                >
                  <summary>
                    <span>Trusted hosts</span>
                    <span>
                      {trustedHosts.length} / {MAX_TRUSTED_HOSTS}
                    </span>
                  </summary>
                  <div className={styles.trustedHostsList}>
                    {trustedHosts.length ? (
                      trustedHosts.map((trustedHost) => {
                        const endpoint = formatHostEndpoint(
                          trustedHost.host,
                          trustedHost.port,
                        );
                        return (
                          <div
                            className={styles.trustedHostItem}
                            key={hostEndpointKey(
                              trustedHost.host,
                              trustedHost.port,
                            )}
                          >
                            <div>
                              <strong>{endpoint}</strong>
                              <code>{trustedHost.hostKey.fingerprint}</code>
                            </div>
                            <button
                              type="button"
                              onClick={() => forgetTrustedHost(trustedHost)}
                              aria-label={`Forget trusted host key for ${endpoint}`}
                            >
                              Forget
                            </button>
                          </div>
                        );
                      })
                    ) : (
                      <p className={styles.noTrustedHosts}>
                        No saved host keys.
                      </p>
                    )}
                  </div>
                </details>
              </>
            ) : null}

            <p className={styles.storageNote}>
              Stars and destinations are saved only in this browser. SSH
              verified public host keys are device-local and managed under
              Trusted hosts when SSH is selected. Passwords, Telnet input, and
              terminal activity are never saved.
            </p>
          </section>
        </aside>

        <section className={styles.terminalPanel} aria-labelledby="terminal-title">
          <header className={styles.terminalToolbar}>
            <div className={styles.terminalTitle}>
              <span className={styles.terminalMark} aria-hidden="true">›_</span>
              <div>
                <h2 id="terminal-title">Terminal</h2>
                <p>{sessionTarget || "No active session"}</p>
              </div>
            </div>
            <div className={styles.sessionControls}>
              <div className={`${styles.status} ${statusTone}`} role="status">
                <span aria-hidden="true" />
                {stateLabels[connectionState]}
              </div>
              <button
                type="button"
                className={styles.disconnectButton}
                onClick={disconnect}
                disabled={!sessionBusy || connectionState === "disconnecting"}
                aria-label={`Disconnect ${sessionProtocolName} session`}
                title={
                  sessionBusy
                    ? `Disconnect ${sessionProtocolName} session`
                    : `No active ${selectedProtocolName} session`
                }
              >
                Disconnect
              </button>
            </div>
          </header>

          <div className={styles.terminalBody}>
            <p id="terminal-help" className="sr-only">
              Terminal input is enabled only after a connection is established.
              Use the SSH or Telnet connection form to begin.
            </p>
            <div
              ref={terminalContainerRef}
              className={styles.terminalMount}
              aria-describedby="terminal-help"
            />
            {!terminalReady ? (
              <div className={styles.terminalLoading} role="status">
                <span aria-hidden="true" />
                Preparing the terminal
              </div>
            ) : null}
          </div>
        </section>
      </section>

      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {announcement}
      </p>

      {hostKeyChallenge ? (
        <HostKeyDialog
          challenge={hostKeyChallenge}
          destination={sessionTarget}
          onCancel={cancelHostKey}
          onTrust={trustHostKey}
        />
      ) : null}
    </>
  );
}
