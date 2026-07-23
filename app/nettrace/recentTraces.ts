export const RECENT_TRACES_STORAGE_KEY =
  "better-network-tools.nettrace.recent-targets";
export const RECENT_TRACES_VERSION = 1;
export const MAX_RECENT_TRACES = 6;

export type RecentTrace = {
  target: string;
  traced_at: string;
};

type RecentTraceStorage = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeRecentTrace(value: unknown): RecentTrace | null {
  if (
    !isRecord(value) ||
    typeof value.target !== "string" ||
    typeof value.traced_at !== "string"
  ) {
    return null;
  }
  const target = value.target.trim();
  if (
    !isValidTraceTarget(target) ||
    !Number.isFinite(Date.parse(value.traced_at))
  ) {
    return null;
  }
  return { target, traced_at: value.traced_at };
}

export function isValidTraceTarget(value: string) {
  const target = value.trim();
  return (
    target.length > 0 &&
    target.length <= 253 &&
    !target.startsWith("-") &&
    !/[\s/?#@\\]/.test(target) &&
    !/[\u0000-\u001f\u007f]/.test(target) &&
    !/^[a-z][a-z\d+.-]*:\/\//i.test(target)
  );
}

function sanitizeRecentTraces(value: unknown): RecentTrace[] | null {
  if (
    !isRecord(value) ||
    value.version !== RECENT_TRACES_VERSION ||
    !Array.isArray(value.entries)
  ) {
    return null;
  }

  const entries: RecentTrace[] = [];
  const seen = new Set<string>();
  for (const candidate of value.entries) {
    const normalized = normalizeRecentTrace(candidate);
    if (!normalized) continue;
    const key = normalized.target.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    entries.push(normalized);
    if (entries.length === MAX_RECENT_TRACES) break;
  }
  return entries;
}

export function writeRecentTraces(
  entries: RecentTrace[],
  storage: RecentTraceStorage = window.localStorage,
) {
  try {
    const sanitized =
      sanitizeRecentTraces({ version: RECENT_TRACES_VERSION, entries }) ?? [];
    storage.setItem(
      RECENT_TRACES_STORAGE_KEY,
      JSON.stringify({
        version: RECENT_TRACES_VERSION,
        entries: sanitized,
      }),
    );
  } catch {
    // Trace results remain usable when browser storage is unavailable.
  }
}

export function readRecentTraces(
  storage: RecentTraceStorage = window.localStorage,
) {
  try {
    const raw = storage.getItem(RECENT_TRACES_STORAGE_KEY);
    if (!raw) return [];
    const sanitized = sanitizeRecentTraces(JSON.parse(raw) as unknown);
    if (sanitized === null) {
      storage.removeItem(RECENT_TRACES_STORAGE_KEY);
      return [];
    }
    // Rewriting strips any unexpected fields and normalizes the cap/deduping.
    writeRecentTraces(sanitized, storage);
    return sanitized;
  } catch {
    try {
      storage.removeItem(RECENT_TRACES_STORAGE_KEY);
    } catch {
      // Ignore unavailable storage in the recovery path as well.
    }
    return [];
  }
}

export function upsertRecentTrace(
  entries: RecentTrace[],
  entry: RecentTrace,
) {
  const normalized = normalizeRecentTrace(entry);
  if (!normalized) return entries.slice(0, MAX_RECENT_TRACES);
  const key = normalized.target.toLowerCase();
  const current =
    sanitizeRecentTraces({ version: RECENT_TRACES_VERSION, entries }) ?? [];
  return [
    normalized,
    ...current
      .filter((recent) => recent.target.toLowerCase() !== key)
      .map((recent) => ({
        target: recent.target,
        traced_at: recent.traced_at,
      })),
  ].slice(0, MAX_RECENT_TRACES);
}

export function removeRecentTrace(entries: RecentTrace[], target: string) {
  return entries.filter((recent) => recent.target !== target);
}

export function clearRecentTraceStorage(
  storage: RecentTraceStorage = window.localStorage,
) {
  try {
    storage.removeItem(RECENT_TRACES_STORAGE_KEY);
  } catch {
    // The in-memory list can still be cleared.
  }
}
