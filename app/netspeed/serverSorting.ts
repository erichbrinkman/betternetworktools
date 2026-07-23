export type SortableSpeedServer = {
  id: string;
  name: string;
  provider: "cloudflare" | "librespeed";
  location: string | null;
  country: string | null;
  sponsor: string | null;
  automatic: boolean;
  latency_ms: number | null;
};

function compareText(left: string | null, right: string | null) {
  return (left ?? "").localeCompare(right ?? "", "en", {
    numeric: true,
    sensitivity: "base",
  });
}

function compareLatency(left: number | null, right: number | null) {
  const leftLatency =
    left != null && Number.isFinite(left) && left >= 0
      ? left
      : Number.POSITIVE_INFINITY;
  const rightLatency =
    right != null && Number.isFinite(right) && right >= 0
      ? right
      : Number.POSITIVE_INFINITY;
  return leftLatency - rightLatency;
}

export function providerNameForServer(server: SortableSpeedServer) {
  return (
    server.sponsor?.trim() ||
    (server.provider === "cloudflare" ? "Cloudflare" : "LibreSpeed")
  );
}

export function compareServersByProvider(
  left: SortableSpeedServer,
  right: SortableSpeedServer,
) {
  return (
    Number(right.automatic) - Number(left.automatic) ||
    compareText(providerNameForServer(left), providerNameForServer(right)) ||
    compareLatency(left.latency_ms, right.latency_ms) ||
    compareText(left.location, right.location) ||
    compareText(left.name, right.name) ||
    compareText(left.country, right.country) ||
    compareText(left.id, right.id)
  );
}

export function sortServersByProvider<T extends SortableSpeedServer>(
  servers: readonly T[],
) {
  return [...servers].sort(compareServersByProvider);
}
