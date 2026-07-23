import assert from "node:assert/strict";
import test from "node:test";

import {
  providerNameForServer,
  sortServersByProvider,
} from "../app/netspeed/serverSorting.ts";

function server(id, overrides = {}) {
  return {
    id,
    name: id,
    provider: "librespeed",
    location: "Test Lab",
    country: "US",
    sponsor: null,
    automatic: false,
    latency_ms: null,
    ...overrides,
  };
}

test("NetSpeed provider sorting groups operators without mutating the directory", () => {
  const input = [
    server("zulu-fast", { sponsor: "Zulu Fiber", latency_ms: 2 }),
    server("alpha-unavailable", { sponsor: "Alpha Net" }),
    server("automatic", {
      provider: "cloudflare",
      automatic: true,
      sponsor: "Cloudflare",
    }),
    server("fallback", { sponsor: "   ", latency_ms: 4 }),
    server("alpha-fast", { sponsor: "Alpha Net", latency_ms: 8 }),
  ];
  const originalOrder = input.map(({ id }) => id);

  assert.deepEqual(
    sortServersByProvider(input).map(({ id }) => id),
    ["automatic", "alpha-fast", "alpha-unavailable", "fallback", "zulu-fast"],
  );
  assert.deepEqual(input.map(({ id }) => id), originalOrder);
  assert.equal(providerNameForServer(input[3]), "LibreSpeed");
});
