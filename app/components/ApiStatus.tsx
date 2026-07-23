"use client";

import { useEffect, useState } from "react";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";

type EngineState = "checking" | "online" | "offline";

export function ApiStatus() {
  const [state, setState] = useState<EngineState>("checking");

  useEffect(() => {
    let active = true;

    async function checkEngine() {
      try {
        const response = await fetch(`${API_BASE_URL}/api/health`, {
          cache: "no-store",
          signal: AbortSignal.timeout(2500),
        });
        const payload = response.ok
          ? ((await response.json()) as { status?: string; service?: string })
          : null;
        const isOurEngine =
          payload?.status === "ok" && payload.service === "better-network-tools-api";
        if (active) setState(isOurEngine ? "online" : "offline");
      } catch {
        if (active) setState("offline");
      }
    }

    void checkEngine();
    const timer = window.setInterval(checkEngine, 15000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  const label =
    state === "online"
      ? "Scan engine online"
      : state === "offline"
        ? "Scan engine offline"
        : "Checking scan engine";

  return (
    <span
      className={`api-status api-status-${state}`}
      title={label}
      role="status"
      aria-live="polite"
    >
      <i aria-hidden="true" /> {label}
    </span>
  );
}
