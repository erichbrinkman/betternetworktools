"use client";

import { FormEvent, useRef, useState } from "react";
import styles from "./oui.module.css";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_BNT_API_URL?.replace(/\/$/, "") ??
  "http://127.0.0.1:8766";

type LookupResult = {
  query: string;
  normalized: string;
  matched_prefix: string;
  vendor: string;
  found: true;
  input_type: "mac" | "oui";
  locally_administered: boolean;
  multicast: boolean;
  source: "bundled_ieee_registry";
};

type ApiError = {
  detail?:
    | string
    | {
        code?: string;
        message?: string;
        normalized?: string;
        matched_prefix?: string;
      }
    | Array<{ msg?: string }>;
};

const examples = ["00:50:56:C0:00:08", "00-1C-42-00-00-08", "001B.6320.0001"];

function errorMessage(payload: ApiError | null, fallback: string) {
  if (typeof payload?.detail === "string") return payload.detail;
  if (Array.isArray(payload?.detail)) {
    return payload.detail.map((item) => item.msg).filter(Boolean).join(" ") || fallback;
  }
  return payload?.detail?.message ?? fallback;
}

export function OuiLookupClient() {
  const [address, setAddress] = useState("");
  const [result, setResult] = useState<LookupResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  async function lookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const query = address.trim();
    setResult(null);
    setMessage(null);
    setNotFound(false);

    if (!query) {
      setMessage("Enter a MAC address or OUI prefix.");
      inputRef.current?.focus();
      return;
    }

    setLoading(true);
    try {
      const parameters = new URLSearchParams({ mac: query });
      const response = await fetch(`${API_BASE_URL}/api/oui?${parameters}`, {
        cache: "no-store",
      });

      let payload: LookupResult | ApiError | null = null;
      try {
        payload = (await response.json()) as LookupResult | ApiError;
      } catch {
        // Keep a status-based fallback if the local API did not return JSON.
      }

      if (!response.ok) {
        const fallback =
          response.status === 404
            ? "No registered vendor was found for that OUI."
            : response.status === 422
              ? "Enter a valid 48-bit MAC address or 24-bit OUI prefix."
              : "The local lookup service could not complete the request.";
        setNotFound(response.status === 404);
        setMessage(errorMessage(payload as ApiError | null, fallback));
        return;
      }

      setResult(payload as LookupResult);
    } catch (caught) {
      setMessage(
        caught instanceof TypeError
          ? "The local API is offline. Start Better Network Tools and try again."
          : "The lookup could not be completed.",
      );
    } finally {
      setLoading(false);
    }
  }

  function selectExample(value: string) {
    setAddress(value);
    setResult(null);
    setMessage(null);
    setNotFound(false);
    inputRef.current?.focus();
  }

  return (
    <section className={styles.workspace} aria-labelledby="lookup-form-title">
      <div className={styles.formPanel}>
        <div className={styles.panelHeading}>
          <div>
            <h2 id="lookup-form-title">Lookup</h2>
            <p>Enter a full MAC address or the first three octets.</p>
          </div>
          <span>Offline</span>
        </div>

        <form onSubmit={lookup} noValidate>
          <label className={styles.label} htmlFor="mac-address">
            MAC address or OUI
          </label>
          <div className={styles.inputRow}>
            <input
              ref={inputRef}
              id="mac-address"
              name="mac"
              value={address}
              onChange={(event) => {
                setAddress(event.target.value);
                setMessage(null);
                setNotFound(false);
              }}
              placeholder="00:50:56:C0:00:08"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              aria-invalid={Boolean(message && !notFound)}
              aria-describedby="mac-format-help lookup-status"
              disabled={loading}
            />
            <button type="submit" disabled={loading}>
              {loading ? "Looking up…" : "Lookup"}
            </button>
          </div>
          <p className={styles.help} id="mac-format-help">
            Colon, hyphen, Cisco dotted, and unseparated formats are accepted.
          </p>
        </form>

        <div className={styles.examples}>
          <span>Examples</span>
          <div>
            {examples.map((example) => (
              <button key={example} type="button" onClick={() => selectExample(example)}>
                {example}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div
        className={styles.resultPanel}
        id="lookup-status"
        aria-live="polite"
        aria-busy={loading}
      >
        {loading ? (
          <div className={styles.emptyState}>
            <span className={styles.statusMark} aria-hidden="true" />
            <h2>Checking the local registry</h2>
            <p>Looking for the first 24 bits of the address.</p>
          </div>
        ) : result ? (
          <div className={styles.result}>
            <div className={styles.resultHeader}>
              <span className={styles.foundLabel}>Match found</span>
              <span>{result.input_type === "mac" ? "MAC address" : "OUI prefix"}</span>
            </div>
            <p className={styles.vendorLabel}>Registered organization</p>
            <h2>{result.vendor}</h2>

            <dl className={styles.details}>
              <div>
                <dt>Normalized input</dt>
                <dd>{result.normalized}</dd>
              </div>
              <div>
                <dt>Matched prefix</dt>
                <dd>{result.matched_prefix}</dd>
              </div>
              <div>
                <dt>Administration</dt>
                <dd>
                  {result.locally_administered
                    ? "Locally administered"
                    : "Universally administered"}
                </dd>
              </div>
              <div>
                <dt>Transmission</dt>
                <dd>{result.multicast ? "Multicast" : "Unicast"}</dd>
              </div>
            </dl>
          </div>
        ) : message ? (
          <div className={styles.emptyState} role={notFound ? "status" : "alert"}>
            <span className={styles.statusCode} aria-hidden="true">
              {notFound ? "—" : "!"}
            </span>
            <h2>{notFound ? "No vendor match" : "Lookup unavailable"}</h2>
            <p>{message}</p>
            {notFound ? (
              <p className={styles.secondaryMessage}>
                Randomized and locally administered addresses often do not have an IEEE vendor entry.
              </p>
            ) : null}
          </div>
        ) : (
          <div className={styles.emptyState}>
            <span className={styles.statusCode} aria-hidden="true">
              OUI
            </span>
            <h2>Vendor result</h2>
            <p>The registered organization and matched prefix will appear here.</p>
          </div>
        )}
      </div>
    </section>
  );
}
