import type { Metadata } from "next";
import { ApiStatus } from "../components/ApiStatus";
import { AppShell } from "../components/AppShell";
import { NetScannerClient } from "./NetScannerClient";

export const metadata: Metadata = {
  title: "NetScanner",
  description:
    "Discover and fingerprint devices on an IPv4 subnet from a local scan engine.",
};

export default function NetScannerPage() {
  return (
    <AppShell current="netscanner">
      <main className="page-content scanner-page">
        <header className="scanner-heading">
          <div>
            <span className="section-kicker">Discovery & fingerprinting</span>
            <h1>NetScanner</h1>
            <p>
              Map an IPv4 subnet, identify responsive devices, and collect the
              evidence behind every result.
            </p>
          </div>
          <ApiStatus />
        </header>
        <NetScannerClient />
      </main>
    </AppShell>
  );
}
