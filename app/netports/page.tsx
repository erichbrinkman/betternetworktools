import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { NetPortsClient } from "./NetPortsClient";
import styles from "./netports.module.css";

export const metadata: Metadata = {
  title: "NetPorts",
  description:
    "Scan an authorized hostname or IP address for open TCP ports with the local Better Network Tools Python service.",
  openGraph: {
    title: "NetPorts · Better Network Tools",
    description:
      "A focused TCP port scanner with bounded concurrency, live progress, and optional safe service banners.",
  },
  twitter: {
    card: "summary",
    title: "NetPorts · Better Network Tools",
    description:
      "A focused TCP port scanner with bounded concurrency, live progress, and optional safe service banners.",
  },
};

export default function NetPortsPage() {
  return (
    <AppShell current="netports">
      <main className={styles.page}>
        <header className={styles.heading}>
          <div className={styles.headingMeta}>
            <p className={styles.kicker}>TCP service discovery</p>
            <span>Local Python engine</span>
          </div>
          <h1>NetPorts</h1>
          <p>
            Check a hostname or IP address for listening TCP services. Choose a
            focused preset or define an exact port range, then follow every
            connection attempt as it completes.
          </p>
        </header>

        <NetPortsClient />

        <section className={styles.boundary} aria-labelledby="netports-boundary-title">
          <span className={styles.boundaryIcon} aria-hidden="true">
            !
          </span>
          <div>
            <h2 id="netports-boundary-title">Authorized targets only</h2>
            <p>
              Port scans can trigger security alerts and may violate policy or
              law when performed without permission. Scan only systems you own
              or are explicitly authorized to assess. Targets and results stay
              between this browser and the loopback Python service.
            </p>
          </div>
        </section>
      </main>
    </AppShell>
  );
}
