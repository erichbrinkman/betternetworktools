import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { NetSpeedClient } from "./NetSpeedClient";
import styles from "./netspeed.module.css";

export const metadata: Metadata = {
  title: "NetSpeed",
  description:
    "Measure internet latency, jitter, download, and upload from the local Python service against a selected public test server.",
  openGraph: {
    title: "NetSpeed · Better Network Tools",
    description:
      "Python-powered internet latency and throughput testing against a public server you choose.",
  },
  twitter: {
    card: "summary",
    title: "NetSpeed · Better Network Tools",
    description:
      "Python-powered internet latency and throughput testing against a public server you choose.",
  },
};

export default function NetSpeedPage() {
  return (
    <AppShell current="netspeed">
      <main className={styles.page}>
        <header className={styles.heading}>
          <div className={styles.headingMeta}>
            <p className={styles.kicker}>Internet speed test</p>
            <span>Local Python engine</span>
          </div>
          <h1>NetSpeed</h1>
          <p>
            Measure response time and internet throughput from this machine.
            Choose a public server and transfer size, then let the local Python
            service run a sample long enough for fast connections to ramp up.
          </p>
        </header>

        <NetSpeedClient />

        <section className={styles.boundary} aria-labelledby="boundary-title">
          <span className={styles.boundaryIcon} aria-hidden="true">
            i
          </span>
          <div>
            <h2 id="boundary-title">Public test traffic</h2>
            <p>
              Public servers receive your IP address during the small HTTPS
              probes used to rank them nearest-first; the selected server also
              receives generated test traffic. NetSpeed keeps the list
              constrained and caps probe time, test time, and data; results
              remain in local process memory and this browser.
            </p>
          </div>
        </section>
      </main>
    </AppShell>
  );
}
