import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { NetPingerClient } from "./NetPingerClient";
import styles from "./netpinger.module.css";

export const metadata: Metadata = {
  title: "NetPinger",
  description:
    "Continuously ping multiple hostnames and IP addresses and compare live reachability, success and failure streaks, and latency until monitoring is stopped.",
};

export default function NetPingerPage() {
  return (
    <AppShell current="netpinger">
      <main className={styles.page}>
        <header className={styles.heading}>
          <p className={styles.kicker}>Reachability check</p>
          <h1>NetPinger</h1>
          <p>
            Ping hostnames and IP addresses in parallel. Follow live response,
            success and failure streaks, loss, and latency for every target in
            one table until you press Stop.
          </p>
        </header>

        <NetPingerClient />
      </main>
    </AppShell>
  );
}
