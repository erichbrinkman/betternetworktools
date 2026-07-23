import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { NetTraceClient } from "./NetTraceClient";
import styles from "./nettrace.module.css";

export const metadata: Metadata = {
  title: "NetTrace",
  description:
    "Trace the route to a hostname or IP address, inspect every probe, and identify autonomous-system boundaries along the path.",
};

export default function NetTracePage() {
  return (
    <AppShell current="nettrace">
      <main className={styles.page}>
        <header className={styles.heading}>
          <p className={styles.kicker}>Route &amp; network path</p>
          <h1>NetTrace</h1>
          <p>
            Follow every hop to a hostname or IP address. Compare probe times,
            inspect responders, and see where the route changes autonomous
            systems.
          </p>
        </header>

        <NetTraceClient />
      </main>
    </AppShell>
  );
}
