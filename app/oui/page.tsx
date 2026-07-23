import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { OuiLookupClient } from "./OuiLookupClient";
import styles from "./oui.module.css";

export const metadata: Metadata = {
  title: "MAC OUI Lookup",
  description: "Look up a MAC address vendor using a local IEEE OUI database.",
};

export default function OuiLookupPage() {
  return (
    <AppShell current="oui">
      <main className={styles.page}>
        <header className={styles.heading}>
          <p className={styles.kicker}>Address lookup</p>
          <h1>MAC OUI Lookup</h1>
          <p>
            Find the organization registered to a MAC address prefix. Lookup
            data stays on this computer.
          </p>
        </header>

        <OuiLookupClient />

        <p className={styles.dataNote}>
          Vendor names are read from the IEEE registry snapshot bundled with
          the local API. No external lookup service is contacted.
        </p>
      </main>
    </AppShell>
  );
}
