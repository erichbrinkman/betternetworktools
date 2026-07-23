import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { QuickSSHClient } from "./QuickSSHClient";
import styles from "./quickssh.module.css";

export const metadata: Metadata = {
  title: "QuickSSH",
  description:
    "Open an interactive SSH or Telnet terminal through the local Better Network Tools service.",
  openGraph: {
    title: "QuickSSH · Better Network Tools",
    description:
      "Open an interactive SSH or Telnet terminal through the local Better Network Tools service.",
  },
  twitter: {
    card: "summary",
    title: "QuickSSH · Better Network Tools",
    description:
      "Open an interactive SSH or Telnet terminal through the local Better Network Tools service.",
  },
};

export default function QuickSSHPage() {
  return (
    <AppShell current="quickssh">
      <main className={styles.page}>
        <header className={styles.heading}>
          <div>
            <p className={styles.kicker}>SSH + Telnet terminal</p>
            <h1>QuickSSH</h1>
          </div>
          <p>
            Open an interactive SSH or Telnet session through the local Python
            service. Recent destinations stay on this device; credentials and
            terminal activity do not.
          </p>
        </header>

        <QuickSSHClient />
      </main>
    </AppShell>
  );
}
