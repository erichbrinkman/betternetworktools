import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { NetTransferClient } from "./NetTransferClient";
import styles from "./nettransfer.module.css";

const description =
  "Run local TFTP, SFTP, or FTP servers from one scoped, server-managed root.";

export const metadata: Metadata = {
  title: "NetTransfer",
  description,
  openGraph: {
    title: "NetTransfer · Better Network Tools",
    description,
  },
  twitter: {
    card: "summary",
    title: "NetTransfer · Better Network Tools",
    description,
  },
};

export default function NetTransferPage() {
  return (
    <AppShell current="nettransfer">
      <main className={styles.page}>
        <header className={styles.hero}>
          <div className={styles.heroCopy}>
            <div className={styles.heroMeta}>
              <p className={styles.kicker}>Local file transfer service</p>
              <span>TFTP · SFTP · FTP</span>
            </div>
            <h1>NetTransfer</h1>
            <p>
              Run a scoped local file server for device images, boot files, and
              lab transfers. Choose the protocol that fits the client while
              every transfer stays inside one managed root.
            </p>
          </div>

          <div className={styles.heroBoundary}>
            <span aria-hidden="true">↕</span>
            <div>
              <strong>One managed root</strong>
              <small>TFTP, SFTP, and FTP share the protected directory.</small>
            </div>
          </div>
        </header>

        <NetTransferClient />
      </main>
    </AppShell>
  );
}
