import type { Metadata } from "next";
import { AppShell } from "../components/AppShell";
import { SubnetCalculator } from "./SubnetCalculator";
import styles from "./subnet.module.css";

export const metadata: Metadata = {
  title: "Subnet Calculator",
  description:
    "Calculate IPv4 network ranges, masks, host capacity, classifications, and binary values.",
};

export default function SubnetPage() {
  return (
    <AppShell current="subnet">
      <main className={styles.page}>
        <header className={styles.heading}>
          <p className={styles.eyebrow}>IPv4 utility</p>
          <h1>Subnet Calculator</h1>
          <p>
            Enter an IPv4 address and prefix to inspect its network range,
            capacity, address type, and binary values.
          </p>
        </header>
        <SubnetCalculator />
      </main>
    </AppShell>
  );
}
