import Link from "next/link";
import type { ReactNode } from "react";
import { UpdateButton } from "./UpdateButton";

type AppShellProps = {
  children: ReactNode;
  current:
    | "home"
    | "netscanner"
    | "netports"
    | "netpinger"
    | "netspeed"
    | "nettransfer"
    | "nettrace"
    | "quickssh"
    | "oui"
    | "subnet";
};

export function AppShell({ children, current }: AppShellProps) {
  return (
    <div className="app-shell">
      <header className="topbar">
        <Link className="brand" href="/" aria-label="Better Network Tools home">
          Better Network Tools
        </Link>

        <nav className="primary-nav" aria-label="Primary navigation">
          <Link
            className={current === "home" ? "is-current" : ""}
            href="/"
            aria-current={current === "home" ? "page" : undefined}
          >
            Apps
          </Link>
          <Link
            className={current === "netscanner" ? "is-current" : ""}
            href="/netscanner"
            aria-current={current === "netscanner" ? "page" : undefined}
          >
            Scanner
          </Link>
          <Link
            className={current === "netports" ? "is-current" : ""}
            href="/netports"
            aria-current={current === "netports" ? "page" : undefined}
          >
            Ports
          </Link>
          <Link
            className={current === "netpinger" ? "is-current" : ""}
            href="/netpinger"
            aria-current={current === "netpinger" ? "page" : undefined}
          >
            Pinger
          </Link>
          <Link
            className={current === "netspeed" ? "is-current" : ""}
            href="/netspeed"
            aria-current={current === "netspeed" ? "page" : undefined}
          >
            Speed
          </Link>
          <Link
            className={current === "nettransfer" ? "is-current" : ""}
            href="/nettransfer"
            aria-current={current === "nettransfer" ? "page" : undefined}
          >
            Transfer
          </Link>
          <Link
            className={current === "nettrace" ? "is-current" : ""}
            href="/nettrace"
            aria-current={current === "nettrace" ? "page" : undefined}
          >
            Trace
          </Link>
          <Link
            className={current === "quickssh" ? "is-current" : ""}
            href="/quickssh"
            aria-current={current === "quickssh" ? "page" : undefined}
          >
            SSH
          </Link>
          <Link
            className={current === "oui" ? "is-current" : ""}
            href="/oui"
            aria-current={current === "oui" ? "page" : undefined}
          >
            OUI
          </Link>
          <Link
            className={current === "subnet" ? "is-current" : ""}
            href="/subnet"
            aria-current={current === "subnet" ? "page" : undefined}
          >
            Subnet
          </Link>
        </nav>

        <div className="topbar-actions">
          <UpdateButton />
          <div className="workspace-badge">
            <span aria-hidden="true">●</span>
            Local
          </div>
        </div>
      </header>
      {children}
    </div>
  );
}
