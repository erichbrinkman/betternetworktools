import Link from "next/link";
import { AppShell } from "./components/AppShell";
import { FeedbackForm } from "./components/FeedbackForm";

const apps = [
  {
    name: "NetScanner",
    description:
      "Scan an IPv4 subnet for responsive devices, hostnames, MAC addresses, and common services.",
    category: "Network discovery",
    href: "/netscanner",
    glyph: "NS",
    note: "Uses the local scan engine",
  },
  {
    name: "NetPorts",
    description:
      "Scan a single hostname or IP across common, custom, or all TCP ports with live open-service results.",
    category: "Port analysis",
    href: "/netports",
    glyph: "PT",
    note: "Bounded local TCP connect scan",
  },
  {
    name: "NetPinger",
    description:
      "Continuously ping multiple hostnames and IP addresses with live reachability and latency statistics.",
    category: "Reachability monitoring",
    href: "/netpinger",
    glyph: "NP",
    note: "Live local results",
  },
  {
    name: "NetSpeed",
    description:
      "Measure ping, jitter, download, and upload against a public speed-test server you choose.",
    category: "Internet performance",
    href: "/netspeed",
    glyph: "SD",
    note: "Local Python test engine",
  },
  {
    name: "NetTransfer",
    description:
      "Run scoped TFTP, SFTP, or FTP servers from one managed local root.",
    category: "File transfer",
    href: "/nettransfer",
    glyph: "XF",
    note: "TFTP · SFTP · FTP",
  },
  {
    name: "NetTrace",
    description:
      "Trace every hop to a hostname or IP address and inspect latency, responders, and autonomous-system boundaries.",
    category: "Route analysis",
    href: "/nettrace",
    glyph: "NT",
    note: "Hop timing + optional AS lookup",
  },
  {
    name: "QuickSSH",
    description:
      "Open SSH or Telnet sessions in the browser with quick access to starred and recent connections.",
    category: "Remote access",
    href: "/quickssh",
    glyph: "SH",
    note: "Local Python SSH + Telnet engine",
  },
  {
    name: "MAC OUI Lookup",
    description:
      "Look up the registered organization associated with a MAC address or OUI prefix.",
    category: "Device identification",
    href: "/oui",
    glyph: "OU",
    note: "Local registry lookup",
  },
  {
    name: "Subnet Calculator",
    description:
      "Calculate network, broadcast, usable host range, masks, and address properties from IPv4 CIDR.",
    category: "IP addressing",
    href: "/subnet",
    glyph: "SC",
    note: "Runs in the browser",
  },
] as const;

export default function Home() {
  return (
    <AppShell current="home">
      <main className="page-content apps-page">
        <header className="apps-header">
          <div>
            <h1>Better Network Tools</h1>
            <p>
              Network utilities for discovery, monitoring, performance testing,
              route analysis, secure access, addressing, and device identification.
            </p>
          </div>
        </header>

        <section className="apps-section" aria-labelledby="apps-title">
          <div className="apps-section-heading">
            <h2 id="apps-title">Apps</h2>
            <span>{apps.length} available</span>
          </div>

          <div className="apps-grid">
            {apps.map((app) => (
              <Link className="app-card" href={app.href} key={app.name}>
                <div className="app-card-heading">
                  <span className="app-glyph" aria-hidden="true">
                    {app.glyph}
                  </span>
                  <span className="app-category">{app.category}</span>
                </div>
                <h3>{app.name}</h3>
                <p>{app.description}</p>
                <div className="app-card-footer">
                  <span>{app.note}</span>
                  <span aria-hidden="true">Open →</span>
                </div>
              </Link>
            ))}
          </div>
        </section>

        <section className="feedback-section" aria-labelledby="feedback-title">
          <div className="feedback-heading">
            <span>Feedback</span>
            <h2 id="feedback-title">Help improve the toolkit</h2>
            <p>
              Share an idea, request a tool, or tell us what could work better.
              Your message is delivered privately to the developer.
            </p>
          </div>
          <FeedbackForm />
        </section>

        <footer className="product-footer">
          <span>
            Developed and managed by Erich Brinkman -{" "}
            <a href="https://github.com/erichbrinkman/">
              https://github.com/erichbrinkman/
            </a>{" "}
            -{" "}
            <a href="https://www.linkedin.com/in/erichbrinkman/">
              https://www.linkedin.com/in/erichbrinkman/
            </a>
          </span>
        </footer>
      </main>
    </AppShell>
  );
}
