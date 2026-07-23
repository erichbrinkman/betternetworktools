import type { Metadata, Viewport } from "next";
import { headers } from "next/headers";
import "./globals.css";

const siteTitle = "Better Network Tools";
const siteDescription =
  "A local-first toolkit for network discovery, performance testing, investigation, secure access, and troubleshooting.";

export async function generateMetadata(): Promise<Metadata> {
  const requestHeaders = await headers();
  const forwardedHost = requestHeaders
    .get("x-forwarded-host")
    ?.split(",")[0]
    ?.trim();
  const host = forwardedHost || requestHeaders.get("host") || "localhost:3000";
  const forwardedProtocol = requestHeaders
    .get("x-forwarded-proto")
    ?.split(",")[0]
    ?.trim();
  const protocol =
    forwardedProtocol === "http" || forwardedProtocol === "https"
      ? forwardedProtocol
      : host.startsWith("localhost") || host.startsWith("127.0.0.1")
        ? "http"
        : "https";
  let metadataBase: URL;

  try {
    metadataBase = new URL(`${protocol}://${host}`);
  } catch {
    metadataBase = new URL("http://localhost:3000");
  }

  return {
    metadataBase,
    title: {
      default: siteTitle,
      template: `%s · ${siteTitle}`,
    },
    description: siteDescription,
    icons: {
      icon: "/favicon.svg",
      shortcut: "/favicon.svg",
    },
    openGraph: {
      type: "website",
      siteName: siteTitle,
      title: siteTitle,
      description: siteDescription,
    },
    twitter: {
      card: "summary",
      title: siteTitle,
      description: siteDescription,
    },
  };
}

export const viewport: Viewport = {
  colorScheme: "dark",
  themeColor: "#121315",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
