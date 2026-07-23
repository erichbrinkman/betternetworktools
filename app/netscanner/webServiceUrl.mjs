/**
 * Build a browser URL only when a scan result carries HTTP or HTTPS evidence.
 *
 * @param {string} ipAddress
 * @param {{
 *   port: number,
 *   service: string | null,
 *   http_status: number | null,
 *   http_server: string | null,
 * }} entry
 * @returns {string | null}
 */
export function webServiceUrl(ipAddress, entry) {
  if (!Number.isInteger(entry.port) || entry.port < 1 || entry.port > 65535) {
    return null;
  }

  const service = entry.service?.toLowerCase() ?? "";
  let scheme;
  if (service === "https" || service === "https-alt") {
    scheme = "https";
  } else if (
    service === "http" ||
    service === "http-alt" ||
    entry.http_status !== null ||
    entry.http_server !== null
  ) {
    scheme = "http";
  } else {
    return null;
  }

  const isDefaultPort =
    (scheme === "http" && entry.port === 80) ||
    (scheme === "https" && entry.port === 443);
  const port = isDefaultPort ? "" : `:${entry.port}`;
  return `${scheme}://${ipAddress}${port}/`;
}
