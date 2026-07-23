"use client";

import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import styles from "./subnet.module.css";

const IPV4_SIZE = 2 ** 32;

type ParsedInput = {
  address: string;
  addressValue: number;
  prefix: number;
};

type SubnetResult = ParsedInput & {
  networkValue: number;
  broadcastValue: number;
  network: string;
  broadcast: string;
  normalizedCidr: string;
  netmask: string;
  wildcard: string;
  firstUsable: string;
  lastUsable: string;
  totalAddresses: number;
  usableHosts: number;
  hostBits: number;
  addressClass: string;
  classifications: string[];
  subnetRole: string;
};

type DetailRow = {
  key: string;
  label: string;
  value: string;
  note?: string;
};

function parseIpv4(rawAddress: string): { address: string; value: number } {
  const text = rawAddress.trim();
  const octets = text.split(".");

  if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet))) {
    throw new Error("Enter an IPv4 address with four decimal octets, such as 192.168.1.25.");
  }

  if (octets.some((octet) => octet.length > 1 && octet.startsWith("0"))) {
    throw new Error("Remove leading zeroes from the IPv4 address to avoid ambiguous notation.");
  }

  const parts = octets.map(Number);
  if (parts.some((part) => part < 0 || part > 255)) {
    throw new Error("Each IPv4 octet must be between 0 and 255.");
  }

  return {
    address: parts.join("."),
    value: parts.reduce((value, part) => value * 256 + part, 0),
  };
}

function parsePrefix(rawPrefix: string) {
  const text = rawPrefix.trim();
  if (!/^\d{1,2}$/.test(text)) {
    throw new Error("Enter a whole-number prefix between 0 and 32.");
  }

  const prefix = Number(text);
  if (prefix < 0 || prefix > 32) {
    throw new Error("The IPv4 prefix must be between 0 and 32.");
  }
  return prefix;
}

function parseInput(rawInput: string, rawPrefix: string): ParsedInput {
  const text = rawInput.trim();
  if (!text) throw new Error("Enter an IPv4 address or CIDR block.");

  const segments = text.split("/");
  if (segments.length > 2) {
    throw new Error("Use one slash for CIDR notation, such as 192.168.1.25/24.");
  }

  const parsedAddress = parseIpv4(segments[0]);
  const prefixText = segments.length === 2 ? segments[1] : rawPrefix;
  if (segments.length === 2 && !prefixText.trim()) {
    throw new Error("Add a prefix after the slash, such as /24.");
  }

  return {
    address: parsedAddress.address,
    addressValue: parsedAddress.value,
    prefix: parsePrefix(prefixText),
  };
}

function numberToIpv4(value: number) {
  const first = Math.floor(value / 16777216);
  const remainderAfterFirst = value - first * 16777216;
  const second = Math.floor(remainderAfterFirst / 65536);
  const remainderAfterSecond = remainderAfterFirst - second * 65536;
  const third = Math.floor(remainderAfterSecond / 256);
  const fourth = remainderAfterSecond - third * 256;
  return `${first}.${second}.${third}.${fourth}`;
}

function ipv4ToBinary(address: string) {
  return address
    .split(".")
    .map((octet) => Number(octet).toString(2).padStart(8, "0"))
    .join(".");
}

function isInRange(value: number, start: string, prefix: number) {
  const startValue = parseIpv4(start).value;
  const size = 2 ** (32 - prefix);
  return value >= startValue && value < startValue + size;
}

function getAddressClass(value: number) {
  const firstOctet = Math.floor(value / 16777216);
  if (firstOctet <= 127) return "Class A (legacy)";
  if (firstOctet <= 191) return "Class B (legacy)";
  if (firstOctet <= 223) return "Class C (legacy)";
  if (firstOctet <= 239) return "Class D (multicast)";
  return "Class E (reserved)";
}

function getClassifications(value: number) {
  const labels: string[] = [];

  if (
    isInRange(value, "10.0.0.0", 8) ||
    isInRange(value, "172.16.0.0", 12) ||
    isInRange(value, "192.168.0.0", 16)
  ) {
    labels.push("Private (RFC 1918)");
  }
  if (isInRange(value, "169.254.0.0", 16)) labels.push("Link-local");
  if (isInRange(value, "127.0.0.0", 8)) labels.push("Loopback");
  if (isInRange(value, "224.0.0.0", 4)) labels.push("Multicast");
  if (isInRange(value, "100.64.0.0", 10)) labels.push("Shared address space");
  if (isInRange(value, "198.18.0.0", 15)) labels.push("Benchmark testing");
  if (
    isInRange(value, "192.0.2.0", 24) ||
    isInRange(value, "198.51.100.0", 24) ||
    isInRange(value, "203.0.113.0", 24)
  ) {
    labels.push("Documentation range");
  }
  if (isInRange(value, "192.0.0.0", 24)) labels.push("Special-purpose");
  if (isInRange(value, "0.0.0.0", 8) || isInRange(value, "240.0.0.0", 4)) {
    labels.push("Reserved");
  }
  if (value === IPV4_SIZE - 1) labels.push("Limited broadcast");

  if (labels.length === 0) labels.push("Public unicast");
  return labels;
}

function calculateSubnet(parsed: ParsedInput): SubnetResult {
  const hostBits = 32 - parsed.prefix;
  const totalAddresses = 2 ** hostBits;
  const networkValue = Math.floor(parsed.addressValue / totalAddresses) * totalAddresses;
  const broadcastValue = networkValue + totalAddresses - 1;
  const netmaskValue = IPV4_SIZE - totalAddresses;
  const wildcardValue = totalAddresses - 1;
  const network = numberToIpv4(networkValue);
  const broadcast = numberToIpv4(broadcastValue);

  let firstUsableValue: number;
  let lastUsableValue: number;
  let usableHosts: number;
  let subnetRole: string;

  if (parsed.prefix === 32) {
    firstUsableValue = networkValue;
    lastUsableValue = networkValue;
    usableHosts = 1;
    subnetRole = "Host route";
  } else if (parsed.prefix === 31) {
    firstUsableValue = networkValue;
    lastUsableValue = broadcastValue;
    usableHosts = 2;
    subnetRole = "Point-to-point endpoint";
  } else {
    firstUsableValue = networkValue + 1;
    lastUsableValue = broadcastValue - 1;
    usableHosts = totalAddresses - 2;
    subnetRole =
      parsed.addressValue === networkValue
        ? "Network address"
        : parsed.addressValue === broadcastValue
          ? "Broadcast address"
          : "Host address";
  }

  return {
    ...parsed,
    networkValue,
    broadcastValue,
    network,
    broadcast,
    normalizedCidr: `${network}/${parsed.prefix}`,
    netmask: numberToIpv4(netmaskValue),
    wildcard: numberToIpv4(wildcardValue),
    firstUsable: numberToIpv4(firstUsableValue),
    lastUsable: numberToIpv4(lastUsableValue),
    totalAddresses,
    usableHosts,
    hostBits,
    addressClass: getAddressClass(parsed.addressValue),
    classifications: getClassifications(parsed.addressValue),
    subnetRole,
  };
}

function getInitialResult() {
  return calculateSubnet(parseInput("192.168.1.25/24", "24"));
}

const numberFormatter = new Intl.NumberFormat("en-US");

export function SubnetCalculator() {
  const [addressInput, setAddressInput] = useState("192.168.1.25/24");
  const [prefixInput, setPrefixInput] = useState("24");
  const [result, setResult] = useState<SubnetResult>(getInitialResult);
  const [error, setError] = useState<string | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const copyTimer = useRef<number | undefined>(undefined);

  const hasInlinePrefix = addressInput.includes("/");
  const displayedPrefix = hasInlinePrefix
    ? (addressInput.split("/")[1] ?? "")
    : prefixInput;

  useEffect(() => {
    return () => {
      if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
    };
  }, []);

  const networkRows = useMemo<DetailRow[]>(
    () => [
      { key: "entered", label: "Entered address", value: `${result.address}/${result.prefix}` },
      { key: "network-cidr", label: "Normalized network", value: result.normalizedCidr },
      { key: "netmask", label: "Subnet mask", value: result.netmask },
      { key: "wildcard", label: "Wildcard mask", value: result.wildcard },
      { key: "network", label: "Network address", value: result.network },
      { key: "broadcast", label: "Broadcast address", value: result.broadcast },
      { key: "first-usable", label: "First usable", value: result.firstUsable },
      { key: "last-usable", label: "Last usable", value: result.lastUsable },
    ],
    [result],
  );

  const binaryRows = useMemo<DetailRow[]>(
    () => [
      { key: "binary-entered", label: "Entered address", value: ipv4ToBinary(result.address) },
      { key: "binary-network", label: "Network address", value: ipv4ToBinary(result.network) },
      { key: "binary-netmask", label: "Subnet mask", value: ipv4ToBinary(result.netmask) },
      { key: "binary-wildcard", label: "Wildcard mask", value: ipv4ToBinary(result.wildcard) },
      { key: "binary-broadcast", label: "Broadcast", value: ipv4ToBinary(result.broadcast) },
    ],
    [result],
  );

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const nextResult = calculateSubnet(parseInput(addressInput, prefixInput));
      setResult(nextResult);
      setAddressInput(
        hasInlinePrefix ? `${nextResult.address}/${nextResult.prefix}` : nextResult.address,
      );
      setPrefixInput(String(nextResult.prefix));
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Unable to calculate this subnet.");
    }
  }

  function selectExample(value: string) {
    try {
      const nextResult = calculateSubnet(parseInput(value, prefixInput));
      setAddressInput(value);
      setPrefixInput(String(nextResult.prefix));
      setResult(nextResult);
      setError(null);
    } catch {
      // The fixed examples are known-valid inputs.
    }
  }

  async function copyValue(key: string, value: string) {
    let copied = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
        copied = true;
      } else {
        const textArea = document.createElement("textarea");
        textArea.value = value;
        textArea.setAttribute("readonly", "");
        textArea.style.position = "fixed";
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.select();
        copied = document.execCommand("copy");
        document.body.removeChild(textArea);
      }
    } catch {
      copied = false;
    }

    if (!copied) return;
    setCopiedKey(key);
    if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
    copyTimer.current = window.setTimeout(() => setCopiedKey(null), 1600);
  }

  const prefixNote =
    result.prefix === 31
      ? "A /31 uses both addresses as point-to-point endpoints (RFC 3021)."
      : result.prefix === 32
        ? "A /32 identifies one host; the network, broadcast, and usable address are the same."
        : `${result.hostBits} host bits with network and broadcast addresses excluded from usable hosts.`;

  return (
    <div className={styles.calculator}>
      <section className={styles.inputPanel} aria-labelledby="subnet-input-heading">
        <div className={styles.panelHeading}>
          <div>
            <h2 id="subnet-input-heading">Address and prefix</h2>
            <p>Use a complete CIDR, or enter an address and set the prefix separately.</p>
          </div>
        </div>

        <form className={styles.form} onSubmit={submit} noValidate>
          <div className={styles.addressField}>
            <label htmlFor="subnet-address">IPv4 address or CIDR</label>
            <input
              id="subnet-address"
              name="address"
              value={addressInput}
              onChange={(event) => {
                setAddressInput(event.target.value);
                if (error) setError(null);
              }}
              placeholder="192.168.1.25/24"
              inputMode="decimal"
              autoComplete="off"
              spellCheck={false}
              aria-invalid={Boolean(error)}
              aria-describedby={error ? "subnet-error" : "address-help"}
            />
            <span id="address-help" className={styles.fieldHelp}>
              Example: 172.16.20.14/21
            </span>
          </div>

          <div className={styles.prefixField}>
            <label htmlFor="subnet-prefix">Prefix</label>
            <div className={styles.prefixControl}>
              <span aria-hidden="true">/</span>
              <input
                id="subnet-prefix"
                name="prefix"
                type="number"
                min="0"
                max="32"
                step="1"
                value={displayedPrefix}
                onChange={(event) => {
                  setPrefixInput(event.target.value);
                  if (error) setError(null);
                }}
                disabled={hasInlinePrefix}
                aria-describedby="prefix-help"
              />
            </div>
            <span id="prefix-help" className={styles.fieldHelp}>
              {hasInlinePrefix ? "Read from the CIDR above" : "0 through 32"}
            </span>
          </div>

          <button className={styles.calculateButton} type="submit">
            Calculate
          </button>
        </form>

        {error ? (
          <p className={styles.error} id="subnet-error" role="alert">
            {error}
          </p>
        ) : null}

        <div className={styles.examples} aria-label="Example subnet inputs">
          <span>Examples</span>
          {["192.168.1.25/24", "10.0.0.10/31", "8.8.8.8/32"].map((example) => (
            <button key={example} type="button" onClick={() => selectExample(example)}>
              {example}
            </button>
          ))}
        </div>
      </section>

      <section className={styles.resultHeader} aria-labelledby="calculation-heading">
        <div>
          <p className={styles.resultLabel}>Normalized network</p>
          <h2 id="calculation-heading">{result.normalizedCidr}</h2>
        </div>
        <button
          className={styles.copyButton}
          type="button"
          onClick={() => copyValue("summary", result.normalizedCidr)}
          aria-label={`Copy normalized network ${result.normalizedCidr}`}
        >
          {copiedKey === "summary" ? "Copied" : "Copy CIDR"}
        </button>
      </section>

      <div className={styles.tagRow} aria-label="Address classification">
        <span>{result.addressClass}</span>
        <span>{result.subnetRole}</span>
        {result.classifications.map((classification) => (
          <span key={classification}>{classification}</span>
        ))}
      </div>

      <div className={styles.resultGrid}>
        <section className={styles.panel} aria-labelledby="network-details-heading">
          <div className={styles.panelHeading}>
            <div>
              <h2 id="network-details-heading">Network details</h2>
              <p>Calculated from the address and prefix.</p>
            </div>
          </div>
          <dl className={styles.detailsList}>
            {networkRows.map((row) => (
              <div className={styles.detailRow} key={row.key}>
                <dt>{row.label}</dt>
                <dd>
                  <code>{row.value}</code>
                  <button
                    className={styles.inlineCopy}
                    type="button"
                    onClick={() => copyValue(row.key, row.value)}
                    aria-label={`Copy ${row.label.toLowerCase()} ${row.value}`}
                  >
                    {copiedKey === row.key ? "Copied" : "Copy"}
                  </button>
                </dd>
              </div>
            ))}
          </dl>
        </section>

        <section className={styles.panel} aria-labelledby="capacity-heading">
          <div className={styles.panelHeading}>
            <div>
              <h2 id="capacity-heading">Capacity</h2>
              <p>Address counts for the normalized network.</p>
            </div>
          </div>
          <dl className={styles.capacityList}>
            <div>
              <dt>Prefix length</dt>
              <dd>/{result.prefix}</dd>
            </div>
            <div>
              <dt>Total addresses</dt>
              <dd>{numberFormatter.format(result.totalAddresses)}</dd>
            </div>
            <div>
              <dt>Usable hosts</dt>
              <dd>{numberFormatter.format(result.usableHosts)}</dd>
            </div>
            <div>
              <dt>Host bits</dt>
              <dd>{result.hostBits}</dd>
            </div>
          </dl>
          <p className={styles.capacityNote}>{prefixNote}</p>
        </section>
      </div>

      <section className={`${styles.panel} ${styles.binaryPanel}`} aria-labelledby="binary-heading">
        <div className={styles.panelHeading}>
          <div>
            <h2 id="binary-heading">Binary representation</h2>
            <p>Each group represents one 8-bit octet.</p>
          </div>
        </div>
        <dl className={styles.binaryList}>
          {binaryRows.map((row) => (
            <div className={styles.binaryRow} key={row.key}>
              <dt>{row.label}</dt>
              <dd>
                <code>{row.value}</code>
                <button
                  className={styles.inlineCopy}
                  type="button"
                  onClick={() => copyValue(row.key, row.value)}
                  aria-label={`Copy binary ${row.label.toLowerCase()}`}
                >
                  {copiedKey === row.key ? "Copied" : "Copy"}
                </button>
              </dd>
            </div>
          ))}
        </dl>
      </section>

      <p className={styles.copyStatus} role="status" aria-live="polite">
        {copiedKey ? "Value copied to the clipboard." : ""}
      </p>
    </div>
  );
}
