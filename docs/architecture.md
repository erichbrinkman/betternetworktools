# Architecture

Better Network Tools is a local-first launchpad with a browser UI and a Python
network service. Keeping packet and socket access behind the local service gives
tools one security boundary while allowing the UI to remain portable.

## Runtime topology

```text
Browser (React/vinext, 127.0.0.1:3000)
       |
       | JSON API
       v
FastAPI service (127.0.0.1:8766)
       |-- bounded discovery, port-scan, ping, and traceroute jobs
       |      `-- authorized network targets
       |-- probe/fingerprint and platform capability adapters
       `-- NetTransfer singleton control and lifecycle
              |-- fixed, shared server root
              `-- one selected listener (loopback default; allowlisted LAN opt-in)
                     |-- TFTP over UDP
                     |-- SFTP over SSH/TCP
                     `-- FTP control plus bounded passive TCP ports
```

- The UI owns navigation, input, progress, and result presentation. It never
  shells out or opens scanner sockets.
- FastAPI owns target validation, resource limits, job lifecycle, and the
  response contract. It also owns the singleton NetTransfer server lifecycle
  while keeping its HTTP control plane on loopback.
- Probe adapters return observations plus provenance and confidence. A later
  fingerprinting step combines observations; it should not hide conflicting
  evidence.
- Platform adapters isolate the few macOS/Windows differences. Core scan logic
  must not branch on the operating system or parse localized command output.

## NetScanner flow

1. Parse and normalize a CIDR with Python's `ipaddress` module.
2. Reject disallowed or oversized targets before creating a job.
3. Discover candidates with bounded, cancellable probes.
4. Enrich responsive hosts through independent adapters such as reverse DNS,
   neighbor-cache lookup, selected TCP connects, and protocol-safe banners.
5. Combine observations into device fields with source and confidence metadata.
6. Stream or poll job progress, then expire in-memory results after the
   configured retention window.

A partial result is valid. Timeouts, missing privileges, and unavailable
platform capabilities should appear as structured observations or warnings,
not fail the whole subnet scan.

## NetPorts flow

1. Validate one hostname or IPv4/IPv6 address and normalize a comma-separated
   expression of TCP ports and inclusive ranges. Deduplicate the ports and
   enforce the configured port-count ceiling before starting a job.
2. Resolve a hostname once with a bounded deadline, validate the answer, and
   pass only that canonical numeric address to the connection probe. Literal
   addresses are canonicalized without DNS. NetPorts isolates blocking system
   resolver calls in its own fixed-size executor so a slow DNS provider cannot
   consume the shared worker pool used by other tools.
3. Scan with a fixed number of pure-Python TCP connect workers behind a shared
   concurrency ceiling. Per-connection and total-job timeouts keep a broad
   range bounded without creating one task for every port.
4. Retain detailed results only for ports that accepted a connection, up to a
   configured result cap, while counting every closed, timed-out, and failed
   attempt for progress. Mark truncated detail sets explicitly. Optional bounded
   banner and HTTP evidence collection runs only for open ports and is off by
   default.
5. Expose the in-memory job for browser polling and cancellation, preserve any
   open-port results collected before cancellation or a total deadline, and
   expire the job after the configured retention window. A separate retained-job
   count cap evicts the oldest terminal work so rapid small scans cannot grow
   memory until the time window elapses.

NetPorts is an unprivileged TCP connect scanner. It does not implement SYN, UDP,
or stealth scanning, and a connection timeout means only that no TCP response
arrived before the deadline; it is not proof of packet filtering. Deliberate
CSV or JSON exports remain on the user's machine but contain sensitive network
inventory and must be handled accordingly.

## NetTransfer flow

1. The loopback API accepts one start policy containing the selected protocol,
   bind address and port, download/upload/overwrite switches, and any allowed
   IPv4 client CIDRs. SFTP and FTP additionally require one username and
   password. It validates the complete policy before creating the singleton
   listener; a second TFTP, SFTP, or FTP server cannot start in the same process.
2. The service resolves `BNT_TRANSFER_ROOT` on the server side and creates that
   directory on first start. The browser can display this root but cannot change
   it or submit arbitrary filesystem paths. All three adapters use the same
   root, reject symlink or traversal escape, and share bounded file-list and
   transfer-event response models.
3. The listeners default to `127.0.0.1:6969` for TFTP,
   `127.0.0.1:2222` for SFTP, and `127.0.0.1:2121` for FTP. A
   wildcard/LAN bind is an explicit data-plane choice and requires one or more
   bounded IPv4 CIDRs. This never changes the FastAPI service's loopback-only
   bind. FTP additionally requires an explicit plaintext acknowledgement for a
   non-loopback bind.
4. Downloads are enabled by default, while uploads and overwrites require
   independent opt-ins. Each adapter applies the same file-size, per-client,
   and active-transfer ceilings. Completed uploads are published
   atomically where the protocol adapter supports a staged write; create-only is
   the default and overwrite requires its own explicit switch.
5. The browser polls `/api/transfer-server` for lifecycle state, protocol,
   endpoint, counters, sanitized activity, SFTP fingerprint, and FTP passive
   range. `/api/transfer-server/files` returns the bounded shared-root listing.
   Neither response contains a password. Stopping NetTransfer or shutting down
   FastAPI closes the active listener and transfers without deleting shared
   files.

### TFTP adapter

The standard-library datagram adapter handles bounded octet-mode RRQ and WRQ.
The source of an initial request is checked against the CIDR allowlist before a
transfer is allocated, and each transfer socket remains associated with that
client endpoint. Upload data remains in a temporary file until the final block
is published atomically. RFC 2347–2349 `blksize`, `timeout`, and `tsize` options
are negotiated only within server caps; file and block sizes, retry count, retry
interval, and total transfer time are bounded. TFTP provides no authentication
or encryption, so its listener is suitable only for a trusted, firewalled
network and never the public Internet.

### SFTP adapter

The AsyncSSH adapter accepts password-authenticated SFTP only. The submitted
username is sanitized status metadata, while the password remains only in
memory for the active runtime and is never returned, logged, or persisted. The service
loads or creates one persistent Ed25519 server key at
`BNT_TRANSFER_SFTP_HOST_KEY`; only its public fingerprint crosses the control
API so clients can verify a stable server identity. SFTP encrypts both
credentials and file data, but LAN exposure still requires the same explicit
CIDR gate.

### FTP adapter

The FTP adapter accepts one named password-authenticated account and does not
enable anonymous access. Its control listener defaults to TCP port 2121 and its
passive data listeners are constrained to the configured `50000-50019` range.
Both ranges remain subject to the client CIDR gate. FTP credentials and file
contents are plaintext, so a non-loopback start requires explicit acknowledgement
and firewall configuration must cover the control port and passive range.

Every selected data plane is deliberately separate from the loopback HTTP
control plane. The hosted launchpad cannot create any of these local listeners.

## NetPinger flow

1. Validate and deduplicate hostnames plus IPv4/IPv6 literals.
2. Resolve each hostname once with a bounded deadline. For literal IP input,
   start one bounded reverse-DNS lookup in parallel and expose the PTR name as
   optional identity metadata.
3. Ping the resulting numeric addresses concurrently with one sequential sample
   loop per target and a global process ceiling until the user stops the job.
4. Record each reply or failure with constant-memory latency and streak
   accumulators, retain only the latest 60 reply-time graph samples, and expose
   the cancellable in-memory job for UI polling.

The platform adapter builds fixed native command arguments for macOS and
Windows. Reverse-DNS absence, timeout, or failure does not change ping status or
statistics. Cancellation terminates active child processes and lookup tasks; no
continuous work is left running after the user stops a job or the API shuts
down. The browser retains only the active job identifier so it can reattach
after a page refresh, while the API caps the number of simultaneous jobs.

## NetTrace flow

1. Validate one hostname or IP address, resolve it once, and pass only the
   resulting numeric address to a platform-specific native traceroute adapter.
2. Run a fixed three probes per hop with bounded hop, timeout, active-job, and
   retention limits. Preserve each probe's address and round-trip time so ECMP
   or other alternate paths are not flattened into one answer.
3. Optionally resolve responder PTR names locally. When the user separately
   opts into ASN mapping, submit only public responder addresses in one bounded
   bulk request to Team Cymru and attach the returned BGP origin ASN, announced
   prefix, registry, assigned country code, and network name.
4. Build an AS path from observed responders. Only call a boundary exact when
   adjacent hops have one unambiguous known ASN; timeouts and multipath replies
   make the inferred handoff uncertain and remain visible in the response.
5. Expose the cancellable in-memory job for browser polling and terminate the
   native process immediately when the user stops the trace or the API shuts
   down.

Traceroute reveals the path observed from this machine at this moment, not a
guaranteed physical carrier handoff. Autonomous systems may be access providers,
transit networks, exchanges, CDNs, enterprises, or destination networks, so the
interface uses “network operator” unless the source data establishes more.

## QuickSSH flow

1. The browser selects SSH or Telnet, then opens that protocol's separate
   WebSocket on the loopback FastAPI service with a validated destination and
   terminal size.
2. For SSH, the service retrieves the server's public host key before
   authentication. New or changed keys pause the connection until the user
   verifies the SHA-256 fingerprint and explicitly trusts that exact key.
   AsyncSSH then opens a pseudo-terminal using a one-time password or the local
   SSH agent/default keys.
3. For Telnet, the Python service opens a bounded TCP stream and handles only
   the terminal option negotiation needed for binary data, echo, suppress-go-
   ahead, terminal type, and window size. Until binary mode is accepted it
   applies NVT carriage-return framing; the browser preserves CRLF pairs when
   splitting bounded input frames so a remaining bare CR unambiguously means
   Enter. The bridge supplies local terminal echo only when the server declines
   remote echo. Telnet login remains interactive;
   there is no browser credential field, encryption, or host verification.
4. The selected service forwards bounded binary terminal frames and resize
   events without logging their contents. Disconnecting the browser, remote
   endpoint, or local API closes the stream promptly. Per-protocol ceilings and
   one shared SSH-and-Telnet session limiter prevent unbounded connections.

The browser may remember a bounded list of protocol, host, port, SSH username
and authentication method when applicable, last connection time, and favorite
state. SSH trusted public host keys stay in a separate bounded device-local
store. It must never retain passwords, private keys, passphrases, terminal
output, or commands. Selecting Telnet must clearly warn that all terminal data,
including credentials typed at a login prompt, crosses the network in plaintext.

## NetSpeed flow

1. The Python service fetches and size-bounds LibreSpeed's public directory,
   validates each server and its relative test endpoints, upgrades only
   protocol-relative entries to HTTPS, then concurrently measures each usable
   host with a small, bounded HTTPS probe. The cached picker order uses measured
   network latency with deterministic location/name tie-breaks; timed-out hosts
   remain available after measured hosts. A fixed Cloudflare automatic-edge
   entry remains first and available when that directory is offline.
2. The browser selects an opaque catalog ID. The API resolves that ID from its
   private catalog; request bodies never contain an outbound URL.
3. A bounded in-memory job measures several HTTPS round trips, then capped
   parallel download and upload streams. The browser may select each aggregate
   transfer size within server-published minima and maxima; omitted values use
   server defaults. Median latency, mean consecutive-sample jitter, aggregate
   Mbps, transferred bytes, duration, and server identity are returned as one
   result.
4. The browser polls the job through its ping, download, and upload phases and
   may cancel it. Active-job, byte, request-time, total-time, and retention
   ceilings prevent unbounded traffic or memory use. Per-job options are frozen
   at creation, and cancellation or shutdown cancels all owned streams. The
   service derives a bounded speed-over-time series from cumulative transfer
   progress so the browser can render a live graph without estimating rates
   from slower UI polling.
5. Failed third-party servers are quarantined from the in-memory catalog for a
   short cooldown. The browser refreshes the directory and offers the fixed
   Cloudflare automatic entry instead of repeatedly presenting the same failed
   endpoint.

NetSpeed traffic originates from the local FastAPI process, so the result
describes that machine's Internet path. It intentionally performs bulk network
transfers to the selected public operator but sends no result telemetry. Catalog
ranking measures network proximity rather than geographic distance and contacts
each validated LibreSpeed host once per cached refresh.

## Update flow

1. The shared top-bar control asks the loopback FastAPI service to check the
   official repository's latest stable GitHub release. Hosted UI code never
   receives filesystem or Git privileges.
2. The service validates a strict release tag and immutable release record,
   resolves the peeled tag commit and `main` tip through GitHub's API, and fetches
   those pinned IDs in a temporary bare repository with isolated Git config.
   Only a bundle whose two object IDs match the API pins enters the checkout.
   One updater lock serializes checks and applies, and a total server deadline
   bounds the complete check in addition to each network and Git command.
3. A read-only preflight checks ancestry, the attached branch, worktree
   cleanliness, tree modes, protected paths, and dependency-manifest changes.
4. The browser presents a separate install action pinned to the observed local
   commit, release commit, and tag. The service rejects stale confirmation.
5. The service disables hooks and autostash, protects ignored paths, rechecks the
   branch/commit/clean state, and performs only a fast-forward merge. It never
   stashes, resets, force-updates, switches branches, or runs downloaded setup
   code. The user restarts the suite and reruns bootstrap only when instructed.

The local API exposes bounded operation status, while the current browser tab
retains only the expected commit and tag. Together they recover the result after
page navigation or a development-server reload without retrying an uncertain
write. The hosted site shows a GitHub Releases link because it has no local file
authority.

Source archives and packaged builds can check the release but cannot self-replace
without a future external installer that supports verification and rollback.

## Extension model

Each future launchpad tool should have:

- a small FastAPI router under the `/api` prefix, with explicit versioning when
  a breaking contract change becomes necessary;
- a Python service boundary independent of HTTP models;
- explicit capability and safety limits;
- a launchpad manifest (name, description, route, status, and capability tags);
- unit tests for target validation plus contract tests for its API models.

NetScanner probes should implement one narrow asynchronous interface: accept an
immutable target and deadline, then return zero or more typed observations.
Keep vendor/OUI data and fingerprint signatures as versioned data sources so
they can be updated without rewriting orchestration.

NetPorts probes similarly accept one immutable numeric target, address family,
port, and deadline, then return a typed connection observation. Job scheduling,
DNS resolution, port-range normalization, and retention stay outside the probe
so tests can replace network access with deterministic adapters.

## State and deployment

Network jobs and NetTransfer runtime state are process-local and short-lived.
The selected listener, active transfers, counters, credentials, and bounded
event history disappear when the Python service stops; only shared files and the
persistent SFTP server host key remain on disk. Do not add a database until the
product needs saved inventories, comparisons, or multi-user history. If durable
storage is added, treat hostnames, addresses, filenames, banners, and
credentials as sensitive operational data with an explicit retention policy.

Sites can host the launchpad UI, but hosted workers cannot perform private-LAN
scans, run a traceroute from the user's device, initiate SSH or Telnet from the
user's machine, host TCP or UDP file-transfer services on the user's LAN, or
measure the user's own internet path. Full hosted use therefore requires a
separately installed local
agent, mutual authentication, origin pairing, and a deliberately narrow command
protocol. Until that design exists, NetScanner, NetPorts, NetPinger, NetSpeed,
NetTransfer, NetTrace, and QuickSSH are supported only with the local FastAPI
service, and that service must remain loopback-bound. Only NetTransfer's
separate, explicitly selected data listener may use a LAN bind, and only with an
explicit client-network allowlist.

## Compatibility policy

- Supported runtimes: Python 3.11+ and Node.js 22.23.1+.
- Supported developer platforms: current macOS and supported Windows releases.
- Prefer pure Python socket APIs and maintained libraries over native commands.
- Never depend on raw-socket/admin access for the baseline scan path.
- Capability-specific probes must declare `supported`, `unavailable`, or
  `permission_required`; they must not guess or elevate automatically.

## Release path

The source workflow intentionally runs two development processes. An end-user
release should build the web assets ahead of time and package them with the
local Python service behind one loopback origin; network engineers should not
need Node.js to use an installed release. Choose a packager only after native
probe dependencies stabilize, then validate signed artifacts in a macOS and
Windows CI matrix. Treat installers, automatic updates, and code signing as a
separate release milestone rather than widening the API bind address.
