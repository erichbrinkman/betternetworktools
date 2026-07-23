# Network tool safety

Better Network Tools is for authorized administration. Network probes and
remote terminal connections may be logged or interpreted as hostile. Product and code changes
must keep the following guardrails intact.

## Required defaults

- Bind the API and development UI to loopback (`127.0.0.1`) only. The installed
  API and shared launcher refuse wildcard and LAN `BNT_HOST` values, and the
  application rejects HTTP requests from non-loopback clients.
- Allow browser requests only from normalized origins explicitly listed in
  `BNT_CORS_ORIGINS`. A `localhost` origin on an unconfigured port is not
  implicitly trusted.
- Accept only tool-appropriate CIDRs, IP addresses, or validated hostnames, not
  arbitrary URLs or shell fragments. Normalize addresses with `ipaddress` and
  validate every target before any job is queued.
- Limit hosts, ports, concurrency, per-probe timeouts, and job retention. A
  request may lower those limits but must not bypass configured ceilings.
- Make every job cancellable and every long-running server explicitly stoppable;
  release owned sockets and tasks promptly on cancellation or shutdown.
- Default to unprivileged TCP/DNS techniques. Treat raw ICMP, ARP capture, and
  packet injection as optional capabilities with visible permission status.
- Keep scan results in memory initially and expire them. Never transmit
  inventory or telemetry off the machine without a separate opt-in design.
- Keep NetTransfer's control API and every default data listener on loopback. A
  LAN listener requires an explicit exposure choice and one or more bounded
  IPv4 client CIDRs; it never widens the FastAPI bind.
- Keep downloads enabled but uploads and overwrites disabled by default for
  TFTP, SFTP, and FTP. All file content must remain inside the one configured
  server-side root.
- Keep SFTP and FTP passwords memory-only for one active server run. Persist
  only the SFTP server host key, expose only its public fingerprint, and never
  enable anonymous FTP.

## Target policy

NetScanner's first implementation accepts normalized IPv4 CIDRs, enforces the
configured host-count ceiling before enumeration, and rejects IPv6, multicast,
and specific unspecified/broadcast targets (`0.0.0.0/32` and
`255.255.255.255/32`). It does **not** treat address classification as proof of
authorization and does not yet enforce a private-range allowlist.

NetPorts accepts exactly one validated hostname or IP address. Resolve a hostname
once under a deadline, validate the answer, and use only that numeric address
for every connection attempt. Reject unspecified and multicast addresses, the
IPv4 limited broadcast address, and unscoped IPv6 link-local addresses. Parse
custom port expressions as decimal ports and inclusive ranges, deduplicate them,
and enforce the configured unique-port limit before scheduling probes.

Policy for public, reserved, and link-local ranges is a future hardening and
product decision. Add it as explicit, tested configuration rather than a hidden
assumption. IPv4 and IPv6 policies should be evaluated independently; never
assume an IPv6 prefix has a manageable host count.

Show the normalized target and estimated address count before starting a subnet
scan. For NetPorts, show the single target, normalized port expression, and
unique TCP-port count. The user is responsible for authorization, but the
application is responsible for preventing accidental scope expansion.

## NetTransfer server policy

NetTransfer serves one fixed, server-configured root shared by TFTP, SFTP, and
FTP. Resolve and create that root inside the Python service; never accept a
directory path from the browser, a credential field, or a protocol packet, and
never expand user or environment tokens from a requested filename. Reject empty, absolute,
NUL-bearing, backslash-containing, traversal, Windows device-name, and drive/UNC
paths, and ensure every filesystem component remains under the configured root
when symlinks are present. Do not expose host paths in protocol errors or normal
logs.

Exactly one protocol runtime may be starting or running. The listeners default
to `127.0.0.1:6969` for TFTP, `127.0.0.1:2222` for SFTP, and
`127.0.0.1:2121` for FTP. Treat any wildcard/LAN bind as a separate data-plane
opt-in and require at least one validated IPv4 CIDR whose expanded size remains
within the configured host ceiling. Apply the allowlist before allocating
transfer state. The HTTP control API always stays loopback-only. Privileged
standard ports must be explicit; report permission failure and never elevate
automatically.

Keep downloads on and uploads plus overwrites off by default. Enforce global and
per-client transfer ceilings before disk or socket work, cap actual bytes rather
than trusting client-declared sizes, stage uploads safely, publish completed
files atomically, and remove partial files on error, timeout, Stop, or API
shutdown. Retain only bounded sanitized transfer metadata for status display,
never file contents, packet payloads, or credentials.

SFTP and FTP require a validated named username and password. Passwords are
single-run, memory-only inputs: never place one in a URL, browser storage,
status response, event record, application log, screenshot, configuration file,
or database. Clear browser password state after a successful start and release
the server-side credential when the runtime stops.

### TFTP

The UDP listener defaults to `127.0.0.1:6969`. Apply the allowlist to the source
of the initial request before opening a file or allocating transfer state. UDP
port 69 must be an explicit choice; report permission failure and never elevate
automatically.

Support only bounded octet-mode RRQ and WRQ. For every accepted transfer:

- pin the transfer socket to the requesting IP address and UDP port, reject
  packets from an unknown transfer ID, and reject multicast or unspecified
  client sources;
- enforce global and per-client transfer ceilings before disk or socket work;
- cap file size from actual bytes, not only the untrusted `tsize` option;
- negotiate RFC 2347–2349 `blksize`, `timeout`, and `tsize` only within server
  caps, and bound packet size, retry count, retry interval, and total transfer
  time;
- write uploads to a temporary file, publish a completed file atomically, allow
  creation only unless overwrite is explicitly enabled, and remove partial
  files on protocol error, timeout, Stop, or API shutdown;
- cleanly close every owned transfer socket on timeout, Stop, or API shutdown;
  and
- retain only bounded transfer metadata for status display, never file content
  or packet payloads.

TFTP has no authentication, confidentiality, or cryptographic integrity. A CIDR
allowlist reduces accidental exposure but is not client identity. Keep the data
listener behind a trusted firewall, never publish it to the Internet, and use
SFTP when credentials or secrecy are required.

### SFTP

SFTP runs over SSH with password authentication and encrypted file contents.
Load or create one persistent Ed25519 server key at the configured
`BNT_TRANSFER_SFTP_HOST_KEY` path with restrictive local permissions. Never
return its private material; expose only the public fingerprint so operators can
verify a stable server identity in their SFTP client. Treat an unexpected
fingerprint change as a security event, not an inconvenience to bypass.

Constrain the authenticated account to the shared root and the selected
download/upload/overwrite policy. Reject unsupported filesystem operations,
symlink escape, and any path which cannot be proven to remain below the root.
Authentication failure must not disclose whether a username or password was
wrong, and repeated attempts must remain bounded by the connection and runtime
ceilings.

### FTP

FTP provides neither confidentiality nor cryptographic server identity. It
requires one named password-authenticated account; anonymous access must remain
disabled. Show a persistent plaintext warning, and require a separate explicit
acknowledgement before binding FTP beyond loopback. Prefer SFTP whenever the
client supports it, and never expose FTP to the public Internet.

Constrain passive data listeners to `BNT_TRANSFER_FTP_PASSIVE_PORT_START`
through `BNT_TRANSFER_FTP_PASSIVE_PORT_END`, defaulting to `50000-50019`, with a
maximum configured width. Apply the client allowlist to control and data
connections, prevent one client from attaching to another client's transfer,
and close unused passive listeners promptly. LAN firewall rules must cover both
the FTP control port and the bounded passive range.

## Probe implementation

- Never use `shell=True`. Pass fixed argument arrays only when an OS utility is
  unavoidable, validate every value, set a short timeout, and capture bounded
  output.
- Prefer protocol-aware parsing. Put byte and response-size ceilings on banners,
  redact control characters, and label unverified text as untrusted device data.
- Do not execute discovered content, follow arbitrary redirects, resolve user
  input into file paths, or use scanner targets as outbound proxy destinations.
- Use monotonic deadlines, bounded queues, and predictable retry counts. Avoid
  synchronized retry bursts.
- Record which probe produced each claim. Fingerprints are hypotheses, so expose
  confidence and conflicting evidence instead of asserting certainty.

For NetPorts specifically, use only unprivileged, pure-Python TCP connect probes;
do not claim SYN, UDP, or stealth scanning. Resolve a hostname once and supply
only the validated numeric address to every socket operation. Bound the port
count, active jobs, fixed worker count, shared connection concurrency,
per-connection timeout, total job time, optional banner timeout, and retention.
Cap both retained jobs and retained open-port details; report detail truncation
without losing aggregate open/closed/no-response/error counts. Do not create one
task per requested port. Cancellation and API shutdown must cancel and gather
all workers so pending sockets stop promptly while already collected open-port
results remain available. Treat connection refusal as
closed, but label a timeout only as no response—not proof of firewall filtering.
Banner collection must be off by default and, when enabled, read only bounded
responses, remove control characters, never follow redirects, and never execute
device-provided content.

For NetPinger specifically, resolve each hostname once per job, pass only the
validated resolved address to the native ping command, and start subprocesses
with fixed argument arrays. Keep target count, finite samples, intervals,
timeouts, and total concurrent workers bounded. Continuous jobs must be
explicit and visible, use constant-memory statistics, and provide a stop
action. Cap the number of active jobs atomically, and retain the active job
identifier locally so a refreshed page can recover its Stop control. Stopping
a job or shutting down the API must terminate active ping processes and leave
no probes running in the background. Any per-probe data used for graphs must be
stored in a fixed-size window rather than an unbounded history. A literal IP may
receive one bounded PTR lookup per job, in parallel with probing. Treat the
returned hostname as untrusted optional metadata: reject malformed or numeric
fallback values, never let lookup failure affect reachability, and cancel the
lookup with its owning job.

For NetTrace specifically, resolve the target once and pass only a validated
numeric address to a fixed native `traceroute`, `traceroute6`, or `tracert`
argument vector. Bound maximum hops, probes per hop, per-probe wait time, total
process time, active jobs, captured output, and retention. Preserve partial
results, and terminate the owned process on cancellation or API shutdown.
Treat PTR names, native annotations, and ASN descriptions as untrusted display
data. Public-hop ASN mapping is a separate, default-off option because it sends
the observed public addresses to Team Cymru; name the provider and disclosure
in the interface, batch the request, skip non-public addresses, and make lookup
failure a warning rather than a trace failure. AS transitions are inferences:
do not claim an exact carrier boundary across a timed-out or multipath hop.

For NetSpeed specifically, accept only an opaque server ID returned by the
local service catalog. Fetch the public LibreSpeed directory from its fixed
HTTPS URL, discard malformed, non-public, explicitly HTTP, cross-origin, or
path-traversing entries, and never expose or accept measurement URLs through
the API. Resolve directory hosts with a bounded deadline before caching them,
reject an entry if any answer is not globally routable, and repeat that check
immediately before test traffic. Protocol-relative official entries may be
upgraded to HTTPS. Keep a fixed Cloudflare automatic-edge entry as the reliable
fallback. Rank validated public entries by small concurrent HTTPS latency probes
with per-request, concurrency, response-size, and whole-ranking deadlines; cache
the order, keep failures after measured entries, and describe this as network
latency rather than physical distance. This ranking exposes the local machine's
public IP address to each probed host, so disclose it in the interface and
documentation. Do not follow redirects. Bound the directory response, ping
samples, download and upload bytes, individual request time, total job time,
active jobs, and retention. User-selected download and upload sizes are
aggregate limits across all parallel streams, must be strict integers, and must
be rejected when outside the server-published minimum and maximum; never let the
browser choose stream concurrency or silently clamp an invalid size.
Cancellation or API shutdown must close the owned HTTP work promptly. Speed
tests send and receive deliberate bulk traffic to the selected public operator;
they do not submit telemetry or persist results.
Use provider-compatible per-request chunks, bound all retries, and never retry
an upload whose remote receipt cannot be ruled out. Temporarily quarantine a
third-party server after a bounded job failure, but keep endpoint details and
failure internals out of the public API. Throughput graph samples must contain
only phase, elapsed time, and finite nonnegative Mbps values under a fixed count
cap; never include endpoint URLs, resolved addresses, or transport exceptions.

For QuickSSH specifically, accept sessions only over the loopback service and
validate the WebSocket Origin before accepting it. Bound active sessions,
connection setup time, input frame size, terminal dimensions, and output frame
size. A browser disconnect, remote exit, API shutdown, or explicit Disconnect
action must close the channel and network connection promptly. Never disable
SSH server host-key verification: show the SHA-256 fingerprint for a new key,
warn distinctly when a remembered key changes, require explicit confirmation,
and validate the subsequent SSH handshake against the exact confirmed key.

Keep Telnet on a separate loopback WebSocket and separate service lifecycle so
it cannot weaken SSH host-key or authentication handling. Validate the actual
client and server socket endpoints, bound TCP setup and all terminal frames,
reject unsupported option negotiation, and close a Telnet stream promptly on
Disconnect, browser loss, remote EOF, or API shutdown. Telnet provides neither
confidentiality nor server identity: show a persistent plaintext warning before
connecting, collect no browser-side Telnet credentials, and never describe it
as secure. Use it only for authorized legacy devices on trusted isolated
networks.

## Credentials and sensitive data

Do not put SNMP communities, API tokens, device credentials, or inventories in
committed files, URLs, browser storage, screenshots, or normal logs. Secrets
belong in the local environment or an OS credential store. Prefer SNMPv3 and
read-only accounts with the minimum supported scope; do not ship default
credentials or automatic credential guessing.

QuickSSH's SSH passwords are single-use, memory-only connection inputs. Telnet
credentials are typed only into the live terminal but still traverse the
network in plaintext. Do not put a password, passphrase, private key, terminal
output, or command history in a URL,
browser storage, application log, screenshot, or recent-connection record.
Device-local recents may contain only the selected protocol, host, port, SSH
username and authentication method when applicable, last connection time, and
favorite state. SSH public host keys belong in their separate bounded trust
store; the UI must provide deletion controls for both stores.

Scan output may reveal addressing, hostnames, vendors, operating systems, and
open services. Treat exports as sensitive, make export a deliberate user
action, and document retention and deletion once persistence is introduced.
NetPorts CSV and JSON exports may additionally contain the resolved numeric
target, per-port timing, service hints, and untrusted banner evidence. Keep them
out of browser storage, logs, tickets, and shared locations unless explicitly
required and protected for the authorized assessment.

NetTransfer's configured root and persistent SFTP host key are operational data;
filenames, account names, client addresses, fingerprints, and transfer events
may also be sensitive. Place only deliberately shared files in the root, protect
the root and private host key with OS permissions, review files before enabling
LAN downloads, and keep credentials plus transfer metadata out of browser
storage and normal logs.

## Software updates

Treat updates as local code installation, not ordinary web content. Update API
routes must remain loopback-only, and every route that fetches or changes Git
objects must require an exact configured local Origin. Apply additionally needs
a JSON confirmation that pins the current commit, candidate commit, and stable
release tag. The browser must never supply a
repository URL, branch, tag, command, or filesystem path.

Only install immutable stable GitHub releases from the configured official
repository. Resolve and peel the release tag and `main` commit through GitHub's
API, fetch those exact IDs in a temporary bare repository with isolated Git
configuration, compare both IDs, and import only the verified bundle. Require a
clean attached `main` checkout, reject divergent history, and merge only with
`--ff-only`, `--no-overwrite-ignore`, hooks disabled, autostash disabled, and a
clean branch/commit recheck immediately before and after. Reject symlinks,
gitlinks, submodules, protected local paths, unsafe attributes/grafts/sparse
metadata, and new files that collide with ignored or untracked paths. Never
stash, reset, force, execute newly downloaded code, or run dependency installers automatically.
Serialize check/apply Git operations and enforce both per-command limits and a
total update-check deadline so a browser retry cannot overlap a timed-out check.
Report when the setup script must be rerun and require a restart. Non-Git
installations remain manual until signed platform bundles support staging,
atomic replacement, and rollback.

## Review checklist

For every new probe or target type, tests should cover:

- malformed, oversized, mixed-family, and disallowed targets;
- timeout, cancellation, partial failure, and concurrency ceilings;
- hostile or oversized device responses;
- path traversal, symlink escape, partial upload, overwrite, and unknown-transfer
  behavior for file-transfer services;
- macOS and Windows capability behavior without elevated privileges;
- redaction of secrets and untrusted response data;
- confirmation that no external telemetry or unexpected network destination is
  contacted.
