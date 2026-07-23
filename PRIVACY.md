# Privacy

This notice describes the data behavior of the Better Network Tools v0.1.0
source preview and its hosted feedback relay. It is not a promise by the
operators of networks or third-party services that you choose to contact.

Last updated: July 23, 2026.

## Local network tools

The Python control API and development UI run on loopback by default. Scan and
job results are held locally and are not sent to a Better Network Tools
analytics or telemetry service. Some bounded client state—such as active job
references, recent traces, speed-test history and preferences, and SSH
connection metadata or trusted host fingerprints—may be stored in the browser's
local or session storage. Passwords are not intended to be persisted there.
Clear the site's browser storage to remove that client state.

Features that necessarily contact third parties disclose that behavior in the
interface and security documentation. Examples include:

- checking releases against GitHub;
- obtaining a NetSpeed server catalog and running a selected speed test, which
  exposes the machine's public address and transfers test traffic;
- optional NetTrace ASN enrichment through Team Cymru; and
- sending the optional hosted feedback form.

Normal network tools also contact the targets you explicitly select. Those
targets and network operators may log the activity. See
[docs/security.md](docs/security.md) for the detailed data-flow and safety
boundaries.

## Hosted feedback

Submitting the feedback form sends the following to a hosted Cloudflare Worker:

- your comments;
- an email address, only if you choose to provide one;
- request metadata needed to deliver and protect the service, including the
  source IP address, origin, timestamp, and Cloudflare request identifiers.

The browser sends the feedback request without credentials. The Worker
validates the submission and creates an issue in a private GitHub repository.
The issue contains the comments, optional email, and submission timestamp. The
application does not intentionally add the source IP address to that issue.
The optional email is used only when a reply is needed.

### Abuse prevention

For rate limiting, the Worker computes separate hourly and daily HMAC-SHA-256
identifiers from the source IP address, a server-only secret, and the current
time bucket. The application stores only each derived identifier, a request
count, and an expiry timestamp in Cloudflare D1—not the raw IP address.

Hourly and daily rows are marked to expire at the end of their time bucket plus
a five-minute grace period. Cleanup occurs opportunistically when a later
feedback request runs, so an expired row can remain longer when the form is
idle. Cloudflare may also process or retain network and service logs under its
own policies.

### Retention and deletion

Feedback issues are retained in the private GitHub repository until the
maintainer deletes them; there is no automatic deletion schedule or
self-service deletion mechanism. GitHub and Cloudflare may retain backups,
security records, or operational logs after application-level deletion under
their respective policies.

To request deletion, submit the feedback form with `Deletion request` at the
start of the message and provide enough detail to locate the original
submission, such as its approximate date and distinctive wording. Supplying the
same optional email can help verify and locate it. The maintainer will make a
reasonable effort to delete the private issue, but cannot guarantee immediate
or complete removal from provider backups, logs, or prior notifications.

## Your choices

- Do not submit the feedback form if you do not want the content processed by
  Cloudflare and GitHub.
- Leave the email field blank to submit feedback without contact information.
- Use only sanitized, non-confidential examples in feedback and public issues.
- Clear local browser storage to remove locally persisted UI state.

For vulnerabilities, do not use the feedback form. Follow the private process
in [SECURITY.md](SECURITY.md).

Material changes to this notice will be committed with the related code change.
