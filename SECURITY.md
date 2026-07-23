# Security policy

Better Network Tools performs sensitive network operations. Safety issues and
vulnerabilities are taken seriously, including defects that could expand a scan,
expose the loopback API, escape a transfer root, leak credentials, or install an
untrusted update.

## Supported versions

| Version | Security support |
| --- | --- |
| Current `main` / v0.1.0 source preview | Best-effort fixes |
| Older commits and forks | Not supported |

There is no signed installer or packaged desktop release yet. This table will
be updated when stable releases are published.

## Report a vulnerability privately

Use [GitHub's private security advisory
form](https://github.com/erichbrinkman/betternetworktools/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue, discussion, pull
request, screenshot, or feedback submission.

Include, when possible:

- the affected version, tag, or commit;
- operating system and relevant configuration;
- a clear impact statement and attack prerequisites;
- minimal, safe reproduction steps using systems you control;
- sanitized logs or a proof of concept; and
- a suggested mitigation, if known.

Do not include real credentials, private keys, customer data, third-party
device inventories, or unnecessary exploit data. Do not test against networks
or devices without authorization.

## What to expect

The maintainer aims to acknowledge a report within five business days and
provide an initial assessment within ten business days. These are best-effort
targets, not a service-level agreement. Remediation and disclosure timing
depends on severity, complexity, and affected users.

Please allow time for investigation and a coordinated fix before public
disclosure. The maintainer will credit reporters who request credit and will
keep reporters informed when practical.

## If sensitive data was posted publicly

Remove it from view if possible, revoke or rotate exposed credentials
immediately, and submit a private advisory describing where it appeared.
Editing or deleting a GitHub comment does not guarantee removal from clones,
caches, notifications, or provider retention systems.

For secure-development requirements and the current threat boundaries, read
[docs/security.md](docs/security.md).
