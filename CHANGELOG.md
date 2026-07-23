# Changelog

All notable user-visible changes to Better Network Tools are recorded here.
The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/), and stable releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Community contribution, support, private security-reporting, privacy, and
  release-process documentation.
- Reproducible pnpm and hashed Python dependency lock workflows.
- GitHub issue forms, a pull request template, CI, and supported dependency
  update automation for release readiness.
- MIT licensing and matching JavaScript and Python package metadata.

### Changed

- Source setup now clearly requires the pinned pnpm version, directly or
  through Corepack; npm dependency installation is unsupported.
- Web dependency updates remain manual and CI-audited until GitHub Dependabot
  supports the repository's pinned pnpm 11 release.

### Security

- Enforced loopback-only API binding, HTTP clients, and explicitly configured
  local CORS origins.
- Upgraded and pinned the web and Python dependency graphs so complete
  production and development audits report no known vulnerabilities.

When v0.1.0 is published, move its entries out of Unreleased into a
`## [0.1.0] - YYYY-MM-DD` section and leave a new empty Unreleased section at
the top.
