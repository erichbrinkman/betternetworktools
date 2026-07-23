# Contributing to Better Network Tools

Thank you for helping improve Better Network Tools. The project welcomes
focused bug fixes, documentation improvements, tests, and carefully scoped
features.

Report security vulnerabilities through the private process in
[SECURITY.md](SECURITY.md), not in an issue or pull request.

By submitting a contribution, you agree that it will be licensed under the
[MIT License](LICENSE).

## Before you start

1. Search existing issues and pull requests.
2. Open an issue before a large feature, behavior change, new dependency, or
   network-facing capability.
3. Keep work limited to devices and networks you are authorized to test.
4. Never include credentials, private keys, tokens, customer information,
   device inventories, packet captures, or unredacted logs and screenshots.

## Development setup

Requirements are Python 3.11+, Node.js 22.23.1+, Git, and pnpm 11.9.0. Corepack
may provide the pinned pnpm version declared by `package.json`.

macOS:

```bash
python3 scripts/bootstrap.py
.venv/bin/python scripts/dev.py
```

Windows PowerShell:

```powershell
py -3 scripts\bootstrap.py
.venv\Scripts\python.exe scripts\dev.py
```

The bootstrap script creates `.venv`, installs the Python package in editable
mode with development dependencies, installs web dependencies, and copies
`.env.example` to `.env` when needed.

`pnpm-lock.yaml` is the authoritative JavaScript dependency lock. Bootstrap
uses `pnpm install --frozen-lockfile` directly or through Corepack. npm
dependency installation is not supported; do not run `npm install` or add
`package-lock.json`.

### Updating dependency locks

When JavaScript dependencies change, run `pnpm install` from the repository
root and commit the reviewed `package.json` and `pnpm-lock.yaml` changes
together.

Python resolution is recorded in `backend/uv.lock`. Bootstrap and CI install
the hashed, pip-compatible `backend/requirements.lock`. After changing
`backend/pyproject.toml`, install
[uv](https://docs.astral.sh/uv/getting-started/installation/) and regenerate
both files from the repository root:

```bash
uv lock --project backend
uv export --project backend --all-extras --no-emit-project \
  --format requirements.txt --output-file backend/requirements.lock --locked
```

Review and commit `backend/pyproject.toml`, `backend/uv.lock`, and
`backend/requirements.lock` together. Do not hand-edit either lock file.

## Local configuration

Edit the ignored `.env`, never `.env.example`, for machine-specific settings.
The template documents every supported variable. In particular:

- `BNT_HOST`, `BNT_WEB_HOST`, and `BNT_CORS_ORIGINS` preserve the loopback-only
  control boundary.
- `BNT_PORT`, `BNT_WEB_PORT`, and `NEXT_PUBLIC_BNT_API_URL` select the local
  endpoints.
- `BNT_*_LIMIT` and timeout values bound network jobs and services.
- `BNT_TRANSFER_*` controls the fixed transfer root, listeners, permissions,
  and resource ceilings.
- `BNT_UPDATE_*` identifies the fixed release source. It must not be changed to
  install arbitrary branches.
- `BNT_FEEDBACK_*` values are deployment secrets for the hosted relay and are
  not required to run the local network tools.

The shared launcher rejects non-loopback web and API hosts. Do not weaken that
guardrail. Read [docs/security.md](docs/security.md) before changing target
validation, subprocesses, remote sessions, transfer services, or update logic.

## Making changes

- Create a focused branch from current `main`.
- Match the existing TypeScript, React, and Python style.
- Add or update tests for behavior changes and failure paths.
- Keep network work bounded, cancellable, and explicit.
- Treat remote banners, hostnames, paths, terminal output, and probe results as
  untrusted input.
- Avoid unrelated formatting or generated-file churn.
- Update user documentation when behavior, configuration, or privacy changes.
- Add user-visible changes to the [Unreleased changelog](CHANGELOG.md).

## Validation

Run the relevant checks before opening a pull request:

```bash
.venv/bin/python -m pytest backend
pnpm run lint
pnpm test
```

On Windows, replace `.venv/bin/python` with
`.venv\Scripts\python.exe`. Release and CI validation use pnpm's frozen
lockfile.

For platform-specific behavior, state which macOS and/or Windows versions you
tested. Never test scanning, transfer, SSH, or Telnet behavior against systems
without authorization.

## Pull requests

Complete the pull request template and include:

- the user-visible problem and the chosen solution;
- testing performed and any gaps;
- screenshots only when they contain no sensitive data;
- security, privacy, configuration, and compatibility effects; and
- documentation or release-note changes when applicable.

Maintainers may ask for a smaller scope, additional tests, or design discussion
before merging. Contributions are reviewed on a best-effort basis; see
[SUPPORT.md](SUPPORT.md).
