# Release process

Better Network Tools is currently a v0.1.0 source preview. There is no signed
installer or packaged desktop artifact. Until the first stable, immutable
GitHub release exists, the in-app updater intentionally reports that no
installable release is available.

## Versioning

Stable tags use semantic versioning in the form `vMAJOR.MINOR.PATCH`. Keep the
version synchronized in:

- `package.json`;
- `backend/pyproject.toml`;
- `backend/src/better_network_tools/__init__.py`; and
- any version-specific updater tests or defaults.

## Release checklist

### Policy and repository readiness

- [ ] `LICENSE` contains the MIT License and the JavaScript and Python package
      metadata declare `MIT`.
- [ ] `SECURITY.md`, `PRIVACY.md`, `SUPPORT.md`, contribution guidance, and
      release notes reflect the candidate.
- [ ] `CHANGELOG.md` moves relevant Unreleased entries under the release
      version and date.
- [ ] GitHub security features and dependency alerts are enabled.
- [ ] `main` is protected, required checks pass, and force pushes and deletion
      are blocked.
- [ ] The working tree contains no secrets, local `.env`, credentials, private
      keys, inventories, build output, caches, or unrelated files.
- [ ] Dependencies and production advisories have been reviewed and resolved or
      explicitly documented.

### Candidate validation

- [ ] Versions are synchronized and use semantic versioning.
- [ ] `uv lock --project backend` and the documented `uv export` command
      produce reviewed `backend/uv.lock` and `backend/requirements.lock`
      updates with no unexplained drift.
- [ ] `pnpm install --frozen-lockfile` succeeds from a clean checkout.
- [ ] `.venv/bin/python -m pytest backend` passes.
- [ ] `pnpm run lint` passes.
- [ ] `pnpm test` passes, including the production web build.
- [ ] The source bootstrap and launcher are tested on supported macOS and
      Windows versions.
- [ ] Loopback binding, CORS restrictions, bounded jobs, cancellation, transfer
      containment, credential handling, and update refusal paths are verified.
- [ ] Documentation links and repository templates are validated.

### Publish

- [ ] Merge the complete candidate to `main`.
- [ ] Write release notes covering user-visible changes, security/privacy
      changes, known limitations, upgrade steps, and checksums for any attached
      artifacts.
- [ ] Create the matching `vMAJOR.MINOR.PATCH` tag from the reviewed `main`
      commit.
- [ ] Publish a non-draft, non-prerelease GitHub release for that tag.
- [ ] Make the release immutable and verify GitHub reports it as immutable
      before announcing updater availability.
- [ ] Do not advertise an installer as signed unless its signature and
      provenance have been independently verified.

### Post-release

- [ ] From a fresh clean clone, verify the update check identifies the release
      and pins the expected tag and commit.
- [ ] Verify the updater refuses mutable, prerelease, off-`main`, non-fast-
      forward, locally modified, or unsafe release trees.
- [ ] Confirm release documentation, source archives, and repository metadata
      are visible.
- [ ] Open a tracked issue for every deferred known limitation.

## Updater release gate

The updater trusts only the configured official repository and stable semantic
version tags. It requires the latest GitHub release to be immutable and
reachable from official `main`; it also validates the fetched commit and local
worktree before applying a clean fast-forward. A tag or mutable release alone
does not activate update installation.

If any publication check fails, leave the release unannounced, correct it with a
new version when necessary, and do not weaken updater validation to accommodate
the release.
