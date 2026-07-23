## Summary

Describe the user-visible problem and the focused solution.

## Changes

- Describe the main change.

## Validation

List the exact checks and supported platforms tested.

```text
.venv/bin/python -m pytest backend
pnpm run lint
pnpm test
```

## Security and privacy

Describe effects on target scope, loopback exposure, credentials, retained data,
external services, subprocesses, file paths, resource limits, cancellation, and
updates. Write `No change` only after considering each area.

> Do not attach credentials, tokens, private keys, real device inventories,
> packet contents, customer information, `.env` files, or unredacted logs and
> screenshots.

## Checklist

- [ ] I kept the change focused and documented user-visible or configuration changes.
- [ ] I added or updated tests for behavior and relevant failure paths.
- [ ] I ran the relevant Python and web checks, or explained why I could not.
- [ ] I tested only on systems and networks I am authorized to use.
- [ ] I verified that this pull request contains no sensitive data or generated local state.
- [ ] I preserved loopback-only control, bounded work, cancellation, and safe defaults.
- [ ] I considered macOS and Windows compatibility.
- [ ] I reviewed the [contribution guide](https://github.com/erichbrinkman/betternetworktools/blob/main/CONTRIBUTING.md) and [Code of Conduct](https://github.com/erichbrinkman/betternetworktools/blob/main/CODE_OF_CONDUCT.md).
