# Contributing to PortScope

Thanks for helping. PortScope is a defensive tool, so changes are judged first on whether they keep users safe and second on features.

## Before you start

- **Security issues:** do not open a public issue. Report them privately as described in [SECURITY.md](SECURITY.md).
- **Bugs and ideas:** open an [issue](https://github.com/IvelianK/Port-Scope/issues/new/choose) first for anything larger than a small fix, so we can agree on the approach.

## Set up

PortScope needs Python 3.10 or newer and has no runtime dependencies.

```bash
git clone https://github.com/IvelianK/Port-Scope.git
cd Port-Scope
python3 -m unittest -v
python3 -m portscope --cli --no-upnp --no-history
```

## Making a change

1. Branch from `main`. `main` only accepts squash-merged pull requests that pass CI on Windows and Linux (Python 3.10 and 3.13) and CodeQL.
2. Add or update a test for any behavior change. Tests use the standard library only and avoid mocks when the real code can run.
3. Keep the project dependency-free at runtime. Treat everything from the network, from routers and from process names as untrusted input.
4. Update both `README.md` and `README_es.md` when user-facing behavior changes.

### Common contributions

- **A new port or service:** add an entry to [`portscope/data/ports.json`](portscope/data/ports.json) with `service`, `risk`, `attack` (MITRE ATT&CK technique IDs), and `en`/`es` texts. The test suite checks that every entry is complete.
- **A new language:** add `portscope/web/i18n/<code>.json` with every key from `en.json`, and a `"<code>"` text to each entry of `ports.json`.
- **Close-port guidance:** commands in `portscope/web/app.js` must be safe to paste. Each blocking command needs an undo command, and core OS services must never be suggested for stopping.

## Releases

Maintainers release by pushing a `vX.Y.Z` tag that points at the current `main` and matches `portscope.__version__`. The release workflow builds and smoke-tests both executables, publishes SHA-256 checksums, and attests their provenance.

By contributing you agree that your work is released under the [MIT License](LICENSE) and that you follow the [Code of Conduct](CODE_OF_CONDUCT.md).
