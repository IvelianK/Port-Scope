# Security policy

## Supported versions

Security fixes target the latest PortScope 2.x release. Earlier versions may not receive patches. Download releases only from [this repository](https://github.com/IvelianK/Port-Scope/releases) and verify their checksums and build provenance before running them.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/IvelianK/Port-Scope/security/advisories/new). Include the affected version, operating system, steps to reproduce, expected and observed behavior, and a minimal proof of concept if needed. Do not post exploit details, tokens, private IP addresses, or customer data in a public issue.

For a defect without security impact, open a regular [issue](https://github.com/IvelianK/Port-Scope/issues). The maintainer will triage private reports and coordinate a fix and disclosure through the GitHub advisory.

## Security model

PortScope is a local, read-only exposure aid. It enumerates sockets on the current machine and, by default, sends UPnP discovery and read-only gateway queries on the local network. It does not scan arbitrary remote targets, change firewall or router configuration, or transmit telemetry.

The browser dashboard listens on loopback and uses a per-run token. The terminal URL and JSON reports are sensitive. Router responses, process names, and network data are treated as untrusted input, but no software can guarantee that an environment is free of vulnerabilities. Use the tool only on systems and networks you are authorized to assess.
