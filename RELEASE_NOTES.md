# PortScope 2.0.2

PortScope is a local defensive cybersecurity tool for Windows and Linux. It lists listening TCP ports and bound UDP sockets, identifies their processes when available, and reads router port mappings reported through UPnP IGD. It provides bilingual explanations, a heuristic exposure score, changes since the previous scan, and guides for manual mitigation.

## Changes since 2.0.1

- Serves translation files through a startup allow-list, so request paths never become filesystem paths.
- Updates pinned GitHub Actions and keeps the release build, hash manifest, and provenance checks.
- Publishes the current source and documentation from a clean repository history.

## Download and run

**Windows x64:** Download `portscope-windows-x64.exe` and `SHA256SUMS.txt` below. Compare the executable's SHA-256 digest with the manifest, then double-click the executable. A terminal opens and the dashboard appears in your browser. No installer or Python is required.

```powershell
Get-FileHash .\portscope-windows-x64.exe -Algorithm SHA256
.\portscope-windows-x64.exe
```

**Linux x64:** Download `portscope-linux-x64.tar.gz` and `SHA256SUMS.txt`. Compare the digest, extract the archive, and run the executable:

```bash
sha256sum portscope-linux-x64.tar.gz
tar -xzf portscope-linux-x64.tar.gz
./portscope
```

Keep the terminal open while using PortScope. Stop it with the dashboard's **Quit / Salir** button or `Ctrl+C`. Use `--no-upnp` to skip local-network discovery. Run `--help` for the full command-line reference. Start as a normal user; elevated privileges are optional and can reveal additional process owners.

GitHub Actions publishes a signed build attestation for each executable or archive. With GitHub CLI installed, verify the file you downloaded:

```bash
gh attestation verify ./portscope-linux-x64.tar.gz --repo IvelianK/Port-Scope
```

For Windows, replace the path with `.\portscope-windows-x64.exe`. The Windows executable is unsigned and may show an unknown publisher warning; do not disable Windows security protections. The Linux build uses Ubuntu 22.04 system libraries. See the [English README](https://github.com/IvelianK/Port-Scope/blob/v2.0.2/README.md) or [guía en español](https://github.com/IvelianK/Port-Scope/blob/v2.0.2/README_es.md) for source-based installation and limitations.

## What this release changes

- Replaces the original Tkinter prototype with a local browser dashboard and command-line output
- Enumerates local listeners and owning processes without third-party Python runtime packages
- Queries UPnP Internet Gateway Devices for reported port mappings
- Explains 70 services in English and Spanish with relevant MITRE ATT&CK references
- Adds a scan diff, heuristic score, JSON export, and exit codes for automation
- Protects the local dashboard with a per-run token, strict host validation, and a restrictive content policy
- Enforces the total UPnP request deadline even when a device sends HTTP headers one byte at a time

A UPnP forward is **potential** exposure, not proof that a host is reachable from the public Internet. PortScope cannot detect manual router forwards or inspect firewall rules per port. It does not run the mitigation commands it suggests.

## Instrucciones en español

**Windows x64:** descarga `portscope-windows-x64.exe` y `SHA256SUMS.txt`, compara el hash con `Get-FileHash` y abre el ejecutable. **Linux x64:** descarga `portscope-linux-x64.tar.gz`, compara el hash con `sha256sum`, extrae el archivo con `tar -xzf` y ejecuta `./portscope`. No hace falta instalar Python para usar estos binarios. Consulta la [guía completa en español](https://github.com/IvelianK/Port-Scope/blob/v2.0.2/README_es.md) y la [política de seguridad](https://github.com/IvelianK/Port-Scope/blob/v2.0.2/SECURITY.md).
