"""Run a full scan: the only module that touches the OS, the network and the history file."""

from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import sockets, upnp
from .analysis import build_report

HISTORY = Path.home() / ".portscope" / "last_scan.json"


def _owned(directory: Path) -> bool:
    """POSIX: refuse a history dir owned by someone else (e.g. HOME kept under sudo)."""
    return not hasattr(os, "geteuid") or directory.stat().st_uid == os.geteuid()


def load_history(history: Path) -> dict | None:
    try:
        if not _owned(history.parent):
            return None
        previous = json.loads(history.read_text("utf-8"))
        findings = previous.get("findings") if isinstance(previous, dict) else None
        valid = isinstance(findings, list) and all(isinstance(f, dict) and {"id", "severity"} <= f.keys() for f in findings)
        return previous if valid else None
    except (OSError, ValueError):
        return None


def save_history(history: Path, report: dict) -> None:
    # Only what the next diff needs: no public IP, LAN inventory or process names at rest.
    minimal = {"format": 1, "upnp": None if report["upnp"] is None else {},
               "findings": [{"id": f["id"], "severity": f["severity"]} for f in report["findings"]]}
    tmp = None
    try:
        history.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not _owned(history.parent):
            raise PermissionError(f"{history.parent} is not owned by this user")
        if os.name != "nt":
            os.chmod(history.parent, 0o700)
        fd, tmp = tempfile.mkstemp(dir=history.parent, prefix=".last_scan.")  # 0600, never follows a symlink
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(minimal, f)
        os.replace(tmp, history)  # atomic; replaces a planted symlink instead of writing through it
    except OSError as e:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        print(f"portscope: scan history not saved: {e}", file=sys.stderr)


def run_scan(with_upnp: bool = True, history: Path | None = HISTORY) -> dict:
    """Sockets + firewall (+ UPnP). Diffs against and updates `history` unless it is None."""
    previous = load_history(history) if history else None
    # UPnP is network-bound (SSDP wait + HTTP); run it alongside the local enumeration.
    with ThreadPoolExecutor(max_workers=2) as pool:
        upnp_job = pool.submit(upnp.scan) if with_upnp else None
        firewall_job = pool.submit(sockets.firewall_status)
        listeners = sockets.list_listeners()
        report = build_report(listeners, upnp_job.result() if upnp_job else None, firewall_job.result(),
                              platform.system(), previous)
    if history:
        save_history(history, report)
    return report
