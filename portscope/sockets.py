"""Enumerate listening sockets on the local machine, with the owning process.

No third-party dependencies: Windows uses `netstat -ano` + `tasklist`,
Linux reads /proc directly. Parsers are pure functions so they can be tested
with captured output.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from typing import TypedDict

from . import clean

_TIMEOUT = 15
# Hide the console window that subprocess would flash on Windows (frozen .exe).
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
# Absolute paths: CreateProcess looks in the launching .exe's folder (often Downloads) before PATH,
# so a planted tasklist.exe there would run with our privileges.
_SYSTEM32 = os.path.join(os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows", "System32")
TASKLIST = os.path.join(_SYSTEM32, "tasklist.exe")
NETSTAT = os.path.join(_SYSTEM32, "netstat.exe")
POWERSHELL = os.path.join(_SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")


@dataclass(frozen=True)
class Listener:
    proto: str  # "tcp" | "udp"
    address: str
    port: int
    pid: int | None = None
    process: str | None = None


def _run(cmd: list[str]) -> str:
    out = subprocess.run(
        cmd, capture_output=True, timeout=_TIMEOUT, check=False, creationflags=_NO_WINDOW
    ).stdout
    # Windows console tools emit the OEM code page (the "oem" codec exists only on Windows).
    return out.decode("oem" if os.name == "nt" else "utf-8", errors="replace")


def _split_endpoint(endpoint: str) -> tuple[str, int] | None:
    """'0.0.0.0:135' / '[::]:445' / '[fe80::1%12]:1900' -> (address, port)."""
    host, sep, port = endpoint.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.strip("[]").split("%", 1)[0]
    return host, int(port)


def parse_netstat_windows(text: str) -> list[tuple[str, str, int, int | None]]:
    """Parse `netstat -ano`. Locale-independent: a TCP listener is recognised by its
    wildcard remote endpoint, not by the (translated) state column."""
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0].lower()
        local = _split_endpoint(parts[1])
        if local is None:
            continue
        remote = parts[2]
        if proto == "tcp" and remote not in ("0.0.0.0:0", "[::]:0"):
            continue
        if proto == "udp" and remote != "*:*":
            continue
        pid = int(parts[-1]) if parts[-1].isdigit() else None
        rows.append((proto, local[0], local[1], pid))
    return rows


def parse_tasklist(text: str) -> dict[int, str]:
    names = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 2 and row[1].isdigit():
            names[int(row[1])] = clean(row[0])
    return names


def _hex_to_ip(hex_addr: str) -> str:
    raw = bytes.fromhex(hex_addr)
    # /proc stores the address as host-order 32-bit words.
    words = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.ip_address(words))


def parse_proc_net(text: str, proto: str) -> list[tuple[str, int, int]]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6} -> [(address, port, inode)].
    TCP keeps state 0A (LISTEN); UDP keeps unconnected sockets (07)."""
    wanted = "0A" if proto == "tcp" else "07"
    rows = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10 or parts[3] != wanted:
            continue
        addr, port = parts[1].split(":")
        rows.append((_hex_to_ip(addr), int(port, 16), int(parts[9])))
    return rows


def _linux_inode_owners() -> dict[int, tuple[int, str]]:
    """Map socket inode -> (pid, comm). Other users' processes need root; they stay unknown."""
    owners = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
            # comm is attacker-chosen bytes (prctl PR_SET_NAME): never assume UTF-8 or printable.
            with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as f:
                comm = clean(f.read())
        except OSError:
            continue
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", target)
            if m:
                owners[int(m.group(1))] = (int(pid), comm)
    return owners


def _listeners_windows() -> list[Listener]:
    names = parse_tasklist(_run([TASKLIST, "/fo", "csv", "/nh"]))
    return [
        Listener(proto, addr, port, pid, names.get(pid) if pid is not None else None)
        for proto, addr, port, pid in parse_netstat_windows(_run([NETSTAT, "-ano"]))
    ]


def _listeners_linux() -> list[Listener]:
    owners = _linux_inode_owners()
    result = []
    for proto in ("tcp", "udp"):
        for suffix in ("", "6"):
            try:
                with open(f"/proc/net/{proto}{suffix}", encoding="ascii") as f:
                    rows = parse_proc_net(f.read(), proto)
            except OSError:
                continue
            for addr, port, inode in rows:
                pid, comm = owners.get(inode, (None, None))
                result.append(Listener(proto, addr, port, pid, comm))
    return result


def list_listeners() -> list[Listener]:
    system = platform.system()
    if system == "Windows":
        listeners = _listeners_windows()
    elif system == "Linux":
        listeners = _listeners_linux()
    else:
        raise NotImplementedError(f"Socket enumeration is not supported on {system}")
    return sorted(set(listeners), key=lambda l: (l.port, l.proto, l.address))


class Firewall(TypedDict):
    state: str  # on | off | partial | unknown
    detail: str


def _firewall_windows() -> Firewall:
    out = _run([
        POWERSHELL, "-NoProfile", "-Command",
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
    ])
    profiles = json.loads(out)
    enabled = {p["Name"]: p["Enabled"] in (1, True) for p in (profiles if isinstance(profiles, list) else [profiles])}
    match sum(enabled.values()):
        case 0:
            state = "off"
        case n if n == len(enabled):
            state = "on"
        case _:
            state = "partial"
    return {"state": state, "detail": ", ".join(f"{name}: {'on' if on else 'off'}" for name, on in enabled.items())}


def _firewall_linux() -> Firewall:
    # ponytail: only ufw/firewalld; raw nftables/iptables rulesets need root to inspect.
    # ufw.service is a oneshot that stays "active" even when ufw is disabled, so read its config instead.
    try:
        with open("/etc/ufw/ufw.conf", encoding="utf-8", errors="replace") as f:
            if re.search(r"^ENABLED=yes", f.read(), re.MULTILINE):
                return {"state": "on", "detail": "ufw enabled"}
    except OSError:
        pass
    try:
        if subprocess.run(["firewall-cmd", "--state"], capture_output=True, timeout=_TIMEOUT, check=False).returncode == 0:
            return {"state": "on", "detail": "firewalld running"}
    except OSError:
        pass
    return {"state": "unknown", "detail": "neither ufw nor firewalld is enabled (nftables/iptables not inspected)"}


def firewall_status() -> Firewall:
    """Best-effort host firewall state."""
    system = platform.system()
    try:
        match system:
            case "Windows":
                return _firewall_windows()
            case "Linux":
                return _firewall_linux()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        return {"state": "unknown", "detail": clean(str(e))}
    return {"state": "unknown", "detail": system}
