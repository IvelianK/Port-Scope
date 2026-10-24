"""Turn raw listeners + UPnP data into scored findings. Pure: no I/O besides loading the port database."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

from . import __version__
from .sockets import Firewall, Listener
from .upnp import Mapping

LEVELS = ("info", "low", "medium", "high", "critical")
PENALTY = {"info": 0, "low": 1, "medium": 3, "high": 8, "critical": 25}
# Per-level ceiling so twenty low findings cannot outweigh one critical.
PENALTY_CAP = {"info": 0, "low": 5, "medium": 20, "high": 40, "critical": 100}
EPHEMERAL_START = 49152
PORTS: dict[str, dict] = json.loads((Path(__file__).parent / "data" / "ports.json").read_text("utf-8"))


class ForwardedMapping(Mapping):
    gateway: str


class Finding(TypedDict):
    id: str
    port: int
    proto: str
    service: str
    base_risk: str
    severity: str
    exposure: str  # local | network | internet
    addresses: list[str]
    pid: int | None
    process: str | None
    attack: list[str]
    text: dict[str, dict[str, str] | None]
    upnp: list[ForwardedMapping]
    host: str | None  # None = this machine, else the LAN device a UPnP mapping points to


def port_info(port: int, proto: str) -> dict:
    if str(port) in PORTS:
        return PORTS[str(port)]
    if port >= EPHEMERAL_START:
        # Unknown high UDP ports are almost always client sockets (DNS, mDNS, QUIC replies).
        return {"service": "Dynamic / ephemeral", "risk": "info" if proto == "udp" else "low", "attack": []}
    return {"service": "Unknown", "risk": "low", "attack": []}


def is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    # ::ffff:127.0.0.1 is not is_loopback before Python 3.13.
    return (getattr(ip, "ipv4_mapped", None) or ip).is_loopback


def severity(base: str, exposure: str) -> str:
    match exposure:
        case "local":
            return "info"
        case "internet":
            # At least medium, then one level up, capped at critical.
            return LEVELS[min(len(LEVELS) - 1, max(LEVELS.index(base), LEVELS.index("medium")) + 1)]
        case _:
            return base


def _finding(id: str, port: int, proto: str, exposure: str, sev: str | None, addresses: list[str],
             upnp: list[ForwardedMapping], host: str | None, pid: int | None = None, process: str | None = None) -> Finding:
    info = port_info(port, proto)
    return {
        "id": id, "port": port, "proto": proto, "service": info["service"], "base_risk": info["risk"],
        "severity": sev or severity(info["risk"], exposure), "exposure": exposure, "addresses": addresses,
        "pid": pid, "process": process, "attack": info["attack"],
        "text": {"en": info.get("en"), "es": info.get("es")}, "upnp": upnp, "host": host,
    }


def assess(listeners: list[Listener], upnp: dict | None) -> list[Finding]:
    """One finding per (proto, port) on this host, plus one per UPnP mapping to another host."""
    gateways = (upnp or {}).get("gateways", [])
    local_ips = {g["local_ip"] for g in gateways}
    forwarded: dict[tuple[str, int], list[ForwardedMapping]] = {}
    other: list[ForwardedMapping] = []
    for gw in gateways:
        for m in gw["mappings"]:
            fm: ForwardedMapping = {**m, "gateway": gw["ip"]}
            if m["internal_client"] in local_ips and m["enabled"]:
                forwarded.setdefault((m["protocol"], m["internal_port"]), []).append(fm)
            else:
                other.append(fm)

    grouped: dict[tuple[str, int], list[Listener]] = {}
    for l in listeners:
        grouped.setdefault((l.proto, l.port), []).append(l)

    findings = []
    unreachable: list[ForwardedMapping] = []
    for (proto, port), group in grouped.items():
        # A forward only exposes the service if it listens where the router sends traffic.
        reaching = []
        for m in forwarded.get((proto, port), []):
            if any(l.address in ("0.0.0.0", "::", m["internal_client"]) for l in group):
                reaching.append(m)
            else:
                unreachable.append(m)
        if reaching:
            exposure = "internet"
        elif all(is_loopback(l.address) for l in group):
            exposure = "local"
        else:
            exposure = "network"
        owner = next((l for l in group if l.process), group[0])
        findings.append(_finding(f"{proto}/{port}", port, proto, exposure, None, sorted({l.address for l in group}),
                                 reaching, None, owner.pid, owner.process))

    # Mappings to this host with nothing listening there are still holes in the router.
    dangling = [m for key, ms in forwarded.items() if key not in grouped for m in ms] + unreachable
    for m in other + dangling:
        findings.append(_finding(f"upnp/{m['gateway']}/{m['protocol']}/{m['external_port']}/{m['internal_client']}", m["internal_port"],
                                 m["protocol"], "internet", None if m["enabled"] else "low", [m["internal_client"]],
                                 [m], m["internal_client"]))

    findings.sort(key=lambda f: (-LEVELS.index(f["severity"]), f["port"], f["proto"]))
    return findings


def score(findings: list[Finding], upnp: dict | None, firewall: Firewall) -> dict:
    # ponytail: firewall rules are not parsed per port; with the firewall on, assume half of
    # what listens on the network is filtered. Parse rules (netsh/nft) if this proves too coarse.
    state = firewall["state"]
    per_level = dict.fromkeys(LEVELS, 0.0)
    for f in findings:
        weight = 0.5 if state == "on" and f["exposure"] == "network" else 1.0
        per_level[f["severity"]] += PENALTY[f["severity"]] * weight
    penalty = sum(min(per_level[lvl], PENALTY_CAP[lvl]) for lvl in LEVELS)
    if upnp and upnp["gateways"]:
        penalty += 5  # UPnP IGD lets any LAN program open the router: attack surface on its own.
    penalty += {"off": 15, "partial": 5}.get(state, 0)
    value = max(0, round(100 - penalty))
    grade = next(g for g, floor in (("A", 90), ("B", 75), ("C", 55), ("D", 35), ("F", 0)) if value >= floor)
    counts = {lvl: sum(f["severity"] == lvl for f in findings) for lvl in LEVELS}
    return {"value": value, "grade": grade, "counts": counts}


def diff(current: list[Finding], previous: list[Finding]) -> dict[str, list[str]]:
    """Finding ids that appeared / disappeared since the previous scan (info-level churn ignored)."""
    now, before = ({f["id"] for f in fs if f["severity"] != "info"} for fs in (current, previous))
    return {"new": sorted(now - before), "gone": sorted(before - now)}


def build_report(listeners: list[Listener], upnp: dict | None, firewall: Firewall, system: str,
                 previous: dict | None) -> dict:
    findings = assess(listeners, upnp)
    # Only compare like with like: a scan without UPnP would report every router mapping as "gone".
    comparable = previous and (previous.get("upnp") is None) == (upnp is None)
    return {
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "platform": system,
        "firewall": firewall,
        "upnp": upnp,
        "findings": findings,
        "score": score(findings, upnp, firewall),
        "diff": diff(findings, previous["findings"]) if comparable else None,
    }
