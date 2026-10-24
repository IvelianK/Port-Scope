"""UPnP discovery and Internet Gateway Device (IGD) port-mapping enumeration.

Everything here talks to devices on the LAN, so every response is untrusted:
- description/control URLs must point back at the IP that answered and at a
  private or link-local address. The responder IP is the UDP source address,
  which a LAN attacker can spoof, so this limits SSRF to blind GETs/POSTs at
  private addresses, never at the Internet or loopback;
- no proxies, no redirects, bounded response size, a total time budget;
- text fields are sanitised by `clean` and protocols are allow-listed, because
  they end up in the UI, the terminal and copy-paste firewall commands.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import TypedDict
from urllib.parse import urljoin, urlsplit

from . import clean

SSDP_ADDR = ("239.255.255.250", 1900)
SEARCH_TARGETS = (
    "upnp:rootdevice",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
)
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
PROTOCOLS = ("tcp", "udp")
MAX_BODY = 512 * 1024
MAX_MAPPINGS = 512
MAX_LOCATIONS_PER_IP = 8  # a spoofing flood cannot crowd out the real router, which has its own IP
HTTP_TIMEOUT = 4.0  # per socket operation; consumer routers routinely take 1-3 s per UPnP request
BUDGET = 30.0  # whole UPnP phase; a tarpit device cannot hold the scan hostage beyond this
CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Errors a hostile or broken LAN device can provoke; never allowed to abort the whole scan.
NET_ERRORS = (OSError, ValueError, ET.ParseError, http.client.HTTPException)


class Mapping(TypedDict):
    external_port: int
    protocol: str
    internal_client: str
    internal_port: int
    enabled: bool
    description: str
    remote_host: str
    lease_seconds: int


class Gateway(TypedDict):
    ip: str
    name: str
    local_ip: str
    external_ip: str
    double_nat: bool
    mappings: list[Mapping]
    error: str


class UnsafeURL(ValueError):
    pass


def checked_url(url: str, device_ip: str) -> tuple[str, int, str]:
    """Return (host, port, path) if url is plain http to device_ip on a private network."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise UnsafeURL(f"not http: {url!r}")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        raise UnsafeURL(f"host is not an IP literal: {url!r}") from None
    if str(ip) != device_ip:
        raise UnsafeURL(f"{url!r} does not point at responder {device_ip}")
    if not (ip.is_private or ip.is_link_local) or ip.is_loopback:
        raise UnsafeURL(f"{ip} is not a LAN address")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return str(ip), parts.port or 80, path


def http_request(url: str, device_ip: str, deadline: float, body: bytes | None = None,
                 headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    host, port, path = checked_url(url, device_ip)
    remaining = deadline - time.monotonic()
    if remaining <= 0:  # also never pass timeout=0, which would make the socket non-blocking
        raise TimeoutError("UPnP time budget exhausted")
    conn = http.client.HTTPConnection(host, port, timeout=min(HTTP_TIMEOUT, remaining))
    watchdog: threading.Timer | None = None
    try:
        conn.request("POST" if body is not None else "GET", path, body=body, headers=headers or {})
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("UPnP time budget exhausted")
        sock = conn.sock

        def abort_at_deadline() -> None:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(remaining, abort_at_deadline)
        watchdog.daemon = True
        watchdog.start()
        resp = conn.getresponse()
        data = b""
        # Read in chunks against a total deadline: a per-recv timeout alone lets a device drip 1 byte every few seconds.
        while chunk := resp.read1(64 * 1024):
            data += chunk
            if len(data) > MAX_BODY:
                raise ValueError(f"response from {host} exceeds {MAX_BODY} bytes")
            if time.monotonic() > deadline:
                raise TimeoutError(f"UPnP time budget exhausted while reading from {host}")
        if time.monotonic() > deadline:
            raise TimeoutError(f"UPnP time budget exhausted while reading from {host}")
        return resp.status, data
    finally:
        if watchdog is not None:
            watchdog.cancel()
        conn.close()


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    headers = {}
    for line in data.decode("utf-8", errors="replace").split("\r\n")[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def local_ip_towards(ip: str) -> str:
    """The address this host uses to reach ip (UDP connect sends no packet)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((ip, 9))
        return s.getsockname()[0]


def ssdp_search(timeout: float = 2.0) -> dict[str, dict[str, str]]:
    """M-SEARCH the LAN. Returns {raw location: {ip, server}} for each responder."""
    found: dict[str, dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        # Multicast otherwise leaves through whatever interface the OS prefers (often a
        # Hyper-V/WSL/Docker virtual switch). Use the default-route interface instead.
        try:
            lan_ip = local_ip_towards("192.0.2.1")  # TEST-NET-1: routed via default gateway, never sent
            sock.bind((lan_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(lan_ip))
        except OSError:
            pass  # no default route: fall back to the OS choice
        sock.settimeout(0.3)
        for st in SEARCH_TARGETS:
            msg = f'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: {st}\r\n\r\n'
            sock.sendto(msg.encode(), SSDP_ADDR)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            headers = parse_ssdp_response(data)
            location = headers.get("location")
            per_ip = sum(r["ip"] == ip for r in found.values())
            if location and location not in found and per_ip < MAX_LOCATIONS_PER_IP:
                found[location] = {"ip": ip, "server": clean(headers.get("server"))}
    finally:
        sock.close()
    return found


def parse_xml(xml: bytes) -> ET.Element:
    """UPnP never needs a DTD; refusing one rules out entity expansion on old expat builds.
    NUL bytes catch the UTF-16 spelling of the same thing."""
    if b"<!DOCTYPE" in xml or b"\x00" in xml:
        raise ValueError("XML with DTD or NUL bytes rejected")
    return ET.fromstring(xml)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(elem: ET.Element | None, name: str, limit: int = 200) -> str:
    if elem is None:
        return ""
    for child in elem:
        if _local(child.tag) == name:
            return clean(child.text, limit)
    return ""


def parse_description(xml: bytes) -> dict:
    """Parse a UPnP device description: identity + WAN connection services."""
    root = parse_xml(xml)
    device = next((e for e in root.iter() if _local(e.tag) == "device"), None)
    return {
        "friendly_name": _text(device, "friendlyName"),
        "manufacturer": _text(device, "manufacturer"),
        "model": _text(device, "modelName"),
        "device_type": _text(device, "deviceType"),
        "url_base": _text(root, "URLBase", 2048),
        "wan_services": [
            {"type": _text(svc, "serviceType"), "control_url": _text(svc, "controlURL", 2048)}
            for svc in root.iter()
            if _local(svc.tag) == "service" and any(w in _text(svc, "serviceType") for w in WAN_SERVICES)
        ],
    }


def soap_envelope(service_type: str, action: str, args: dict[str, int]) -> bytes:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service_type}">{body}</u:{action}>'
        "</s:Body></s:Envelope>"
    ).encode()


def parse_soap_response(xml: bytes, action: str) -> dict[str, str]:
    root = parse_xml(xml)
    resp = next((e for e in root.iter() if _local(e.tag) == f"{action}Response"), None)
    if resp is None:
        return {}
    return {_local(child.tag): clean(child.text) for child in resp}


def soap_call(control_url: str, device_ip: str, service_type: str, action: str, deadline: float,
              **args: int) -> dict[str, str] | None:
    """Invoke a SOAP action. None on a UPnP fault (e.g. 713 = index out of range)."""
    status, data = http_request(
        control_url,
        device_ip,
        deadline,
        body=soap_envelope(service_type, action, args),
        headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service_type}#{action}"'},
    )
    return parse_soap_response(data, action) if status == 200 else None


def parse_mapping(entry: dict[str, str]) -> Mapping:
    """Validate one GetGenericPortMappingEntry reply. Raises ValueError on anything off-spec."""
    protocol = entry.get("NewProtocol", "").lower()
    if protocol not in PROTOCOLS:
        raise ValueError(f"invalid protocol in port mapping: {protocol[:20]!r}")
    client = str(ipaddress.ip_address(entry.get("NewInternalClient", "")))
    ports = int(entry.get("NewExternalPort") or 0), int(entry.get("NewInternalPort") or 0)
    if not all(0 < p < 65536 for p in ports):
        raise ValueError(f"invalid port in port mapping: {ports}")
    return {
        "external_port": ports[0],
        "protocol": protocol,
        "internal_client": client,
        "internal_port": ports[1],
        "enabled": entry.get("NewEnabled", "1").lower() in ("1", "true"),
        "description": entry.get("NewPortMappingDescription", ""),
        "remote_host": entry.get("NewRemoteHost", ""),
        "lease_seconds": int(entry.get("NewLeaseDuration") or 0),
    }


def port_mappings(control_url: str, device_ip: str, service_type: str, deadline: float):
    """Yield mappings one by one so a failure halfway still keeps what was read."""
    for index in range(MAX_MAPPINGS):
        if time.monotonic() > deadline:
            raise TimeoutError("UPnP time budget exhausted")
        entry = soap_call(control_url, device_ip, service_type, "GetGenericPortMappingEntry", deadline,
                          NewPortMappingIndex=index)
        if not entry:
            return
        yield parse_mapping(entry)


def _describe(location: str, responder: dict[str, str], deadline: float) -> dict:
    device = {"ip": responder["ip"], "server": responder["server"], "location": location, "igd": False}
    try:
        status, xml = http_request(location, responder["ip"], deadline)
        if status != 200:
            return device | {"error": f"HTTP {status}"}
        device |= parse_description(xml)
    except NET_ERRORS as e:
        return device | {"error": clean(str(e))}
    device["igd"] = bool(device["wan_services"])
    return device


def _inspect_gateway(device: dict, deadline: float) -> Gateway:
    ip = device["ip"]
    gateway: Gateway = {"ip": ip, "name": device["friendly_name"] or device["model"], "local_ip": local_ip_towards(ip),
                        "external_ip": "", "double_nat": False, "mappings": [], "error": ""}
    # Routers may list an idle WANIPConnection before the live WANPPPConnection: query every one.
    for svc in device["wan_services"]:
        control = urljoin(device["url_base"] or device["location"], svc["control_url"])
        try:
            ext = soap_call(control, ip, svc["type"], "GetExternalIPAddress", deadline) or {}
            ext_ip = ipaddress.ip_address(ext.get("NewExternalIPAddress", ""))
            gateway["external_ip"] = gateway["external_ip"] or str(ext_ip)
            gateway["double_nat"] = gateway["double_nat"] or ext_ip.is_private or ext_ip in CGNAT
        except NET_ERRORS:
            pass  # cosmetic; the mappings below are what matters
        try:
            gateway["mappings"].extend(port_mappings(control, ip, svc["type"], deadline))
        except NET_ERRORS as e:
            # Never report a partial list as complete: "0 mappings" must mean zero.
            gateway["error"] = f"mapping list incomplete after {len(gateway['mappings'])} entries: {clean(str(e))}"
    return gateway


def scan(timeout: float = 2.0) -> dict:
    """Discover UPnP devices and read the port mappings of every IGD found."""
    result: dict = {"devices": [], "gateways": [], "errors": []}
    try:
        responders = ssdp_search(timeout)
    except OSError as e:
        result["errors"].append(f"SSDP: {clean(str(e))}")
        return result
    deadline = time.monotonic() + BUDGET
    with ThreadPoolExecutor(max_workers=8) as pool:
        devices = list(pool.map(lambda item: _describe(*item, deadline), responders.items()))
    # One physical device usually answers with several locations; keep the richest entry per IP.
    by_ip: dict[str, dict] = {}
    for d in devices:
        if d["ip"] not in by_ip or (d["igd"] and not by_ip[d["ip"]]["igd"]):
            by_ip[d["ip"]] = d
    result["devices"] = sorted(by_ip.values(), key=lambda d: ipaddress.ip_address(d["ip"]))
    for device in result["devices"]:
        if device["igd"]:
            try:
                result["gateways"].append(_inspect_gateway(device, deadline))
            except NET_ERRORS as e:
                result["errors"].append(f"{device['ip']}: {clean(str(e))}")
    for device in result["devices"]:
        device.pop("wan_services", None)
        device.pop("url_base", None)
        device["location"] = clean(device["location"], 300)
    return result
