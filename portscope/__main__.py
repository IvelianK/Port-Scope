"""Entry point: `portscope` opens the dashboard; `portscope --cli` prints a report."""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser

from . import __version__
from .analysis import LEVELS
from .scan import HISTORY, run_scan


def print_report(report: dict) -> None:
    s = report["score"]
    fw = report["firewall"]
    print(f"PortScope {report['version']}  |  score {s['value']}/100 (grade {s['grade']})  |  firewall: {fw['state']} ({fw['detail']})")
    for gw in (report["upnp"] or {}).get("gateways", []):
        nat = "  [double NAT / CGNAT]" if gw["double_nat"] else ""
        print(f"UPnP gateway {gw['ip']} {gw['name']!r}: external IP {gw['external_ip'] or '?'}, {len(gw['mappings'])} port mapping(s){nat}")
        if gw["error"]:
            print(f"  WARNING: {gw['error']}")
    if report["diff"] and (report["diff"]["new"] or report["diff"]["gone"]):
        print(f"Since last scan: new {report['diff']['new'] or '-'}, gone {report['diff']['gone'] or '-'}")
    print()
    print(f"{'SEVERITY':<9} {'PORT':<11} {'EXPOSURE':<9} {'SERVICE':<28} PROCESS / HOST")
    for f in report["findings"]:
        who = f"-> {f['host']} (UPnP)" if f["host"] else f"{f['process'] or '?'} ({f['pid']})"
        print(f"{f['severity'].upper():<9} {f['proto'] + '/' + str(f['port']):<11} {f['exposure']:<9} {f['service'][:28]:<28} {who}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="portscope", description="See which ports your machine and router expose, and how to close them.")
    p.add_argument("--cli", action="store_true", help="print a text report instead of opening the dashboard")
    p.add_argument("--json", action="store_true", help="print the full report as JSON")
    p.add_argument("--no-upnp", action="store_true", help="skip UPnP discovery on the LAN")
    p.add_argument("--fail-on", choices=LEVELS[1:], help="exit with code 2 if any finding is at or above this severity")
    p.add_argument("--no-history", action="store_true", help=f"do not read or write {HISTORY} (no diff)")
    p.add_argument("--port", type=int, default=0, help="dashboard port on 127.0.0.1 (default: random free port)")
    p.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    history = None if args.no_history else HISTORY
    # Redirected stdout on Windows is cp1252: never crash on a process name it cannot encode.
    sys.stdout.reconfigure(errors="replace")

    if args.cli or args.json or args.fail_on:
        try:
            report = run_scan(not args.no_upnp, history)
        except NotImplementedError as e:
            print(f"portscope: {e}", file=sys.stderr)
            return 1
        if args.json:
            json.dump(report, sys.stdout, indent=2)
            print()
        else:
            print_report(report)
        if args.fail_on:
            floor = LEVELS.index(args.fail_on)
            return 2 if any(LEVELS.index(f["severity"]) >= floor for f in report["findings"]) else 0
        return 0

    from .server import App

    try:
        app = App(args.port, history)
    except OSError as e:
        print(f"portscope: cannot listen on 127.0.0.1:{args.port} ({e.strerror}). Wait a minute or pick another --port.", file=sys.stderr)
        return 1
    print(f"PortScope {__version__} running at {app.url}\nPress Ctrl+C (or 'Quit' in the dashboard) to stop.", flush=True)
    # Under sudo the browser would run as root (or fail to reach the user's display): let the user open the link.
    as_root = getattr(os, "geteuid", lambda: 1)() == 0
    if not args.no_browser and not as_root:
        webbrowser.open(app.launch_url)
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
