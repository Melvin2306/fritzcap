#!/usr/bin/env python3
"""
fritzcap — long, unattended packet captures from a FRITZ!Box, driven from the
command line instead of the web UI.

FRITZ!OS ships a built-in packet sniffer ("Paketmitschnitt", at
http://fritz.box/html/capture.html) that streams a .pcap of any interface to your
browser. It is great — until you need a long capture: the web session logs out
after a while and the capture dies with it, and a dropped stream loses everything.

fritzcap talks to the same capture endpoint directly. It logs in with AVM's
PBKDF2 challenge, starts the capture on the interface(s) you choose, streams the
pcap straight to disk, and if the stream ever drops it logs back in and starts a
fresh numbered segment — so an overnight or multi-day capture just works. Every
segment is a complete, openable pcap; merge them with `mergecap` afterwards.

  * Works on any FRITZ!Box with the built-in capture feature (FRITZ!OS serves the
    interface list from either data.lua or the older capture.html; both are tried).
  * Capture one named interface, or --all of them in parallel.
  * The password is read from the FRITZBOX_PASSWORD env var or prompted; it is
    never written to disk. The tool only ever talks to your router.

Usage:
  # list the capture interfaces your box exposes, then exit
  python3 -I fritzcap.py --host fritz.box --list

  # capture one interface until you press Ctrl-C
  FRITZBOX_PASSWORD=... python3 -I fritzcap.py --iface guest5

  # capture every interface in parallel for 8 hours
  FRITZBOX_PASSWORD=... python3 -I fritzcap.py --all --hours 8

  # merge the segments of a run into one pcap
  mergecap -F pcap -w capture.pcap out/capture-*/<iface>/seg*.pcap

Requires only Python 3 (standard library). tshark/mergecap are optional, for
working with the result. MIT licensed.
"""
import argparse
import getpass
import hashlib
import os
import re
import signal
import sys
import threading
import time
import urllib.parse
import urllib.request

STOP = False


def http(url, data=None, timeout=30):
    req = urllib.request.Request(url, data=data)
    return urllib.request.urlopen(req, timeout=timeout)


def login(host, user, password):
    """AVM login_sid.lua v2 (PBKDF2 challenge-response). Returns (sid, user)."""
    base = f"http://{host}"
    xml = http(f"{base}/login_sid.lua?version=2").read().decode()
    m = re.search(r"<Challenge>(.+?)</Challenge>", xml)
    if not m:
        raise SystemExit("no challenge in login response — is --host a FRITZ!Box?")
    ch = m.group(1)
    if not ch.startswith("2$"):
        # Very old firmware uses the MD5 challenge scheme; this tool targets the
        # modern PBKDF2 one that every current FRITZ!OS serves.
        raise SystemExit("router returned a legacy challenge format this tool does not support")
    _, it1, s1, it2, s2 = ch.split("$")
    h1 = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(s1), int(it1))
    h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(s2), int(it2))
    response = f"{s2}${h2.hex()}"
    if not user:
        m = (re.search(r'<User[^>]*last="1"[^>]*>([^<]+)</User>', xml)
             or re.search(r"<User[^>]*>([^<]+)</User>", xml))
        user = m.group(1) if m else ""
    body = urllib.parse.urlencode({"username": user, "response": response}).encode()
    out = http(f"{base}/login_sid.lua?version=2", data=body).read().decode()
    sid = re.search(r"<SID>(.+?)</SID>", out).group(1)
    if sid == "0" * 16:
        raise SystemExit(f"login failed — wrong username/password? (user tried: {user!r})")
    return sid, user


def list_interfaces(host, sid, dump_dir=None):
    """Return [(iface, minor, type), ...] of capture interfaces the box exposes.

    FRITZ!OS encodes them in the capture UI as a Stop-button value
    "type;minor;iface" (e.g. "1;-1;guest5"). Newer firmware serves that UI from
    data.lua; older firmware from html/capture.html. Both are tried."""
    html = ""
    for page in ("cap", "capture"):
        for lang in ("en", "de"):
            try:
                body = urllib.parse.urlencode(
                    {"xhr": "1", "sid": sid, "lang": lang, "page": page, "no_sidrenew": ""}
                ).encode()
                html = http(f"http://{host}/data.lua", data=body).read().decode("utf-8", "replace")
                if len(html) > 500 and ("iface" in html.lower() or "ghz" in html.lower() or "capture" in html.lower()):
                    break
            except Exception:
                pass
        if len(html) > 500:
            break
    if len(html) < 500:  # older firmware
        try:
            html = http(f"http://{host}/html/capture.html?sid={sid}").read().decode("utf-8", "replace")
        except Exception:
            pass
    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)
        with open(os.path.join(dump_dir, "capture_page.raw"), "w") as f:
            f.write(html)
    out, seen = [], set()
    for typ, minor, iface in re.findall(r'value="(\d+);(-?\d+);([^"]+)"', html):
        if iface in ("stopall",) or iface in seen or " " in iface or "(" in iface:
            continue  # skip UI labels / the stop-all control; keep clean tokens
        seen.add(iface)
        out.append((iface, minor, typ))
    return out


def start_url(host, iface, minor, typ, sid):
    return (f"http://{host}/cgi-bin/capture_notimeout?iface={urllib.parse.quote(iface)}"
            f"&minor={minor}&type={typ}&capture=Start&sid={sid}")


def capture_segment(host, sid, triple, path, deadline, label):
    """Stream to `path` until the deadline, Ctrl-C, or the stream closes.
    An idle interface produces no packets, so a read timeout is normal, not an
    error — keep waiting and re-check the deadline / STOP flag each time."""
    iface, minor, typ = triple
    resp = http(start_url(host, iface, minor, typ, sid), timeout=20)
    got = 0
    with open(path, "wb") as f:
        while not STOP and time.time() < deadline:
            try:
                chunk = resp.read(65536)
            except TimeoutError:
                continue          # quiet interface; keep the capture open
            except Exception:
                break             # connection dropped -> caller reconnects
            if not chunk:
                break             # router closed the stream -> caller reconnects
            f.write(chunk)
            f.flush()
            got += len(chunk)
            if got // (1 << 20) != (got - len(chunk)) // (1 << 20):
                print(f"   [{label}] {os.path.basename(path)}: {got/1048576:.1f} MB", flush=True)
    return got


def stop_capture(host, sid, triple):
    iface, minor, typ = triple
    try:
        http(f"http://{host}/cgi-bin/capture_notimeout?iface={urllib.parse.quote(iface)}"
             f"&minor={minor}&type={typ}&capture=Stop&sid={sid}", timeout=15).read()
    except Exception:
        pass


def run_interface(host, user, pw, triple, outroot, deadline):
    """Capture one interface into outroot/<iface>/seg###.pcap, reconnecting across
    segment boundaries until the deadline or STOP."""
    iface = triple[0]
    outdir = os.path.join(outroot, iface)
    os.makedirs(outdir, exist_ok=True)
    sid, _ = login(host, user, pw)
    seg = 0
    while not STOP and time.time() < deadline:
        seg += 1
        path = os.path.join(outdir, f"seg{seg:03d}.pcap")
        n = capture_segment(host, sid, triple, path, deadline, iface)
        print(f"   [{iface}] segment {seg}: {n/1048576:.1f} MB", flush=True)
        if STOP or time.time() >= deadline:
            break
        time.sleep(2)
        try:
            sid, _ = login(host, user, pw)
        except SystemExit:
            print(f"   [{iface}] re-login failed; stopping this interface.", flush=True)
            break
    stop_capture(host, sid, triple)


def main():
    ap = argparse.ArgumentParser(description="Long, segmented FRITZ!Box packet captures from the CLI.")
    ap.add_argument("--host", default="fritz.box", help="router address (default: fritz.box)")
    ap.add_argument("--user", default="", help="FRITZ!Box user (optional; auto-detected if omitted)")
    ap.add_argument("--iface", default="", help="interface to capture (see --list)")
    ap.add_argument("--all", action="store_true", help="capture every available interface in parallel")
    ap.add_argument("--list", action="store_true", help="list capture interfaces and exit")
    ap.add_argument("--hours", type=float)
    ap.add_argument("--minutes", type=float)
    ap.add_argument("--out", default=os.path.join(os.getcwd(), "out"), help="output directory (default: ./out)")
    a = ap.parse_args()

    pw = os.environ.get("FRITZBOX_PASSWORD") or getpass.getpass("FRITZ!Box password: ")
    sid, user = login(a.host, a.user, pw)
    print(f"logged in as {user!r}")

    dump = os.path.join(a.out, "session-" + time.strftime("%Y%m%d-%H%M"))
    ifaces = list_interfaces(a.host, sid, dump)
    if not ifaces:
        print(f"no capture interfaces parsed. Raw capture page saved to {dump}/capture_page.raw")
        raise SystemExit(1)
    print("capture interfaces:")
    for c in ifaces:
        print(f"   {c[0]}   (minor={c[1]}, type={c[2]})")
    if a.list:
        return

    if a.all:
        targets = ifaces
    elif a.iface:
        targets = [c for c in ifaces if c[0] == a.iface] or [(a.iface, "-1", "1")]
    else:
        raise SystemExit("choose an interface with --iface <name>, or --all. See --list.")

    limit = (a.hours or 0) * 3600 + (a.minutes or 0) * 60 or 10 * 3600
    outroot = os.path.join(a.out, "capture-" + time.strftime("%Y%m%d-%H%M"))
    os.makedirs(outroot, exist_ok=True)
    names = ", ".join(t[0] for t in targets)
    print(f"capturing [{names}] up to {limit/3600:.1f} h into {outroot}  (Ctrl-C to stop)")

    signal.signal(signal.SIGINT, lambda *_: globals().__setitem__("STOP", True))
    deadline = time.time() + limit

    threads = [threading.Thread(target=run_interface, args=(a.host, a.user, pw, t, outroot, deadline), daemon=True)
               for t in targets]
    for t in threads:
        t.start()
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        globals().__setitem__("STOP", True)

    print(f"\ndone. segments in {outroot}")
    print("merge one interface's segments with:")
    print(f"   mergecap -F pcap -w capture.pcap {outroot}/<iface>/seg*.pcap")


if __name__ == "__main__":
    main()
