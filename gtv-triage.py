#!/usr/bin/env python3
"""
tv-triage.py - non-root ADB triage of an Android / Google TV device.

Collects firmware integrity properties, processes, packages, persistence
locations (boot receivers, init services, jobs, alarms, device admins,
accessibility/notification listeners, IME) and network sockets, then:

  * writes raw output        -> <run>/raw/
  * writes normalized lists  -> <run>/norm/   (stable, sorted, diff-friendly)
  * writes summary.txt       -> red flags + items worth a human look
  * diffs norm/ against the previous run (or --baseline) -> <run>/diff.txt

Each run lands in  <outdir>/<timestamp>_<build-id>/  so successive firmware
builds can be compared.

Usage:
  ./tv-triage.py                        # scan the LAN and pick a TV to triage
  ./tv-triage.py --device 192.168.1.50:5555
  ./tv-triage.py --device 192.168.1.50:5555 --ioc badbox_iocs.txt
  ./tv-triage.py --pull-apks new        # pull APKs whose hash is new vs baseline
  ./tv-triage.py --baseline tv-triage-runs/20261115-080000_XYZ
  ./tv-triage.py --device 192.168.1.50 --vt-links     # VT links, no API key
  VT_API_KEY=... ./tv-triage.py --device 192.168.1.50 --virustotal  # VT API enrichment

Requirements: adb in PATH, Python 3.8+, stdlib only. No root needed.
IOC file: one indicator per line (package name, domain, IP, sha256, path
fragment); '#' comments allowed. Matched case-insensitively as substrings.
"""

import argparse
import datetime as dt
import difflib
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# --------------------------------------------------------------------------
# adb helpers
# --------------------------------------------------------------------------

ERRORS = []


def adb(args, serial=None, timeout=180):
    cmd = ["adb"] + (["-s", serial] if serial else []) + args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        ERRORS.append(f"TIMEOUT ({timeout}s): {' '.join(cmd)}")
        return ""
    except FileNotFoundError:
        sys.exit("adb not found in PATH (sudo apt install adb)")
    if r.stderr.strip():
        ERRORS.append(f"$ {' '.join(cmd)}\n{r.stderr.strip()}")
    return r.stdout


def sh(cmd, serial, timeout=180):
    return adb(["shell", cmd], serial, timeout)


# Absolute paths that are unambiguous Vo1d / BADBOX on-device artifacts.
# (Non-root shells often cannot stat /data/** -- a miss is inconclusive, so
# absence here is never treated as proof of cleanliness.)
MALWARE_ARTIFACT_PATHS = (
    "/system/xbin/vo1d", "/system/xbin/wd", "/data/google", "/data/google/daemon",
    "/data/google/rild", "/data/system/Corejava", "/data/system/installd",
    "/data/system/startup", "/data/secondstage", "/cache/secondstage",
    "/data/data/com.goog1e.apps", "/data/data/com.adups.fota",
    "/data/system/shared_prefs/open_preference.xml",
)

# What to collect: name -> (shell command, timeout)
COLLECT = {
    "getprop": ("getprop", 60),
    "getenforce": ("getenforce", 30),
    "id": ("id", 30),
    "uname": ("uname -a", 30),
    "mounts": ("cat /proc/mounts", 30),
    "ps": ("ps -A -o USER,PID,PPID,NAME,ARGS 2>/dev/null || ps -A", 60),
    "packages_all": ("pm list packages -f -U -i", 120),
    "packages_system": ("pm list packages -s", 60),
    "packages_3p": ("pm list packages -3", 60),
    "packages_disabled": ("pm list packages -d", 60),
    "dumpsys_package": ("dumpsys package", 600),
    "boot_receivers": ("cmd package query-receivers --brief "
                       "-a android.intent.action.BOOT_COMPLETED", 120),
    "locked_boot_receivers": ("cmd package query-receivers --brief "
                              "-a android.intent.action.LOCKED_BOOT_COMPLETED", 120),
    "init_rc": ("for d in /system/etc/init /vendor/etc/init /product/etc/init "
                "/system_ext/etc/init /odm/etc/init; do for f in $d/*.rc; do "
                "[ -r \"$f\" ] && { echo \"### $f\"; cat \"$f\"; }; done; done 2>/dev/null", 180),
    "jobscheduler": ("dumpsys jobscheduler", 180),
    "alarm": ("dumpsys alarm", 180),
    "activity_services": ("dumpsys activity services", 180),
    "device_policy": ("dumpsys device_policy", 60),
    "accessibility": ("settings get secure enabled_accessibility_services", 30),
    "notification_listeners": ("settings get secure enabled_notification_listeners", 30),
    "default_ime": ("settings get secure default_input_method", 30),
    "enabled_imes": ("settings get secure enabled_input_methods", 30),
    "settings_global": ("settings list global", 60),
    "settings_secure": ("settings list secure", 60),
    "settings_system": ("settings list system", 60),
    "netstat": ("netstat -tunap 2>/dev/null || netstat -tuna", 60),
    "proc_net_tcp": ("cat /proc/net/tcp", 30),
    "proc_net_tcp6": ("cat /proc/net/tcp6", 30),
    "proc_net_udp": ("cat /proc/net/udp", 30),
    "proc_net_udp6": ("cat /proc/net/udp6", 30),
    "netstats": ("dumpsys netstats detail", 300),
    "connectivity": ("dumpsys connectivity", 120),
    "data_local_tmp": ("ls -la /data/local/tmp", 30),
    "malware_artifacts": (
        "for p in " + " ".join(MALWARE_ARTIFACT_PATHS) +
        "; do [ -e \"$p\" ] && echo \"$p\"; done 2>/dev/null", 60),
    # sha256 of every APK (base + splits), computed on-device
    "apk_hashes": ("for p in $(pm list packages | cut -d: -f2); do "
                   "pm path \"$p\" | while read l; do f=${l#package:}; "
                   "h=$(sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1); "
                   "echo \"$p ${h:-UNREADABLE} $f\"; done; done", 900),
}

# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------

AID = {0: "root", 1000: "system", 1001: "radio", 1002: "bluetooth",
       1010: "wifi", 1013: "media", 1021: "gps", 1041: "audioserver",
       1047: "cameraserver", 1051: "network_stack", 1068: "secure_element",
       1073: "networkstack", 2000: "shell", 9999: "nobody"}

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
              "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
              "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
              "0A": "LISTEN", "0B": "CLOSING"}

WATCH_PERMS = {
    "android.permission.INSTALL_PACKAGES", "android.permission.DELETE_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_LOGS",
    "android.permission.WRITE_SECURE_SETTINGS", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_FRAME_BUFFER", "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.CAPTURE_VIDEO_OUTPUT", "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS", "android.permission.MANAGE_DEVICE_ADMINS",
    "android.permission.INSTALL_SELF_UPDATES", "android.permission.UPDATE_PACKAGES_WITHOUT_USER_ACTION",
    "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.QUERY_ALL_PACKAGES",
}


# Known-bad / suspect streaming-box model strings from published BADBOX,
# BADBOX 2.0 and Vo1d infected-device lists (HUMAN Security; DesktopECHO
# T95-H616-Malware feed). Matched EXACTLY (case-insensitively) against the
# device's product properties -- these are correlation, not proof: an attacker
# can set any model string, and a clean unit of the same model can exist.
KNOWN_BAD_MODELS = {m.lower(): m for m in (
    # BADBOX (original / T95-class)
    "T95", "T95Max", "X12-Plus", "X88-Pro-10",
    # BADBOX 2.0 published model list
    "TV98", "X96Q_Max_P", "Q96L2", "X96Q2", "X96mini", "S168",
    "ums512_1h10_Natv", "X96_S400", "X96mini_RP", "TX3mini", "HY-001",
    "MX10PRO", "X96mini_Plus1", "LongTV_GN7501E", "Xtv77", "NETBOX_B68",
    "X96Q_PR01", "AV-M9", "OCBN", "X96MATE_PLUS", "KM1", "X96Q_PRO",
    "Projector_T6P", "X96QPRO-TM", "sp7731e_1h10_native", "M8SPROW", "TV008",
    "X96Mini_5G", "Q96MAX", "Orbsmart_TR43", "KM9PRO", "Transpeed", "KM7",
    "iSinbox", "I96", "Fujicom-SmartTV", "MXQ9PRO", "MBOX", "X96Q", "R11",
    "GameBox", "KM6", "X96Max_Plus2", "TV007", "Q9 Stick", "SP7731E",
    "X88", "X98K", "TXCZ",
)}

# Model strings on the list that are too generic (or belong to a legitimate
# device) to flag outright -- reported as a soft note instead of a red flag.
GENERIC_MODELS = {m.lower() for m in (
    "Z6", "TVBOX", "Smart", "A15", "SMART_TV", "H6",
    "ADT-3",  # genuine Google ADT-3 developer boxes share this model string
)}
KNOWN_BAD_MODELS.update({m: m.upper() for m in GENERIC_MODELS})

# Properties that carry the model / product / board identity.
MODEL_PROPS = ("ro.product.model", "ro.product.device", "ro.product.name",
               "ro.build.product", "ro.product.board", "ro.product.vendor.model")

# Package names that ARE known Vo1d / BADBOX malware (unique/unambiguous).
# Installed-presence of any of these is treated as a malicious indicator.
MALWARE_PACKAGES = {m.lower() for m in (
    "com.goog1e.apps", "com.google.android.services",
    "com.google.android.gms.stable", "com.hs.app", "com.hs.cld", "com.hs.q",
    "com.mz.sdk", "com.debby.devour", "com.rmk.app.AllPlayer",
    "com.nasa.cook.CookInit", "com.sun.galaxy.lib.OceanInit",
    "com.www.intallapp", "com.swe.dgbluancher", "com.mozgame.fruitmania",
)}
# Packages associated with BADBOX but also plausibly benign (OTA/test) -> HIGH.
SUSPECT_PACKAGES = {m.lower() for m in ("com.adups.fota", "com.ftest")}


def parse_props(text):
    return dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", text, re.M))


def parse_packages(text):
    """pm list packages -f -U -i -> {pkg: {path, uid, installer}}"""
    pkgs = {}
    for line in text.splitlines():
        m = re.match(r"^package:(\S*)=([A-Za-z0-9_.]+)(?:\s|$)", line)
        if not m:
            continue
        uid = re.search(r"uid:([\d,]+)", line)
        inst = re.search(r"installer=(\S+)", line)
        pkgs[m.group(2)] = {"path": m.group(1),
                            "uid": uid.group(1) if uid else "?",
                            "installer": inst.group(1) if inst else "?"}
    return pkgs


def uid_map(pkgs):
    m = {}
    for name, p in pkgs.items():
        for u in p["uid"].split(","):
            if u.isdigit():
                m.setdefault(int(u), []).append(name)
    return m


def uid_label(uid, umap):
    if uid in umap:
        names = sorted(umap[uid])
        return names[0] if len(names) == 1 else f"{names[0]}(+{len(names)-1} shared)"
    if uid in AID:
        return AID[uid]
    return f"uid:{uid}"


def parse_ps(text):
    procs = []
    lines = text.splitlines()
    if not lines:
        return procs
    hdr = lines[0].split()
    for line in lines[1:]:
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        if "PPID" in hdr and len(parts) >= 4:
            user, pid, ppid, name = parts[:4]
            args = parts[4] if len(parts) > 4 else name
        else:  # plain ps -A fallback: USER PID PPID VSZ RSS WCHAN ADDR S NAME
            f = line.split()
            user, pid, ppid, name, args = f[0], f[1], f[2], f[-1], f[-1]
        procs.append({"user": user, "pid": pid, "ppid": ppid,
                      "name": name, "args": args.strip()})
    return procs


def is_kernel(p):
    return p["pid"] == "2" or p["ppid"] == "2" or p["pid"] == "0"


def hex_ip(h):
    if len(h) == 8:
        return socket.inet_ntop(socket.AF_INET, struct.pack("<I", int(h, 16)))
    b = b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8))
    ip = ipaddress.IPv6Address(b)
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)


def parse_proc_net(text, proto):
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        try:
            lip, lport = f[1].split(":")
            rip, rport = f[2].split(":")
            out.append({"proto": proto,
                        "laddr": hex_ip(lip), "lport": int(lport, 16),
                        "raddr": hex_ip(rip), "rport": int(rport, 16),
                        "state": TCP_STATES.get(f[3], f[3]) if proto.startswith("tcp") else
                                 ("LISTEN" if int(rport, 16) == 0 else "CONNECTED"),
                        "uid": int(f[7])})
        except (ValueError, OSError):
            continue
    return out


def is_local(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_loopback
    except ValueError:
        return False


def is_private(addr):
    try:
        ip = ipaddress.ip_address(addr)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified
    except ValueError:
        return False


def parse_components(text):
    return sorted(set(re.findall(r"^\s*([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)\s*$", text, re.M)))


def parse_rc_services(text):
    out = set()
    cur = "?"
    for line in text.splitlines():
        if line.startswith("### "):
            cur = line[4:].strip()
            continue
        m = re.match(r"^\s*service\s+(\S+)\s+(\S+)", line)
        if m:
            out.add(f"{m.group(1)} {m.group(2)}  [{cur}]")
    return sorted(out)


def parse_granted_perms(text):
    """dumpsys package -> sorted 'pkg PERM' for watched perms granted=true."""
    out = set()
    pkg = None
    for line in text.splitlines():
        m = re.match(r"^\s{2}Package \[([^\]]+)\]", line)
        if m:
            pkg = m.group(1)
            continue
        if pkg:
            m = re.match(r"^\s+([A-Za-z0-9_.]+): granted=true", line)
            if m and m.group(1) in WATCH_PERMS:
                out.add(f"{pkg} {m.group(1).rsplit('.', 1)[-1]}")
    return sorted(out)


def split_setting(v):
    v = v.strip()
    if not v or v == "null":
        return []
    return sorted(x for x in re.split(r"[:]", v) if x)


# --------------------------------------------------------------------------
# device discovery  (mirrors discover_tv in install-tv-apps.sh)
# --------------------------------------------------------------------------

def port_open(ip, port, timeout=0.5):
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except OSError:
        return False


def pc_ip():
    """This PC's IPv4 address on the route to the internet (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 53))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def discover_tv():
    """Find Google TV / Android devices on the LAN and let the user pick one.

    Returns an 'ip:port' string to adb-connect, or None to fall back to the
    default adb device. Combines three sources, like install-tv-apps.sh:
      1. Google Cast mDNS announcements (avahi-browse, if installed)
      2. Android wireless-debugging mDNS (adb mdns services)
      3. a 5555/8008/8009 sweep of this PC's /24
    """
    found = {}  # ip -> label

    def add(ip, label):
        found.setdefault(ip, label)

    # 1) Google Cast announcements: name + model in the TXT record.
    if shutil.which("avahi-browse"):
        print("Listening for Google TV / Cast devices (about 8s)...", flush=True)
        try:
            out = subprocess.run(["avahi-browse", "-rpt", "_googlecast._tcp"],
                                 capture_output=True, text=True, timeout=10).stdout
        except (subprocess.TimeoutExpired, OSError):
            out = ""
        for line in out.splitlines():
            f = line.split(";")
            if len(f) < 10 or f[0] != "=" or f[2] != "IPv4":
                continue
            addr, txt = f[7], f[9]
            fn = re.search(r"fn=([^\"]*)", txt)
            md = re.search(r"md=([^\"]*)", txt)
            label = (fn.group(1) if fn else "Cast device")
            if md:
                label += f" ({md.group(1)})"
            add(addr, label)

    # 2) Android wireless-debugging announcements.
    print("Asking adb for mDNS devices (about 5s)...", flush=True)
    try:
        out = subprocess.run(["adb", "mdns", "services"],
                             capture_output=True, text=True, timeout=8).stdout
    except (subprocess.TimeoutExpired, OSError):
        out = ""
    for m in re.findall(r"(\d+\.\d+\.\d+\.\d+):\d+", out):
        add(m, "Android device (wireless debugging)")

    # 3) Sweep this PC's /24 for debugging and Cast ports.
    src = pc_ip()
    if src:
        prefix = src.rsplit(".", 1)[0]
        print(f"Scanning {prefix}.1-254 for debugging and Cast ports (about 10s)...",
              flush=True)
        hits = {}  # ip -> set(kinds)

        def probe(i):
            ip = f"{prefix}.{i}"
            if ip == src:
                return
            if port_open(ip, 5555):
                hits.setdefault(ip, set()).add("adb")
            elif port_open(ip, 8009) or port_open(ip, 8008):
                hits.setdefault(ip, set()).add("cast")

        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(probe, range(1, 255)))
        for ip, kinds in hits.items():
            try:
                hn = socket.gethostbyaddr(ip)[0]
            except OSError:
                hn = ""
            kind = "ADB port open" if "adb" in kinds else "Cast port open"
            add(ip, f"{hn or 'Unnamed device'} ({kind})")
    else:
        print("Couldn't work out this PC's network address; skipping the scan.")

    # Present the menu, flagging devices that already accept ADB.
    ips = sorted(found, key=lambda x: tuple(int(o) for o in x.split(".")))
    print()
    if ips:
        for i, ip in enumerate(ips, 1):
            ready = "  [Network debugging on]" if port_open(ip, 5555) else ""
            print(f"  {i}) {ip:<15} {found[ip]}{ready}")
    else:
        print("  No devices found.")
    print("  m) My TV isn't listed: enter its IP address")
    print("  r) Rescan")

    rng = f"1-{len(ips)}, " if ips else ""
    try:
        choice = input(f"\nWhich one is your TV? [{rng}m, r]: ").strip()
    except EOFError:
        return None
    if choice in ("r", "R"):
        return discover_tv()
    if choice in ("m", "M", "n", "N"):
        try:
            ip = input("TV IP address: ").strip()
        except EOFError:
            return None
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip):
            sys.exit("That doesn't look like an IP address.")
        return ip if ":" in ip else ip + ":5555"
    if choice.isdigit() and 1 <= int(choice) <= len(ips):
        ip = ips[int(choice) - 1]
        return ip if ":" in ip else ip + ":5555"
    sys.exit("Invalid choice. Re-run and pick a number, m or r.")


# --------------------------------------------------------------------------
# VirusTotal enrichment  (API v3, stdlib only; hash/IP/domain LOOKUPS only --
# never uploads a file, so no device content leaves the machine)
# --------------------------------------------------------------------------

def vt_get(kind, ident, key, timeout=30):
    """GET /api/v3/{kind}/{ident}. kind in {files, ip_addresses, domains}."""
    url = f"https://www.virustotal.com/api/v3/{kind}/{ident}"
    req = urllib.request.Request(url, headers={
        "x-apikey": key, "Accept": "application/json",
        "User-Agent": "gtv-triage"})  # generic UA - no user/project identity
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_notfound": True}
        msg = {401: "unauthorized (401) - check API key",
               429: "rate-limited (429) - lower --vt-qpm or wait"}.get(e.code,
               f"HTTP {e.code}")
        return {"_error": msg}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"_error": str(e)}


def vt_stats(j):
    """-> (malicious, suspicious, reputation) from a VT object response."""
    attrs = j.get("data", {}).get("attributes", {})
    s = attrs.get("last_analysis_stats", {})
    return (s.get("malicious", 0), s.get("suspicious", 0),
            attrs.get("reputation"))


def vt_gui_url(kind, ident):
    """A VirusTotal GUI report URL (opens in a browser; needs no API key)."""
    path = {"files": "file", "ip_addresses": "ip-address", "domains": "domain"}[kind]
    return f"https://www.virustotal.com/gui/{path}/{ident}"


def vt_classify(token, pkgs_lower):
    """If a raw indicator string is a sha256 / public IP / domain, return
    (vt_kind, ident); else None. Installed package names are not domains."""
    t = token.strip().lower()
    if re.fullmatch(r"[a-f0-9]{64}", t):
        return ("files", t)
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", t):
        try:
            return ("ip_addresses", t) if ipaddress.ip_address(t).is_global else None
        except ValueError:
            return None
    if t in pkgs_lower or t.startswith(("com.", "org.", "net.", "io.", "android.")):
        return None  # reverse-DNS package id, not a hostname
    if "." in t and re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", t):
        return ("domains", t)
    return None


def vt_severity(kind, mal, susp):
    """Map VT counts to a triage severity (None = not worth scoring)."""
    if kind == "files":
        if mal >= 3:
            return "CRITICAL"
        if mal >= 1:
            return "HIGH"
    else:  # ip_addresses / domains: a couple of FP engines are common
        if mal >= 2:
            return "HIGH"
        if mal >= 1:
            return "MEDIUM"
    return "LOW" if susp >= 1 else None


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def safe(s):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60] or "unknown"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", help="ip[:port] for adb over Wi-Fi, or a USB serial")
    ap.add_argument("--scan", action="store_true",
                    help="scan the LAN for Google TV devices and pick one (default when "
                         "--device is omitted and no single device is already attached)")
    ap.add_argument("--outdir", default="tv-triage-runs", help="where runs are stored")
    ap.add_argument("--baseline", help="run directory to diff against (default: previous run)")
    ap.add_argument("--ioc", help="file of indicators to match")
    ap.add_argument("--pull-apks", choices=["new", "all"],
                    help="pull APKs: 'new' = hashes not in baseline, 'all' = every APK")
    ap.add_argument("--virustotal", action="store_true",
                    help="enrich APK hashes, public remote IPs and their domains via "
                         "VirusTotal (lookups only - never uploads files). Needs an API "
                         "key in $VT_API_KEY or --vt-key.")
    ap.add_argument("--vt-links", action="store_true",
                    help="write vt_links.txt of clickable VirusTotal GUI URLs for APK "
                         "hashes, public IPs and their domains (no API key needed; "
                         "nothing is sent until you open a link)")
    ap.add_argument("--vt-key", help="VirusTotal API key (else read from $VT_API_KEY)")
    ap.add_argument("--vt-qpm", type=int, default=4,
                    help="VT queries per minute (default 4 = free-tier limit)")
    ap.add_argument("--vt-max", type=int, default=40,
                    help="max VT lookups per run, to protect the daily quota (default 40)")
    a = ap.parse_args()

    serial = None
    if a.device:
        if re.match(r"^[\d.]+(:\d+)?$", a.device):
            dev = a.device if ":" in a.device else a.device + ":5555"
            print(adb(["connect", dev]).strip())
            serial = dev
        else:
            serial = a.device
    else:
        # No device given: discover one on the LAN unless a single device is
        # already attached (and --scan wasn't explicitly requested).
        attached = [l.split("\t")[0] for l in adb(["devices"], None, 30).splitlines()[1:]
                    if "\tdevice" in l]
        if a.scan or len(attached) != 1:
            dev = discover_tv()
            if dev:
                print(adb(["connect", dev]).strip())
                serial = dev
        else:
            serial = attached[0]
            print(f"Using already-attached device {serial}")
    if adb(["get-state"], serial, 30).strip() != "device":
        sys.exit("No authorized adb device. Check `adb devices` / accept the prompt on the TV.")

    props = parse_props(sh("getprop", serial, 60))
    build = props.get("ro.build.id", "unknown") + "_" + props.get("ro.build.version.incremental", "")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    outroot = Path(a.outdir)
    run = outroot / f"{stamp}_{safe(build)}"
    raw, norm = run / "raw", run / "norm"
    raw.mkdir(parents=True)
    norm.mkdir()

    data = {}
    for i, (name, (cmd, to)) in enumerate(COLLECT.items(), 1):
        print(f"[{i:2}/{len(COLLECT)}] {name}", flush=True)
        data[name] = sh(cmd, serial, to)
        (raw / f"{name}.txt").write_text(data[name])

    # ---- parse ----
    props = parse_props(data["getprop"])
    pkgs = parse_packages(data["packages_all"])
    umap = uid_map(pkgs)
    procs = parse_ps(data["ps"])
    sys_pkgs = {l.split(":", 1)[1].strip() for l in data["packages_system"].splitlines() if ":" in l}
    tp_pkgs = {l.split(":", 1)[1].strip() for l in data["packages_3p"].splitlines() if ":" in l}
    installed_malware = sorted(n for n in pkgs if n.lower() in MALWARE_PACKAGES)
    suspect_pkgs = sorted(n for n in pkgs if n.lower() in SUSPECT_PACKAGES)
    mal_artifacts = sorted({l.strip() for l in data["malware_artifacts"].splitlines() if l.strip()})

    socks = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        socks += parse_proc_net(data[f"proc_net_{proto}"], proto)

    apk_lines = sorted(l.strip() for l in data["apk_hashes"].splitlines() if l.count(" ") >= 2)

    boot = parse_components(data["boot_receivers"])
    lboot = parse_components(data["locked_boot_receivers"])
    init_svc = {k[len("init.svc."):]: v for k, v in props.items() if k.startswith("init.svc.")}
    rc_svcs = parse_rc_services(data["init_rc"])
    perms = parse_granted_perms(data["dumpsys_package"])
    admins = sorted(set(re.findall(r"ComponentInfo\{([^}]+)\}", data["device_policy"])))
    a11y = split_setting(data["accessibility"])
    nls = split_setting(data["notification_listeners"])
    imes = split_setting(data["enabled_imes"])

    listening = sorted({f"{s['proto']} {s['laddr']}:{s['lport']} {uid_label(s['uid'], umap)}"
                        for s in socks if s["state"] == "LISTEN"})
    remotes = sorted({f"{s['proto']} {s['raddr']}:{s['rport']} {s['state']} {uid_label(s['uid'], umap)}"
                      for s in socks if s["state"] not in ("LISTEN",) and s["raddr"] not in ("0.0.0.0", "::")})

    # ---- normalized (diffable) lists ----
    def wnorm(name, lines):
        (norm / f"{name}.txt").write_text("\n".join(lines) + ("\n" if lines else ""))

    wnorm("build", [f"{k}={props.get(k, '')}" for k in (
        "ro.build.fingerprint", "ro.build.version.security_patch", "ro.build.tags",
        "ro.build.type", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state", "ro.debuggable", "ro.secure",
        "ro.product.manufacturer", "ro.product.model", "ro.vendor.build.fingerprint")]
        + [f"selinux={data['getenforce'].strip()}"])
    wnorm("processes", sorted({f"{p['user']} {p['name']} {p['args']}" for p in procs if not is_kernel(p)}))
    wnorm("packages", sorted(f"{n} {p['path']} installer={p['installer']}" for n, p in pkgs.items()))
    wnorm("apk_hashes", apk_lines)
    wnorm("boot_receivers", boot)
    wnorm("locked_boot_receivers", lboot)
    wnorm("init_services", sorted(init_svc))
    wnorm("init_rc_services", rc_svcs)
    wnorm("sensitive_perms", perms)
    wnorm("device_admins", admins)
    wnorm("accessibility", a11y)
    wnorm("notification_listeners", nls)
    wnorm("input_methods", imes)
    wnorm("listening", listening)
    wnorm("remote_endpoints", remotes)  # volatile; reviewed, not diffed

    # ---- summary ----
    S = []
    flag = lambda msg: S.append(f"  [!] {msg}")
    note = lambda msg: S.append(f"      {msg}")

    S.append(f"tv-triage run {run.name}")
    S.append(f"Device: {props.get('ro.product.manufacturer')} {props.get('ro.product.model')}")
    S.append(f"Fingerprint: {props.get('ro.build.fingerprint')}")
    S.append(f"Security patch: {props.get('ro.build.version.security_patch')}\n")

    S.append("== Firmware integrity ==")
    checks = [("ro.build.tags", "release-keys"), ("ro.build.type", "user"),
              ("ro.boot.verifiedbootstate", "green"), ("ro.boot.flash.locked", "1"),
              ("ro.debuggable", "0"), ("ro.secure", "1")]
    for k, want in checks:
        v = props.get(k, "")
        (note if v == want else flag)(f"{k} = {v or '(unset)'}  (expected {want})")
    se = data["getenforce"].strip()
    (note if se == "Enforcing" else flag)(f"SELinux = {se}")
    if "test-keys" in props.get("ro.build.fingerprint", ""):
        flag("fingerprint contains test-keys")

    # ---- known-bad device model ----
    model_hits = {}  # canonical model -> list of "prop=value" it matched on
    for k in MODEL_PROPS:
        v = props.get(k, "").strip()
        if v and v.lower() in KNOWN_BAD_MODELS:
            model_hits.setdefault(KNOWN_BAD_MODELS[v.lower()], []).append(f"{k}={v}")
    strong = {m: w for m, w in model_hits.items() if m.lower() not in GENERIC_MODELS}
    weak = {m: w for m, w in model_hits.items() if m.lower() in GENERIC_MODELS}
    for m, where in sorted(strong.items()):
        flag(f"device model on BADBOX/Vo1d published list: '{m}' ({', '.join(where)})")
    for m, where in sorted(weak.items()):
        note(f"device model matches a GENERIC entry on the BADBOX list: '{m}' "
             f"({', '.join(where)}) - weak signal, corroborate with other findings")
    if strong:
        note("Model match is correlation, not proof - confirm with the behavioural "
             "findings below (sideloaded apps, boot receivers, C2 endpoints).")
    elif not model_hits:
        note(f"device model ({props.get('ro.product.model', '?')}) not on the known-bad list")

    S.append("\n== Known-malware indicators ==")
    for n in installed_malware:
        flag(f"MALWARE PACKAGE INSTALLED: {n}  (known Vo1d/BADBOX component)")
    for n in suspect_pkgs:
        flag(f"suspect package installed: {n}  (BADBOX-associated; can be benign OTA/test)")
    for p in mal_artifacts:
        flag(f"malware file artifact present: {p}")
    if not (installed_malware or suspect_pkgs or mal_artifacts):
        note("no known Vo1d/BADBOX packages or file artifacts found")
        note("non-root cannot read most of /data/** and /system is restricted, so a")
        note("clean result here is NOT proof - corroborate with --ioc, APK hashing, and")
        note("the YARA rules on pulled APKs.")

    S.append("\n== Processes ==")
    user_procs = [p for p in procs if not is_kernel(p)]
    note(f"{len(procs)} total, {len(user_procs)} userland")
    # Flag a process only when its EXECUTABLE lives in a writable dir -- not
    # merely because a writable path appears among its arguments (stock daemons
    # like keystore2/credstore/gatekeeperd legitimately take a /data/misc arg).
    WRITABLE = ("/data/", "/sdcard/", "/mnt/", "/storage/", "/tmp/", "/cache/")
    # ...but /data/app/<pkg>/... is where normal installed apps' native libs run.
    def runs_from_writable(p):
        exe = (p["args"].split()[0] if p["args"].strip() else p["name"])
        return exe.startswith(WRITABLE) and not exe.startswith("/data/app/")
    sus = [p for p in user_procs if runs_from_writable(p)]
    for p in sus:
        flag(f"runs from writable path: {p['user']} pid={p['pid']} {p['args']}")
    if not sus:
        note("no processes running from /data, /sdcard, /mnt, /tmp")
    root_procs = sorted({p["args"].split()[0] if p["args"] else p["name"]
                         for p in user_procs if p["user"] == "root"})
    note(f"root userland binaries ({len(root_procs)}) - review for non-stock names:")
    for r in root_procs:
        note(f"    {r}")

    S.append("\n== Packages ==")
    note(f"{len(pkgs)} total, {len(sys_pkgs)} system, {len(tp_pkgs)} third-party")
    sideloaded = sorted(n for n in tp_pkgs
                        if pkgs.get(n, {}).get("installer", "?") != "com.android.vending")
    for n in sideloaded:
        note(f"sideloaded/non-Play: {n} (installer={pkgs.get(n, {}).get('installer', '?')})")
    unread = [l for l in apk_lines if " UNREADABLE " in l]
    if unread:
        flag(f"{len(unread)} APKs could not be hashed (see norm/apk_hashes.txt)")

    S.append("\n== Persistence ==")
    note(f"BOOT_COMPLETED receivers: {len(boot)}  (LOCKED_BOOT: {len(lboot)})")
    if not boot and data["boot_receivers"].strip() == "":
        flag("query-receivers returned nothing - check raw/boot_receivers.txt / errors.log")
    tp_boot = [c for c in boot if c.split("/")[0] in tp_pkgs]
    for c in tp_boot:
        note(f"third-party boot receiver: {c}")
    note(f"native init services: {len(init_svc)} running/declared, {len(rc_svcs)} in readable .rc files")
    if a11y:
        for x in a11y:
            flag(f"accessibility service enabled: {x}")
    else:
        note("no accessibility services enabled")
    for x in nls:
        note(f"notification listener: {x}")
    for x in admins:
        flag(f"device admin / policy component: {x}")
    note(f"default IME: {data['default_ime'].strip()}")
    ls = [l for l in (data["data_local_tmp"].splitlines()) if l and not l.startswith("total")
          and not l.rstrip().endswith((" .", " .."))]
    if ls:
        flag(f"/data/local/tmp not empty ({len(ls)} entries) - see raw/data_local_tmp.txt")

    S.append("\n== Sensitive permissions granted (pkg PERM) ==")
    by_perm = {}
    for line in perms:
        pk, pm = line.split(" ", 1)
        by_perm.setdefault(pm, []).append(pk)
    for pm in sorted(by_perm):
        note(f"{pm}: {len(by_perm[pm])} pkgs")
    note("full list: norm/sensitive_perms.txt")

    S.append("\n== Network ==")
    # Ports a stock Google/Android TV legitimately listens on: Cast (8008/8009/
    # 8443/9000), SSDP/DIAL (1900), mDNS (5353), GMS (5228), Matter (5540),
    # Android TV remote (6466/6467). Listeners here, or owned by a Google/system
    # package, are expected; only others are worth flagging.
    EXPECTED_LISTEN_PORTS = {1900, 5353, 5228, 5540, 6466, 6467, 8008, 8009, 8443, 9000}

    def listen_owner(l):
        parts = l.split(None, 2)
        return parts[2] if len(parts) > 2 else "?"

    def listen_port(l):
        try:
            return int(l.split()[1].rsplit(":", 1)[1])
        except (IndexError, ValueError):
            return -1

    def listen_expected(l):
        return (listen_port(l) in EXPECTED_LISTEN_PORTS
                or listen_owner(l).startswith(("com.google.", "com.android.", "android")))

    ext_listen = [l for l in listening if not is_local(l.split()[1].rsplit(":", 1)[0])]
    unexpected_listen = []
    for l in ext_listen:
        if l.split()[1].endswith(":5555"):
            note(f"listening on non-loopback: {l}  (adb over Wi-Fi - expected while connected)")
        elif listen_expected(l):
            note(f"listening on non-loopback: {l}  (Cast/discovery/system - expected)")
        else:
            flag(f"listening on non-loopback: {l}  (non-standard port - review owning app)")
            unexpected_listen.append(l)
    if not ext_listen:
        note("no non-loopback listeners")
    ext = sorted({r for r in remotes if not is_private(r.split()[1].rsplit(":", 1)[0])})
    note(f"connections to public IPs right now ({len(ext)}):")
    for r in ext:
        note(f"    {r}")
    note("Socket snapshot is a point in time - pair with DNS/router logs over days.")

    # ---- VirusTotal: indicator collection (shared by --vt-links and --virustotal) ----
    vt_findings = []  # (severity, text) -> fed into the score
    # VT GUI links (no API key) for every indicator rated suspicious-or-higher,
    # whether flagged by the VT API below or by IOC matching further down.
    flagged_links = {}  # url -> reason
    pkgs_lower = {n.lower() for n in pkgs}
    if a.virustotal or a.vt_links:
        # Hashes: sha256 of APKs, sideloaded/non-Play first, deduped, readable only.
        seen_h, hash_items = set(), []
        side = set(sideloaded)
        for pass_side in (True, False):
            for line in apk_lines:
                parts = line.split(" ", 2)
                if len(parts) < 2:
                    continue
                pkg, sha = parts[0], parts[1]
                if (pkg in side) != pass_side:
                    continue
                if sha and sha != "UNREADABLE" and sha not in seen_h:
                    seen_h.add(sha)
                    hash_items.append((sha, pkg))
        # Public remote IPs from the socket snapshot, and their reverse-DNS domains.
        ip_items = sorted({r.split()[1].rsplit(":", 1)[0] for r in remotes
                           if not is_private(r.split()[1].rsplit(":", 1)[0])})
        dom_items = set()
        for ip in ip_items:
            try:
                host = socket.gethostbyaddr(ip)[0]
            except OSError:
                continue
            if host and "." in host:
                dom_items.add(host.lower())
        dom_items = sorted(dom_items)

    # ---- VirusTotal links (no API key needed) ----
    if a.vt_links:
        S.append("\n== VirusTotal links (no API key) ==")
        gui = "https://www.virustotal.com/gui"
        link_lines = ([f"{gui}/file/{sha}  # {pkg}" for sha, pkg in hash_items]
                      + [f"{gui}/ip-address/{ip}" for ip in ip_items]
                      + [f"{gui}/domain/{dom}" for dom in dom_items])
        (run / "vt_links.txt").write_text("\n".join(link_lines) + ("\n" if link_lines else ""))
        note(f"wrote {len(link_lines)} VirusTotal GUI links to vt_links.txt "
             f"({len(hash_items)} APK hashes, {len(ip_items)} IPs, {len(dom_items)} domains)")
        note("open them in a browser - no API key required. Nothing is sent from this")
        note("machine; VirusTotal only sees an indicator when you open its link.")

    # ---- VirusTotal API enrichment (needs a key) ----
    if a.virustotal:
        S.append("\n== VirusTotal ==")
        vt_key = a.vt_key or os.environ.get("VT_API_KEY", "")
        if not vt_key:
            flag("VirusTotal requested but no API key ($VT_API_KEY / --vt-key) - skipped")
            if not a.vt_links:
                note("tip: re-run with --vt-links for clickable VT links without a key")
        else:
            vtdir = raw / "virustotal"
            vtdir.mkdir(exist_ok=True)
            delay = 60.0 / max(1, a.vt_qpm)
            note(f"querying VirusTotal (<= {a.vt_max} lookups, {a.vt_qpm}/min): "
                 f"{len(hash_items)} hashes, {len(ip_items)} IPs, {len(dom_items)} domains")
            note("sends only these indicators to VirusTotal; no APK/file contents are uploaded.")

            queried = [0]
            label = {"files": "file", "ip_addresses": "IP", "domains": "domain"}

            def vt_batch(kind, idents, tagger):
                for ident in idents:
                    if queried[0] >= a.vt_max:
                        note(f"VT budget ({a.vt_max}) reached - remaining {label[kind]}s skipped")
                        return
                    if queried[0] > 0 and delay:
                        time.sleep(delay)
                    j = vt_get(kind, ident, vt_key)
                    queried[0] += 1
                    (vtdir / f"{kind}_{safe(ident)}.json").write_text(json.dumps(j))
                    if "_error" in j:
                        note(f"VT {label[kind]} {ident}: {j['_error']}")
                        if "429" in j["_error"] or "401" in j["_error"]:
                            return  # stop hammering a bad key / exhausted quota
                        continue
                    if j.get("_notfound"):
                        continue  # not in VT corpus
                    mal, susp, rep = vt_stats(j)
                    sev = vt_severity(kind, mal, susp)
                    if sev:
                        url = vt_gui_url(kind, ident)
                        flagged_links[url] = f"{label[kind]} mal={mal} susp={susp} {ident}"
                        if sev in ("CRITICAL", "HIGH"):
                            flag(f"VT: {label[kind]} flagged by {mal} engines "
                                 f"(susp {susp}): {ident}{tagger(ident)}\n        {url}")
                        else:
                            note(f"VT: {label[kind]} low detections (mal {mal}, susp "
                                 f"{susp}): {ident}{tagger(ident)}\n        {url}")
                        vt_findings.append((sev, f"VT {label[kind]} {ident} "
                                            f"(mal {mal}, susp {susp})  {url}"))

            sha_pkg = {s: p for s, p in hash_items}
            vt_batch("files", [s for s, _ in hash_items],
                     lambda i: f"  [{sha_pkg.get(i, '?')}]")
            vt_batch("ip_addresses", ip_items, lambda i: "")
            vt_batch("domains", dom_items, lambda i: "")

            hits = len([1 for sv, _ in vt_findings if sv in ("CRITICAL", "HIGH")])
            note(f"VirusTotal done: {queried[0]} lookups, {hits} indicator(s) with "
                 f"significant detections (raw JSON in raw/virustotal/)")

    # ---- IOC matching ----
    ioc_hits = []
    if a.ioc:
        S.append("\n== IOC matches ==")
        iocs = [l.strip().lower() for l in Path(a.ioc).read_text().splitlines()
                if l.strip() and not l.lstrip().startswith("#")]
        for f in sorted(norm.glob("*.txt")) + [raw / "netstat.txt"]:
            for ln in f.read_text().splitlines():
                low = ln.lower()
                for ioc in iocs:
                    if ioc in low:
                        flag(f"IOC '{ioc}' in {f.parent.name}/{f.name}: {ln.strip()}")
                        ioc_hits.append((ioc, f"{f.name}: {ln.strip()}"))
                        cl = vt_classify(ioc, pkgs_lower)
                        if cl:
                            flagged_links.setdefault(vt_gui_url(*cl), f"IOC match: {ioc}")
        if not ioc_hits:
            note(f"no matches for {len(iocs)} indicators")

    # ---- VirusTotal links for everything rated suspicious-or-higher ----
    if flagged_links:
        S.append("\n== VirusTotal links for flagged indicators (no API key needed) ==")
        for url in sorted(flagged_links):
            note(f"{url}   ({flagged_links[url]})")
        (run / "vt_flagged_links.txt").write_text(
            "\n".join(f"{u}  # {flagged_links[u]}" for u in sorted(flagged_links)) + "\n")
        note("open any link in a browser to see the report - no API key required.")

    # ---- diff vs baseline ----
    S.append("\n== Diff vs baseline ==")
    firmware_changed = False
    base = Path(a.baseline) if a.baseline else None
    if base is None and outroot.exists():
        prev = sorted(d for d in outroot.iterdir() if d.is_dir() and d != run and (d / "norm").is_dir())
        base = prev[-1] if prev else None
    base_hashes = set()
    if base and (base / "norm").is_dir():
        note(f"baseline: {base}")
        bfp = (base / "norm" / "build.txt").read_text().splitlines()[:1]
        cfp = (norm / "build.txt").read_text().splitlines()[:1]
        if bfp != cfp:
            firmware_changed = True
            flag(f"FIRMWARE CHANGED: {bfp[0] if bfp else '?'} -> {cfp[0] if cfp else '?'}")
        out = []
        for f in sorted(norm.glob("*.txt")):
            if f.name == "remote_endpoints.txt":
                continue
            bf = base / "norm" / f.name
            old = bf.read_text().splitlines() if bf.exists() else []
            new = f.read_text().splitlines()
            d = list(difflib.unified_diff(old, new, f"baseline/{f.name}", f"current/{f.name}", lineterm="", n=0))
            if d:
                out += d + [""]
                add = sum(1 for x in d if x.startswith("+") and not x.startswith("+++"))
                rem = sum(1 for x in d if x.startswith("-") and not x.startswith("---"))
                (flag if f.name != "processes.txt" else note)(f"{f.name}: +{add} / -{rem}")
        (run / "diff.txt").write_text("\n".join(out))
        if not out:
            note("no changes in any normalized list")
        else:
            note("details: diff.txt")
        bh = base / "norm" / "apk_hashes.txt"
        if bh.exists():
            base_hashes = {l.split()[1] for l in bh.read_text().splitlines() if len(l.split()) >= 3}
    else:
        note("no baseline yet - this run becomes the baseline for the next one")

    # ---- optional APK pull ----
    if a.pull_apks:
        apkdir = run / "apks"
        apkdir.mkdir()
        todo = [l.split(" ", 2) for l in apk_lines]
        if a.pull_apks == "new":
            todo = [t for t in todo if t[1] not in base_hashes]
        print(f"Pulling {len(todo)} APKs ...")
        for pk, h, path in todo:
            adb(["pull", path, str(apkdir / f"{pk}__{Path(path).name}")], serial, 600)
        note(f"pulled {len(todo)} APKs to {apkdir}")

    # ---- overall security assessment score ----
    # Collect weighted risk signals from what was parsed above. CRITICAL =
    # confirmed-malicious; HIGH = highly suspicious; MEDIUM/LOW = hygiene.
    risk = []  # (severity, text)

    def R(sev, text):
        risk.append((sev, text))

    for n in installed_malware:
        R("CRITICAL", f"known malware package installed: {n}")
    for p in mal_artifacts:
        R("CRITICAL", f"known malware file artifact present: {p}")
    for n in suspect_pkgs:
        R("HIGH", f"BADBOX-associated package installed: {n}")
    # Firmware / boot integrity (unlocked verified boot weighs heavier)
    HARD_BOOT = {"ro.boot.verifiedbootstate", "ro.boot.flash.locked",
                 "ro.boot.vbmeta.device_state"}
    for k, want in checks:
        if props.get(k, "") != want:
            R("HIGH" if k in HARD_BOOT else "MEDIUM",
              f"{k}={props.get(k, '') or '(unset)'} (expected {want})")
    if se != "Enforcing":
        R("HIGH", f"SELinux not enforcing ({se or 'unknown'})")
    if "test-keys" in props.get("ro.build.fingerprint", ""):
        R("MEDIUM", "firmware signed with test-keys")
    for m in strong:
        R("HIGH", f"device model on BADBOX/Vo1d list: {m}")
    for m in weak:
        R("LOW", f"device model matches generic BADBOX entry: {m}")
    for p in sus:
        R("HIGH", f"process from writable path: {p['args'][:70]}")
    for x in a11y:
        R("HIGH", f"accessibility service enabled: {x}")
    for x in admins:
        R("HIGH", f"device admin / policy component: {x}")
    # Third-party boot receivers and non-standard listeners are extremely common
    # on a normal media box (every streaming app registers them); they are NOT
    # per-item risk. Record a single low-weight attack-surface note for each.
    if tp_boot:
        R("LOW", f"{len(tp_boot)} third-party boot receiver(s) (normal for media apps)")
    if unexpected_listen:
        R("LOW", f"{len(unexpected_listen)} non-standard listener(s) on sideloaded/"
                 f"unknown apps (review owning apps)")
    if unread:
        R("MEDIUM", f"{len(unread)} APK(s) could not be hashed")
    if ls:
        R("MEDIUM", "/data/local/tmp is not empty")
    for n in sideloaded:
        R("LOW", f"sideloaded / non-Play app: {n}")
    for ioc, where in ioc_hits:
        R("HIGH", f"IOC '{ioc}' matched ({where})")
    for sev, text in vt_findings:
        R(sev, text)
    if firmware_changed:
        R("MEDIUM", "firmware changed vs baseline")

    # Weight, with a per-severity cap so one noisy category can't dominate.
    W = {"CRITICAL": 100, "HIGH": 30, "MEDIUM": 10, "LOW": 3}
    CAP = {"CRITICAL": 10 ** 6, "HIGH": 180, "MEDIUM": 40, "LOW": 15}
    by_sev = {s: [t for sv, t in risk if sv == s] for s in W}
    points = sum(min(len(by_sev[s]) * W[s], CAP[s]) for s in W)
    score = max(0, 100 - points)
    has_crit = bool(by_sev["CRITICAL"])
    has_high = bool(by_sev["HIGH"])
    has_med = bool(by_sev["MEDIUM"])

    # The VERDICT is gated on the worst severity actually found: with no
    # CRITICAL and no HIGH, the device cannot be called "compromised", no matter
    # how many low-severity hygiene items pile up.
    if has_crit:
        grade, verdict = "F", ("MALICIOUS — known malware present; treat the device "
                               "as COMPROMISED")
    elif has_high:
        if score < 40:
            grade, verdict = "E", "SEVERE — multiple strong indicators; investigate for compromise"
        elif score < 65:
            grade, verdict = "D", "HIGH RISK — strong indicator(s); investigate before trusting"
        else:
            grade, verdict = "C", "ELEVATED — a highly-suspicious item to review"
    else:  # only hygiene / attack-surface items -> never "compromise"
        if score >= 90 and not has_med:
            grade, verdict = "A", "CLEAN — no malicious or highly suspicious indicators found"
        elif score >= 70:
            grade, verdict = "B", "LOW–MODERATE — minor hygiene / sideloaded-app review"
        else:
            grade, verdict = "C", "ELEVATED — several hygiene / attack-surface items to review"

    A = []
    A.append("=" * 68)
    A.append(f"SECURITY ASSESSMENT:  {score}/100  (grade {grade})")
    A.append(f"VERDICT: {verdict}")
    A.append(f"Risk points {points}  "
             f"[CRITICAL {len(by_sev['CRITICAL'])}, HIGH {len(by_sev['HIGH'])}, "
             f"MEDIUM {len(by_sev['MEDIUM'])}, LOW {len(by_sev['LOW'])}]")
    A.append("")
    A.append("Malicious indicators (CRITICAL):")
    for t in by_sev["CRITICAL"] or ["  none"]:
        A.append(f"  [X] {t}" if by_sev["CRITICAL"] else t)
    A.append("Highly suspicious (HIGH):")
    hi = by_sev["HIGH"]
    for t in (hi[:15] or ["  none"]):
        A.append(f"  [!] {t}" if hi else t)
    if len(hi) > 15:
        A.append(f"  ... and {len(hi) - 15} more (see flags below)")
    if by_sev["MEDIUM"] or by_sev["LOW"]:
        A.append("Lower-severity (hygiene / attack surface):")
        for t in by_sev["MEDIUM"][:8]:
            A.append(f"  [-] {t}")
        for t in by_sev["LOW"][:8]:
            A.append(f"  [.] {t}")
    A.append("")
    A.append("Heuristic triage score, NOT a definitive verdict. A non-root scan sees")
    A.append("limited state, so a high score is not a clean bill of health; confirm")
    A.append("every flag by hand. Details follow.")
    A.append("=" * 68)

    summary = "\n".join(A) + "\n\n" + "\n".join(S) + "\n"
    (run / "summary.txt").write_text(summary)
    (run / "errors.log").write_text("\n\n".join(ERRORS) + "\n")
    print("\n" + summary)
    print(f"Run saved to {run}")


if __name__ == "__main__":
    main()
