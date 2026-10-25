#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MOTH -- Modbus Observation & Threat Honeypot
============================================

A low-interaction Modbus/TCP honeypot that looks like a real PLC on the wire.

MOTH answers as a Schneider Modicon M340 running a wastewater lift station
(three submersible pumps, a wet well with diurnal influent, level control with
lead/lag/lag2 alternation, VFD speed, alarms, run-hour counters).  The process
is simulated live, so an attacker polling the registers sees values that move
the way a real station moves -- and if they write a setpoint or force a pump,
the process reacts.

Every touch is an alert:

  * ICMP echo (ping) to the honeypot                       -> PING
  * ARP request for the honeypot's address                 -> ARP_REQUEST
  * One host ARP-ing many addresses on the segment         -> ARP_SWEEP
  * TCP/UDP probes across many ports (nmap etc.)           -> PORT_SCAN
  * NULL / FIN / XMAS TCP probes                           -> STEALTH_PROBE
  * Connection to an optional decoy service port (--decoy)  -> DECOY_CONNECT
  * Any Modbus/TCP connection                              -> MODBUS_CONNECT
  * Every Modbus function code received, decoded, tagged   -> MODBUS_READ / _WRITE /
                                                              _IDENT / _DIAG / _UNSUPPORTED
  * Malformed or non-Modbus bytes on port 502              -> MODBUS_MALFORMED

Severity ladder: INFO < NOTICE < WARN < HIGH < CRIT.  Nobody has a legitimate
reason to talk Modbus to a honeypot, so every Modbus request is at least HIGH
(reads, device ID, diagnostics, unknown function codes) and every write attempt
-- applied or refused -- is CRIT.

Alerts go to the console and a local text log (moth_alerts.log beside the
script).  Optionally each alert is also sent to a syslog server over UDP
(RFC 3164 or RFC 5424) and/or written as JSON lines.

Sensor health (v0.2.0): a watchdog keeps Tier 1 capture alive across sleep/resume,
adapter resets and address changes (SENSOR_DOWN / SENSOR_RESTORED /
SENSOR_IP_CHANGE); HEARTBEAT records go to the log and syslog, never the console;
console output runs on its own thread so a blocked console cannot stall the
honeypot; and console close / Ctrl+Break / SIGTERM / SIGHUP stop it cleanly.

Detection tiers
---------------
  Tier 1 -- packet capture (--capture auto|pcap|raw):
            Windows : Npcap via the optional 'scapy' package (preferred, chosen
                      automatically when installed).  Npcap captures at the driver
                      layer, BELOW Windows Defender Firewall, so it sees ARP, pings and
                      SYNs to closed ports even though the firewall drops them.
                      Fallback: stdlib raw IP socket (SIO_RCVALL, needs Administrator).
                      SIO_RCVALL sits ABOVE the firewall: inbound pings and SYNs to
                      closed ports are dropped before MOTH sees them, so PING and
                      PORT_SCAN go quiet.  MOTH warns about this at startup.
            Linux   : AF_PACKET raw socket (root) -> ARP, ping, scans, probes; no extras.
                      (--capture pcap uses scapy/libpcap instead.)
            macOS   : scapy/BPF if installed (untested); otherwise Tier 2 only.
            Traffic from the honeypot's own addresses is ignored -- test from a
            second machine, not by pinging or scanning the MOTH host from itself.
  Tier 2 -- the Modbus listener itself, plus optional decoy service ports (--decoy LIST,
            off by default so only TCP 502 is open).  A connection to a decoy port is an
            alert and feeds the scan detector.  If Tier 1 cannot start, MOTH says so and
            keeps running on Tier 2.

Usage
-----
  python moth.py                          # defaults: 0.0.0.0:502, M340 profile, sniffer on
  python moth.py --syslog 10.10.5.20      # also forward alerts to a syslog server
  python moth.py --port 5020 --no-sniff   # unprivileged demo on a high port
  python moth.py --list-map               # print the register / coil map and exit
  python moth.py --test-alert             # push one test alert through log + syslog

Author   : Mike Holcomb (with Claude)
Licence  : Use freely for training, research and authorized monitoring.

DISCLAIMER
----------
FOR AUTHORIZED USE ONLY.  MOTH is intended for training, research, and monitoring
on networks you own or are explicitly authorized to instrument.  It deliberately
advertises itself as a control system; deploy it only where a decoy PLC will not
confuse operators, asset inventories, or safety reviews.  It is not intended for
production environments where safety or operational availability cannot be
guaranteed.  The author accepts no liability for misuse.

Changelog
---------
  0.2.0  Version line renumbered to 0.x at the author's request; this release follows 1.1.0.
         CAPTURE WATCHDOG: a dead capture engine (sleep/resume, adapter reset, driver
         error) used to stay dead silently while port 502 kept answering.  It is now
         reopened with backoff (5 s doubling to 60 s), with SENSOR_DOWN (WARN) once per
         outage and SENSOR_RESTORED (NOTICE) when it is back.  Host addresses are
         re-read every 30 s; a change raises SENSOR_IP_CHANGE and reopens engines tied
         to an address.  Npcap read errors (instant empty reads) are now detected
         instead of spinning forever; an engine idle for 600 s is reopened quietly.
         Reopens never fall back from Npcap to SIO_RCVALL.
         HEARTBEAT: --heartbeat SECONDS (default 900, 0 = off) writes state=start / alive
         / stop records with capture state and counters to the log, JSON log and syslog
         -- never the console.
         CONSOLE: output now runs on its own thread with a bounded queue.  Previously a
         blocked console (QuickEdit selection, unread pipe) froze Modbus replies and
         packet capture.  QuickEdit is switched off while MOTH runs and restored on exit
         (--keep-quickedit to opt out).
         SHUTDOWN: closing the console window and Ctrl+Break (Windows) and SIGTERM /
         SIGHUP (POSIX; SIGHUP left alone under nohup) now stop MOTH cleanly: summary
         line with the reason, HEARTBEAT state=stop, SIO_RCVALL switched off, QuickEdit
         restored.  Cleanup is time-boxed and survives a second Ctrl+C.  (Windows sends
         logoff/shutdown events only to services.)
         FIXES: syslog collector name is resolved once (a hostname was re-resolved on
         every alert, stalling Modbus and capture whenever DNS was down; failed lookups
         now retry once a minute).  No more escape-code garbage on Windows 7 / 8.1
         consoles (VT mode failure was ignored).  Linux AF_PACKET skips its own transmit
         copies.  Runs under pythonw (no stdout).
         New alert kinds SENSOR_DOWN, SENSOR_RESTORED, SENSOR_IP_CHANGE.  Status line
         (opt-in) now shows capture state.  No existing flag, alert kind or log format
         changed.
  1.1.0  FIX: on Windows, pings and port scans were not detected.  ICMP/TCP/UDP were
         captured with SIO_RCVALL, which only sees what Windows Firewall lets through
         (it drops inbound echo and SYNs to closed ports); ARP worked because it came
         through scapy/Npcap.  When scapy + Npcap are present, MOTH now captures
         EVERYTHING through Npcap (below the firewall).  New --capture auto|pcap|raw.
         SIO_RCVALL fallback now prints a firewall warning at startup.
         New HIGH severity (syslog 3) between WARN and CRIT.  Modbus reads, device-ID,
         diagnostics and unknown FCs are now HIGH (were NOTICE); all write attempts are
         CRIT (untagged-address writes were WARN); writes refused by --reject-writes are
         now MODBUS_WRITE/CRIT (were MODBUS_UNSUPPORTED/NOTICE); FC 8 restart-comm /
         force-listen-only attempts are CRIT.  Exception replies keep the function's
         class (READ/WRITE/...) instead of collapsing to MODBUS_UNSUPPORTED.
  1.0.2  Decoy ports are now off by default: MOTH listens only on the Modbus port (502).
         Ping / ARP / port-scan detection is unchanged (sniffer).  --decoy LIST re-enables them.
  1.0.1  STATUS lines no longer printed to the console by default (--status-interval now
         defaults to 0; pass a value to opt back in).
  1.0.0  Initial release.  Modbus/TCP lift-station emulation (FC 1,2,3,4,5,6,8,15,16,
         17,23,43/14), M340 / MicroLogix / generic identities, raw-socket sniffer for
         ping/ARP/scan/stealth-probe detection, decoy service ports, text alert log,
         optional syslog (RFC 3164/5424) and JSON-lines output, --list-map, --test-alert.
"""

import argparse
import datetime as _dt
import json
import math
import os
import platform
import queue
import random
import select
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque

__version__ = "0.2.0"
TOOL_NAME = "MOTH"
TOOL_LONG = "Modbus Observation & Threat Honeypot"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MODBUS_PORT = 502
DEFAULT_DECOY_PORTS = [21, 22, 23, 80, 102, 443, 20000, 44818]
DEFAULT_LOG = "moth_alerts.log"

SCAN_WINDOW_S = 30          # sliding window for port-scan detection
SCAN_THRESHOLD = 5          # distinct ports from one source inside the window
ARP_SWEEP_THRESHOLD = 8     # distinct target IPs from one sender inside the window
DEFAULT_THROTTLE_S = 10     # suppress identical PING / probe alerts for this long
MODBUS_IDLE_TIMEOUT = 300   # seconds before an idle Modbus connection is dropped
MAX_PDU = 253

# Sensor health (v0.2.0)
DEFAULT_HEARTBEAT_S = 900   # HEARTBEAT to log + syslog every 15 min (never the console)
IP_REFRESH_S = 30           # how often the watchdog re-reads this host's IPv4 addresses
RETRY_MIN_S = 5             # first capture-reopen delay after a failure ...
RETRY_MAX_S = 60            # ... doubling up to this cap
STALL_S = 600               # no packets at all for this long -> reopen capture as a precaution
PCAP_ERROR_RUN = 50         # consecutive instant empty reads from pcap = error state, not timeout
SHUTDOWN_WAIT_S = 4.5       # Windows kills a closing console app ~5 s after the close event
CONSOLE_QUEUE_MAX = 5000    # console lines buffered while the console is blocked

# Data store sizes (0-based addresses)
N_COILS = 64
N_DISCRETE = 64
N_INPUT_REGS = 64
N_HOLDING_REGS = 128

# Ignore chatty broadcast/multicast UDP so it never looks like a scan
UDP_NOISE_PORTS = {67, 68, 137, 138, 1900, 5353, 5355, 3702}

# Modbus function names
FC_NAMES = {
    1: "READ_COILS", 2: "READ_DISCRETE_INPUTS", 3: "READ_HOLDING_REGISTERS",
    4: "READ_INPUT_REGISTERS", 5: "WRITE_SINGLE_COIL", 6: "WRITE_SINGLE_REGISTER",
    7: "READ_EXCEPTION_STATUS", 8: "DIAGNOSTICS", 11: "GET_COMM_EVENT_COUNTER",
    12: "GET_COMM_EVENT_LOG", 15: "WRITE_MULTIPLE_COILS", 16: "WRITE_MULTIPLE_REGISTERS",
    17: "REPORT_SERVER_ID", 20: "READ_FILE_RECORD", 21: "WRITE_FILE_RECORD",
    22: "MASK_WRITE_REGISTER", 23: "READ_WRITE_MULTIPLE_REGISTERS", 24: "READ_FIFO_QUEUE",
    43: "ENCAPSULATED_INTERFACE_TRANSPORT", 90: "UMAS_SCHNEIDER_PRIVATE",
}
EXC_NAMES = {
    1: "ILLEGAL_FUNCTION", 2: "ILLEGAL_DATA_ADDRESS", 3: "ILLEGAL_DATA_VALUE",
    4: "SERVER_DEVICE_FAILURE", 10: "GATEWAY_PATH_UNAVAILABLE", 11: "GATEWAY_TARGET_FAILED",
}

# Function-code classes (Modbus Application Protocol v1.1b3, section 5).  The class
# sets the alert kind and severity whether the request succeeded or got an exception.
WRITE_FCS = (5, 6, 15, 16, 21, 22, 23)
READ_FCS = (1, 2, 3, 4, 20, 24)
IDENT_FCS = (17, 43)
DIAG_FCS = (7, 8, 11, 12)
# FC 8 sub-functions that change the device's comm state (spec 6.8.1) -> CRIT
FC8_SUBS = {0: "RETURN_QUERY_DATA", 1: "RESTART_COMM_OPTION", 2: "RETURN_DIAG_REGISTER",
            3: "CHANGE_ASCII_DELIMITER", 4: "FORCE_LISTEN_ONLY_MODE", 10: "CLEAR_COUNTERS"}
FC8_DISRUPTIVE = (1, 3, 4, 10)

# Tag names -- what each address means on the lift station.  Used in alerts so
# a reader sees "addr=0 (P1_RUN_CMD)" rather than a bare number.
COIL_TAGS = {
    0: "P1_RUN_CMD", 1: "P2_RUN_CMD", 2: "P3_RUN_CMD",
    3: "P1_AUTO_MODE", 4: "P2_AUTO_MODE", 5: "P3_AUTO_MODE",
    6: "ALARM_HORN", 7: "ALARM_ACK", 8: "GENERATOR_RUN_CMD", 9: "FLUSH_VALVE_OPEN",
    10: "REMOTE_ENABLE", 11: "STATION_LOCKOUT",
}
DISCRETE_TAGS = {
    0: "P1_RUNNING", 1: "P2_RUNNING", 2: "P3_RUNNING",
    3: "P1_FAULT", 4: "P2_FAULT", 5: "P3_FAULT",
    6: "HIGH_LEVEL_FLOAT", 7: "HIGH_HIGH_FLOAT", 8: "LOW_LEVEL_FLOAT", 9: "LOW_LOW_FLOAT",
    10: "UTILITY_POWER_OK", 11: "GENERATOR_RUNNING", 12: "HATCH_OPEN",
    13: "P1_SEAL_LEAK", 14: "P2_SEAL_LEAK", 15: "P3_SEAL_LEAK",
    16: "FLOW_METER_OK", 17: "SCADA_COMM_OK", 18: "FLUSH_VALVE_OPENED", 19: "GEN_FUEL_LOW",
}
INPUT_REG_TAGS = {
    0: "WET_WELL_LEVEL_x100ft", 1: "INFLUENT_FLOW_gpm", 2: "DISCHARGE_FLOW_gpm",
    3: "P1_AMPS_x10", 4: "P2_AMPS_x10", 5: "P3_AMPS_x10",
    6: "P1_SPEED_pct", 7: "P2_SPEED_pct", 8: "P3_SPEED_pct",
    9: "DISCHARGE_PRESSURE_x10psi", 10: "WET_WELL_TEMP_x10F", 11: "H2S_ppm",
    12: "UTILITY_VOLTAGE_V", 13: "GEN_FUEL_pct",
    14: "P1_RUN_HOURS_HI", 15: "P1_RUN_HOURS_LO", 16: "P2_RUN_HOURS_HI", 17: "P2_RUN_HOURS_LO",
    18: "P3_RUN_HOURS_HI", 19: "P3_RUN_HOURS_LO",
    20: "P1_STARTS_HI", 21: "P1_STARTS_LO", 22: "P2_STARTS_HI", 23: "P2_STARTS_LO",
    24: "P3_STARTS_HI", 25: "P3_STARTS_LO",
    26: "TOTAL_FLOW_TODAY_HI_gal", 27: "TOTAL_FLOW_TODAY_LO_gal",
    28: "PLC_SCAN_TIME_ms", 29: "PLC_UPTIME_HI_s", 30: "PLC_UPTIME_LO_s",
    31: "ACTIVE_ALARM_COUNT",
}
HOLDING_REG_TAGS = {
    0: "LEAD_START_LEVEL_x100ft", 1: "LAG_START_LEVEL_x100ft", 2: "LAG2_START_LEVEL_x100ft",
    3: "ALL_STOP_LEVEL_x100ft", 4: "HIGH_ALARM_LEVEL_x100ft", 5: "HIGH_HIGH_LEVEL_x100ft",
    6: "LOW_ALARM_LEVEL_x100ft", 7: "ALTERNATION_MODE", 8: "LEAD_PUMP_NUMBER",
    9: "MAX_RUN_TIME_min", 10: "VFD_MIN_SPEED_pct", 11: "VFD_MAX_SPEED_pct",
    12: "LEVEL_SETPOINT_x100ft", 13: "PID_KP_x100", 14: "PID_KI_x100", 15: "PID_KD_x100",
    16: "ALARM_DELAY_s", 17: "HMI_HEARTBEAT", 18: "STATION_ID", 19: "APP_REVISION_x100",
    20: "SCADA_POLL_RATE_s", 21: "DRY_RUN_TRIP_s",
}
STATION_NAME = "LS-07 MAPLE CREEK PS"   # packed into holding registers 40..49
STATION_NAME_HR = 40

DEVICE_PROFILES = {
    "m340": {
        "desc": "Schneider Electric Modicon M340 (BMX P34 2020) -- lift station",
        "vendor": "Schneider Electric", "product_code": "BMX P34 2020",
        "revision": "V2.70", "vendor_url": "http://www.schneider-electric.com",
        "product_name": "Modicon M340", "model_name": "BMXP342020",
        "app_name": "LS07_MAPLECREEK",
        "server_id": b"\xB6", "supports_devid": True, "supports_report_id": True,
        "http_banner": "Schneider-WEB/V2.1.3",
    },
    "micrologix": {
        "desc": "Allen-Bradley MicroLogix 1400 (1766-L32BXB) -- lift station",
        "vendor": "Rockwell Automation/Allen-Bradley", "product_code": "1766-L32BXB",
        "revision": "21.00", "vendor_url": "http://www.rockwellautomation.com",
        "product_name": "MicroLogix 1400", "model_name": "1766-L32BXB",
        "app_name": "LS07_MAPLECREEK",
        "server_id": b"\x0E", "supports_devid": False, "supports_report_id": False,
        "http_banner": "A-B WWW/0.1",
    },
    "generic": {
        "desc": "Generic Modbus/TCP controller -- lift station",
        "vendor": "Modbus Device", "product_code": "MB-TCP-01",
        "revision": "1.00", "vendor_url": "", "product_name": "Modbus TCP Controller",
        "model_name": "MB-TCP-01", "app_name": "LIFT_STATION",
        "server_id": b"\x01", "supports_devid": True, "supports_report_id": True,
        "http_banner": "httpd",
    },
}

# Alert severities -> syslog severity numbers (RFC 5424 table)
# INFO < NOTICE < WARN < HIGH < CRIT
SEVERITY = {"INFO": 6, "NOTICE": 5, "WARN": 4, "HIGH": 3, "CRIT": 2}
SYSLOG_FACILITIES = {
    "kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5, "security": 13,
    "local0": 16, "local1": 17, "local2": 18, "local3": 19,
    "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

# ---------------------------------------------------------------------------
# Console colour
# ---------------------------------------------------------------------------

class C:
    """ANSI colour helper.  Bright white body text; degrades to plain."""
    enabled = True
    RESET = "\033[0m"; BOLD = "\033[1m"
    WHITE = "\033[97m"; RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"; DIM = "\033[2m"
    ORANGE = "\033[38;5;208m"

    @classmethod
    def setup(cls, want_color):
        if not want_color or sys.stdout is None or not sys.stdout.isatty():
            cls.enabled = False
            return
        if os.name == "nt":
            try:                       # enable VT processing on Windows 10+
                import ctypes
                k32 = ctypes.windll.kernel32
                h = k32.GetStdHandle(-11)
                mode = ctypes.c_uint32()
                if not (k32.GetConsoleMode(h, ctypes.byref(mode))
                        and k32.SetConsoleMode(h, mode.value | 0x0004)):
                    cls.enabled = False        # Windows 7 / 8.1: no VT mode -> plain text
            except Exception:
                cls.enabled = False

    @classmethod
    def c(cls, color, text):
        if not cls.enabled:
            return text
        return color + text + cls.RESET


SEV_COLOR = {"INFO": C.CYAN, "NOTICE": C.GREEN, "WARN": C.YELLOW, "HIGH": C.ORANGE, "CRIT": C.RED}


def now_str(ms=True):
    t = _dt.datetime.now()
    return t.strftime("%Y-%m-%d %H:%M:%S") + (".%03d" % (t.microsecond // 1000) if ms else "")


def printable(data, limit=48):
    """Render bytes as a safe printable snippet for logs."""
    data = data[:limit]
    txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return "%s hex=%s" % (txt, data.hex())


def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return "%dd%02dh%02dm" % (d, h, m)
    if h:
        return "%dh%02dm" % (h, m)
    if m:
        return "%dm%02ds" % (m, s)
    return "%ds" % s


# ---------------------------------------------------------------------------
# Console output (own thread) and Windows console mode
# ---------------------------------------------------------------------------

class ConsoleWriter(threading.Thread):
    """Prints on its own thread so a stalled console can never stall MOTH.

    In a classic Windows console a mouse click starts a QuickEdit selection, and
    every write to the console blocks until the selection ends.  A pipe nobody
    reads does the same on any OS.  Before v0.2.0 that froze the Modbus server
    and the sniffer, because they printed while holding the alert lock.  Lines are
    now queued; if the queue fills, console lines are dropped and counted -- the
    log file and syslog still get every alert.
    """

    def __init__(self, maxlen=CONSOLE_QUEUE_MAX):
        super().__init__(name="console", daemon=True)
        self.q = queue.Queue(maxsize=maxlen)
        self._drop_lock = threading.Lock()
        self.dropped = 0
        self.dead = False

    def put(self, text):
        if self.dead:
            return
        try:
            self.q.put_nowait(text)
        except queue.Full:
            with self._drop_lock:
                self.dropped += 1

    def run(self):
        while True:
            item = self.q.get()
            if item is None:
                return
            with self._drop_lock:
                dropped, self.dropped = self.dropped, 0
            if dropped:
                self._write(C.c(C.YELLOW, "[console] %d line(s) not shown while the console was blocked "
                                          "-- every alert is in the log file" % dropped))
            if not self._write(item):
                self.dead = True             # console gone (window closed / broken pipe)
                return

    @staticmethod
    def _write(text):
        try:
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            return True
        except UnicodeEncodeError:           # legacy code page
            try:
                sys.stdout.write(text.encode("ascii", "replace").decode("ascii") + "\n")
                sys.stdout.flush()
                return True
            except Exception:
                return False
        except (OSError, ValueError, AttributeError):    # AttributeError: pythonw (no stdout)
            return False

    def close(self, timeout=1.0):
        try:
            self.q.put_nowait(None)
        except queue.Full:
            pass                             # writer is stuck on a blocked console: don't wait on it
        self.join(timeout)


class WinConsoleMode:
    """Windows only: switch QuickEdit off while MOTH runs and put it back on exit.

    The console mode belongs to the console window, not the process, so it must be
    restored or the operator's cmd window stays changed after MOTH exits.
    """
    ENABLE_QUICK_EDIT_MODE = 0x0040
    ENABLE_EXTENDED_FLAGS = 0x0080

    def __init__(self):
        self._saved = None
        self._handle = None

    _dll = None

    @classmethod
    def _k32(cls):
        import ctypes
        from ctypes import wintypes
        if cls._dll is None:        # private handle: never retype the shared ctypes.windll objects
            cls._dll = ctypes.WinDLL("kernel32", use_last_error=True)
        k32 = cls._dll
        k32.GetStdHandle.restype = wintypes.HANDLE
        k32.GetStdHandle.argtypes = [wintypes.DWORD]
        k32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        return ctypes, wintypes, k32

    def disable_quickedit(self):
        """Returns True if QuickEdit was on and is now off."""
        if os.name != "nt":
            return False
        try:
            ctypes, wintypes, k32 = self._k32()
            h = k32.GetStdHandle(wintypes.DWORD(-10 & 0xFFFFFFFF))     # STD_INPUT_HANDLE
            mode = wintypes.DWORD()
            if not h or not k32.GetConsoleMode(h, ctypes.byref(mode)):
                return False                 # no console: redirected, or a scheduled task
            if not mode.value & self.ENABLE_QUICK_EDIT_MODE:
                return False
            new = (mode.value | self.ENABLE_EXTENDED_FLAGS) & ~self.ENABLE_QUICK_EDIT_MODE
            if k32.SetConsoleMode(h, new):
                self._saved, self._handle = mode.value, h
                return True
        except Exception:
            pass
        return False

    def restore(self):
        if self._saved is None:
            return
        try:
            _, _, k32 = self._k32()
            k32.SetConsoleMode(self._handle, self._saved | self.ENABLE_EXTENDED_FLAGS)
        except Exception:
            pass
        self._saved = None


# ---------------------------------------------------------------------------
# Syslog sender (stdlib UDP, RFC 3164 / RFC 5424)
# ---------------------------------------------------------------------------

class SyslogSender:
    def __init__(self, host, port=514, facility="local0", fmt="rfc3164", hostname=None):
        self.host = host
        self.port = port
        self.facility = SYSLOG_FACILITIES.get(facility, 16)
        self.fmt = fmt
        self.hostname = (hostname or socket.gethostname().split(".")[0] or "moth")
        self.pid = os.getpid()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.errors = 0
        self.sent = 0
        self._addr = None
        self._next_resolve = 0.0
        self.resolve_error = None
        self._resolve()

    def _resolve(self):
        """Look the collector up once.  Passing a hostname to every sendto() re-resolved
        it per alert, so with DNS down (common on isolated OT networks) every alerting
        thread -- Modbus and capture included -- stalled for a DNS timeout.  A failed
        lookup is retried at most once a minute; messages in between are dropped."""
        self._next_resolve = time.time() + 60
        try:
            self._addr = socket.getaddrinfo(self.host, self.port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
            self.resolve_error = None
        except (OSError, UnicodeError) as exc:
            self.resolve_error = first_line(exc)

    def send(self, sev_num, msg):
        pri = self.facility * 8 + sev_num
        if self.fmt == "rfc5424":
            ts = _dt.datetime.now().astimezone().isoformat(timespec="milliseconds")
            line = "<%d>1 %s %s moth %d - - %s" % (pri, ts, self.hostname, self.pid, msg)
        else:
            ts = _dt.datetime.now().strftime("%b %d %H:%M:%S")
            if ts[4] == "0":            # RFC 3164 wants a space-padded day
                ts = ts[:4] + " " + ts[5:]
            line = "<%d>%s %s moth[%d]: %s" % (pri, ts, self.hostname, self.pid, msg)
        if self._addr is None:
            if time.time() < self._next_resolve:
                self.errors += 1
                return
            self._resolve()
            if self._addr is None:
                self.errors += 1
                return
        try:
            self.sock.sendto(line.encode("utf-8", "replace")[:2048], self._addr)
            self.sent += 1
        except OSError:
            self.errors += 1

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Alert engine
# ---------------------------------------------------------------------------

class AlertEngine:
    """Formats, throttles, files and forwards alerts; hands console lines to ConsoleWriter.

    File and JSON writes happen under the lock (local disk, fast).  Console output
    never does -- it is queued -- so nothing on the console can stall the threads
    that answer Modbus or capture packets.
    """

    def __init__(self, log_path, syslog=None, json_path=None, quiet=False,
                 throttle_s=DEFAULT_THROTTLE_S, modbus_throttle_s=0):
        self.lock = threading.Lock()
        self.quiet = quiet
        self.syslog = syslog
        self.throttle_s = throttle_s
        self.modbus_throttle_s = modbus_throttle_s
        self.counts = {}
        self.total = 0
        self._last = {}          # throttle key -> [last_emit_time, suppressed_count]
        self.log_path = log_path
        self.json_path = json_path
        self.closed = False
        self.logf = open(log_path, "a", encoding="utf-8")
        self.jsonf = open(json_path, "a", encoding="utf-8") if json_path else None
        self.console = None
        if not quiet:
            self.console = ConsoleWriter()
            self.console.start()

    def _file(self, line, rec=None):
        """Write one line to the text log (and JSON log).  Caller holds self.lock."""
        if self.closed:
            return
        try:
            self.logf.write(line + "\n")
            self.logf.flush()
        except (OSError, ValueError):
            pass
        if self.jsonf and rec is not None:
            try:
                self.jsonf.write(json.dumps(rec, default=str) + "\n")
                self.jsonf.flush()
            except (OSError, ValueError):
                pass

    def console_line(self, text):
        """Queue a pre-formatted line for the console (no-op when quiet)."""
        if self.console is not None:
            self.console.put(text)

    def _throttle_window(self, kind):
        if kind.startswith("MODBUS_"):
            return self.modbus_throttle_s
        if kind in ("PING", "ARP_REQUEST", "STEALTH_PROBE", "DECOY_CONNECT"):
            return self.throttle_s
        return 0

    def alert(self, kind, severity, src, message, throttle_key=None, **fields):
        """Emit one alert.  Returns True if it was emitted, False if throttled."""
        window = self._throttle_window(kind)
        suffix = ""
        with self.lock:
            if window > 0:
                key = (kind, src, throttle_key)
                now = time.time()
                ent = self._last.get(key)
                if ent and now - ent[0] < window:
                    ent[1] += 1
                    return False
                if ent and ent[1]:
                    suffix = "  (+%d identical suppressed in last %ds)" % (ent[1], window)
                self._last[key] = [now, 0]
            self.total += 1
            self.counts[kind] = self.counts.get(kind, 0) + 1
            ts = now_str()
            line = "%s %-6s %-16s src=%s %s%s" % (ts, severity, kind, src, message, suffix)
            rec = {"ts": ts, "severity": severity, "kind": kind, "src": src, "message": message}
            rec.update(fields)
            self._file(line, rec)
            if self.console is not None:     # queued inside the lock so console order == log order
                col = SEV_COLOR.get(severity, C.WHITE)
                self.console.put(C.c(C.DIM, ts) + " " + C.c(col + C.BOLD, "%-6s" % severity) + " "
                                 + C.c(col, "%-16s" % kind) + " " + C.c(C.WHITE, "src=%s %s" % (src, message))
                                 + C.c(C.DIM, suffix))
        if self.syslog:
            self.syslog.send(SEVERITY.get(severity, 5), "%s %s src=%s %s" % (severity, kind, src, message))
        return True

    def info(self, message):
        """Operational (non-alert) console/log message."""
        ts = now_str()
        line = "%s %-6s %-16s %s" % (ts, "INFO", "MOTH", message)
        with self.lock:
            self._file(line)
            if self.console is not None:
                self.console.put(C.c(C.DIM, ts) + " " + C.c(C.BLUE, "MOTH  ") + " " + C.c(C.WHITE, message))

    def log_only(self, message):
        """Operational note for the text log only (no console, no syslog)."""
        with self.lock:
            self._file("%s %-6s %-16s %s" % (now_str(), "INFO", "MOTH", message))

    def heartbeat(self, message, **fields):
        """Sensor-alive record: text log, JSON log and syslog -- never the console.
        Not counted as an alert."""
        ts = now_str()
        line = "%s %-6s %-16s src=- %s" % (ts, "INFO", "HEARTBEAT", message)
        rec = {"ts": ts, "severity": "INFO", "kind": "HEARTBEAT", "src": "-", "message": message}
        rec.update(fields)
        with self.lock:
            self._file(line, rec)
        if self.syslog:
            self.syslog.send(SEVERITY["INFO"], "INFO HEARTBEAT src=- %s" % message)

    def close(self):
        if self.console is not None:
            self.console.close()
        with self.lock:
            self.closed = True
            for f in (self.logf, self.jsonf):
                if f:
                    try:
                        f.close()
                    except OSError:
                        pass
        if self.syslog:
            self.syslog.close()


# ---------------------------------------------------------------------------
# Scan / sweep trackers
# ---------------------------------------------------------------------------

class ScanTracker:
    """Sliding-window distinct-port counter per source IP."""

    def __init__(self, alerts, window=SCAN_WINDOW_S, threshold=SCAN_THRESHOLD):
        self.alerts = alerts
        self.window = window
        self.threshold = threshold
        self.lock = threading.Lock()
        self.hits = {}        # src -> deque of (t, proto, port)
        self.alerted = {}     # src -> distinct count at last alert

    def touch(self, src, proto, port):
        now = time.time()
        with self.lock:
            dq = self.hits.setdefault(src, deque())
            dq.append((now, proto, port))
            while dq and now - dq[0][0] > self.window:
                dq.popleft()
            if not dq:
                self.alerted.pop(src, None)
            ports = sorted({p for (_, _, p) in dq})
            n = len(ports)
            last = self.alerted.get(src, 0)
            if n >= self.threshold and (last == 0 or n >= last * 2):
                self.alerted[src] = n
                protos = sorted({pr for (_, pr, _) in dq})
                sample = ports[:12]
                more = "" if n <= 12 else " ...(+%d)" % (n - 12)
                self.alerts.alert(
                    "PORT_SCAN", "WARN", src,
                    "%d distinct ports in %ds proto=%s ports=%s%s" % (
                        n, self.window, "/".join(protos), sample, more),
                    distinct_ports=n, ports=ports, protocols=protos)


class ArpSweepTracker:
    def __init__(self, alerts, window=SCAN_WINDOW_S, threshold=ARP_SWEEP_THRESHOLD):
        self.alerts = alerts
        self.window = window
        self.threshold = threshold
        self.lock = threading.Lock()
        self.hits = {}
        self.alerted = {}

    def touch(self, sender_ip, sender_mac, target_ip):
        now = time.time()
        with self.lock:
            dq = self.hits.setdefault(sender_ip, deque())
            dq.append((now, target_ip))
            while dq and now - dq[0][0] > self.window:
                dq.popleft()
            targets = {t for (_, t) in dq}
            n = len(targets)
            last = self.alerted.get(sender_ip, 0)
            if n >= self.threshold and (last == 0 or n >= last * 2):
                self.alerted[sender_ip] = n
                self.alerts.alert("ARP_SWEEP", "WARN", sender_ip,
                                  "mac=%s asked for %d different hosts in %ds" % (sender_mac, n, self.window),
                                  targets=n)


# ---------------------------------------------------------------------------
# Modbus data store + lift-station process simulation
# ---------------------------------------------------------------------------

class DataStore:
    def __init__(self):
        self.lock = threading.RLock()
        self.coils = [0] * N_COILS
        self.discrete = [0] * N_DISCRETE
        self.input_regs = [0] * N_INPUT_REGS
        self.holding = [0] * N_HOLDING_REGS
        self.write_count = 0
        self._init_defaults()

    def _init_defaults(self):
        hr = self.holding
        hr[0] = 650; hr[1] = 750; hr[2] = 850; hr[3] = 300
        hr[4] = 900; hr[5] = 1000; hr[6] = 200
        hr[7] = 1; hr[8] = 1; hr[9] = 240; hr[10] = 60; hr[11] = 100
        hr[12] = 700; hr[13] = 180; hr[14] = 25; hr[15] = 5; hr[16] = 10
        hr[17] = 0; hr[18] = 7; hr[19] = 312; hr[20] = 2; hr[21] = 60
        name = STATION_NAME.encode("ascii")[:20].ljust(20, b" ")
        for i in range(10):
            hr[STATION_NAME_HR + i] = (name[2 * i] << 8) | name[2 * i + 1]
        co = self.coils
        co[3] = co[4] = co[5] = 1     # pumps in AUTO
        co[10] = 1                    # remote enable
        di = self.discrete
        di[10] = 1; di[16] = 1; di[17] = 1
        ir = self.input_regs
        ir[12] = 481; ir[13] = 87; ir[10] = 612; ir[11] = 3

    @staticmethod
    def split32(v):
        v = int(v) & 0xFFFFFFFF
        return (v >> 16) & 0xFFFF, v & 0xFFFF


class LiftStation(threading.Thread):
    """1-second physics tick for a 3-pump wastewater lift station."""

    GAL_PER_FT = 376.0        # 8 ft diameter wet well
    PUMP_CAP_GPM = 420.0      # each pump at 100 % speed
    WELL_DEPTH_FT = 12.0

    def __init__(self, store, seed=None):
        super().__init__(name="physics", daemon=True)
        self.store = store
        self.stop_evt = threading.Event()
        self.rng = random.Random(seed)
        self.level = 5.2
        self.running = [False, False, False]
        self.fault = [False, False, False]
        self.dry_secs = [0, 0, 0]
        self.run_secs = [0, 0, 0]
        self.runtime_s = [3_412_800 + self.rng.randint(0, 40000),
                          3_398_100 + self.rng.randint(0, 40000),
                          1_207_400 + self.rng.randint(0, 40000)]
        self.starts = [21_884 + self.rng.randint(0, 300),
                       21_713 + self.rng.randint(0, 300),
                       7_902 + self.rng.randint(0, 300)]
        self.flow_today = 0.0
        self.day = _dt.date.today()
        self.boot = time.time() - 86400 * 37 - self.rng.randint(0, 3600)
        self.influent = 180.0
        self.discharge = 0.0
        self.cycle_stopped = True

    def run(self):
        while not self.stop_evt.is_set():
            try:
                self.tick()
            except Exception as exc:       # never let the sim thread die silently
                sys.stderr.write("[physics] %s\n" % exc)
            self.stop_evt.wait(1.0)

    def tick(self):
        st = self.store
        with st.lock:
            hr, co, di, ir = st.holding, st.coils, st.discrete, st.input_regs
            rng = self.rng
            # --- influent: diurnal curve (min ~03:00, peak ~14:00) + noise
            tod = _dt.datetime.now()
            hour = tod.hour + tod.minute / 60.0
            base = 180 + 120 * math.sin(2 * math.pi * (hour - 8.5) / 24.0)
            self.influent = max(15.0, base + rng.gauss(0, 6))
            # --- setpoints (attacker-writable)
            lead_start = hr[0] / 100.0
            lag_start = hr[1] / 100.0
            lag2_start = hr[2] / 100.0
            stop_lvl = hr[3] / 100.0
            hi = hr[4] / 100.0; hh = hr[5] / 100.0; lo = hr[6] / 100.0
            alternate = hr[7] == 1
            lead = (hr[8] - 1) % 3
            vmin = max(0, min(100, hr[10])); vmax = max(vmin, min(100, hr[11]))
            dry_trip = max(5, hr[21])
            lockout = bool(co[11])
            order = [lead, (lead + 1) % 3, (lead + 2) % 3]
            starts = [lead_start, lag_start, lag2_start]
            # --- alarm ack (momentary)
            if co[7]:
                self.fault = [False, False, False]
                self.dry_secs = [0, 0, 0]
                co[6] = 0
                co[7] = 0
            # --- pump control
            new_running = list(self.running)
            for rank, p in enumerate(order):
                auto = bool(co[3 + p])
                if lockout or self.fault[p]:
                    new_running[p] = False
                elif auto:
                    if self.level >= starts[rank]:
                        new_running[p] = True
                    elif self.level <= stop_lvl:
                        new_running[p] = False
                else:
                    new_running[p] = bool(co[p])
            # alternation: when the whole station goes idle after a pumping cycle
            if any(self.running) and not any(new_running) and alternate:
                hr[8] = ((lead + 1) % 3) + 1
            for p in range(3):
                if new_running[p] and not self.running[p]:
                    self.starts[p] += 1
                    self.run_secs[p] = 0
            self.running = new_running
            # --- hydraulics
            span = max(0.5, hh - stop_lvl)
            speed_pct = vmin + (max(0.0, self.level - stop_lvl) / span) * (vmax - vmin)
            speed_pct = max(vmin, min(vmax, speed_pct))
            discharge = 0.0
            for p in range(3):
                if self.running[p]:
                    self.runtime_s[p] += 1
                    self.run_secs[p] += 1
                    eff = 1.0 if self.level > 0.6 else max(0.0, self.level / 0.6)
                    discharge += self.PUMP_CAP_GPM * (speed_pct / 100.0) * eff
                    if self.level < 0.5:
                        self.dry_secs[p] += 1
                        if self.dry_secs[p] >= dry_trip:
                            self.fault[p] = True
                            co[6] = 1
                    else:
                        self.dry_secs[p] = 0
            self.discharge = discharge
            self.level += (self.influent - discharge) / 60.0 / self.GAL_PER_FT
            self.level = max(0.0, min(self.WELL_DEPTH_FT, self.level))
            self.flow_today += discharge / 60.0
            if _dt.date.today() != self.day:
                self.day = _dt.date.today()
                self.flow_today = 0.0
            # --- discrete inputs
            for p in range(3):
                di[p] = 1 if self.running[p] else 0
                di[3 + p] = 1 if self.fault[p] else 0
                di[13 + p] = 0
            di[6] = 1 if self.level >= hi else 0
            di[7] = 1 if self.level >= hh else 0
            di[8] = 1 if self.level <= lo else 0
            di[9] = 1 if self.level <= 0.5 else 0
            di[11] = 1 if co[8] else 0
            di[18] = 1 if co[9] else 0
            if di[7]:
                co[6] = 1
            alarms = di[3] + di[4] + di[5] + di[6] + di[7] + di[8] + di[9] + di[19]
            # --- input registers
            ir[0] = int(self.level * 100)
            ir[1] = int(self.influent)
            ir[2] = int(discharge)
            for p in range(3):
                if self.running[p]:
                    amps = 4.0 + 28.0 * (speed_pct / 100.0) ** 2 + rng.gauss(0, 0.3)
                    ir[3 + p] = max(0, int(amps * 10))
                    ir[6 + p] = int(speed_pct)
                else:
                    ir[3 + p] = 0
                    ir[6 + p] = 0
            ir[9] = int((11.5 + 0.018 * discharge + rng.gauss(0, 0.15)) * 10) if discharge else int(4.2 * 10)
            ir[10] = int((61.2 + 0.4 * math.sin(2 * math.pi * (hour - 15) / 24) + rng.gauss(0, 0.05)) * 10)
            ir[11] = max(0, min(50, int(3 + (self.level - 4) * 0.8 + rng.gauss(0, 0.4))))
            ir[12] = int(480 + rng.gauss(0, 1.2))
            ir[13] = 87 if not co[8] else max(0, ir[13] - (1 if rng.random() < 0.01 else 0))
            for p in range(3):
                ir[14 + 2 * p], ir[15 + 2 * p] = DataStore.split32(self.runtime_s[p] // 3600)
                ir[20 + 2 * p], ir[21 + 2 * p] = DataStore.split32(self.starts[p])
            ir[26], ir[27] = DataStore.split32(self.flow_today)
            ir[28] = 4 + rng.randint(0, 3)
            ir[29], ir[30] = DataStore.split32(time.time() - self.boot)
            ir[31] = alarms
            di[19] = 1 if ir[13] < 20 else 0

    def status(self):
        pumps = "".join(
            ("F" if self.fault[p] else ("R" if self.running[p] else "-")) for p in range(3))
        return "level=%.2fft in=%3.0fgpm out=%3.0fgpm pumps[P1P2P3]=%s" % (
            self.level, self.influent, self.discharge, pumps)


# ---------------------------------------------------------------------------
# Modbus/TCP server
# ---------------------------------------------------------------------------

class ModbusException(Exception):
    def __init__(self, code):
        super().__init__(EXC_NAMES.get(code, str(code)))
        self.code = code


def tagname(table, addr):
    t = table.get(addr)
    return " (%s)" % t if t else ""


class ModbusProtocol:
    """Pure PDU handler.  Takes a PDU, returns (response_pdu, description, kind, severity)."""

    def __init__(self, store, profile, unit_id, reject_writes=False):
        self.store = store
        self.profile = profile
        self.unit_id = unit_id
        self.reject_writes = reject_writes

    # -- helpers
    @staticmethod
    def _pack_bits(bits):
        out = bytearray((len(bits) + 7) // 8)
        for i, b in enumerate(bits):
            if b:
                out[i // 8] |= 1 << (i % 8)
        return bytes(out)

    @staticmethod
    def _unpack_bits(data, n):
        return [(data[i // 8] >> (i % 8)) & 1 for i in range(n)]

    @staticmethod
    def _need(pdu, n):
        if len(pdu) < n:
            raise ModbusException(3)

    def handle(self, unit, pdu):
        """Returns (resp_pdu, description, kind, severity)."""
        fc = pdu[0]
        name = FC_NAMES.get(fc, "FC_%d" % fc)
        if unit not in (self.unit_id, 0, 255):
            desc = "unit=%d fc=%d %s %s -> EXC 0x0B GATEWAY_TARGET_FAILED (wrong unit id)" % (
                unit, fc, name, self._summ(pdu))
            return bytes([fc | 0x80, 0x0B]), desc, self._kind_for(fc), self._sev_for(pdu)
        try:
            handler = getattr(self, "fc_%d" % fc, None)
            if handler is None:
                raise ModbusException(1)
            resp, detail, kind, sev = handler(pdu)
            desc = "unit=%d fc=%d %s %s -> OK" % (unit, fc, name, detail)
            return resp, desc, kind, sev
        except ModbusException as exc:
            # Kind and severity follow what the client TRIED to do, not whether it worked:
            # a refused write is still a write attempt.
            note = " (writes rejected)" if exc.code == 1 and fc in WRITE_FCS and self.reject_writes else ""
            desc = "unit=%d fc=%d %s %s -> EXC 0x%02X %s%s" % (
                unit, fc, name, self._summ(pdu), exc.code, EXC_NAMES.get(exc.code, ""), note)
            return bytes([fc | 0x80, exc.code]), desc, self._kind_for(fc), self._sev_for(pdu)

    @staticmethod
    def _kind_for(fc):
        if fc in WRITE_FCS:
            return "MODBUS_WRITE"
        if fc in IDENT_FCS:
            return "MODBUS_IDENT"
        if fc in DIAG_FCS:
            return "MODBUS_DIAG"
        if fc in READ_FCS:
            return "MODBUS_READ"
        return "MODBUS_UNSUPPORTED"

    @staticmethod
    def _sev_for(pdu):
        """CRIT for anything that tries to change state; HIGH for every other request."""
        fc = pdu[0]
        if fc in WRITE_FCS:
            return "CRIT"
        if fc == 8 and len(pdu) >= 3 and struct.unpack(">H", pdu[1:3])[0] in FC8_DISRUPTIVE:
            return "CRIT"
        return "HIGH"

    @staticmethod
    def _summ(pdu):
        if pdu[0] == 8 and len(pdu) >= 3:
            sub, = struct.unpack(">H", pdu[1:3])
            return "sub=%d %s data=%s" % (sub, FC8_SUBS.get(sub, ""), pdu[3:].hex())
        if len(pdu) >= 5:
            a, q = struct.unpack(">HH", pdu[1:5])
            return "addr=%d qty/val=%d" % (a, q)
        return "pdu=%s" % pdu.hex()

    def _read_bits(self, pdu, table, tags, kind_label):
        self._need(pdu, 5)
        addr, qty = struct.unpack(">HH", pdu[1:5])
        if not 1 <= qty <= 2000:
            raise ModbusException(3)
        if addr + qty > len(table):
            raise ModbusException(2)
        with self.store.lock:
            bits = table[addr:addr + qty]
        data = self._pack_bits(bits)
        shown = bits[:16]
        detail = "%s addr=%d%s qty=%d vals=%s%s" % (
            kind_label, addr, tagname(tags, addr), qty, shown, "..." if qty > 16 else "")
        return bytes([pdu[0], len(data)]) + data, detail, "MODBUS_READ", "HIGH"

    def _read_regs(self, pdu, table, tags, kind_label):
        self._need(pdu, 5)
        addr, qty = struct.unpack(">HH", pdu[1:5])
        if not 1 <= qty <= 125:
            raise ModbusException(3)
        if addr + qty > len(table):
            raise ModbusException(2)
        with self.store.lock:
            regs = table[addr:addr + qty]
        data = struct.pack(">%dH" % qty, *regs)
        detail = "%s addr=%d%s qty=%d vals=%s%s" % (
            kind_label, addr, tagname(tags, addr), qty, regs[:10], "..." if qty > 10 else "")
        return bytes([pdu[0], len(data)]) + data, detail, "MODBUS_READ", "HIGH"

    def _check_writes(self):
        if self.reject_writes:
            raise ModbusException(1)

    # -- function codes
    def fc_1(self, pdu):
        return self._read_bits(pdu, self.store.coils, COIL_TAGS, "coils")

    def fc_2(self, pdu):
        return self._read_bits(pdu, self.store.discrete, DISCRETE_TAGS, "discrete")

    def fc_3(self, pdu):
        return self._read_regs(pdu, self.store.holding, HOLDING_REG_TAGS, "holding")

    def fc_4(self, pdu):
        return self._read_regs(pdu, self.store.input_regs, INPUT_REG_TAGS, "input")

    def fc_5(self, pdu):
        self._need(pdu, 5)
        self._check_writes()
        addr, val = struct.unpack(">HH", pdu[1:5])
        if val not in (0x0000, 0xFF00):
            raise ModbusException(3)
        if addr >= N_COILS:
            raise ModbusException(2)
        with self.store.lock:
            self.store.coils[addr] = 1 if val else 0
            self.store.write_count += 1
        detail = "coil addr=%d%s value=%s" % (addr, tagname(COIL_TAGS, addr), "ON" if val else "OFF")
        return pdu[:5], detail, "MODBUS_WRITE", "CRIT"

    def fc_6(self, pdu):
        self._need(pdu, 5)
        self._check_writes()
        addr, val = struct.unpack(">HH", pdu[1:5])
        if addr >= N_HOLDING_REGS:
            raise ModbusException(2)
        with self.store.lock:
            old = self.store.holding[addr]
            self.store.holding[addr] = val
            self.store.write_count += 1
        detail = "holding addr=%d%s value=%d (was %d)" % (addr, tagname(HOLDING_REG_TAGS, addr), val, old)
        return pdu[:5], detail, "MODBUS_WRITE", "CRIT"

    def fc_7(self, pdu):
        with self.store.lock:
            status = (self.store.discrete[6] << 0) | (self.store.discrete[7] << 1) | \
                     (self.store.discrete[3] << 2) | (self.store.discrete[4] << 3) | \
                     (self.store.discrete[5] << 4)
        return bytes([7, status & 0xFF]), "status=0x%02X" % status, "MODBUS_DIAG", "HIGH"

    def fc_8(self, pdu):
        self._need(pdu, 5)
        sub, = struct.unpack(">H", pdu[1:3])
        if sub == 0:                              # Return Query Data (echo)
            return pdu, "sub=0 RETURN_QUERY_DATA data=%s" % pdu[3:].hex(), "MODBUS_DIAG", "HIGH"
        raise ModbusException(1)

    def fc_15(self, pdu):
        self._need(pdu, 6)
        self._check_writes()
        addr, qty, bc = struct.unpack(">HHB", pdu[1:6])
        if not 1 <= qty <= 1968 or bc != (qty + 7) // 8 or len(pdu) < 6 + bc:
            raise ModbusException(3)
        if addr + qty > N_COILS:
            raise ModbusException(2)
        bits = self._unpack_bits(pdu[6:6 + bc], qty)
        with self.store.lock:
            for i, b in enumerate(bits):
                self.store.coils[addr + i] = b
            self.store.write_count += 1
        detail = "coils addr=%d%s qty=%d values=%s%s" % (
            addr, tagname(COIL_TAGS, addr), qty, bits[:16], "..." if qty > 16 else "")
        return pdu[:5], detail, "MODBUS_WRITE", "CRIT"

    def fc_16(self, pdu):
        self._need(pdu, 6)
        self._check_writes()
        addr, qty, bc = struct.unpack(">HHB", pdu[1:6])
        if not 1 <= qty <= 123 or bc != qty * 2 or len(pdu) < 6 + bc:
            raise ModbusException(3)
        if addr + qty > N_HOLDING_REGS:
            raise ModbusException(2)
        vals = list(struct.unpack(">%dH" % qty, pdu[6:6 + bc]))
        with self.store.lock:
            for i, v in enumerate(vals):
                self.store.holding[addr + i] = v
            self.store.write_count += 1
        detail = "holding addr=%d%s qty=%d values=%s%s" % (
            addr, tagname(HOLDING_REG_TAGS, addr), qty, vals[:10], "..." if qty > 10 else "")
        return pdu[:5], detail, "MODBUS_WRITE", "CRIT"

    def fc_17(self, pdu):
        if not self.profile["supports_report_id"]:
            raise ModbusException(1)
        extra = ("%s %s" % (self.profile["product_code"], self.profile["revision"])).encode("ascii")
        body = self.profile["server_id"] + b"\xFF" + extra      # server id, run indicator ON
        return bytes([17, len(body)]) + body, "server_id=%s run=ON" % self.profile["server_id"].hex(), \
            "MODBUS_IDENT", "HIGH"

    def fc_22(self, pdu):
        self._need(pdu, 7)
        self._check_writes()
        addr, andm, orm = struct.unpack(">HHH", pdu[1:7])
        if addr >= N_HOLDING_REGS:
            raise ModbusException(2)
        with self.store.lock:
            old = self.store.holding[addr]
            new = (old & andm) | (orm & ~andm & 0xFFFF)
            self.store.holding[addr] = new
            self.store.write_count += 1
        detail = "holding addr=%d%s and=0x%04X or=0x%04X -> %d (was %d)" % (
            addr, tagname(HOLDING_REG_TAGS, addr), andm, orm, new, old)
        return pdu[:7], detail, "MODBUS_WRITE", "CRIT"

    def fc_23(self, pdu):
        self._need(pdu, 10)
        self._check_writes()
        raddr, rqty, waddr, wqty, bc = struct.unpack(">HHHHB", pdu[1:10])
        if not 1 <= rqty <= 125 or not 1 <= wqty <= 121 or bc != wqty * 2 or len(pdu) < 10 + bc:
            raise ModbusException(3)
        if raddr + rqty > N_HOLDING_REGS or waddr + wqty > N_HOLDING_REGS:
            raise ModbusException(2)
        vals = list(struct.unpack(">%dH" % wqty, pdu[10:10 + bc]))
        with self.store.lock:
            for i, v in enumerate(vals):
                self.store.holding[waddr + i] = v
            self.store.write_count += 1
            regs = self.store.holding[raddr:raddr + rqty]
        data = struct.pack(">%dH" % rqty, *regs)
        detail = "write addr=%d%s values=%s ; read addr=%d qty=%d" % (
            waddr, tagname(HOLDING_REG_TAGS, waddr), vals[:10], raddr, rqty)
        return bytes([23, len(data)]) + data, detail, "MODBUS_WRITE", "CRIT"

    def fc_43(self, pdu):
        self._need(pdu, 4)
        mei, code, obj = pdu[1], pdu[2], pdu[3]
        if mei != 0x0E or not self.profile["supports_devid"]:
            raise ModbusException(1)
        p = self.profile
        objects = {0: p["vendor"], 1: p["product_code"], 2: p["revision"], 3: p["vendor_url"],
                   4: p["product_name"], 5: p["model_name"], 6: p["app_name"]}
        if code == 1:
            ids = [0, 1, 2]
        elif code == 2:
            ids = [0, 1, 2, 3, 4, 5, 6]
        elif code == 3:
            ids = list(range(7))
        elif code == 4:
            if obj not in objects:
                raise ModbusException(2)
            ids = [obj]
        else:
            raise ModbusException(3)
        ids = [i for i in ids if i >= obj] if code != 4 else ids
        body = bytearray([43, 0x0E, code, 0x83, 0x00, 0x00, len(ids)])   # conformity: extended + individual
        for i in ids:
            val = objects[i].encode("ascii", "replace")
            body += bytes([i, len(val)]) + val
        detail = "MEI=0x0E READ_DEVICE_ID code=%d obj=%d -> %s / %s / %s" % (
            code, obj, p["vendor"], p["product_code"], p["revision"])
        return bytes(body), detail, "MODBUS_IDENT", "HIGH"


class ModbusConnection(threading.Thread):
    def __init__(self, server, conn, addr):
        super().__init__(name="mb-%s:%d" % addr, daemon=True)
        self.server = server
        self.conn = conn
        self.addr = addr
        self.src = "%s:%d" % addr

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def run(self):
        alerts = self.server.alerts
        proto = self.server.proto
        self.conn.settimeout(MODBUS_IDLE_TIMEOUT)
        alerts.alert("MODBUS_CONNECT", "NOTICE", self.src, "TCP connection to Modbus port %d" % self.server.port)
        n_req = 0
        try:
            while not self.server.stop_evt.is_set():
                hdr = self._recv_exact(7)
                if hdr is None:
                    break
                tid, pid, length, unit = struct.unpack(">HHHB", hdr)
                if pid != 0 or not 2 <= length <= MAX_PDU + 1:
                    rest = b""
                    try:
                        self.conn.settimeout(0.5)
                        rest = self.conn.recv(256)
                    except OSError:
                        pass
                    alerts.alert("MODBUS_MALFORMED", "WARN", self.src,
                                 "bad MBAP header (proto=%d len=%d) data=%s" % (
                                     pid, length, printable(hdr + rest)))
                    break
                pdu = self._recv_exact(length - 1)
                if pdu is None or len(pdu) == 0:
                    alerts.alert("MODBUS_MALFORMED", "WARN", self.src, "truncated PDU after MBAP header")
                    break
                n_req += 1
                resp, desc, kind, sev = proto.handle(unit, pdu)
                alerts.alert(kind, sev, self.src, "tid=%d %s" % (tid, desc),
                             unit=unit, fc=pdu[0], tid=tid)
                self.server.requests += 1
                out = struct.pack(">HHHB", tid, 0, len(resp) + 1, unit) + resp
                self.conn.sendall(out)
        except socket.timeout:
            alerts.info("Modbus connection from %s idle %ds, closing" % (self.src, MODBUS_IDLE_TIMEOUT))
        except (ConnectionError, OSError) as exc:
            alerts.info("Modbus connection from %s dropped (%s)" % (self.src, exc.__class__.__name__))
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            alerts.alert("MODBUS_DISCONNECT", "INFO", self.src, "closed after %d request(s)" % n_req)


class ModbusServer(threading.Thread):
    def __init__(self, bind, port, proto, alerts, stop_evt):
        super().__init__(name="modbus-server", daemon=True)
        self.bind = bind
        self.port = port
        self.proto = proto
        self.alerts = alerts
        self.stop_evt = stop_evt
        self.requests = 0
        self.sock = None

    def start_listening(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, self.port))
        s.listen(16)
        s.settimeout(1.0)
        self.sock = s

    def run(self):
        while not self.stop_evt.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ModbusConnection(self, conn, addr).start()
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Decoy service listeners
# ---------------------------------------------------------------------------

DECOY_BANNERS = {
    21: b"220 FTP server ready.\r\n",
    22: b"SSH-2.0-dropbear_2019.78\r\n",
    23: b"\xff\xfb\x01\xff\xfb\x03\r\nlogin: ",
    25: b"220 mail ESMTP\r\n",
}


class DecoyListener(threading.Thread):
    def __init__(self, bind, port, alerts, scans, stop_evt, http_banner):
        super().__init__(name="decoy-%d" % port, daemon=True)
        self.bind = bind
        self.port = port
        self.alerts = alerts
        self.scans = scans
        self.stop_evt = stop_evt
        self.http_banner = http_banner
        self.sock = None

    def start_listening(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.bind, self.port))
        s.listen(8)
        s.settimeout(1.0)
        self.sock = s

    def run(self):
        while not self.stop_evt.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self, conn, addr):
        src = "%s:%d" % addr
        self.scans.touch(addr[0], "tcp", self.port)
        data = b""
        try:
            conn.settimeout(3.0)
            banner = DECOY_BANNERS.get(self.port)
            if banner:
                conn.sendall(banner)
            try:
                data = conn.recv(512)
            except (socket.timeout, OSError):
                data = b""
            if self.port in (80, 8080, 443) and data.startswith((b"GET", b"HEAD", b"POST")):
                body = ("<html><head><title>%s - Web Server</title></head><body>"
                        "<h2>%s</h2><p>Embedded web server. Authentication required.</p>"
                        "</body></html>" % (self.http_banner.split("/")[0], STATION_NAME)).encode()
                conn.sendall(b"HTTP/1.0 401 Unauthorized\r\nServer: " + self.http_banner.encode()
                             + b"\r\nWWW-Authenticate: Basic realm=\"PLC\"\r\nContent-Type: text/html\r\n"
                             + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
        msg = "decoy port %d" % self.port
        if data:
            msg += " received %d bytes: %s" % (len(data), printable(data))
        self.alerts.alert("DECOY_CONNECT", "WARN", src, msg, throttle_key=self.port,
                          port=self.port, bytes=len(data))


# ---------------------------------------------------------------------------
# Packet sniffer (Tier 1 detection)
# ---------------------------------------------------------------------------

def local_ipv4s():
    ips = set()
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    ips.add("127.0.0.1")
    return ips


def primary_ipv4():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def first_line(exc):
    txt = str(exc).strip()
    return txt.splitlines()[0] if txt else exc.__class__.__name__


WINDOWS_FIREWALL_WARNING = (
    "WARNING: SIO_RCVALL sits ABOVE Windows Defender Firewall.  Inbound pings and SYNs to "
    "closed ports are dropped by the firewall before MOTH sees them, so PING and PORT_SCAN "
    "alerts will be missing.  Fix: install Npcap (https://npcap.com) and 'pip install scapy' "
    "-- MOTH then captures below the firewall automatically.")


class Sniffer(threading.Thread):
    """Tier 1 packet capture.  Three engines feed one decoder:

         linux   -- AF_PACKET raw socket (stdlib, root): ARP + IP.
         pcap    -- scapy + Npcap (Windows) or libpcap/BPF: ARP + IP.  Npcap hooks the
                    NDIS driver stack BELOW Windows Defender Firewall, so pings and SYNs
                    the firewall drops are still seen.
         windows -- SIO_RCVALL raw IP socket (stdlib, Administrator): IP only, and only
                    what Windows Firewall lets through.
    """

    def __init__(self, local_ips, bind_ip, alerts, scans, arps, listening_ports, stop_evt,
                 engine="auto", allow_fallback=True, refresh_ifaces=False):
        super().__init__(name="sniffer", daemon=True)
        self.local_ips = set(local_ips)
        self.bind_ip = bind_ip
        self.alerts = alerts
        self.scans = scans
        self.arps = arps
        self.listening = set(listening_ports)
        self.stop_evt = stop_evt      # per-instance: the watchdog sets it to retire this engine
        self.engine = engine          # auto | pcap | raw
        self.allow_fallback = allow_fallback   # False on watchdog reopens: never silently downgrade
        self.refresh_ifaces = refresh_ifaces   # re-enumerate scapy interfaces (after a reset / IP change)
        self.sock = None              # stdlib raw socket (linux / windows modes)
        self.psock = None             # scapy listen socket (pcap mode)
        self.mode = None
        self.packets = 0
        self.last_packet = time.time()
        self.notes = []               # extra startup lines for the operator
        self.fail_reason = None       # why the capture loop died (None = asked to stop)
        self.retryable = True         # False when reopening cannot help (no privilege, no support)
        self._pcap_permanent = False
        self._raw_permanent = False

    # -- open
    def open(self):
        """Pick and open a capture engine.  Returns (ok, message); see self.notes too."""
        sysname = platform.system()
        tried_pcap = False
        if self.engine == "pcap" or (self.engine == "auto" and sysname != "Linux"):
            tried_pcap = True
            ok, msg = self._open_pcap()
            if ok:
                self.last_packet = time.time()
                return True, msg
            if not self.allow_fallback:
                self.retryable = not self._pcap_permanent
                return False, msg
            if sysname not in ("Linux", "Windows"):
                self.notes.append("pcap engine unavailable: %s" % msg)
            elif self.engine == "pcap":
                self.notes.append("pcap engine unavailable (%s) -- falling back to the raw socket" % msg)
            else:
                self.notes.append("Npcap engine not available (%s) -- falling back to SIO_RCVALL" % msg)
        ok, msg = self._open_raw(sysname)
        if ok:
            self.last_packet = time.time()
            if self.mode == "windows":
                self.notes.append(WINDOWS_FIREWALL_WARNING)
        else:
            # Worth retrying if either engine might come back (e.g. adapter not up yet).
            self.retryable = (not self._raw_permanent) or (tried_pcap and not self._pcap_permanent)
        return ok, msg

    def _open_pcap(self):
        """scapy + Npcap / libpcap.  Returns (ok, message)."""
        try:
            import logging
            for name in ("scapy", "scapy.runtime", "scapy.loading"):
                logging.getLogger(name).setLevel(logging.ERROR)   # keep scapy's import chatter quiet
            from scapy.all import conf
        except Exception as exc:                  # ImportError, or a broken install
            self._pcap_permanent = True
            return False, "scapy not installed (%s)" % first_line(exc)
        if platform.system() == "Windows" and not getattr(conf, "use_pcap", False):
            self._pcap_permanent = True
            return False, "scapy is installed but Npcap is not (https://npcap.com)"
        if self.refresh_ifaces:
            # scapy caches the adapter list at import; after sleep/resume or a new
            # DHCP lease it is stale.
            for fn in (lambda: conf.ifaces.reload(), lambda: conf.route.resync()):
                try:
                    fn()
                except Exception:
                    pass
        if not self.bind_ip or self.bind_ip in ("0.0.0.0", ""):
            self.bind_ip = primary_ipv4()
        iface = self._pcap_iface(conf, self.bind_ip)
        label = self._iface_label(iface)
        bpf = self._bpf()
        try:
            self.psock = self._pcap_listen(conf, iface, bpf)
        except PermissionError:
            return False, "capture on %s needs Administrator/root" % label
        except Exception as exc:
            # Filter compilation needs libpcap/Npcap or tcpdump; the decoder filters
            # anyway, so retry unfiltered before giving up.
            try:
                self.psock = self._pcap_listen(conf, iface, None)
                self.notes.append("pcap: BPF filter not applied (%s); filtering in Python" % first_line(exc))
            except PermissionError:
                return False, "capture on %s needs Administrator/root" % label
            except Exception as exc2:
                return False, "could not open capture on %s (%s)" % (label, first_line(exc2))
        self.mode = "pcap"
        if platform.system() == "Windows":
            lib = "Npcap" if getattr(conf, "use_npcap", False) else "WinPcap"
        else:
            lib = "libpcap" if getattr(conf, "use_pcap", False) else "native"
        try:
            import scapy
            ver = getattr(scapy, "VERSION", "") or getattr(scapy, "__version__", "")
        except Exception:
            ver = ""
        return True, "%s via scapy %s on %s [%s] (ARP, ping, TCP/UDP scan, stealth probes%s)" % (
            lib, ver, label, self.bind_ip,
            "; sees traffic before Windows Firewall" if platform.system() == "Windows" else "")

    @staticmethod
    def _pcap_listen(conf, iface, bpf):
        kw = {"iface": iface, "promisc": False}   # broadcasts + traffic to us is all MOTH needs
        if bpf:
            kw["filter"] = bpf
        try:
            return conf.L2listen(**kw)
        except TypeError:                         # very old scapy: no promisc keyword
            kw.pop("promisc")
            return conf.L2listen(**kw)

    @staticmethod
    def _pcap_iface(conf, ip):
        """The scapy interface that owns `ip`; falls back to scapy's default (route) interface."""
        if ip:
            try:                                  # scapy >= 2.4.5
                for ifc in conf.ifaces.values():
                    ips = [getattr(ifc, "ip", None)]
                    try:
                        ips += list(ifc.ips.get(4, []))
                    except Exception:
                        pass
                    if ip in ips:
                        return ifc
            except Exception:
                pass
            try:                                  # older scapy
                from scapy.all import get_if_list, get_if_addr
                for name in get_if_list():
                    if get_if_addr(name) == ip:
                        return name
            except Exception:
                pass
        return conf.iface

    @staticmethod
    def _iface_label(iface):
        for attr in ("description", "name"):
            val = getattr(iface, attr, None)
            if val:
                return str(val)
        return str(iface)

    def _bpf(self):
        ips = sorted(ip for ip in self.local_ips if ip)
        if not ips:
            return "arp or ip"
        return "arp or (ip and (%s))" % " or ".join("dst host %s" % ip for ip in ips)

    def _open_raw(self, sysname):
        """stdlib raw sockets.  Returns (ok, message)."""
        if sysname == "Linux":
            try:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.sock.settimeout(1.0)
                self.mode = "linux"
                return True, "AF_PACKET raw socket (ping, ARP, TCP/UDP scan, stealth probes)"
            except PermissionError:
                self._raw_permanent = True
                return False, "raw socket needs root (sudo)"
            except (OSError, AttributeError) as exc:
                return False, "could not open AF_PACKET socket (%s)" % exc
        if sysname == "Windows":
            if not self.bind_ip or self.bind_ip in ("0.0.0.0", "127.0.0.1"):
                self.bind_ip = primary_ipv4()
            if not self.bind_ip:
                return False, "could not determine an interface IP for SIO_RCVALL (network down? or use --ip)"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((self.bind_ip, 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                s.settimeout(1.0)
                self.sock = s
                self.mode = "windows"
                return True, "SIO_RCVALL raw socket on %s (ping, TCP/UDP scan, stealth probes; ARP via scapy if present)" % self.bind_ip
            except PermissionError:
                self._raw_permanent = True
                return False, "raw socket needs Administrator"
            except (OSError, AttributeError, ValueError) as exc:
                return False, "could not open raw socket on %s (%s)" % (self.bind_ip, exc)
        self._raw_permanent = True
        return False, "no stdlib raw-socket sniffer on %s (install scapy for BPF capture)" % sysname

    def close(self):
        if self.psock is not None:
            try:
                self.psock.close()
            except Exception:
                pass
        if self.sock:
            try:
                if self.mode == "windows":
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass

    # -- loop
    def run(self):
        if self.mode == "pcap":
            self._run_pcap()
            self.close()
            return
        linux = self.mode == "linux"
        outgoing = getattr(socket, "PACKET_OUTGOING", 4)
        while not self.stop_evt.is_set():
            try:
                if linux:
                    # AF_PACKET also delivers our own transmit copies; skip them so a frame
                    # looped through lo (or a bridge) is not counted twice.
                    pkt, sll = self.sock.recvfrom(65535)
                    if len(sll) > 2 and sll[2] == outgoing:
                        continue
                else:
                    pkt = self.sock.recv(65535)
            except socket.timeout:
                continue
            except OSError as exc:
                if not self.stop_evt.is_set():
                    self.fail_reason = "raw socket error: %s" % first_line(exc)
                break
            self.packets += 1
            self.last_packet = time.time()
            try:
                if self.mode == "linux":
                    self.handle_ethernet(pkt)
                else:
                    self.handle_ip(pkt)
            except Exception:
                pass          # malformed frame -- never let the sniffer thread die
        self.close()

    def _run_pcap(self):
        recv_raw = getattr(self.psock, "recv_raw", None)      # scapy >= 2.4.3: no dissection
        # Linux libpcap's 100 ms read timeout does not fire while NO packets arrive, so
        # a bare read on a silent link blocks forever and the engine cannot be stopped
        # or replaced.  On POSIX, wait on the capture fd with select() first.  (Npcap's
        # read timeout fires regardless, and its handle is not select()-able.)
        fd = None
        if platform.system() != "Windows":
            try:
                fd = self.psock.fileno()
            except Exception:
                fd = None
        instant_empty = 0
        while not self.stop_evt.is_set():
            if fd is not None:
                try:
                    ready, _, _ = select.select([fd], [], [], 1.0)
                except (OSError, ValueError) as exc:
                    if not self.stop_evt.is_set():
                        self.fail_reason = "capture error: %s" % first_line(exc)
                    break
                if not ready:
                    continue
            t0 = time.time()
            try:
                if recv_raw is not None:
                    cls, data, _ts = recv_raw()
                else:
                    p = self.psock.recv()
                    cls, data = (type(p), bytes(p)) if p is not None else (None, None)
            except Exception as exc:
                if not self.stop_evt.is_set():
                    self.fail_reason = "capture error: %s" % first_line(exc)
                break
            if not data:
                # Npcap/libpcap return empty after their 100 ms read timeout.  pcap_next_ex
                # errors (adapter reset or removed) come back INSTANTLY and look the same
                # through scapy, so a long run of instant empties means the handle is dead.
                if time.time() - t0 < 0.005:
                    instant_empty += 1
                    if instant_empty >= PCAP_ERROR_RUN:
                        if not self.stop_evt.is_set():
                            self.fail_reason = "capture handle returning errors (adapter reset or removed?)"
                        break
                    time.sleep(0.05)
                else:
                    instant_empty = 0
                continue
            instant_empty = 0
            self.packets += 1
            self.last_packet = time.time()
            try:
                self._handle_l2(cls, data)
            except Exception:
                pass          # malformed frame -- never let the sniffer thread die

    def _handle_l2(self, cls, data):
        """Dispatch a captured frame on the link type scapy reports."""
        name = getattr(cls, "__name__", "") if cls is not None else ""
        if name in ("IP", "IPv46"):                       # DLT_RAW (some VPN / tunnel adapters)
            self.handle_ip(data)
        elif name in ("Loopback", "LoopbackOld"):         # DLT_NULL: 4-byte address family
            self.handle_ip(data[4:])
        elif name == "CookedLinux" and len(data) >= 16:   # Linux 'any' / SLL
            proto = struct.unpack(">H", data[14:16])[0]
            if proto == 0x0806:
                self.handle_arp(data[16:])
            elif proto == 0x0800:
                self.handle_ip(data[16:])
        else:                                             # Ethernet (incl. Wi-Fi under Npcap)
            self.handle_ethernet(data)

    # -- parsers
    def handle_ethernet(self, frame):
        if len(frame) < 14:
            return
        eth_type = struct.unpack(">H", frame[12:14])[0]
        off = 14
        if eth_type == 0x8100 and len(frame) >= 18:        # 802.1Q
            eth_type = struct.unpack(">H", frame[16:18])[0]
            off = 18
        if eth_type == 0x0806:
            self.handle_arp(frame[off:])
        elif eth_type == 0x0800:
            self.handle_ip(frame[off:])

    def handle_arp(self, pkt):
        if len(pkt) < 28:
            return
        op = struct.unpack(">H", pkt[6:8])[0]
        sha = ":".join("%02x" % b for b in pkt[8:14])
        spa = socket.inet_ntoa(pkt[14:18])
        tpa = socket.inet_ntoa(pkt[24:28])
        if op != 1 or spa in self.local_ips:
            return
        if tpa in self.local_ips:
            self.alerts.alert("ARP_REQUEST", "NOTICE", spa, "who-has %s from mac=%s" % (tpa, sha),
                              mac=sha, target=tpa)
        self.arps.touch(spa, sha, tpa)

    def handle_ip(self, pkt):
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            return
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        src = socket.inet_ntoa(pkt[12:16])
        dst = socket.inet_ntoa(pkt[16:20])
        if src in self.local_ips or dst not in self.local_ips:
            return                        # our own traffic, or not aimed at us
        body = pkt[ihl:]
        if proto == 1 and len(body) >= 4:
            if body[0] == 8:               # echo request
                ident, seq = struct.unpack(">HH", body[4:8]) if len(body) >= 8 else (0, 0)
                self.alerts.alert("PING", "NOTICE", src, "ICMP echo request to %s id=%d seq=%d size=%d" % (
                    dst, ident, seq, len(body)), target=dst)
            elif body[0] == 13:
                self.alerts.alert("PING", "NOTICE", src, "ICMP timestamp request to %s (nmap -PP style)" % dst,
                                  throttle_key="ts", target=dst)
        elif proto == 6 and len(body) >= 14:
            sport, dport = struct.unpack(">HH", body[0:4])
            flags = body[13] & 0x3F
            syn, ack, fin, rst, psh, urg = (flags & 2, flags & 16, flags & 1, flags & 4, flags & 8, flags & 32)
            if syn and not ack:
                self.scans.touch(src, "tcp", dport)
            elif not syn and not ack and not rst:
                if flags == 0:
                    kind = "NULL"
                elif fin and psh and urg:
                    kind = "XMAS"
                elif fin and not psh and not urg:
                    kind = "FIN"
                else:
                    kind = "flags=0x%02X" % flags
                self.alerts.alert("STEALTH_PROBE", "WARN", src, "TCP %s scan probe to port %d" % (kind, dport),
                                  throttle_key=kind, port=dport, probe=kind)
                self.scans.touch(src, "tcp", dport)
        elif proto == 17 and len(body) >= 8:
            sport, dport = struct.unpack(">HH", body[0:4])
            if dport not in UDP_NOISE_PORTS:
                self.scans.touch(src, "udp", dport)


class ScapyArpSniffer(threading.Thread):
    """Windows-only optional ARP detection via scapy + Npcap."""

    def __init__(self, local_ips, alerts, arps, stop_evt):
        super().__init__(name="scapy-arp", daemon=True)
        self.local_ips = set(local_ips)
        self.alerts = alerts
        self.arps = arps
        self.stop_evt = stop_evt
        self.ok = False
        self.err = None
        try:
            import logging
            logging.getLogger("scapy").setLevel(logging.ERROR)
            from scapy.all import sniff, ARP, conf     # noqa
            self._sniff = sniff
            self._ARP = ARP
            if getattr(conf, "use_pcap", True):
                self.ok = True
            else:
                self.err = "Npcap not installed"
        except Exception as exc:                 # ImportError or Npcap missing
            self.err = first_line(exc)

    def _cb(self, pkt):
        try:
            a = pkt[self._ARP]
            if a.op != 1 or a.psrc in self.local_ips:
                return
            if a.pdst in self.local_ips:
                self.alerts.alert("ARP_REQUEST", "NOTICE", a.psrc, "who-has %s from mac=%s" % (a.pdst, a.hwsrc),
                                  mac=a.hwsrc, target=a.pdst)
            self.arps.touch(a.psrc, a.hwsrc, a.pdst)
        except Exception:
            pass

    def run(self):
        try:
            self._sniff(filter="arp", prn=self._cb, store=0,
                        stop_filter=lambda p: self.stop_evt.is_set())
        except Exception as exc:
            self.alerts.info("scapy ARP sniffer stopped: %s" % exc)


# ---------------------------------------------------------------------------
# Capture watchdog (Tier 1 sensor health)
# ---------------------------------------------------------------------------

class CaptureSupervisor(threading.Thread):
    """Keeps Tier 1 capture alive and says so when it is not.

    * An engine that dies (adapter reset, sleep/resume, driver error) is reopened
      with backoff, RETRY_MIN_S doubling to RETRY_MAX_S.  SENSOR_DOWN is raised once
      per outage, SENSOR_RESTORED when capture is back (with the outage length).
    * This host's IPv4 addresses are re-read every IP_REFRESH_S.  A change raises
      SENSOR_IP_CHANGE, updates the decoder at once, and reopens engines that are
      tied to an address (pcap BPF filter, SIO_RCVALL bind).
    * An engine that has seen no packet at all for STALL_S is reopened quietly
      (text-log note only): a dead handle and a silent network look the same.
    * Reopens use the engine that first worked, with no fallback, so Npcap is never
      silently swapped for the firewall-blind SIO_RCVALL socket.
    * A failure that reopening cannot fix (no privilege, unsupported OS) is
      reported once and not retried.
    """

    def __init__(self, args, alerts, scans, arps, listening, stop_evt, local_ips, pinned_ips):
        super().__init__(name="capture-watchdog", daemon=True)
        self.args = args
        self.alerts = alerts
        self.scans = scans
        self.arps = arps
        self.listening = listening
        self.stop_evt = stop_evt
        self.local_ips = set(local_ips)
        self.pinned_ips = set(pinned_ips)     # --bind / --ip addresses: always ours
        self.sniffer = None
        self.mode = None
        self.engine = args.capture            # engine to request on (re)open
        self.allow_fallback = True            # until an engine has worked once
        self.scapy_arp = None
        self._arp_checked = False
        self.down_since = None
        self.down_reason = None
        self.attempts = 0
        self.backoff = RETRY_MIN_S
        self.next_retry = 0.0
        self.given_up = False
        self.restarts = 0
        self._packets_retired = 0
        self._last_notes = []
        self._last_ip_check = time.time()

    # -- status for the heartbeat / status line
    @property
    def packets(self):
        sn = self.sniffer
        return self._packets_retired + (sn.packets if sn is not None else 0)

    def state(self):
        if self.given_up:
            return "off"
        if self.sniffer is None:
            return "DOWN(%s)" % fmt_duration(time.time() - (self.down_since or time.time()))
        return "up(%s)" % self.mode

    # -- open / adopt / retire
    def _new_sniffer(self, initial):
        return Sniffer(self.local_ips, self.args.ip or self.args.bind, self.alerts, self.scans,
                       self.arps, self.listening, threading.Event(), engine=self.engine,
                       allow_fallback=self.allow_fallback, refresh_ifaces=not initial)

    def _notes(self, notes):
        if notes and notes != self._last_notes:       # don't repeat the same warning every reopen
            for note in notes:
                self.alerts.info(note)
        self._last_notes = list(notes)

    def _adopt(self, sn):
        sn.start()
        self.sniffer = sn
        self.mode = sn.mode
        if self.allow_fallback:                       # lock in the engine that worked
            self.engine = "pcap" if sn.mode == "pcap" else "raw"
            self.allow_fallback = False
        if sn.mode == "windows" and not self._arp_checked:
            self._arp_checked = True
            arp = ScapyArpSniffer(self.local_ips, self.alerts, self.arps, self.stop_evt)
            if arp.ok:
                self.alerts.info("Tier 1 ARP: scapy/Npcap available -- ARP request detection enabled")
                arp.start()
                self.scapy_arp = arp
            else:
                self.alerts.info("Tier 1 ARP: not available on Windows without scapy + Npcap (%s)" % arp.err)

    def _retire(self, sn):
        """Ask an engine to stop and wait for it to close its own handle (closing a
        pcap handle from another thread while it is reading can crash libpcap)."""
        sn.stop_evt.set()
        sn.join(2.0)
        self._packets_retired += sn.packets
        if sn is self.sniffer:
            self.sniffer = None
            self.mode = None

    def start_initial(self):
        """First open, done synchronously so startup lines stay in order."""
        sn = self._new_sniffer(initial=True)
        ok, msg = sn.open()
        self._notes(sn.notes)
        if ok:
            self._adopt(sn)
            self.alerts.info("Tier 1 sniffer: " + msg)
            return True
        if not sn.retryable:
            self.given_up = True
            self.alerts.info("Tier 1 sniffer: %s.  Running decoy-only detection." % msg)
            return False
        self._mark_down(msg, initial=True)            # e.g. network not up yet at boot
        return False

    # -- outage handling
    def _mark_down(self, reason, initial=False):
        now = time.time()
        if self.down_since is None:
            self.down_since = now
            self.down_reason = reason
            self.attempts = 0
            self.backoff = RETRY_MIN_S
            self.alerts.alert(
                "SENSOR_DOWN", "WARN", "-",
                "Tier 1 capture %s (%s) -- pings, ARP and port scans are NOT being detected; "
                "retrying every %d-%ds" % ("not available" if initial else "lost", reason,
                                           RETRY_MIN_S, RETRY_MAX_S),
                reason=reason)
        self.next_retry = now + self.backoff

    def _try_reopen(self):
        if self.stop_evt.is_set():
            return
        sn = self._new_sniffer(initial=False)
        ok, msg = sn.open()
        if ok:
            outage = time.time() - (self.down_since or time.time())
            self._notes(sn.notes)
            self._adopt(sn)
            self.alerts.alert("SENSOR_RESTORED", "NOTICE", "-",
                              "Tier 1 capture back after %s (%d attempt(s)): %s" % (
                                  fmt_duration(outage), self.attempts + 1, msg),
                              outage_s=int(outage))
            self.down_since = self.down_reason = None
            self.attempts = 0
            self.backoff = RETRY_MIN_S
            return
        self.attempts += 1
        if not sn.retryable:
            self.given_up = True
            self.alerts.alert("SENSOR_DOWN", "WARN", "-",
                              "Tier 1 capture cannot be reopened (%s) -- not retrying; restart MOTH" % msg,
                              reason=msg)
            return
        if msg != self.down_reason:
            self.alerts.log_only("capture reopen attempt %d failed: %s" % (self.attempts, msg))
            self.down_reason = msg
        self.backoff = min(self.backoff * 2, RETRY_MAX_S)
        self.next_retry = time.time() + self.backoff

    def _restart(self, why, quiet=False):
        """Replace a running engine (address change, stall)."""
        if self.sniffer is not None:
            self._retire(self.sniffer)
        if self.stop_evt.is_set():                     # shutting down while we retired it
            return
        sn = self._new_sniffer(initial=False)
        ok, msg = sn.open()
        if ok and self.stop_evt.is_set():
            sn.close()
            return
        if ok:
            self._notes(sn.notes)
            self._adopt(sn)
            self.restarts += 1
            (self.alerts.log_only if quiet else self.alerts.info)(
                "Tier 1 capture reopened (%s): %s" % (why, msg))
        elif not sn.retryable:
            self.given_up = True
            self.alerts.alert("SENSOR_DOWN", "WARN", "-",
                              "Tier 1 capture cannot be reopened after %s (%s) -- not retrying" % (why, msg),
                              reason=msg)
        else:
            self._mark_down("%s; reopen failed: %s" % (why, msg))

    def _check_ips(self):
        fresh = local_ipv4s() | self.pinned_ips
        if fresh == self.local_ips:
            return
        added = sorted(fresh - self.local_ips)
        removed = sorted(self.local_ips - fresh)
        self.local_ips = fresh
        self.alerts.alert("SENSOR_IP_CHANGE", "NOTICE", "-",
                          "host addresses changed: added=%s removed=%s" % (
                              ",".join(added) or "-", ",".join(removed) or "-"),
                          added=added, removed=removed)
        if self.scapy_arp is not None:
            self.scapy_arp.local_ips = set(fresh)
        sn = self.sniffer
        if sn is None:
            if self.down_since is not None and not self.given_up:
                self.next_retry = time.time()          # new address: try again now
            return
        sn.local_ips = set(fresh)                      # decoder filter: effective immediately
        if sn.mode in ("pcap", "windows"):             # BPF filter / bind address are now stale
            self._restart("host address change")

    # -- loop
    def run(self):
        while not self.stop_evt.wait(1.0):
            try:
                self._tick()
            except Exception as exc:                   # the watchdog itself must never die
                self.alerts.log_only("capture watchdog error: %s" % first_line(exc))

    def _tick(self):
        if self.stop_evt.is_set():
            return
        now = time.time()
        if now - self._last_ip_check >= IP_REFRESH_S:
            self._last_ip_check = now
            self._check_ips()
        sn = self.sniffer
        if sn is not None and not sn.is_alive():
            self._retire(sn)
            self._mark_down(sn.fail_reason or "capture thread exited")
        elif sn is not None and sn.mode in ("pcap", "windows") and now - sn.last_packet > STALL_S:
            self._restart("no packets for %ds" % STALL_S, quiet=True)
        if (self.sniffer is None and not self.given_up and self.down_since is not None
                and now >= self.next_retry and not self.stop_evt.is_set()):
            self._try_reopen()

    def shutdown(self, budget=2.5):
        """Stop the watchdog and the running engine (which closes its own handle;
        SIO_RCVALL is switched off on the way out), within `budget` seconds."""
        end = time.time() + budget
        sn = self.sniffer
        if sn is not None:
            sn.stop_evt.set()
        if self.is_alive():
            self.join(max(0.1, (end - time.time()) / 2))   # may be mid-reopen
        sn = self.sniffer
        if sn is not None:
            sn.stop_evt.set()
            sn.join(max(0.1, end - time.time()))


# ---------------------------------------------------------------------------
# Shutdown handling (Windows console events, POSIX signals)
# ---------------------------------------------------------------------------

_CTRL_HANDLER_REFS = []     # module lifetime: the OS may call the handler during interpreter teardown


class Shutdown:
    """One place that turns 'the OS wants us gone' into an orderly stop.

    Windows: closing the console window sends CTRL_CLOSE_EVENT; Python ignores it
    and the process is killed ~5 s later with no summary and SIO_RCVALL still on.
    We catch it, set the stop event, and hold the handler until main() has written
    the summary and cleaned up.  (Windows delivers the logoff / shutdown events only
    to services, so an interactive console gets at most the close; a service or
    scheduled-task deployment is what makes logoff/shutdown clean.)
    Ctrl+C keeps Python's KeyboardInterrupt; Ctrl+Break is handled as a stop.
    POSIX: SIGTERM (systemd stop, kill) and SIGHUP (terminal closed) stop cleanly.
    SIGHUP is left alone when it is already ignored, so 'nohup moth.py &' still
    survives logout.
    """

    WIN_EVENTS = {2: "console window closed", 5: "user logoff", 6: "system shutdown"}

    def __init__(self, stop_evt):
        self.stop_evt = stop_evt
        self.done = threading.Event()
        self.reason = None
        self._win_cb = None                            # keep the ctypes callback alive

    def request(self, reason, wait=False):
        """Ask for a clean stop.  With wait=True, block until main() has finished
        cleaning up (or SHUTDOWN_WAIT_S passes) -- used by the Windows handler."""
        if self.reason is None:
            self.reason = reason
        self.stop_evt.set()
        if wait:
            self.done.wait(SHUTDOWN_WAIT_S)

    def install(self):
        """Returns a short description of what was hooked, for the startup log."""
        hooked = []
        # On Windows SIGTERM is never delivered (os.kill / taskkill /F use TerminateProcess).
        sigs = (("SIGBREAK", "Ctrl+Break"),) if os.name == "nt" else (("SIGTERM", "SIGTERM"), ("SIGHUP", "SIGHUP"))
        for name, label in sigs:
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                if name == "SIGHUP" and signal.getsignal(sig) == signal.SIG_IGN:
                    continue                           # nohup: respect it
                signal.signal(sig, lambda s, f, label=label: self.request(label))
                hooked.append(label)
            except (ValueError, OSError, RuntimeError):  # not the main thread, or not allowed
                pass
        if os.name == "nt":
            # Registered LAST so it runs before the C runtime's handler, which would map a
            # console close to SIGBREAK and return at once -- letting Windows kill us.
            try:
                import ctypes
                from ctypes import wintypes
                handler_t = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)

                def _handler(ctrl_type):
                    reason = self.WIN_EVENTS.get(ctrl_type)
                    if reason is None:
                        return False                   # Ctrl+C / Ctrl+Break: Python's own handling
                    self.request(reason, wait=True)
                    return True

                cb = handler_t(_handler)
                _CTRL_HANDLER_REFS.append(cb)          # never freed, never unregistered
                k32 = ctypes.WinDLL("kernel32", use_last_error=True)
                k32.SetConsoleCtrlHandler.argtypes = [handler_t, wintypes.BOOL]
                if k32.SetConsoleCtrlHandler(cb, True):
                    hooked.append("console close")
            except Exception:
                pass
        return ", ".join(hooked)


# ---------------------------------------------------------------------------
# CLI layer
# ---------------------------------------------------------------------------

def print_banner(args, profile):
    art = r"""
   __  __  ___ _____ _  _
  |  \/  |/ _ \_   _| || |    %s
  | |\/| | (_) || | | __ |    v%s
  |_|  |_|\___/ |_| |_||_|
""" % (TOOL_LONG, __version__)
    print(C.c(C.CYAN + C.BOLD, art))
    print(C.c(C.WHITE, "  Emulating : %s" % profile["desc"]))
    print(C.c(C.WHITE, "  Modbus    : %s:%d  unit=%d  (%s)" % (
        args.bind, args.port, args.unit, "writes REJECTED" if args.reject_writes else "writes accepted")))
    print(C.c(C.WHITE, "  Alert log : %s" % os.path.abspath(args.log)))
    if args.syslog:
        print(C.c(C.WHITE, "  Syslog    : %s:%d  facility=%s  %s" % (
            args.syslog, args.syslog_port, args.syslog_facility, args.syslog_format)))
    if args.json_log:
        print(C.c(C.WHITE, "  JSON log  : %s" % os.path.abspath(args.json_log)))
    print(C.c(C.YELLOW, "\n  AUTHORIZED USE ONLY -- training / research / monitoring on networks you are"
                        "\n  permitted to instrument.  Not for production networks where a decoy PLC"
                        "\n  could confuse operators or safety reviews.\n"))


def print_map():
    def table(title, tags, n):
        print(C.c(C.CYAN + C.BOLD, "\n%s (0-based, %d total)" % (title, n)))
        for a in sorted(tags):
            print(C.c(C.WHITE, "  %4d  %s" % (a, tags[a])))
    print(C.c(C.CYAN + C.BOLD, "%s v%s -- %s -- register map" % (TOOL_NAME, __version__, STATION_NAME)))
    table("COILS (FC1 read / FC5,15 write)", COIL_TAGS, N_COILS)
    table("DISCRETE INPUTS (FC2)", DISCRETE_TAGS, N_DISCRETE)
    table("INPUT REGISTERS (FC4)", INPUT_REG_TAGS, N_INPUT_REGS)
    table("HOLDING REGISTERS (FC3 read / FC6,16,22,23 write)", HOLDING_REG_TAGS, N_HOLDING_REGS)
    print(C.c(C.WHITE, "  %4d-%d  STATION_NAME (ASCII, 2 chars/reg) = '%s'" % (
        STATION_NAME_HR, STATION_NAME_HR + 9, STATION_NAME)))
    print(C.c(C.DIM, "\nLevels are x100 ft (650 = 6.50 ft).  Try: write LEAD_START_LEVEL lower and watch the pumps."))


def parse_ports(text):
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return sorted({p for p in out if 1 <= p <= 65535})


def build_parser():
    epilog = """
examples:
  python moth.py                                run with defaults (0.0.0.0:502, M340, sniffer on)
  python moth.py --syslog 10.10.5.20            forward every alert to a syslog collector (UDP 514)
  python moth.py --syslog siem.local --syslog-format rfc5424 --syslog-facility local3
  python moth.py --port 5020 --no-sniff         unprivileged demo on a high port
  python moth.py --profile micrologix           answer as an Allen-Bradley MicroLogix 1400
  python moth.py --decoy 21,22,23,80,102,443    also open decoy service ports (off by default)
  python moth.py --capture raw                  force the stdlib raw socket (compare with Npcap)
  python moth.py --list-map                     print the coil / register map and exit

detection tiers:
  Tier 1 packet capture -> ping, ARP, TCP/UDP port scans, NULL/FIN/XMAS probes.
          Windows: Npcap via scapy when installed (captures BELOW Windows Firewall, so pings
          and SYNs the firewall drops are still seen).  Without it MOTH falls back to an
          SIO_RCVALL raw socket (Administrator), which only sees what the firewall lets
          through -- pings and scans of closed ports go unseen.  Linux: AF_PACKET (root).
  Tier 2 (no privileges): the Modbus server itself, plus any --decoy ports you enable.
  If Tier 1 cannot start MOTH tells you why and keeps running on Tier 2 -- note that with
  no decoy ports, Tier 2 alone cannot see pings or scans, only Modbus connections.
  Traffic from MOTH's own addresses is ignored: test from a second machine.

sensor health:
  A watchdog reopens capture if it dies (sleep/resume, adapter reset, new DHCP lease) and raises
  SENSOR_DOWN / SENSOR_RESTORED / SENSOR_IP_CHANGE.  HEARTBEAT records go to the log and syslog
  every --heartbeat seconds (start / alive / stop) so a SIEM can alert on a silent sensor.
  Closing the console window, Ctrl+Break, SIGTERM and SIGHUP all stop MOTH cleanly.

severity: INFO < NOTICE < WARN < HIGH < CRIT.  Every Modbus request is HIGH or above;
  every write attempt (applied or refused) is CRIT.

DISCLAIMER: authorized use only.  Intended for training, research and monitoring on networks
you are permitted to instrument; not for production environments where safety or operational
availability cannot be guaranteed.
"""
    p = argparse.ArgumentParser(
        prog="moth.py",
        description="%s v%s -- %s" % (TOOL_NAME, __version__, TOOL_LONG),
        epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bind", default="0.0.0.0", help="address to listen on (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=DEFAULT_MODBUS_PORT, help="Modbus/TCP port (default 502)")
    p.add_argument("--unit", type=int, default=1, help="Modbus unit id to answer (0 and 255 also accepted)")
    p.add_argument("--profile", choices=sorted(DEVICE_PROFILES), default="m340",
                   help="device identity to present (default m340)")
    p.add_argument("--reject-writes", action="store_true",
                   help="answer every write function with exception 01 instead of applying it")
    p.add_argument("--decoy", default="none",
                   help="comma/range list of extra decoy TCP ports to listen on (default none: only the "
                        "Modbus port is open; e.g. --decoy %s)" % ",".join(str(x) for x in DEFAULT_DECOY_PORTS))
    p.add_argument("--no-sniff", action="store_true", help="disable the raw-socket sniffer (Tier 2 only)")
    p.add_argument("--capture", choices=["auto", "pcap", "raw"], default="auto",
                   help="Tier 1 engine: auto (Windows: Npcap via scapy if installed, else raw socket; "
                        "Linux: AF_PACKET), pcap (scapy + Npcap/libpcap), raw (stdlib raw socket)")
    p.add_argument("--ip", default=None, help="IP of the interface to sniff on (default: the default-route interface)")
    p.add_argument("--log", default=None, help="alert text log (default moth_alerts.log beside the script)")
    p.add_argument("--json-log", default=None, help="also write alerts as JSON lines to this file")
    p.add_argument("--syslog", default=None, help="syslog server host/IP to forward alerts to (UDP)")
    p.add_argument("--syslog-port", type=int, default=514, help="syslog UDP port (default 514)")
    p.add_argument("--syslog-facility", choices=sorted(SYSLOG_FACILITIES), default="local0",
                   help="syslog facility (default local0)")
    p.add_argument("--syslog-format", choices=["rfc3164", "rfc5424"], default="rfc3164",
                   help="syslog message format (default rfc3164)")
    p.add_argument("--throttle", type=int, default=DEFAULT_THROTTLE_S,
                   help="seconds to suppress identical PING/ARP/probe/decoy alerts (default %d, 0=off)" % DEFAULT_THROTTLE_S)
    p.add_argument("--modbus-throttle", type=int, default=0,
                   help="seconds to suppress identical Modbus request alerts (default 0 = log every one)")
    p.add_argument("--scan-threshold", type=int, default=SCAN_THRESHOLD,
                   help="distinct ports within %ds that count as a port scan (default %d)" % (SCAN_WINDOW_S, SCAN_THRESHOLD))
    p.add_argument("--status-interval", type=int, default=0,
                   help="seconds between process status lines on the console (default 0 = never shown)")
    p.add_argument("--heartbeat", type=int, default=DEFAULT_HEARTBEAT_S,
                   help="seconds between HEARTBEAT records to the log and syslog -- never the console "
                        "(default %d, 0 = off)" % DEFAULT_HEARTBEAT_S)
    p.add_argument("--keep-quickedit", action="store_true",
                   help="Windows: leave console QuickEdit on (by default it is switched off while MOTH "
                        "runs so a stray click cannot pause the console)")
    p.add_argument("--seed", type=int, default=None, help="random seed for the process simulation")
    p.add_argument("--list-map", action="store_true", help="print the coil/register map and exit")
    p.add_argument("--test-alert", action="store_true", help="emit one test alert through log/syslog and exit")
    p.add_argument("-q", "--quiet", action="store_true", help="no console alert output (log/syslog still written)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("-V", "--version", action="version", version="%s %s" % (TOOL_NAME, __version__))
    return p


_HARD_EXIT = [False]


def main(argv=None):
    args = build_parser().parse_args(argv)
    C.setup(not args.no_color and not args.quiet)
    profile = DEVICE_PROFILES[args.profile]
    if args.list_map:
        print_map()
        return 0
    if args.log is None:
        args.log = os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_LOG)

    syslog = None
    if args.syslog:
        try:
            syslog = SyslogSender(args.syslog, args.syslog_port, args.syslog_facility, args.syslog_format)
        except OSError as exc:
            print(C.c(C.RED, "Could not create syslog socket: %s" % exc))
            return 2
    try:
        alerts = AlertEngine(args.log, syslog, args.json_log, args.quiet, args.throttle, args.modbus_throttle)
    except OSError as exc:
        print(C.c(C.RED, "Cannot open alert log %s: %s" % (args.log, exc)))
        return 2

    if args.test_alert:
        alerts.alert("TEST", "INFO", "127.0.0.1", "MOTH test alert -- log/syslog pipeline check")
        print(C.c(C.GREEN, "Test alert written to %s%s" % (
            args.log, " and sent to %s:%d" % (args.syslog, args.syslog_port) if syslog else "")))
        alerts.close()
        return 0

    if not args.quiet:
        print_banner(args, profile)

    stop_evt = threading.Event()
    store = DataStore()
    proto = ModbusProtocol(store, profile, args.unit, args.reject_writes)
    scans = ScanTracker(alerts, SCAN_WINDOW_S, args.scan_threshold)
    arps = ArpSweepTracker(alerts)

    # -- Modbus server
    server = ModbusServer(args.bind, args.port, proto, alerts, stop_evt)
    try:
        server.start_listening()
    except PermissionError:
        print(C.c(C.RED, "Cannot bind port %d: permission denied.  Run as Administrator/root or use --port 5020." % args.port))
        alerts.close()
        return 2
    except OSError as exc:
        print(C.c(C.RED, "Cannot bind %s:%d: %s  (is something else listening on it?)" % (args.bind, args.port, exc)))
        alerts.close()
        return 2

    # -- decoys
    decoys = []
    listening = {args.port}
    if args.decoy.strip().lower() != "none":
        for port in parse_ports(args.decoy):
            if port == args.port:
                continue
            d = DecoyListener(args.bind, port, alerts, scans, stop_evt, profile["http_banner"])
            try:
                d.start_listening()
                decoys.append(d)
                listening.add(port)
            except OSError as exc:
                alerts.info("decoy port %d not available (%s) -- skipped" % (port, exc.strerror or exc))

    # -- Tier 1 capture under the watchdog
    pinned = {ip for ip in (args.bind, args.ip) if ip and ip not in ("0.0.0.0", "")}
    local_ips = local_ipv4s() | pinned
    supervisor = None
    if not args.no_sniff:
        supervisor = CaptureSupervisor(args, alerts, scans, arps, listening, stop_evt, local_ips, pinned)
        supervisor.start_initial()
    else:
        alerts.info("Tier 1 sniffer disabled (--no-sniff); decoy-only detection")
    if (supervisor is None or supervisor.given_up) and not decoys:
        alerts.info("WARNING: no sniffer and no decoy ports -- only Modbus connections to port %d "
                    "will be detected (pings and port scans will not be seen)" % args.port)

    physics = LiftStation(store, args.seed)

    # -- clean shutdown hooks
    shutdown = Shutdown(stop_evt)
    hooked = shutdown.install()
    console_mode = WinConsoleMode()
    started = time.time()

    def heartbeat(state, reason=None):
        ips = supervisor.local_ips if supervisor is not None else local_ips
        msg = "state=%s v=%s uptime=%s capture=%s pkts=%s alerts=%d modbus_req=%d writes=%d ips=%s" % (
            state, __version__, fmt_duration(time.time() - started),
            supervisor.state() if supervisor is not None else "off",
            supervisor.packets if supervisor is not None else "n/a",
            alerts.total, server.requests, store.write_count,
            ",".join(sorted(ip for ip in ips if not ip.startswith("127."))) or "-")
        if reason:
            msg += " reason=%s" % reason.replace(" ", "_")
        alerts.heartbeat(msg, state=state)

    try:
        if not args.quiet and not args.keep_quickedit and console_mode.disable_quickedit():
            alerts.info("Console QuickEdit is off while MOTH runs (a click in this window would pause "
                        "the console); it is restored on exit.  --keep-quickedit leaves it on.")
        if syslog is not None and syslog.resolve_error:
            alerts.info("WARNING: syslog host %s does not resolve (%s) -- alerts are logged locally; "
                        "the lookup is retried once a minute" % (args.syslog, syslog.resolve_error))
        alerts.info("MOTH v%s started  profile=%s  modbus=%s:%d  decoys=%s  local_ips=%s" % (
            __version__, args.profile, args.bind, args.port,
            ",".join(str(d.port) for d in decoys) or "none", ",".join(sorted(local_ips))))
        if hooked:
            alerts.log_only("clean-shutdown hooks: %s" % hooked)

        physics.start()
        server.start()
        for d in decoys:
            d.start()
        if supervisor is not None and not supervisor.given_up:
            supervisor.start()
        if args.heartbeat > 0:
            heartbeat("start")

        last_status = last_hb = time.time()
        while not stop_evt.is_set():
            time.sleep(0.5)
            now = time.time()
            if args.heartbeat > 0 and now - last_hb >= args.heartbeat:
                last_hb = now
                heartbeat("alive")
            if args.status_interval and now - last_status >= args.status_interval:
                last_status = now
                alerts.console_line(C.c(C.DIM, now_str()) + " " + C.c(C.MAGENTA, "STATUS") + " " + C.c(
                    C.WHITE, "%s  modbus_req=%d  writes=%d  alerts=%d  pkts=%s  capture=%s" % (
                        physics.status(), server.requests, store.write_count, alerts.total,
                        supervisor.packets if supervisor is not None else "n/a",
                        supervisor.state() if supervisor is not None else "off")))
    except KeyboardInterrupt:
        shutdown.request("Ctrl+C")
    finally:
        # A second Ctrl+C must not cut cleanup short (it would leave QuickEdit off in
        # the operator's window).  Everything here is time-boxed: a Windows console
        # close allows ~5 s in total, so the record is written first.
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except (ValueError, OSError, RuntimeError):
            pass
        try:
            stop_evt.set()
            physics.stop_evt.set()
            reason = shutdown.reason or "exit"
            summary = ", ".join("%s=%d" % (k, v) for k, v in sorted(alerts.counts.items())) or "none"
            alerts.info("MOTH stopping (%s).  Alerts: %d total (%s)" % (reason, alerts.total, summary))
            if args.heartbeat > 0:
                heartbeat("stop", reason)
            console_mode.restore()
            if supervisor is not None:
                supervisor.shutdown(budget=2.5)     # engines close their own handles; SIO_RCVALL off
            alerts.close()
        finally:
            console_mode.restore()                  # idempotent; covers an exception above
            shutdown.done.set()                     # releases a waiting Windows close handler
        # Only print directly if the console thread has finished: if it is stuck on a
        # blocked console it holds the stdout lock and this print would hang, and
        # interpreter exit would then abort trying to flush stdout.
        if alerts.console is not None and alerts.console.is_alive():
            _HARD_EXIT[0] = True
        elif not args.quiet:
            try:
                print(C.c(C.CYAN, "\nAlert log: %s" % os.path.abspath(args.log)))
                sys.stdout.flush()
            except Exception:
                pass                                # console already gone
    return 0


if __name__ == "__main__":
    try:
        rc = main()
        if _HARD_EXIT[0]:
            os._exit(rc)        # console writer stuck holding stdout; logs are already closed
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:          # e.g. `moth.py --list-map | head`
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
