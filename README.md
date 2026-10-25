# MOTH — Modbus Observation & Threat Honeypot

`moth.py` v0.2.0 · Python 3.8+ · standard library only (scapy + Npcap optional, recommended on Windows) · Windows / Linux

MOTH sits on a network segment looking like a Schneider Modicon M340 running a
wastewater lift station. Nobody has a legitimate reason to talk to it, so every
ping, ARP request, port scan and Modbus request is an alert.

## Quick start

```
python moth.py                         # 0.0.0.0:502, M340 identity, sniffer on (run as Admin/root)
python moth.py --syslog 10.10.5.20     # also forward alerts to a syslog collector (UDP 514)
python moth.py --port 5020 --no-sniff  # unprivileged demo
python moth.py --list-map              # coil / register map
python moth.py --test-alert            # one test alert through log + syslog, then exit
```

Alerts print to the console and append to `moth_alerts.log` beside the script
(`--log` to move it). `--json-log file` adds one JSON object per alert.
Stop with Ctrl+C (or close the window, Ctrl+Break, `kill`/`systemctl stop`). MOTH
writes an alert summary with the reason it stopped.

Windows: install [Npcap](https://npcap.com) and `pip install scapy` so MOTH can see
pings and port scans (see *Detection tiers*), and allow inbound TCP 502 (plus any
`--decoy` ports) through Windows Firewall, or no Modbus client will reach the honeypot.

## What it alerts on

Severity ladder: **INFO < NOTICE < WARN < HIGH < CRIT**. Nobody has a legitimate
reason to talk Modbus to a honeypot, so every Modbus request is at least HIGH and
every attempt to change state is CRIT.

| Kind | Trigger | Default severity |
|---|---|---|
| `PING` | ICMP echo / timestamp request to the honeypot | NOTICE |
| `ARP_REQUEST` | ARP who-has for the honeypot's IP | NOTICE |
| `ARP_SWEEP` | one sender ARP-ing ≥8 different hosts in 30 s | WARN |
| `PORT_SCAN` | ≥5 distinct TCP/UDP ports from one source in 30 s (re-alerts as the count doubles) | WARN |
| `STEALTH_PROBE` | TCP NULL / FIN / XMAS probes | WARN |
| `DECOY_CONNECT` | connection to an optional decoy port (`--decoy 21,22,23,80,...`; off by default); logs any bytes received | WARN |
| `MODBUS_CONNECT` / `MODBUS_DISCONNECT` | TCP session on the Modbus port | NOTICE / INFO |
| `MODBUS_READ` | FC 1, 2, 3, 4 (and 20, 24) — decoded with address, tag name, count and the values returned | **HIGH** |
| `MODBUS_WRITE` | FC 5, 6, 15, 16, 21, 22, 23 — decoded with tag name, old and new values. Every attempt, including ones refused by `--reject-writes` or sent to a wrong unit ID | **CRIT** |
| `MODBUS_IDENT` | FC 17 Report Server ID, FC 43/14 Read Device Identification | **HIGH** |
| `MODBUS_DIAG` | FC 7, 8, 11, 12. FC 8 sub-functions that change comm state (1 restart, 3, 4 force listen-only, 10 clear counters) are CRIT | **HIGH** / CRIT |
| `MODBUS_UNSUPPORTED` | function codes outside the classes above, e.g. FC 90 UMAS (exception 01 sent) | **HIGH** |
| `MODBUS_MALFORMED` | non-Modbus bytes or a bad MBAP header on port 502 | WARN |
| `SENSOR_DOWN` | Tier 1 capture lost or unavailable: pings, ARP and scans are **not** being seen. Once per outage | WARN |
| `SENSOR_RESTORED` | capture is back, with outage length and attempt count | NOTICE |
| `SENSOR_IP_CHANGE` | this host's IPv4 addresses changed (new DHCP lease, adapter up/down) | NOTICE |
| `HEARTBEAT` | sensor-alive record (`state=start / alive / stop`); log and syslog only, never the console, not counted as an alert | INFO |

Identical `PING` / `ARP_REQUEST` / `STEALTH_PROBE` / `DECOY_CONNECT` alerts from
the same source are suppressed for `--throttle` seconds (default 10) and the
next alert carries a `(+N identical suppressed)` note. Modbus requests are all
logged by default; `--modbus-throttle N` collapses a chatty poller.

A request that gets an exception reply keeps the kind of what the client *tried*
to do: an out-of-range read is `MODBUS_READ` / HIGH, a write to the wrong unit ID
is `MODBUS_WRITE` / CRIT. The exception code is in the message.

### Alert line format

```
2026-09-22 03:42:57.936 CRIT   MODBUS_WRITE     src=10.20.30.44:51234 tid=9 unit=1 fc=6 WRITE_SINGLE_REGISTER holding addr=0 (LEAD_START_LEVEL_x100ft) value=400 (was 650) -> OK
```

Syslog messages carry the same text after `moth[pid]:` (RFC 3164) or the
structured header (RFC 5424, `--syslog-format rfc5424`). Severity maps to syslog
severity: CRIT→2, HIGH→3, WARN→4, NOTICE→5, INFO→6. Facility defaults to `local0`.

## Sensor health

A honeypot that has quietly stopped seeing traffic is worse than none, so v0.2.0
watches itself.

**Capture watchdog.** If Tier 1 capture dies (laptop sleep/resume, adapter reset,
Wi-Fi reconnect, Npcap driver error), MOTH raises one `SENSOR_DOWN` and reopens it
with backoff (5 s, doubling to 60 s), then raises `SENSOR_RESTORED` with how long it
was blind. Host addresses are re-read every 30 s. A change raises `SENSOR_IP_CHANGE`
and reopens capture with the new address. A capture that has seen nothing at all for
10 minutes is reopened quietly (text-log note only), because a dead handle and a
silent network look the same. Reopens use the same engine that first worked, so
MOTH never quietly drops from Npcap to the firewall-blind raw socket. If capture
can't work at all (no privileges), it says so once and runs on Tier 2.

**Heartbeat.** Every `--heartbeat` seconds (default 900, `0` = off) MOTH writes a
`HEARTBEAT` record to the log, JSON log and syslog, never the console:

```
2026-10-04 07:21:46.612 INFO   HEARTBEAT        src=- state=alive v=0.2.0 uptime=2h15m capture=up(pcap) pkts=48211 alerts=37 modbus_req=12 writes=0 ips=192.168.22.174
```

`state=start` and `state=stop reason=...` bracket each run. A SIEM rule of *"no
MOTH HEARTBEAT from this host for 2 × interval"* catches a dead or unplugged
sensor. A `stop` record tells a clean shutdown from a crash.

**Console never stalls the honeypot.** Console output runs on its own thread. In
a classic Windows console a mouse click starts a QuickEdit selection, which pauses
every write to the window. Before v0.2.0 that froze Modbus replies and packet
capture. MOTH now switches QuickEdit off while it runs and restores it on exit
(`--keep-quickedit` to opt out). If the console is blocked anyway, lines are
buffered and then dropped from the screen with a count. The log file and syslog
still get every alert.

**Clean shutdown.** Closing the console window and Ctrl+Break on Windows, and
SIGTERM / SIGHUP on Linux, all write the summary (with the reason), send the
`stop` heartbeat, switch SIO_RCVALL off and restore the console. Cleanup is time-boxed
(Windows allows about 5 s after a window close) and a second Ctrl+C can't cut it
short. Under `nohup` SIGHUP is left ignored, as you'd expect. Windows sends logoff
and shutdown events only to services, so for unattended Windows boxes run MOTH
as a scheduled task or service.

**Syslog without DNS.** The collector name is resolved once at startup. If it
doesn't resolve, MOTH says so, keeps logging locally and retries the lookup once
a minute, and it never stalls alerting on DNS. Use an IP address for `--syslog`
on isolated networks.

## Detection tiers

**Tier 1 — packet capture** (`--capture auto|pcap|raw`, default `auto`):

* **Windows — Npcap (preferred).** With `scapy` and Npcap installed, MOTH captures
  everything (ARP, ICMP, TCP, UDP) through Npcap. Npcap hooks the NDIS driver
  stack *below* Windows Defender Firewall, so it sees the pings and the SYNs to
  closed ports that the firewall drops. With a default Npcap install this works
  without an elevated prompt.
* **Windows — `SIO_RCVALL` fallback** (stdlib, needs Administrator). Used when
  scapy or Npcap is missing, or with `--capture raw`. This raw socket sits
  *above* the firewall, and the firewall drops inbound echo requests and SYNs to
  closed ports by default. MOTH never sees them, so `PING` and `PORT_SCAN` go
  quiet: the scanner's SYN to 502 is the only one that gets through, and one port
  is under the scan threshold. ARP is invisible here as well (scapy is used for
  ARP alone if it is present). MOTH prints a warning at startup in this mode.
  The fix is Npcap. *Allowing python.exe inbound for all protocols* is reported to
  let SIO_RCVALL see more, but it also opens every Python listener on the box, so
  it isn't recommended.
* **Linux:** `AF_PACKET` raw socket (root). Sees ARP, ICMP, TCP and UDP before
  netfilter. Nothing extra needed. `--capture pcap` uses scapy/libpcap instead.
* **macOS:** scapy/BPF if it is installed (untested). Otherwise Tier 2 only.

`--ip` picks the interface by its IP when the default-route interface is the
wrong one (e.g. a lab NIC alongside Wi-Fi).

Traffic from MOTH's own addresses is ignored, so pinging or scanning the MOTH
host from itself shows nothing. Test from a second machine.

**Tier 2 — listeners** (bind privileges only): the Modbus port itself, plus any
decoy service ports you enable with `--decoy` (off by default, so only TCP 502 is
open). With decoys on, every connection to one is an alert and feeds the
port-scan counter, so a plain `nmap -sT` is caught even without raw sockets.
If Tier 1 cannot start, MOTH tells you why and keeps going on Tier 2 — and warns
that with no decoys it will then only see Modbus connections, not pings or scans.

## The emulated process

`LS-07 MAPLE CREEK PS` — a three-pump submersible lift station, 8 ft wet well,
diurnal influent (trough ~03:00, peak ~14:00), lead/lag/lag2 level control with
alternation, VFD speed proportional to level, run-hour and start counters,
high / high-high / low / low-low floats, dry-run trips, alarm horn and ack.
The physics runs on a 1 s tick, so polled values move realistically.

Writes are applied to the process (that is the lure): lower
`LEAD_START_LEVEL` and the pumps cycle more; put a pump in manual and force
`P1_RUN_CMD` and it will pump the well down until it dry-run trips. Use
`--reject-writes` to answer every write with exception 01 instead (a
write-protected controller).

Run `python moth.py --list-map` for the full coil / discrete / input / holding
register map with tag names. Levels are stored ×100 ft (650 = 6.50 ft), amps
×10, pressure ×10 psi. 32-bit counters are hi/lo register pairs.

### Identity

| `--profile` | FC 43/14 Read Device ID | FC 17 |
|---|---|---|
| `m340` (default) | Schneider Electric / BMX P34 2020 / V2.70 / Modicon M340 | yes |
| `micrologix` | not supported (exception 01, as the real 1766 controllers behave) | no |
| `generic` | Modbus Device / MB-TCP-01 / 1.00 | yes |

Unit IDs: MOTH answers `--unit` (default 1) plus 0 and 255; any other unit ID
gets exception 0x0B *Gateway Target Failed*.

If enabled, decoy port 80/443 answers HTTP with a `401` and a `Server: Schneider-WEB/V2.1.3`
header; 21/22/23 send short service banners and log whatever the client types.

## Options

```
--bind ADDR            listen address (default 0.0.0.0)
--port N               Modbus/TCP port (default 502)
--unit N               Modbus unit id (default 1)
--profile m340|micrologix|generic
--reject-writes        answer writes with exception 01 instead of applying them
--decoy LIST           extra decoy TCP ports, comma/range list (default none — only 502 is open)
--no-sniff             Tier 2 only
--capture auto|pcap|raw  Tier 1 engine (auto: Npcap on Windows if installed, else raw socket)
--ip ADDR              IP of the interface to sniff on
--log FILE             alert text log (default moth_alerts.log beside the script)
--json-log FILE        also write JSON lines
--syslog HOST          forward alerts over UDP
--syslog-port N        (514)   --syslog-facility NAME (local0)   --syslog-format rfc3164|rfc5424
--throttle S           suppress identical ping/ARP/probe/decoy alerts (10; 0 = off)
--modbus-throttle S    suppress identical Modbus request alerts (0 = log every one)
--scan-threshold N     distinct ports in 30 s that count as a scan (5)
--status-interval S    process status line on console (0 = never shown, the default)
--heartbeat S          HEARTBEAT to log + syslog, never console (900; 0 = off)
--keep-quickedit       Windows: leave console QuickEdit on
--seed N               deterministic simulation
--list-map / --test-alert / -q / --no-color / -V
```

## Test procedure

1. `python moth.py --port 5020 --syslog 127.0.0.1 --syslog-port 5514` on one
   box (or with `--no-sniff` if not elevated).
   On Windows the first startup line should read `Tier 1 sniffer: Npcap via scapy …`.
   If it says `SIO_RCVALL` you will also see the firewall warning. Fix that first.
2. From a **second** host (not the MOTH box): `ping <moth>`; `nmap -sS -p 1-1024 <moth>`;
   `nmap -sN <moth>`; `nmap -sU -p 161,47808 <moth>`. Expect `PING`, `PORT_SCAN`,
   `STEALTH_PROBE`. If no host-discovery reply comes back (Windows Firewall drops ping),
   add `-Pn` to the nmap runs. MOTH alerts either way.
3. Point AtomICS's Modbus module (or `nmap --script modbus-discover -p 5020 <moth>`)
   at it. Expect `MODBUS_CONNECT`, then `MODBUS_READ` / `MODBUS_IDENT` at **HIGH**,
   and for any write, `MODBUS_WRITE` at **CRIT** with the tag name and previous value.
4. Optional, Windows: run once with `--capture raw` and repeat step 2 to watch
   the firewall blind spot. Then go back to the default.
5. Confirm `moth_alerts.log` and the syslog collector show the same lines.
6. Sensor health: with MOTH running, disable and re-enable the network adapter
   (or sleep and wake the laptop). Expect `SENSOR_DOWN`, then `SENSOR_RESTORED`
   (and `SENSOR_IP_CHANGE` if the address changed), then repeat step 2 to confirm
   detection is back. Click in the console window: alerts keep arriving.
   Close the window: the log ends with `MOTH stopping (console window closed)`.

## Operational notes

* MOTH advertises itself as a PLC. Deploy only where a decoy controller will not
  confuse operators, asset inventories or safety reviews, and tell the people who
  run the network it is there.
* It is low-interaction: it never initiates traffic, never writes to anything
  but its own log, and cannot be used to reach real equipment.
* Legitimate discovery tools (asset inventory scanners, a misconfigured HMI poll
  list) will trigger it. That is a finding too.
* Realism: a real M340 answers ping and sends RST from closed ports. A Windows
  host with the firewall on does neither, and a careful attacker can notice. If
  that matters, enable the *File and Printer Sharing (Echo Request – ICMPv4-In)*
  rule on the MOTH host. Detection does not depend on it.

AUTHORIZED USE ONLY. Intended for training, research and monitoring on networks
you are permitted to instrument; not for production environments where safety or
operational availability cannot be guaranteed.
