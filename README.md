# Port Monitor

A real-time, color-coded network port monitor for Windows. It continuously scans all active TCP/UDP connections, identifies the owning process for each port, detects new and closed connections between scans, and alerts you when a connection appears on a known malicious port.

---

## Features

- **Live table** — refreshes every 5 seconds, showing every active connection on the system
- **Process attribution** — each port is linked to the PID and process name that owns it
- **Change detection** — new and closed connections since the last scan are highlighted and counted
- **Suspicious port alerts** — 16 well-known trojan, RAT, worm, and botnet ports are flagged in real time
- **Persistent log** — new established connections and all suspicious-port alerts are written to `port_monitor.log`
- **Graceful access handling** — prints a warning if elevated privileges are needed; continues with available data

---

## Requirements

- Python 3.10+
- `psutil`
- `colorama`

Dependencies are installed into the project virtual environment during setup (see below).

---

## Setup

### 1. Create the virtual environment (first run only)

```bash
uv venv .venv
uv pip install psutil colorama --python .venv/Scripts/python.exe
```

If `uv` is not available, use standard pip:

```bash
python -m venv .venv
.venv\Scripts\pip install psutil colorama
```

### 2. Run the monitor

```bash
.venv\Scripts\python.exe port_monitor.py
```

> **Tip:** Run from an **elevated (Administrator) terminal** to see connections owned by system processes. Without elevation, some rows may show `N/A` for the process name and a partial connection list.

Stop the monitor at any time with **Ctrl+C**.

---

## Configuration

Two constants at the top of `port_monitor.py` control runtime behaviour:

| Constant | Default | Description |
|---|---|---|
| `SCAN_INTERVAL` | `5` | Seconds between scans |
| `LOG_FILE` | `port_monitor.log` | Path to the append-only event log |

To add or remove suspicious port definitions, edit the `SUSPICIOUS_PORTS` dictionary. Each entry is `port_number: "label"`.

---

## Reading the Output

The display clears and redraws on every scan.

```
=== Port Monitor  [2026-05-18 17:32:12]  (Ctrl+C to stop) ===
  PORT    REMOTE                       STATUS        PID         PROCESS
──────────────────────────────────────────────────────────────────────────────
  :443    142.250.80.46:443            ESTABLISHED   PID:76672   chrome.exe
  :4444   192.168.1.55:4444            ESTABLISHED   PID:9901    unknown.exe  *** Metasploit / Blaster Worm ***
  :49664  -                            LISTEN        PID:1652    lsass.exe

  Total: 48  |  New: 3  |  Closed: 1

  [ALERT] Suspicious port :4444 (Metasploit / Blaster Worm)  remote=192.168.1.55:4444  PID:9901 (unknown.exe)
  [NEW ESTABLISHED] :443 -> 142.250.80.46:443  PID:76672 (chrome.exe)
```

### Columns

| Column | Description |
|---|---|
| `PORT` | Local port number the system is listening on or connecting from |
| `REMOTE` | Remote IP and port for active connections; `-` for listening/unconnected sockets |
| `STATUS` | TCP state (see table below) |
| `PID` | Process ID that owns the socket |
| `PROCESS` | Executable name of the owning process |

### Connection statuses

| Status | Meaning |
|---|---|
| `LISTEN` | Waiting for incoming connections (server socket) |
| `ESTABLISHED` | Active two-way connection |
| `TIME_WAIT` | Connection closed, waiting for delayed packets to expire |
| `CLOSE_WAIT` | Remote end closed; local process has not yet closed its side |
| `NONE` / `?` | UDP socket or state not available |

### Color coding

| Color | Meaning |
|---|---|
| **Green** | `ESTABLISHED` connection — actively transferring data |
| **Red + bold** | Port matches a known suspicious signature — investigate immediately |
| White | All other connections (listening, waiting, UDP) |

### Footer line

```
Total: 48  |  New: 3  |  Closed: 1
```

- **Total** — number of connections visible in this scan
- **New** — connections that did not exist in the previous scan
- **Closed** — connections present in the previous scan that are now gone

### Inline alerts (below the table)

Alerts appear beneath the footer whenever new connections are detected:

- `[ALERT]` — a new connection appeared on a suspicious port; also written to the log file
- `[NEW ESTABLISHED]` — any other new `ESTABLISHED` connection; also written to the log file

---

## Log File

`port_monitor.log` is created in the working directory on first use and appended to on every run. Each line is prefixed with an ISO-8601 timestamp.

```
2026-05-18T17:35:01.123456  [ALERT] Suspicious port :4444 (Metasploit / Blaster Worm)  remote=192.168.1.55:4444  PID:9901 (unknown.exe)
2026-05-18T17:35:06.654321  [NEW ESTABLISHED] :443 -> 142.250.80.46:443  PID:76672 (chrome.exe)
2026-05-18T17:35:11.000000  [CLOSED] :443 -> 142.250.80.46:443  PID:76672
```

Closed connections are logged but not printed to the terminal.

---

## Suspicious Port Reference

| Port | Associated Threat |
|---|---|
| 1080 | SOCKS Proxy / PoisonIvy RAT |
| 1234 | SubSeven Trojan |
| 1243 | SubSeven Trojan |
| 2745 | Bagle Worm |
| 3127 | MyDoom |
| 4444 | Metasploit / Blaster Worm |
| 5554 | Sasser Worm |
| 6667 | IRC Botnet C2 |
| 6697 | IRC Botnet C2 (SSL) |
| 9001 | Tor Relay |
| 9050 | Tor SOCKS Proxy |
| 12345 | NetBus Trojan |
| 23456 | Evil FTP / Whack-a-Mole Trojan |
| 27374 | SubSeven Trojan |
| 31337 | Back Orifice Trojan |
| 65000 | Devil Trojan |

> **Note:** A match on one of these ports is an indicator to investigate further, not a definitive confirmation of infection. Legitimate software occasionally uses the same port numbers.
