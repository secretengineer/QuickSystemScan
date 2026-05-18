import os
import sys
import time
import psutil
from datetime import datetime
from collections import namedtuple
from colorama import init, Fore, Style

# autoreset=True means each print() call resets color back to default automatically,
# so we never need to manually append Style.RESET_ALL.
init(autoreset=True)

# ── Configuration ──────────────────────────────────────────────────────────────
SCAN_INTERVAL = 5          # seconds between scans — lower values give faster detection
                           # but increase CPU usage; 5s is a reasonable default
LOG_FILE      = "port_monitor.log"  # appended to on every run; excluded from git

# ── Suspicious port signatures ─────────────────────────────────────────────────
# Maps a port number to the threat it is associated with.
# A match is an indicator to investigate — not a confirmed infection, since
# legitimate software can occasionally bind to the same port numbers.
# Add new entries as: port_number: "Threat label"
SUSPICIOUS_PORTS = {
    1080:  "SOCKS Proxy / PoisonIvy RAT",
    1234:  "SubSeven Trojan",
    1243:  "SubSeven Trojan",
    2745:  "Bagle Worm",
    3127:  "MyDoom",
    4444:  "Metasploit / Blaster Worm",
    5554:  "Sasser Worm",
    6667:  "IRC Botnet C2",
    6697:  "IRC Botnet C2 (SSL)",
    9001:  "Tor Relay",
    9050:  "Tor SOCKS Proxy",
    12345: "NetBus Trojan",
    23456: "Evil FTP / Whack-a-Mole Trojan",
    27374: "SubSeven Trojan",
    31337: "Back Orifice Trojan",
    65000: "Devil Trojan",
}

# Lightweight data container for a single network connection snapshot.
# Using a namedtuple keeps it immutable and hashable (needed for set diffing).
#   lport  — local port number
#   raddr  — remote "ip:port" string, or "-" for unconnected sockets
#   status — TCP state string (LISTEN, ESTABLISHED, TIME_WAIT, etc.)
#   pid    — owning process ID (0 if unknown)
#   pname  — owning process executable name ("N/A" if inaccessible)
Connection = namedtuple("Connection", ["lport", "raddr", "status", "pid", "pname"])


# ── Helpers ────────────────────────────────────────────────────────────────────
def get_process_name(pid):
    # Resolve a PID to its executable name.
    # NoSuchProcess  — process exited between the connection snapshot and this call
    # AccessDenied   — process is owned by SYSTEM/another user; requires elevation
    if not pid:
        return "N/A"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"


def get_connections():
    # Collect all active IPv4/IPv6 TCP and UDP connections from the OS.
    # kind="inet" covers both IPv4 and IPv6 on both TCP and UDP.
    # On Windows, a top-level AccessDenied is raised when the script is not
    # running as Administrator — we degrade gracefully rather than crash.
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            # Skip entries with no local address (can occur on some OS states)
            if not c.laddr:
                continue
            # Format the remote address as "ip:port"; use "-" for listening/UDP sockets
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            conns.append(Connection(
                lport=c.laddr.port,
                raddr=raddr,
                status=c.status or "?",  # UDP sockets have no TCP status
                pid=c.pid or 0,
                pname=get_process_name(c.pid),
            ))
    except psutil.AccessDenied:
        print(Fore.RED + "[ERROR] Access denied — run as Administrator for full results.")
    return conns


def log_event(message):
    # Append a timestamped event line to the log file.
    # The file is opened and closed on each call so no data is lost if the
    # script is killed mid-run.
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().isoformat()}  {message}\n")


def render_row(conn):
    # Build a formatted, color-coded string for one connection row.
    # Priority: suspicious port (red+bold) > ESTABLISHED (green) > everything else (white)
    suspicious_label = SUSPICIOUS_PORTS.get(conn.lport, "")
    if suspicious_label:
        color = Fore.RED + Style.BRIGHT
        flag  = f"  *** {suspicious_label} ***"  # inline warning appended to the row
    elif conn.status == "ESTABLISHED":
        color = Fore.GREEN
        flag  = ""
    else:
        color = Fore.WHITE
        flag  = ""
    return (
        color
        + f"  :{conn.lport:<6} {conn.raddr:<28} {conn.status:<13} "
          f"PID:{conn.pid:<7} {conn.pname}{flag}"
    )


# ── Core scan ─────────────────────────────────────────────────────────────────
def scan(prev_keys: set) -> set:
    # Take a fresh snapshot of all connections and diff it against the previous scan.
    # prev_keys is a set of (lport, raddr, status, pid) tuples from the last cycle.
    conns    = get_connections()

    # Build a dict keyed by the 4-tuple so we can look up the full Connection
    # object when we need to print details about a new/changed entry.
    curr_map  = {(c.lport, c.raddr, c.status, c.pid): c for c in conns}
    curr_keys = set(curr_map)

    # Set arithmetic gives us exactly what appeared and disappeared since last scan
    new_keys    = curr_keys - prev_keys   # connections that didn't exist before
    closed_keys = prev_keys - curr_keys   # connections that no longer exist

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Clear the terminal each cycle so the table always starts at line 1 —
    # this prevents scrollback buildup during long monitoring sessions.
    os.system("cls" if os.name == "nt" else "clear")

    # ── Table header ──
    print(Fore.CYAN + Style.BRIGHT
          + f"=== Port Monitor  [{ts}]  (Ctrl+C to stop) ===")
    print(Fore.WHITE
          + f"  {'PORT':<7} {'REMOTE':<28} {'STATUS':<13} {'PID':<11} PROCESS")
    print(Fore.WHITE + "─" * 78)

    # Print every connection sorted by local port number (ascending)
    for conn in sorted(conns, key=lambda c: c.lport):
        print(render_row(conn))

    # ── Footer: per-scan change counters ──
    print(Fore.CYAN
          + f"\n  Total: {len(conns)}  |  "
            f"New: {len(new_keys)}  |  Closed: {len(closed_keys)}")

    # ── Inline alerts for new connections ──
    # Only new connections trigger alerts — we don't re-alert on connections
    # that were already present in the previous scan.
    for key in new_keys:
        conn = curr_map[key]
        if conn.lport in SUSPICIOUS_PORTS:
            # High-priority alert: port matches a known malicious signature
            msg = (f"[ALERT] Suspicious port :{conn.lport} "
                   f"({SUSPICIOUS_PORTS[conn.lport]})  remote={conn.raddr}  "
                   f"PID:{conn.pid} ({conn.pname})")
            print(Fore.RED + Style.BRIGHT + f"\n  {msg}")
            log_event(msg)  # always write suspicious alerts to disk
        elif conn.status == "ESTABLISHED":
            # Informational: a new active connection appeared
            msg = (f"[NEW ESTABLISHED] :{conn.lport} -> {conn.raddr}  "
                   f"PID:{conn.pid} ({conn.pname})")
            print(Fore.YELLOW + f"  {msg}")
            log_event(msg)

    # Log closed connections silently (no terminal output — reduces noise)
    for lport, raddr, status, pid in closed_keys:
        log_event(f"[CLOSED] :{lport} -> {raddr}  PID:{pid}")

    # Return the current snapshot so the next scan can diff against it
    return curr_keys


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    print(Fore.CYAN + f"Port Monitor starting — scanning every {SCAN_INTERVAL}s\n")
    prev_keys: set = set()  # empty on first run; all connections will appear as "new"
    while True:
        try:
            prev_keys = scan(prev_keys)
            time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            # Catch Ctrl+C inside the sleep so we exit cleanly without a traceback
            print(Fore.YELLOW + "\nStopped.")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nStopped.")
        sys.exit(0)
