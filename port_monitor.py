import os
import sys
import time
import psutil
from datetime import datetime
from collections import namedtuple
from colorama import init, Fore, Style

init(autoreset=True)

# ── Configuration ──────────────────────────────────────────────────────────────
SCAN_INTERVAL = 5          # seconds between scans
LOG_FILE      = "port_monitor.log"

# Well-known trojan/RAT/backdoor/botnet ports
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

Connection = namedtuple("Connection", ["lport", "raddr", "status", "pid", "pname"])


# ── Helpers ────────────────────────────────────────────────────────────────────
def get_process_name(pid):
    if not pid:
        return "N/A"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"


def get_connections():
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if not c.laddr:
                continue
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
            conns.append(Connection(
                lport=c.laddr.port,
                raddr=raddr,
                status=c.status or "?",
                pid=c.pid or 0,
                pname=get_process_name(c.pid),
            ))
    except psutil.AccessDenied:
        print(Fore.RED + "[ERROR] Access denied — run as Administrator for full results.")
    return conns


def log_event(message):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now().isoformat()}  {message}\n")


def render_row(conn):
    suspicious_label = SUSPICIOUS_PORTS.get(conn.lport, "")
    if suspicious_label:
        color = Fore.RED + Style.BRIGHT
        flag  = f"  *** {suspicious_label} ***"
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
    conns    = get_connections()
    curr_map = {(c.lport, c.raddr, c.status, c.pid): c for c in conns}
    curr_keys = set(curr_map)

    new_keys    = curr_keys - prev_keys
    closed_keys = prev_keys - curr_keys

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.system("cls" if os.name == "nt" else "clear")

    # Header
    print(Fore.CYAN + Style.BRIGHT
          + f"=== Port Monitor  [{ts}]  (Ctrl+C to stop) ===")
    print(Fore.WHITE
          + f"  {'PORT':<7} {'REMOTE':<28} {'STATUS':<13} {'PID':<11} PROCESS")
    print(Fore.WHITE + "─" * 78)

    for conn in sorted(conns, key=lambda c: c.lport):
        print(render_row(conn))

    # Change summary
    print(Fore.CYAN
          + f"\n  Total: {len(conns)}  |  "
            f"New: {len(new_keys)}  |  Closed: {len(closed_keys)}")

    # Alerts for new connections
    for key in new_keys:
        conn = curr_map[key]
        if conn.lport in SUSPICIOUS_PORTS:
            msg = (f"[ALERT] Suspicious port :{conn.lport} "
                   f"({SUSPICIOUS_PORTS[conn.lport]})  remote={conn.raddr}  "
                   f"PID:{conn.pid} ({conn.pname})")
            print(Fore.RED + Style.BRIGHT + f"\n  {msg}")
            log_event(msg)
        elif conn.status == "ESTABLISHED":
            msg = (f"[NEW ESTABLISHED] :{conn.lport} -> {conn.raddr}  "
                   f"PID:{conn.pid} ({conn.pname})")
            print(Fore.YELLOW + f"  {msg}")
            log_event(msg)

    for lport, raddr, status, pid in closed_keys:
        log_event(f"[CLOSED] :{lport} -> {raddr}  PID:{pid}")

    return curr_keys


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    print(Fore.CYAN + f"Port Monitor starting — scanning every {SCAN_INTERVAL}s\n")
    prev_keys: set = set()
    while True:
        try:
            prev_keys = scan(prev_keys)
            time.sleep(SCAN_INTERVAL)
        except KeyboardInterrupt:
            print(Fore.YELLOW + "\nStopped.")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nStopped.")
        sys.exit(0)
