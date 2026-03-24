#!/usr/bin/env python3
"""
===========================================================================
 DDoS Defense & Detection Simulator
 DDoS Simulation Lab — Personal Cybersecurity Research
 Author  : Cleveland Henry
 Purpose : Simulate and demonstrate DDoS mitigation techniques
           - Rate limiting (token bucket)
           - IP reputation / blacklisting
           - SYN cookie simulation
           - Anomaly detection (traffic spike alerting)
           - Connection throttling
===========================================================================
"""
 
import time
import random
import threading
import json
import os
import sys
from collections import defaultdict, deque
from datetime import datetime
 
LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "defense.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
 
 
# ── Logging ───────────────────────────────────────────────────────────────────
 
def log(msg: str, level: str = "INFO") -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colour = {
        "INFO":  "\033[36m",
        "WARN":  "\033[33m",
        "ALERT": "\033[31m",
        "BLOCK": "\033[35m",
        "OK":    "\033[32m",
    }.get(level, "\033[0m")
    reset = "\033[0m"
    line  = f"[{timestamp}] [{level}] {msg}"
    print(f"{colour}{line}{reset}")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  1. TOKEN BUCKET RATE LIMITER
# ══════════════════════════════════════════════════════════════════════════════
 
class TokenBucketRateLimiter:
    """
    Classic token bucket algorithm.
    Each IP gets 'capacity' tokens. Tokens refill at 'rate' per second.
    A request costs 1 token. If bucket is empty → request is DROPPED.
    """
 
    def __init__(self, capacity: int = 100, rate: float = 10.0):
        self.capacity  = capacity   # max burst
        self.rate      = rate       # tokens added per second
        self.buckets   = defaultdict(lambda: {"tokens": capacity, "last": time.time()})
        self.lock      = threading.Lock()
        self.stats     = {"allowed": 0, "dropped": 0}
 
    def _refill(self, ip: str) -> None:
        now   = time.time()
        b     = self.buckets[ip]
        delta = now - b["last"]
        b["tokens"] = min(self.capacity, b["tokens"] + delta * self.rate)
        b["last"]   = now
 
    def allow(self, ip: str) -> bool:
        with self.lock:
            self._refill(ip)
            b = self.buckets[ip]
            if b["tokens"] >= 1:
                b["tokens"] -= 1
                self.stats["allowed"] += 1
                return True
            self.stats["dropped"] += 1
            return False
 
    def report(self) -> dict:
        total   = self.stats["allowed"] + self.stats["dropped"]
        drop_pct = round(self.stats["dropped"] / max(total, 1) * 100, 2)
        return {**self.stats, "total": total, "drop_rate_pct": drop_pct}
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  2. IP REPUTATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════
 
class IPReputationEngine:
    """
    Tracks per-IP request counts. Automatically blacklists IPs that exceed
    thresholds within a rolling time window.
    """
 
    def __init__(self, threshold: int = 200, window_sec: int = 10):
        self.threshold   = threshold
        self.window      = window_sec
        self.history     = defaultdict(deque)   # ip → deque of timestamps
        self.blacklist   = set()
        self.whitelist   = {"127.0.0.1"}
        self.lock        = threading.Lock()
        self.stats       = {"blacklisted": 0, "blocked_requests": 0, "total_checked": 0}
 
    def record(self, ip: str) -> bool:
        """Returns True if request should be ALLOWED, False if blocked."""
        with self.lock:
            self.stats["total_checked"] += 1
 
            if ip in self.whitelist:
                return True
 
            if ip in self.blacklist:
                self.stats["blocked_requests"] += 1
                return False
 
            now = time.time()
            dq  = self.history[ip]
 
            # Trim old timestamps outside window
            while dq and now - dq[0] > self.window:
                dq.popleft()
 
            dq.append(now)
 
            if len(dq) >= self.threshold:
                self.blacklist.add(ip)
                self.stats["blacklisted"] += 1
                log(f"IP BLACKLISTED: {ip}  ({len(dq)} requests in {self.window}s)", "BLOCK")
                return False
 
            return True
 
    def unblock(self, ip: str) -> None:
        with self.lock:
            self.blacklist.discard(ip)
            log(f"IP UNBLOCKED: {ip}", "OK")
 
    def report(self) -> dict:
        return {
            **self.stats,
            "active_blacklist_size": len(self.blacklist),
            "blacklisted_ips": list(self.blacklist)[:10],  # first 10 for readability
        }
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  3. SYN COOKIE SIMULATOR
# ══════════════════════════════════════════════════════════════════════════════
 
class SYNCookieSimulator:
    """
    Simulates the SYN cookie technique:
      - On receiving SYN → DO NOT allocate state, send SYN-ACK with encoded cookie
      - On receiving ACK  → validate cookie, only then allocate connection
    This prevents half-open connection table exhaustion from SYN floods.
    """
 
    def __init__(self):
        self.half_open   = {}   # cookie → (ip, port, timestamp)
        self.established = 0
        self.rejected    = 0
        self.lock        = threading.Lock()
        self._cookie_ctr = 0
 
    def _make_cookie(self, ip: str, port: int) -> int:
        """Simple deterministic cookie (production: use HMAC-SHA256)."""
        import hashlib
        raw = f"{ip}:{port}:{int(time.time() // 60)}".encode()
        return int(hashlib.sha256(raw).hexdigest()[:8], 16)
 
    def receive_syn(self, src_ip: str, src_port: int) -> int:
        """Returns the SYN cookie to embed in SYN-ACK."""
        cookie = self._make_cookie(src_ip, src_port)
        # No state stored → immune to SYN flood
        return cookie
 
    def receive_ack(self, src_ip: str, src_port: int, ack_cookie: int) -> bool:
        """Validates ACK cookie. Returns True if connection is legitimate."""
        expected = self._make_cookie(src_ip, src_port)
        with self.lock:
            if ack_cookie == expected:
                self.established += 1
                return True
            else:
                self.rejected += 1
                return False
 
    def report(self) -> dict:
        return {
            "established_connections": self.established,
            "rejected_connections":    self.rejected,
        }
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  4. ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════════════════
 
class AnomalyDetector:
    """
    Monitors request rate. Raises alerts when traffic spikes beyond
    a dynamic threshold (baseline × multiplier).
    """
 
    def __init__(self, window_sec: int = 5, spike_multiplier: float = 3.0):
        self.window      = window_sec
        self.multiplier  = spike_multiplier
        self.timestamps  = deque()
        self.baseline    = None
        self.alerts      = []
        self.lock        = threading.Lock()
 
    def record(self) -> None:
        with self.lock:
            now = time.time()
            self.timestamps.append(now)
            while self.timestamps and now - self.timestamps[0] > self.window:
                self.timestamps.popleft()
 
    def current_rps(self) -> float:
        with self.lock:
            return len(self.timestamps) / self.window
 
    def check_anomaly(self) -> bool:
        rps = self.current_rps()
        if self.baseline is None:
            self.baseline = rps
            return False
        if rps > self.baseline * self.multiplier and rps > 10:
            alert = {
                "time":     datetime.now().isoformat(),
                "rps":      round(rps, 2),
                "baseline": round(self.baseline, 2),
                "ratio":    round(rps / max(self.baseline, 1), 2),
            }
            self.alerts.append(alert)
            log(
                f"⚠  ANOMALY DETECTED — RPS: {rps:.1f} "
                f"({alert['ratio']}× baseline of {self.baseline:.1f})",
                "ALERT",
            )
            return True
        # Slowly update baseline
        self.baseline = self.baseline * 0.95 + rps * 0.05
        return False
 
    def report(self) -> dict:
        return {
            "current_rps": round(self.current_rps(), 2),
            "baseline_rps": round(self.baseline or 0, 2),
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-5:],
        }
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  5. UNIFIED DEFENSE LAYER
# ══════════════════════════════════════════════════════════════════════════════
 
class DefenseLayer:
    def __init__(self):
        self.rate_limiter  = TokenBucketRateLimiter(capacity=100, rate=20.0)
        self.ip_reputation = IPReputationEngine(threshold=150, window_sec=10)
        self.syn_cookies   = SYNCookieSimulator()
        self.anomaly       = AnomalyDetector(window_sec=5, spike_multiplier=2.5)
        self.total_in      = 0
        self.total_blocked = 0
 
    def handle_request(self, ip: str, request_type: str = "HTTP") -> dict:
        self.total_in += 1
        self.anomaly.record()
 
        verdict = {"ip": ip, "type": request_type, "allowed": False, "reason": ""}
 
        # Layer 1: IP reputation check
        if not self.ip_reputation.record(ip):
            self.total_blocked += 1
            verdict["reason"] = "IP_BLACKLISTED"
            return verdict
 
        # Layer 2: Rate limit
        if not self.rate_limiter.allow(ip):
            self.total_blocked += 1
            verdict["reason"] = "RATE_LIMITED"
            return verdict
 
        # Layer 3: Anomaly check (non-blocking, just alerts)
        self.anomaly.check_anomaly()
 
        verdict["allowed"] = True
        verdict["reason"]  = "PASSED"
        return verdict
 
    def full_report(self) -> dict:
        return {
            "summary": {
                "total_requests": self.total_in,
                "total_blocked":  self.total_blocked,
                "block_rate_pct": round(self.total_blocked / max(self.total_in, 1) * 100, 2),
            },
            "rate_limiter":  self.rate_limiter.report(),
            "ip_reputation": self.ip_reputation.report(),
            "syn_cookies":   self.syn_cookies.report(),
            "anomaly":       self.anomaly.report(),
        }
 
 
# ══════════════════════════════════════════════════════════════════════════════
#  6. SIMULATION DEMO
# ══════════════════════════════════════════════════════════════════════════════
 
def simulate_defense(duration: int = 30) -> None:
    log("═══════════════════════════════════════════════════")
    log("  DEFENSE LAYER SIMULATION STARTING")
    log(f"  Duration: {duration}s")
    log("═══════════════════════════════════════════════════")
 
    defense = DefenseLayer()
 
    # Simulate legitimate IPs
    legit_ips = [f"192.168.1.{i}" for i in range(10, 30)]
    # Simulate attacker IPs (high rate from few sources)
    attack_ips = [f"10.0.0.{i}" for i in range(1, 6)]
 
    stop = threading.Event()
 
    def legit_traffic():
        while not stop.is_set():
            ip = random.choice(legit_ips)
            defense.handle_request(ip, "HTTP")
            time.sleep(random.uniform(0.05, 0.2))
 
    def attack_traffic():
        while not stop.is_set():
            ip = random.choice(attack_ips)
            defense.handle_request(ip, "SYN" if random.random() < 0.5 else "HTTP")
            time.sleep(0.001)  # Very high rate
 
    # Start threads
    threads = (
        [threading.Thread(target=legit_traffic,  daemon=True) for _ in range(5)] +
        [threading.Thread(target=attack_traffic, daemon=True) for _ in range(10)]
    )
    for t in threads:
        t.start()
 
    end = time.time() + duration
    try:
        while time.time() < end:
            elapsed = duration - (end - time.time())
            report  = defense.full_report()
            sys.stdout.write(
                f"\r  🛡  In: {report['summary']['total_requests']:,}  |  "
                f"Blocked: {report['summary']['total_blocked']:,}  |  "
                f"Block%: {report['summary']['block_rate_pct']}%  |  "
                f"RPS: {report['anomaly']['current_rps']}  |  "
                f"Elapsed: {elapsed:.1f}s   "
            )
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("\nSimulation interrupted.", "WARN")
 
    stop.set()
    for t in threads:
        t.join(timeout=1)
 
    final = defense.full_report()
    log("\n═══════════════════════════════════════════════════")
    log("  DEFENSE SIMULATION COMPLETE — FINAL REPORT")
    log("═══════════════════════════════════════════════════")
    log(f"  Total requests : {final['summary']['total_requests']:,}")
    log(f"  Total blocked  : {final['summary']['total_blocked']:,}")
    log(f"  Block rate     : {final['summary']['block_rate_pct']}%")
    log(f"  IPs blacklisted: {final['ip_reputation']['blacklisted']}")
    log(f"  Anomaly alerts : {final['anomaly']['total_alerts']}")
 
    out = os.path.join(os.path.dirname(__file__), "..", "logs", "defense_results.json")
    with open(out, "w") as f:
        json.dump(final, f, indent=2)
    log(f"  Results saved → {out}")
 
 
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="DDoS Defense Simulator — Personal Lab")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Simulation duration (default: 30s)")
    args = parser.parse_args()
    simulate_defense(args.duration)
