#!/usr/bin/env python3
"""
===========================================================================
 DDoS Simulation Lab — Master Runner
 Personal Cybersecurity Research Project
 Author : Cleveland Henry
 
 Usage:
   python run_lab.py --mode attack-syn  --target 192.168.56.101
   python run_lab.py --mode attack-http --target 192.168.56.101
   python run_lab.py --mode defense
   python run_lab.py --mode full         --target 192.168.56.101
 
 WARNING: Run ONLY inside an isolated VirtualBox lab. Never against
          systems you do not own or have written permission to test.
===========================================================================
"""
 
import argparse
import sys
import os
import json
from datetime import datetime
 
sys.path.insert(0, os.path.dirname(__file__))
 
BANNER = r"""
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ ██╗  ██╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔═══██╗╚██╗██╔╝
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║█████╗  ██║   ██║ ╚███╔╝ 
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██╔══╝  ██║   ██║ ██╔██╗ 
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║     ╚██████╔╝██╔╝ ██╗
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝
 
         DDoS Simulation Lab  |  Personal Cybersecurity Research
         Author: Cleveland Henry  |  Environment: VirtualBox Lab VM
  ─────────────────────────────────────────────────────────────────────────────
  ⚠  ETHICAL USE ONLY — Authorised isolated lab environment required
  ─────────────────────────────────────────────────────────────────────────────
"""
 
 
def print_banner():
    print("\033[96m" + BANNER + "\033[0m")
 
 
def run_syn(target: str, port: int, duration: int, threads: int):
    from syn_flood import run_syn_flood
    return run_syn_flood(target, port, duration, threads)
 
 
def run_http(target: str, port: int, duration: int, threads: int):
    from http_flood import run_http_flood
    return run_http_flood(target, port, duration, threads)
 
 
def run_defense(duration: int):
    from defense import simulate_defense
    simulate_defense(duration)
 
 
def run_full(target: str, port: int, duration: int):
    """Run both attacks then the defense simulation and save a combined report."""
    print("\n\033[93m[FULL MODE] Running SYN Flood...\033[0m\n")
    syn_results  = run_syn(target, port, duration // 3, 10)
 
    print("\n\033[93m[FULL MODE] Running HTTP Flood...\033[0m\n")
    http_results = run_http(target, port, duration // 3, 30)
 
    print("\n\033[93m[FULL MODE] Running Defense Simulation...\033[0m\n")
    run_defense(duration // 3)
 
    # Load defense results
    def_path = os.path.join(os.path.dirname(__file__), "..", "logs", "defense_results.json")
    defense_results = {}
    if os.path.exists(def_path):
        with open(def_path) as f:
            defense_results = json.load(f)
 
    report = {
        "lab":            "DDoS Simulation Lab — Personal Project",
        "author":         "Cleveland Henry",
        "timestamp":      datetime.now().isoformat(),
        "target":         target,
        "syn_flood":      syn_results,
        "http_flood":     http_results,
        "defense":        defense_results,
    }
 
    out = os.path.join(os.path.dirname(__file__), "..", "logs", "full_lab_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n\033[92m[✓] Full lab report saved → {out}\033[0m")
 
 
if __name__ == "__main__":
    print_banner()
 
    parser = argparse.ArgumentParser(
        description="DDoS Lab Master Runner — Personal Project",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "--mode", required=True,
        choices=["attack-syn", "attack-http", "defense", "full"],
        help=(
            "attack-syn  : Run SYN flood only\n"
            "attack-http : Run HTTP flood only\n"
            "defense     : Run defense/detection only\n"
            "full        : Run all modules in sequence"
        ),
    )
    parser.add_argument("--target",   default="192.168.56.101", help="Target IP (lab VM)")
    parser.add_argument("--port",     type=int, default=80,     help="Target port")
    parser.add_argument("--duration", type=int, default=30,     help="Duration per module (seconds)")
    parser.add_argument("--threads",  type=int, default=20,     help="Thread count")
 
    args = parser.parse_args()
 
    if args.mode == "attack-syn":
        run_syn(args.target, args.port, args.duration, args.threads)
    elif args.mode == "attack-http":
        run_http(args.target, args.port, args.duration, args.threads)
    elif args.mode == "defense":
        run_defense(args.duration)
    elif args.mode == "full":
        run_full(args.target, args.port, args.duration)
