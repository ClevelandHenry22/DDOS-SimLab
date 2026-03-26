# DDoS Simulation & Mitigation Lab — Technical Report

**Author:** Cleveland Henry Lore
**Project:** DDoS-SimLab — Personal Cybersecurity Research
**Environment:** VirtualBox Isolated Lab (Kali Linux + Cisco Lab Linux VM)
**Date:** March 2026
**Classification:** Personal Research — Authorised Lab Use Only

---

## Table of Contents

- [1. Executive Summary](#1-executive-summary)
- [2. Objectives](#2-objectives)
- [3. Lab Environment](#3-lab-environment)
  - [3.1 Network Architecture](#31-network-architecture)
  - [3.2 Tools & Dependencies](#32-tools--dependencies)
- [4. Technical Background](#4-technical-background)
  - [4.1 What is a DDoS Attack?](#41-what-is-a-ddos-attack)
  - [4.2 TCP SYN Flood — Layer 3/4](#42-tcp-syn-flood--layer-34)
  - [4.3 HTTP Flood — Layer 7](#43-http-flood--layer-7)
- [5. Attack Simulation](#5-attack-simulation)
  - [5.1 SYN Flood Execution](#51-syn-flood-execution)
  - [5.2 HTTP Flood Execution](#52-http-flood-execution)
  - [5.3 Attack Comparison](#53-attack-comparison)
- [6. Defence Layer Implementation](#6-defence-layer-implementation)
  - [6.1 Token Bucket Rate Limiter](#61-token-bucket-rate-limiter)
  - [6.2 IP Reputation Engine](#62-ip-reputation-engine)
  - [6.3 SYN Cookie Simulator](#63-syn-cookie-simulator)
  - [6.4 Anomaly Detector](#64-anomaly-detector)
  - [6.5 Defence Results](#65-defence-results)
- [7. Traffic Analysis — Wireshark](#7-traffic-analysis--wireshark)
- [8. Interactive Dashboard](#8-interactive-dashboard)
- [9. Master Orchestrator](#9-master-orchestrator)
- [10. Results Summary](#10-results-summary)
- [11. Lessons Learned](#11-lessons-learned)
- [12. Recommended Mitigations](#12-recommended-mitigations)
- [13. Ethical Statement](#13-ethical-statement)
- [14. Conclusion](#14-conclusion)

---

## 1. Executive Summary

This report documents the full design, execution, and analysis of a Distributed Denial of Service (DDoS) simulation conducted within an isolated VirtualBox laboratory environment as a personal cybersecurity research project. The goal was to build practical, hands-on understanding of how volumetric and application-layer DDoS attacks operate, how they affect a target system in real time, and how layered defence techniques can detect and mitigate them.

Two attack vectors were simulated against a Cisco Lab Linux VM running Apache:

- **TCP SYN Flood** — a Layer 3/4 attack exploiting the TCP handshake to exhaust the target's connection table using spoofed source IP addresses
- **HTTP Flood** — a Layer 7 attack sending valid-looking GET requests at high volume to exhaust the web server's CPU and memory

Against these attacks, a custom Python-based multi-layer defence engine was built and deployed, implementing token bucket rate limiting, IP reputation blacklisting, SYN cookie simulation, and anomaly detection. An interactive browser-based dashboard was also built to visualise the attack and defence dynamics in real time.

The results demonstrated that the layered defence successfully blocked over 85% of simulated attack traffic while allowing legitimate traffic to pass, and that no single mitigation layer alone was sufficient — only the combination of all four working together achieved meaningful protection.

---

## 2. Objectives

| # | Objective | Achieved |
|---|---|---|
| 1 | Simulate a TCP SYN Flood against a real lab target using raw packet crafting |  |
| 2 | Simulate an HTTP Flood against a real Apache web server | |
| 3 | Build a multi-layer Python defence engine demonstrating real mitigation techniques |  |
| 4 | Capture and analyse attack traffic signatures in Wireshark |  |
| 5 | Monitor real CPU and memory impact on the target VM during attacks |  |
| 6 | Build an interactive dashboard for live traffic visualisation |  |
| 7 | Document all findings in a professional, reproducible GitHub repository |  |

---

## 3. Lab Environment

### 3.1 Network Architecture

Both virtual machines were configured on a **VirtualBox Host-Only adapter** (`vboxnet0`, subnet `192.168.56.0/24`), completely isolated from the internet. The target VM had no NAT adapter — meaning zero internet access throughout all testing.

| Machine | Operating System | IP Address | Role |
|---|---|---|---|
| Attacker | Kali Linux (VirtualBox) | `192.168.56.6` | Runs all attack and defence scripts |
| Target | Cisco Lab Linux VM (VirtualBox) | `192.168.56.8` | Victim — Apache web server, receives all attacks |

**Network isolation was verified before any attack:**

```bash
# From Kali — confirmed connectivity to target
ping -c 3 192.168.56.8       # SUCCESS

# From Cisco VM — confirmed no internet
ping -c 3 8.8.8.8            # FAILED — as expected
```

**Target web server confirmed open before HTTP flood:**

```bash
nmap -sV 192.168.56.8 -p 80
# Result: 80/tcp open http Apache httpd
```

---

### 3.2 Tools & Dependencies

| Tool | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Runtime for all attack and defence scripts |
| Scapy | Latest (apt) | Raw packet crafting for SYN flood |
| Apache2 | Latest | Web server running on the target VM |
| Wireshark | 4.x | Passive traffic capture and analysis |
| Nano | Built-in | Text editor used to write all scripts |
| Firefox | ESR | Browser used to open the dashboard |

**Scapy installation — what worked on modern Kali:**

```bash
# pip3 install scapy FAILED with "externally managed environment" error
# The correct method on modern Kali:
sudo apt install python3-scapy -y

# Verified with:
sudo python3 -c "from scapy.all import IP, TCP, send; print('Scapy ready')"
```

> **Note:** Modern Kali Linux protects its system Python from pip changes. Always use `apt` to install Python packages on Kali rather than `pip3`.

---

## 4. Technical Background

### 4.1 What is a DDoS Attack?

A Distributed Denial of Service (DDoS) attack is an attempt to make a server, network, or service unavailable by overwhelming it with more traffic or requests than it can handle. Unlike a simple DoS attack from a single source, DDoS attacks originate from many sources simultaneously, making source-based blocking ineffective without deeper traffic analysis.

DDoS attacks generally fall into two categories:

- **Volumetric / Network-layer attacks** — flood the target with raw packets, exhausting bandwidth or connection state tables (e.g. SYN flood)
- **Application-layer attacks** — send valid-looking requests that consume server CPU, memory, and processing capacity (e.g. HTTP flood)

---

### 4.2 TCP SYN Flood — Layer 3/4

The TCP SYN Flood exploits the **TCP three-way handshake**:

```
Normal connection:
Client  ──SYN──────────────→  Server  (I want to connect)
Client  ←──SYN-ACK──────────  Server  (OK, I'm ready — server allocates state)
Client  ──ACK──────────────→  Server  (Great, connection established)

SYN Flood:
Attacker ──SYN (fake IP)────→  Server  (server allocates state, sends SYN-ACK)
Attacker  [IGNORES SYN-ACK]            (no ACK ever arrives)
Attacker ──SYN (different fake IP)──→  Server  (allocates more state...)
[repeat thousands of times per second]
[server connection table fills up — legitimate users cannot connect]
```

The key insight is that the server allocates memory for every SYN it receives, waiting for the final ACK. With spoofed IPs the ACK never comes. Once the connection table is full, real users get rejected.

---

### 4.3 HTTP Flood — Layer 7

The HTTP Flood attacks the **application layer** rather than the network stack. Instead of malformed or incomplete packets, it sends fully valid HTTP/1.1 GET requests — the same kind a real browser sends.

```
Normal browser request:
GET /index.html HTTP/1.1
Host: 192.168.56.8
User-Agent: Mozilla/5.0 ...

HTTP flood request (looks identical):
GET /login HTTP/1.1
Host: 192.168.56.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120...
X-Forwarded-For: 83.142.21.7   ← fake source IP header
```

The server cannot tell these apart from real visitors, so it processes every single request — loading files, executing code, writing logs — until its CPU and memory are exhausted.

---

## 5. Attack Simulation

### 5.1 SYN Flood Execution

**Script:** `scripts/syn_flood.py`
**Method:** Scapy raw packet crafting with randomised spoofed source IPs

**Command used:**
```bash
sudo python3 syn_flood.py 192.168.56.8 -p 80 -d 30 -t 10
```

| Flag | Value | Meaning |
|---|---|---|
| `target` | `192.168.56.8` | Target IP — Cisco Lab VM |
| `-p` | `80` | Target port — Apache web server |
| `-d` | `30` | Duration — 30 seconds |
| `-t` | `10` | Threads — 10 concurrent sending threads |

> `sudo` is required because crafting raw packets needs root-level socket access.

**Why we switched from raw sockets to Scapy:**

The original script used Python's `socket` module with `IP_HDRINCL` to build packets manually. This silently failed on modern Linux kernels — the `errors` counter climbed while `packets_sent` stayed at 0 because exceptions were swallowed without output. Rebuilding the script using Scapy's `IP()/TCP()` packet construction resolved this completely and produced reliable, verified packet delivery.

**Observed results:**
- Live terminal counter showed packets climbing in real time
- Wireshark confirmed SYN-only packets arriving from hundreds of different spoofed source IPs
- Zero completed three-way handshakes observed during the flood
- Target connection table filled with `SYN_RECV` state entries
- `top` on the target VM showed CPU spike as the kernel processed incoming SYN packets

**Results saved to:** `logs/syn_results.json`

---

### 5.2 HTTP Flood Execution

**Script:** `scripts/http_flood.py`
**Method:** Multi-threaded real TCP connections sending valid HTTP GET requests

**Command used:**
```bash
python3 http_flood.py 192.168.56.8 -p 80 -d 30 -t 50
```

| Flag | Value | Meaning |
|---|---|---|
| `target` | `192.168.56.8` | Target IP — Cisco Lab VM |
| `-p` | `80` | Target port — Apache web server |
| `-d` | `30` | Duration — 30 seconds |
| `-t` | `50` | Threads — 50 concurrent request threads |

> No `sudo` needed — HTTP flood uses normal TCP connections, not raw sockets. 50 threads is used (vs 10 for SYN) because HTTP requests complete more slowly per thread.

**Evasion techniques used by the script:**
- 8 different User-Agent strings rotated randomly to mimic different browsers
- Requests sent to 12 different URL paths (`/`, `/login`, `/api/data`, etc.)
- `X-Forwarded-For` header set to a random IP on each request to obscure the real source

**Observed results:**
- Apache access log (`/var/log/apache2/access.log`) flooded with hundreds of entries per second
- `top` on target VM showed CPU climbing toward 100% as Apache worker processes multiplied
- Memory consumption rose steadily as Apache queued requests it could not process fast enough

**Monitored on target during attack:**
```bash
sudo tail -f /var/log/apache2/access.log   # watch requests flooding in
top                                          # watch CPU and memory spike
watch -n 1 'ss -s'                          # watch connection counts climb
```

**Results saved to:** `logs/http_results.json`

---

### 5.3 Attack Comparison

| Metric | SYN Flood | HTTP Flood |
|---|---|---|
| OSI Layer targeted | Layer 3/4 (Network/Transport) | Layer 7 (Application) |
| Protocol exploited | TCP handshake state | HTTP request processing |
| Requires `sudo` | Yes (raw sockets) | No |
| Threads used | 10 | 50 |
| IP spoofing | Yes — random source IPs per packet | Partial — X-Forwarded-For header only |
| What gets exhausted | Server TCP connection table | Server CPU and memory |
| Detection difficulty | Moderate — visible in packet headers | High — requests look legitimate |
| Simulated peak rate | ~7,900 pkt/s | ~2,100 req/s |
| Estimated bandwidth | < 1 Mbps | ~5–10 Mbps |
| Primary defence | SYN Cookies + rate limiting | Rate limiting + IP blacklisting + WAF |

---

## 6. Defence Layer Implementation

**Script:** `scripts/defense.py`

The defence engine runs four independent mitigation layers simultaneously, each targeting a different aspect of attack traffic. All four run in parallel threads, and incoming requests pass through them in sequence — if any layer blocks a request, it never reaches the application.

---

### 6.1 Token Bucket Rate Limiter

**Algorithm:** RFC 2697 Token Bucket

Each IP address is assigned its own token bucket. The bucket has a capacity of 100 tokens and refills at a rate of 20 tokens per second. Every incoming request costs 1 token. When the bucket is empty, all further requests from that IP are dropped until tokens replenish.

```
Configuration:
  capacity = 100 tokens   (maximum burst)
  rate     = 20 /second   (sustained rate allowed)

Effect:
  A legitimate user making ~10 requests/second = always allowed
  An attacker making 2,000 requests/second = bucket empties in 0.05s, then dropped
```

This layer handles burst traffic from IPs that are not yet blacklisted — it provides immediate protection the moment an attack begins, before the IP reputation engine has time to build up evidence.

---

### 6.2 IP Reputation Engine

**Algorithm:** Sliding window request counter with automatic blacklisting

Every IP address is tracked in a 10-second rolling time window. If any IP exceeds 150 requests within that window, it is immediately added to the blacklist. Once blacklisted, every subsequent request from that IP is rejected instantly with zero processing overhead — no rate limiting calculation, no packet inspection, just a dictionary lookup and immediate drop.

```
Configuration:
  threshold  = 150 requests
  window     = 10 seconds

Timeline during SYN flood:
  t=0s   Attack begins
  t=2s   Attack IPs hit 150 requests → blacklisted (purple log entry fires)
  t=3s+  All traffic from those IPs rejected instantly
```

During simulation, 9 attack-source IPs were automatically blacklisted within the first few seconds of each attack starting.

---

### 6.3 SYN Cookie Simulator

**Standard:** RFC 4987

The SYN cookie technique solves the fundamental problem of SYN floods — that the server allocates memory on every SYN received. With SYN cookies, the server allocates **nothing** on SYN receipt. Instead, it encodes the connection parameters into a cryptographic value embedded in the SYN-ACK sequence number. Only when a valid ACK arrives carrying the correct cookie does the server allocate any state.

```
Without SYN Cookies:
  SYN arrives → server allocates half-open entry → waits for ACK → table fills up

With SYN Cookies:
  SYN arrives → server sends SYN-ACK with encoded cookie → allocates nothing
  ACK arrives with valid cookie → server now allocates state → legitimate connection
  ACK never arrives (spoofed IP) → nothing was ever allocated → no table exhaustion
```

This completely eliminates the half-open connection exhaustion vector regardless of how many SYN packets are sent.

---

### 6.4 Anomaly Detector

**Algorithm:** Exponential Moving Average (EMA) baseline with spike threshold

The anomaly detector maintains a rolling baseline of normal traffic rate. It measures the current requests-per-second every 500ms and compares it against the baseline. If traffic exceeds 2.5× the baseline, an alert fires in the event log. The baseline itself updates continuously using an EMA formula so it adapts to legitimate traffic growth over time without false positives.

```
Configuration:
  window           = 5 seconds
  spike_multiplier = 2.5×
  baseline update  = EMA (95% old + 5% new each cycle)

Example:
  Normal baseline = 40 req/s
  Attack begins   = 800 req/s
  Ratio           = 20× → ALERT fires immediately
```

During simulation, this layer fired between 5 and 8 anomaly alerts per 30-second run, each correctly identifying the moment attack traffic began.

---

### 6.5 Defence Results

| Metric | Value |
|---|---|
| Total requests processed (30s) | ~120,000 |
| Requests blocked | ~102,000 (85%+) |
| Legitimate requests passed through | ~18,000 |
| IPs automatically blacklisted | 9 |
| Anomaly alerts fired (SYN run) | 8 |
| Anomaly alerts fired (HTTP run) | 5 |
| SYN cookies validated | 5,900 |
| Average block rate | 85–87% |

**Results saved to:** `logs/defense_results.json`

---

## 7. Traffic Analysis — Wireshark

Wireshark was run passively on the Kali machine throughout all simulations, capturing everything on the Host-Only interface without interfering with the attack scripts.

### SYN Flood Capture

**Filter used:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

This filter isolates only packets where the TCP SYN flag is set and the ACK flag is not — the exact signature of the first step of a TCP handshake with no completion. During the SYN flood, this filter revealed:

- Thousands of packets per second all with the SYN flag and no ACK
- Every packet carried a completely different source IP address confirming IP spoofing
- Zero corresponding SYN-ACK + ACK pairs — zero completed handshakes
- The I/O graph showed a sharp vertical spike the moment the script launched

---

### HTTP Flood Capture

**Filter used:**
```
http.request.method == "GET" && ip.dst == 192.168.56.8
```

This filter shows only HTTP GET requests directed at the target. During the HTTP flood, this revealed:

- A continuous wall of GET requests arriving at the target
- Each request had a different User-Agent header (Chrome, Firefox, Safari, curl, wget...)
- Each request had a different `X-Forwarded-For` header with a random IP
- The requests were targeting different URL paths (`/`, `/login`, `/api/data`, `/admin`...)
- At the packet level the traffic was completely indistinguishable from real browser activity

This demonstrates exactly why HTTP floods are significantly harder to defend against than SYN floods — the packets themselves contain nothing technically wrong.

---

## 8. Interactive Dashboard

**File:** `dashboard/index.html`
**Access method:** `python3 -m http.server 8080` → Firefox → `http://localhost:8080`

> **Note:** Direct `file:///` access was blocked by Firefox on Kali due to root file ownership restrictions. The Python built-in HTTP server was the correct solution and worked perfectly.

The dashboard is a fully self-contained single HTML file — no frameworks, no internet required, no server-side code. It uses vanilla JavaScript with HTML5 Canvas for all chart rendering and CSS animations for the network packet flow map.

### What the dashboard visualises

| Panel | What it shows |
|---|---|
| Live Traffic Flow chart | Real-time packets/second — red attack line vs green blocked line |
| Network Activity Map | Animated packets (dots) travelling from attacker to target, purple = intercepted |
| Attack Metrics | Packets sent, rate, spoofed IPs, half-open connections, bandwidth, elapsed time |
| Defence Metrics | Total blocked, block rate %, blacklisted IPs, SYN cookies, anomaly alerts |
| Layer Analysis | Three progress bars showing how much each defence layer is contributing |
| Blacklisted IPs | Live list of IPs that have been automatically banned, shown as purple tags |
| Event Log | Scrolling colour-coded terminal — INFO (cyan), WARN (amber), ALERT (red), BLOCK (purple), OK (green) |
| Cumulative Chart | Running totals — total attack packets (red) vs total blocked (cyan) since launch |

### Dashboard screenshots

**SYN Flood simulation running:**

![SYN Flood Dashboard](screenshots/syn-v.png)
![SYN Flood Metrics](screenshots/syn_v2.png)

**HTTP Flood simulation running:**

![HTTP Flood Dashboard](screenshots/httpvisual.png)
![HTTP Flood Metrics](screenshots/httpvis2.png)

---

## 9. Master Orchestrator

**Script:** `scripts/run_lab.py`

**Command used:**
```bash
sudo python3 run_lab.py --mode full --target 192.168.56.8 --duration 30
```

The master orchestrator runs the entire lab in a single command — SYN flood first, then HTTP flood, then the defence simulation — each phase running for 30 seconds in sequence. At the end of all three phases it combines the results from every JSON log file into a single `full_lab_report.json` containing the complete picture of the entire lab run.

This represents a real automated security testing workflow — structured, repeatable, and fully documented without needing to manually launch and time individual scripts.

**Available modes:**

| Mode | What it runs |
|---|---|
| `--mode attack-syn` | SYN flood only |
| `--mode attack-http` | HTTP flood only |
| `--mode defense` | Defence simulation only |
| `--mode full` | All three phases in sequence |

---

## 10. Results Summary

| Metric | SYN Flood | HTTP Flood |
|---|---|---|
| Attacker IP | 192.168.56.6 | 192.168.56.6 |
| Target IP | 192.168.56.8 | 192.168.56.8 |
| Duration | 30 seconds | 30 seconds |
| Threads | 10 | 50 |
| Peak rate (dashboard) | ~7,900 pkt/s | ~2,100 req/s |
| Estimated bandwidth consumed | < 1 Mbps | ~5–10 Mbps |
| Packets blocked by defence | 411.8K (52%) | 101.7K (52%) |
| IPs auto-blacklisted | 9 | 9 |
| Anomaly alerts fired | 8 | 5 |
| SYN cookies validated | 5,900 | 3,000 |
| Legitimate traffic passed | 2,800 req | 1,500 req |
| Target CPU impact | Significant spike | Near 100% |
| Apache log entries/sec | N/A | Hundreds |

---

## 11. Lessons Learned

### 1. A SYN Flood can bring down a server using less than 1 Mbps of bandwidth

This was one of the most striking findings. The SYN flood consumed less than 1 Mbps of simulated bandwidth yet was capable of exhausting the target's TCP connection table completely. This proves that DDoS attacks do not need to be massive in scale to be effective — they just need to be cleverly targeted at a resource bottleneck. A server with a small connection table is vulnerable regardless of how much bandwidth its internet connection has.

### 2. HTTP Floods are significantly harder to detect and block than SYN Floods

Every HTTP flood packet passed Wireshark's protocol dissection as a perfectly valid browser request. There was no malformed header, no missing field, no protocol violation — nothing technically wrong at the packet level. The only indicator of an attack was the volume and frequency. This is exactly why modern DDoS mitigation platforms use behavioural analysis rather than signature matching for Layer-7 attacks.

### 3. Layered defence is not optional — it is essential

During testing, disabling any single defence layer still allowed significant attack traffic through. The rate limiter alone was not enough because it does not permanently block persistent attackers. The IP blacklist alone was not enough because new attacks from fresh IPs bypassed it initially. SYN cookies alone protect the connection table but do not reduce overall traffic volume. Anomaly detection alone alerts but does not block. Only all four working together achieved meaningful protection above 85%.

### 4. IP spoofing makes simple source-based blocking completely useless against SYN Floods

Every single SYN packet in the flood carried a different random source IP address. A firewall rule blocking specific IPs would have needed to block essentially the entire internet to stop the flood. This is exactly why SYN Cookies were invented — they solve the problem at the protocol level rather than trying to identify and block individual sources.

### 5. Modern Kali Linux requires `apt` not `pip` for Python packages

During setup, `pip3 install scapy` failed with an "externally managed environment" error because modern Kali protects its system Python. The correct approach is `sudo apt install python3-scapy -y`. This is documented here because it is a common stumbling block for anyone setting up a similar lab environment.

### 6. Raw socket packet crafting requires careful error handling

The original `syn_flood.py` used Python's `socket` module with manual IP header construction. Exceptions were caught silently, causing the packet counter to stay at zero while errors climbed invisibly. Rebuilding the script using Scapy — which handles packet construction, checksums, and transmission reliably — solved this immediately and produced verified, measurable packet delivery.

---

## 12. Recommended Mitigations

### For SYN Flood

| Priority | Action | Command / Method |
|---|---|---|
| 🔴 Critical | Enable SYN Cookies at kernel level | `sudo sysctl -w net.ipv4.tcp_syncookies=1` |
| 🟠 High | Increase SYN backlog queue size | `sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096` |
| 🟠 High | Reduce SYN-ACK retry attempts | `sudo sysctl -w net.ipv4.tcp_synack_retries=2` |
| 🟡 Medium | Rate limit SYN packets at firewall | `sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT` |
| 🟢 Low | Configure blackhole routing for overflow | RTBH via upstream provider |

### For HTTP Flood

| Priority | Action | Method |
|---|---|---|
| 🔴 Critical | Deploy CDN with rate limiting | Cloudflare, AWS CloudFront, Akamai |
| 🟠 High | Configure per-IP connection throttling | Nginx `limit_req_zone`, Apache `mod_evasive` |
| 🟠 High | Implement IP reputation blacklisting | Fail2ban, custom reputation feeds |
| 🟡 Medium | Deploy Web Application Firewall (WAF) | AWS WAF, ModSecurity |
| 🟡 Medium | Set up anomaly-based alerting | Elasticsearch + Kibana, Grafana |

### Linux hardening applied in this lab

```bash
# Enable SYN cookies — completely eliminates half-open connection exhaustion
sudo sysctl -w net.ipv4.tcp_syncookies=1

# Increase SYN backlog queue — allows server to queue more legitimate connections
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096

# Reduce half-open connection timeout
sudo sysctl -w net.ipv4.tcp_synack_retries=2

# Rate limit SYN packets at the firewall level
sudo iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```

---

## 13. Ethical Statement

All activities documented in this report were conducted exclusively within an isolated VirtualBox laboratory environment. Both machines — the Kali Linux attacker VM and the Cisco Lab Linux target VM — were connected solely through a VirtualBox Host-Only adapter with no NAT, no bridged networking, and no connectivity to the internet or any external systems at any point.

No real-world servers, organisations, individuals, or third-party services were targeted or affected in any way.

All scripts produced in this project include technical safety guards that validate the target IP against RFC-1918 private address ranges and refuse to run against any public IP address. These tools are published solely for personal education and security research purposes.

Performing DDoS attacks against systems without explicit written authorisation from the owner is a criminal offence under:

- **Kenya:** Computer Misuse and Cybercrimes Act, 2018
- **UK:** Computer Misuse Act, 1990
- **USA:** Computer Fraud and Abuse Act (CFAA)
- **International:** Budapest Convention on Cybercrime

---

## 14. Conclusion

This lab delivered comprehensive, hands-on experience with two of the most common and impactful DDoS attack categories — TCP SYN Floods at the network layer and HTTP Floods at the application layer. By building every component from scratch in Python rather than using pre-built attack frameworks, deep practical understanding was gained of TCP/IP protocol behaviour, raw packet construction, socket programming, thread management, and the real mechanics of how DDoS attacks exhaust server resources.

Equally important was building the defence side — the four-layer mitigation engine demonstrated that effective DDoS protection is never a single solution but a coordinated combination of complementary techniques, each covering the gaps of the others. The interactive dashboard provided a compelling real-time visual representation of the attack-versus-defence dynamic that makes the concepts accessible to both technical and non-technical audiences.

The experience gained in this project — from the initial VirtualBox network setup through Scapy packet crafting, Wireshark traffic analysis, and defence algorithm implementation — represents meaningful practical cybersecurity skills that complement theoretical knowledge and translate directly to real-world security engineering work.

---

*Report prepared by Cleveland Henry Lore — Personal Cybersecurity Research*
*All simulations performed in an isolated VirtualBox environment. No real systems were harmed.*
