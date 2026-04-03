# Scenario 01 — Port Scan Detection

## Overview
**Attack type:** Network Reconnaissance  
**Tool used by attacker:** Nmap  
**Detection tool:** Wireshark  
**Severity:** Medium  
**Status:** Detected & Documented  

---

## Scenario Description

An unknown host on the network begins sending an unusually high volume 
of TCP SYN packets to multiple ports on a target machine in a short 
time window — a classic indicator of a port scan.

**Goal:** Detect the scan, identify the source, document findings, 
and recommend containment actions.

---

## Attack Timeline

10:02:31 — First SYN packet observed from 192.168.1.105
10:02:31 — Rapid SYN packets to ports 22, 80, 443, 3306, 8080...
10:02:33 — 1,000+ SYN packets in under 2 seconds
10:02:33 — No corresponding ACK responses — SYN scan confirmed
10:02:35 — Alert triggered — investigation initiated

---

## Detection Steps

### Step 1 — Capture Traffic
Start Wireshark capture on the monitored interface:
Interface: eth0
Capture filter: host 192.168.1.105

### Step 2 — Apply Display Filter
Isolate SYN packets (no ACK flag = scan traffic): 
tcp.flags.syn == 1 and tcp.flags.ack == 0

### Step 3 — Identify Pattern
- Single source IP sending SYN to sequential ports
- No three-way handshake completing
- High packet rate in short time window

### Step 4 — Extract IOCs
Source IP:     192.168.1.105
Target IP:     192.168.1.10
Ports scanned: 1–1024 (sequential)
Scan duration: ~2 seconds
Packet count:  1,024 SYN packets
Tool detected: Nmap (TTL=64, window size=1024)

### Step 5 — Confirm with Statistics
Wireshark → Statistics → Conversations → TCP tab  
Sort by packets — source IP with highest count = scanner

---

## Wireshark Filters Used
```wireshark
# Detect SYN scan
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Filter by source IP
ip.src == 192.168.1.105

# Show only RST responses (closed ports)
tcp.flags.reset == 1

# High packet rate from single source
ip.src == 192.168.1.105 and tcp.flags.syn == 1
```

---

## Findings

| IOC | Value |
|---|---|
| Attack type | TCP SYN Port Scan |
| Source IP | 192.168.1.105 |
| Target IP | 192.168.1.10 |
| Ports targeted | 1–1024 |
| Duration | ~2 seconds |
| Packets sent | 1,024 |
| Open ports found | 22 (SSH), 80 (HTTP) |
| Tool fingerprint | Nmap default scan |

---

## Risk Assessment

| Factor | Assessment |
|---|---|
| Severity | Medium |
| Intent | Reconnaissance — likely precursor to attack |
| Immediate threat | Low — scan only, no exploitation yet |
| Risk if ignored | High — attacker mapping network for next stage |

---

## Containment Actions

1. **Block source IP** at firewall level immediately
```bash
   iptables -A INPUT -s 192.168.1.105 -j DROP
```

2. **Alert escalation** — notify security team with IOC report

3. **Review open ports** — close unnecessary services
```bash
   ss -tlnp   # List listening ports
```

4. **Check auth logs** — verify no access attempts on open ports
```bash
   grep "192.168.1.105" /var/log/auth.log
```

5. **Document and monitor** — flag IP for continued observation

---

## Lessons Learned

- SYN scans are fast and stealthy — Wireshark filters essential
- Open ports 22 and 80 should be reviewed and hardened
- Firewall rules should block unknown internal IPs by default
- Early detection of reconnaissance prevents escalation

---

## References

- [Nmap Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)
- [MITRE ATT&CK — Network Scanning T1046](https://attack.mitre.org/techniques/T1046/)
