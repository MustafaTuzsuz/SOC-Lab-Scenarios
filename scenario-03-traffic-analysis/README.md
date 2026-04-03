# Scenario 03 — Anomalous Traffic Analysis

## Overview
**Attack type:** Suspected Data Exfiltration / C2 Communication  
**Detection tool:** Wireshark  
**Severity:** High  
**Status:** Detected & Investigated  

---

## Scenario Description

A workstation on the internal network is generating unusual outbound 
traffic — large data transfers to an unknown external IP at irregular 
intervals. Behaviour is consistent with Command & Control (C2) 
communication or data exfiltration.

**Goal:** Analyse the suspicious traffic, identify IOCs, determine 
scope of potential compromise, and recommend response actions.

---

## Attack Timeline

14:22:10 — Unusual outbound traffic detected from 192.168.1.50
14:22:10 — Large POST requests to unknown external IP: 203.0.113.42
14:22:15 — Data transfer volume: 450MB in 5 minutes
14:22:20 — Periodic beaconing pattern identified — 60s intervals
14:22:25 — C2 communication pattern confirmed
14:22:30 — Host isolated — investigation initiated

---

## Detection Steps

### Step 1 — Identify Unusual Traffic Volume
```wireshark
# Show all outbound traffic from suspect host
ip.src == 192.168.1.50

# Filter large packets — potential exfiltration
ip.src == 192.168.1.50 and frame.len > 1400

# Show HTTP POST requests — common exfil method
http.request.method == "POST" and ip.src == 192.168.1.50
```

### Step 2 — Identify Beaconing Pattern
```wireshark
# Filter traffic to external IP
ip.dst == 203.0.113.42

# Look for periodic intervals
# Wireshark → Statistics → IO Graph
# Regular spikes = beaconing behaviour
```

### Step 3 — Analyse DNS Queries
```wireshark
# Show all DNS queries from suspect host
dns and ip.src == 192.168.1.50

# Look for unusual domains — long random strings = DGA
dns.qry.name contains ".ru" or dns.qry.name contains ".xyz"

# DNS tunnelling indicator — unusually large DNS queries
dns and frame.len > 512
```

### Step 4 — Check Protocol Usage
```wireshark
# Unexpected protocols from workstation
ip.src == 192.168.1.50 and not tcp.port == 80 \
and not tcp.port == 443 and not tcp.port == 53

# Encrypted traffic to non-standard ports
ip.src == 192.168.1.50 and tcp.port != 443 and tcp.port != 80
```

### Step 5 — Wireshark Statistics
Statistics → Conversations → IPv4
→ Sort by bytes — identify top talkers
Statistics → Protocol Hierarchy
→ Look for unexpected protocols
Statistics → IO Graph
→ Identify beaconing intervals

---

## Findings

| IOC | Value |
|---|---|
| Attack type | C2 Communication + Data Exfiltration |
| Compromised host | 192.168.1.50 |
| External C2 IP | 203.0.113.42 |
| Data transferred | ~450MB |
| Beaconing interval | Every 60 seconds |
| Protocol used | HTTPS (port 443) |
| Duration | 35 minutes before detection |
| Exfil method | Encrypted POST requests |

---

## Risk Assessment

| Factor | Assessment |
|---|---|
| Severity | Critical |
| Intent | Data theft + persistent access |
| Immediate threat | Critical — active exfiltration |
| Risk if ignored | Catastrophic — full data breach |

---

## Containment Actions

### Immediate
```bash
# Isolate compromised host — block all traffic
iptables -A INPUT -s 192.168.1.50 -j DROP
iptables -A OUTPUT -d 192.168.1.50 -j DROP

# Block C2 server at perimeter firewall
iptables -A OUTPUT -d 203.0.113.42 -j DROP

# Preserve evidence — capture full traffic
tcpdump -i eth0 host 192.168.1.50 -w evidence.pcap
```

### Investigation
```bash
# Check running processes on compromised host
ps aux | grep -v "^root"

# Check network connections
ss -tlnp
netstat -antp | grep 203.0.113.42

# Check scheduled tasks — persistence mechanism
crontab -l
ls -la /etc/cron*

# Review bash history
cat ~/.bash_history
```

### Recovery
- Reimage compromised host from clean backup
- Reset all credentials that may have been exposed
- Review and rotate API keys and secrets
- Conduct full network scan for lateral movement

---

## Wireshark Filters — Quick Reference
```wireshark
# Large outbound transfers
ip.src == 192.168.1.50 and frame.len > 1400

# Beaconing — periodic traffic
ip.dst == 203.0.113.42

# DNS anomalies
dns and frame.len > 512

# HTTP exfiltration
http.request.method == "POST"

# Non-standard port traffic
tcp.port != 80 and tcp.port != 443 and tcp.port != 53
```

---

## Lessons Learned

- Baseline normal traffic — anomalies only visible against a baseline
- Beaconing detection requires IO graph analysis over time
- Encrypted C2 traffic hides in plain sight on port 443
- Network segmentation limits blast radius of compromise
- Full packet capture essential for post-incident forensics

---

## References

- [MITRE ATT&CK — Exfiltration T1041](https://attack.mitre.org/techniques/T1041/)
- [MITRE ATT&CK — C2 T1071](https://attack.mitre.org/techniques/T1071/)
- [Wireshark IO Graph Guide](https://www.wireshark.org/docs/wsug_html_chunked/ChStatIOGraphs.html)
