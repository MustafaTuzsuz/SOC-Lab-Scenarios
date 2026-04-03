# Wireshark Cheat Sheet — SOC Analyst Reference

## Essential Display Filters

### IP Filtering
```wireshark
Filter by source IP
ip.src == 192.168.1.100Filter by destination IP
ip.dst == 192.168.1.100Filter by either source or destination
ip.addr == 192.168.1.100Filter between two hosts
ip.addr == 192.168.1.100 and ip.addr == 192.168.1.200Exclude an IP
ip.addr != 192.168.1.100

### TCP/UDP Filtering
```wireshark
📄 tools-and-references/wireshark-cheatsheet.md
GitHub'da → "Add file" → "Create new file" → dosya adı:
tools-and-references/wireshark-cheatsheet.md
İçeriği yapıştır:
markdown# Wireshark Cheat Sheet — SOC Analyst Reference

## Essential Display Filters

### IP Filtering
```wireshark
# Filter by source IP
ip.src == 192.168.1.100

# Filter by destination IP
ip.dst == 192.168.1.100

# Filter by either source or destination
ip.addr == 192.168.1.100

# Filter between two hosts
ip.addr == 192.168.1.100 and ip.addr == 192.168.1.200

# Exclude an IP
ip.addr != 192.168.1.100
```

### TCP/UDP Filtering
```wireshark
# Filter by port
tcp.port == 22
udp.port == 53

# Filter by source port
tcp.srcport == 4444

# Filter by destination port
tcp.dstport == 80

# Show only SYN packets — detect scans
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Show only RST packets — connection resets
tcp.flags.reset == 1

# Show TCP handshakes
tcp.flags.syn == 1
```

### HTTP Filtering
```wireshark
# All HTTP traffic
http

# HTTP GET requests
http.request.method == "GET"

# HTTP POST requests — potential exfiltration
http.request.method == "POST"

# Filter by URL keyword
http.request.uri contains "login"
http.request.uri contains "upload"

# HTTP response codes
http.response.code == 200
http.response.code == 404
http.response.code == 500
```

### DNS Filtering
```wireshark
# All DNS traffic
dns

# DNS queries only
dns.flags.response == 0

# DNS responses only
dns.flags.response == 1

# Filter by domain
dns.qry.name contains "google"

# Large DNS packets — potential tunnelling
dns and frame.len > 512

# Failed DNS lookups
dns.flags.rcode != 0
```

### Attack Detection Filters
```wireshark
# Port scan detection — SYN flood
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Brute force — high volume to single port
ip.src == 192.168.1.200 and tcp.port == 22

# Data exfiltration — large outbound frames
ip.src == 192.168.1.50 and frame.len > 1400

# ARP spoofing detection
arp.duplicate-address-detected

# ICMP flood
icmp and ip.src == 192.168.1.100

# C2 beaconing — periodic traffic to external IP
ip.dst == 203.0.113.42

# DNS tunnelling
dns and frame.len > 512

# Suspicious user agents
http.user_agent contains "curl"
http.user_agent contains "python"
http.user_agent contains "nmap"
```

---

## Capture Filters (Before Capture Starts)
```bash
# Capture only traffic from specific host
host 192.168.1.100

# Capture only TCP traffic
tcp

# Capture only port 22
port 22

# Capture all except port 80
not port 80

# Capture traffic between two hosts
host 192.168.1.100 and host 192.168.1.200

# Save capture to file
tcpdump -i eth0 -w capture.pcap
```

---

## Statistics — Key Menus

| Menu | Purpose |
|---|---|
| Statistics → Conversations | Top talkers — source/dest pairs |
| Statistics → Protocol Hierarchy | Protocol breakdown |
| Statistics → IO Graph | Traffic volume over time — beaconing |
| Statistics → Endpoints | All IPs/MACs seen in capture |
| Analyze → Expert Info | Automatic anomaly detection |

---

## Common IOC Indicators

| Pattern | Indicator |
|---|---|
| SYN packets, no ACK | Port scan |
| High failed SSH attempts | Brute force |
| Large POST requests | Data exfiltration |
| Periodic outbound traffic | C2 beaconing |
| Oversized DNS packets | DNS tunnelling |
| Traffic to unusual ports | C2 or malware |
| Multiple failed logins | Credential attack |
| ARP duplicates | ARP spoofing / MITM |

---

## Useful CLI Commands
```bash
# Capture and save to file
tcpdump -i eth0 -w output.pcap

# Read saved capture
tcpdump -r output.pcap

# Filter by host while capturing
tcpdump -i eth0 host 192.168.1.100

# Count packets from IP
tcpdump -r output.pcap | grep "192.168.1.100" | wc -l

# Extract HTTP traffic
tcpdump -r output.pcap -A port 80

# Live capture with verbose output
tcpdump -i eth0 -v
```

---

## MITRE ATT&CK Quick Reference

| Technique | ID | Detection |
|---|---|---|
| Network Scanning | T1046 | SYN flood, sequential ports |
| Brute Force | T1110 | Auth log failures |
| Data Exfiltration | T1041 | Large outbound transfers |
| C2 Communication | T1071 | Beaconing, unusual destinations |
| DNS Tunnelling | T1071.004 | Oversized DNS packets |
| ARP Spoofing | T1557.002 | Duplicate ARP responses |
