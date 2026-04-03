# Scenario 02 — SSH Brute Force Detection

## Overview
**Attack type:** Credential Attack — Brute Force  
**Target service:** SSH (port 22)  
**Detection tools:** Linux auth logs, Wireshark  
**Severity:** High  
**Status:** Detected & Contained  

---

## Scenario Description

An attacker attempts to gain unauthorised access to a Linux server 
by systematically trying username and password combinations via SSH.
The high volume of failed authentication attempts triggers investigation.

**Goal:** Detect brute force activity, identify source, contain 
the attack, and harden the system against future attempts.

---

## Attack Timeline

11:15:42 — First SSH connection attempt from 192.168.1.200
11:15:42 — Rapid sequential login failures begin
11:15:44 — 50+ failed attempts in under 3 seconds
11:15:45 — auth.log alert threshold exceeded
11:15:46 — Investigation initiated
11:16:10 — Source IP blocked at firewall

---

## Detection Steps

### Step 1 — Monitor Auth Logs
```bash
# Real-time SSH failure monitoring
tail -f /var/log/auth.log | grep "Failed password"

# Count failures per IP
grep "Failed password" /var/log/auth.log | \
awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Show all attempts from specific IP
grep "192.168.1.200" /var/log/auth.log
```

### Step 2 — Sample Log Output
Nov 14 11:15:42 server sshd[1234]: Failed password for root from 192.168.1.200 port 54321 ssh2
Nov 14 11:15:42 server sshd[1234]: Failed password for admin from 192.168.1.200 port 54321 ssh2
Nov 14 11:15:43 server sshd[1235]: Failed password for root from 192.168.1.200 port 54322 ssh2
Nov 14 11:15:43 server sshd[1235]: Failed password for ubuntu from 192.168.1.200 port 54322 ssh2
Nov 14 11:15:44 server sshd[1236]: Failed password for root from 192.168.1.200 port 54323 ssh2

### Step 3 — Wireshark Confirmation
```wireshark
# Filter SSH traffic from attacker
ip.src == 192.168.1.200 and tcp.port == 22

# Show TCP handshakes (each = new attempt)
tcp.flags.syn == 1 and tcp.port == 22

# High connection rate indicator
ip.src == 192.168.1.200
```

### Step 4 — Quantify the Attack
```bash
# Total failed attempts
grep "Failed password" /var/log/auth.log | \
grep "192.168.1.200" | wc -l

# Usernames targeted
grep "Failed password" /var/log/auth.log | \
grep "192.168.1.200" | awk '{print $9}' | sort | uniq -c | sort -rn
```

---

## Findings

| IOC | Value |
|---|---|
| Attack type | SSH Brute Force |
| Source IP | 192.168.1.200 |
| Target IP | 192.168.1.10 |
| Target port | 22 (SSH) |
| Attempts | 347 failed logins |
| Duration | ~4 minutes |
| Usernames tried | root, admin, ubuntu, user |
| Successful login | No |

---

## Risk Assessment

| Factor | Assessment |
|---|---|
| Severity | High |
| Intent | Unauthorised access |
| Immediate threat | High — active attack in progress |
| Risk if ignored | Critical — potential system compromise |

---

## Containment Actions

### Immediate Response
```bash
# Block attacker IP at firewall
iptables -A INPUT -s 192.168.1.200 -j DROP

# Verify block is active
iptables -L INPUT -n | grep 192.168.1.200
```

### Short-term Hardening
```bash
# Disable root SSH login
sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config

# Change SSH to non-standard port
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config

# Restart SSH service
systemctl restart sshd

# Install fail2ban — auto-ban brute force IPs
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban
```

### Long-term Hardening
```bash
# Disable password authentication — key-based only
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' \
/etc/ssh/sshd_config

# Allow SSH only from trusted IPs
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP
```

---

## Lessons Learned

- Root login over SSH should always be disabled
- Password authentication alone is insufficient — use key-based auth
- fail2ban essential for automated brute force protection
- Non-standard SSH port reduces automated scanning noise
- Log monitoring must be continuous — not reactive

---

## References

- [MITRE ATT&CK — Brute Force T1110](https://attack.mitre.org/techniques/T1110/)
- [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [SSH Hardening Guide](https://www.ssh.com/academy/ssh/sshd_config)
