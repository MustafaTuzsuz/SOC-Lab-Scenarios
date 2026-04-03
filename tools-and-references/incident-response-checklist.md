# Incident Response Checklist — SOC Analyst

## Phase 1 — Detection
- [ ] Alert received or anomaly identified
- [ ] Initial triage — confirm true positive vs false positive
- [ ] Log timestamp and assign severity level
- [ ] Notify team lead if severity is High or Critical

## Phase 2 — Analysis
- [ ] Identify source IP, destination IP, ports involved
- [ ] Pull relevant logs — auth.log, syslog, firewall logs
- [ ] Capture network traffic — Wireshark / tcpdump
- [ ] Identify attack type and technique (MITRE ATT&CK)
- [ ] Document all IOCs found

## Phase 3 — Containment
- [ ] Isolate affected host from network
- [ ] Block attacker IP at firewall
- [ ] Preserve evidence — do not wipe affected system
- [ ] Revoke compromised credentials immediately

## Phase 4 — Eradication
- [ ] Remove malware or malicious files
- [ ] Close exploited vulnerability
- [ ] Patch affected systems
- [ ] Verify no persistence mechanisms remain

## Phase 5 — Recovery
- [ ] Restore from clean backup if needed
- [ ] Monitor restored system closely for 48 hours
- [ ] Reset all potentially exposed credentials
- [ ] Confirm normal operations resumed

## Phase 6 — Documentation
- [ ] Write full incident report
- [ ] Document timeline of events
- [ ] List all IOCs
- [ ] Record containment and recovery actions
- [ ] Submit lessons learned
