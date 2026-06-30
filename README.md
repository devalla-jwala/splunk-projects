# MITRE ATT&CK Mapping & Threat Detection — Splunk Log Analysis Project

[#mitre-attack-mapping-threat-detection](#mitre-attack-mapping-threat-detection)

## Introduction

[#introduction](#introduction)

This document extends the DHCP, DNS, SMTP, SSH, and Tunnel log analysis projects by mapping detected behaviors to [MITRE ATT&CK](https://attack.mitre.org/) techniques and adding SPL queries specifically aimed at brute-force detection and anomaly identification. The goal is to move from "what does this log show" to "what adversary technique does this log help detect."

## MITRE ATT&CK Technique Mapping

[#mitre-attack-technique-mapping](#mitre-attack-technique-mapping)

| Log Source | Technique ID | Technique Name | Tactic | Why it maps |
|---|---|---|---|---|
| SSH | T1110 / T1110.001 | Brute Force / Password Guessing | Credential Access | Repeated failed logins from one or few source IPs against one or more accounts |
| SSH | T1078 | Valid Accounts | Defense Evasion, Persistence | Successful login following a string of failures (credential compromise) |
| SMTP | T1110.003 | Password Spraying | Credential Access | Many accounts, each tried with few attempts, from the same source — avoids lockouts |
| SMTP | T1566 | Phishing | Initial Access | Anomalous sender domains, spoofed addresses, suspicious attachment types/sizes |
| SMTP | T1071.003 | Application Layer Protocol: Mail Protocols | Command and Control | Mail protocol used for C2 or data exfiltration |
| DNS | T1071.004 | Application Layer Protocol: DNS | Command and Control | High-volume or high-entropy DNS queries indicating tunneling/beaconing |
| DNS | T1568.002 | Dynamic Resolution: DGA | Command and Control | Spikes in NXDOMAIN responses suggesting domain generation algorithms |
| DNS | T1590 | Gather Victim Network Information | Reconnaissance | Repeated lookups against internal naming patterns |
| DHCP | T1590.005 | IP Addresses | Reconnaissance | Unusual or unauthorized client identifiers requesting leases |
| DHCP | T1557 | Adversary-in-the-Middle | Credential Access, Collection | Rogue DHCP server behavior (unexpected lease offers) |
| Tunnel (Zeek/GRE) | T1572 | Protocol Tunneling | Command and Control | GRE/IP-in-IP tunnels used to wrap and conceal C2 traffic |
| Tunnel (Zeek/GRE) | T1071 | Application Layer Protocol | Command and Control | Tunneled traffic riding over allowed protocols to bypass filtering |

## Brute Force & Anomaly Detection — SPL Queries

[#brute-force-anomaly-detection-spl-queries](#brute-force-anomaly-detection-spl-queries)

These queries supplement the existing per-log SPL searches and are written to directly surface brute-force attempts and outlier behavior, each tagged with its mapped technique.

### SSH — T1110 Brute Force

[#ssh-t1110-brute-force](#ssh-t1110-brute-force)

**1. Failed login threshold per source IP**
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype> action="failed"
| stats count by src_ip, user
| where count > 5
```

**2. Brute force against multiple accounts from one source (password spraying variant)**
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype> action="failed"
| stats dc(user) as unique_users, count by src_ip
| where unique_users > 3 AND count > 10
```

**3. Failed-then-success pattern (possible compromised credential)**
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype>
| transaction user maxspan=10m
| search action="failed" action="success"
| table _time user src_ip action
```

**4. Brute force velocity over time (rate of failed attempts)**
```
index=<your_ssh_index> sourcetype=<your_ssh_sourcetype> action="failed"
| bin _time span=5m
| stats count by _time, src_ip
| where count > 10
```

### SMTP — T1110.003 Password Spraying / T1566 Phishing

[#smtp-t1110003-password-spraying-t1566-phishing](#smtp-t1110003-password-spraying-t1566-phishing)

**5. Low-and-slow auth failures across many mailboxes (spray pattern)**
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype> status="failed"
| stats dc(recipient_address) as targeted_accounts, count by src_ip
| where targeted_accounts > 5
```

**6. Spike in failed SMTP auth in short window**
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype> status="failed"
| timechart span=15m count by src_ip
```

**7. Suspicious sender domain / spoofing indicators**
```
index=<your_smtp_index> sourcetype=<your_smtp_sourcetype>
| rex field=sender_address "@(?<sender_domain>.+)"
| stats count by sender_domain
| sort -count
```

### DNS — T1071.004 C2 over DNS / T1568.002 DGA

[#dns-t1071004-c2-over-dns-t1568002-dga](#dns-t1071004-c2-over-dns-t1568002-dga)

**8. High query volume per host (possible tunneling/beaconing)**
```
index=* sourcetype=dns_sample
| stats count by src_ip
| sort -count
| where count > 1000
```

**9. NXDOMAIN spike (possible DGA activity)**
```
index=* sourcetype=dns_sample rcode="NXDOMAIN"
| timechart span=1h count by src_ip
```

**10. High-entropy / long subdomain queries (tunneling indicator)**
```
index=* sourcetype=dns_sample
| eval qlen=len(fqdn)
| where qlen > 50
| stats count by fqdn, src_ip
```

**11. Rare or first-seen domains in the environment**
```
index=* sourcetype=dns_sample
| stats earliest(_time) as first_seen by fqdn
| where first_seen > relative_time(now(), "-1d")
```

### DHCP — T1590.005 Reconnaissance / T1557 AiTM

[#dhcp-t1590005-reconnaissance-t1557-aitm](#dhcp-t1590005-reconnaissance-t1557-aitm)

**12. Unauthorized/unknown client identifiers requesting leases**
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype>
| search NOT client_identifier IN ("authorized_identifier_1","authorized_identifier_2")
| stats count by client_identifier, leased_ip
```

**13. Multiple DHCP servers responding (rogue server indicator)**
```
index=<your_dhcp_index> sourcetype=<your_dhcp_sourcetype> event_type="offer"
| stats dc(server_ip) as offering_servers by leased_ip
| where offering_servers > 1
```

### Tunnel (Zeek) — T1572 Protocol Tunneling

[#tunnel-zeek-t1572-protocol-tunneling](#tunnel-zeek-t1572-protocol-tunneling)

**14. GRE tunnel volume anomaly by source/destination pair**
```
index=<your_tunnel_index> sourcetype=<your_tunnel_sourcetype> tunnel_protocol=GRE
| stats count by src_ip, dest_ip
| sort -count
```

**15. New tunnel endpoints not previously observed**
```
index=<your_tunnel_index> sourcetype=<your_tunnel_sourcetype> tunnel_protocol=GRE
| stats earliest(_time) as first_seen by src_ip, dest_ip
| where first_seen > relative_time(now(), "-7d")
```

## Cross-Source Correlation

[#cross-source-correlation](#cross-source-correlation)

**16. Correlate SSH brute force with subsequent DNS/tunnel activity from the same host (possible post-compromise C2)**
```
| multisearch
  [ search index=<your_ssh_index> sourcetype=<your_ssh_sourcetype> action="failed"
    | stats count as failed_logins by src_ip ]
  [ search index=* sourcetype=dns_sample
    | stats count as dns_queries by src_ip as src_ip ]
| stats values(failed_logins) as failed_logins, values(dns_queries) as dns_queries by src_ip
| where failed_logins > 10 AND dns_queries > 500
```

## Conclusion

[#conclusion](#conclusion)

Mapping each log source to specific MITRE ATT&CK techniques turns isolated SPL searches into a coherent detection strategy: SSH and SMTP queries target Credential Access (T1110 family), DNS and Tunnel queries target Command and Control (T1071/T1572), and DHCP queries support Reconnaissance and AiTM detection. Together with the original per-log SPL queries, this brings the project to 15+ purpose-built detection searches across brute-force, anomaly, and C2 use cases.
