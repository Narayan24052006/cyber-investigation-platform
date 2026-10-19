# Incident Investigation & Threat Intelligence Report: Operation RedBridge

## 1. Executive Summary

Operation RedBridge involved a sophisticated attack on an enterprise Linux server, resulting in the exfiltration of sensitive data. The threat actor utilized a multi-phase attack, leveraging reconnaissance, masquerading, command and control, and exfiltration techniques. The attack was contained, but not before the adversary gained access to sensitive data. This report provides a detailed analysis of the attack, highlighting the threat actor's methodology, indicators of compromise, and recommendations for future prevention and detection.

## 2. Attack Lifecycle & Kill Chain Reconstruction

### Phase 1: Reconnaissance
- Techniques: TCP SYN Half-Open Scan (MITRE T1046)
- Source: 172.20.0.10
- Destination: 172.20.0.20

### Phase 2: Initial Delivery & Masquerading
- Techniques: Masquerading (MITRE T1036.005)
- Evidence: Execution of sys_update.py (SHA256: 4d084f83182bbd83...)
- Source: sys_update.py

### Phase 3: Command & Control (C2) Establishment
- Techniques: Non-Application Layer Protocol (MITRE T1095)
- Evidence: Egress connection to 4444/TCP. Reverse shell interactive session active.
- Source: 172.20.0.10:47720
- Destination: 172.20.0.20:5555

### Phase 4: Host Discovery & Credential Dumping
- Techniques: OS Credential Dumping (MITRE T1003)
- Evidence: Read access to /etc/passwd and /etc/shadow by non-interactive shell
- Source: 172.20.0.20
- Destination: /etc/passwd and /etc/shadow

### Phase 5: Persistence Mechanism Installation
- Techniques: Scheduled Task/Job: Cron (MITRE T1053.003)
- Evidence: Scheduled cron job injected: */5 * * * * root python3 /evidence/sys_update.py
- Source: 172.20.0.10
- Destination: /etc/crontab

### Phase 6: Exfiltration Over Alternative Channel
- Techniques: Exfiltration Over C2 Channel (MITRE T1041)
- Evidence: Transmission of /etc/passwd payload outbound over port 5555/TCP
- Source: 172.20.0.20
- Destination: 172.20.0.10:5555

## 3. MITRE ATT&CK Matrix Alignment

| Phase | Technique ID | Technique Name | Evidence & Artifact Reference |
| --- | --- | --- | --- |
| 1 | T1046 | Network Service Scanning | PCAP: SYN Port Sweep from 172.20.0.10 to 172.20.0.20 |
| 2 | T1036.005 | Masquerading | Static Malware Analysis: Execution of sys_update.py |
| 3 | T1095 | Non-Application Layer Protocol | SIEM Alert (Rule 100001) + PCAP: Egress connection to 4444/TCP |
| 4 | T1003 | OS Credential Dumping | SIEM Alert (Rule 100003) + PCAP: Read access to /etc/passwd and /etc/shadow |
| 5 | T1053.003 | Scheduled Task/Job: Cron | SIEM Alert (Rule 100002) + YARA: Scheduled cron job injected |
| 6 | T1041 | Exfiltration Over C2 Channel | SIEM Alert (Rule 100004) + Carved Stream 394: Transmission of /etc/passwd payload outbound over port 5555/TCP |

## 4. Comprehensive Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Source | Destination |
| --- | --- | --- |
| 172.20.0.10 | Source | 172.20.0.20 |
| 172.20.0.20 | Source | 172.20.0.10 |
| 4444/TCP | Source | 172.20.0.10:47720 |
| 5555/TCP | Source | 172.20.0.20:5555 |

### Host Artifacts

| Artifact | Source | Destination |
| --- | --- | --- |
| sys_update.py | Source | /evidence/sys_update.py |
| /etc/passwd | Source | 172.20.0.20 |
| /etc/shadow | Source | 172.20.0.20 |
| /etc/crontab | Source | 172.20.0.10 |

### Cryptographic Fingerprints

| Hash | Source | Destination |
| --- | --- | --- |
| SHA256: 4d084f83182bbd83... | Source | sys_update.py |
| MD5: ... | Source | sys_update.py |
| SHA1: ... | Source | sys_update.py |

## 5. Detection Gap Analysis & SIEM Visibility Deficiencies

The reconnaissance SYN scan and web enumeration did not trigger high-severity host alerts because the SIEM rules did not account for these specific techniques. The SIEM rules flagged the C2 establishment and exfiltration phases, but not the reconnaissance and initial delivery phases. To improve detection, the SIEM rules should be updated to include these techniques.

## 6. Containment & Remediation Roadmap

### Immediate Containment

* Host isolation: Isolate the affected host from the network.
* Process kill: Kill the sys_update.py process.
* Network block: Block all outgoing traffic on port 5555/TCP.

### Eradication & Recovery

* Cron removal: Remove the scheduled cron job.
* Account audit: Audit all user accounts for suspicious activity.
* Password reset: Reset all passwords for affected user accounts.

### Strategic Hardening

* Network egress filtering: Implement network egress filtering to prevent outbound traffic on port 5555/TCP.
* File integrity monitoring: Implement file integrity monitoring to detect any changes to sensitive files.
* Host-based firewalls: Implement host-based firewalls to block all incoming and outgoing traffic on port 4444/TCP.

## 7. Supplemental Threat Hunting & Custom Wazuh Rule Recommendations

### Wazuh XML Rule 1

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rule id="wazuh_rule_1">
  <description>SYN Port Sweep Detection</description>
  <pattern>SYN|TCP|<IP>:<PORT></pattern>
  <severity>INFO</severity>
  <action>log</action>
</rule>
```

### Wazuh XML Rule 2

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rule id="wazuh_rule_2">
  <description>Exfiltration Over C2 Channel Detection</description>
  <pattern>5555|TCP|<IP>:<PORT></pattern>
  <severity>WARNING</severity>
  <action>log</action>
</rule>
```

These custom Wazuh rules can be used to detect future occurrences of the same attack.