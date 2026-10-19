import json

def build_timeline():
    # Load previously generated evidence artifacts
    with open("evidence/network_forensics.json") as f:
        net_data = json.load(f)
    with open("evidence/malware_report.json") as f:
        mal_data = json.load(f)
    with open("evidence/wazuh_alerts.json") as f:
        siem_data = json.load(f)

    timeline = [
        {
            "stage": "Phase 1: Reconnaissance",
            "timestamp": "T+00:00",
            "source": "Network Capture (PCAP)",
            "indicator": "SYN Port Sweep from 172.20.0.10 to 172.20.0.20",
            "mitre": "T1046 - Network Service Scanning",
            "severity": "Medium"
        },
        {
            "stage": "Phase 2: Initial Foothold & Masquerading",
            "timestamp": "T+00:45",
            "source": "Static Malware Analysis",
            "indicator": f"Execution of {mal_data['sample_metadata']['filename']} (SHA256: {mal_data['sample_metadata']['hashes']['sha256'][:16]}...)",
            "mitre": "T1036.005 - Masquerading",
            "severity": "High"
        },
        {
            "stage": "Phase 3: C2 Establishment",
            "timestamp": "T+01:06",
            "source": "SIEM Alert (Rule 100001) + PCAP",
            "indicator": f"Egress connection to {net_data['c2_traffic']['channel_port']}/TCP. Reverse shell interactive session active.",
            "mitre": "T1095 - Non-Application Layer Protocol",
            "severity": "Critical"
        },
        {
            "stage": "Phase 4: Credential Access",
            "timestamp": "T+02:15",
            "source": "SIEM Alert (Rule 100003)",
            "indicator": "Read access to /etc/passwd and /etc/shadow by non-interactive shell",
            "mitre": "T1003 - OS Credential Dumping",
            "severity": "High"
        },
        {
            "stage": "Phase 5: Persistence Installation",
            "timestamp": "T+03:01",
            "source": "SIEM Alert (Rule 100002) + YARA",
            "indicator": "Scheduled cron job injected: */5 * * * * root python3 /evidence/sys_update.py",
            "mitre": "T1053.003 - Scheduled Task/Job: Cron",
            "severity": "High"
        },
        {
            "stage": "Phase 6: Data Exfiltration",
            "timestamp": "T+04:19",
            "source": "SIEM Alert (Rule 100004) + Carved Stream 394",
            "indicator": f"Transmission of /etc/passwd payload outbound over port {net_data['exfiltration_traffic']['channel_port']}/TCP",
            "mitre": "T1041 - Exfiltration Over C2 Channel",
            "severity": "Critical"
        }
    ]

    # Save structured JSON
    with open("evidence/attack_timeline.json", "w") as f:
        json.dump(timeline, f, indent=2)

    # Save human-readable text report
    with open("evidence/timeline.txt", "w") as f:
        f.write("=" * 80 + "\n")
        f.write("UNIFIED ATTACK TIMELINE & CORRELATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        for item in timeline:
            f.write(f"[{item['timestamp']}] {item['stage']}\n")
            f.write(f"  * Source:   {item['source']}\n")
            f.write(f"  * Evidence: {item['indicator']}\n")
            f.write(f"  * MITRE:    {item['mitre']}\n")
            f.write(f"  * Severity: {item['severity']}\n\n")

    print("[+] Unified timeline generated:")
    print("    - evidence/attack_timeline.json")
    print("    - evidence/timeline.txt")

if __name__ == "__main__":
    build_timeline()
