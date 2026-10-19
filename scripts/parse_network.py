import json, subprocess

pcap_file = "evidence/full_attack.pcap"

def run_tshark_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

ips_raw = run_tshark_cmd(f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst | tr '\t' '\n' | sort -u")
ips = [ip for ip in ips_raw.split('\n') if ip and not ip.startswith('127.')]

network_evidence = {
    "artifact_analyzed": pcap_file,
    "identified_hosts": ips,
    "c2_traffic": {
        "channel_port": 4444,
        "protocol": "TCP",
        "description": "Interactive cleartext reverse shell session (MITRE T1095)"
    },
    "exfiltration_traffic": {
        "channel_port": 5555,
        "protocol": "TCP",
        "description": "Cleartext transmission of sensitive file (/etc/passwd) (MITRE T1041)"
    },
    "reconnaissance": {
        "technique": "TCP SYN Half-Open Scan (MITRE T1046)",
        "source": "172.20.0.10",
        "target": "172.20.0.20"
    }
}

with open("evidence/network_forensics.json", "w") as f:
    json.dump(network_evidence, f, indent=2)

print("[+] Successfully generated evidence/network_forensics.json")
