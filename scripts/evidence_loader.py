import json, os
from pathlib import Path

class EvidenceLoader:
    def __init__(self, evidence_dir="evidence"):
        self.evidence_dir = Path(evidence_dir)

    def _read_file_safe(self, filename, default="[Artifact not available]"):
        path = self.evidence_dir / filename
        if path.exists():
            with open(path, "r", errors="ignore") as f:
                return f.read().strip()
        return default

    def load_network_forensics(self):
        content = self._read_file_safe("network_forensics.json")
        try:
            return json.dumps(json.loads(content), indent=2)
        except Exception:
            return content

    def load_malware_report(self):
        content = self._read_file_safe("malware_report.json")
        try:
            return json.dumps(json.loads(content), indent=2)
        except Exception:
            return content

    def load_siem_alerts(self):
        content = self._read_file_safe("wazuh_alerts.json")
        try:
            return json.dumps(json.loads(content), indent=2)
        except Exception:
            return content

    def load_timeline(self):
        return self._read_file_safe("timeline.txt")

    def load_carved_data(self):
        content = self._read_file_safe("carved_exfil.txt")
        # Return first 10 lines to prevent prompt bloat while giving ground truth
        lines = content.splitlines()[:12]
        return "\n".join(lines) if lines else "[No carved payload found]"

    def get_consolidated_context(self):
        return f"""
=== MULTI-SOURCE INVESTIGATION EVIDENCE CASE FILE ===

[1] NETWORK FORENSICS (Zeek / tshark PCAP Analysis):
{self.load_network_forensics()}

[2] CARVED NETWORK EXFILTRATION STREAM (TCP Port 5555):
{self.load_carved_data()}

[3] STATIC MALWARE ANALYSIS & YARA DETECTIONS:
{self.load_malware_report()}

[4] WAZUH SIEM ALERTS & DETECTION GAPS:
{self.load_siem_alerts()}

[5] UNIFIED INCIDENT TIMELINE:
{self.load_timeline()}
"""

if __name__ == "__main__":
    loader = EvidenceLoader()
    ctx = loader.get_consolidated_context()
    print(f"[+] Evidence loader verified. Total context size: {len(ctx)} characters")
