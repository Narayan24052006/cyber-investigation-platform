import re, json, xml.etree.ElementTree as ET
from datetime import datetime

RULES_PATH = "rules/local_rules.xml"
LOGS_PATH = "evidence/victim_syslog.log"
ALERTS_OUTPUT = "evidence/wazuh_alerts.json"

def load_rules(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rules = []
    for rule_elem in root.findall("rule"):
        rule_id = rule_elem.get("id")
        level = int(rule_elem.get("level"))
        match_elem = rule_elem.find("match")
        regex_elem = rule_elem.find("regex")
        desc_elem = rule_elem.find("description")
        mitre_elem = rule_elem.find("mitre")
        
        mitre_ids = [m.text for m in mitre_elem.findall("id")] if mitre_elem is not None else []
        
        rules.append({
            "id": rule_id,
            "level": level,
            "match": match_elem.text if match_elem is not None else None,
            "regex": regex_elem.text if regex_elem is not None else None,
            "description": desc_elem.text if desc_elem is not None else "",
            "mitre": mitre_ids
        })
    return rules

def evaluate_logs(rules, log_path):
    alerts = []
    unmatched_events = []
    
    with open(log_path, "r") as f:
        log_lines = [line.strip() for line in f if line.strip()]
        
    for line in log_lines:
        matched = False
        for rule in rules:
            match_ok = True
            if rule["match"]:
                patterns = rule["match"].split("|")
                if not any(p in line for p in patterns):
                    match_ok = False
            if match_ok and rule["regex"]:
                if not re.search(rule["regex"], line):
                    match_ok = False
            
            if match_ok:
                alerts.append({
                    "timestamp": line[:15],
                    "agent": {"id": "001", "name": "ubuntu-victim", "ip": "172.20.0.20"},
                    "rule": {
                        "id": rule["id"],
                        "level": rule["level"],
                        "description": rule["description"],
                        "mitre": rule["mitre"]
                    },
                    "full_log": line
                })
                matched = True
                break
        
        if not matched:
            unmatched_events.append(line)
            
    return alerts, unmatched_events

def main():
    rules = load_rules(RULES_PATH)
    alerts, missed = evaluate_logs(rules, LOGS_PATH)
    
    # Calculate detection gap metrics
    summary = {
        "total_logs_processed": len(alerts) + len(missed),
        "total_alerts_generated": len(alerts),
        "alerts": alerts,
        "detection_gaps": {
            "unmatched_count": len(missed),
            "unmatched_samples": missed,
            "analysis": "Reconnaissance SYN sweeps and standard HTTP requests bypassed custom alert rules."
        }
    }
    
    with open(ALERTS_OUTPUT, "w") as f:
        json.dump(summary, f, indent=2)
        
    print(f"[+] SIEM Ingestion complete.")
    print(f"    - Processed Logs: {summary['total_logs_processed']}")
    print(f"    - Alerts Generated: {summary['total_alerts_generated']}")
    print(f"    - Unmatched Events (Gaps): {summary['detection_gaps']['unmatched_count']}")
    print(f"    - Output: {ALERTS_OUTPUT}")

if __name__ == "__main__":
    main()
