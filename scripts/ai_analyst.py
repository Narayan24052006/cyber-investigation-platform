import os, sys
from pathlib import Path
from evidence_loader import EvidenceLoader
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

# Initialize console
console = Console()

def generate_report():
    loader = EvidenceLoader()
    evidence_context = loader.get_consolidated_context()

    console.print(Panel("[bold green]AI-Augmented Cyber Attack Investigation Platform[/bold green]\n"
                        "[cyan]Correlating multi-source evidence via local Ollama (llama3.2)...[/cyan]"))

    prompt = f"""You are an elite Principal Incident Responder and Threat Hunter.
Analyze the following multi-source forensic evidence gathered from an enterprise Linux server intrusion.
Produce an exhaustive, highly professional Incident Investigation Report based SOLELY on the provided data.

{evidence_context}

Your report MUST strictly adhere to the following markdown structure and detail:

# Incident Investigation & Threat Intelligence Report: Operation RedBridge

## 1. Executive Summary
Provide a high-impact, non-technical executive overview (3-4 sentences) defining the incident scope, business impact, threat actor methodology, and immediate containment status.

## 2. Attack Lifecycle & Kill Chain Reconstruction
Provide a detailed chronological breakdown of each phase from initial access to objective completion. Explicitly cite indicators (IPs, ports, commands, and hashes) from the case file:
- Phase 1: Reconnaissance (Techniques, source/destination)
- Phase 2: Initial Delivery & Masquerading
- Phase 3: Command & Control (C2) Establishment
- Phase 4: Host Discovery & Credential Dumping
- Phase 5: Persistence Mechanism Installation
- Phase 6: Exfiltration Over Alternative Channel

## 3. MITRE ATT&CK Matrix Alignment
Create a clean markdown table summarizing every identified technique:
| Phase | Technique ID | Technique Name | Evidence & Artifact Reference |

## 4. Comprehensive Indicators of Compromise (IOCs)
List the technical indicators in structured tables or lists:
- Network Indicators: Host IPs, suspicious ports, and traffic direction
- Host Artifacts: Filenames, file paths, and process parameters
- Cryptographic Fingerprints: MD5, SHA-1, SHA-256 hashes

## 5. Detection Gap Analysis & SIEM Visibility Deficiencies
Critically evaluate what the SIEM rules flagged versus what slipped through. Explain why the reconnaissance SYN scan and web enumeration did not trigger high-severity host alerts, and what telemetry would have caught them earlier.

## 6. Containment & Remediation Roadmap
Provide prioritized, actionable recommendations categorized into:
- Immediate Containment (Host isolation, process kill, network block)
- Eradication & Recovery (Cron removal, account audit, password reset)
- Strategic Hardening (Network egress filtering, file integrity monitoring, host-based firewalls)

## 7. Supplemental Threat Hunting & Custom Wazuh Rule Recommendations
Provide at least two additional Wazuh XML rules or Sigma rules that the SOC should deploy to detect future occurrences of this specific behavior.

Format the response in clean, professional GitHub-flavored Markdown. Do not include introductory conversational text."""

    try:
        from langchain_ollama import ChatOllama
        llm = ChatOllama(model="llama3.2", temperature=0.1)
        console.print("[yellow]Invoking Llama 3.2 inference engine...[/yellow]")
        response = llm.invoke(prompt)
        report_text = response.content
    except Exception as e:
        console.print(f"[bold red]LangChain Ollama invocation failed ({e}). Falling back to direct Ollama REST API...[/bold red]")
        import requests
        res = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3.2", "prompt": prompt, "stream": False, "options": {"temperature": 0.1}},
            timeout=180
        )
        if res.status_code == 200:
            report_text = res.json().get("response", "")
        else:
            console.print(f"[bold red]Direct API call failed with status: {res.status_code}[/bold red]")
            sys.exit(1)

    # Save output to evidence folder
    output_path = Path("evidence/incident_report.md")
    with open(output_path, "w") as f:
        f.write(report_text)

    console.print(f"\n[bold green][+] Analysis complete! Incident report saved to: {output_path}[/bold green]\n")
    console.print(Panel(Markdown(report_text), title="Generated Incident Report", expand=False))

if __name__ == "__main__":
    generate_report()
