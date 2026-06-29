# 🛡️ AEGIS — AI-Augmented Penetration Testing Assistant

<p align="center">
  <strong>An Autonomous AI-Driven Penetration Testing Framework</strong>
</p>

<p align="center">
  <em>AI decides. AI executes. AI chains. AI reports.</em>
</p>

---

## 🧠 What is AEGIS?

AEGIS is a **fully autonomous penetration testing agent** that uses multiple AI models to:
- **Scan** targets intelligently
- **Reason** about vulnerabilities
- **Plan** and execute attack chains
- **Escalate** privileges through chained exploits
- **Generate** professional PDF reports

Unlike existing tools (Metasploit, Nessus, BurpSuite), AEGIS has a **complete AI decision loop** — it sees results, decides the next attack, chains them together, and explains everything.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              AEGIS — AI AUTONOMOUS PENTEST AGENT                │
│                                                                 │
│   Target Input ──► AI Reasoning Engine ──► Attack Planner      │
│                           │                      │             │
│                    Knowledge Base          Tool Executor        │
│                    (CVEs, exploits,        (Terminal Access)    │
│                     techniques)                  │             │
│                           │                      │             │
│                    Chain Builder ◄───────── Results Parser      │
│                           │                                     │
│                    Report Generator                             │
│                    (Full PDF Report)                            │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- [Ollama](https://ollama.ai) installed with models
- Kali Linux recommended (has all security tools)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/aegis.git
cd aegis

# Install dependencies
pip install -r requirements.txt

# Pull AI models
ollama pull llama3
ollama pull mistral
ollama pull deepseek-coder

# Run AEGIS
python -m aegis --target <TARGET_IP> --scope full
```

### Web UI

```bash
# Start the API server
python -m aegis.api

# Start the React frontend
cd ui && npm install && npm run dev
```

## 🤖 Multi-Model AI Strategy

| Task | Model | Why |
|------|-------|-----|
| Reasoning & Planning | Llama 3 / Mistral | Best general reasoning |
| Code Analysis | DeepSeek Coder | Code-specific intelligence |
| Report Writing | Mistral | Strong structured output |
| Vulnerability Analysis | Llama 3 | Deep technical knowledge |

## 📋 Attack Modules

- **Web Scanner**: SQLi, XSS, SSRF, XXE, LFI/RFI, auth bypass, JWT attacks
- **Network Scanner**: Port scanning, service exploitation, SSL/TLS, SMB, DNS
- **Password Cracker**: Hash cracking, bruteforce, credential stuffing, spraying
- **Post-Exploitation**: Privilege escalation, lateral movement, persistence, pivoting

## 📊 Report Generation

AEGIS generates professional penetration test reports including:
- Executive Summary (management-friendly)
- Attack Surface Map
- Vulnerability Findings with CVSS scores
- Attack Chain Narrative
- Complete Terminal Log
- Remediation Roadmap
- Compliance Mapping (OWASP, NIST, ISO 27001)

## ⚠️ Legal Disclaimer

**AEGIS is designed for authorized penetration testing only.**

You must have explicit written permission before testing any system. Unauthorized access to computer systems is illegal. The developers are not responsible for any misuse of this tool.

## 📝 License

MIT License — See [LICENSE](LICENSE) for details.
