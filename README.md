# LLM Prompt Injection & Red-Teaming Firewall (OWASP LLM01)

An automated AI security & red-teaming suite in Python & Streamlit that fires **50 adversarial prompt injection payloads** across 5 OWASP vectors, featuring a **Live Attack Sandbox**, **Canary Token Leak Detection**, and **One-Click Pentest Report Export**.

## Attack Vectors Covered (OWASP LLM01)
1. **Direct Instruction Override** (10 payloads)
2. **System Prompt Extraction** (10 payloads — verbatim, translation, Base64, reverse spelling)
3. **Roleplay & Persona Jailbreaks** (10 payloads — DAN, rogue sysadmin, terminal simulation)
4. **Delimiter & Context Smuggling** (10 payloads — XML/Markdown boundary spoofing)
5. **Adversarial Obfuscation** (10 payloads — leetspeak, hyphenation, multilingual bypass)

## Visual Preview

### 1. Red-Team Scan KPIs (Unpatched Baseline — 92.0% ASR)
![Scan KPIs](preview_metrics.jpg)

### 2. Attack Success Rate (ASR) Across 5 OWASP Categories
![Security Benchmark](preview_benchmark.jpg)

### 3. Interactive Red-Team Sandbox (Unpatched vs. Hardened Guardrail)
![Live Sandbox](preview_sandbox.jpg)

## Quickstart
```bash
pip install -r requirements.txt
python -m streamlit run app.py
```
