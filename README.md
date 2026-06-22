# 🛡 Phishing Awareness Analysis

**Cyber Security — Project 3 | DecodeLabs Industrial Training Kit | Batch 2026**
**Author:** Lohitaksh Raj

## 📌 Project Goal
Analyze sample emails/messages to identify phishing attempts using Python.

## ✨ Features
- Detects suspicious keywords (urgency, threats, rewards)
- Extracts and analyzes every URL in the message
- Flags URL shorteners, suspicious TLDs, IP-based URLs, and lookalike domains
- Detects sender impersonation (e.g. "paypal" from a gmail address)
- Identifies emotional manipulation (excessive caps, exclamation marks, urgency)
- Generates a risk score and a clean text report
- Includes a Red Flag Checklist for quick reference

## 🧰 Tech Stack
- Python 3 (standard library only — `re`, `urllib`)
- Tested on macOS (Apple Silicon M1)

## 🚀 How to Run
```bash
git clone https://github.com/<lohitakshraj>/Phishing-Awareness-Analysis.git
cd Phishing-Awareness-Analysis
python3 phishing_analyzer.py
