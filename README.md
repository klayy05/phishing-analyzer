# Phishing Email Analyzer

A Python-based phishing email triage tool that automatically analyzes .eml files and generates a detailed HTML triage report. Built as part of a SOC Analyst portfolio roadmap.

## What it does
- Parses email headers and extracts SPF, DKIM, DMARC authentication results
- Detects display name spoofing and Reply-To mismatches
- Extracts and analyzes all URLs for suspicious indicators
- Checks URLs against VirusTotal (70+ antivirus engines)
- Checks originating IP against AbuseIPDB for abuse history and Tor exit nodes
- Scores all findings with a weighted risk engine
- Outputs a professional HTML report with MALICIOUS / SUSPICIOUS / BENIGN verdict

## Demo
![Report](docs/report1.png)
![Indicators](docs/report2.png)
![IP Reputation](docs/report3.png)

## Setup
```bash
git clone https://github.com/klayy05/phishing-analyzer.git
cd phishing-analyzer
python3 -m venv venv
source venv/bin/activate
pip install requests python-dotenv jinja2 dnspython
```

Create a `.env` file with your API keys:> VIRUSTOTAL_API_KEY=your_key_here
> ABUSEIPDB_API_KEY=your_key_here
> ```
>
> ## Usage
> ```bash
> python3 analyzer.py samples/email.eml
> ```
>
> ## Sample output
> Running against a PayPal phishing email:
> - Verdict: MALICIOUS (100/100)
> - Caught: SPF/DKIM/DMARC failures, display name spoofing, suspicious TLD, IP-based URL, Tor exit node (100% abuse score, 95 reports)
>
> ## Tools and stack
> Python · VirusTotal API · AbuseIPDB API · Jinja2 · Regex · Email forensics
>
> ## Author
> Built by Klay Clinton — cybersecurity student, SOC analyst track.
