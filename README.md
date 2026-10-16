# Phishing Email Detection System

A student-friendly, portfolio-ready phishing email triage tool built with Python, Pandas, regex, and Streamlit. It inspects pasted email content or a CSV batch and explains *why* a message may be risky.

> **Important:** This is a defensive triage aid, not a guarantee that an email is safe or malicious. It does not open links, download attachments, or connect to mailboxes. Analyze suspicious messages as plain text and never paste confidential or personal information into an untrusted service.

## Features

- Risk score (0–100), verdict, and confidence label
- Suspicious URL checks: IP-address hosts, URL shorteners, punycode, unusual ports, misleading URL text, risky URL schemes, and lookalike-ish host clues
- Urgency, credential/payment requests, threat language, and social-engineering phrases
- Sender display-name/email mismatch and sender-domain vs link-domain mismatch
- Sender patterns such as free-mail accounts claiming to represent a company
- Grammar/formatting indicators (excessive caps, repeated punctuation, spelling-like red flags) treated as weak signals only
- Attachment risk warnings for executable, script, archive, macro-enabled, and disk-image extensions
- Explainable findings, evidence snippets, safe recommendations, and deterministic scoring
- Streamlit web UI, command-line interface, CSV batch analysis, JSON output, sample data, and tests
- Optional experimental ML baseline; the default rules-based engine works without a trained model

## Quick start

### 1. Create and activate a virtual environment

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS/Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the web app
```bash
streamlit run app.py
```

### 4. Analyze an email from the terminal
```bash
python cli.py --subject "Urgent: Verify account" --sender "Security Team <alerts@example.invalid>" --body "Your account is locked. Verify now at http://192.0.2.10/login"
```

### 5. Analyze a CSV file
CSV columns supported: `subject`, `sender`, `body`, `urls`, `attachments`, and optionally `label`. Only `body` is required. `urls` and `attachments` may be semicolon-separated strings.
```bash
python cli.py --csv data/sample_emails.csv --output reports/analysis.csv
```

### 6. Run tests
```bash
pytest -q
```

## Scoring overview

The detector adds weighted risk points for observable indicators and caps the score at 100. The final verdict is one of:
- **High risk**: score 70–100
- **Suspicious**: score 40–69
- **Low observed risk**: score 0–39

“Low observed risk” does **not** mean an email is safe. Attackers can use legitimate services, compromised accounts, and polished writing. Scores are heuristic indicators, not calibrated probabilities.

## Project structure

```text
phishing_email_detection_system/
├── app.py
├── cli.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── phishing_detector/
│   ├── __init__.py
│   ├── analyzer.py
│   └── ml_baseline.py
├── data/
│   └── sample_emails.csv
├── reports/
│   └── .gitkeep
└── tests/
    └── test_analyzer.py
```

## Suggested final-year project extensions

1. Add a safe `.eml` parser using Python's `email` package (never automatically fetch remote content).
2. Add a configurable allowlist/denylist and organization-specific sender policies.
3. Integrate DNS/WHOIS/reputation APIs only after privacy review and rate limiting.
4. Add model evaluation on a properly licensed, representative dataset; report precision, recall, F1, false-positive rate, and a confusion matrix.
5. Add HTML email sanitization and a sandboxed attachment-analysis workflow. Never execute an attachment.
6. Add authentication, audit logs, retention controls, and deployment hardening before handling real company email.

## Limitations

- No external threat-intelligence or live reputation checks are performed.
- URL parsing is static; links are never visited.
- Domain similarity detection is intentionally conservative and cannot reliably detect every homograph or brand impersonation.
- Grammar is a weak signal and is not used as proof of phishing.
- Sample dataset is synthetic and must not be used to claim real-world model performance.
