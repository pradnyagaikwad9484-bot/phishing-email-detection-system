# Project Report: Phishing Email Detection System

## Abstract
This project implements an offline-first phishing email triage application. It examines email subject, sender metadata, body text, URLs, and attachment names, then returns a bounded risk score, a verdict band, explainable indicators, and safe next-step recommendations.

## Problem statement
Email phishing uses urgency, impersonation, deceptive links, and risky attachments to persuade recipients to disclose information or execute unsafe content. A lightweight triage tool can help users recognize suspicious patterns before taking action.

## Objectives
1. Detect common phishing indicators with deterministic rules.
2. Provide explanations instead of a black-box label.
3. Support single-email and CSV batch analysis.
4. Keep analysis local and avoid fetching URLs or executing files.
5. Include automated tests and a clear path for responsible evaluation.

## Architecture
- **Input layer:** Streamlit form, CLI arguments, or CSV upload.
- **Analysis layer:** regex language checks, URL parsing, sender-domain heuristics, attachment-extension warnings.
- **Scoring layer:** weighted risk points capped at 100.
- **Output layer:** risk band, findings, recommendation, downloadable batch results.
- **Optional ML experiment:** TF-IDF + logistic regression baseline in `phishing_detector/ml_baseline.py`.

## Methodology
Each configured indicator contributes a weight. The sum is capped at 100 and mapped to Low observed risk (0–39), Suspicious (40–69), or High risk (70–100). Writing-style indicators receive low weights because grammar is not reliable evidence on its own. Domain mismatch is also a modest signal because many legitimate services use separate link domains.

## Testing
Run `pytest -q`. Tests verify relative risk behavior, URL indicators, score bounds, and dataframe batch output. The bundled dataset is synthetic and intended only for demonstrations.

## Evaluation plan
For a serious evaluation, use a permitted, representative labeled dataset and a held-out test set. Report precision, recall, F1, false-positive rate, false-negative rate, and a confusion matrix. Split by campaign or time when possible to reduce leakage. Do not report synthetic sample performance as real-world accuracy.

## Limitations
Rules can miss new or carefully crafted attacks and may flag legitimate mail. The tool does not check DNS, domain age, sender authentication (SPF/DKIM/DMARC), live reputation, or attachment contents. It does not establish whether a message is genuinely safe.

## Future work
Add safe `.eml` parsing, organization-specific policies, optional approved threat-intelligence integrations, calibrated ML models, a feedback loop, and hardened authenticated deployment.
