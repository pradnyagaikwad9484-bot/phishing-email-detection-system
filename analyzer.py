"""Explainable, offline-first phishing email triage heuristics."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from email.utils import parseaddr
from typing import Any
import pandas as pd

URL_RE = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>"\'\])}]+')
EMAIL_RE = re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b')
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
}
RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".msi", ".ps1", ".vbs",
    ".js", ".jse", ".wsf", ".hta", ".jar", ".iso", ".img", ".lnk",
    ".dll", ".reg", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z"
}
URGENT_PATTERNS = [
    (r'\b(urgent|immediately|act now|right now|asap|final warning|last chance)\b', "Urgent or pressure language", 10),
    (r'\b(account (?:will be|is) (?:suspended|closed|locked)|account locked|unusual activity)\b', "Account-threat language", 12),
    (r'\b(within \d+ hours?|expires today|limited time)\b', "Time-limited demand", 8),
]
CREDENTIAL_PATTERNS = [
    (r'\b(password|login credentials|verify your account|confirm your identity|sign in to avoid)\b', "Credential or identity request", 16),
    (r'\b(one[- ]time passcode|security code|mfa code|authentication code)\b', "Authentication-code request", 16),
]
PAYMENT_PATTERNS = [
    (r'\b(gift card|wire transfer|bank details|payment overdue|invoice attached|change of bank account)\b', "Payment or financial pressure", 12),
    (r'\b(crypto(?:currency)?|wallet recovery phrase|seed phrase)\b', "Sensitive financial information request", 18),
]
THREAT_PATTERNS = [
    (r'\b(legal action|lawsuit|penalty|fine will be|account permanently deleted)\b', "Threat or consequence language", 8),
]
GRAMMAR_PATTERNS = [
    (r'!{2,}', "Repeated exclamation marks", 3),
    (r'\?{2,}', "Repeated question marks", 2),
    (r'\b(?:KINDLY|CONGRATULATIONS|WINNER|FREE MONEY)\b', "Promotional/caps wording", 3),
]

def _clean(value: Any) -> str:
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return str(value).strip()

def _extract_urls(text: str) -> list[str]:
    found = URL_RE.findall(text or "")
    cleaned = []
    for url in found:
        url = url.rstrip(".,;:!?")
        if url.lower().startswith("www."):
            url = "http://" + url
        if url and url not in cleaned:
            cleaned.append(url)
    return cleaned

def _domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower().strip(".")
        return host.encode("idna").decode("ascii")
    except (ValueError, UnicodeError):
        return ""

def _registrable_ish_domain(host: str) -> str:
    # Deliberately conservative approximation; public suffix lists are not bundled.
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()

def _sender_details(sender: str) -> tuple[str, str]:
    display, address = parseaddr(sender or "")
    if not address:
        matches = EMAIL_RE.findall(sender or "")
        address = matches[0] if matches else ""
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    return display.strip(), domain

def _risk_level(score: int) -> str:
    if score >= 70:
        return "High risk"
    if score >= 40:
        return "Suspicious"
    return "Low observed risk"

def analyze_email(subject: str = "", sender: str = "", body: str = "",
                  urls: str | list[str] = "", attachments: str | list[str] = "",
                  display_url_text: str = "") -> dict[str, Any]:
    """Analyze supplied email fields without making network requests."""
    subject, sender, body = _clean(subject), _clean(sender), _clean(body)
    full_text = "\n".join(part for part in [subject, body] if part)
    lower_text = full_text.lower()
    findings: list[dict[str, Any]] = []
    score = 0

    def add(category: str, title: str, detail: str, points: int, evidence: str = "") -> None:
        nonlocal score
        score += points
        findings.append({
            "category": category, "indicator": title, "detail": detail,
            "points": points, "evidence": evidence[:220]
        })

    # Sender identity and domain clues
    display, sender_domain = _sender_details(sender)
    if not sender:
        add("Sender", "Sender information missing", "No sender field was supplied; identity cannot be assessed.", 4)
    if sender_domain in {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"}:
        company_words = re.findall(r'\b(IT|Support|Security|Payroll|HR|Admin|Microsoft|Google|Apple|Bank|CEO|Finance)\b', display, re.I)
        if company_words:
            add("Sender", "Free-mail sender claims an organization role",
                f"Display name contains organization/authority wording but sender domain is {sender_domain}. Verify through a known channel.", 16, sender)
    if display and sender_domain and re.search(r'\b(microsoft|google|apple|paypal|amazon|bank|security|support|it helpdesk)\b', display, re.I):
        brand = re.search(r'\b(microsoft|google|apple|paypal|amazon|bank|security|support|it helpdesk)\b', display, re.I).group(1).lower()
        if brand not in sender_domain and not (brand == "security" or brand == "support" or brand == "bank"):
            add("Sender", "Display name and sender domain may not align",
                 f"The display name references '{brand}', but the email domain is '{sender_domain}'. This can be legitimate; verify independently.", 12, sender)

    # URLs
    explicit_urls: list[str] = []
    if isinstance(urls, list):
        explicit_urls.extend([_clean(x) for x in urls if _clean(x)])
    elif _clean(urls):
        explicit_urls.extend([x.strip() for x in re.split(r'[;\n,]+', _clean(urls)) if x.strip()])
    detected_urls = _extract_urls(full_text)
    all_urls = []
    for u in explicit_urls + detected_urls:
        normalized = u if re.match(r'(?i)^https?://', u) else ("http://" + u if u.lower().startswith("www.") else u)
        if normalized and normalized not in all_urls:
            all_urls.append(normalized)

    domains = []
    for url in all_urls:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = _domain_from_url(url)
        if host:
            domains.append(host)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            add("Link", "Unusual URL scheme", f"URL uses '{scheme}' rather than ordinary HTTP(S). Do not open it.", 22, url)
        if host:
            try:
                ipaddress.ip_address(host)
                add("Link", "Link uses an IP address", "A raw IP address in a login or account link deserves extra scrutiny.", 18, url)
            except ValueError:
                pass
            if host in SHORTENERS:
                add("Link", "URL shortener detected", "The final destination is hidden behind a URL-shortening service.", 10, url)
            if host.startswith("xn--") or ".xn--" in host:
                add("Link", "Punycode domain detected", "Internationalized domain encoding can be legitimate but may conceal lookalike characters.", 14, url)
            if len(host) > 45 or host.count("-") >= 3:
                add("Link", "Unusual domain structure", "Long or heavily hyphenated hostnames can be used in deceptive links.", 7, url)
            if parsed.port and parsed.port not in {80, 443}:
                add("Link", "Non-standard URL port", f"URL specifies port {parsed.port}. This is not automatically malicious but is unusual for everyday email links.", 8, url)
            if host.count(".") >= 4:
                add("Link", "Deeply nested subdomain", "Many subdomain levels can make a hostname harder to read.", 5, url)
        if scheme == "http":
            add("Link", "Unencrypted HTTP link", "The link does not specify HTTPS. This alone does not prove phishing.", 5, url)

    # URL text vs destination: only check if user provides visible link text.
    if display_url_text and all_urls:
        visible_domains = [_domain_from_url(x) for x in _extract_urls(display_url_text)]
        if not visible_domains:
            visible_domains = [x.lower().strip() for x in re.findall(r'(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', display_url_text)]
        for actual in domains:
            if visible_domains and not any(v and (v == actual or v.endswith("." + actual) or actual.endswith("." + v)) for v in visible_domains):
                add("Link", "Visible link text may not match destination",
                     "The supplied visible link text does not appear to match the extracted destination domain.", 18, f"Visible: {display_url_text}; destination: {actual}")
                break

    # Sender-domain vs link-domain mismatch, with conservative comparison.
    if sender_domain and domains:
        sender_root = _registrable_ish_domain(sender_domain)
        for host in domains:
            host_root = _registrable_ish_domain(host)
            if host_root != sender_root:
                # Generic providers are common for legitimate services, so this is a modest signal.
                add("Domain", "Sender and link domains differ",
                     f"Sender domain '{sender_domain}' differs from link domain '{host}'. This is common in legitimate newsletters too; verify the destination.", 8, host)
                break

    # Language indicators
    for pattern, label, points in URGENT_PATTERNS + CREDENTIAL_PATTERNS + PAYMENT_PATTERNS + THREAT_PATTERNS:
        match = re.search(pattern, lower_text, re.I)
        if match:
            add("Language", label, "This phrase is often used in social engineering. Consider whether the request is expected.", points, match.group(0))

    # Grammar/formatting are deliberately weak signals.
    if len(full_text) > 30:
        caps_words = re.findall(r'\b[A-Z]{5,}\b', full_text)
        if len(caps_words) >= 3:
            add("Writing", "Excessive all-caps wording", "Several long all-caps words can be a pressure tactic, but style alone is weak evidence.", 3, " ".join(caps_words[:6]))
    for pattern, label, points in GRAMMAR_PATTERNS:
        match = re.search(pattern, full_text)
        if match:
            add("Writing", label, "Formatting may be attention-grabbing, but it is not proof of malicious intent.", points, match.group(0))

    # Attachment warnings
    attachment_items: list[str] = []
    if isinstance(attachments, list):
        attachment_items = [_clean(x) for x in attachments if _clean(x)]
    elif _clean(attachments):
        attachment_items = [x.strip() for x in re.split(r'[;\n,]+', _clean(attachments)) if x.strip()]
    for item in attachment_items:
        ext = "." + item.lower().rsplit(".", 1)[-1] if "." in item else ""
        if ext in RISKY_EXTENSIONS:
            add("Attachment", "Potentially risky attachment type",
                 f"'{item}' has extension '{ext}', which can contain executable code, scripts, macros, or packaged payloads. Do not open unexpectedly.", 18, item)
        elif ext in {".pdf", ".doc", ".xls", ".ppt", ".html", ".htm", ".one"}:
            add("Attachment", "Attachment requires caution",
                 f"'{item}' is a common document/web format that can still contain deceptive content or exploit attempts.", 5, item)

    # Sparse message is not a strong signal, but helps flag low-context lures.
    if len(body) < 25 and (all_urls or attachment_items):
        add("Context", "Very little message context", "A short message with a link or attachment gives little basis for trust.", 5, body)

    score = min(100, max(0, int(score)))
    verdict = _risk_level(score)
    if score >= 70:
        recommendation = "Do not click links or open attachments. Verify with the sender through a known, separate channel and report it to your security team."
    elif score >= 40:
        recommendation = "Treat cautiously. Do not provide credentials or payment details. Verify the sender and destination independently before taking action."
    else:
        recommendation = "No strong indicators were detected by these rules. Still verify unexpected requests; a low score does not establish safety."
    return {
        "score": score,
        "verdict": verdict,
        "confidence": "Heuristic estimate — not a calibrated probability",
        "finding_count": len(findings),
        "findings": findings,
        "urls": all_urls,
        "sender_domain": sender_domain,
        "link_domains": sorted(set(domains)),
        "recommendation": recommendation,
    }

def analyze_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Analyze each row of a dataframe; returns original columns plus result fields."""
    results = []
    for _, row in df.iterrows():
        result = analyze_email(
            subject=row.get("subject", ""),
            sender=row.get("sender", ""),
            body=row.get("body", ""),
            urls=row.get("urls", ""),
            attachments=row.get("attachments", ""),
            display_url_text=row.get("display_url_text", ""),
        )
        results.append({
            "score": result["score"],
            "verdict": result["verdict"],
            "finding_count": result["finding_count"],
            "sender_domain": result["sender_domain"],
            "link_domains": "; ".join(result["link_domains"]),
            "recommendation": result["recommendation"],
            "findings": " | ".join(f'{f["indicator"]}: {f["detail"]}' for f in result["findings"]),
        })
    return pd.concat([df.reset_index(drop=True), pd.DataFrame(results)], axis=1)
