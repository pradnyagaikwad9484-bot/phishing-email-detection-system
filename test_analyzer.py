from phishing_detector import analyze_email, analyze_dataframe
import pandas as pd

def test_suspicious_email_scores_higher_than_plain_message():
    suspicious = analyze_email(
        subject="URGENT account locked",
        sender="Security Team <alerts@gmail.com>",
        body="Verify your account immediately or account will be suspended! Sign in now.",
        urls="http://192.0.2.10/login",
        attachments="invoice.xlsm"
    )
    ordinary = analyze_email(
        subject="Team lunch",
        sender="Alex <alex@company.example>",
        body="Hi team, lunch is scheduled for Friday at noon. Please let me know if you can attend."
    )
    assert suspicious["score"] > ordinary["score"]
    assert suspicious["finding_count"] > 0

def test_detects_shortener_and_http():
    result = analyze_email(body="Please review https://bit.ly/example and http://example.com")
    labels = {f["indicator"] for f in result["findings"]}
    assert "URL shortener detected" in labels
    assert "Unencrypted HTTP link" in labels

def test_score_is_bounded():
    result = analyze_email(
        subject="URGENT!!! FINAL WARNING!!!",
        sender="Support <help@yahoo.com>",
        body=("Verify your account immediately. Password login credentials. " * 20),
        urls="http://192.0.2.12/a; https://bit.ly/x",
        attachments="run.exe; macro.xlsm; archive.zip"
    )
    assert 0 <= result["score"] <= 100

def test_dataframe_keeps_input_columns():
    df = pd.DataFrame([{"subject": "hello", "body": "ordinary message"}])
    out = analyze_dataframe(df)
    assert "subject" in out.columns
    assert "verdict" in out.columns
    assert len(out) == 1
