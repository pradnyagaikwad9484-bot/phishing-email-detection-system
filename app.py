import pandas as pd
import streamlit as st
from phishing_detector import analyze_email, analyze_dataframe

st.set_page_config(page_title="Phishing Email Detector", page_icon="🛡️", layout="wide")
st.title("🛡️ Phishing Email Detection System")
st.caption("Offline-first email triage • Explainable rules • No links opened or files executed")

with st.sidebar:
    st.header("About this tool")
    st.write("This tool looks for suspicious patterns in supplied email text. It is not a guarantee of safety.")
    st.warning("Avoid uploading confidential email, personal data, or secrets to any hosted instance.")
    st.markdown("**Risk bands**")
    st.write("0–39: Low observed risk")
    st.write("40–69: Suspicious")
    st.write("70–100: High risk")

tab_single, tab_batch, tab_about = st.tabs(["Analyze one email", "Batch CSV analysis", "How it works"])

with tab_single:
    left, right = st.columns(2)
    with left:
        subject = st.text_input("Subject", placeholder="e.g. Urgent: Verify your account")
        sender = st.text_input("Sender", placeholder='e.g. "IT Support" <help@example.com>')
        body = st.text_area("Email body (plain text)", height=230, placeholder="Paste the email text here. Do not click its links.")
    with right:
        urls = st.text_area("Additional URLs (optional)", height=100, placeholder="https://example.com/login")
        attachments = st.text_input("Attachment names (optional)", placeholder="invoice.xlsm; report.pdf")
        display_url_text = st.text_input("Visible link text (optional)", placeholder="https://trusted.example")
        st.info("Tip: Paste the visible URL text and destination separately if you know both. Never visit a suspicious link just to find its destination.")
    if st.button("Analyze email", type="primary", use_container_width=True):
        result = analyze_email(subject, sender, body, urls, attachments, display_url_text)
        c1, c2, c3 = st.columns(3)
        c1.metric("Risk score", f'{result["score"]}/100')
        c2.metric("Verdict", result["verdict"])
        c3.metric("Indicators", result["finding_count"])
        st.progress(result["score"] / 100)
        st.subheader("Recommended action")
        st.write(result["recommendation"])
        st.caption(result["confidence"])
        st.subheader("Findings")
        if result["findings"]:
            st.dataframe(pd.DataFrame(result["findings"]), use_container_width=True, hide_index=True)
        else:
            st.success("No configured indicators were detected. This does not prove the email is safe.")
        if result["urls"]:
            st.subheader("URLs detected (not opened)")
            for url in result["urls"]:
                st.code(url)
        if result["link_domains"]:
            st.write("Link domains:", ", ".join(result["link_domains"]))

with tab_batch:
    st.write("Upload a CSV with `body` and optional `subject`, `sender`, `urls`, `attachments`, `display_url_text` columns.")
    uploaded = st.file_uploader("Choose CSV", type=["csv"])
    if uploaded:
        try:
            df = pd.read_csv(uploaded).fillna("")
            if "body" not in df.columns:
                st.error("CSV must include a `body` column.")
            elif len(df) > 5000:
                st.error("For safety and responsiveness, upload no more than 5,000 rows at a time.")
            else:
                analyzed = analyze_dataframe(df)
                st.dataframe(analyzed, use_container_width=True, hide_index=True)
                st.download_button("Download analyzed CSV", analyzed.to_csv(index=False).encode("utf-8"), "phishing_analysis.csv", "text/csv")
                st.caption("CSV results are heuristic triage, not a definitive classification.")
        except Exception as exc:
            st.error(f"Could not read this CSV: {exc}")

with tab_about:
    st.subheader("What is checked?")
    st.markdown("""
    - **Links:** raw IP hosts, URL shorteners, punycode, non-standard ports, HTTP, long or nested hosts.
    - **Language:** urgency, account threats, credential requests, payment pressure, and intimidation.
    - **Sender/domain clues:** display-name mismatch, free-mail accounts claiming an organization role, and sender/link domain differences.
    - **Attachments:** extensions often associated with executable files, scripts, archives, or macro-enabled documents.
    - **Writing style:** repeated punctuation and excessive capitalization, used only as weak signals.

    The rules add weighted points and cap the total at 100. The score is not a probability. Legitimate emails may trigger warnings, and sophisticated phishing may evade detection.
    """)
    st.subheader("Safer handling")
    st.markdown("""
    1. Don't click links or open unexpected attachments.
    2. Verify requests using a known phone number, bookmark, or previously trusted contact method.
    3. Report suspicious messages through your organization's approved channel.
    4. Never send passwords or one-time codes by email.
    """)
