# Security and privacy notes

- Treat every email as untrusted input.
- This application analyzes text locally and does not fetch URLs, resolve DNS, download files, or execute attachments.
- Do not paste secrets, customer data, or sensitive company information into a hosted instance unless approved by your organization.
- The Streamlit app runs locally by default. If deployed, use access controls, HTTPS, secrets management, and an approved retention policy.
- CSV uploads are read as data only. Use trusted, size-limited files.
- File extensions are clues only; they do not prove the actual file type.
- Always report suspicious messages using your organization's approved process. Do not reply, click links, or open attachments to “test” them.
