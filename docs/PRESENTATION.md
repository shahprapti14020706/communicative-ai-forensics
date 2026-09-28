# Presentation procedure

Use synthetic data only. Complete the local setup and tests in README.md before presenting.

1. Open **About the Prototype** after login. Introduce the research question, authors and academic disclaimer.
2. On **Dashboard**, explain the generated user identifier, role, accessible cases and disabled encryption status.
3. Use **New Investigation** with `samples/obvious_phishing.eml`, or select a case created by `modules.demo_setup`. Intake creates a case and registers one evidence file together.
4. On **Evidence Analysis**, show the SHA-256 and choose **Verify Integrity Again**. Explain that matching bytes do not establish authenticity or safety.
5. Show masked headers/body and non-clickable URL text. Choose **Run Phishing Analysis**. Explain rule contributions and that the score is not a probability.
6. Expand a finding to connect its explanation with a masked evidence excerpt and manual check.
7. On **Ask the Evidence**, ask “Why is this email suspicious?” and “What evidence supports the result?”. Then ask “Is the sender guilty?” to demonstrate safe refusal. No network lookup occurs.
8. On **Human Verification**, review integrity, limitations and findings. Choose a decision yourself, enter fictional investigator details and meaningful review notes, and confirm the review. Never claim that the tool verifies criminal responsibility.
9. On **Forensic Report**, preview the separate automated and human results, generate HTML/JSON, and verify the report hash. Reports remain versioned snapshots.
10. On **Dashboard**, show completed stages. On **Audit Log**, explain custody events. Administrator management can demonstrate assignments using separately prepared synthetic accounts; no account/password is created by the demo helper.
11. Logout and demonstrate that direct page navigation returns to login. Stop Streamlit with Ctrl+C.

Allow roughly 10–15 minutes. For a shorter presentation, prepare analysis beforehand but record the human decision live.

Keep the original evidence unchanged. Demonstrate failed-integrity behavior through the automated temporary-storage tests, never by tampering with stored demonstration or production evidence.

The cleanup helper removes only unchanged intake created by `demo_setup`. Once opened or investigated, the case may contain additional audit records or investigator work and automatic cleanup refuses it. Retain completed presentation cases; deleting them requires the separate reviewed administrator archive/delete workflow. Do not delete existing project cases as part of preparation.
