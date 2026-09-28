"""Academic presentation and limitations; authenticated like every other page."""
import streamlit as st
from modules.ui import setup_page, page_errors

with page_errors():
    setup_page('About the Prototype')
    st.title('Communicative AI in Digital Forensics: A Human-in-the-Loop Framework for Cybercrime Investigation')
    st.caption('Academic prototype | Authors: Prapti Shah and Aayursha Raut')
    sections = [
        ('Research objective', 'Explore how evidence-linked explanations and controlled questions can help investigators review phishing-email indicators while retaining human responsibility for conclusions.'),
        ('Problem addressed', 'Automated classifications can be difficult to explain, can expose personal information and may be mistaken for verified forensic conclusions.'),
        ('Proposed solution', 'A local workflow combines SHA-256 evidence checks, masked working copies, transparent phishing rules, deterministic evidence Q&A and separately recorded human decisions.'),
        ('Prototype workflow', 'Login → create or select a case → register evidence → verify integrity → inspect masked evidence and run analysis → ask evidence questions → record a human decision → generate and verify a report → review the audit trail.'),
        ('Main security controls', 'Salted PBKDF2 password hashes, account lockout, expiring sessions, database-backed roles and case assignments, contained storage paths, safe text rendering, original-byte preservation and versioned decisions/reports. Encryption at rest is not configured.'),
        ('Human-in-the-loop principle', 'An automated finding is an investigative lead. The investigator reviews evidence and limitations, then approves, rejects, modifies the conclusion or requests further analysis. Automated results and previous decisions remain preserved.'),
        ('Current limitations', 'This is a deterministic rule-based prototype, not a trained language model. Masking is heuristic; scores are not probabilities. No URLs, attachments, sender identities or external reputation services are queried. SQLite and local files are not encrypted, cryptographically signed or protected against a malicious operating-system administrator.'),
        ('Future scope', 'Evaluate rules and usability on approved datasets, improve privacy evaluation, review authenticated encryption and digital signatures, and study additional evidence formats under explicit authorization.'),
    ]
    for heading, content in sections:
        st.subheader(heading)
        st.write(content)
    st.warning('This application is an academic proof of concept. Its automated findings are investigative leads and must not be treated as legal conclusions.')
