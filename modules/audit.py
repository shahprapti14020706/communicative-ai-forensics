"""Structured local custody events; details are developer-owned summaries."""
from datetime import datetime, timezone
import re

SAFE_ACTIONS = set('''LOGIN_SUCCESS LOGIN_FAILURE ACCOUNT_LOCKED LOGOUT SESSION_EXPIRED
USER_CREATED USER_DISABLED USER_ENABLED PASSWORD_RESET CASE_ASSIGNED CASE_OPENED
CASE_ARCHIVED CASE_DELETION_REQUESTED CASE_DELETED ACCESS_DENIED ENCRYPTION_STATUS_CHECKED
ACTIVITY_HISTORY_VIEWED HUMAN_VERIFICATION_OPENED DECISION_RECORDED DECISION_APPROVED DECISION_REJECTED
CONCLUSION_MODIFIED FURTHER_ANALYSIS_REQUESTED DECISION_VERSION_CREATED
DECISION_SUBMISSION_BLOCKED INTEGRITY_CHECK_BEFORE_DECISION REPORT_PAGE_OPENED
REPORT_PREVIEWED REPORT_GENERATED REPORT_DOWNLOADED REPORT_VERSION_CREATED
REPORT_INTEGRITY_CHECKED REPORT_GENERATION_BLOCKED DEMO_CREATED DEMO_CLEANED'''.split())
SAFE_ACTIONS.update(('Case created', 'Authorization confirmed', 'Evidence uploaded', 'Hash generated',
    'Original evidence stored', 'Email parsed', 'Personal details masked', 'Working copy created',
    'Duplicate upload detected', 'Validation failure', 'Registration failed', 'Evidence viewed',
    'Integrity rechecked', 'Analysis requested', 'Reanalysis requested', 'Integrity checked before analysis',
    'Analysis refused due to integrity failure', 'Analysis completed', 'Analysis version',
    'Classification', 'Risk score', 'Rule-processing error', 'Analysis viewed',
    'Ask-the-Evidence page opened', 'Conversation display cleared', 'Question submitted',
    'Intent recognized', 'Unsupported question', 'Insufficient evidence response',
    'High-risk conclusion refused', 'Intent clarification requested', 'Evidence-grounded response generated',
    'Prompt-injection instruction ignored', 'Question-processing error'))


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def record(connection, actor, action, status='success', case_id=None, evidence_id=None, details=''):
    # Preserve generated account identifiers; never persist entered names in new custody events.
    actor = actor if isinstance(actor, str) and (re.fullmatch(r'USR-[A-F0-9]{24}', actor)
        or actor in {'[INVESTIGATOR]', '[LOCAL-USER]'}) else '[LOCAL-USER]'
    connection.execute(
        'INSERT INTO audit_logs(case_id,evidence_id,actor,action,status,details,created_at) VALUES(?,?,?,?,?,?,?)',
        (case_id, evidence_id, actor[:200], action, status, details, utc_now()),
    )
