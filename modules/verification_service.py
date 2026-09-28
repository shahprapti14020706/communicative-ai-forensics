"""Local, scoped, integrity-gated and append-only human decisions."""
import json
import re
import sqlite3
import uuid
from modules.auth import guard, current_user

from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database
from modules.evidence_handler import DATA_ROOT, ValidationError, verify_integrity
from modules.qa_service import scoped_row, masked_analysis, ScopeError
from modules.qa_engine import redact

DECISIONS = {'Approve Analysis': ('approve', 'DECISION_APPROVED'),
             'Reject Analysis': ('reject', 'DECISION_REJECTED'),
             'Modify Conclusion': ('modify', 'CONCLUSION_MODIFIED'),
             'Request Further Analysis': ('reanalyse', 'FURTHER_ANALYSIS_REQUESTED')}
CLASSIFICATIONS = ['Suspicious', 'Uncertain', 'No Significant Indicators Detected']
ACTIONS = ['Verify sender identity', 'Inspect email headers', 'Examine suspicious links',
           'Examine attachments', 'Review authentication results', 'Compare with other evidence',
           'Perform external verification manually', 'Other']
WARNING = ('Automated findings are investigative leads only. A qualified investigator must verify '
           'the evidence before drawing a conclusion.')
CONFIRMATION = ('I confirm that I reviewed the displayed evidence, automated findings, integrity '
                'status and stated limitations.')
BLOCKED = 'Human verification is blocked because evidence integrity verification failed.'
# Free prose can contain names, addresses and secrets that regex PII masking cannot
# recognize. Retain only common review vocabulary after the existing privacy mask.
# This intentionally over-redacts; no name recognition model or external service.
SAFE_WORDS = set(('i a an the this that these those and or but because after before with without '
    'of for to from in on at is are was were be been it its not no yes my we have has had '
    'review reviewed verify verified verification evidence automated human analysis findings '
    'classification conclusion suspicious uncertain significant indicators detected agree '
    'disagree approve approved reject rejected modify modified request requested further '
    'additional examination required needs needed more insufficient sufficient context '
    'sender recipient identity email headers authentication results links link attachments '
    'attachment integrity hash passed failed failure success original unchanged preserved '
    'notes reason changed change version previous new final score risk rule based '
    'check checked compare compared independently manual manually external limitations '
    'confirm confirmed confirmation malicious legitimate safe safety phishing urgency urgent '
    'password otp payment credentials account suspended final warning verify now action '
    'transfer money bank details invoice gift cards refund claim login your within hours '
    'request requests source body subject domain mismatch missing unavailable reported '
    'test synthetic example fictional investigator explanation supports supported does do '
    'cannot establish establish requires investigation reviewable corrected correction '
    'false positive negative high medium low pending completed rejected approved').split())


def private_text(value):
    """Existing identifier masker plus conservative free-text suppression."""
    masked = redact(value)
    return re.sub(r'\[(?:(?:EMAIL|PHONE|IP|CARD|AADHAAR|PAN|PERSONAL)-\d+|PRIVATE)\]|[^\W_]+|_',
                  lambda m: m[0] if m[0].startswith('[') or m[0].lower() in SAFE_WORDS
                  else '[PRIVATE]', masked, flags=re.UNICODE)


def _event(connection, action, status='success', scope=None, **metadata):
    record(connection, '[INVESTIGATOR]', action, status,
           case_id=scope[0] if scope else None, evidence_id=scope[1] if scope else None,
           details=json.dumps(metadata, sort_keys=True))


@guard('read')
def selections(case_id=None, db_path=DEFAULT_DB_PATH, include_archived=False):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        user = current_user(db_path)
        cases = [r[0] for r in connection.execute("SELECT case_id FROM cases WHERE (? OR status IN ('open','under_review')) AND "
            "(? OR EXISTS (SELECT 1 FROM case_assignments a WHERE a.case_id=cases.case_id AND a.user_id=? AND a.active=1)) ORDER BY created_at DESC",
            (bool(include_archived), user['role']=='Administrator', user['user_id']))]
        evidence = [r[0] for r in connection.execute('SELECT evidence_id FROM evidence WHERE case_id=? ORDER BY created_at DESC', (case_id,))] if case_id in cases else []
        return cases, evidence
    finally:
        connection.close()


def _scope(connection, case_id, evidence_id, analysis_id):
    row = scoped_row(connection, case_id, evidence_id)
    active = connection.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone()
    analysis = connection.execute("SELECT * FROM analysis_results WHERE case_id=? AND evidence_id=? AND analysis_id=? AND status='completed'",
                                  (case_id, evidence_id, analysis_id)).fetchone()
    if not active or not analysis:
        raise ScopeError('Select an active case, its evidence and a completed analysis version.')
    return row, masked_analysis(analysis, case_id, evidence_id)


def _history(connection, case_id, evidence_id, analysis_id):
    # Join supports legacy decisions whose new scope/version columns are NULL.
    return [dict(r) for r in connection.execute(
        'SELECT d.* FROM investigator_decisions d JOIN analysis_results a USING(analysis_id) '
        'WHERE a.case_id=? AND a.evidence_id=? AND a.analysis_id=? '
        'ORDER BY COALESCE(d.decision_version,0) DESC,d.created_at DESC,d.decision_id DESC',
        (case_id, evidence_id, analysis_id))]


@guard('read')
def decision_history(case_id, evidence_id, analysis_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        _scope(connection, case_id, evidence_id, analysis_id)
        return _history(connection, case_id, evidence_id, analysis_id)
    finally:
        connection.close()


@guard('read')
def open_review(case_id, evidence_id, analysis_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        row, analysis = _scope(connection, case_id, evidence_id, analysis_id)
        valid = verify_integrity(evidence_id, db_path, data_root, audit=False)
        with connection:
            _event(connection, 'HUMAN_VERIFICATION_OPENED', scope=(case_id, evidence_id), analysis_id=analysis_id)
            _event(connection, 'INTEGRITY_CHECK_BEFORE_DECISION', 'success' if valid else 'failure',
                   (case_id, evidence_id), analysis_id=analysis_id, integrity_status='verified' if valid else 'failed')
            if not valid:
                _event(connection, 'DECISION_SUBMISSION_BLOCKED', 'failure', (case_id, evidence_id), analysis_id=analysis_id, reason='integrity_failed')
        return {'analysis': analysis, 'integrity_valid': valid, 'sha256': row['sha256'],
                'history': _history(connection, case_id, evidence_id, analysis_id)}
    finally:
        connection.close()


def _required(value, label, minimum=1, maximum=5000):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= maximum:
        raise ValidationError(f'{label} must contain {minimum}–{maximum} characters.')
    return value.strip()


@guard('decide')
def record_decision(case_id, evidence_id, analysis_id, investigator_name, decision_type,
                    notes, confirmed, final_classification=None, requested_actions=None,
                    other_description='', change_reason='', version_reason='',
                    expected_previous_id=None, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    connection = connect_database(db_path)
    scope = None
    try:
        connection.execute('BEGIN IMMEDIATE')
        row, analysis = _scope(connection, case_id, evidence_id, analysis_id)
        scope = (case_id, evidence_id)
        _required(investigator_name, 'Investigator name', maximum=200)
        _required(notes, 'Verification notes', minimum=20)
        if confirmed is not True:
            raise ValidationError('The review confirmation is required.')
        if decision_type not in DECISIONS:
            raise ValidationError('Select a valid decision type.')
        previous = _history(connection, case_id, evidence_id, analysis_id)
        prior_id = previous[0]['decision_id'] if previous else None
        if expected_previous_id != prior_id:
            raise ValidationError('Decision history changed. Review the latest decision before submitting.')
        if previous:
            _required(version_reason, 'Reason for creating a new version')
        final = None
        actions = []
        if decision_type == 'Approve Analysis':
            final = analysis['classification']
        elif decision_type == 'Modify Conclusion':
            if final_classification not in CLASSIFICATIONS or final_classification == analysis['classification']:
                raise ValidationError('Select a different final classification.')
            _required(change_reason, 'Reason for changing the classification')
            final = final_classification
        elif decision_type == 'Request Further Analysis':
            if not isinstance(requested_actions, list) or not requested_actions or any(a not in ACTIONS for a in requested_actions):
                raise ValidationError('Select at least one valid further-analysis request.')
            actions = list(dict.fromkeys(requested_actions))
            if 'Other' in actions:
                _required(other_description, 'Other request description')
        valid = verify_integrity(evidence_id, db_path, data_root, audit=False)
        _event(connection, 'INTEGRITY_CHECK_BEFORE_DECISION', 'success' if valid else 'failure', scope,
               analysis_id=analysis_id, integrity_status='verified' if valid else 'failed')
        if not valid:
            # Commit only safe audit events; no decision has been inserted.
            connection.commit()
            raise ValidationError(BLOCKED)
        version = max([r['decision_version'] or 0 for r in previous] + [len(previous)]) + 1
        now = utc_now()
        decision_id = 'DEC-' + uuid.uuid4().hex[:12].upper()
        masked_notes = private_text(notes.strip())
        action_json = json.dumps({'actions': actions, 'other_description': private_text(other_description.strip()) if 'Other' in actions else ''})
        result = dict(decision_id=decision_id, analysis_id=analysis_id, case_id=case_id,
                      evidence_id=evidence_id, investigator_name='[INVESTIGATOR-' + uuid.uuid4().hex[:12].upper() + ']',
                      decision=DECISIONS[decision_type][0], rationale=masked_notes,
                      revised_finding=final if decision_type == 'Modify Conclusion' else None,
                      created_at=now, decision_version=version, decision_type=decision_type,
                      automated_classification=analysis['classification'], automated_risk_score=analysis['risk_score'],
                      final_classification=final, masked_verification_notes=masked_notes,
                      requested_actions=action_json, integrity_status='verified', evidence_sha256=row['sha256'],
                      created_at_utc=now, supersedes_decision_id=prior_id,
                      masked_version_reason=private_text(version_reason.strip()) if previous else '',
                      masked_change_reason=private_text(change_reason.strip()) if decision_type == 'Modify Conclusion' else '')
        # Column names are developer-owned; every value is parameterized.
        connection.execute('INSERT INTO investigator_decisions (' + ','.join(result) + ') VALUES (' + ','.join('?' for _ in result) + ')', tuple(result.values()))
        for action in ['DECISION_RECORDED', DECISIONS[decision_type][1]] + (['DECISION_VERSION_CREATED'] if previous else []):
            _event(connection, action, scope=scope, analysis_id=analysis_id, decision_id=decision_id,
                   decision_version=version, supersedes_decision_id=prior_id, integrity_status='verified')
        connection.commit()
        return result
    except (ValueError, TypeError):
        connection.rollback()
        with connection:
            _event(connection, 'DECISION_SUBMISSION_BLOCKED', 'failure', scope, reason='validation_or_scope_failed')
        raise
    finally:
        connection.close()
