"""Authorized, metadata-only presentation of the latest recorded workflow."""
import sqlite3
import json
from modules.auth import guard, current_user
from modules.database import DEFAULT_DB_PATH, connect_database
from modules.case_service import _status

STAGES = ('Case Created', 'Evidence Registered', 'Integrity Verified', 'Analysis Completed',
          'Evidence Questions Reviewed', 'Human Decision Recorded', 'Report Generated')
INTEGRITY_EVENTS = ('Integrity rechecked', 'Integrity checked before analysis', 'INTEGRITY_CHECK_BEFORE_DECISION')


@guard('read')
def case_progress(case_id=None, db_path=DEFAULT_DB_PATH):
    result = dict(case_id=case_id, status='No case selected', evidence_count=0,
                  classification='No analysis', next_action='Select an accessible case or create a new investigation.',
                  next_page='pages/1_New_Investigation.py', stages=dict.fromkeys(STAGES, 'Not Started'))
    if not case_id:
        return result
    c = connect_database(db_path)
    c.row_factory = sqlite3.Row
    try:
        result['status'] = _status(c, case_id)
        evidence = c.execute('SELECT evidence_id FROM evidence WHERE case_id=?', (case_id,)).fetchall()
        result['evidence_count'] = len(evidence)
        result['stages']['Case Created'] = 'Completed'
        counts = dict.fromkeys(STAGES[1:], 0)
        failed = False
        reanalysis = False
        latest = []
        for item in evidence:
            eid = item['evidence_id']
            counts['Evidence Registered'] += 1
            check = c.execute('SELECT status FROM audit_logs WHERE case_id=? AND evidence_id=? '
                'AND action IN (?,?,?) ORDER BY audit_id DESC LIMIT 1', (case_id, eid, *INTEGRITY_EVENTS)).fetchone()
            failed |= bool(check and check[0] == 'failure')
            counts['Integrity Verified'] += bool(check and check[0] == 'success')
            analysis = c.execute("SELECT analysis_id,classification,analysis_timestamp FROM analysis_results "
                "WHERE evidence_id=? AND status='completed' ORDER BY analysis_version DESC LIMIT 1", (eid,)).fetchone()
            if not analysis:
                continue
            counts['Analysis Completed'] += 1
            latest.append(analysis)
            # A recorded supported answer is a review interaction, not proof of comprehension.
            interactions = c.execute(
                "SELECT analysis_id,masked_response FROM qa_interactions WHERE case_id=? AND evidence_id=? AND status='completed' "
                "AND created_at>=?", (case_id, eid, analysis['analysis_timestamp']))
            for interaction in interactions:
                try:
                    selected = json.loads(interaction['masked_response']).get('selected_analysis_id')
                except (ValueError, AttributeError):
                    selected = None
                if (selected or interaction['analysis_id']) == analysis['analysis_id']:
                    counts['Evidence Questions Reviewed'] += 1
                    break
            decision = c.execute('SELECT decision_id,decision FROM investigator_decisions WHERE analysis_id=? '
                'ORDER BY decision_version DESC LIMIT 1', (analysis['analysis_id'],)).fetchone()
            if decision:
                counts['Human Decision Recorded'] += 1
                reanalysis |= decision['decision'] == 'reanalyse'
                counts['Report Generated'] += bool(c.execute('SELECT 1 FROM reports WHERE decision_id=?',
                                                             (decision['decision_id'],)).fetchone())
        total = len(evidence)
        for stage, count in counts.items():
            result['stages'][stage] = 'Completed' if total and count == total else 'In Progress' if count else 'Not Started'
        if latest:
            classification = max(latest, key=lambda a: a['analysis_timestamp'] or '')['classification']
            result['classification'] = classification if classification in {'Suspicious', 'Uncertain', 'No Significant Indicators Detected'} else 'Unavailable'
        actions = [
            ('Evidence Registered', 'Register synthetic evidence in New Investigation.', 'pages/1_New_Investigation.py'),
            ('Integrity Verified', 'Use Verify Integrity Again on Evidence Analysis.', 'pages/2_Evidence_Analysis.py'),
            ('Analysis Completed', 'Run Phishing Analysis and review its evidence-linked explanations.', 'pages/2_Evidence_Analysis.py'),
            ('Evidence Questions Reviewed', 'Ask a supported question and review its evidence references.', 'pages/3_Ask_the_Evidence.py'),
            ('Human Decision Recorded', 'Review the latest analysis and record a human decision.', 'pages/4_Human_Verification.py'),
            ('Report Generated', 'Generate and verify a forensic report for the latest human decision.', 'pages/5_Forensic_Report.py')]
        result.update(next_action='Review the report integrity and audit trail before presentation.', next_page='pages/5_Forensic_Report.py')
        for stage, action, page in actions:
            if result['stages'][stage] != 'Completed':
                result.update(next_action=action, next_page=page)
                break
        if reanalysis:
            result.update(next_action='The human decision requests further analysis. Review the requested checks.', next_page='pages/2_Evidence_Analysis.py')
        if failed:
            for stage in STAGES[2:]:
                result['stages'][stage] = 'Blocked'
            result.update(next_action='Integrity failed. Preserve the original and investigate the discrepancy before continuing.', next_page='pages/2_Evidence_Analysis.py')
        if result['status'] == 'Archived':
            result.update(next_action='This case is archived. Review preserved records; new investigation actions are blocked.', next_page='pages/5_Forensic_Report.py')
        return result
    finally:
        c.close()


@guard('read')
def recent_events(case_id=None, db_path=DEFAULT_DB_PATH):
    """No actors, details, questions, titles or filenames reach the dashboard."""
    user = current_user(db_path)
    c = connect_database(db_path)
    try:
        rows = c.execute('SELECT created_at,action,status FROM audit_logs WHERE case_id=? '
            'OR (case_id IS NULL AND actor=?) ORDER BY audit_id DESC LIMIT 8', (case_id, user['user_id']))
        # Event names are developer-owned. Legacy/custom free text is suppressed.
        from modules.audit import SAFE_ACTIONS
        return [dict(timestamp_utc=r[0], event=r[1] if r[1] in SAFE_ACTIONS else 'Legacy event',
                     status=r[2]) for r in rows]
    finally:
        c.close()
