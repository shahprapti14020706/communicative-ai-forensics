"""Assigned case browsing, lifecycle and administrator-only deletion."""
import json
from pathlib import Path
import re
import secrets
import stat

from modules.auth import guard, current_user, can_access, event, AccessDenied, DENIED
from modules.audit import utc_now
from modules.database import DEFAULT_DB_PATH, connect_database
from modules.evidence_handler import DATA_ROOT, confined, evidence_path, ValidationError
from modules.verification_service import private_text

DELETION_WARNING = 'Deletion removes the application’s files and database records, but guaranteed physical erasure cannot be assured on modern storage devices.'


def _status(c, case_id):
    row = c.execute('SELECT archived_at_utc,status FROM cases WHERE case_id=?', (case_id,)).fetchone()
    if row[0] or row[1] == 'closed':
        return 'Archived'
    evidence = c.execute('SELECT evidence_id FROM evidence WHERE case_id=?', (case_id,)).fetchall()
    if not evidence:
        return 'Open'
    stages = []
    for (evidence_id,) in evidence:
        analysis = c.execute("SELECT analysis_id FROM analysis_results WHERE evidence_id=? AND status='completed' ORDER BY analysis_version DESC LIMIT 1", (evidence_id,)).fetchone()
        if not analysis:
            stages.append(1)
            continue
        decision = c.execute("SELECT decision_id,decision FROM investigator_decisions WHERE analysis_id=? AND status='recorded' ORDER BY decision_version DESC LIMIT 1", (analysis[0],)).fetchone()
        if not decision:
            stages.append(2)
        elif decision[1] == 'reanalyse':
            stages.append(1)
        elif c.execute('SELECT 1 FROM reports WHERE decision_id=?', (decision[0],)).fetchone():
            stages.append(4)
        else:
            stages.append(3)
    return {1:'Under Analysis', 2:'Awaiting Human Verification', 3:'Verified', 4:'Report Generated'}[min(stages)]


def refresh_statuses(db_path=DEFAULT_DB_PATH):
    c = connect_database(db_path)
    try:
        with c:
            for (case_id,) in c.execute('SELECT case_id FROM cases').fetchall():
                c.execute('UPDATE cases SET workflow_status=? WHERE case_id=?', (_status(c, case_id), case_id))
    finally:
        c.close()


@guard('read')
def list_cases(search='', db_path=DEFAULT_DB_PATH):
    user = current_user(db_path)
    refresh_statuses(db_path)
    c = connect_database(db_path)
    try:
        rows = c.execute('SELECT case_id,title,workflow_status FROM cases WHERE '
            '(? OR EXISTS (SELECT 1 FROM case_assignments a WHERE a.case_id=cases.case_id AND a.user_id=? AND a.active=1)) '
            'AND (instr(lower(case_id),lower(?))>0 OR instr(lower(title),lower(?))>0) ORDER BY created_at DESC',
            (user['role']=='Administrator', user['user_id'], search[:200], search[:200])).fetchall()
        result = []
        for case_id, title, status in rows:
            evidence = [r[0] for r in c.execute('SELECT evidence_id FROM evidence WHERE case_id=?', (case_id,))]
            latest = c.execute('SELECT status FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?) ORDER BY created_at DESC LIMIT 1', (case_id,)).fetchone()
            decisions = c.execute('SELECT COUNT(*) FROM investigator_decisions WHERE analysis_id IN (SELECT analysis_id FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?))', (case_id,)).fetchone()[0]
            reports = c.execute('SELECT COUNT(*) FROM reports WHERE case_id=?', (case_id,)).fetchone()[0]
            safe_title = 'SYNTHETIC DEMONSTRATION' if title == 'SYNTHETIC DEMONSTRATION' else private_text(title)
            result.append(dict(case_id=case_id, masked_title=safe_title, status=status, evidence_count=len(evidence),
                latest_analysis_status=latest[0] if latest else 'Not started', verification_status='Recorded' if decisions else 'Not recorded',
                report_status='Generated' if reports else 'Not generated'))
        return result
    finally:
        c.close()


@guard('read')
def open_case(case_id, db_path=DEFAULT_DB_PATH):
    user = current_user(db_path)
    c = connect_database(db_path)
    try:
        rows = [r[0] for r in c.execute('SELECT evidence_id FROM evidence WHERE case_id=? ORDER BY created_at DESC', (case_id,))]
        with c:
            event(c, 'CASE_OPENED', user['user_id'], case_id=case_id)
        return rows
    finally:
        c.close()


@guard('admin')
def assign_case(case_id, user_id, active=True, db_path=DEFAULT_DB_PATH):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        with c:
            if not c.execute('SELECT 1 FROM users WHERE user_id=? AND enabled=1', (user_id,)).fetchone():
                raise ValueError('Select an enabled user.')
            c.execute('INSERT INTO case_assignments(assignment_id,case_id,user_id,assigned_by,assigned_at_utc,active) VALUES(?,?,?,?,?,?) '
                'ON CONFLICT(case_id,user_id) DO UPDATE SET active=excluded.active,assigned_by=excluded.assigned_by,assigned_at_utc=excluded.assigned_at_utc',
                ('ASN-'+secrets.token_hex(12).upper(), case_id, user_id, actor, utc_now(), int(bool(active))))
            event(c, 'CASE_ASSIGNED', actor, case_id=case_id, target_user_id=user_id, active=bool(active))
    finally:
        c.close()


@guard('archive')
def archive_case(case_id, db_path=DEFAULT_DB_PATH):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        with c:
            c.execute("UPDATE cases SET status='closed',workflow_status='Archived',archived_at_utc=?,archived_by=? WHERE case_id=?",
                      (utc_now(), actor, case_id))
            event(c, 'CASE_ARCHIVED', actor, case_id=case_id)
    finally:
        c.close()


def _targets(c, case_id, data_root):
    if not re.fullmatch(r'CASE-[A-Z0-9-]{1,60}', case_id or ''):
        raise ValidationError('Invalid deletion scope.')
    targets = [confined(data_root, area, case_id) for area in ('evidence','working','reports')]
    for row in c.execute('SELECT * FROM evidence WHERE case_id=?', (case_id,)):
        names = [v[0] for v in c.execute('SELECT * FROM evidence LIMIT 0').description]
        evidence = dict(zip(names, row))
        for working in (False, True):
            evidence_path(evidence, working=working, data_root=data_root)
    for rid, version, html, manifest in c.execute('SELECT report_id,report_version,html_path,json_path FROM reports WHERE case_id=?', (case_id,)):
        if not re.fullmatch(r'RPT-[A-F0-9]{12}', rid):
            raise ValidationError('Invalid report storage identifier.')
        for kind, path in [('html',html),('json',manifest)]:
            if confined(data_root, path) != confined(data_root, 'reports', case_id, rid, f'{rid}-v{version}.{kind}'):
                raise ValidationError('Report path does not match the selected case.')
    for target in targets:
        _validate_tree(target, data_root)
    return targets


def _validate_tree(target, data_root):
    # Reject redirected paths before traversal, including Windows junctions.
    confined(data_root, *target.relative_to(Path(data_root).absolute()).parts)
    if target.exists():
        for child in target.iterdir():
            confined(data_root, *child.relative_to(Path(data_root).absolute()).parts)
            if child.is_dir():
                _validate_tree(child, data_root)


def _inventory(c, case_id, data_root):
    targets = _targets(c, case_id, data_root)
    result = {label: sum(p.is_file() for p in target.rglob('*')) if target.exists() else 0
              for label, target in zip(('Evidence originals','Masked working copies','Report files'), targets)}
    for label, table, column in [('Analysis results','analysis_results','case_id'), ('Q&A interactions','qa_interactions','case_id'),
                                ('Human decisions','investigator_decisions','case_id'),('Reports','reports','case_id'),('Audit records','audit_logs','case_id')]:
        if table in {'analysis_results','investigator_decisions'}:
            query = ('SELECT COUNT(*) FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?)'
                     if table == 'analysis_results' else 'SELECT COUNT(*) FROM investigator_decisions WHERE analysis_id IN (SELECT analysis_id FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?))')
            result[label] = c.execute(query, (case_id,)).fetchone()[0]
        else:
            result[label] = c.execute(f'SELECT COUNT(*) FROM {table} WHERE {column}=?', (case_id,)).fetchone()[0]
    return result


@guard('admin')
def deletion_preview(case_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    c = connect_database(db_path)
    try:
        row = c.execute('SELECT archived_at_utc FROM cases WHERE case_id=?', (case_id,)).fetchone()
        if not row or not row[0]:
            raise ValidationError('Archive the case before marking it for deletion.')
        return _inventory(c, case_id, data_root)
    finally:
        c.close()


@guard('admin')
def request_deletion(case_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    inventory = deletion_preview(case_id, db_path, data_root)
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        with c:
            c.execute('UPDATE cases SET deletion_requested_at_utc=?,deletion_requested_by=? WHERE case_id=?', (utc_now(), actor, case_id))
            event(c, 'CASE_DELETION_REQUESTED', actor, case_id=case_id)
        return inventory
    finally:
        c.close()


def _purge(path, data_root):
    _validate_tree(path, data_root)
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            _purge(child, data_root)
        else:
            child.chmod(stat.S_IREAD | stat.S_IWRITE)
            child.unlink()
    path.rmdir()


@guard('admin')
def pending_deletions(db_path=DEFAULT_DB_PATH):
    c = connect_database(db_path)
    try:
        return [dict(zip(('job_id','case_id'), r)) for r in c.execute("SELECT job_id,case_id FROM deletion_jobs WHERE status='pending'")]
    finally:
        c.close()


@guard('admin')
def finish_deletion(job_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        row = c.execute("SELECT case_id FROM deletion_jobs WHERE job_id=? AND status='pending'", (job_id,)).fetchone()
        if not row or not re.fullmatch(r'DEL-[A-F0-9]{24}', job_id):
            raise ValidationError('No pending deletion is available.')
        _purge(confined(data_root, '.deletion', job_id), data_root)
        with c:
            c.execute("UPDATE deletion_jobs SET status='completed',completed_at_utc=? WHERE job_id=?", (utc_now(), job_id))
            event(c, 'CASE_DELETED', actor, deleted_case_id=row[0], deletion_id=job_id)
    finally:
        c.close()


@guard('admin')
def delete_case(case_id, confirmation, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT, demo_only=False):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    moved = []
    committed = False
    created_staging = False
    job_id = 'DEL-' + secrets.token_hex(12).upper()
    staging = confined(data_root, '.deletion', job_id)
    try:
        c.execute('PRAGMA secure_delete=ON')
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT archived_at_utc,deletion_requested_at_utc,deletion_requested_by FROM cases WHERE case_id=?', (case_id,)).fetchone()
        if confirmation != 'DELETE ' + case_id or not row or not row[0] or not row[1] or row[2] != actor:
            raise ValidationError('Deletion requires this administrator to mark the archived case and enter the exact confirmation.')
        if demo_only:
            from modules.demo_setup import _validated
            # Recheck provenance under the deletion write lock, before moving files.
            _validated(case_id, db_path, data_root)
        targets = _targets(c, case_id, data_root)
        staging.parent.mkdir(exist_ok=True)
        staging.mkdir(exist_ok=False)
        created_staging = True
        for target in targets:
            if target.exists():
                destination = confined(data_root, '.deletion', job_id, target.parent.name)
                target.rename(destination)
                moved.append((target, destination))
        c.create_function('case_deletion_allowed', 1, lambda candidate: int(candidate == case_id))
        for (report_id,) in c.execute('SELECT report_id FROM reports WHERE case_id=? ORDER BY report_version DESC', (case_id,)).fetchall():
            c.execute('DELETE FROM reports WHERE report_id=?', (report_id,))
        c.execute('DELETE FROM qa_interactions WHERE case_id=?', (case_id,))
        for (decision_id,) in c.execute('SELECT decision_id FROM investigator_decisions WHERE analysis_id IN '
            '(SELECT analysis_id FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?)) ORDER BY decision_version DESC', (case_id,)).fetchall():
            c.execute('DELETE FROM investigator_decisions WHERE decision_id=?', (decision_id,))
        c.execute('DELETE FROM analysis_results WHERE evidence_id IN (SELECT evidence_id FROM evidence WHERE case_id=?)', (case_id,))
        c.execute('DELETE FROM audit_logs WHERE case_id=?', (case_id,))
        c.execute('DELETE FROM evidence WHERE case_id=?', (case_id,))
        c.execute('DELETE FROM case_assignments WHERE case_id=?', (case_id,))
        c.execute('DELETE FROM cases WHERE case_id=?', (case_id,))
        c.execute("INSERT INTO deletion_jobs(job_id,case_id,requested_by,status,created_at_utc) VALUES(?,?,?,'pending',?)", (job_id, case_id, actor, utc_now()))
        c.commit()
        committed = True
    except Exception:
        c.rollback()
        if not committed:
            for original, staged in reversed(moved):
                _validate_tree(staged, data_root)
                confined(data_root, *original.relative_to(Path(data_root).absolute()).parts)
                staged.rename(original)
            if created_staging and staging.exists():
                staging.rmdir()
        raise
    finally:
        c.close()
    try:
        finish_deletion(job_id, db_path, data_root)
    except OSError:
        return {'job_id':job_id, 'status':'pending'}
    return {'job_id':job_id, 'status':'completed'}


@guard('audit')
def audit_history(case_id=None, db_path=DEFAULT_DB_PATH, event_filter=None, status_filter=None, offset=0):
    if type(offset) is not int or offset < 0:
        raise ValidationError('History offset must be a non-negative integer.')
    c = connect_database(db_path)
    try:
        return [dict(zip(('timestamp_utc','case_id','evidence_id','event','status','actor','details'), r)) for r in c.execute(
            'SELECT created_at,case_id,evidence_id,action,status,actor,details FROM audit_logs '
            'WHERE (? IS NULL OR case_id=?) AND (? IS NULL OR action=?) AND (? IS NULL OR status=?) '
            'ORDER BY audit_id DESC LIMIT 500 OFFSET ?',
            (case_id, case_id, event_filter, event_filter, status_filter, status_filter, offset))]
    finally:
        c.close()
