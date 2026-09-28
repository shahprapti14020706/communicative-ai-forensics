"""Explicit, authenticated synthetic intake; conservative cleanup of untouched demos."""
import argparse
import getpass
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3

from modules import auth
from modules.audit import record
from modules.database import DEFAULT_DB_PATH, connect_database
from modules.evidence_handler import DATA_ROOT, confined, atomic_write, register_evidence, ValidationError
from modules.case_service import archive_case, request_deletion, delete_case, _targets

LABEL = 'SYNTHETIC DEMONSTRATION'
SAMPLE_PATH = Path(__file__).resolve().parent.parent / 'samples' / 'obvious_phishing.eml'
SAMPLE_SHA256 = 'bf8ec322b34ae7f2d5b550a4c290e78e9688fa3faeadbb364a9fcdc2d4eddf81'


def sample_bytes():
    try:
        data = SAMPLE_PATH.read_bytes()
    except OSError:
        raise ValidationError('The bundled synthetic sample is missing or unreadable.') from None
    if hashlib.sha256(data).hexdigest() != SAMPLE_SHA256:
        raise ValidationError('The synthetic sample was changed or is malformed. Restore the reviewed sample before setup.')
    # A synthetic header in the COPY permits independent demonstrations without
    # weakening global duplicate detection or modifying the sample file.
    return b'X-Synthetic-Demonstration: ' + secrets.token_hex(16).encode('ascii') + b'\r\n' + data


def _receipt(case_id, data_root):
    if not re.fullmatch(r'CASE-\d{8}-[A-F0-9]{4}', case_id or ''):
        raise ValidationError('Invalid demonstration identifier.')
    return confined(data_root, 'demo_setup', case_id + '.json')


def _fingerprint(case_id, db_path, data_root):
    """Only unchanged helper-created records/files are eligible for automatic removal."""
    c = connect_database(db_path)
    try:
        state = {}
        for table in ('cases', 'evidence', 'analysis_results', 'qa_interactions',
                      'investigator_decisions', 'reports', 'case_assignments', 'audit_logs'):
            if table == 'cases':
                state[table] = c.execute('SELECT case_id,title,investigator_name,description,evidence_source,created_at FROM cases WHERE case_id=?', (case_id,)).fetchall()
            elif table == 'audit_logs':
                state[table] = c.execute("SELECT * FROM audit_logs WHERE case_id=? AND action NOT IN ('CASE_ARCHIVED','CASE_DELETION_REQUESTED') ORDER BY rowid", (case_id,)).fetchall()
            else:
                state[table] = c.execute('SELECT * FROM ' + table + ' WHERE case_id=? ORDER BY rowid', (case_id,)).fetchall()
        paths = _targets(c, case_id, data_root)
        state['files'] = {str(p.relative_to(Path(data_root).absolute())): hashlib.sha256(p.read_bytes()).hexdigest()
                          for target in paths if target.exists() for p in target.rglob('*') if p.is_file()}
        return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()
    finally:
        c.close()


@auth.guard('admin')
def create_demo(db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    confined(data_root, Path(db_path).absolute())
    data = sample_bytes()
    directory = confined(data_root, 'demo_setup')
    directory.mkdir(parents=True, exist_ok=True)
    case_id, evidence_id = register_evidence(LABEL, 'Synthetic Investigator',
        'Synthetic academic demonstration only.', 'Bundled synthetic sample', True,
        'synthetic-demonstration.eml', data, db_path=db_path, data_root=data_root)
    nonce = secrets.token_hex(24)
    c = connect_database(db_path)
    try:
        with c:
            record(c, auth.current_user(db_path)['user_id'], 'DEMO_CREATED', case_id=case_id,
                   evidence_id=evidence_id, details=json.dumps({'demo_receipt': nonce}))
    finally:
        c.close()
    receipt = dict(case_id=case_id, evidence_id=evidence_id, nonce=nonce,
                   fingerprint=_fingerprint(case_id, db_path, data_root))
    atomic_write(_receipt(case_id, data_root), json.dumps(receipt).encode())
    return case_id, evidence_id


def _validated(case_id, db_path, data_root):
    confined(data_root, Path(db_path).absolute())
    path = _receipt(case_id, data_root)
    try:
        if path.stat().st_size > 4096:
            raise ValueError()
        receipt = json.loads(path.read_text(encoding='utf-8'))
        if receipt['case_id'] != case_id:
            raise ValueError()
        c = connect_database(db_path)
        try:
            row = c.execute('SELECT title FROM cases WHERE case_id=?', (case_id,)).fetchone()
            event = c.execute("SELECT details FROM audit_logs WHERE case_id=? AND evidence_id=? AND action='DEMO_CREATED'",
                              (case_id, receipt['evidence_id'])).fetchone()
            if not row or row[0] != LABEL or not event or json.loads(event[0]) != {'demo_receipt':receipt['nonce']}:
                raise ValueError()
        finally:
            c.close()
        if receipt['fingerprint'] != _fingerprint(case_id, db_path, data_root):
            raise ValidationError('Demo changed after setup. Cleanup refuses to remove investigator-created records or files. Preserve it or use the reviewed administrator case-deletion workflow.')
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, ValidationError):
            raise
        raise ValidationError('No valid helper-created synthetic demonstration is available for cleanup.') from None
    return path


@auth.guard('admin')
def list_demos(db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    directory = confined(data_root, 'demo_setup')
    result = []
    for path in sorted(directory.glob('CASE-*.json')):
        try:
            _validated(path.stem, db_path, data_root)
            result.append({'case_id': path.stem, 'cleanup': 'Eligible'})
        except ValidationError:
            # Report only a syntactically valid ID, never arbitrary receipt content.
            if re.fullmatch(r'CASE-\d{8}-[A-F0-9]{4}', path.stem):
                result.append({'case_id': path.stem, 'cleanup': 'Blocked: changed or invalid receipt'})
    return result


@auth.guard('admin')
def cleanup_demo(case_id, confirmation, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    if confirmation != 'DELETE DEMO ' + case_id:
        raise ValidationError('Enter the exact synthetic demo cleanup confirmation.')
    path = _validated(case_id, db_path, data_root)
    archive_case(case_id, db_path)
    request_deletion(case_id, db_path, data_root)
    result = delete_case(case_id, 'DELETE ' + case_id, db_path, data_root, demo_only=True)
    if result['status'] == 'completed':
        path.unlink()
    c = connect_database(db_path)
    try:
        with c:
            auth.event(c, 'DEMO_CLEANED', auth.current_user(db_path)['user_id'], demo_case_id=case_id,
                       cleanup_status=result['status'])
    finally:
        c.close()
    return result


def main():
    parser = argparse.ArgumentParser(description='Local synthetic demonstration setup or conservative cleanup')
    parser.add_argument('command', nargs='?', choices=['create', 'cleanup'], default='create')
    args = parser.parse_args()
    token = None
    try:
        token = auth.login(input('Administrator username: ').strip(), getpass.getpass('Password: '))
        with auth.as_session(token):
            auth.require_permission('admin')
            if args.command == 'create':
                if input('Type CREATE SYNTHETIC DEMONSTRATION: ') != 'CREATE SYNTHETIC DEMONSTRATION':
                    print('Cancelled. No demonstration created.')
                    return
                case_id, _ = create_demo()
                print(LABEL + ': ' + case_id)
                print('Open it on Dashboard. No analysis, human approval or report was created.')
            else:
                demos = list_demos()
                for item in demos:
                    print(item['case_id'] + ' | ' + item['cleanup'])
                eligible = [item['case_id'] for item in demos if item['cleanup'] == 'Eligible']
                if not eligible:
                    print('No unchanged helper-created cases are eligible. Nothing will be removed.')
                for case_id in eligible:
                    confirmation = input('Remove exactly ' + case_id + '? Type DELETE DEMO ' + case_id + ': ')
                    if confirmation == 'DELETE DEMO ' + case_id:
                        print(case_id + ': ' + cleanup_demo(case_id, confirmation)['status'])
                    else:
                        print('Skipped ' + case_id)
    except (ValueError, OSError, sqlite3.Error):
        raise SystemExit('Demo operation unavailable. Check administrator access, the bundled sample, cleanup eligibility and local storage. No non-demo case was selected for cleanup.') from None
    except (EOFError, KeyboardInterrupt):
        raise SystemExit('Demo operation cancelled.') from None
    finally:
        if token:
            try:
                auth.logout(token)
            except (OSError, sqlite3.Error):
                print('Session cleanup could not reach local storage. The session remains subject to its normal expiry.')


if __name__ == '__main__':
    main()
