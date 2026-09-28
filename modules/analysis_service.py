"""Integrity-gated, append-only local analysis persistence."""
import json
from pathlib import Path
import sqlite3
import uuid

from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database
from modules.evidence_handler import (DATA_ROOT, MAX_FILE_SIZE, get_evidence, evidence_path,
                                      sha256_bytes, log_event, ValidationError)
from modules.email_parser import parse_email
from modules.phishing_analyzer import analyze, ENGINE_VERSION, RULESET_VERSION
from modules.auth import guard


class IntegrityFailure(ValidationError):
    pass


@guard('analyze')
def run_analysis(evidence_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    row = get_evidence(evidence_id, db_path)
    if not row:
        raise ValidationError('Evidence record not found.')
    actor, case_id = row['investigator_name'], row['case_id']

    def event(action, status='success', details=''):
        log_event(actor, action, status, case_id, evidence_id, details, db_path)

    event('Analysis requested')
    connection = connect_database(db_path)
    try:
        prior = connection.execute('SELECT COUNT(*) FROM analysis_results WHERE evidence_id=?', (evidence_id,)).fetchone()[0]
        if prior:
            event('Reanalysis requested', details='A separate analysis record was requested; previous results retained.')
        # Read and hash the SAME bounded byte buffer subsequently passed to the
        # parser, avoiding a verify-then-reopen gap. Never write to the original.
        try:
            with evidence_path(row, data_root=data_root).open('rb') as stream:
                original = stream.read(MAX_FILE_SIZE + 1)
            valid = len(original) <= MAX_FILE_SIZE and sha256_bytes(original) == row['sha256']
        except (OSError, ValueError):
            valid = False
        event('Integrity checked before analysis', 'success' if valid else 'failure',
              'Integrity verified' if valid else 'Integrity check failed')
        if not valid:
            event('Analysis refused due to integrity failure', 'failure', 'No rules were run and no analysis result was created.')
            raise IntegrityFailure('Integrity check failed. Analysis refused.')
        selected_row = None
        extension = Path(row['original_filename']).suffix.lower()
        if extension == '.csv':
            with evidence_path(row, working=True, data_root=data_root).open('rb') as stream:
                working = stream.read(5 * 1024 * 1024 + 1)
            if len(working) > 5 * 1024 * 1024:
                raise ValidationError('Working representation exceeds limits.')
            selected_row = json.loads(working).get('selected_csv_row')
            if type(selected_row) is not int or not 1 <= selected_row <= 500:
                raise ValidationError('The registered CSV row is unavailable.')
        result = analyze(parse_email(original, extension, selected_row))
        del original
        analysis_id = 'ANL-' + uuid.uuid4().hex.upper()
        connection.execute('BEGIN IMMEDIATE')
        # Allocate under the write lock so concurrent reruns get distinct versions.
        version = connection.execute('SELECT COALESCE(MAX(analysis_version),0)+1 FROM analysis_results WHERE evidence_id=?', (evidence_id,)).fetchone()[0]
        result.update(analysis_id=analysis_id, case_id=case_id, evidence_id=evidence_id,
                      analysis_version=version, status='completed')
        connection.execute(
            'INSERT INTO analysis_results(analysis_id,evidence_id,rule_version,findings_json,status,created_at,updated_at,'
            'case_id,classification,risk_score,risk_level,engine_version,missing_information_json,'
            'recommended_verification_json,analysis_timestamp,analysis_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (analysis_id, evidence_id, RULESET_VERSION, json.dumps(result, ensure_ascii=True), 'completed',
             result['analysis_timestamp'], result['analysis_timestamp'], case_id, result['classification'],
             result['risk_score'], result['risk_level'], ENGINE_VERSION,
             json.dumps(result['missing_information']), json.dumps(result['recommended_verification']),
             result['analysis_timestamp'], version))
        connection.execute('UPDATE evidence SET status=?,updated_at=? WHERE evidence_id=?', ('analysed', utc_now(), evidence_id))
        for action, details in (
            ('Analysis completed', f'Analysis {analysis_id}; engine {ENGINE_VERSION}; ruleset {RULESET_VERSION}.'),
            ('Analysis version', f'Version {version}; analysis {analysis_id}.'),
            ('Classification', result['classification']),
            ('Risk score', f"Rule-based score {result['risk_score']}/100; not a probability."),
        ):
            record(connection, actor, action, case_id=case_id, evidence_id=evidence_id, details=details)
        connection.commit()
        return result
    except IntegrityFailure:
        raise
    except Exception:
        connection.rollback()
        event('Rule-processing error', 'failure', 'Analysis failed; no new result committed. Previous records retained.')
        raise
    finally:
        connection.close()


@guard('read')
def analysis_history(evidence_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        return connection.execute('SELECT analysis_id,analysis_version,analysis_timestamp,classification,risk_score '
                                  'FROM analysis_results WHERE evidence_id=? AND status=? '
                                  'ORDER BY analysis_version DESC,created_at DESC LIMIT 100',
                                  (evidence_id, 'completed')).fetchall()
    finally:
        connection.close()


@guard('read')
def view_analysis(analysis_id, evidence_id, db_path=DEFAULT_DB_PATH):
    connection = connect_database(db_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute('SELECT analysis_results.*,cases.investigator_name FROM analysis_results '
                                 'JOIN evidence USING(evidence_id) JOIN cases ON cases.case_id=evidence.case_id '
                                 'WHERE analysis_id=? AND analysis_results.evidence_id=?', (analysis_id, evidence_id)).fetchone()
        if not row:
            raise ValidationError('Analysis record not found.')
        result = json.loads(row['findings_json'])
        with connection:
            record(connection, row['investigator_name'], 'Analysis viewed', case_id=row['case_id'],
                   evidence_id=evidence_id, details=f"Analysis {analysis_id}; version {row['analysis_version']}.")
        return result
    finally:
        connection.close()
