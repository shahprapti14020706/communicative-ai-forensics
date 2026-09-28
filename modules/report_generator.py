"""Offline report snapshots. No network, original-body parsing or source mutation."""
from html import escape
import json
from pathlib import Path
import re
import sqlite3
import uuid
from modules.auth import guard

from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, initialize_database, connect_database
from modules.evidence_handler import (DATA_ROOT, ValidationError, confined, atomic_write,
                                      verify_integrity, sha256_bytes)
from modules.verification_service import _scope, private_text, DECISIONS, CLASSIFICATIONS, ACTIONS
from modules.phishing_analyzer import RULES

NO_DECISION = 'Complete Human Verification before generating the forensic report.'
BLOCKED = 'Report generation is blocked because evidence integrity verification failed.'
EMPTY_QA = 'No Ask-the-Evidence interactions were recorded for this evidence.'
HASH_NOTICE = 'The authoritative final HTML SHA-256 is stored in the application record and accompanying JSON manifest.'
LIMITATIONS = [
    'The system is an academic proof of concept.',
    'Analysis is rule-based and may produce false positives or false negatives.',
    'Masking is heuristic and may not identify every personal detail.',
    'URL and attachment contents are not opened or executed.',
    'No external sender or domain verification is performed.',
    'Findings require qualified human interpretation.',
    'The report is not a legal determination of guilt or liability.',
    'Conservative masking may remove useful context. Investigator identifiers do not authenticate identity.',
    'This is a snapshot of the selected versions, not a claim that they are the latest versions.',
    'SHA-256 detects changes relative to the local record; it is not a digital signature.',
]
CONCLUSIONS = {
    'approve': 'The investigator approved the automated analysis after reviewing the available evidence.',
    'reject': 'The investigator rejected the automated analysis based on the recorded verification notes.',
    'modify': 'The investigator recorded a different human-verified conclusion. The original automated result remains preserved.',
    'reanalyse': 'The investigator requested further analysis before reaching a final conclusion.',
}
EVENTS = {'REPORT_PAGE_OPENED', 'REPORT_PREVIEWED', 'REPORT_GENERATED', 'REPORT_DOWNLOADED',
          'REPORT_VERSION_CREATED', 'REPORT_INTEGRITY_CHECKED', 'REPORT_GENERATION_BLOCKED'}
CUSTODY_EVENTS = {
    'Case created', 'Evidence uploaded', 'Hash generated', 'Original evidence stored',
    'Working copy created', 'Analysis completed', 'Analysis version', 'Integrity rechecked',
    'Integrity checked before analysis', 'INTEGRITY_CHECK_BEFORE_DECISION', 'DECISION_RECORDED',
    'DECISION_VERSION_CREATED', 'REPORT_GENERATED', 'REPORT_VERSION_CREATED', 'REPORT_INTEGRITY_CHECKED',
}
MAX_HISTORY = 1000
MAX_ARTIFACT = 32 * 1024 * 1024


def masked(value):
    value = str(value or '')
    if len(value) > 100000:
        raise ValidationError('Stored text exceeds report limits.')
    # Suppress paths as units before conservative masking; never export host paths.
    value = re.sub(r'(?:[A-Za-z]:[\\/]|\\\\|/)[^\s<>"\']+', '[PRIVATE]', value)
    return private_text(value)


def _json(value):
    if not isinstance(value, str) or len(value) > 5 * 1024 * 1024:
        raise ValidationError('Stored JSON exceeds report limits.')
    return json.loads(value)


def _event(c, action, scope=None, status='success', **metadata):
    if action not in EVENTS:
        raise ValueError('Unsupported report event.')
    record(c, '[INVESTIGATOR]', action, status,
           scope[0] if scope else None, scope[1] if scope else None,
           json.dumps(metadata, sort_keys=True))


def _sources(c, case_id, evidence_id, analysis_id, decision_id):
    evidence, analysis = _scope(c, case_id, evidence_id, analysis_id)
    decision = c.execute("SELECT * FROM investigator_decisions WHERE decision_id=? AND case_id=? "
                         "AND evidence_id=? AND analysis_id=? AND status='recorded'",
                         (decision_id, case_id, evidence_id, analysis_id)).fetchone()
    if not decision:
        raise ValidationError(NO_DECISION)
    d = dict(decision)
    if (d['integrity_status'] != 'verified' or d['evidence_sha256'] != evidence['sha256']
            or not d['decision_version'] or d['decision_type'] not in DECISIONS
            or DECISIONS[d['decision_type']][0] != d['decision']
            or d['automated_classification'] != analysis['classification']
            or d['automated_risk_score'] != analysis['risk_score']
            or not d['created_at_utc'] or not d['masked_verification_notes']):
        raise ValidationError('The selected human decision is incomplete or inconsistent. Complete Human Verification again.')
    if ((d['decision'] == 'approve' and d['final_classification'] != analysis['classification'])
            or (d['decision'] == 'modify' and (d['final_classification'] not in CLASSIFICATIONS
                or d['final_classification'] == analysis['classification']))
            or (d['decision'] in {'reject', 'reanalyse'} and d['final_classification'] is not None)):
        raise ValidationError('The selected human conclusion is inconsistent.')
    case = dict(c.execute('SELECT * FROM cases WHERE case_id=?', (case_id,)).fetchone())
    return case, evidence, analysis, d


@guard('read')
def available_decisions(case_id, evidence_id, analysis_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        _scope(c, case_id, evidence_id, analysis_id)
        return [dict(r) for r in c.execute(
            "SELECT decision_id,decision_version,decision_type,created_at_utc FROM investigator_decisions "
            "WHERE case_id=? AND evidence_id=? AND analysis_id=? AND status='recorded' "
            "AND integrity_status='verified' ORDER BY decision_version DESC",
            (case_id, evidence_id, analysis_id))]
    finally:
        c.close()


@guard('read')
def page_opened(case_id, evidence_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        if not c.execute('SELECT 1 FROM evidence WHERE case_id=? AND evidence_id=?', (case_id, evidence_id)).fetchone():
            raise ValidationError('Select evidence belonging to the active case.')
        with c:
            _event(c, 'REPORT_PAGE_OPENED', (case_id, evidence_id))
    finally:
        c.close()


def _history(c, case_id, evidence_id, analysis_id, decision_id):
    c.row_factory = sqlite3.Row
    return [dict(r) for r in c.execute('SELECT * FROM reports WHERE case_id=? AND evidence_id=? '
        'AND analysis_id=? AND decision_id=? ORDER BY report_version DESC',
        (case_id, evidence_id, analysis_id, decision_id))]


@guard('report_read')
def report_history(case_id, evidence_id, analysis_id, decision_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        _sources(c, case_id, evidence_id, analysis_id, decision_id)
        return _history(c, case_id, evidence_id, analysis_id, decision_id)
    finally:
        c.close()


def _document(c, sources, info):
    case, evidence, analysis, decision = sources
    case_id, evidence_id = case['case_id'], evidence['evidence_id']
    qa_rows = c.execute('SELECT * FROM qa_interactions WHERE case_id=? AND evidence_id=? '
                        'ORDER BY created_at DESC,interaction_id DESC LIMIT ?',
                        (case_id, evidence_id, MAX_HISTORY + 1)).fetchall()
    interactions = []
    for row in reversed(qa_rows[:MAX_HISTORY]):
        response = _json(row['masked_response'])
        refs = _json(row['evidence_references_json'])
        if not isinstance(response, dict) or not isinstance(refs, list):
            raise ValidationError('Stored Q&A structure is invalid.')
        interactions.append(dict(interaction_id=row['interaction_id'], analysis_id=row['analysis_id'],
            masked_question=masked(row['masked_question']), masked_answer=masked(response.get('answer', '')),
            evidence_source_labels=[masked(r.get('source', '')) for r in refs if isinstance(r, dict)
                and r.get('case_id', case_id) == case_id and r.get('evidence_id', evidence_id) == evidence_id],
            timestamp_utc=row['created_at'], status=row['status'],
            limitations=[masked(v) for v in response.get('limitations', [])]))
    event_names = sorted(CUSTODY_EVENTS)
    events = c.execute('SELECT audit_id,action,status,created_at FROM audit_logs '
        'WHERE case_id=? AND evidence_id=? AND action IN (' + ','.join('?' for _ in event_names) + ') '
        'ORDER BY audit_id DESC LIMIT ?',
        (case_id, evidence_id, *event_names, MAX_HISTORY + 1)).fetchall()
    custody = [dict(audit_id=r['audit_id'], event=r['action'], status=r['status'],
                    timestamp_utc=r['created_at'], case_id=case_id, evidence_id=evidence_id)
               for r in reversed(events[:MAX_HISTORY]) if r['action'] in CUSTODY_EVENTS]
    findings = []
    for finding in analysis['findings']:
        rule = RULES.get(finding['rule_id'])
        indicator = rule[0] if rule and rule[0] == finding['indicator'] else masked(finding['indicator'])
        findings.append(dict(indicator=indicator, explanation=masked(finding['explanation']),
            evidence_source=masked(finding['evidence_source']), masked_supporting_snippet=masked(finding['masked_evidence']),
            suggested_manual_check=masked(finding['manual_verification'])))
    requests = _json(decision['requested_actions'])
    if not isinstance(requests, dict) or not isinstance(requests.get('actions'), list):
        raise ValidationError('Stored human requests are invalid.')
    human_status = decision['final_classification'] or (
        'Further analysis required' if decision['decision'] == 'reanalyse' else 'Analysis rejected; no final classification')
    file_type = Path(evidence['original_filename']).suffix.lower()
    investigator = decision['investigator_name']
    if not re.fullmatch(r'\[INVESTIGATOR-[A-F0-9]{12}\]', investigator):
        investigator = '[INVESTIGATOR]'
    return {
        'report_information': dict(info, system_name='Communicative AI Digital Forensics Assistant',
            academic_statement='This system is an academic prototype.'),
        'case_information': dict(case_id=case_id, case_title=masked(case['title']),
            masked_investigator_identifier=investigator, purpose=masked(case['description']),
            created_at_utc=case['created_at']),
        'evidence_information': dict(evidence_id=evidence_id, original_filename=masked(evidence['original_filename']),
            file_type=file_type if file_type in {'.eml', '.txt', '.csv'} else 'Unavailable',
            file_size_bytes=evidence['file_size'], sha256=evidence['sha256'],
            registered_at_utc=evidence['created_at'], current_integrity_status='Pass'),
        'chain_of_custody': dict(events=custody, scope='Selected case and evidence only; private audit details and actors omitted.',
            history_limit=MAX_HISTORY, truncated=len(events) > MAX_HISTORY),
        'automated_analysis': dict(analysis_id=analysis['analysis_id'], analysis_version=analysis['analysis_version'],
            automated_classification=analysis['classification'], rule_based_risk_score=analysis['risk_score'],
            score_out_of=100, risk_level=analysis['risk_level'] if analysis['risk_level'] in {'Low', 'Medium', 'High'} else 'Unavailable',
            score_statement='The score is a rule-based risk score and is not a probability.',
            warning='Automated findings are investigative leads and require human verification.', findings=findings,
            missing_information=[masked(v) for v in analysis['missing_information']],
            suggested_manual_checks=[masked(v) for v in analysis['recommended_verification']],
            analysis_timestamp_utc=analysis['analysis_timestamp']),
        'ask_the_evidence_summary': dict(interactions=interactions, message='' if interactions else EMPTY_QA,
            scope='Selected case and evidence, including other analysis versions explicitly identified per interaction.',
            history_limit=MAX_HISTORY, truncated=len(qa_rows) > MAX_HISTORY),
        'human_verification': dict(decision_id=decision['decision_id'], decision_version=decision['decision_version'],
            decision_type=decision['decision_type'], automated_classification=decision['automated_classification'],
            human_verified_classification_or_status=human_status, masked_verification_notes=masked(decision['masked_verification_notes']),
            requested_further_actions=[v if v in ACTIONS else '[PRIVATE]' for v in requests['actions']],
            other_request=masked(requests.get('other_description', '')),
            masked_change_reason=masked(decision['masked_change_reason']),
            masked_version_reason=masked(decision['masked_version_reason']),
            integrity_status_at_decision=decision['integrity_status'], decision_timestamp_utc=decision['created_at_utc']),
        'limitations': list(LIMITATIONS),
        'final_conclusion': CONCLUSIONS[decision['decision']],
        'report_integrity': dict(report_sha256=HASH_NOTICE, generation_timestamp_utc=info['created_at_utc'],
            source_evidence_sha256=evidence['sha256'], analysis_id=analysis['analysis_id'],
            analysis_version=analysis['analysis_version'], decision_id=decision['decision_id'],
            decision_version=decision['decision_version']),
    }


def render_html(document):
    """All dynamic strings, including keys, are escaped; no dynamic attributes."""
    def render(value):
        if isinstance(value, dict):
            return '<table><tbody>' + ''.join('<tr><th>' + escape(str(k).replace('_', ' ').capitalize(), quote=True)
                + '</th><td>' + render(v) + '</td></tr>' for k, v in value.items()) + '</tbody></table>'
        if isinstance(value, list):
            return '<ul>' + ''.join('<li>' + render(v) + '</li>' for v in value) + '</ul>' if value else '<p>None recorded.</p>'
        return '<span>' + escape('Not applicable' if value is None else str(value), quote=True) + '</span>'
    body = ''.join('<section><h2>' + escape(k.replace('_', ' ').upper(), quote=True) + '</h2>' + render(v) + '</section>' for k, v in document.items())
    return ('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Local Forensic Report</title><style>
body{font:14px Georgia,serif;color:#000;background:#fff;max-width:1100px;margin:32px auto;padding:20px;line-height:1.5}
h1,h2{font-family:Arial,sans-serif;color:#000}h1{border-bottom:3px solid #000}h2{font-size:18px;border-bottom:1px solid #000;padding-top:20px}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid #777;text-align:left;vertical-align:top;padding:8px;overflow-wrap:anywhere}
th{width:26%;font-family:Arial,sans-serif}span{white-space:pre-wrap}li{margin:6px 0}
@media print{body{margin:0;padding:0;max-width:none;font-size:10pt}h2{break-after:avoid}tr{break-inside:avoid}thead{display:table-header-group}}
</style></head><body><h1>Forensic Report</h1>''' + body + '</body></html>').encode('utf-8')


@guard('report_read')
def preview_report(case_id, evidence_id, analysis_id, decision_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    c = connect_database(db_path)
    scope = None
    try:
        c.execute('BEGIN')
        sources = _sources(c, case_id, evidence_id, analysis_id, decision_id)
        scope = (case_id, evidence_id)
        if not verify_integrity(evidence_id, db_path, data_root, audit=False):
            raise ValidationError(BLOCKED)
        document = _document(c, sources, dict(report_id='Not generated', report_version=None,
                             created_at_utc=utc_now(), status='preview'))
        _event(c, 'REPORT_PREVIEWED', (case_id, evidence_id), analysis_id=analysis_id, decision_id=decision_id, integrity_status='verified')
        c.commit()
        return document
    except Exception:
        c.rollback()
        with c:
            _event(c, 'REPORT_GENERATION_BLOCKED', scope, status='failure', reason='preview_validation_failed')
        raise
    finally:
        c.close()


def _report_directory(data_root, case_id, report_id):
    if not re.fullmatch(r'CASE-[A-Z0-9-]{1,60}', case_id or '') or not re.fullmatch(r'RPT-[A-F0-9]{12}', report_id or ''):
        raise ValidationError('Invalid report storage identifiers.')
    return confined(data_root, 'reports', case_id, report_id)


@guard('report_generate')
def generate_report(case_id, evidence_id, analysis_id, decision_id, version_reason='',
                    expected_previous_id=None, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    c = connect_database(db_path)
    directory = None
    created = False
    scope = None
    try:
        c.execute('BEGIN IMMEDIATE')
        sources = _sources(c, case_id, evidence_id, analysis_id, decision_id)
        scope = (case_id, evidence_id)
        history = _history(c, case_id, evidence_id, analysis_id, decision_id)
        previous = history[0]['report_id'] if history else None
        if expected_previous_id != previous:
            raise ValidationError('Report history changed. Review the latest report before generating a new version.')
        if history and (not isinstance(version_reason, str) or not 1 <= len(version_reason.strip()) <= 5000):
            raise ValidationError('A reason of 1–5000 characters is required for a new report version.')
        report_id = 'RPT-' + uuid.uuid4().hex[:12].upper()
        version = history[0]['report_version'] + 1 if history else 1
        now = utc_now()
        info = dict(report_id=report_id, report_version=version, created_at_utc=now, status='generated',
                    supersedes_report_id=previous, masked_version_reason=masked(version_reason.strip()) if history else '')
        # The event is part of the same transaction and therefore of the report's
        # custody snapshot. Neither survives if artifact creation fails.
        _event(c, 'REPORT_GENERATED', (case_id, evidence_id), report_id=report_id, report_version=version,
               analysis_id=analysis_id, decision_id=decision_id, integrity_status='verified')
        if history:
            _event(c, 'REPORT_VERSION_CREATED', (case_id, evidence_id), report_id=report_id, supersedes_report_id=previous)
        document = _document(c, sources, info)
        # Fresh check immediately before serializing/writing this snapshot.
        if not verify_integrity(evidence_id, db_path, data_root, audit=False):
            raise ValidationError(BLOCKED)
        html_bytes = render_html(document)
        digest = sha256_bytes(html_bytes)
        document['report_integrity']['report_sha256'] = digest
        json_bytes = json.dumps(document, ensure_ascii=True, indent=2).encode('utf-8')
        if max(len(html_bytes), len(json_bytes)) > MAX_ARTIFACT:
            raise ValidationError('Report exceeds the local artifact size limit.')
        directory = _report_directory(data_root, case_id, report_id)
        directory.parent.mkdir(parents=True, exist_ok=True)
        directory.mkdir(exist_ok=False)
        created = True
        html_path = directory / f'{report_id}-v{version}.html'
        json_path = directory / f'{report_id}-v{version}.json'
        atomic_write(html_path, html_bytes)
        atomic_write(json_path, json_bytes)
        result = dict(info, case_id=case_id, evidence_id=evidence_id, analysis_id=analysis_id, decision_id=decision_id,
                      html_path=html_path.relative_to(Path(data_root).absolute()).as_posix(),
                      json_path=json_path.relative_to(Path(data_root).absolute()).as_posix(),
                      report_sha256=digest, json_sha256=sha256_bytes(json_bytes), source_evidence_sha256=sources[1]['sha256'])
        c.execute('INSERT INTO reports (' + ','.join(result) + ') VALUES (' + ','.join('?' for _ in result) + ')', tuple(result.values()))
        c.commit()
        return result
    except Exception:
        c.rollback()
        # Only this invocation's newly and exclusively created directory is cleaned.
        # The checked location cannot name another report or leave the report tree.
        if created and directory == _report_directory(data_root, case_id, report_id):
            for path in directory.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.unlink()
            directory.rmdir()
        with c:
            _event(c, 'REPORT_GENERATION_BLOCKED', scope, status='failure', reason='generation_failed')
        raise
    finally:
        c.close()


def _stored(c, case_id, evidence_id, report_id):
    c.row_factory = sqlite3.Row
    row = c.execute('SELECT * FROM reports WHERE report_id=? AND case_id=? AND evidence_id=?',
                     (report_id, case_id, evidence_id)).fetchone()
    if not row:
        raise ValidationError('The selected report does not belong to the active case and evidence.')
    return dict(row)


def _read_artifact(row, kind, data_root):
    directory = _report_directory(data_root, row['case_id'], row['report_id'])
    expected = directory / (row['report_id'] + '-v' + str(row['report_version']) + '.' + kind)
    actual = confined(data_root, row[kind + '_path'])
    if actual != expected:
        raise ValidationError('Report location does not match its identifiers.')
    with actual.open('rb') as stream:
        value = stream.read(MAX_ARTIFACT + 1)
    if len(value) > MAX_ARTIFACT:
        raise ValidationError('Report exceeds the local artifact size limit.')
    return value


@guard('report_read')
def verify_report_integrity(case_id, evidence_id, report_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        row = _stored(c, case_id, evidence_id, report_id)
        try:
            valid = sha256_bytes(_read_artifact(row, 'html', data_root)) == row['report_sha256']
        except (OSError, ValueError, TypeError):
            valid = False
        with c:
            _event(c, 'REPORT_INTEGRITY_CHECKED', (case_id, evidence_id), 'success' if valid else 'failure',
                   report_id=report_id, integrity_status='Pass' if valid else 'Fail')
        return valid
    finally:
        c.close()


@guard('report_read')
def download_bytes(case_id, evidence_id, report_id, kind, audit=False, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    if kind not in {'html', 'json'}:
        raise ValidationError('Unsupported report format.')
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        row = _stored(c, case_id, evidence_id, report_id)
        html_bytes = _read_artifact(row, 'html', data_root)
        json_bytes = _read_artifact(row, 'json', data_root)
        if sha256_bytes(html_bytes) != row['report_sha256'] or sha256_bytes(json_bytes) != row['json_sha256']:
            raise ValidationError('Report integrity failed. Downloads are blocked.')
        if audit:
            with c:
                _event(c, 'REPORT_DOWNLOADED', (case_id, evidence_id), report_id=report_id, format=kind)
        return html_bytes if kind == 'html' else json_bytes
    finally:
        c.close()
