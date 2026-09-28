"""Scoped retrieval and append-only Q&A persistence. Never reads original content."""
import json
import sqlite3
import uuid
from modules.auth import guard
from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database
from modules.evidence_handler import DATA_ROOT, evidence_path, ValidationError
from modules.qa_engine import (answer_question, redact, MAX_QUESTION, MAX_MESSAGES,
                               INJECTION, MAX_REFERENCES, MAX_SNIPPET)

MAX_JSON_BYTES = 5 * 1024 * 1024


class ScopeError(ValidationError):
    pass


def scoped_row(connection, case_id, evidence_id):
    connection.row_factory = sqlite3.Row
    row = connection.execute('SELECT evidence.*,cases.investigator_name FROM evidence '
                             'JOIN cases USING(case_id) WHERE evidence.case_id=? AND evidence.evidence_id=?',
                             (case_id, evidence_id)).fetchone()
    if not row:
        raise ScopeError('The selected case and evidence do not match an available record.')
    return dict(row)


def text_field(value, limit=2000):
    if not isinstance(value, str):
        raise ValueError('Invalid text field in stored representation.')
    if len(value) > 100000:
        raise ValueError('Stored text field exceeds Q&A limits.')
    # Redact before shortening so a boundary cannot expose a partial identifier.
    return redact(value)[:limit]


def bounded_list(value, maximum):
    if not isinstance(value, list):
        raise ValueError('Invalid list field in stored representation.')
    return value[:maximum]


def masked_working(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid working representation.')
    result = {key: text_field(value.get(key, ''), 100000 if key == 'body' else 2000)
              for key in ('sender', 'recipient', 'cc', 'reply_to', 'subject', 'date', 'message_id', 'body')}
    result['urls'] = [text_field(item) for item in bounded_list(value.get('urls', []), 100)]
    result['attachments'] = []
    for item in bounded_list(value.get('attachments', []), 50):
        if not isinstance(item, dict) or type(item.get('size')) is not int or item['size'] < 0:
            raise ValueError('Invalid attachment metadata.')
        result['attachments'].append({'name': text_field(item.get('name', '')), 'type': text_field(item.get('type', '')), 'size': item['size']})
    result['truncated'] = bool(value.get('truncated')) or len(value.get('urls', [])) > 100 or len(value.get('attachments', [])) > 50
    result['format'] = text_field(value.get('format', ''), 10)
    return result


def masked_analysis(row, case_id, evidence_id):
    if len(row['findings_json']) > MAX_JSON_BYTES:
        raise ValueError('Stored analysis exceeds limits.')
    value = json.loads(row['findings_json'])
    if not isinstance(value, dict):
        raise ValueError('Invalid analysis representation.')
    for key, expected in [('case_id', case_id), ('evidence_id', evidence_id), ('analysis_id', row['analysis_id'])]:
        if value.get(key) != expected:
            raise ScopeError('Selected analysis identity does not match its stored scope.')
    if row['classification'] not in {'Suspicious', 'Uncertain', 'No Significant Indicators Detected'} or type(row['risk_score']) is not int or not 0 <= row['risk_score'] <= 100:
        raise ValueError('Invalid stored analysis result.')
    result = {key: row[key] for key in ('analysis_id', 'case_id', 'evidence_id', 'classification', 'risk_score', 'risk_level', 'analysis_version', 'engine_version', 'analysis_timestamp')}
    result['ruleset_version'] = row['rule_version']
    result['score_calculation'] = text_field(value.get('score_calculation', ''), 250)
    result['findings'] = []
    for finding in bounded_list(value.get('findings', []), 100):
        if not isinstance(finding, dict):
            raise ValueError('Invalid finding.')
        result['findings'].append({key: text_field(finding.get(key, ''), 1000 if key in {'explanation', 'manual_verification'} else 260)
                                   for key in ('rule_id', 'indicator', 'evidence_source', 'masked_evidence', 'explanation', 'manual_verification')})
    for field in ('missing_information', 'recommended_verification'):
        result[field] = [text_field(item, 1000) for item in bounded_list(value.get(field, []), 50)]
    auth = value.get('authentication', {})
    if not isinstance(auth, dict):
        raise ValueError('Invalid authentication metadata.')
    result['authentication'] = {key: [text_field(item, 30) for item in bounded_list(auth.get(key, []), 10)] for key in ('spf', 'dkim', 'dmarc')}
    return result


@guard('read')
def available_analyses(case_id, evidence_id, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        scoped_row(connection, case_id, evidence_id)
        return [dict(row) for row in connection.execute(
            'SELECT analysis_id,analysis_version,analysis_timestamp FROM analysis_results '
            'WHERE case_id=? AND evidence_id=? AND status=? ORDER BY analysis_version DESC LIMIT 100',
            (case_id, evidence_id, 'completed'))]
    finally:
        connection.close()


@guard('read')
def load_context(case_id, evidence_id, analysis_id=None, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        row = scoped_row(connection, case_id, evidence_id)
        metadata = {key: row[key] for key in ('case_id', 'evidence_id', 'sha256', 'file_size', 'created_at')}
        metadata['original_filename'] = text_field(row['original_filename'])
        context = {'metadata': metadata, 'actor': text_field(row['investigator_name'], 200),
                   'working': None, 'analysis': None, 'integrity': {}}
        if analysis_id is None:
            analysis_row = connection.execute('SELECT * FROM analysis_results WHERE case_id=? AND evidence_id=? AND status=? ORDER BY analysis_version DESC LIMIT 1',
                                              (case_id, evidence_id, 'completed')).fetchone()
        else:
            analysis_row = connection.execute('SELECT * FROM analysis_results WHERE case_id=? AND evidence_id=? AND analysis_id=? AND status=?',
                                              (case_id, evidence_id, analysis_id, 'completed')).fetchone()
            if not analysis_row:
                raise ScopeError('The selected analysis does not belong to the active case and evidence.')
        if analysis_row:
            context['analysis'] = masked_analysis(analysis_row, case_id, evidence_id)
        integrity = connection.execute("SELECT audit_id,status,created_at FROM audit_logs WHERE case_id=? AND evidence_id=? "
                                       "AND action IN ('Integrity rechecked','Integrity checked before analysis') ORDER BY audit_id DESC LIMIT 1",
                                       (case_id, evidence_id)).fetchone()
        if integrity:
            context['integrity'] = dict(integrity)
        try:
            path = evidence_path(row, working=True, data_root=data_root)
            if path.name != 'masked.json':
                raise ValueError('Unexpected working filename.')
            with path.open('rb') as stream:
                data = stream.read(MAX_JSON_BYTES + 1)
            if len(data) > MAX_JSON_BYTES:
                raise ValueError('Working representation exceeds limits.')
            context['working'] = masked_working(json.loads(data))
        except (OSError, ValueError, TypeError, RecursionError):
            # No fallback to original evidence, another case, or prior answers.
            context['working'] = None
        return context
    finally:
        connection.close()


@guard('read')
def page_event(case_id, evidence_id, action, db_path=DEFAULT_DB_PATH):
    if action not in {'Ask-the-Evidence page opened', 'Conversation display cleared'}:
        raise ValueError('Unsupported Q&A page event.')
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        row = scoped_row(connection, case_id, evidence_id)
        with connection:
            record(connection, text_field(row['investigator_name'], 200), action, case_id=case_id, evidence_id=evidence_id,
                   details='Display-only action; persisted records are retained.' if action == 'Conversation display cleared' else 'Scoped masked evidence Q&A opened.')
    finally:
        connection.close()


@guard('ask')
def ask(case_id, evidence_id, question, analysis_id=None, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT):
    initialize_database(db_path)
    connection = connect_database(db_path)
    actor = '(unavailable)'
    scoped = False
    try:
        row = scoped_row(connection, case_id, evidence_id)
        actor = text_field(row['investigator_name'], 200)
        scoped = True
        with connection:
            record(connection, actor, 'Question submitted', case_id=case_id, evidence_id=evidence_id,
                   details='Question received for selected scope; raw question is never audited.')
        if not isinstance(question, str) or not question.strip() or len(question) > MAX_QUESTION:
            raise ValidationError('Enter a nonempty question of at most 500 characters. Long questions are rejected without being stored.')
        # Fresh retrieval on EVERY submission; the visible transcript is not an input.
        context = load_context(case_id, evidence_id, analysis_id, db_path, data_root)
        result = answer_question(question, context)
        result['question'] = redact(question.strip())
        result['interaction_id'] = 'QA-' + uuid.uuid4().hex.upper()
        result['case_id'], result['evidence_id'] = case_id, evidence_id
        selected = context.get('analysis')
        result['analysis_id'] = selected['analysis_id'] if selected and result['analysis_used'] else None
        result['selected_analysis_id'] = selected['analysis_id'] if selected else None
        result['created_at'] = utc_now()
        for ref in result['evidence_references']:
            ref.update(case_id=case_id, evidence_id=evidence_id)
            if ref['source'].startswith('Selected analysis') or 'selected analysis' in ref['source']:
                ref['analysis_id'] = selected['analysis_id'] if selected else None
        assert len(result['evidence_references']) <= MAX_REFERENCES
        assert all(len(ref['snippet']) <= MAX_SNIPPET for ref in result['evidence_references'])
        # Persist only bounded, masked responses, never the context/body itself.
        serialized = json.dumps({key: value for key, value in result.items() if key != 'question'}, ensure_ascii=True)
        with connection:
            connection.execute('INSERT INTO qa_interactions(interaction_id,case_id,evidence_id,analysis_id,investigator_name,'
                               'masked_question,intent,masked_response,evidence_references_json,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                               (result['interaction_id'], case_id, evidence_id, result['analysis_id'], actor,
                                result['question'], result['intent'], serialized, json.dumps(result['evidence_references']), result['status'], result['created_at']))
            record(connection, actor, 'Intent recognized', case_id=case_id, evidence_id=evidence_id, details='Matched intent: ' + result['intent'])
            action = {'unsupported': 'Unsupported question', 'insufficient': 'Insufficient evidence response',
                      'refused': 'High-risk conclusion refused', 'clarification': 'Intent clarification requested'}.get(result['status'], 'Evidence-grounded response generated')
            record(connection, actor, action, case_id=case_id, evidence_id=evidence_id, details='Interaction ' + result['interaction_id'])
            if result['high_risk_refused'] and action != 'High-risk conclusion refused':
                record(connection, actor, 'High-risk conclusion refused', case_id=case_id, evidence_id=evidence_id, details='Conclusive attribution or safety was not asserted.')
            if result['injection_ignored']:
                record(connection, actor, 'Prompt-injection instruction ignored', case_id=case_id, evidence_id=evidence_id,
                       details='Matched instruction-like text treated as data only; no instruction executed.')
        return result
    except Exception:
        connection.rollback()
        with connection:
            record(connection, actor, 'Question-processing error', 'failure',
                   case_id if scoped else None, evidence_id if scoped else None,
                   details='Question could not be processed; no raw input or other case content logged.')
        raise
    finally:
        connection.close()


def conversation_key(case_id, evidence_id, analysis_id):
    return 'qa_conversation:' + case_id + ':' + evidence_id + ':' + (analysis_id or 'none')


def append_visible(state, key, result):
    # One interaction represents two visible chat messages (question + answer).
    visible = list(state.get(key, []))
    visible.append(result)
    dropped = len(visible) > MAX_MESSAGES // 2
    state[key] = visible[-MAX_MESSAGES // 2:]
    return dropped


def clear_visible(state, key, case_id, evidence_id, db_path=DEFAULT_DB_PATH):
    page_event(case_id, evidence_id, 'Conversation display cleared', db_path)
    state.pop(key, None)
