"""Validated local registration and integrity verification; no network operations."""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import tempfile
from urllib.parse import unquote
from email import policy
from email.parser import BytesParser

from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database
from modules.email_parser import parse_email
from modules.privacy import mask_evidence
from modules.auth import guard, current_user, can_access
from modules.errors import ValidationError

DATA_ROOT = DEFAULT_DB_PATH.parent
MAX_FILE_SIZE = 10 * 1024 * 1024
EXTENSIONS = {'.eml', '.txt', '.csv'}
DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.com', '.bat', '.cmd', '.ps1', '.sh', '.py', '.js', '.vbs', '.scr', '.msi', '.jar', '.hta', '.lnk'}


class DuplicateEvidence(ValueError):
    def __init__(self, case_id, evidence_id):
        super().__init__('This file is already registered. No copy was created.')
        self.case_id, self.evidence_id = case_id, evidence_id


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def traversal(value):
    for _ in range(3):
        value = unquote(value)
    return bool(re.search(r'\.\.[/\\]|(?:^|\s)[A-Za-z]:[/\\]|(?:^|\s)\\\\', value))


def sanitize_filename(name):
    if not isinstance(name, str) or not name or len(name) > 200:
        raise ValidationError('Unsafe filename.')
    decoded = unquote(name)
    if (decoded != name or '..' in name or any(c in name for c in '/\\:<>"|?*')
            or any(ord(c) < 32 for c in name) or name != name.strip() or name.endswith('.')
            or re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', name, re.I)):
        raise ValidationError('Unsafe filename.')
    safe = re.sub(r'[^A-Za-z0-9_. -]', '_', name)
    if Path(safe).suffix.lower() not in EXTENSIONS:
        raise ValidationError('Unsupported file extension.')
    return safe


def unsafe_payload(data):
    if data.startswith((b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'#!')) or b'\x00' in data:
        return True
    text = data.decode('utf-8', errors='replace')
    return traversal(text) or bool(re.search(
        r'<\s*(script|iframe|object|embed)\b|javascript\s*:|\bon\w+\s*=|^\s*(?:@echo\s+off|powershell\s|import\s+os\b|from\s+os\s+import|eval\s*\(|exec\s*\()', text, re.I | re.M))


def validate_upload(name, data):
    safe = sanitize_filename(name)
    if not isinstance(data, bytes) or not data or not data.strip():
        raise ValidationError('Empty evidence is not accepted.')
    if len(data) > MAX_FILE_SIZE:
        raise ValidationError('Evidence exceeds the 10 MB limit.')
    if unsafe_payload(data):
        raise ValidationError('Executable content or path traversal pattern detected.')
    if Path(safe).suffix.lower() == '.eml':
        if len(re.findall(br'(?im)^content-type\s*:', data)) > 200:
            raise ValidationError('MIME structure exceeds the safety limit.')
        try:
            message = BytesParser(policy=policy.default).parsebytes(data)
            for index, part in enumerate(message.walk()):
                if index >= 200:
                    raise ValidationError('MIME structure exceeds the safety limit.')
                name = part.get_filename() or ''
                if (traversal(name) or '/' in name or '\\' in name or ':' in name
                        or Path(name).suffix.lower() in DANGEROUS_EXTENSIONS
                        or part.get_content_type() in {'application/x-msdownload', 'application/x-executable', 'application/javascript'}):
                    raise ValidationError('Unsafe attachment metadata.')
                if not part.is_multipart() and unsafe_payload(part.get_payload(decode=True) or b''):
                    raise ValidationError('Unsafe encoded email content or attachment.')
        except (RecursionError, LookupError) as exc:
            raise ValidationError('Email structure cannot be processed safely.') from exc
    return safe


def confined(root, *parts):
    root = Path(root).absolute()
    if root.is_symlink() or root.resolve() != root:
        raise ValidationError('Data directory must not be redirected.')
    target = root.joinpath(*parts)
    if not target.resolve().is_relative_to(root):
        raise ValidationError('Storage path leaves the data directory.')
    current = target
    while current != root:
        if current.is_symlink() or (hasattr(current, 'is_junction') and current.is_junction()):
            raise ValidationError('Redirected storage paths are not permitted.')
        current = current.parent
    return target


def atomic_write(path, data):
    # Destination lives in a freshly, exclusively created evidence directory.
    descriptor, temporary = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists():
            raise ValidationError('Existing evidence must not be overwritten.')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@guard('read')
def log_event(actor, action, status='success', case_id=None, evidence_id=None, details='', db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    connection = connect_database(db_path)
    try:
        with connection:
            record(connection, actor or '(unspecified)', action, status, case_id, evidence_id, details)
    finally:
        connection.close()


@guard('upload')
def register_evidence(title, investigator, description, source, authorized, filename, data,
                      selected_row=None, data_root=DATA_ROOT, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    authenticated = current_user(db_path)
    actor = investigator.strip() if isinstance(investigator, str) else '(unspecified)'
    created_dirs = []
    connection = connect_database(db_path)
    try:
        for value in (title, investigator, description, source):
            if not isinstance(value, str) or not value.strip() or len(value) > 2000:
                raise ValidationError('All case fields are required and must be at most 2000 characters.')
        if len(investigator) > 200 or not authorized:
            raise ValidationError('Authorization and a valid investigator name are required.')
        # Hash before MIME validation, parsing or masking.
        if not isinstance(data, bytes) or len(data) > MAX_FILE_SIZE:
            raise ValidationError('Missing evidence or evidence exceeds 10 MB.')
        digest = sha256_bytes(data)
        safe_name = validate_upload(filename, data)
        connection.execute('BEGIN IMMEDIATE')
        duplicate = connection.execute('SELECT case_id,evidence_id FROM evidence WHERE sha256=?', (digest,)).fetchone()
        if duplicate:
            if not can_access(connection, authenticated, duplicate[0]):
                record(connection, authenticated['user_id'], 'ACCESS_DENIED', 'failure', details='Duplicate registration unavailable.')
                connection.commit()
                raise ValidationError('This evidence cannot be registered. Contact an administrator.')
            record(connection, actor, 'Duplicate upload detected', 'failure', *duplicate,
                   details='Matching SHA-256; registration stopped.')
            connection.commit()
            raise DuplicateEvidence(*duplicate)
        parsed = mask_evidence(parse_email(data, Path(safe_name).suffix.lower(), selected_row))
        date = utc_now()[:10].replace('-', '')
        def new_id(prefix, table, column):
            for _ in range(100):
                identifier = f'{prefix}-{date}-{secrets.token_hex(2).upper()}'
                if not connection.execute(f'SELECT 1 FROM {table} WHERE {column}=?', (identifier,)).fetchone():
                    return identifier
            raise ValidationError('Could not allocate a unique identifier.')
        case_id = new_id('CASE', 'cases', 'case_id')
        evidence_id = new_id('EVD', 'evidence', 'evidence_id')
        original_dir = confined(data_root, 'evidence', case_id, evidence_id)
        working_dir = confined(data_root, 'working', case_id, evidence_id)
        for directory in (original_dir, working_dir):
            directory.parent.mkdir(parents=True, exist_ok=True)
            directory.mkdir(exist_ok=False)
            created_dirs.append(directory)
        original = original_dir / ('original' + Path(safe_name).suffix.lower())
        working = working_dir / 'masked.json'
        atomic_write(original, data)
        original.chmod(stat.S_IREAD)
        atomic_write(working, json.dumps(parsed, ensure_ascii=True, indent=2).encode('utf-8'))
        now = utc_now()
        connection.execute('INSERT INTO cases(case_id,title,investigator_name,description,evidence_source,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)',
                           (case_id, title.strip(), actor, description.strip(), source.strip(), 'open', now, now))
        connection.execute('INSERT INTO evidence(evidence_id,case_id,original_filename,storage_path,sha256,status,created_at,updated_at,file_size,working_path) VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (evidence_id, case_id, safe_name, str(original), digest, 'stored', now, now, len(data), str(working)))
        connection.execute('INSERT INTO case_assignments(assignment_id,case_id,user_id,assigned_by,assigned_at_utc,active) VALUES(?,?,?,?,?,1)',
                           ('ASN-' + secrets.token_hex(12).upper(), case_id, authenticated['user_id'], authenticated['user_id'], now))
        record(connection, authenticated['user_id'], 'CASE_ASSIGNED', case_id=case_id, details='Creator assigned to new case.')
        for action in ('Case created', 'Authorization confirmed', 'Evidence uploaded', 'Hash generated',
                       'Original evidence stored', 'Email parsed', 'Personal details masked', 'Working copy created'):
            record(connection, actor, action, case_id=case_id, evidence_id=evidence_id,
                   details='Analysis truncation recorded in working JSON.' if parsed['truncated'] else '')
        connection.commit()
        return case_id, evidence_id
    except DuplicateEvidence:
        raise
    except Exception as exc:
        connection.rollback()
        for directory in reversed(created_dirs):
            for file in directory.iterdir():
                file.chmod(stat.S_IWRITE | stat.S_IREAD)
                file.unlink()
            directory.rmdir()
            if not any(directory.parent.iterdir()):
                directory.parent.rmdir()
        log_event(actor, 'Validation failure' if isinstance(exc, ValueError) else 'Registration failed',
                  'failure', details='Registration stopped; no evidence registered.', db_path=db_path)
        raise
    finally:
        connection.close()


@guard('read')
def get_evidence(evidence_id, db_path=DEFAULT_DB_PATH):
    connection = connect_database(db_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute('SELECT evidence.*,cases.investigator_name FROM evidence JOIN cases USING(case_id) WHERE evidence_id=?', (evidence_id,)).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def evidence_path(row, working=False, data_root=DATA_ROOT):
    area = 'working' if working else 'evidence'
    path = Path(row['working_path' if working else 'storage_path'])
    expected = confined(data_root, area, row['case_id'], row['evidence_id'])
    checked = confined(data_root, *path.absolute().relative_to(Path(data_root).absolute()).parts)
    if checked.parent != expected:
        raise ValidationError('Evidence location does not match its identifiers.')
    return checked


@guard('read')
def verify_integrity(evidence_id, db_path=DEFAULT_DB_PATH, data_root=DATA_ROOT, audit=True):
    row = get_evidence(evidence_id, db_path)
    if not row:
        raise ValidationError('Evidence record not found.')
    try:
        path = evidence_path(row, data_root=data_root)
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(65536), b''):
                digest.update(chunk)
        valid = digest.hexdigest() == row['sha256']
    except (OSError, ValueError, TypeError):
        valid = False
    if audit:
        log_event(row['investigator_name'], 'Integrity rechecked', 'success' if valid else 'failure',
                  row['case_id'], evidence_id, 'Integrity verified' if valid else 'Integrity check failed', db_path)
    return valid
