"""Local authentication and permission boundary. Passwords never leave this module."""
import argparse
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from functools import wraps
import getpass
import hashlib
import hmac
import inspect
import json
import re
import secrets
import sqlite3

from modules.audit import record, utc_now
from modules.database import DEFAULT_DB_PATH, connect_database, initialize_database
from modules.errors import ValidationError

ITERATIONS = 600000
FAILURE = 'Invalid credentials or account temporarily unavailable.'
DENIED = 'Permission denied. The requested operation is unavailable.'
ROLES = ('Administrator', 'Investigator', 'Reviewer')
PERMISSIONS = {
 'Administrator': {'read','upload','analyze','ask','decide','report_generate','report_read','admin','audit','archive'},
 'Investigator': {'read','upload','analyze','ask','decide','report_generate','report_read'},
 'Reviewer': {'read','decide','report_read'},
}
_token = ContextVar('local_auth_session', default=None)
_depth = ContextVar('authorized_service_depth', default=0)
_dummy_salt = secrets.token_bytes(32)
PUBLIC_COLUMNS = 'user_id,username,role,enabled,failed_attempts,locked_until_utc,created_at_utc,updated_at_utc'


class AccessDenied(ValidationError):
    pass


def now():
    return datetime.now(timezone.utc)


def event(c, action, user_id=None, status='success', case_id=None, **metadata):
    record(c, user_id or '[LOCAL-USER]', action, status, case_id=case_id, details=json.dumps(metadata, sort_keys=True))


def _password(password):
    if (not isinstance(password, str) or not 12 <= len(password) <= 1024
            or not all(re.search(p, password) for p in (r'[A-Z]', r'[a-z]', r'[0-9]', r'[^A-Za-z0-9\s]'))):
        raise ValueError('Password must have 12–1024 characters, uppercase, lowercase, a number and a special character.')


def _username(username):
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', username):
        raise ValueError('Username must have 3–64 letters, numbers, dots, underscores or hyphens.')
    return username.lower()


def _insert_user(c, username, password, role, actor=None):
    username = _username(username)
    _password(password)
    if role not in ROLES:
        raise ValueError('Select a valid role.')
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    user_id, timestamp = 'USR-' + secrets.token_hex(12).upper(), utc_now()
    c.execute('INSERT INTO users(user_id,username,password_hash,password_salt,password_iterations,role,created_at_utc,updated_at_utc) '
              'VALUES(?,?,?,?,?,?,?,?)', (user_id, username, digest, salt, ITERATIONS, role, timestamp, timestamp))
    event(c, 'USER_CREATED', actor or user_id, target_user_id=user_id, role=role)
    return user_id


def create_first_admin(username, password, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    c = connect_database(db_path)
    try:
        with c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise AccessDenied('Initial setup is already complete. Use Administrator user management.')
            return _insert_user(c, username, password, 'Administrator')
    finally:
        c.close()


def login(username, password, db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    c = connect_database(db_path)
    c.row_factory = sqlite3.Row
    try:
        with c:
            c.execute('BEGIN IMMEDIATE')
            normalized = username.lower() if isinstance(username, str) and re.fullmatch(r'[A-Za-z0-9_.-]{3,64}', username) else ''
            row = c.execute('SELECT * FROM users WHERE username=?', (normalized,)).fetchone()
            value = password if isinstance(password, str) and len(password) <= 1024 else ''
            digest = hashlib.pbkdf2_hmac('sha256', value.encode(), row['password_salt'] if row else _dummy_salt,
                                         row['password_iterations'] if row else ITERATIONS)
            matches = hmac.compare_digest(digest, row['password_hash'] if row else bytes(32))
            timestamp = now()
            locked = bool(row and row['locked_until_utc'] and datetime.fromisoformat(row['locked_until_utc']) > timestamp)
            if not row or not row['enabled'] or locked or not matches:
                if row and row['enabled'] and not locked:
                    attempts = (0 if row['locked_until_utc'] else row['failed_attempts']) + 1
                    until = (timestamp + timedelta(minutes=15)).isoformat() if attempts >= 5 else None
                    c.execute('UPDATE users SET failed_attempts=?,locked_until_utc=?,updated_at_utc=? WHERE user_id=?',
                              (attempts, until, timestamp.isoformat(), row['user_id']))
                    if until:
                        event(c, 'ACCOUNT_LOCKED', row['user_id'], status='failure')
                event(c, 'LOGIN_FAILURE', status='failure')
                return None
            token = secrets.token_urlsafe(48)
            session_id = hashlib.sha256(token.encode()).hexdigest()
            c.execute('UPDATE users SET failed_attempts=0,locked_until_utc=NULL,updated_at_utc=? WHERE user_id=?',
                      (timestamp.isoformat(), row['user_id']))
            c.execute("INSERT INTO sessions(session_id,user_id,login_time_utc,last_activity_utc,status) VALUES(?,?,?,?,'active')",
                      (session_id, row['user_id'], timestamp.isoformat(), timestamp.isoformat()))
            event(c, 'LOGIN_SUCCESS', row['user_id'])
            return token
    finally:
        c.close()


def session_token():
    if _token.get():
        return _token.get()
    from streamlit.runtime.scriptrunner import get_script_run_ctx
    if get_script_run_ctx(suppress_warning=True) is not None:
        import streamlit as st
        return st.session_state.get('auth_token')
    return None


@contextmanager
def as_session(token):
    """Bind an opaque, database-validated session to a local caller/thread."""
    handle = _token.set(token)
    try:
        yield
    finally:
        _token.reset(handle)


def current_user(db_path=DEFAULT_DB_PATH, token=None, touch=False):
    token = token or session_token()
    if not isinstance(token, str) or len(token) > 256:
        raise AccessDenied(DENIED)
    c = connect_database(db_path)
    c.row_factory = sqlite3.Row
    try:
        session_id = hashlib.sha256(token.encode()).hexdigest()
        row = c.execute("SELECT u.user_id,u.username,u.role,u.enabled,s.last_activity_utc FROM users u JOIN sessions s USING(user_id) "
                        "WHERE s.session_id=? AND s.status='active'", (session_id,)).fetchone()
        if not row or not row['enabled']:
            raise AccessDenied(DENIED)
        timestamp = now()
        if timestamp - datetime.fromisoformat(row['last_activity_utc']) >= timedelta(minutes=30):
            with c:
                c.execute("UPDATE sessions SET status='expired',logout_time_utc=? WHERE session_id=? AND status='active'", (timestamp.isoformat(), session_id))
                event(c, 'SESSION_EXPIRED', row['user_id'])
            raise AccessDenied(DENIED)
        if touch:
            with c:
                c.execute('UPDATE sessions SET last_activity_utc=? WHERE session_id=?', (timestamp.isoformat(), session_id))
        return {key: row[key] for key in ('user_id', 'username', 'role', 'enabled')}
    finally:
        c.close()


def logout(token=None, state=None, db_path=DEFAULT_DB_PATH):
    token = token or session_token()
    c = connect_database(db_path)
    try:
        if token:
            session_id = hashlib.sha256(token.encode()).hexdigest()
            with c:
                row = c.execute("SELECT user_id FROM sessions WHERE session_id=? AND status='active'", (session_id,)).fetchone()
                if row:
                    c.execute("UPDATE sessions SET status='logged_out',logout_time_utc=? WHERE session_id=?", (utc_now(), session_id))
                    event(c, 'LOGOUT', row[0])
    finally:
        c.close()
        if state is not None:
            state.clear()


def can_access(c, user, case_id):
    return bool(c.execute('SELECT 1 FROM cases WHERE case_id=?', (case_id,)).fetchone() and
        (user['role'] == 'Administrator' or c.execute('SELECT 1 FROM case_assignments WHERE case_id=? AND user_id=? AND active=1',
                                                     (case_id, user['user_id'])).fetchone()))


def require_permission(action, case_id=None, evidence_id=None, db_path=DEFAULT_DB_PATH, touch=False):
    user = current_user(db_path, touch=touch)
    c = connect_database(db_path)
    try:
        allowed = action in PERMISSIONS[user['role']]
        if evidence_id:
            row = c.execute('SELECT case_id FROM evidence WHERE evidence_id=?', (evidence_id,)).fetchone()
            allowed = allowed and bool(row) and (case_id is None or row[0] == case_id)
            case_id = row[0] if row else None
        if case_id:
            allowed = allowed and can_access(c, user, case_id)
            if action in {'upload','analyze','ask','decide','report_generate'}:
                row = c.execute('SELECT archived_at_utc,deletion_requested_at_utc,status FROM cases WHERE case_id=?', (case_id,)).fetchone()
                allowed = allowed and bool(row) and not row[0] and not row[1] and row[2] != 'closed'
        if not allowed:
            with c:
                event(c, 'ACCESS_DENIED', user['user_id'], status='failure', permission=action)
            raise AccessDenied(DENIED)
        return user
    finally:
        c.close()


def guard(action):
    """Require role and database-backed case assignment on every public service call."""
    def decorate(function):
        signature = inspect.signature(function)
        @wraps(function)
        def call(*args, **kwargs):
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            values = bound.arguments
            db = values.get('db_path', DEFAULT_DB_PATH)
            user = require_permission(action, values.get('case_id'), values.get('evidence_id'), db, touch=_depth.get() == 0)
            depth = _depth.set(_depth.get() + 1)
            try:
                result = function(*args, **kwargs)
            finally:
                _depth.reset(depth)
            if action in {'upload','analyze','decide','report_generate'} and _depth.get() == 0:
                from modules.case_service import refresh_statuses
                refresh_statuses(db)
            return result
        return call
    return decorate


@guard('admin')
def list_users(db_path=DEFAULT_DB_PATH):
    c = connect_database(db_path)
    try:
        columns = PUBLIC_COLUMNS.split(',')
        return [dict(zip(columns, row)) for row in c.execute('SELECT ' + PUBLIC_COLUMNS + ' FROM users ORDER BY username')]
    finally:
        c.close()


@guard('admin')
def create_user(username, password, role, db_path=DEFAULT_DB_PATH):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        with c:
            return _insert_user(c, username, password, role, actor)
    finally:
        c.close()


@guard('admin')
def set_enabled(user_id, enabled, db_path=DEFAULT_DB_PATH):
    actor = current_user(db_path)['user_id']
    c = connect_database(db_path)
    try:
        with c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT role,enabled FROM users WHERE user_id=?', (user_id,)).fetchone()
            if not row or type(enabled) is not bool:
                raise ValueError('Select a valid account and status.')
            if not enabled and row[0] == 'Administrator' and row[1] and c.execute("SELECT COUNT(*) FROM users WHERE role='Administrator' AND enabled=1").fetchone()[0] <= 1:
                raise ValueError('The last enabled administrator cannot be disabled.')
            c.execute('UPDATE users SET enabled=?,updated_at_utc=? WHERE user_id=?', (int(enabled), utc_now(), user_id))
            if not enabled:
                c.execute("UPDATE sessions SET status='revoked',logout_time_utc=? WHERE user_id=? AND status='active'", (utc_now(), user_id))
            event(c, 'USER_ENABLED' if enabled else 'USER_DISABLED', actor, target_user_id=user_id)
    finally:
        c.close()


@guard('admin')
def reset_password(user_id, password, db_path=DEFAULT_DB_PATH):
    _password(password)
    actor = current_user(db_path)['user_id']
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    c = connect_database(db_path)
    try:
        with c:
            if not c.execute('SELECT 1 FROM users WHERE user_id=?', (user_id,)).fetchone():
                raise ValueError('Select a valid account.')
            c.execute('UPDATE users SET password_hash=?,password_salt=?,password_iterations=?,failed_attempts=0,locked_until_utc=NULL,updated_at_utc=? WHERE user_id=?',
                      (digest, salt, ITERATIONS, utc_now(), user_id))
            c.execute("UPDATE sessions SET status='revoked',logout_time_utc=? WHERE user_id=? AND status='active'", (utc_now(), user_id))
            event(c, 'PASSWORD_RESET', actor, target_user_id=user_id)
    finally:
        c.close()


def main():
    parser = argparse.ArgumentParser(description='Local first-administrator setup')
    parser.add_argument('command', choices=['create-admin'])
    parser.parse_args()
    username = input('Username: ').strip()
    password = getpass.getpass('Password: ')
    confirmation = getpass.getpass('Confirm password: ')
    if not hmac.compare_digest(password.encode(), confirmation.encode()):
        raise SystemExit('Passwords do not match.')
    try:
        user_id = create_first_admin(username, password)
    except Exception:
        raise SystemExit('Administrator setup failed. Check the requirements and whether initial setup is already complete.')
    print('Administrator created: ' + user_id)


if __name__ == '__main__':
    main()
